"""Adaptadores conservadores para ACLs NTFS, SMB e bits POSIX."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .path_security import parse_unc_path

PERMISSION_POLICY_VERSION = "windows-acl-1.0"
_GENERIC_READ = 0x80000000
_GENERIC_ALL = 0x10000000
_FILE_READ_DATA = 0x00000001
_PUBLIC_SIDS = {"S-1-1-0", "S-1-5-7", "S-1-5-32-546"}
_INTERNAL_ALL_SIDS = {"S-1-5-11", "S-1-5-32-545"}
_PRIVILEGED_SIDS = {
    "S-1-3-0",  # Creator Owner
    "S-1-3-1",  # Creator Group
    "S-1-3-4",  # Owner Rights
    "S-1-5-18",  # Local System
    "S-1-5-32-544",  # Builtin Administrators
}


class WindowsAclDependencyError(OSError):
    """pywin32 e necessario para o perfil corporativo no Windows."""


class ReportProtectionError(OSError):
    """O sistema nao conseguiu aplicar uma ACL restritiva ao relatorio."""


@dataclass(frozen=True)
class PermissionAssessment:
    level: str = "unknown"
    score: int = 10
    owner: str = "unknown"
    unknown: bool = True
    source: str = "unavailable"
    acl_inheritance: str = "unknown"
    share_acl_evaluated: bool = False


class PermissionAdapter(Protocol):
    def assess(self, path: Path) -> PermissionAssessment: ...


@dataclass(frozen=True)
class AccessControlEntry:
    sid: str
    ace_type: str
    mask: int
    inherited: bool = False


@dataclass(frozen=True)
class SecurityDescriptorSnapshot:
    owner_sid: str = "unknown"
    owner_name: str = "unknown"
    aces: tuple[AccessControlEntry, ...] = ()
    null_dacl: bool = False
    dacl_protected: bool | None = None
    unsupported_ace: bool = False


class WindowsSecurityBackend(Protocol):
    def read_file_security(self, path: Path) -> SecurityDescriptorSnapshot: ...

    def read_share_security(self, server: str, share: str) -> SecurityDescriptorSnapshot: ...

    def protect_file(self, path: Path) -> None: ...


class PyWin32SecurityBackend:
    """Le descritores com APIs nativas, sem interpretar texto localizado do icacls."""

    def __init__(self) -> None:
        try:
            import ntsecuritycon
            import win32api
            import win32con
            import win32net
            import win32security
        except ImportError as exception:
            raise WindowsAclDependencyError("dependencia Windows indisponivel") from exception
        self.ntsecuritycon = ntsecuritycon
        self.win32api = win32api
        self.win32con = win32con
        self.win32net = win32net
        self.win32security = win32security

    def _sid_text(self, sid: object) -> str:
        return self.win32security.ConvertSidToStringSid(sid)

    def _owner_name(self, sid: object) -> str:
        try:
            name, domain, _kind = self.win32security.LookupAccountSid(None, sid)
        except Exception:  # pywintypes.error nao deriva de OSError em todas as versoes
            return self._sid_text(sid)
        return f"{domain}\\{name}" if domain else name

    def _snapshot(self, descriptor: object) -> SecurityDescriptorSnapshot:
        owner = descriptor.GetSecurityDescriptorOwner()
        owner_sid = self._sid_text(owner) if owner is not None else "unknown"
        owner_name = self._owner_name(owner) if owner is not None else "unknown"
        dacl = descriptor.GetSecurityDescriptorDacl()
        control, _revision = descriptor.GetSecurityDescriptorControl()
        protected_flag = getattr(self.win32security, "SE_DACL_PROTECTED", 0x1000)
        if dacl is None:
            return SecurityDescriptorSnapshot(
                owner_sid,
                owner_name,
                null_dacl=True,
                dacl_protected=bool(control & protected_flag),
            )
        allow_types = {
            self.win32security.ACCESS_ALLOWED_ACE_TYPE,
            getattr(self.win32security, "ACCESS_ALLOWED_OBJECT_ACE_TYPE", 5),
        }
        deny_types = {
            self.win32security.ACCESS_DENIED_ACE_TYPE,
            getattr(self.win32security, "ACCESS_DENIED_OBJECT_ACE_TYPE", 6),
        }
        inherited_flag = getattr(self.win32security, "INHERITED_ACE", 0x10)
        entries: list[AccessControlEntry] = []
        unsupported = False
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            header = ace[0]
            ace_type, flags = int(header[0]), int(header[1])
            if ace_type in allow_types:
                kind = "allow"
            elif ace_type in deny_types:
                kind = "deny"
            else:
                unsupported = True
                continue
            try:
                sid = self._sid_text(ace[-1])
                mask = int(ace[1])
            except (TypeError, ValueError, OSError):
                unsupported = True
                continue
            entries.append(AccessControlEntry(sid, kind, mask, bool(flags & inherited_flag)))
        return SecurityDescriptorSnapshot(
            owner_sid,
            owner_name,
            tuple(entries),
            dacl_protected=bool(control & protected_flag),
            unsupported_ace=unsupported,
        )

    def read_file_security(self, path: Path) -> SecurityDescriptorSnapshot:
        try:
            information = (
                self.win32security.OWNER_SECURITY_INFORMATION
                | self.win32security.DACL_SECURITY_INFORMATION
            )
            descriptor = self.win32security.GetNamedSecurityInfo(
                str(path), self.win32security.SE_FILE_OBJECT, information
            )
            return self._snapshot(descriptor)
        except Exception as exception:
            raise OSError("leitura da DACL NTFS falhou") from exception

    def read_share_security(self, server: str, share: str) -> SecurityDescriptorSnapshot:
        try:
            information = self.win32net.NetShareGetInfo(f"\\\\{server}", share, 502)
            descriptor = information.get("security_descriptor")
            if descriptor is None:
                raise OSError("descritor do compartilhamento indisponivel")
            return self._snapshot(descriptor)
        except Exception as exception:
            raise OSError("leitura da ACL SMB falhou") from exception

    def protect_file(self, path: Path) -> None:
        try:
            token = self.win32security.OpenProcessToken(
                self.win32api.GetCurrentProcess(), self.win32con.TOKEN_QUERY
            )
            current_sid = self.win32security.GetTokenInformation(
                token, self.win32security.TokenUser
            )[0]
            system_sid = self.win32security.ConvertStringSidToSid("S-1-5-18")
            administrators_sid = self.win32security.ConvertStringSidToSid("S-1-5-32-544")
            dacl = self.win32security.ACL()
            for sid in (current_sid, system_sid, administrators_sid):
                dacl.AddAccessAllowedAceEx(
                    self.win32security.ACL_REVISION_DS,
                    0,
                    self.ntsecuritycon.FILE_ALL_ACCESS,
                    sid,
                )
            protected_dacl = getattr(
                self.win32security, "PROTECTED_DACL_SECURITY_INFORMATION", 0x80000000
            )
            information = (
                self.win32security.OWNER_SECURITY_INFORMATION
                | self.win32security.DACL_SECURITY_INFORMATION
                | protected_dacl
            )
            self.win32security.SetNamedSecurityInfo(
                str(path),
                self.win32security.SE_FILE_OBJECT,
                information,
                current_sid,
                None,
                dacl,
                None,
            )
        except Exception as exception:
            raise OSError("protecao da DACL falhou") from exception


@dataclass(frozen=True)
class _DescriptorAssessment:
    level: str
    score: int
    unknown: bool
    inheritance: str


def _can_read(mask: int) -> bool:
    return bool(mask & (_GENERIC_READ | _GENERIC_ALL | _FILE_READ_DATA))


def _descriptor_assessment(snapshot: SecurityDescriptorSnapshot) -> _DescriptorAssessment:
    if snapshot.null_dacl:
        return _DescriptorAssessment("public", 30, False, "unprotected")
    inheritance = "protected" if snapshot.dacl_protected else "inherited_or_unprotected"
    if snapshot.unsupported_ace or any(ace.ace_type == "deny" for ace in snapshot.aces):
        return _DescriptorAssessment("unknown", 10, True, inheritance)
    readable = {ace.sid for ace in snapshot.aces if ace.ace_type == "allow" and _can_read(ace.mask)}
    if readable & _PUBLIC_SIDS:
        return _DescriptorAssessment("public", 30, False, inheritance)
    if readable & _INTERNAL_ALL_SIDS or any(sid.endswith("-513") for sid in readable):
        return _DescriptorAssessment("internal_all", 22, False, inheritance)
    restricted = readable - _PRIVILEGED_SIDS - {snapshot.owner_sid}
    if restricted:
        return _DescriptorAssessment("internal_limited", 5, False, inheritance)
    return _DescriptorAssessment("owner_restricted", 0, False, inheritance)


class WindowsPermissionAdapter:
    """Combina DACL do arquivo e do share, usando a mais restritiva quando ambas sao conhecidas."""

    def __init__(
        self,
        *,
        include_share_acl: bool = True,
        require_backend: bool = True,
        backend: WindowsSecurityBackend | None = None,
    ) -> None:
        self.include_share_acl = include_share_acl
        self._share_cache: dict[tuple[str, str], _DescriptorAssessment | None] = {}
        try:
            self.backend = backend or PyWin32SecurityBackend()
        except WindowsAclDependencyError:
            if require_backend:
                raise
            self.backend = None

    @property
    def available(self) -> bool:
        return self.backend is not None

    def assess(self, path: Path) -> PermissionAssessment:
        if self.backend is None:
            return PermissionAssessment(source="windows_acl_dependency_missing")
        try:
            ntfs_snapshot = self.backend.read_file_security(path)
            ntfs = _descriptor_assessment(ntfs_snapshot)
        except OSError:
            return PermissionAssessment(source="windows_ntfs_dacl_unavailable")
        owner = ntfs_snapshot.owner_name
        unc = parse_unc_path(str(path))
        if unc is None or not self.include_share_acl:
            return PermissionAssessment(
                ntfs.level,
                ntfs.score,
                owner,
                ntfs.unknown,
                "windows_ntfs_dacl",
                ntfs.inheritance,
                False,
            )
        share_key = (unc.server.casefold(), unc.share.casefold())
        if share_key not in self._share_cache:
            try:
                self._share_cache[share_key] = _descriptor_assessment(
                    self.backend.read_share_security(unc.server, unc.share)
                )
            except OSError:
                self._share_cache[share_key] = None
        share = self._share_cache[share_key]
        if share is None:
            return PermissionAssessment(
                "unknown" if ntfs.score < 10 else ntfs.level,
                max(ntfs.score, 10),
                owner,
                True,
                "windows_ntfs_dacl+windows_smb_share_dacl_unavailable",
                ntfs.inheritance,
                False,
            )
        if ntfs.unknown or share.unknown:
            return PermissionAssessment(
                "unknown",
                max(min(ntfs.score, share.score), 10),
                owner,
                True,
                "windows_ntfs_dacl+windows_smb_share_dacl",
                ntfs.inheritance,
                True,
            )
        effective = min((ntfs, share), key=lambda item: item.score)
        return PermissionAssessment(
            effective.level,
            effective.score,
            owner,
            False,
            "windows_ntfs_dacl+windows_smb_share_dacl",
            ntfs.inheritance,
            True,
        )


class PosixPermissionAdapter:
    """Interpreta bits POSIX sem presumir equivalencia com ACLs corporativas."""

    def assess(self, path: Path) -> PermissionAssessment:
        try:
            metadata = path.stat()
            import pwd

            owner = pwd.getpwuid(metadata.st_uid).pw_name
            mode = stat.S_IMODE(metadata.st_mode)
        except (KeyError, OSError, ImportError):
            return PermissionAssessment(source="posix_stat_failed")
        if mode & stat.S_IROTH:
            return PermissionAssessment("internal_all", 22, owner, False, "posix_mode_bits")
        if mode & stat.S_IRGRP:
            return PermissionAssessment("internal_limited", 5, owner, False, "posix_mode_bits")
        return PermissionAssessment("owner_restricted", 0, owner, False, "posix_mode_bits")


class LocalPermissionAdapter:
    """Seleciona o adaptador nativo e preserva compatibilidade com a API anterior."""

    def __init__(self, *, include_share_acl: bool = True, require_windows_acl: bool = False) -> None:
        if os.name == "nt":
            self.adapter: PermissionAdapter = WindowsPermissionAdapter(
                include_share_acl=include_share_acl,
                require_backend=require_windows_acl,
            )
        else:
            self.adapter = PosixPermissionAdapter()

    def assess(self, path: Path) -> PermissionAssessment:
        return self.adapter.assess(path)


def default_permission_adapter(
    *, include_share_acl: bool = True, require_windows_acl: bool = True
) -> PermissionAdapter:
    return LocalPermissionAdapter(
        include_share_acl=include_share_acl,
        require_windows_acl=require_windows_acl,
    )


def protect_report_path(
    path: Path,
    *,
    strict: bool = True,
    backend: WindowsSecurityBackend | None = None,
) -> str:
    """Aplica 0600 no POSIX ou DACL somente operador, SYSTEM e Administradores no Windows."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        if stat.S_IMODE(path.stat().st_mode) != 0o600 and strict:
            raise ReportProtectionError("modo restritivo nao foi aplicado")
        return "posix_mode_0600"
    try:
        (backend or PyWin32SecurityBackend()).protect_file(path)
    except (OSError, WindowsAclDependencyError) as exception:
        if strict:
            raise ReportProtectionError("ACL restritiva nao foi aplicada") from exception
        return "windows_acl_unavailable"
    return "windows_protected_dacl"
