"""Politica de caminhos para execucao corporativa local e UNC."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

PATH_POLICY_VERSION = "windows-path-1.0"
_URI = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://")
_WINDOWS_DRIVE = re.compile(r"(?i)^[a-z]:[\\/]")
_DEVICE_PREFIXES = (
    "\\\\.\\",
    "\\\\?\\globalroot\\",
    "\\\\?\\pipe\\",
    "\\??\\",
)
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class UnsafePathError(ValueError):
    """Entrada usa uma sintaxe de caminho inadequada para varredura corporativa."""


@dataclass(frozen=True)
class UncShare:
    """Componentes nao secretos de uma raiz UNC valida."""

    server: str
    share: str


def normalize_windows_display_path(value: str) -> str:
    """Remove somente o prefixo Win32 estendido, preservando a semantica UNC."""
    if value.startswith(("\\", "//")) or _WINDOWS_DRIVE.match(value):
        normalized = value.replace("/", "\\")
    else:
        normalized = value
    lowered = normalized.lower()
    if lowered.startswith("\\\\?\\unc\\"):
        return "\\\\" + normalized[8:]
    if lowered.startswith("\\\\?\\") and len(normalized) >= 7 and normalized[5:7] == ":\\":
        return normalized[4:]
    return normalized


def parse_unc_path(value: str) -> UncShare | None:
    """Retorna servidor e compartilhamento sem tentar autenticar ou acessar a rede."""
    normalized = normalize_windows_display_path(value)
    if not normalized.startswith("\\\\") or normalized.startswith("\\\\.\\"):
        return None
    components = [item for item in normalized[2:].split("\\") if item]
    if len(components) < 2:
        raise UnsafePathError("caminho UNC deve informar servidor e compartilhamento")
    server, share = components[:2]
    if share.casefold() == "ipc$":
        raise UnsafePathError("IPC$ nao e uma raiz de arquivos autorizavel")
    return UncShare(server, share)


def path_kind(value: str) -> str:
    return "unc" if parse_unc_path(value) else "local"


def validate_root_syntax(value: str, *, require_absolute: bool = True) -> None:
    """Rejeita URLs, namespaces de dispositivo e raizes relativas."""
    if not value or "\x00" in value:
        raise UnsafePathError("caminho raiz vazio ou invalido")
    if _URI.match(value):
        raise UnsafePathError("use caminho local ou UNC, nao URL")
    lowered = value.replace("/", "\\").casefold()
    if lowered.startswith(_DEVICE_PREFIXES):
        raise UnsafePathError("namespace de dispositivo Windows nao e permitido")
    display_value = normalize_windows_display_path(value)
    unc = parse_unc_path(display_value)
    if require_absolute and unc is None:
        if _WINDOWS_DRIVE.match(display_value):
            if not PureWindowsPath(display_value).is_absolute():
                raise UnsafePathError("caminho Windows deve ser absoluto")
        elif not Path(display_value).expanduser().is_absolute():
            raise UnsafePathError("caminho raiz deve ser absoluto ou UNC")


def is_reparse_point(path: Path) -> bool:
    """Detecta links e reparse points, incluindo junctions em Python 3.10/3.11."""
    if path.is_symlink():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & _REPARSE_POINT)


def is_within(path: Path, root: Path) -> bool:
    """Compara caminhos canonicos usando a regra de caixa do sistema operacional."""
    candidate = os.path.normcase(os.path.normpath(str(path)))
    boundary = os.path.normcase(os.path.normpath(str(root)))
    try:
        return os.path.commonpath((candidate, boundary)) == boundary
    except ValueError:
        return False


def validate_report_targets(
    root: Path,
    targets: tuple[Path, ...],
    *,
    allow_inside_root: bool = False,
) -> None:
    """Impede sobrescrita entre relatorios e, por padrao, saida dentro da raiz lida."""
    canonical_root = root.expanduser().resolve(strict=True)
    normalized_targets: set[str] = set()
    for target in targets:
        requested = target.expanduser().absolute()
        if requested.is_symlink():
            raise UnsafePathError("relatorio nao pode substituir link simbolico")
        canonical_target = requested.resolve(strict=False)
        normalized = os.path.normcase(os.path.normpath(str(canonical_target)))
        if normalized in normalized_targets:
            raise UnsafePathError("cada relatorio deve usar um arquivo distinto")
        normalized_targets.add(normalized)
        if not allow_inside_root and is_within(canonical_target, canonical_root):
            raise UnsafePathError("relatorios devem ficar fora da raiz examinada")
