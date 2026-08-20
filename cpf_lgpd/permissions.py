"""Adaptadores conservadores para sinais de exposicao e propriedade."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class PermissionAssessment:
    level: str = "unknown"
    score: int = 10
    owner: str = "unknown"
    unknown: bool = True
    source: str = "unavailable"


class PermissionAdapter(Protocol):
    def assess(self, path: Path) -> PermissionAssessment: ...


class LocalPermissionAdapter:
    """Interpreta bits POSIX sem presumir equivalencia com ACLs corporativas."""

    def assess(self, path: Path) -> PermissionAssessment:
        if os.name == "nt":
            return PermissionAssessment(source="windows_acl_adapter_not_configured")
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
