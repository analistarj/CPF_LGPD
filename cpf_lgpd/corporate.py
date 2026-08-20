"""Preflight minimo para execucao corporativa controlada."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .path_security import path_kind, validate_root_syntax
from .permissions import PermissionAdapter, PermissionAssessment

CORPORATE_PROFILE_VERSION = "windows-corporate-1.0-rc1"


@dataclass(frozen=True)
class PreflightAssessment:
    root_kind: str
    directory_listable: bool
    permissions: PermissionAssessment
    profile_version: str = CORPORATE_PROFILE_VERSION

    @property
    def approved(self) -> bool:
        return self.directory_listable and self.permissions.source != "unavailable"


def preflight_root(
    root: Path | str,
    permission_adapter: PermissionAdapter,
    *,
    require_absolute_root: bool = True,
) -> PreflightAssessment:
    """Valida sintaxe, existencia, listagem e disponibilidade da fonte de permissoes."""
    original = str(root)
    validate_root_syntax(original, require_absolute=require_absolute_root)
    resolved = Path(root).expanduser().resolve(strict=True)
    if not resolved.is_dir():
        raise NotADirectoryError("raiz autorizada nao e diretorio")
    with os.scandir(resolved):
        pass
    permissions = permission_adapter.assess(resolved)
    return PreflightAssessment(path_kind(original), True, permissions)
