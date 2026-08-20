"""Carregamento estrito de configuracao local em JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass, fields
from pathlib import Path

from .risk import GovernanceMetadata, ScoreWeights


@dataclass(frozen=True)
class ToolConfig:
    mode: str = "cpf-anchor"
    context_window: int = 500
    max_file_size_mb: int = 50
    max_age_days: int | None = None
    max_processing_seconds: int | None = None
    extensions: tuple[str, ...] = ()
    permission_mode: str = "strict"
    include_share_acl: bool = True
    report_protection_mode: str = "strict"
    require_absolute_root: bool = True
    allow_reports_inside_root: bool = False
    weights: ScoreWeights = ScoreWeights()
    governance: GovernanceMetadata = GovernanceMetadata()


def _known_values(model: type, values: dict[str, object]) -> dict[str, object]:
    allowed = {item.name for item in fields(model)}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"chaves de configuracao desconhecidas: {', '.join(sorted(unknown))}")
    return values


def load_config(path: Path | None) -> ToolConfig:
    if path is None:
        return ToolConfig()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("a configuracao deve ser um objeto JSON")
    values = _known_values(ToolConfig, payload)
    weights = ScoreWeights(**_known_values(ScoreWeights, values.pop("weights", {})))
    governance_values = _known_values(GovernanceMetadata, values.pop("governance", {}))
    if values.get("max_age_days") is not None:
        governance_values.setdefault("max_age_days", values["max_age_days"])
    extensions = tuple(values.pop("extensions", ()))
    config = ToolConfig(
        **values,
        extensions=extensions,
        weights=weights,
        governance=GovernanceMetadata(**governance_values),
    )
    if config.permission_mode not in {"strict", "best-effort"}:
        raise ValueError("permission_mode deve ser strict ou best-effort")
    if config.report_protection_mode not in {"strict", "best-effort"}:
        raise ValueError("report_protection_mode deve ser strict ou best-effort")
    for name in (
        "include_share_acl",
        "require_absolute_root",
        "allow_reports_inside_root",
    ):
        if not isinstance(getattr(config, name), bool):
            raise ValueError(f"{name} deve ser booleano")
    return config
