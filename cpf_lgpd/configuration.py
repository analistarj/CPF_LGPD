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


def _known_values(
    model: type,
    values: object,
    label: str,
) -> dict[str, object]:
    if not isinstance(values, dict):
        raise ValueError(f"{label} deve ser um objeto JSON")
    allowed = {item.name for item in fields(model)}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"chaves de configuracao desconhecidas: {', '.join(sorted(unknown))}")
    return dict(values)


def _validate_integer(
    values: dict[str, object],
    name: str,
    *,
    minimum: int,
    allow_none: bool = False,
) -> None:
    if name not in values:
        return
    value = values[name]
    if value is None and allow_none:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} deve ser inteiro maior ou igual a {minimum}")


def _validate_string(
    values: dict[str, object],
    name: str,
    *,
    choices: set[str] | None = None,
) -> None:
    if name not in values:
        return
    value = values[name]
    if not isinstance(value, str) or (choices is not None and value not in choices):
        raise ValueError(f"{name} possui valor ou tipo invalido")


def load_config(path: Path | None) -> ToolConfig:
    if path is None:
        return ToolConfig()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("a configuracao deve ser um objeto JSON")
    values = _known_values(ToolConfig, payload, "configuracao")
    weights_values = _known_values(ScoreWeights, values.pop("weights", {}), "weights")
    governance_values = _known_values(
        GovernanceMetadata,
        values.pop("governance", {}),
        "governance",
    )
    for name in weights_values:
        _validate_integer(weights_values, name, minimum=0)
    for name in ("purpose", "legal_basis", "origin", "retention_deadline"):
        _validate_string(governance_values, name)
    _validate_integer(governance_values, "max_age_days", minimum=0, allow_none=True)

    _validate_string(values, "mode", choices={"cpf-anchor", "full-discovery"})
    _validate_integer(values, "context_window", minimum=0)
    _validate_integer(values, "max_file_size_mb", minimum=1)
    _validate_integer(values, "max_age_days", minimum=0, allow_none=True)
    _validate_integer(values, "max_processing_seconds", minimum=1, allow_none=True)
    _validate_string(values, "permission_mode", choices={"strict", "best-effort"})
    _validate_string(
        values,
        "report_protection_mode",
        choices={"strict", "best-effort"},
    )
    for name in (
        "include_share_acl",
        "require_absolute_root",
        "allow_reports_inside_root",
    ):
        if name in values and not isinstance(values[name], bool):
            raise ValueError(f"{name} deve ser booleano")

    extension_values = values.pop("extensions", [])
    if not isinstance(extension_values, list) or any(
        not isinstance(value, str) or not value.strip() for value in extension_values
    ):
        raise ValueError("extensions deve ser uma lista de textos nao vazios")
    extensions = tuple(extension_values)
    weights = ScoreWeights(**weights_values)
    if values.get("max_age_days") is not None:
        governance_values.setdefault("max_age_days", values["max_age_days"])
    config = ToolConfig(
        **values,
        extensions=extensions,
        weights=weights,
        governance=GovernanceMetadata(**governance_values),
    )
    return config
