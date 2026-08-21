"""Relatorios tecnico e executivo sem conteudo ou valores pessoais."""

from __future__ import annotations

import csv
import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from .permissions import protect_report_path
from .scanner import ScanResult


def _csv_safe(value: object) -> object:
    if not isinstance(value, str):
        return value
    return f"'{value}" if value.lstrip().startswith(("=", "+", "-", "@")) else value


def _atomic_write(
    path: Path,
    writer: Callable[[object], None],
    *,
    newline: str | None = None,
    protection_mode: str = "strict",
) -> None:
    if protection_mode not in {"strict", "best-effort"}:
        raise ValueError("protection_mode deve ser strict ou best-effort")
    requested = path.expanduser().absolute()
    if requested.is_symlink():
        raise OSError("destino do relatorio nao pode ser link simbolico")
    target = requested.resolve(strict=False)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        protect_report_path(Path(temporary_name), strict=protection_mode == "strict")
        with os.fdopen(descriptor, "w", encoding="utf-8", newline=newline) as stream:
            writer(stream)
        # O temporario fica no mesmo diretorio, portanto os.replace preserva
        # o descritor de seguranca ou o modo ja aplicado ao proprio arquivo.
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _write_json(
    path: Path, result: ScanResult, report_level: str, protection_mode: str = "strict"
) -> None:
    def writer(stream: object) -> None:
        json.dump(result.to_dict(report_level), stream, ensure_ascii=False, indent=2)  # type: ignore[arg-type]
        stream.write("\n")  # type: ignore[attr-defined]

    _atomic_write(path, writer, protection_mode=protection_mode)


def write_json_report(
    path: Path, result: ScanResult, *, protection_mode: str = "strict"
) -> None:
    """Grava o relatorio tecnico protegido, incluindo caminhos completos."""
    _write_json(path, result, "technical", protection_mode)


def write_executive_json_report(
    path: Path, result: ScanResult, *, protection_mode: str = "strict"
) -> None:
    """Grava o relatorio executivo protegido, somente com raiz logica e relativo."""
    _write_json(path, result, "executive", protection_mode)


_CSV_COLUMNS = [
    "file_path",
    "relative_path",
    "root_id",
    "location",
    "rule_id",
    "legal_category",
    "subtype",
    "confidence_score",
    "confidence_level",
    "risk_points",
    "match_count",
    "requires_human_review",
    "ruleset_version",
    "score_version",
    "risk_score",
    "risk_level",
    "content_score",
    "exposure_score",
    "volume_score",
    "governance_score",
    "cpf_count",
    "unique_cpf_count",
    "original_path",
    "absolute_or_unc_path",
    "canonical_path",
    "name",
    "extension",
    "size_bytes",
    "created_at",
    "last_modified_at",
    "technical_owner",
    "permissions_source",
    "permission_level",
    "permissions_assessed",
    "acl_inheritance",
    "share_acl_evaluated",
    "path_kind",
    "created_by",
    "last_modified_by",
]


def _csv_rows(result: ScanResult, report_level: str):
    for finding in result.findings:
        payload = finding.to_dict(report_level)
        trace = finding.trace.to_dict(report_level)
        occurrences = finding.occurrences or [{}]
        for occurrence in occurrences:
            location = occurrence.get("location", {})
            row = {
                "file_path": trace["file_path"],
                "relative_path": trace["relative_path"],
                "root_id": trace["root_id"],
                "location": (
                    json.dumps(
                        location,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    if location
                    else ""
                ),
                "rule_id": occurrence.get("rule_id", ""),
                "legal_category": occurrence.get("legal_category", ""),
                "subtype": occurrence.get("subtype", ""),
                "confidence_score": occurrence.get("confidence_score", payload["confidence_score"]),
                "confidence_level": occurrence.get("confidence_level", ""),
                "risk_points": occurrence.get("risk_points", 0),
                "match_count": occurrence.get("match_count", 0),
                "requires_human_review": "true",
                "ruleset_version": occurrence.get("ruleset_version", payload["ruleset_version"]),
                "score_version": payload["score_version"],
                "risk_score": payload["risk_score"],
                "risk_level": payload["risk_level"],
                "content_score": payload["score_breakdown"]["content"],
                "exposure_score": payload["score_breakdown"]["exposure"],
                "volume_score": payload["score_breakdown"]["volume"],
                "governance_score": payload["score_breakdown"]["governance"],
                "cpf_count": finding.count,
                "unique_cpf_count": finding.unique_cpf_count,
                "original_path": trace.get("original_path", ""),
                "absolute_or_unc_path": trace.get("absolute_or_unc_path", ""),
                "canonical_path": trace.get("canonical_path", ""),
                "name": trace["name"],
                "extension": trace["extension"],
                "size_bytes": trace["size_bytes"],
                "created_at": trace["created_at"],
                "last_modified_at": trace["last_modified_at"],
                "technical_owner": trace.get("technical_owner", ""),
                "permissions_source": trace.get("permissions_source", ""),
                "permission_level": trace.get("permission_level", ""),
                "permissions_assessed": trace.get("permissions_assessed", ""),
                "acl_inheritance": trace.get("acl_inheritance", ""),
                "share_acl_evaluated": trace.get("share_acl_evaluated", ""),
                "path_kind": trace.get("path_kind", ""),
                "created_by": trace["created_by"],
                "last_modified_by": trace["last_modified_by"],
            }
            yield {name: _csv_safe(row[name]) for name in _CSV_COLUMNS}


def _write_csv(
    path: Path, result: ScanResult, report_level: str, protection_mode: str = "strict"
) -> None:
    def writer(stream: object) -> None:
        output = csv.DictWriter(stream, fieldnames=_CSV_COLUMNS)  # type: ignore[arg-type]
        output.writeheader()
        output.writerows(_csv_rows(result, report_level))

    _atomic_write(path, writer, newline="", protection_mode=protection_mode)


def write_csv_report(
    path: Path, result: ScanResult, *, protection_mode: str = "strict"
) -> None:
    """Grava CSV tecnico protegido."""
    _write_csv(path, result, "technical", protection_mode)


def write_executive_csv_report(
    path: Path, result: ScanResult, *, protection_mode: str = "strict"
) -> None:
    """Grava CSV executivo protegido sem caminhos completos."""
    _write_csv(path, result, "executive", protection_mode)
