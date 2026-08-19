"""Relatorios estruturados sem conteudo original."""

from __future__ import annotations

import csv
import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from .scanner import ScanResult


def _csv_safe(value: str) -> str:
    """Impede que planilhas interpretem campos controlaveis como formulas."""
    return f"'{value}" if value.lstrip().startswith(("=", "+", "-", "@")) else value


def _atomic_write(
    path: Path, writer: Callable[[object], None], *, newline: str | None = None
) -> None:
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        os.chmod(temporary_name, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline=newline) as stream:
            writer(stream)
        os.replace(temporary_name, target)
        os.chmod(target, 0o600)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        Path(temporary_name).unlink(missing_ok=True)
        raise


def write_json_report(path: Path, result: ScanResult) -> None:
    def writer(stream: object) -> None:
        json.dump(result.to_dict(), stream, ensure_ascii=False, indent=2)  # type: ignore[arg-type]
        stream.write("\n")  # type: ignore[attr-defined]

    _atomic_write(path, writer)


def write_csv_report(path: Path, result: ScanResult) -> None:
    columns = [
        "file_path",
        "cpf_count",
        "unique_cpf_count",
        "risk_score",
        "risk_level",
        "confidence_score",
        "content_score",
        "exposure_score",
        "volume_score",
        "governance_score",
        "categories",
        "unknown_information",
        "requires_human_review",
    ]

    def writer(stream: object) -> None:
        output = csv.DictWriter(stream, fieldnames=columns)  # type: ignore[arg-type]
        output.writeheader()
        for finding in result.findings:
            output.writerow(
                {
                    "file_path": _csv_safe(finding.path),
                    "cpf_count": finding.count,
                    "unique_cpf_count": finding.unique_cpf_count,
                    "risk_score": finding.risk.risk_score,
                    "risk_level": finding.risk.risk_level,
                    "confidence_score": finding.risk.confidence_score,
                    "content_score": finding.risk.score_breakdown["content"],
                    "exposure_score": finding.risk.score_breakdown["exposure"],
                    "volume_score": finding.risk.score_breakdown["volume"],
                    "governance_score": finding.risk.score_breakdown["governance"],
                    "categories": ";".join(
                        item["category"] for item in finding.detected_categories
                    ),
                    "unknown_information": ";".join(finding.risk.unknown_information),
                    "requires_human_review": "true",
                }
            )

    _atomic_write(path, writer, newline="")
