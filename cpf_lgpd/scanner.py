"""Motor de varredura de arquivos para CPFs validos."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .classification import (
    AnalysisConfig,
    ContextAnalyzer,
    redact_cpfs,
)
from .classification import (
    is_valid_cpf as is_valid_cpf,
)
from .extractors import SUPPORTED_EXTENSIONS, ExtractionError, ExtractionLimits, iter_text_path
from .permissions import LocalPermissionAdapter, PermissionAdapter
from .risk import GovernanceMetadata, RiskAssessment, ScoreWeights, assess_risk

DEFAULT_EXTENSIONS = SUPPORTED_EXTENSIONS


@dataclass(frozen=True)
class Finding:
    """Resultado agregado; nunca armazena o CPF encontrado."""

    path: str
    count: int
    unique_cpf_count: int
    detected_categories: list[dict[str, object]]
    risk: RiskAssessment
    cpf_hmac_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "file_path": self.path,
            "path": self.path,
            "cpf_count": self.count,
            "count": self.count,
            "unique_cpf_count": self.unique_cpf_count,
            "detected_categories": self.detected_categories,
            "cpf_hmac_ids": self.cpf_hmac_ids,
            **self.risk.to_dict(),
        }


@dataclass
class ScanResult:
    """Resumo serializavel de uma varredura."""

    root: str
    mode: str = "cpf-anchor"
    files_scanned: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    valid_cpfs: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, int] = field(default_factory=dict)
    scan_timed_out: bool = False

    def record_error(self, exception: BaseException) -> None:
        name = type(exception).__name__
        self.errors[name] = self.errors.get(name, 0) + 1
        self.files_failed += 1

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["findings"] = [finding.to_dict() for finding in self.findings]
        return payload


def _iter_files(
    root: Path, follow_symlinks: bool, on_error: Callable[[OSError], None]
) -> Iterator[Path]:
    for directory, directory_names, file_names in os.walk(
        root, followlinks=follow_symlinks, onerror=on_error
    ):
        directory_path = Path(directory)
        if not follow_symlinks:
            directory_names[:] = [
                name for name in directory_names if not (directory_path / name).is_symlink()
            ]
        for file_name in file_names:
            path = directory_path / file_name
            if follow_symlinks or not path.is_symlink():
                yield path


def _analyze_file(
    path: Path,
    limits: ExtractionLimits,
    ocr_language: str,
    analysis_config: AnalysisConfig,
):
    analyzer = ContextAnalyzer(analysis_config)
    for chunk in iter_text_path(path, limits, ocr_language):
        analyzer.feed(chunk)
    return analyzer.finish()


def scan_directory(
    root: Path,
    *,
    extensions: frozenset[str] = DEFAULT_EXTENSIONS,
    max_file_size: int = 50 * 1024 * 1024,
    follow_symlinks: bool = False,
    ocr_language: str = "por",
    extraction_limits: ExtractionLimits | None = None,
    mode: str = "cpf-anchor",
    context_window: int = 500,
    hmac_secret: bytes | None = None,
    permission_adapter: PermissionAdapter | None = None,
    governance: GovernanceMetadata | None = None,
    score_weights: ScoreWeights | None = None,
    max_processing_seconds: int | None = None,
) -> ScanResult:
    """Varre arquivos textuais dentro de ``root`` e retorna resultados agregados."""
    resolved_root = root.expanduser().resolve(strict=True)
    if not resolved_root.is_dir():
        raise NotADirectoryError(str(resolved_root))
    if max_file_size <= 0:
        raise ValueError("max_file_size deve ser positivo")
    if mode not in {"cpf-anchor", "full-discovery"}:
        raise ValueError("mode deve ser cpf-anchor ou full-discovery")
    if context_window < 0:
        raise ValueError("context_window nao pode ser negativo")
    if max_processing_seconds is not None and max_processing_seconds <= 0:
        raise ValueError("max_processing_seconds deve ser positivo")

    limits = extraction_limits or ExtractionLimits()
    adapter = permission_adapter or LocalPermissionAdapter()
    governance_metadata = governance or GovernanceMetadata()
    weights = score_weights or ScoreWeights()
    analysis_config = AnalysisConfig(context_window, mode, hmac_secret)
    result = ScanResult(root=redact_cpfs(str(resolved_root)), mode=mode)
    started_at = time.monotonic()
    for path in _iter_files(resolved_root, follow_symlinks, result.record_error):
        if max_processing_seconds and time.monotonic() - started_at >= max_processing_seconds:
            result.scan_timed_out = True
            result.errors["ProcessingTimeLimit"] = 1
            break
        try:
            if path.suffix.lower() not in extensions or path.stat().st_size > max_file_size:
                result.files_skipped += 1
                continue
            content = _analyze_file(path, limits, ocr_language, analysis_config)
            result.files_scanned += 1
            should_classify = bool(content.cpf_count) or (
                mode == "full-discovery" and bool(content.categories)
            )
            if should_classify:
                result.valid_cpfs += content.cpf_count
                permissions = adapter.assess(path)
                risk = assess_risk(path, content, permissions, governance_metadata, weights)
                result.findings.append(
                    Finding(
                        path=redact_cpfs(str(path)),
                        count=content.cpf_count,
                        unique_cpf_count=content.unique_cpf_count,
                        detected_categories=content.serializable_categories(),
                        risk=risk,
                        cpf_hmac_ids=content.cpf_hmac_ids,
                    )
                )
        except (ExtractionError, OSError, UnicodeError) as exception:
            result.record_error(exception)
    return result
