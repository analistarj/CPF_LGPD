"""Varredura segura, rastreavel e confinada a raizes autorizadas."""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .classification import (
    AnalysisConfig,
    ContextAnalyzer,
    redact_cpfs,
)
from .classification import is_valid_cpf as is_valid_cpf
from .corporate import CORPORATE_PROFILE_VERSION
from .extractors import (
    SUPPORTED_EXTENSIONS,
    ExtractionError,
    ExtractionLimits,
    iter_units_path,
)
from .path_security import (
    PATH_POLICY_VERSION,
    is_reparse_point,
    is_within,
    path_kind,
    validate_root_syntax,
)
from .permissions import (
    PERMISSION_POLICY_VERSION,
    PermissionAdapter,
    PermissionAssessment,
    default_permission_adapter,
)
from .risk import SCORE_VERSION, GovernanceMetadata, RiskAssessment, ScoreWeights, assess_risk
from .rules import RULESET_VERSION, ruleset_metadata
from .version import APPLICATION_VERSION

DEFAULT_EXTENSIONS = SUPPORTED_EXTENSIONS
_URL_CREDENTIALS = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)([^/@\s]+)@")
_SECRET_QUERY = re.compile(r"(?i)([?&](?:token|password|passwd|secret|key|sig|credential)=)[^&#/\\]+")


class PathEscapeError(OSError):
    """Caminho canonico saiu da raiz autorizada."""


class FileChangedDuringScanError(OSError):
    """Arquivo ou redirecionamento mudou durante a leitura."""


def sanitize_metadata(value: str) -> str:
    """Remove CPFs em formato numerico e credenciais incorporadas em caminhos/URLs."""
    value = _URL_CREDENTIALS.sub(r"\1[credentials-redacted]@", value)
    value = _SECRET_QUERY.sub(r"\1[redacted]", value)
    return redact_cpfs(value)


def _sanitize_structure(value: object) -> object:
    if isinstance(value, str):
        return sanitize_metadata(value)
    if isinstance(value, dict):
        return {str(key): _sanitize_structure(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize_structure(item) for item in value]
    return value


def _iso_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


@dataclass(frozen=True)
class FileTrace:
    root_id: str
    original_path: str
    absolute_or_unc_path: str
    canonical_path: str
    relative_path: str
    name: str
    extension: str
    size_bytes: int
    created_at: str
    last_modified_at: str
    technical_owner: str
    permissions_source: str
    permission_level: str = "unknown"
    permissions_assessed: bool = False
    acl_inheritance: str = "unknown"
    share_acl_evaluated: bool = False
    path_kind: str = "local"
    created_by: str = "unknown"
    last_modified_by: str = "unknown"

    def to_dict(self, report_level: str) -> dict[str, object]:
        common = {
            "root_id": self.root_id,
            "relative_path": self.relative_path,
            "name": self.name,
            "extension": self.extension,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at,
            "last_modified_at": self.last_modified_at,
            "created_by": self.created_by,
            "last_modified_by": self.last_modified_by,
            "path_kind": self.path_kind,
        }
        if report_level == "technical":
            return {
                "file_path": self.canonical_path,
                "original_path": self.original_path,
                "absolute_or_unc_path": self.absolute_or_unc_path,
                "canonical_path": self.canonical_path,
                "technical_owner": self.technical_owner,
                "permissions_source": self.permissions_source,
                "permission_level": self.permission_level,
                "permissions_assessed": self.permissions_assessed,
                "acl_inheritance": self.acl_inheritance,
                "share_acl_evaluated": self.share_acl_evaluated,
                **common,
            }
        return {"file_path": self.relative_path, **common}


@dataclass(frozen=True)
class Finding:
    """Resultado agregado que nunca contem valores pessoais ou trechos."""

    trace: FileTrace
    count: int
    unique_cpf_count: int
    detected_categories: list[dict[str, object]]
    occurrences: list[dict[str, object]]
    risk: RiskAssessment
    cpf_hmac_ids: list[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.trace.canonical_path

    def to_dict(self, report_level: str = "technical") -> dict[str, object]:
        trace = self.trace.to_dict(report_level)
        return {
            **trace,
            "cpf_count": self.count,
            "count": self.count,
            "unique_cpf_count": self.unique_cpf_count,
            "detected_categories": self.detected_categories,
            "occurrences": self.occurrences,
            "cpf_hmac_ids": self.cpf_hmac_ids,
            "ruleset_version": RULESET_VERSION,
            **self.risk.to_dict(),
        }


@dataclass
class ScanResult:
    """Inventario e achados serializaveis em nivel tecnico ou executivo."""

    root: str
    root_id: str
    mode: str = "cpf-anchor"
    files_scanned: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    valid_cpfs: int = 0
    files: list[FileTrace] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, int] = field(default_factory=dict)
    scan_timed_out: bool = False
    ruleset_version: str = RULESET_VERSION
    score_version: str = SCORE_VERSION
    application_version: str = APPLICATION_VERSION
    corporate_profile_version: str = CORPORATE_PROFILE_VERSION
    path_policy_version: str = PATH_POLICY_VERSION
    permission_policy_version: str = PERMISSION_POLICY_VERSION

    def record_error(self, exception: BaseException) -> None:
        name = type(exception).__name__
        self.errors[name] = self.errors.get(name, 0) + 1
        self.files_failed += 1

    def to_dict(self, report_level: str = "technical") -> dict[str, object]:
        if report_level not in {"technical", "executive"}:
            raise ValueError("report_level deve ser technical ou executive")
        return {
            "report_level": report_level,
            "root": self.root if report_level == "technical" else self.root_id,
            "root_id": self.root_id,
            "mode": self.mode,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "files_failed": self.files_failed,
            "valid_cpfs": self.valid_cpfs,
            "files": [item.to_dict(report_level) for item in self.files],
            "findings": [finding.to_dict(report_level) for finding in self.findings],
            "errors": dict(sorted(self.errors.items())),
            "scan_timed_out": self.scan_timed_out,
            "ruleset_version": self.ruleset_version,
            "ruleset": ruleset_metadata(),
            "score_version": self.score_version,
            "application_version": self.application_version,
            "corporate_profile_version": self.corporate_profile_version,
            "path_policy_version": self.path_policy_version,
            "permission_policy_version": self.permission_policy_version,
        }


def _iter_files(root: Path, follow_symlinks: bool, on_error: Callable[[OSError], None]) -> Iterator[Path]:
    seen_directories: set[Path] = set()
    for directory, directory_names, file_names in os.walk(root, followlinks=follow_symlinks, onerror=on_error):
        directory_path = Path(directory)
        try:
            canonical_directory = directory_path.resolve(strict=True)
        except OSError as exception:
            on_error(exception)
            directory_names[:] = []
            continue
        if not is_within(canonical_directory, root) or canonical_directory in seen_directories:
            directory_names[:] = []
            if not is_within(canonical_directory, root):
                on_error(PathEscapeError())
            continue
        seen_directories.add(canonical_directory)
        safe_directories = []
        for name in sorted(directory_names):
            candidate = directory_path / name
            if is_reparse_point(candidate) and not follow_symlinks:
                continue
            try:
                canonical = candidate.resolve(strict=True)
            except OSError as exception:
                on_error(exception)
                continue
            if is_within(canonical, root):
                safe_directories.append(name)
            else:
                on_error(PathEscapeError())
        directory_names[:] = safe_directories
        for file_name in sorted(file_names):
            path = directory_path / file_name
            if is_reparse_point(path) and not follow_symlinks:
                continue
            yield path


def _root_identifier(canonical_root: Path) -> str:
    normalized = os.path.normcase(str(canonical_root))
    return f"root-{hashlib.sha256(normalized.encode()).hexdigest()[:16]}"


def _file_trace(
    path: Path,
    canonical_path: Path,
    canonical_root: Path,
    original_root: str,
    root_id: str,
    metadata: os.stat_result,
    permissions: PermissionAssessment,
) -> FileTrace:
    relative = canonical_path.relative_to(canonical_root)
    original_path = str(Path(original_root) / relative)
    absolute_path = str(path) if str(path).startswith("\\\\") else str(path.absolute())
    if hasattr(metadata, "st_birthtime"):
        created_at = _iso_timestamp(metadata.st_birthtime)  # type: ignore[attr-defined]
    elif os.name == "nt":
        created_at = _iso_timestamp(metadata.st_ctime)
    else:
        created_at = "unknown"
    return FileTrace(
        root_id=root_id,
        original_path=sanitize_metadata(original_path),
        absolute_or_unc_path=sanitize_metadata(absolute_path),
        canonical_path=sanitize_metadata(str(canonical_path)),
        relative_path=sanitize_metadata(str(relative)),
        name=sanitize_metadata(canonical_path.name),
        extension=canonical_path.suffix.lower(),
        size_bytes=metadata.st_size,
        created_at=created_at,
        last_modified_at=_iso_timestamp(metadata.st_mtime),
        technical_owner=sanitize_metadata(permissions.owner),
        permissions_source=permissions.source,
        permission_level=permissions.level,
        permissions_assessed=not permissions.unknown,
        acl_inheritance=permissions.acl_inheritance,
        share_acl_evaluated=permissions.share_acl_evaluated,
        path_kind=path_kind(original_root),
    )


def _analyze_file(path: Path, limits: ExtractionLimits, ocr_language: str, analysis_config: AnalysisConfig):
    analyzer = ContextAnalyzer(analysis_config)
    for unit in iter_units_path(path, limits, ocr_language):
        analyzer.feed_unit(unit)
    return analyzer.finish()


def scan_directory(
    root: Path | str,
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
    root_id: str | None = None,
    include_share_acl: bool = True,
    require_windows_acl: bool = True,
    require_absolute_root: bool = True,
) -> ScanResult:
    """Varre arquivos sem permitir que resolucao canonica escape da raiz autorizada."""
    original_root = str(root)
    validate_root_syntax(original_root, require_absolute=require_absolute_root)
    root_path = Path(root)
    resolved_root = root_path.expanduser().resolve(strict=True)
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
    if root_id is not None and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", root_id):
        raise ValueError("root_id contem caracteres nao permitidos")

    limits = extraction_limits or ExtractionLimits()
    adapter = permission_adapter or default_permission_adapter(
        include_share_acl=include_share_acl,
        require_windows_acl=require_windows_acl,
    )
    governance_metadata = governance or GovernanceMetadata()
    weights = score_weights or ScoreWeights()
    analysis_config = AnalysisConfig(context_window, mode, hmac_secret)
    effective_root_id = root_id or _root_identifier(resolved_root)
    result = ScanResult(sanitize_metadata(str(resolved_root)), effective_root_id, mode=mode)
    started_at = time.monotonic()
    for path in _iter_files(resolved_root, follow_symlinks, result.record_error):
        if max_processing_seconds and time.monotonic() - started_at >= max_processing_seconds:
            result.scan_timed_out = True
            result.errors["ProcessingTimeLimit"] = 1
            break
        try:
            canonical_path = path.resolve(strict=True)
            if not is_within(canonical_path, resolved_root):
                raise PathEscapeError()
            metadata = canonical_path.stat()
            if canonical_path.suffix.lower() not in extensions or metadata.st_size > max_file_size:
                result.files_skipped += 1
                continue
            permissions = adapter.assess(canonical_path)
            trace = _file_trace(
                path,
                canonical_path,
                resolved_root,
                original_root,
                effective_root_id,
                metadata,
                permissions,
            )
            result.files.append(trace)
            content = _analyze_file(canonical_path, limits, ocr_language, analysis_config)
            final_path = path.resolve(strict=True)
            final_metadata = final_path.stat()
            identity_before = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
            identity_after = (
                final_metadata.st_dev,
                final_metadata.st_ino,
                final_metadata.st_size,
                final_metadata.st_mtime_ns,
            )
            if (
                final_path != canonical_path
                or not is_within(final_path, resolved_root)
                or identity_before != identity_after
            ):
                raise FileChangedDuringScanError()
            result.files_scanned += 1
            should_classify = bool(content.cpf_count) or (
                mode == "full-discovery" and bool(content.sensitive_occurrences)
            )
            if should_classify:
                result.valid_cpfs += content.cpf_count
                risk = assess_risk(canonical_path, content, permissions, governance_metadata, weights)
                occurrences = [
                    {
                        **occurrence.to_dict(),
                        "location": _sanitize_structure(occurrence.location),
                        "score_version": SCORE_VERSION,
                    }
                    for occurrence in content.sensitive_occurrences
                ]
                result.findings.append(
                    Finding(
                        trace=trace,
                        count=content.cpf_count,
                        unique_cpf_count=content.unique_cpf_count,
                        detected_categories=content.serializable_categories(),
                        occurrences=occurrences,
                        risk=risk,
                        cpf_hmac_ids=content.cpf_hmac_ids,
                    )
                )
        except (ExtractionError, OSError, UnicodeError) as exception:
            result.record_error(exception)
    return result
