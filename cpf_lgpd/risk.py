"""Metodologia explicavel de score e recomendacoes de remediacao."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .classification import ContentAnalysis
from .permissions import PermissionAssessment

SCORE_VERSION = "1.1"
ADDITIONAL_IDENTIFIERS = {
    "nome",
    "email",
    "telefone",
    "endereco",
    "data_nascimento",
    "documento",
    "informacao_profissional",
}
HIGH_IMPACT = {"financeiro", "autenticacao", "crianca_adolescente"}


@dataclass(frozen=True)
class ScoreWeights:
    cpf: int = 5
    additional_identifier: int = 2
    additional_cap: int = 10
    high_impact_one: int = 10
    high_impact_multiple: int = 15
    content_cap: int = 40
    exposure_unknown: int = 10
    owner_unknown: int = 5
    purpose_unknown: int = 5
    retention_unknown_or_expired: int = 5


@dataclass(frozen=True)
class GovernanceMetadata:
    purpose: str = "unknown"
    legal_basis: str = "unknown"
    origin: str = "unknown"
    retention_deadline: str = "unknown"
    max_age_days: int | None = None


@dataclass
class RiskAssessment:
    risk_score: int
    risk_level: str
    score_version: str
    confidence_score: int
    score_breakdown: dict[str, int]
    risk_factors: list[str]
    unknown_information: list[str]
    recommended_actions: list[str]
    requires_human_review: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def volume_score(unique_count: int) -> int:
    if unique_count <= 0:
        return 0
    if unique_count == 1:
        return 1
    if unique_count <= 9:
        return 3
    if unique_count <= 99:
        return 7
    if unique_count <= 999:
        return 11
    return 15


def risk_level(score: int) -> str:
    if score <= 19:
        return "baixo"
    if score <= 39:
        return "moderado"
    if score <= 59:
        return "alto"
    if score <= 79:
        return "muito_alto"
    return "critico"


def assess_risk(
    path: Path,
    content: ContentAnalysis,
    permissions: PermissionAssessment,
    governance: GovernanceMetadata,
    weights: ScoreWeights,
) -> RiskAssessment:
    categories = set(content.categories)
    sensitive_confidence: dict[str, str] = {}
    for occurrence in content.sensitive_occurrences:
        if occurrence.confidence_level not in {"media", "alta"}:
            continue
        previous = sensitive_confidence.get(occurrence.legal_category)
        if previous != "alta":
            sensitive_confidence[occurrence.legal_category] = occurrence.confidence_level
    scored_sensitive = set(sensitive_confidence)
    identifiers = categories & ADDITIONAL_IDENTIFIERS
    high_impact = categories & HIGH_IMPACT
    content_points = weights.cpf if content.cpf_count else 0
    content_points += min(len(identifiers) * weights.additional_identifier, weights.additional_cap)
    if high_impact:
        content_points += (
            weights.high_impact_one if len(high_impact) == 1 else weights.high_impact_multiple
        )
    if len(scored_sensitive) >= 2:
        content_points += 25
    elif len(scored_sensitive) == 1:
        only_category = next(iter(scored_sensitive))
        content_points += 20 if sensitive_confidence[only_category] == "alta" else 15
    content_points = max(0, min(content_points, 40, weights.content_cap))

    unknown: list[str] = []
    exposure = max(0, min(permissions.score, 30))
    if permissions.unknown:
        exposure = max(0, min(weights.exposure_unknown, 30))
        unknown.append("exposure")

    governance_points = 0
    if permissions.owner == "unknown":
        governance_points += weights.owner_unknown
        unknown.append("owner")
    if (
        governance.origin == "unknown"
        or governance.purpose == "unknown"
        or governance.legal_basis == "unknown"
    ):
        governance_points += weights.purpose_unknown
        unknown.extend(
            name
            for name, value in (
                ("origin", governance.origin),
                ("purpose", governance.purpose),
                ("legal_basis", governance.legal_basis),
            )
            if value == "unknown"
        )
    retention_problem = governance.retention_deadline == "unknown"
    if governance.max_age_days is not None:
        age_days = (datetime.now(timezone.utc).timestamp() - path.stat().st_mtime) / 86_400
        retention_problem = retention_problem or age_days > governance.max_age_days
    if retention_problem:
        governance_points += weights.retention_unknown_or_expired
        unknown.append("retention")
    governance_points = max(0, min(governance_points, 15))

    volume = volume_score(content.unique_cpf_count)
    breakdown = {
        "content": content_points,
        "exposure": exposure,
        "volume": volume,
        "governance": governance_points,
    }
    total = max(0, min(sum(breakdown.values()), 100))
    factors = []
    if identifiers:
        factors.append(f"{len(identifiers)} categoria(s) de identificadores adicionais")
    if high_impact:
        factors.append(f"{len(high_impact)} categoria(s) de alto impacto")
    if scored_sensitive:
        factors.append(f"{len(scored_sensitive)} categoria(s) sensiveis vinculadas")
    factors.append(f"exposicao: {permissions.level}")
    factors.append(f"volume: {content.unique_cpf_count} CPF(s) unico(s)")

    actions = ["submeter os indicadores a validacao humana"]
    if exposure >= 15 or permissions.unknown:
        actions.append("revisar e, se aprovado, restringir as permissoes de acesso")
    if permissions.owner == "unknown":
        actions.append("identificar e atribuir o proprietario do arquivo")
    if governance.origin == "unknown" or governance.purpose == "unknown":
        actions.append("documentar a origem e a finalidade do tratamento")
    if governance.legal_basis == "unknown":
        actions.append("validar a base legal com o encarregado ou Juridico")
    if retention_problem:
        actions.append("definir ou revisar o prazo de retencao")
        actions.append("avaliar eliminacao somente apos aprovacao do responsavel")
    if high_impact or scored_sensitive:
        actions.extend(
            [
                "avaliar mascaramento ou pseudonimizacao",
                "encaminhar para avaliacao de Privacidade e Seguranca da Informacao",
            ]
        )
    if total >= 60:
        actions.append("avaliar movimentacao para repositorio corporativo controlado")
    if total >= 80:
        actions.append("avaliar quarentena somente apos aprovacao")
    if permissions.level in {"external", "public", "anonymous"}:
        actions.append(
            "iniciar triagem de incidente se houver indicio de acesso ou divulgacao nao autorizada"
        )

    return RiskAssessment(
        total,
        risk_level(total),
        SCORE_VERSION,
        content.confidence_score,
        breakdown,
        factors,
        sorted(set(unknown)),
        list(dict.fromkeys(actions)),
    )
