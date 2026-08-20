"""Motor deterministico, explicavel e minimizado de classificacao LGPD."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from dataclasses import asdict, dataclass, field

from .extractors import ExtractedField, ExtractedUnit
from .rules import RULESET_VERSION, SENSITIVE_RULES, SensitiveRule

CPF_PATTERN = re.compile(r"(?<!\d)(?:\d{3}[.\s-]?){2}\d{3}[-.\s]?\d{2}(?!\d)")

PERSONAL_RULES: dict[str, re.Pattern[str]] = {
    "nome": re.compile(r"\b(?:nome(?: completo)?|titular)\s*[:=]\s*\S+"),
    "email": re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b"),
    "telefone": re.compile(r"\b(?:telefone|celular|fone)\s*[:=]\s*\+?[\d ()-]{8,}"),
    "endereco": re.compile(r"\b(?:endereco|logradouro|cep)\s*[:=]\s*\S+"),
    "data_nascimento": re.compile(r"\b(?:data de nascimento|nascimento)\s*[:=]\s*\S+"),
    "documento": re.compile(r"\b(?:rg|cnh|passaporte|documento)\s*[:=]\s*\S+"),
    "informacao_profissional": re.compile(r"\b(?:cargo|emprego|empregador|matricula|profissao)\s*[:=]\s*\S+"),
    "financeiro": re.compile(r"\b(?:conta bancaria|agencia|salario|renda|cartao|pix)\s*[:=]\s*\S+"),
    "autenticacao": re.compile(r"\b(?:senha|password|token|login|credencial)\s*[:=]\s*\S+"),
    "crianca_adolescente": re.compile(r"\b(?:menor de idade|crianca|adolescente|responsavel legal)\s*[:=]\s*\S+"),
}

_PERSON_ANCHOR = re.compile(
    r"\b(?:nome(?: completo)?|titular|email|telefone|celular|rg|cnh|passaporte)\s*[:=]\s*\S+"
)
_AMBIGUITY: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"\b(?:possivel|talvez|suspeita|nao confirmado)\b"), 20),
    (re.compile(r"\b(?:desconhecido|nao informado|nao se aplica)\b"), 40),
    (re.compile(r"\b(?:exemplo|modelo|template|hipotetico)\b"), 60),
)


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return " ".join(
        "".join(character for character in normalized if not unicodedata.combining(character))
        .lower()
        .split()
    )


def digits_only(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def is_valid_cpf(value: str) -> bool:
    digits = digits_only(value)
    if len(digits) != 11 or len(set(digits)) == 1:
        return False
    for position in (9, 10):
        total = sum(int(digits[index]) * (position + 1 - index) for index in range(position))
        expected = 0 if total % 11 < 2 else 11 - total % 11
        if expected != int(digits[position]):
            return False
    return True


def confidence_level(score: int) -> str:
    if score >= 85:
        return "alta"
    if score >= 70:
        return "media"
    return "possivel_ocorrencia"


@dataclass
class CategoryDetection:
    category: str
    count: int = 0
    confidence_score: int = 0
    confidence_level: str = "possivel_ocorrencia"
    possible_occurrence: bool = True

    @property
    def confidence(self) -> str:
        return self.confidence_level

    def register(self, score: int, count: int = 1) -> None:
        self.count += count
        self.confidence_score = max(self.confidence_score, score)
        self.confidence_level = confidence_level(self.confidence_score)
        self.possible_occurrence = self.confidence_level == "possivel_ocorrencia"


@dataclass
class SensitiveOccurrence:
    location: dict[str, object]
    rule_id: str
    legal_category: str
    legal_basis: str
    subtype: str
    confidence_score: int
    confidence_level: str
    risk_points: int
    match_count: int
    requires_human_review: bool
    ruleset_version: str
    link_method: str
    person_anchor: str
    evidence_method: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AnalysisConfig:
    context_window: int = 500
    mode: str = "cpf-anchor"
    hmac_secret: bytes | None = None


@dataclass
class ContentAnalysis:
    cpf_count: int = 0
    unique_cpf_count: int = 0
    cpf_hmac_ids: list[str] = field(default_factory=list)
    categories: dict[str, CategoryDetection] = field(default_factory=dict)
    sensitive_occurrences: list[SensitiveOccurrence] = field(default_factory=list)
    confidence_score: int = 0
    ruleset_version: str = RULESET_VERSION

    def serializable_categories(self) -> list[dict[str, object]]:
        categories = [asdict(self.categories[name]) for name in sorted(self.categories)]
        if self.cpf_count:
            categories.insert(
                0,
                {
                    "category": "cpf",
                    "count": self.cpf_count,
                    "confidence_score": 100,
                    "confidence_level": "alta",
                    "possible_occurrence": False,
                },
            )
        return categories


def _valid_cpfs(value: str) -> list[str]:
    return [digits_only(match.group()) for match in CPF_PATTERN.finditer(value) if is_valid_cpf(match.group())]


def _rule_match_count(rule: SensitiveRule, value: str) -> int:
    return sum(len(re.findall(pattern, value)) for pattern in rule.positive_indicators)


def _negative_matches(rule: SensitiveRule, value: str) -> bool:
    return any(re.search(pattern, value) for pattern in rule.negative_indicators)


def _header_matches(rule: SensitiveRule, header: str | None, value: str) -> bool:
    normalized_header = normalize_text(header or "")
    return bool(value.strip()) and any(re.fullmatch(pattern, normalized_header) for pattern in rule.header_indicators)


def _ambiguity_penalty(value: str, base_penalty: int) -> int:
    penalty = base_penalty
    for pattern, points in _AMBIGUITY:
        if pattern.search(value):
            penalty = max(penalty, points)
    return min(max(penalty, 0), 60)


class ContextAnalyzer:
    """Analisa unidades estruturais e descarta texto e identificadores ao finalizar."""

    def __init__(self, config: AnalysisConfig):
        if config.mode not in {"cpf-anchor", "full-discovery"}:
            raise ValueError("mode deve ser cpf-anchor ou full-discovery")
        self.config = config
        self._analysis = ContentAnalysis()
        self._cpf_values: set[str] = set()
        self._buffer = ""
        self._line_number = 0
        self._occurrence_index: dict[tuple[str, str], SensitiveOccurrence] = {}

    def feed(self, text: str) -> None:
        """Compatibilidade para texto em blocos, com localizacao por linha."""
        self._buffer += text
        records = self._buffer.splitlines(keepends=True)
        if records and not records[-1].endswith(("\n", "\r")):
            self._buffer = records.pop()
        else:
            self._buffer = ""
        for record in records:
            self._feed_text_line(record.rstrip("\r\n"))

    def _feed_text_line(self, text: str) -> None:
        self._line_number += 1
        location = {"format": "text", "line": self._line_number}
        self.feed_unit(
            ExtractedUnit(
                (ExtractedField(text, None, location),),
                location,
                "direct_textual_statement",
            )
        )

    def feed_unit(self, unit: ExtractedUnit) -> None:
        unit_text = unit.text
        normalized_unit = normalize_text(unit_text)
        valid = _valid_cpfs(unit_text)
        self._analysis.cpf_count += len(valid)
        self._cpf_values.update(valid)
        cpf_anchor = bool(valid)
        explicit_person = bool(_PERSON_ANCHOR.search(normalized_unit))
        person_anchor = cpf_anchor or (self.config.mode == "full-discovery" and explicit_person)
        anchor_kind = "valid_cpf" if cpf_anchor else ("explicit_person_identifier" if person_anchor else "none")

        for category, pattern in PERSONAL_RULES.items():
            matches = len(pattern.findall(normalized_unit))
            if matches and person_anchor:
                detection = self._analysis.categories.setdefault(category, CategoryDetection(category))
                detection.register(100 if cpf_anchor else 80, matches)

        for rule in SENSITIVE_RULES:
            if _negative_matches(rule, normalized_unit):
                continue
            for unit_field in unit.fields:
                normalized_value = normalize_text(unit_field.text)
                view = (
                    normalize_text(f"{unit_field.header}: {unit_field.text}")
                    if unit_field.header
                    else normalized_value
                )
                match_count = _rule_match_count(rule, view)
                header_match = _header_matches(rule, unit_field.header, unit_field.text)
                if not match_count and not header_match:
                    continue
                evidence_points = 40 if header_match or re.search(r"[:=]\s*\S+", view) else 35
                evidence_method = (
                    "explicit_sensitive_header_with_value"
                    if evidence_points == 40
                    else "explicit_textual_statement"
                )
                link_points, link_method = self._link_points(unit, person_anchor)
                score = evidence_points + link_points + (20 if cpf_anchor else 0)
                score -= _ambiguity_penalty(normalized_unit, unit.ambiguity_penalty)
                if not person_anchor:
                    link_method = "none"
                score = max(0, min(score, 100))
                level = confidence_level(score)
                points = rule.risk_points[level]
                occurrence = SensitiveOccurrence(
                    location=dict(unit_field.location),
                    rule_id=rule.rule_id,
                    legal_category=rule.legal_category,
                    legal_basis=rule.legal_basis,
                    subtype=rule.subtype,
                    confidence_score=score,
                    confidence_level=level,
                    risk_points=points,
                    match_count=max(match_count, 1),
                    requires_human_review=True,
                    ruleset_version=rule.ruleset_version,
                    link_method=link_method,
                    person_anchor=anchor_kind,
                    evidence_method=evidence_method,
                )
                self._merge_occurrence(occurrence)
                detection = self._analysis.categories.setdefault(
                    rule.legal_category, CategoryDetection(rule.legal_category)
                )
                detection.register(score, max(match_count, 1))

    @staticmethod
    def _link_points(unit: ExtractedUnit, person_anchor: bool) -> tuple[int, str]:
        if not person_anchor:
            return 0, "none"
        if unit.link_method in {
            "same_structured_record",
            "same_json_object",
            "same_xml_element",
            "same_table_row",
            "sensitive_field_linked_to_person_record",
        }:
            return 40, unit.link_method
        if "line" in unit.location:
            return 40, "same_structured_record"
        if "paragraph" in unit.location:
            return 35, "direct_textual_statement"
        return 20, "same_context_window"

    def _merge_occurrence(self, occurrence: SensitiveOccurrence) -> None:
        key = (occurrence.rule_id, json.dumps(occurrence.location, sort_keys=True, ensure_ascii=False))
        current = self._occurrence_index.get(key)
        if current is None:
            self._occurrence_index[key] = occurrence
            return
        current.match_count += occurrence.match_count
        if occurrence.confidence_score > current.confidence_score:
            current.confidence_score = occurrence.confidence_score
            current.confidence_level = occurrence.confidence_level
            current.risk_points = occurrence.risk_points
            current.link_method = occurrence.link_method
            current.person_anchor = occurrence.person_anchor
            current.evidence_method = occurrence.evidence_method

    def finish(self) -> ContentAnalysis:
        if self._buffer:
            self._feed_text_line(self._buffer)
            self._buffer = ""
        self._analysis.unique_cpf_count = len(self._cpf_values)
        if self.config.hmac_secret:
            self._analysis.cpf_hmac_ids = sorted(
                hmac.new(self.config.hmac_secret, value.encode(), hashlib.sha256).hexdigest()
                for value in self._cpf_values
            )
        self._analysis.sensitive_occurrences = sorted(
            self._occurrence_index.values(),
            key=lambda item: (item.rule_id, json.dumps(item.location, sort_keys=True, ensure_ascii=False)),
        )
        confidence_values = [item.confidence_score for item in self._analysis.sensitive_occurrences]
        self._analysis.confidence_score = max(confidence_values, default=100 if self._cpf_values else 0)
        self._cpf_values.clear()
        self._occurrence_index.clear()
        return self._analysis


def redact_cpfs(value: str) -> str:
    """Mascara qualquer sequencia com formato de CPF, valida ou nao, em metadados."""
    return CPF_PATTERN.sub(lambda match: f"***.***.***-{digits_only(match.group())[-2:]}", value)


def analyze_chunks(chunks: list[str] | object, config: AnalysisConfig) -> ContentAnalysis:
    analyzer = ContextAnalyzer(config)
    for chunk in chunks:  # type: ignore[union-attr]
        analyzer.feed(chunk)
    return analyzer.finish()
