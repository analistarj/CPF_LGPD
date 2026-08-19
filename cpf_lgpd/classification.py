"""Deteccao contextual deterministica e classificacao explicavel de risco."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import asdict, dataclass, field

CPF_PATTERN = re.compile(r"(?<!\d)(?:\d{3}[.\s-]?){2}\d{3}[-.\s]?\d{2}(?!\d)")


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


CONFIDENCE_VALUES = {"baixa": 30, "media": 70, "alta": 90}

PERSONAL_RULES: dict[str, re.Pattern[str]] = {
    "nome": re.compile(r"\b(?:nome(?:\s+completo)?|titular)\s*[:=]", re.I),
    "email": re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", re.I),
    "telefone": re.compile(r"(?:\btelefone|\bcelular|\bfone)\s*[:=]?\s*\+?[\d ()-]{8,}", re.I),
    "endereco": re.compile(r"\b(?:endere[cç]o|logradouro|cep)\s*[:=]", re.I),
    "data_nascimento": re.compile(r"\b(?:data\s+de\s+nascimento|nascimento)\s*[:=]", re.I),
    "documento": re.compile(r"\b(?:rg|cnh|passaporte|documento)\s*[:=]", re.I),
    "informacao_profissional": re.compile(
        r"\b(?:cargo|emprego|empregador|matr[ií]cula|profiss[aã]o)\s*[:=]", re.I
    ),
    "financeiro": re.compile(
        r"\b(?:conta\s+banc[aá]ria|ag[eê]ncia|sal[aá]rio|renda|cart[aã]o|pix)\s*[:=]", re.I
    ),
    "autenticacao": re.compile(r"\b(?:senha|password|token|login|credencial)\s*[:=]", re.I),
    "crianca_adolescente": re.compile(
        r"\b(?:menor\s+de\s+idade|crian[cç]a|adolescente|respons[aá]vel\s+legal)\s*[:=]", re.I
    ),
}

SENSITIVE_RULES: dict[str, re.Pattern[str]] = {
    "origem_racial_etnica": re.compile(r"\b(?:ra[cç]a|etnia|origem\s+[eé]tnica)\s*[:=]", re.I),
    "conviccao_religiosa": re.compile(
        r"\b(?:religi[aã]o|convic[cç][aã]o\s+religiosa|credo)\s*[:=]", re.I
    ),
    "opiniao_politica": re.compile(
        r"\b(?:opini[aã]o|posicionamento|prefer[eê]ncia)\s+pol[ií]tica\s*[:=]", re.I
    ),
    "filiacao_sindical": re.compile(
        r"\b(?:filia[cç][aã]o\s+sindical|sindicato\s+filiado)\s*[:=]", re.I
    ),
    "filiacao_organizacao": re.compile(
        r"\bfilia[cç][aã]o\s+(?:religiosa|filos[oó]fica|pol[ií]tica)\s*[:=]", re.I
    ),
    "saude": re.compile(
        r"\b(?:diagn[oó]stico|doen[cç]a|tratamento|prontu[aá]rio|condi[cç][aã]o\s+de\s+sa[uú]de)\s*[:=]",
        re.I,
    ),
    "vida_sexual": re.compile(r"\b(?:vida|orienta[cç][aã]o|comportamento)\s+sexual\s*[:=]", re.I),
    "genetico": re.compile(r"\b(?:dado|teste|perfil|sequenciamento)\s+gen[eé]tico\s*[:=]", re.I),
    "biometrico": re.compile(
        r"\b(?:biometria|impress[aã]o\s+digital|reconhecimento\s+facial|[ií]ris)\s*[:=]", re.I
    ),
}


@dataclass
class CategoryDetection:
    category: str
    count: int = 0
    confidence: str = "baixa"
    possible_occurrence: bool = False

    def register(self, confidence: str) -> None:
        self.count += 1
        if CONFIDENCE_VALUES[confidence] > CONFIDENCE_VALUES[self.confidence]:
            self.confidence = confidence
        self.possible_occurrence = self.confidence == "baixa"

    def promote(self, confidence: str) -> None:
        if CONFIDENCE_VALUES[confidence] > CONFIDENCE_VALUES[self.confidence]:
            self.confidence = confidence
        self.possible_occurrence = self.confidence == "baixa"


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
    confidence_score: int = 0

    def serializable_categories(self) -> list[dict[str, object]]:
        categories = [asdict(self.categories[name]) for name in sorted(self.categories)]
        if self.cpf_count:
            categories.insert(
                0,
                {
                    "category": "cpf",
                    "count": self.cpf_count,
                    "confidence": "alta",
                    "possible_occurrence": False,
                },
            )
        return categories


class ContextAnalyzer:
    """Analisa registros sem reter trechos originais depois da finalizacao."""

    def __init__(self, config: AnalysisConfig):
        self.config = config
        self._buffer = ""
        self._cpf_values: set[str] = set()
        self._analysis = ContentAnalysis()
        self._cpf_distance = config.context_window + 1
        self._pending: list[tuple[str, int]] = []

    def feed(self, text: str) -> None:
        self._buffer += text
        records = re.split(r"[\r\n]+", self._buffer)
        self._buffer = records.pop()
        for record in records:
            self._analyze_record(record)
        maximum_buffer = max(self.config.context_window * 2, 4096)
        while len(self._buffer) > maximum_buffer:
            boundary = len(self._buffer) - self.config.context_window
            self._analyze_record(self._buffer[:boundary])
            self._buffer = self._buffer[boundary:]

    def finish(self) -> ContentAnalysis:
        if self._buffer:
            self._analyze_record(self._buffer)
        self._analysis.unique_cpf_count = len(self._cpf_values)
        if self.config.hmac_secret:
            self._analysis.cpf_hmac_ids = sorted(
                hmac.new(self.config.hmac_secret, value.encode(), hashlib.sha256).hexdigest()
                for value in self._cpf_values
            )
        confidences = [
            CONFIDENCE_VALUES[item.confidence] for item in self._analysis.categories.values()
        ]
        if self._cpf_values:
            confidences.append(90)
        self._analysis.confidence_score = (
            round(sum(confidences) / len(confidences)) if confidences else 0
        )
        self._buffer = ""
        self._cpf_values.clear()
        return self._analysis

    def _analyze_record(self, record: str) -> None:
        if not record:
            return
        self._cpf_distance += len(record) + 1
        self._pending = [
            (category, remaining - len(record) - 1)
            for category, remaining in self._pending
            if remaining - len(record) - 1 >= 0
        ]
        valid = [
            digits_only(match.group())
            for match in CPF_PATTERN.finditer(record)
            if is_valid_cpf(match.group())
        ]
        self._analysis.cpf_count += len(valid)
        self._cpf_values.update(valid)
        if valid:
            for category, _remaining in self._pending:
                self._analysis.categories[category].promote("media")
            self._pending.clear()
            self._cpf_distance = 0
        linked_confidence = (
            "alta"
            if valid
            else ("media" if self._cpf_distance <= self.config.context_window else "baixa")
        )
        for category, pattern in PERSONAL_RULES.items():
            matches = pattern.findall(record)
            for _match in matches:
                self._register(category, linked_confidence)
        for category, pattern in SENSITIVE_RULES.items():
            matches = pattern.findall(record)
            for _match in matches:
                self._register(category, linked_confidence)

    def _register(self, category: str, confidence: str) -> None:
        detection = self._analysis.categories.setdefault(category, CategoryDetection(category))
        detection.register(confidence)
        if confidence == "baixa":
            self._pending.append((category, self.config.context_window))


def redact_cpfs(value: str) -> str:
    """Mascara somente candidatos matematicamente validos encontrados em texto ou caminho."""
    return CPF_PATTERN.sub(
        lambda match: (
            f"***.***.***-{digits_only(match.group())[-2:]}"
            if is_valid_cpf(match.group())
            else match.group()
        ),
        value,
    )


def analyze_chunks(chunks: list[str] | object, config: AnalysisConfig) -> ContentAnalysis:
    analyzer = ContextAnalyzer(config)
    for chunk in chunks:  # type: ignore[union-attr]
        analyzer.feed(chunk)
    return analyzer.finish()
