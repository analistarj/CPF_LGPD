"""Taxonomia legal e regras deterministicas de dados pessoais sensiveis."""

from __future__ import annotations

from dataclasses import asdict, dataclass

RULESET_VERSION = "lgpd-br-1.0.0"
LEGAL_BASIS = "LGPD_ART_5_II"

LEGAL_CATEGORIES = (
    "racial_ethnic_origin",
    "religious_belief",
    "political_opinion",
    "union_membership",
    "religious_philosophical_political_organization_membership",
    "health",
    "sexual_life",
    "genetic",
    "biometric",
)

REQUIRED_LINK_METHODS = (
    "same_structured_record",
    "same_json_object",
    "same_xml_element",
    "sensitive_field_linked_to_person_record",
    "direct_textual_statement",
    "same_table_row",
)


@dataclass(frozen=True)
class SensitiveRule:
    rule_id: str
    legal_category: str
    legal_basis: str
    subtype: str
    ruleset_version: str
    positive_indicators: tuple[str, ...]
    negative_indicators: tuple[str, ...]
    required_person_anchor: bool
    required_link_method: tuple[str, ...]
    confidence_calculation: str
    risk_points: dict[str, int]
    header_indicators: tuple[str, ...] = ()

    def public_metadata(self) -> dict[str, object]:
        payload = asdict(self)
        payload.pop("header_indicators")
        return payload


_CONFIDENCE_FORMULA = (
    "cpf_valido=20; mesmo_registro=40; declaracao_direta_mesmo_periodo=35; "
    "mesmo_paragrafo_ou_janela=20; cabecalho_explicito_com_valor=40; "
    "declaracao_textual_explicita=35; indicador=15; ambiguidade=-20..-60; "
    "regra_negativa=0"
)
_RISK_POINTS = {"alta": 20, "media": 15, "possivel_ocorrencia": 0}


def _rule(
    rule_id: str,
    category: str,
    subtype: str,
    positives: tuple[str, ...],
    negatives: tuple[str, ...],
    headers: tuple[str, ...],
) -> SensitiveRule:
    return SensitiveRule(
        rule_id=rule_id,
        legal_category=category,
        legal_basis=LEGAL_BASIS,
        subtype=subtype,
        ruleset_version=RULESET_VERSION,
        positive_indicators=positives,
        negative_indicators=negatives,
        required_person_anchor=True,
        required_link_method=REQUIRED_LINK_METHODS,
        confidence_calculation=_CONFIDENCE_FORMULA,
        risk_points=dict(_RISK_POINTS),
        header_indicators=headers,
    )


SENSITIVE_RULES: tuple[SensitiveRule, ...] = (
    _rule(
        "LGPD-SENS-001",
        "racial_ethnic_origin",
        "racial_ethnic_origin",
        (
            r"\b(?:raca|etnia|origem etnica)\s*[:=]\s*\S+",
            r"\b(?:declara|informa|identifica-se como)\s+(?:raca|etnia|origem etnica)\b",
        ),
        (r"\braca de cachorro\b", r"\braca canina\b"),
        (r"^(?:raca|etnia|origem etnica)$",),
    ),
    _rule(
        "LGPD-SENS-002",
        "religious_belief",
        "religious_belief",
        (
            r"\b(?:religiao|crenca religiosa|conviccao religiosa|credo)\s*[:=]\s*\S+",
            r"\b(?:declara|informa|professa)\s+(?:religiao|crenca|credo)\b",
        ),
        (
            r"\bigreja\s+(?:situada|localizada|endereco|fica)\b",
            r"\b(?:rua|avenida|av\.)\s+[^\n,;]*\bigreja\b",
        ),
        (r"^(?:religiao|crenca religiosa|conviccao religiosa|credo)$",),
    ),
    _rule(
        "LGPD-SENS-003",
        "political_opinion",
        "political_position",
        (
            r"\bposicionamento politico\s*[:=]\s*\S+",
            r"\b(?:declara|informa)\s+(?:seu\s+)?posicionamento politico\b",
        ),
        (r"\bpolitica de (?:privacidade|seguranca|comercial)\b", r"\bpartido ao meio\b"),
        (r"^posicionamento politico$",),
    ),
    _rule(
        "LGPD-SENS-004",
        "political_opinion",
        "political_preference",
        (
            r"\bpreferencia politica\s*[:=]\s*\S+",
            r"\b(?:declara|informa)\s+(?:sua\s+)?preferencia politica\b",
        ),
        (r"\bpolitica de (?:privacidade|seguranca|comercial)\b", r"\bpartido ao meio\b"),
        (r"^preferencia politica$",),
    ),
    _rule(
        "LGPD-SENS-005",
        "political_opinion",
        "voting_intention",
        (
            r"\bintencao de voto\s*[:=]\s*\S+",
            r"\b(?:declara|informa)\s+(?:sua\s+)?intencao de voto\b",
        ),
        (r"\bpolitica de (?:privacidade|seguranca|comercial)\b", r"\bpartido ao meio\b"),
        (r"^intencao de voto$",),
    ),
    _rule(
        "LGPD-SENS-006",
        "political_opinion",
        "political_opinion",
        (
            r"\bopiniao politica\s*[:=]\s*\S+",
            r"\b(?:declara|informa)\s+(?:sua\s+)?opiniao politica\b",
        ),
        (r"\bpolitica de (?:privacidade|seguranca|comercial)\b", r"\bpartido ao meio\b"),
        (r"^opiniao politica$",),
    ),
    _rule(
        "LGPD-SENS-007",
        "union_membership",
        "union_membership",
        (
            r"\b(?:filiacao sindical|sindicato filiado)\s*[:=]\s*\S+",
            r"\b(?:e|esta|foi)\s+(?:filiado|membro)\s+(?:ao|do)\s+sindicato\b",
        ),
        (
            r"\bsindicato\s+(?:informou|publicou|mencionado|representa|negocia)\b",
            r"\bmencao generica (?:ao|do) sindicato\b",
        ),
        (r"^(?:filiacao sindical|sindicato filiado)$",),
    ),
    _rule(
        "LGPD-SENS-008",
        "religious_philosophical_political_organization_membership",
        "organization_membership",
        (
            r"\bfiliacao (?:a|em) organizacao (?:religiosa|filosofica|politica)\s*[:=]\s*\S+",
            r"\b(?:e|esta|foi) membro de organizacao (?:religiosa|filosofica|politica)\b",
        ),
        (r"\borganizacao (?:de evento|de arquivos|administrativa)\b",),
        (r"^filiacao (?:a|em) organizacao (?:religiosa|filosofica|politica)$",),
    ),
    _rule(
        "LGPD-SENS-009",
        "health",
        "health",
        (
            r"\b(?:diagnostico|doenca|tratamento|prontuario|condicao de saude|cid)\s*[:=]\s*\S+",
            r"\b(?:possui|tem|recebe|informa)\s+(?:diagnostico|doenca|tratamento|condicao de saude)\b",
        ),
        (r"\bsaude financeira\b", r"\bsaude do sistema\b", r"\bsaude da aplicacao\b"),
        (r"^(?:diagnostico|doenca|tratamento|prontuario|condicao de saude|cid)$",),
    ),
    _rule(
        "LGPD-SENS-010",
        "sexual_life",
        "sexual_life",
        (
            r"\b(?:vida sexual|comportamento sexual)\s*[:=]\s*\S+",
            r"\b(?:declara|informa)\s+(?:sua\s+)?(?:vida|comportamento) sexual\b",
        ),
        (r"\beducacao sexual\b", r"\bconteudo educativo sexual\b"),
        (r"^(?:vida sexual|comportamento sexual)$",),
    ),
    _rule(
        "LGPD-SENS-011",
        "sexual_life",
        "orientation_sexual",
        (
            r"\borientacao sexual\s*[:=]\s*\S+",
            r"\b(?:declara|informa)\s+(?:sua\s+)?orientacao sexual\b",
        ),
        (r"\bpesquisa estatistica sobre orientacao sexual\b",),
        (r"^orientacao sexual$",),
    ),
    _rule(
        "LGPD-SENS-012",
        "genetic",
        "genetic",
        (
            r"\b(?:dado|teste|perfil|sequenciamento) genetico\s*[:=]\s*\S+",
            r"\b(?:possui|realizou|informa)\s+(?:teste|perfil|sequenciamento) genetico\b",
        ),
        (r"\bdna da empresa\b", r"\bdna da marca\b"),
        (r"^(?:dado|teste|perfil|sequenciamento) genetico$",),
    ),
    _rule(
        "LGPD-SENS-013",
        "biometric",
        "biometric",
        (
            r"\b(?:template|padrao|dado) biometrico\s*[:=]\s*\S+",
            r"\b(?:reconhecimento facial|biometria facial|leitura de iris|impressao digital)\s+"
            r"(?:para|usada em|destinada a)\s+(?:reconhecimento|autenticacao|identificacao)\b",
            r"\b(?:extracao|captura|processamento)\s+(?:de\s+)?"
            r"(?:biometria|template biometrico|caracteristicas faciais)\b",
        ),
        (
            r"\bimpressao digital de documento\b",
            r"\bassinatura digital\b",
            r"\bfotografia (?:comum|do documento|para cadastro)\b",
            r"\bfoto (?:comum|do documento|para cadastro)\b",
        ),
        (r"^(?:template|padrao|dado) biometrico$",),
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in SENSITIVE_RULES}


def ruleset_metadata() -> list[dict[str, object]]:
    """Retorna a definicao versionada sem objetos regex ou estado mutavel."""
    return [rule.public_metadata() for rule in SENSITIVE_RULES]
