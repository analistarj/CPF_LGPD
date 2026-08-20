import json
import tempfile
import unittest
from pathlib import Path

from cpf_lgpd.classification import AnalysisConfig, ContextAnalyzer
from cpf_lgpd.configuration import load_config
from cpf_lgpd.permissions import PermissionAssessment
from cpf_lgpd.risk import GovernanceMetadata, ScoreWeights, risk_level, volume_score
from cpf_lgpd.rules import LEGAL_CATEGORIES, RULESET_VERSION, SENSITIVE_RULES
from cpf_lgpd.scanner import scan_directory

CPF = "52998224725"


class UnknownPermissions:
    def assess(self, _path):
        return PermissionAssessment()


def analyze(text: str, *, secret: bytes | None = None, mode: str = "cpf-anchor"):
    analyzer = ContextAnalyzer(AnalysisConfig(mode=mode, hmac_secret=secret))
    analyzer.feed(text)
    return analyzer.finish()


class RulesetTests(unittest.TestCase):
    def test_taxonomy_and_rule_contract_are_exact_and_versioned(self):
        self.assertEqual(
            set(LEGAL_CATEGORIES),
            {
                "racial_ethnic_origin",
                "religious_belief",
                "political_opinion",
                "union_membership",
                "religious_philosophical_political_organization_membership",
                "health",
                "sexual_life",
                "genetic",
                "biometric",
            },
        )
        self.assertEqual(RULESET_VERSION, "lgpd-br-1.0.0")
        for rule in SENSITIVE_RULES:
            self.assertEqual(rule.legal_basis, "LGPD_ART_5_II")
            self.assertEqual(rule.ruleset_version, RULESET_VERSION)
            self.assertTrue(rule.rule_id)
            self.assertTrue(rule.subtype)
            self.assertTrue(rule.positive_indicators)
            self.assertTrue(rule.negative_indicators)
            self.assertTrue(rule.required_person_anchor)
            self.assertTrue(rule.required_link_method)
            self.assertIn("cpf_valido=20", rule.confidence_calculation)
            self.assertEqual(rule.risk_points["media"], 15)
            self.assertEqual(rule.risk_points["alta"], 20)

    def test_all_nine_legal_categories_have_positive_synthetic_cases(self):
        cases = {
            "racial_ethnic_origin": "Raça: categoria-sintética",
            "religious_belief": "Religião: categoria-sintética",
            "political_opinion": "Posicionamento político: categoria-sintética",
            "union_membership": "Filiação sindical: categoria-sintética",
            "religious_philosophical_political_organization_membership": (
                "Filiação a organização filosófica: categoria-sintética"
            ),
            "health": "Diagnóstico: condição-sintética",
            "sexual_life": "Orientação sexual: categoria-sintética",
            "genetic": "Teste genético: resultado-sintético",
            "biometric": "Reconhecimento facial para autenticação",
        }
        for expected, evidence in cases.items():
            with self.subTest(category=expected):
                result = analyze(f"CPF: {CPF}; {evidence}")
                self.assertIn(expected, result.categories)
                occurrences = [
                    item for item in result.sensitive_occurrences if item.legal_category == expected
                ]
                self.assertTrue(occurrences)
                self.assertEqual(occurrences[0].confidence_level, "alta")

    def test_operational_subtypes_are_mapped_to_legal_categories(self):
        orientation = analyze(f"CPF: {CPF}; Orientação sexual: categoria-sintética")
        self.assertEqual(orientation.sensitive_occurrences[0].legal_category, "sexual_life")
        self.assertEqual(orientation.sensitive_occurrences[0].subtype, "orientation_sexual")
        political_cases = {
            "Posicionamento político: categoria-sintética": "political_position",
            "Preferência política: categoria-sintética": "political_preference",
            "Intenção de voto: categoria-sintética": "voting_intention",
        }
        for evidence, subtype in political_cases.items():
            with self.subTest(subtype=subtype):
                result = analyze(f"CPF: {CPF}; {evidence}")
                self.assertEqual(result.sensitive_occurrences[0].legal_category, "political_opinion")
                self.assertEqual(result.sensitive_occurrences[0].subtype, subtype)

    def test_required_negative_expressions_do_not_classify(self):
        expressions = (
            "política de privacidade",
            "política de segurança",
            "política comercial",
            "saúde financeira",
            "saúde do sistema",
            "raça de cachorro",
            "partido ao meio",
            "DNA da empresa",
            "impressão digital de documento no sentido de cópia",
            "assinatura digital",
            "sindicato mencionado genericamente",
            "igreja mencionada como endereço ou local",
            "fotografia comum sem processamento biométrico",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                result = analyze(f"CPF: {CPF}; {expression}")
                self.assertEqual(result.sensitive_occurrences, [])

    def test_isolated_words_and_ordinary_photo_never_create_occurrence(self):
        result = analyze(
            f"CPF: {CPF}; saúde religião sindicato raça política DNA fotografia endereço"
        )
        self.assertEqual(result.sensitive_occurrences, [])

    def test_anchor_and_strong_link_are_required_for_confirmation(self):
        without_anchor = analyze("Diagnóstico: condição-sintética", mode="full-discovery")
        self.assertEqual(without_anchor.sensitive_occurrences[0].confidence_score, 40)
        self.assertEqual(
            without_anchor.sensitive_occurrences[0].confidence_level, "possivel_ocorrencia"
        )
        separated = analyze(f"CPF: {CPF}\nDiagnóstico: condição-sintética")
        occurrence = separated.sensitive_occurrences[0]
        self.assertEqual(occurrence.person_anchor, "none")
        self.assertEqual(occurrence.risk_points, 0)

    def test_invalid_cpf_is_not_an_anchor_in_cpf_anchor_mode(self):
        result = analyze("CPF: 11111111111; Diagnóstico: condição-sintética")
        self.assertEqual(result.cpf_count, 0)
        self.assertEqual(result.sensitive_occurrences[0].confidence_level, "possivel_ocorrencia")
        self.assertEqual(result.sensitive_occurrences[0].risk_points, 0)

    def test_hmac_is_deterministic_and_contains_no_cpf(self):
        first = analyze(CPF, secret=b"segredo-sintetico")
        second = analyze(CPF, secret=b"segredo-sintetico")
        self.assertEqual(first.cpf_hmac_ids, second.cpf_hmac_ids)
        self.assertNotIn(CPF, json.dumps(first.cpf_hmac_ids))


class ScoringTests(unittest.TestCase):
    def test_sensitive_score_uses_confidence_and_category_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "high.txt").write_text(
                f"CPF: {CPF}; Diagnóstico: condição-sintética", encoding="utf-8"
            )
            high = scan_directory(root, permission_adapter=UnknownPermissions()).findings[0]
            self.assertEqual(high.risk.score_breakdown["content"], 25)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "medium.json").write_text(
                json.dumps({"nome": "Pessoa Sintética", "diagnostico": "condição-sintética"}),
                encoding="utf-8",
            )
            medium = scan_directory(
                root, mode="full-discovery", permission_adapter=UnknownPermissions()
            ).findings[0]
            self.assertEqual(medium.occurrences[0]["confidence_level"], "media")
            self.assertEqual(medium.risk.score_breakdown["content"], 17)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "multiple.txt").write_text(
                f"CPF: {CPF}; Diagnóstico: condição-sintética; Religião: categoria-sintética",
                encoding="utf-8",
            )
            multiple = scan_directory(root, permission_adapter=UnknownPermissions()).findings[0]
            self.assertEqual(multiple.risk.score_breakdown["content"], 30)

    def test_possible_occurrence_adds_no_sensitive_points(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text(
                f"CPF: {CPF}\nDiagnóstico: condição-sintética", encoding="utf-8"
            )
            finding = scan_directory(root, permission_adapter=UnknownPermissions()).findings[0]
            self.assertEqual(finding.occurrences[0]["risk_points"], 0)
            self.assertEqual(finding.risk.score_breakdown["content"], 5)

    def test_configuration_loads_limits_weights_and_governance(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "context_window": 250,
                        "max_age_days": 365,
                        "weights": {"cpf": 4},
                        "governance": {"purpose": "inventario autorizado"},
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(path)
            self.assertEqual(config.context_window, 250)
            self.assertEqual(config.weights.cpf, 4)
            self.assertEqual(config.governance.max_age_days, 365)

    def test_volume_and_risk_boundaries(self):
        volume_cases = {0: 0, 1: 1, 2: 3, 9: 3, 10: 7, 99: 7, 100: 11, 999: 11, 1000: 15}
        for count, expected in volume_cases.items():
            self.assertEqual(volume_score(count), expected)
        risk_cases = {
            0: "baixo",
            19: "baixo",
            20: "moderado",
            39: "moderado",
            40: "alto",
            59: "alto",
            60: "muito_alto",
            79: "muito_alto",
            80: "critico",
            100: "critico",
        }
        for score, expected in risk_cases.items():
            self.assertEqual(risk_level(score), expected)

    def test_unknowns_are_explained_and_score_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "data.txt"
            path.write_text(f"CPF: {CPF}; Nome: Pessoa; Renda: 1", encoding="utf-8")
            weights = ScoreWeights(
                cpf=999,
                additional_identifier=999,
                additional_cap=999,
                high_impact_one=999,
                high_impact_multiple=999,
                content_cap=999,
                exposure_unknown=999,
                owner_unknown=999,
                purpose_unknown=999,
                retention_unknown_or_expired=999,
            )
            finding = scan_directory(
                root,
                permission_adapter=UnknownPermissions(),
                score_weights=weights,
            ).findings[0]
            self.assertLessEqual(finding.risk.risk_score, 100)
            self.assertLessEqual(finding.risk.score_breakdown["content"], 40)
            self.assertIn("owner", finding.risk.unknown_information)

    def test_result_score_and_confidence_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.txt"
            path.write_text(f"CPF: {CPF}; Diagnóstico: condição-sintética", encoding="utf-8")
            kwargs = {
                "permission_adapter": UnknownPermissions(),
                "governance": GovernanceMetadata(),
                "hmac_secret": b"segredo-sintetico",
            }
            first = scan_directory(Path(temporary), **kwargs).to_dict()
            second = scan_directory(Path(temporary), **kwargs).to_dict()
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
