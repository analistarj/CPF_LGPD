import json
import tempfile
import unittest
from pathlib import Path

from cpf_lgpd.classification import AnalysisConfig, ContextAnalyzer
from cpf_lgpd.configuration import load_config
from cpf_lgpd.permissions import PermissionAssessment
from cpf_lgpd.risk import GovernanceMetadata, ScoreWeights, risk_level, volume_score
from cpf_lgpd.scanner import scan_directory


class UnknownPermissions:
    def assess(self, _path):
        return PermissionAssessment()


def analyze(text: str, *, secret: bytes | None = None):
    analyzer = ContextAnalyzer(AnalysisConfig(hmac_secret=secret))
    analyzer.feed(text)
    return analyzer.finish()


class ContextDetectionTests(unittest.TestCase):
    def test_cpf_isolated_and_unique_count(self):
        result = analyze("52998224725 529.982.247-25")
        self.assertEqual(result.cpf_count, 2)
        self.assertEqual(result.unique_cpf_count, 1)
        self.assertEqual(result.cpf_hmac_ids, [])

    def test_hmac_is_deterministic_and_contains_no_cpf(self):
        first = analyze("52998224725", secret=b"segredo-sintetico")
        second = analyze("52998224725", secret=b"segredo-sintetico")
        self.assertEqual(first.cpf_hmac_ids, second.cpf_hmac_ids)
        self.assertNotIn("52998224725", json.dumps(first.cpf_hmac_ids))

    def test_cpf_with_name_and_financial_data(self):
        result = analyze("CPF: 52998224725; Nome: Pessoa Sintetica; Renda: 100")
        self.assertEqual(result.categories["nome"].confidence, "alta")
        self.assertEqual(result.categories["financeiro"].confidence, "alta")

    def test_linked_health_and_two_sensitive_categories(self):
        result = analyze("CPF: 52998224725; Diagnostico: sintético; Teste genetico: sintético")
        self.assertEqual(result.categories["saude"].confidence, "alta")
        self.assertEqual(result.categories["genetico"].confidence, "alta")

    def test_isolated_sensitive_word_does_not_create_detection(self):
        result = analyze("saude religiao sindicato")
        self.assertEqual(result.categories, {})

    def test_sensitive_label_without_person_is_only_possible_occurrence(self):
        result = analyze("Diagnostico: informação sintética")
        self.assertTrue(result.categories["saude"].possible_occurrence)
        self.assertEqual(result.categories["saude"].confidence, "baixa")

    def test_full_discovery_preview_can_report_non_cpf_indicator(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.txt"
            path.write_text("Diagnostico: informação sintética", encoding="utf-8")
            anchored = scan_directory(Path(temporary), mode="cpf-anchor")
            preview = scan_directory(Path(temporary), mode="full-discovery")
            self.assertEqual(anchored.findings, [])
            self.assertEqual(len(preview.findings), 1)
            self.assertEqual(preview.findings[0].count, 0)


class ScoringTests(unittest.TestCase):
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

    def test_volume_boundaries(self):
        cases = {0: 0, 1: 1, 2: 3, 9: 3, 10: 7, 99: 7, 100: 11, 999: 11, 1000: 15}
        for count, expected in cases.items():
            with self.subTest(count=count):
                self.assertEqual(volume_score(count), expected)

    def test_risk_level_boundaries(self):
        cases = {
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
        for score, expected in cases.items():
            with self.subTest(score=score):
                self.assertEqual(risk_level(score), expected)

    def test_unknown_permissions_and_governance_are_explained(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.txt"
            path.write_text("CPF: 52998224725", encoding="utf-8")
            result = scan_directory(Path(temporary), permission_adapter=UnknownPermissions())
            risk = result.findings[0].risk
            self.assertEqual(risk.score_breakdown["exposure"], 10)
            self.assertEqual(risk.score_breakdown["governance"], 15)
            self.assertIn("owner", risk.unknown_information)

    def test_score_is_bounded_even_with_extreme_configured_weights(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.txt"
            path.write_text(
                "CPF: 52998224725; Nome: Pessoa; Renda: 1; Diagnostico: sintético",
                encoding="utf-8",
            )
            weights = ScoreWeights(
                cpf=999,
                additional_identifier=999,
                additional_cap=999,
                high_impact_one=999,
                sensitive_one=999,
                content_cap=999,
                exposure_unknown=999,
                owner_unknown=999,
                purpose_unknown=999,
                retention_unknown_or_expired=999,
            )
            result = scan_directory(
                Path(temporary),
                permission_adapter=UnknownPermissions(),
                score_weights=weights,
            )
            score = result.findings[0].risk.risk_score
            breakdown = result.findings[0].risk.score_breakdown
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)
            self.assertLessEqual(breakdown["content"], 40)
            self.assertLessEqual(breakdown["exposure"], 30)
            self.assertLessEqual(breakdown["volume"], 15)
            self.assertLessEqual(breakdown["governance"], 15)

    def test_result_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.txt"
            path.write_text("CPF: 52998224725; Nome: Pessoa", encoding="utf-8")
            kwargs = {
                "permission_adapter": UnknownPermissions(),
                "governance": GovernanceMetadata(),
                "hmac_secret": b"segredo-sintetico",
            }
            first = scan_directory(Path(temporary), **kwargs).to_dict()
            second = scan_directory(Path(temporary), **kwargs).to_dict()
            self.assertEqual(first, second)
