import argparse
import io
import json
import os
import sqlite3
import tarfile
import tempfile
import types
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from cpf_lgpd.cli import _normalize_extensions, _positive_int, main
from cpf_lgpd.configuration import load_config
from cpf_lgpd.extractors import (
    ExtractionError,
    ExtractionLimitError,
    ExtractionLimits,
    MissingDependencyError,
    _legacy_doc_units,
    iter_text_bytes,
    iter_text_path,
    iter_units_bytes,
    iter_units_path,
)
from cpf_lgpd.permissions import LocalPermissionAdapter
from cpf_lgpd.scanner import DEFAULT_EXTENSIONS, ScanResult, _sanitize_structure, scan_directory

CPF = "52998224725"
SENSITIVE_VALUE = "condicao-sintetica-confidencial"


class CliAndConfigurationEdgeTests(unittest.TestCase):
    def test_cli_helpers_and_operational_error(self):
        self.assertEqual(_positive_int("2"), 2)
        with self.assertRaises(argparse.ArgumentTypeError):
            _positive_int("0")
        self.assertEqual(_normalize_extensions(None), DEFAULT_EXTENSIONS)
        self.assertEqual(_normalize_extensions(["TXT", ".JSON"]), frozenset({".txt", ".json"}))

        stderr = StringIO()
        with redirect_stderr(stderr):
            exit_code = main(["/caminho/sintetico/inexistente"])
        self.assertEqual(exit_code, 2)
        self.assertIn("Erro operacional", stderr.getvalue())

    def test_cli_writes_every_report_type_with_config_and_hmac(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text(
                f"CPF: {CPF}; Diagnostico: {SENSITIVE_VALUE}", encoding="utf-8"
            )
            config = root / "config.json"
            config.write_text(
                json.dumps({"extensions": [".txt"], "context_window": 200}),
                encoding="utf-8",
            )
            paths = {
                "technical": root / "technical.json",
                "technical_csv": root / "technical.csv",
                "executive": root / "executive.json",
                "executive_csv": root / "executive.csv",
            }
            output = StringIO()
            with mock.patch.dict(os.environ, {"SYNTHETIC_HMAC": "segredo-sintetico"}):
                with redirect_stdout(output):
                    exit_code = main(
                        [
                            str(root),
                            "--config",
                            str(config),
                            "--hmac-secret-env",
                            "SYNTHETIC_HMAC",
                            "--extension",
                            "txt",
                            "--max-file-size-mb",
                            "1",
                            "--report",
                            str(paths["technical"]),
                            "--csv-report",
                            str(paths["technical_csv"]),
                            "--executive-report",
                            str(paths["executive"]),
                            "--executive-csv-report",
                            str(paths["executive_csv"]),
                        ]
                    )
            self.assertEqual(exit_code, 1)
            self.assertTrue(all(path.exists() for path in paths.values()))
            self.assertIn("Relatorio CSV protegido", output.getvalue())
            self.assertIn("Relatorio executivo CSV protegido", output.getvalue())
            self.assertNotIn(CPF, output.getvalue())

    def test_configuration_rejects_unknown_and_non_object_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text('{"desconhecido": true}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


class ScannerEdgeTests(unittest.TestCase):
    def test_scan_argument_validation_and_invalid_report_level(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file_path = root / "not-a-directory.txt"
            file_path.write_text("sintetico", encoding="utf-8")
            with self.assertRaises(NotADirectoryError):
                scan_directory(file_path)
            for kwargs in (
                {"max_file_size": 0},
                {"mode": "invalido"},
                {"context_window": -1},
                {"max_processing_seconds": 0},
                {"root_id": "raiz com espaco"},
            ):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    scan_directory(root, **kwargs)
        with self.assertRaises(ValueError):
            ScanResult("/root", "root-id").to_dict("invalido")

    def test_skipped_files_timeout_and_structural_sanitization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "unsupported.bin").write_bytes(b"x")
            (root / "large.txt").write_text("x" * 20, encoding="utf-8")
            skipped = scan_directory(root, extensions=frozenset({".txt"}), max_file_size=10)
            self.assertEqual(skipped.files_skipped, 2)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text(CPF, encoding="utf-8")
            with mock.patch("cpf_lgpd.scanner.time.monotonic", side_effect=[0.0, 2.0]):
                timed = scan_directory(root, max_processing_seconds=1)
            self.assertTrue(timed.scan_timed_out)
            self.assertEqual(timed.errors, {"ProcessingTimeLimit": 1})

        sanitized = _sanitize_structure(
            [f"arquivo-{CPF}", {"url": "https://usuario:senha@host/?token=segredo"}, 7]
        )
        serialized = json.dumps(sanitized)
        self.assertNotIn(CPF, serialized)
        self.assertNotIn("usuario:senha", serialized)
        self.assertNotIn("token=segredo", serialized)
        self.assertIn("7", serialized)


class PermissionAdapterEdgeTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "bits POSIX indisponiveis no Windows")
    def test_posix_permission_levels_and_failure(self):
        adapter = LocalPermissionAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.txt"
            path.write_text("sintetico", encoding="utf-8")
            cases = (
                (0o644, "internal_all", 22),
                (0o640, "internal_limited", 5),
                (0o600, "owner_restricted", 0),
            )
            for mode, level, score in cases:
                with self.subTest(mode=oct(mode)):
                    path.chmod(mode)
                    assessment = adapter.assess(path)
                    self.assertEqual(assessment.level, level)
                    self.assertEqual(assessment.score, score)
                    self.assertFalse(assessment.unknown)
                    self.assertEqual(assessment.source, "posix_mode_bits")

            with mock.patch.object(Path, "stat", side_effect=OSError("sintetico")):
                failed = adapter.assess(path)
            self.assertEqual(failed.source, "posix_stat_failed")

    def test_windows_adapter_is_conservative(self):
        path = Path("C:/sintetico.txt")
        with mock.patch("cpf_lgpd.permissions.os.name", "nt"):
            result = LocalPermissionAdapter().assess(path)
        self.assertTrue(result.unknown)
        self.assertEqual(result.source, "windows_acl_adapter_not_configured")


class ExtractorEdgeTests(unittest.TestCase):
    limits = ExtractionLimits()

    def test_json_special_keys_scalar_lists_and_compatibility_iterators(self):
        payload = {
            "registro especial": [CPF, None, True, {"diagnostico": SENSITIVE_VALUE}],
        }
        units = list(
            iter_units_bytes(json.dumps(payload).encode(), ".json", self.limits, "por")
        )
        locations = json.dumps([field.location for unit in units for field in unit.fields])
        self.assertIn('[\\"registro especial\\"]', locations)
        self.assertTrue(any(unit.link_method == "same_json_object" for unit in units))

        texts = list(iter_text_bytes(b"linha um\nlinha dois", ".txt", self.limits, "por"))
        self.assertEqual(texts, ["linha um\n", "linha dois\n"])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "data.txt"
            path.write_text("linha sintetica", encoding="utf-8")
            self.assertEqual(
                list(iter_text_path(path, self.limits, "por")), ["linha sintetica\n"]
            )

    def test_xml_attributes_leaf_and_security_failures(self):
        xml = (
            f'<records><record cpf="{CPF}"><diagnostico>{SENSITIVE_VALUE}</diagnostico>'
            "</record><vazio /></records>"
        ).encode()
        units = list(iter_units_bytes(xml, ".xml", self.limits, "por"))
        fields = [field for unit in units for field in unit.fields]
        self.assertTrue(any(field.header == "@cpf" for field in fields))
        self.assertTrue(any(field.header == "diagnostico" for field in fields))

        for invalid in (b"<records>", b"<!DOCTYPE x><records />", b"<!ENTITY x 'y'><r />"):
            with self.subTest(invalid=invalid), self.assertRaises(ExtractionError):
                list(iter_units_bytes(invalid, ".xml", self.limits, "por"))

    def test_invalid_and_oversized_office_documents_are_controlled(self):
        for suffix in (".xlsx", ".docx"):
            with self.subTest(suffix=suffix), self.assertRaises(ExtractionError):
                list(iter_units_bytes(b"invalid-office", suffix, self.limits, "por"))

        with io.BytesIO() as stream:
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("word/document.xml", "x" * 50)
            docx = stream.getvalue()
        with self.assertRaises(ExtractionLimitError):
            list(
                iter_units_bytes(
                    docx,
                    ".docx",
                    ExtractionLimits(max_member_size=10),
                    "por",
                )
            )

        with io.BytesIO() as stream:
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr("xl/workbook.xml", "x" * 50)
            xlsx = stream.getvalue()
        with self.assertRaises(ExtractionLimitError):
            list(
                iter_units_bytes(
                    xlsx,
                    ".xlsx",
                    ExtractionLimits(max_member_size=10),
                    "por",
                )
            )

    def test_pdf_and_image_failures_are_minimized(self):
        pypdf = types.ModuleType("pypdf")
        pypdf.PdfReader = mock.Mock(side_effect=RuntimeError("conteudo-proibido"))
        with mock.patch.dict("sys.modules", {"pypdf": pypdf}):
            with self.assertRaisesRegex(ExtractionError, "PDF invalido"):
                list(iter_units_bytes(b"pdf", ".pdf", self.limits, "por"))

        class FakeImageContext:
            def __enter__(self):
                return object()

            def __exit__(self, *_args):
                return False

        class FakeTesseractNotFoundError(Exception):
            pass

        image_api = types.SimpleNamespace(open=lambda *_args, **_kwargs: FakeImageContext())
        pil = types.ModuleType("PIL")
        pil.Image = image_api
        pytesseract = types.ModuleType("pytesseract")
        pytesseract.TesseractNotFoundError = FakeTesseractNotFoundError
        pytesseract.image_to_string = lambda *_args, **_kwargs: f"CPF: {CPF}"
        with mock.patch.dict("sys.modules", {"PIL": pil, "pytesseract": pytesseract}):
            units = list(iter_units_bytes(b"image", ".png", self.limits, "por"))
        self.assertEqual(units[0].location["format"], "image_ocr")
        self.assertEqual(units[0].ambiguity_penalty, 20)

        pytesseract.image_to_string = mock.Mock(side_effect=FakeTesseractNotFoundError())
        with mock.patch.dict("sys.modules", {"PIL": pil, "pytesseract": pytesseract}):
            with self.assertRaises(MissingDependencyError):
                list(iter_units_bytes(b"image", ".png", self.limits, "por"))

        pytesseract.image_to_string = mock.Mock(side_effect=RuntimeError("sintetico"))
        with mock.patch.dict("sys.modules", {"PIL": pil, "pytesseract": pytesseract}):
            with self.assertRaises(ExtractionError):
                list(iter_units_bytes(b"image", ".png", self.limits, "por"))

    def test_legacy_xls_success_and_failure(self):
        class Cell:
            def __init__(self, value):
                self.value = value

        class Sheet:
            name = "Titulares"

            @staticmethod
            def get_rows():
                return [
                    [Cell("CPF"), Cell("Diagnostico")],
                    [Cell(CPF), Cell(SENSITIVE_VALUE)],
                ]

        workbook = types.SimpleNamespace(sheets=lambda: [Sheet()])
        xlrd = types.ModuleType("xlrd")
        xlrd.open_workbook = lambda **_kwargs: workbook
        with mock.patch.dict("sys.modules", {"xlrd": xlrd}):
            units = list(iter_units_bytes(b"xls", ".xls", self.limits, "por"))
        self.assertEqual(units[0].location["sheet"], "Titulares")
        self.assertEqual(units[0].fields[1].header, "Diagnostico")

        xlrd.open_workbook = mock.Mock(side_effect=RuntimeError("sintetico"))
        with mock.patch.dict("sys.modules", {"xlrd": xlrd}):
            with self.assertRaises(ExtractionError):
                list(iter_units_bytes(b"xls", ".xls", self.limits, "por"))

    def test_legacy_doc_executable_outcomes(self):
        path = Path("synthetic.doc")
        with mock.patch("cpf_lgpd.extractors.shutil.which", return_value=None):
            with self.assertRaises(MissingDependencyError):
                list(_legacy_doc_units(path))

        with mock.patch("cpf_lgpd.extractors.shutil.which", return_value="/usr/bin/antiword"):
            with mock.patch("cpf_lgpd.extractors.subprocess.run", side_effect=OSError("sintetico")):
                with self.assertRaises(ExtractionError):
                    list(_legacy_doc_units(path))
            failed = types.SimpleNamespace(returncode=1, stdout=b"")
            with mock.patch("cpf_lgpd.extractors.subprocess.run", return_value=failed):
                with self.assertRaises(ExtractionError):
                    list(_legacy_doc_units(path))
            success = types.SimpleNamespace(returncode=0, stdout=b"linha sintetica")
            with mock.patch("cpf_lgpd.extractors.subprocess.run", return_value=success):
                units = list(_legacy_doc_units(path))
            self.assertEqual(units[0].location["format"], "doc")

    def test_tar_archive_nested_limit_and_invalid_archive(self):
        payload = f"CPF: {CPF}".encode()
        with io.BytesIO() as stream:
            with tarfile.open(fileobj=stream, mode="w") as archive:
                info = tarfile.TarInfo("internal/data.txt")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            tar_data = stream.getvalue()
        units = list(iter_units_bytes(tar_data, ".tar", self.limits, "por"))
        self.assertEqual(units[0].location["archive_member"], "internal/data.txt")

        with self.assertRaises(ExtractionLimitError):
            list(
                iter_units_bytes(
                    tar_data,
                    ".tar",
                    ExtractionLimits(max_archive_depth=0),
                    "por",
                )
            )
        with self.assertRaises(ExtractionError):
            list(iter_units_bytes(b"invalid-archive", ".zip", self.limits, "por"))

    def test_database_row_limit_invalid_database_and_embedded_restriction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_path = root / "data.sqlite"
            database = sqlite3.connect(database_path)
            database.execute("CREATE TABLE records (cpf TEXT)")
            database.executemany("INSERT INTO records VALUES (?)", [(CPF,), (CPF,)])
            database.commit()
            database.close()
            with self.assertRaises(ExtractionLimitError):
                list(
                    iter_units_path(
                        database_path,
                        ExtractionLimits(max_database_rows=1),
                        "por",
                    )
                )

            invalid_path = root / "invalid.sqlite"
            invalid_path.write_bytes(b"not-a-database")
            with self.assertRaises(ExtractionError):
                list(iter_units_path(invalid_path, self.limits, "por"))

        for suffix in (".doc", ".sqlite"):
            with self.subTest(suffix=suffix), self.assertRaises(ExtractionError):
                list(iter_units_bytes(b"embedded", suffix, self.limits, "por"))


if __name__ == "__main__":
    unittest.main()
