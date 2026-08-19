import json
import sqlite3
import stat
import tempfile
import types
import unittest
import zipfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from cpf_lgpd.cli import main
from cpf_lgpd.extractors import ExtractionLimits
from cpf_lgpd.scanner import is_valid_cpf, redact_cpfs, scan_directory


class CpfValidationTests(unittest.TestCase):
    def test_accepts_formatted_and_plain_valid_cpf(self):
        self.assertTrue(is_valid_cpf("529.982.247-25"))
        self.assertTrue(is_valid_cpf("52998224725"))

    def test_rejects_invalid_and_repeated_values(self):
        self.assertFalse(is_valid_cpf("529.982.247-24"))
        self.assertFalse(is_valid_cpf("111.111.111-11"))
        self.assertFalse(is_valid_cpf("123"))

    def test_redacts_valid_cpf_in_path_but_preserves_invalid_number(self):
        text = "/clientes/52998224725/11111111111.txt"
        self.assertEqual(redact_cpfs(text), "/clientes/***.***.***-25/11111111111.txt")


class ScannerTests(unittest.TestCase):
    def test_scan_aggregates_without_retaining_cpfs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpf_candidate = "529.982.247-25"
            (root / "one.txt").write_text(
                f"CPF {cpf_candidate}\nCPF 111.111.111-11", encoding="utf-8"
            )
            (root / "ignored.bin").write_bytes(b"52998224725")

            result = scan_directory(root)

            self.assertEqual(result.valid_cpfs, 1)
            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.files_skipped, 1)
            self.assertNotIn(cpf_candidate, json.dumps(result.to_dict()))

    def test_finds_cpf_across_chunks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text("x" * 60 + "52998224725", encoding="utf-8")
            self.assertEqual(scan_directory(root).valid_cpfs, 1)

    def test_scans_zip_members_without_extracting_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with zipfile.ZipFile(root / "documents.zip", "w") as archive:
                archive.writestr("internal/data.txt", "52998224725")
            self.assertEqual(scan_directory(root).valid_cpfs, 1)

    def test_rejects_archive_member_over_configured_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with zipfile.ZipFile(root / "large.zip", "w") as archive:
                archive.writestr("large.txt", "x" * 100)
            result = scan_directory(root, extraction_limits=ExtractionLimits(max_member_size=50))
            self.assertEqual(result.files_failed, 1)
            self.assertEqual(result.errors, {"ExtractionLimitError": 1})

    def test_scans_docx_and_xlsx_xml(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with zipfile.ZipFile(root / "document.docx", "w") as archive:
                archive.writestr(
                    "word/document.xml",
                    '<w:document xmlns:w="urn:test"><w:t>529.982.247-25</w:t></w:document>',
                )
            with zipfile.ZipFile(root / "sheet.xlsx", "w") as archive:
                archive.writestr(
                    "xl/sharedStrings.xml",
                    '<sst xmlns="urn:test"><si><t>52998224725</t></si></sst>',
                )
            self.assertEqual(scan_directory(root).valid_cpfs, 2)

    def test_scans_sqlite_values_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = sqlite3.connect(root / "customers.sqlite")
            database.execute("CREATE TABLE customers (document TEXT)")
            database.execute("INSERT INTO customers VALUES (?)", ("52998224725",))
            database.commit()
            database.close()
            self.assertEqual(scan_directory(root).valid_cpfs, 1)

    def test_scans_pdf_text_layer_through_pypdf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "document.pdf").write_bytes(b"synthetic PDF")
            page = types.SimpleNamespace(extract_text=lambda: "52998224725")
            pypdf = types.ModuleType("pypdf")
            pypdf.PdfReader = lambda *_args, **_kwargs: types.SimpleNamespace(pages=[page])
            with mock.patch.dict("sys.modules", {"pypdf": pypdf}):
                self.assertEqual(scan_directory(root).valid_cpfs, 1)

    def test_scans_image_with_ocr_adapter(self):
        class FakeImage:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scan.png").write_bytes(b"synthetic image")
            pillow = types.ModuleType("PIL")
            pillow.Image = types.SimpleNamespace(open=lambda *_args: FakeImage())
            pytesseract = types.ModuleType("pytesseract")
            pytesseract.TesseractNotFoundError = RuntimeError
            pytesseract.image_to_string = lambda *_args, **_kwargs: "52998224725"
            with mock.patch.dict("sys.modules", {"PIL": pillow, "pytesseract": pytesseract}):
                self.assertEqual(scan_directory(root).valid_cpfs, 1)

    def test_non_utf8_file_is_reported_not_fatal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bad.txt").write_bytes(b"\xff\xfe")
            result = scan_directory(root)
            self.assertEqual(result.files_failed, 1)
            self.assertEqual(result.errors, {"UnicodeDecodeError": 1})

    def test_empty_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "empty.txt").write_text("", encoding="utf-8")
            (root / "large.txt").write_text("x" * 100, encoding="utf-8")
            result = scan_directory(root, max_file_size=50)
            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.files_skipped, 1)

    def test_permission_error_is_aggregated_without_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text("conteudo", encoding="utf-8")
            with mock.patch(
                "cpf_lgpd.scanner.iter_text_path", side_effect=PermissionError("segredo")
            ):
                result = scan_directory(root)
            self.assertEqual(result.files_failed, 1)
            self.assertEqual(result.errors, {"PermissionError": 1})
            self.assertNotIn("segredo", json.dumps(result.to_dict()))

    def test_cli_does_not_print_cpf_and_protects_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpf_candidate = "529.982.247-25"
            (root / "data.txt").write_text(cpf_candidate, encoding="utf-8")
            report = root / "reports" / "result.json"
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main([str(root), "--report", str(report)])

            self.assertEqual(exit_code, 1)
            self.assertNotIn(cpf_candidate, output.getvalue())
            self.assertNotIn(cpf_candidate, report.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)

    def test_cli_writes_structured_csv_without_cpf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cpf_candidate = "52998224725"
            (root / "data.txt").write_text(
                f"CPF: {cpf_candidate}; Nome: Pessoa Sintética", encoding="utf-8"
            )
            report = root / "result.csv"
            with redirect_stdout(StringIO()):
                exit_code = main([str(root), "--csv-report", str(report)])
            content = report.read_text(encoding="utf-8")
            self.assertEqual(exit_code, 1)
            self.assertIn("risk_score", content)
            self.assertNotIn(cpf_candidate, content)


if __name__ == "__main__":
    unittest.main()
