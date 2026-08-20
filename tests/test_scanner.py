import csv
import json
import os
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
from cpf_lgpd.reporting import (
    write_csv_report,
    write_executive_csv_report,
    write_executive_json_report,
    write_json_report,
)
from cpf_lgpd.scanner import is_valid_cpf, redact_cpfs, sanitize_metadata, scan_directory

CPF = "52998224725"
SENSITIVE_VALUE = "condicao-sintetica-confidencial"
PERSON_NAME = "Pessoa Sintetica Confidencial"


def _write_xlsx(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "xl/workbook.xml",
            '<workbook xmlns:r="urn:r"><sheets><sheet name="Titulares" r:id="rId1"/></sheets></workbook>',
        )
        archive.writestr(
            "xl/_rels/workbook.xml.rels",
            '<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>',
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            (
                "<worksheet><sheetData>"
                '<row r="1"><c r="A1" t="inlineStr"><is><t>CPF</t></is></c>'
                '<c r="B1" t="inlineStr"><is><t>Diagnostico</t></is></c></row>'
                f'<row r="2"><c r="A2" t="inlineStr"><is><t>{CPF}</t></is></c>'
                f'<c r="B2" t="inlineStr"><is><t>{SENSITIVE_VALUE}</t></is></c></row>'
                "</sheetData></worksheet>"
            ),
        )


def _write_docx(path: Path, *, table: bool = False) -> None:
    if table:
        body = (
            "<w:tbl><w:tr><w:tc><w:p><w:r><w:t>CPF</w:t></w:r></w:p></w:tc>"
            "<w:tc><w:p><w:r><w:t>Diagnostico</w:t></w:r></w:p></w:tc></w:tr>"
            f"<w:tr><w:tc><w:p><w:r><w:t>{CPF}</w:t></w:r></w:p></w:tc>"
            f"<w:tc><w:p><w:r><w:t>{SENSITIVE_VALUE}</w:t></w:r></w:p></w:tc></w:tr>"
            "</w:tbl>"
        )
    else:
        body = f"<w:p><w:r><w:t>CPF: {CPF}; Diagnostico: {SENSITIVE_VALUE}</w:t></w:r></w:p>"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "word/document.xml",
            f'<w:document xmlns:w="urn:w"><w:body>{body}</w:body></w:document>',
        )


class CpfValidationTests(unittest.TestCase):
    def test_accepts_formatted_and_plain_valid_cpf(self):
        self.assertTrue(is_valid_cpf("529.982.247-25"))
        self.assertTrue(is_valid_cpf(CPF))

    def test_rejects_invalid_and_repeated_values(self):
        self.assertFalse(is_valid_cpf("529.982.247-24"))
        self.assertFalse(is_valid_cpf("111.111.111-11"))
        self.assertFalse(is_valid_cpf("123"))

    def test_redacts_every_cpf_shaped_sequence_in_metadata(self):
        text = "/clientes/52998224725/11111111111.txt"
        self.assertEqual(redact_cpfs(text), "/clientes/***.***.***-25/***.***.***-11.txt")


class StructuredLocationTests(unittest.TestCase):
    def _single_occurrence(self, root: Path):
        result = scan_directory(root)
        self.assertEqual(len(result.findings), 1)
        return result.findings[0].occurrences[0]

    def test_csv_location_has_row_column_and_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.csv").write_text(
                f"CPF,Diagnostico\n{CPF},{SENSITIVE_VALUE}\n", encoding="utf-8"
            )
            location = self._single_occurrence(root)["location"]
            self.assertEqual(location["row"], 2)
            self.assertEqual(location["column"], 2)
            self.assertEqual(location["header"], "Diagnostico")

    def test_xlsx_location_has_sheet_row_column_and_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_xlsx(root / "data.xlsx")
            location = self._single_occurrence(root)["location"]
            self.assertEqual(location["sheet"], "Titulares")
            self.assertEqual(location["row"], 2)
            self.assertEqual(location["column"], 2)
            self.assertEqual(location["header"], "Diagnostico")

    def test_json_location_has_jsonpath_and_record_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.json").write_text(
                json.dumps({"records": [{"cpf": CPF, "diagnostico": SENSITIVE_VALUE}]}),
                encoding="utf-8",
            )
            location = self._single_occurrence(root)["location"]
            self.assertEqual(location["json_path"], "$.records[0].diagnostico")
            self.assertEqual(location["record_object"], "$.records[0]")

    def test_xml_location_has_xpath_and_record_element(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.xml").write_text(
                f"<records><record><cpf>{CPF}</cpf><diagnostico>{SENSITIVE_VALUE}</diagnostico></record></records>",
                encoding="utf-8",
            )
            location = self._single_occurrence(root)["location"]
            self.assertEqual(location["xpath"], "/records[1]/record[1]/diagnostico[1]")
            self.assertEqual(location["record_element"], "/records[1]/record[1]")

    def test_txt_location_has_line_number(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text(
                f"cabecalho sintetico\nCPF: {CPF}; Diagnostico: {SENSITIVE_VALUE}\n",
                encoding="utf-8",
            )
            self.assertEqual(self._single_occurrence(root)["location"]["line"], 2)

    def test_docx_locations_have_paragraph_and_table_coordinates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_docx(root / "paragraph.docx")
            self.assertEqual(self._single_occurrence(root)["location"]["paragraph"], 1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_docx(root / "table.docx", table=True)
            location = self._single_occurrence(root)["location"]
            self.assertEqual(location["table"], 1)
            self.assertEqual(location["row"], 2)
            self.assertEqual(location["column"], 2)

    def test_pdf_location_has_page_without_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "document.pdf").write_bytes(b"synthetic PDF")
            pages = [
                types.SimpleNamespace(extract_text=lambda: "cabecalho"),
                types.SimpleNamespace(
                    extract_text=lambda: f"CPF: {CPF}; Diagnostico: {SENSITIVE_VALUE}"
                ),
            ]
            pypdf = types.ModuleType("pypdf")
            pypdf.PdfReader = lambda *_args, **_kwargs: types.SimpleNamespace(pages=pages)
            with mock.patch.dict("sys.modules", {"pypdf": pypdf}):
                occurrence = self._single_occurrence(root)
            self.assertEqual(occurrence["location"]["page"], 2)
            self.assertNotIn(SENSITIVE_VALUE, json.dumps(occurrence))


class TraceabilityAndSecurityTests(unittest.TestCase):
    def test_file_trace_has_required_metadata_without_author_inference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text(CPF, encoding="utf-8")
            result = scan_directory(root, root_id="authorized-root")
            trace = result.files[0]
            self.assertEqual(trace.root_id, "authorized-root")
            self.assertEqual(trace.relative_path, "data.txt")
            self.assertEqual(trace.name, "data.txt")
            self.assertEqual(trace.extension, ".txt")
            self.assertGreater(trace.size_bytes, 0)
            self.assertTrue(trace.absolute_or_unc_path)
            self.assertTrue(trace.canonical_path)
            self.assertTrue(trace.last_modified_at)
            self.assertEqual(trace.created_by, "unknown")
            self.assertEqual(trace.last_modified_by, "unknown")
            self.assertTrue(trace.permissions_source)

    def test_unc_url_credentials_tokens_and_cpfs_are_redacted(self):
        unc_path = r"\\server\share\folder\data.txt"
        self.assertEqual(sanitize_metadata(unc_path), unc_path)
        value = "smb://usuario:senha@server/share/52998224725.txt?token=segredo"
        sanitized = sanitize_metadata(value)
        self.assertNotIn("usuario:senha", sanitized)
        self.assertNotIn(CPF, sanitized)
        self.assertNotIn("token=segredo", sanitized)
        self.assertIn("server/share", sanitized)

    def test_symlink_outside_authorized_root_is_never_scanned(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as outside:
            root = Path(temporary)
            external = Path(outside)
            (external / "secret.txt").write_text(CPF, encoding="utf-8")
            try:
                (root / "escape").symlink_to(external, target_is_directory=True)
            except OSError:
                self.skipTest("links simbolicos indisponiveis")
            result = scan_directory(root, follow_symlinks=True)
            self.assertEqual(result.files_scanned, 0)
            self.assertEqual(result.valid_cpfs, 0)
            self.assertEqual(result.errors, {"PathEscapeError": 1})

    def test_file_read_permission_error_is_aggregated_without_message(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text("conteudo", encoding="utf-8")
            with mock.patch(
                "cpf_lgpd.scanner.iter_units_path", side_effect=PermissionError("segredo")
            ):
                result = scan_directory(root)
            self.assertEqual(result.errors, {"PermissionError": 1})
            self.assertEqual(len(result.files), 1)
            self.assertNotIn("segredo", json.dumps(result.to_dict()))


class ReportingTests(unittest.TestCase):
    def test_technical_and_executive_reports_are_minimized_and_protected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text(
                f"CPF: {CPF}; Nome: {PERSON_NAME}; Diagnostico: {SENSITIVE_VALUE}",
                encoding="utf-8",
            )
            result = scan_directory(root, root_id="authorized-root")
            technical_json = root / "reports" / "technical.json"
            executive_json = root / "reports" / "executive.json"
            technical_csv = root / "reports" / "technical.csv"
            executive_csv = root / "reports" / "executive.csv"
            write_json_report(technical_json, result)
            write_executive_json_report(executive_json, result)
            write_csv_report(technical_csv, result)
            write_executive_csv_report(executive_csv, result)

            for report in (technical_json, executive_json, technical_csv, executive_csv):
                content = report.read_text(encoding="utf-8")
                self.assertNotIn(CPF, content)
                self.assertNotIn(SENSITIVE_VALUE, content)
                self.assertNotIn(PERSON_NAME, content)
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)

            technical = json.loads(technical_json.read_text(encoding="utf-8"))
            executive = json.loads(executive_json.read_text(encoding="utf-8"))
            self.assertEqual(technical["report_level"], "technical")
            self.assertEqual(technical["application_version"], "2.2.0rc1")
            self.assertEqual(technical["score_version"], "1.1")
            self.assertEqual(technical["ruleset_version"], "lgpd-br-1.0.0")
            self.assertIn("positive_indicators", technical["ruleset"][0])
            self.assertIn("negative_indicators", technical["ruleset"][0])
            self.assertTrue(
                Path(technical["findings"][0]["canonical_path"]).samefile(root / "data.txt")
            )
            self.assertEqual(executive["report_level"], "executive")
            self.assertEqual(executive["findings"][0]["file_path"], "data.txt")
            self.assertNotIn("technical_owner", executive["findings"][0])
            self.assertNotIn("permissions_source", executive["findings"][0])
            self.assertNotIn(str(root), executive_json.read_text(encoding="utf-8"))

            with technical_csv.open(encoding="utf-8", newline="") as stream:
                row = next(csv.DictReader(stream))
            for required in (
                "file_path",
                "relative_path",
                "root_id",
                "location",
                "rule_id",
                "legal_category",
                "subtype",
                "confidence_score",
                "confidence_level",
                "risk_points",
                "match_count",
                "requires_human_review",
                "ruleset_version",
                "score_version",
            ):
                self.assertIn(required, row)

    def test_cli_writes_both_report_levels_without_logging_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text(
                f"CPF: {CPF}; Diagnostico: {SENSITIVE_VALUE}", encoding="utf-8"
            )
            output = StringIO()
            technical = root / "technical.json"
            executive = root / "executive.json"
            with redirect_stdout(output):
                exit_code = main(
                    [
                        str(root),
                        "--report",
                        str(technical),
                        "--executive-report",
                        str(executive),
                        "--allow-report-inside-root",
                    ]
                )
            self.assertEqual(exit_code, 1)
            self.assertNotIn(CPF, output.getvalue())
            self.assertNotIn(SENSITIVE_VALUE, output.getvalue())


class AdditionalFormatTests(unittest.TestCase):
    def test_archive_and_sqlite_are_still_scanned_without_extraction_to_disk(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with zipfile.ZipFile(root / "documents.zip", "w") as archive:
                archive.writestr("internal/data.txt", CPF)
            database = sqlite3.connect(root / "customers.sqlite")
            database.execute("CREATE TABLE customers (cpf TEXT)")
            database.execute("INSERT INTO customers VALUES (?)", (CPF,))
            database.commit()
            database.close()
            result = scan_directory(root)
            self.assertEqual(result.valid_cpfs, 2)

    def test_archive_limit_and_non_utf8_errors_are_controlled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with zipfile.ZipFile(root / "large.zip", "w") as archive:
                archive.writestr("large.txt", "x" * 100)
            (root / "bad.txt").write_bytes(b"\xff\xfe")
            result = scan_directory(root, extraction_limits=ExtractionLimits(max_member_size=50))
            self.assertEqual(result.files_failed, 2)
            self.assertEqual(
                result.errors, {"ExtractionLimitError": 1, "UnicodeDecodeError": 1}
            )


if __name__ == "__main__":
    unittest.main()
