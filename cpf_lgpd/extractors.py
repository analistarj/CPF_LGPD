"""Extratores estruturados com localizacao e limites de seguranca."""

from __future__ import annotations

import csv
import io
import json
import re
import shutil
import sqlite3
import subprocess
import tarfile
import zipfile
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree


class ExtractionError(Exception):
    """Falha controlada durante extracao de conteudo."""


class MissingDependencyError(ExtractionError):
    """Dependencia opcional ou executavel externo indisponivel."""


class ExtractionLimitError(ExtractionError):
    """Conteudo excedeu um limite de seguranca."""


@dataclass(frozen=True)
class ExtractionLimits:
    max_member_size: int = 25 * 1024 * 1024
    max_archive_size: int = 200 * 1024 * 1024
    max_archive_members: int = 2_000
    max_archive_depth: int = 2
    max_database_rows: int = 1_000_000


@dataclass
class _ArchiveBudget:
    """Orcamento acumulado para toda a arvore de conteudo compactado."""

    members: int = 0
    total_size: int = 0

    def reserve(self, size: int, limits: ExtractionLimits) -> None:
        if size < 0 or size > limits.max_member_size:
            raise ExtractionLimitError("membro compactado excede limite individual")
        next_members = self.members + 1
        next_total = self.total_size + size
        if (
            next_members > limits.max_archive_members
            or next_total > limits.max_archive_size
        ):
            raise ExtractionLimitError("arquivo compactado excede limites totais")
        self.members = next_members
        self.total_size = next_total


def _reserve_zip_members(
    archive: zipfile.ZipFile,
    limits: ExtractionLimits,
    budget: _ArchiveBudget,
) -> None:
    for info in archive.infolist():
        if not info.is_dir():
            budget.reserve(info.file_size, limits)


@dataclass(frozen=True)
class ExtractedField:
    """Campo efemero. O texto nunca integra o resultado serializado."""

    text: str
    header: str | None
    location: dict[str, object]


@dataclass(frozen=True)
class ExtractedUnit:
    """Unidade na qual um vinculo pessoa-evidencia pode ser verificado."""

    fields: tuple[ExtractedField, ...]
    location: dict[str, object]
    link_method: str
    ambiguity_penalty: int = 0

    @property
    def text(self) -> str:
        return " ; ".join(
            f"{field.header}: {field.text}" if field.header else field.text
            for field in self.fields
            if field.text
        )


TEXT_EXTENSIONS = frozenset(
    {".csv", ".html", ".htm", ".json", ".log", ".md", ".rtf", ".sql", ".txt", ".xml", ".yaml", ".yml"}
)
PDF_EXTENSIONS = frozenset({".pdf"})
WORD_EXTENSIONS = frozenset({".doc", ".docx"})
SPREADSHEET_EXTENSIONS = frozenset({".xls", ".xlsx"})
IMAGE_EXTENSIONS = frozenset({".bmp", ".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"})
ARCHIVE_EXTENSIONS = frozenset({".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz"})
DATABASE_EXTENSIONS = frozenset({".db", ".db3", ".sqlite", ".sqlite3"})
SUPPORTED_EXTENSIONS = frozenset().union(
    TEXT_EXTENSIONS,
    PDF_EXTENSIONS,
    WORD_EXTENSIONS,
    SPREADSHEET_EXTENSIONS,
    IMAGE_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    DATABASE_EXTENSIONS,
)

_HEADER_WORDS = {
    "cpf",
    "nome",
    "raca",
    "etnia",
    "religiao",
    "opiniao politica",
    "posicionamento politico",
    "preferencia politica",
    "intencao de voto",
    "filiacao sindical",
    "diagnostico",
    "doenca",
    "tratamento",
    "vida sexual",
    "orientacao sexual",
    "teste genetico",
    "dado biometrico",
}


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="strict")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _plain_units(text: str, format_name: str) -> Iterator[ExtractedUnit]:
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.strip():
            location = {"format": format_name, "line": line_number}
            yield ExtractedUnit(
                (ExtractedField(line, None, location),),
                location,
                "direct_textual_statement",
            )


def _csv_units(data: bytes) -> Iterator[ExtractedUnit]:
    stream = io.StringIO(_decode(data), newline="")
    try:
        rows = list(csv.reader(stream))
    except csv.Error as exception:
        raise ExtractionError("CSV invalido") from exception
    if not rows:
        return
    first = [value.strip() for value in rows[0]]
    normalized = [re.sub(r"\s+", " ", value.lower()) for value in first]
    has_header = bool(set(normalized) & _HEADER_WORDS)
    headers = first if has_header else [f"column_{index + 1}" for index in range(len(first))]
    start = 1 if has_header else 0
    for index, row in enumerate(rows[start:], start + 1):
        fields = []
        for column_index, value in enumerate(row, 1):
            header = headers[column_index - 1] if column_index <= len(headers) else f"column_{column_index}"
            fields.append(
                ExtractedField(
                    value,
                    header,
                    {"format": "csv", "row": index, "column": column_index, "header": header},
                )
            )
        if any(field.text for field in fields):
            yield ExtractedUnit(tuple(fields), {"format": "csv", "row": index}, "same_structured_record")


def _json_key_path(base: str, key: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return f"{base}.{key}"
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'{base}["{escaped}"]'


def _json_units(data: bytes) -> Iterator[ExtractedUnit]:
    try:
        payload = json.loads(_decode(data))
    except json.JSONDecodeError as exception:
        raise ExtractionError("JSON invalido") from exception

    def walk(value: object, path: str) -> Iterator[ExtractedUnit]:
        if isinstance(value, dict):
            fields = []
            for key, child in value.items():
                child_path = _json_key_path(path, str(key))
                if child is None or isinstance(child, (str, int, float, bool)):
                    fields.append(
                        ExtractedField(
                            "" if child is None else str(child),
                            str(key),
                            {"format": "json", "json_path": child_path, "record_object": path},
                        )
                    )
            if fields:
                yield ExtractedUnit(
                    tuple(fields),
                    {"format": "json", "json_path": path, "record_object": path},
                    "same_json_object",
                )
            for key, child in value.items():
                if isinstance(child, (dict, list)):
                    yield from walk(child, _json_key_path(path, str(key)))
        elif isinstance(value, list):
            scalar_fields = [
                ExtractedField(
                    "" if child is None else str(child),
                    str(index),
                    {"format": "json", "json_path": f"{path}[{index}]", "record_object": path},
                )
                for index, child in enumerate(value)
                if child is None or isinstance(child, (str, int, float, bool))
            ]
            if scalar_fields:
                yield ExtractedUnit(
                    tuple(scalar_fields),
                    {"format": "json", "json_path": path, "record_object": path},
                    "same_json_object",
                )
            for index, child in enumerate(value):
                if isinstance(child, (dict, list)):
                    yield from walk(child, f"{path}[{index}]")

    yield from walk(payload, "$")


def _safe_xml_root(data: bytes) -> ElementTree.Element:
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ExtractionError("declaracoes XML potencialmente inseguras nao sao aceitas")
    try:
        return ElementTree.fromstring(data)  # noqa: S314
    except ElementTree.ParseError as exception:
        raise ExtractionError("XML invalido") from exception


def _xml_units(data: bytes) -> Iterator[ExtractedUnit]:
    root = _safe_xml_root(data)

    def walk(element: ElementTree.Element, path: str) -> Iterator[ExtractedUnit]:
        fields = []
        for name, value in sorted(element.attrib.items()):
            local = _local_name(name)
            fields.append(
                ExtractedField(
                    value,
                    f"@{local}",
                    {"format": "xml", "xpath": f"{path}/@{local}", "record_element": path},
                )
            )
        children = list(element)
        counts: Counter[str] = Counter()
        paths: list[tuple[ElementTree.Element, str]] = []
        for child in children:
            name = _local_name(child.tag)
            counts[name] += 1
            child_path = f"{path}/{name}[{counts[name]}]"
            paths.append((child, child_path))
            if not list(child) and (child.text or "").strip():
                fields.append(
                    ExtractedField(
                        child.text or "",
                        name,
                        {"format": "xml", "xpath": child_path, "record_element": path},
                    )
                )
        if not children and (element.text or "").strip():
            fields.append(
                ExtractedField(
                    element.text or "",
                    _local_name(element.tag),
                    {"format": "xml", "xpath": path, "record_element": path},
                )
            )
        if fields:
            yield ExtractedUnit(
                tuple(fields),
                {"format": "xml", "xpath": path, "record_element": path},
                "same_xml_element",
            )
        for child, child_path in paths:
            if list(child):
                yield from walk(child, child_path)

    yield from walk(root, f"/{_local_name(root.tag)}[1]")


def _column_number(reference: str) -> int:
    letters = re.match(r"[A-Za-z]+", reference)
    result = 0
    for character in letters.group().upper() if letters else "A":
        result = result * 26 + ord(character) - 64
    return result


def _xlsx_units(
    data: bytes,
    limits: ExtractionLimits,
    budget: _ArchiveBudget,
) -> Iterator[ExtractedUnit]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            _reserve_zip_members(archive, limits, budget)
            shared: list[str] = []
            if "xl/sharedStrings.xml" in archive.namelist():
                shared_root = _safe_xml_root(archive.read("xl/sharedStrings.xml"))
                for item in shared_root.iter():
                    if _local_name(item.tag) == "si":
                        shared.append("".join(node.text or "" for node in item.iter() if _local_name(node.tag) == "t"))
            names: dict[str, str] = {}
            relationships: dict[str, str] = {}
            if "xl/_rels/workbook.xml.rels" in archive.namelist():
                rel_root = _safe_xml_root(archive.read("xl/_rels/workbook.xml.rels"))
                for relation in rel_root:
                    relationships[relation.attrib.get("Id", "")] = relation.attrib.get("Target", "")
            if "xl/workbook.xml" in archive.namelist():
                workbook = _safe_xml_root(archive.read("xl/workbook.xml"))
                for sheet in workbook.iter():
                    if _local_name(sheet.tag) == "sheet":
                        rel_id = next(
                            (
                                value
                                for key, value in sheet.attrib.items()
                                if key.endswith("}id") or key == "r:id"
                            ),
                            "",
                        )
                        target = relationships.get(rel_id, "")
                        if target:
                            target = target.lstrip("/")
                            if not target.startswith("xl/"):
                                target = f"xl/{target}"
                            names[target] = sheet.attrib.get("name", Path(target).stem)
            worksheets = sorted(
                name
                for name in archive.namelist()
                if name.startswith("xl/worksheets/") and name.endswith(".xml")
            )
            for sheet_index, worksheet_name in enumerate(worksheets, 1):
                sheet_name = names.get(worksheet_name, f"Sheet{sheet_index}")
                root = _safe_xml_root(archive.read(worksheet_name))
                rows: list[tuple[int, list[tuple[int, str]]]] = []
                for row in root.iter():
                    if _local_name(row.tag) != "row":
                        continue
                    row_number = int(row.attrib.get("r", len(rows) + 1))
                    values = []
                    for cell in row:
                        if _local_name(cell.tag) != "c":
                            continue
                        column = _column_number(cell.attrib.get("r", "A"))
                        kind = cell.attrib.get("t", "")
                        raw = next((node.text or "" for node in cell.iter() if _local_name(node.tag) == "v"), "")
                        if kind == "s" and raw.isdigit() and int(raw) < len(shared):
                            value = shared[int(raw)]
                        elif kind == "inlineStr":
                            value = "".join(node.text or "" for node in cell.iter() if _local_name(node.tag) == "t")
                        else:
                            value = raw
                        values.append((column, value))
                    if values:
                        rows.append((row_number, values))
                if not rows:
                    continue
                normalized = {re.sub(r"\s+", " ", value.strip().lower()) for _column, value in rows[0][1]}
                has_header = bool(normalized & _HEADER_WORDS)
                headers = {column: value for column, value in rows[0][1]} if has_header else {}
                for row_number, values in rows[1 if has_header else 0 :]:
                    fields = tuple(
                        ExtractedField(
                            value,
                            headers.get(column, f"column_{column}"),
                            {
                                "format": "xlsx",
                                "sheet": sheet_name,
                                "row": row_number,
                                "column": column,
                                "header": headers.get(column, f"column_{column}"),
                            },
                        )
                        for column, value in values
                    )
                    yield ExtractedUnit(
                        fields,
                        {"format": "xlsx", "sheet": sheet_name, "row": row_number},
                        "same_structured_record",
                    )
    except zipfile.BadZipFile as exception:
        raise ExtractionError("arquivo XLSX invalido") from exception


def _docx_units(
    data: bytes,
    limits: ExtractionLimits,
    budget: _ArchiveBudget,
) -> Iterator[ExtractedUnit]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            _reserve_zip_members(archive, limits, budget)
            info = archive.getinfo("word/document.xml")
            root = _safe_xml_root(archive.read(info))
    except (KeyError, zipfile.BadZipFile) as exception:
        raise ExtractionError("arquivo DOCX invalido") from exception
    body = next((node for node in root.iter() if _local_name(node.tag) == "body"), root)
    paragraph_number = 0
    table_number = 0
    for child in body:
        kind = _local_name(child.tag)
        if kind == "p":
            paragraph_number += 1
            value = "".join(node.text or "" for node in child.iter() if _local_name(node.tag) == "t")
            if value.strip():
                location = {"format": "docx", "paragraph": paragraph_number}
                yield ExtractedUnit((ExtractedField(value, None, location),), location, "direct_textual_statement")
        elif kind == "tbl":
            table_number += 1
            rows = [node for node in child if _local_name(node.tag) == "tr"]
            headers: list[str] = []
            for row_number, row in enumerate(rows, 1):
                cells = [node for node in row if _local_name(node.tag) == "tc"]
                values = [
                    "".join(
                        node.text or ""
                        for node in cell.iter()
                        if _local_name(node.tag) == "t"
                    )
                    for cell in cells
                ]
                if row_number == 1 and {value.strip().lower() for value in values} & _HEADER_WORDS:
                    headers = values
                    continue
                fields = tuple(
                    ExtractedField(
                        value,
                        headers[index] if index < len(headers) else f"column_{index + 1}",
                        {
                            "format": "docx",
                            "table": table_number,
                            "row": row_number,
                            "column": index + 1,
                            "header": (
                                headers[index]
                                if index < len(headers)
                                else f"column_{index + 1}"
                            ),
                        },
                    )
                    for index, value in enumerate(values)
                )
                if fields:
                    yield ExtractedUnit(
                        fields,
                        {"format": "docx", "table": table_number, "row": row_number},
                        "same_table_row",
                    )


def _pdf_units(data: bytes) -> Iterator[ExtractedUnit]:
    try:
        from pypdf import PdfReader
    except ImportError as exception:
        raise MissingDependencyError("instale pypdf") from exception
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        for page_number, page in enumerate(reader.pages, 1):
            for line_number, line in enumerate((page.extract_text() or "").splitlines(), 1):
                if line.strip():
                    location = {"format": "pdf", "page": page_number, "line": line_number}
                    yield ExtractedUnit((ExtractedField(line, None, location),), location, "direct_textual_statement")
    except Exception as exception:
        raise ExtractionError("PDF invalido ou protegido") from exception


def _image_units(data: bytes, ocr_language: str) -> Iterator[ExtractedUnit]:
    try:
        import pytesseract
        from PIL import Image
    except ImportError as exception:
        raise MissingDependencyError("instale Pillow e pytesseract") from exception
    try:
        with Image.open(io.BytesIO(data)) as image:
            text = pytesseract.image_to_string(image, lang=ocr_language)
        for unit in _plain_units(text, "image_ocr"):
            yield ExtractedUnit(unit.fields, unit.location, unit.link_method, ambiguity_penalty=20)
    except pytesseract.TesseractNotFoundError as exception:
        raise MissingDependencyError("executavel tesseract nao encontrado") from exception
    except Exception as exception:
        raise ExtractionError("imagem invalida ou OCR falhou") from exception


def _legacy_xls_units(data: bytes) -> Iterator[ExtractedUnit]:
    try:
        import xlrd
    except ImportError as exception:
        raise MissingDependencyError("instale xlrd") from exception
    try:
        workbook = xlrd.open_workbook(file_contents=data, on_demand=True)
        for sheet in workbook.sheets():
            headers: list[str] = []
            for row_index, row in enumerate(sheet.get_rows(), 1):
                values = [str(cell.value) for cell in row]
                if row_index == 1 and {value.strip().lower() for value in values} & _HEADER_WORDS:
                    headers = values
                    continue
                fields = tuple(
                    ExtractedField(
                        value,
                        headers[index] if index < len(headers) else f"column_{index + 1}",
                        {
                            "format": "xls",
                            "sheet": sheet.name,
                            "row": row_index,
                            "column": index + 1,
                            "header": (
                                headers[index]
                                if index < len(headers)
                                else f"column_{index + 1}"
                            ),
                        },
                    )
                    for index, value in enumerate(values)
                )
                yield ExtractedUnit(
                    fields,
                    {"format": "xls", "sheet": sheet.name, "row": row_index},
                    "same_structured_record",
                )
    except Exception as exception:
        raise ExtractionError("planilha XLS invalida") from exception


def _legacy_doc_units(path: Path) -> Iterator[ExtractedUnit]:
    executable = shutil.which("antiword")
    if not executable:
        raise MissingDependencyError("executavel antiword nao encontrado")
    try:
        process = subprocess.run(  # noqa: S603
            [executable, str(path)], capture_output=True, check=False, timeout=120, shell=False
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        raise ExtractionError("antiword falhou ou excedeu o tempo limite") from exception
    if process.returncode:
        raise ExtractionError("antiword nao conseguiu ler o documento")
    yield from _plain_units(process.stdout.decode("utf-8", errors="replace"), "doc")


def _archive_units(
    data: bytes,
    suffix: str,
    limits: ExtractionLimits,
    ocr_language: str,
    depth: int,
    budget: _ArchiveBudget,
) -> Iterator[ExtractedUnit]:
    if depth > limits.max_archive_depth:
        raise ExtractionLimitError("profundidade maxima de arquivos compactados excedida")

    def consume(name: str, payload: bytes) -> Iterator[ExtractedUnit]:
        for unit in iter_units_bytes(
            payload,
            Path(name).suffix.lower(),
            limits,
            ocr_language,
            depth,
            budget,
        ):
            location = {"archive_member": name, **unit.location}
            fields = tuple(
                ExtractedField(
                    field.text,
                    field.header,
                    {"archive_member": name, **field.location},
                )
                for field in unit.fields
            )
            yield ExtractedUnit(fields, location, unit.link_method, unit.ambiguity_penalty)

    try:
        if suffix == ".zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if not info.is_dir():
                        budget.reserve(info.file_size, limits)
                        yield from consume(info.filename, archive.read(info))
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for info in archive:
                    if info.isfile():
                        budget.reserve(info.size, limits)
                        stream = archive.extractfile(info)
                        if stream:
                            yield from consume(info.name, stream.read())
    except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, tarfile.TarError, OSError) as exception:
        raise ExtractionError("arquivo compactado invalido") from exception


def iter_units_bytes(
    data: bytes,
    suffix: str,
    limits: ExtractionLimits,
    ocr_language: str,
    depth: int = 0,
    _archive_budget: _ArchiveBudget | None = None,
) -> Iterator[ExtractedUnit]:
    """Extrai unidades estruturais de bytes sem gravar conteudo no disco."""
    if suffix == ".csv":
        yield from _csv_units(data)
    elif suffix == ".json":
        yield from _json_units(data)
    elif suffix == ".xml":
        yield from _xml_units(data)
    elif suffix in TEXT_EXTENSIONS:
        yield from _plain_units(_decode(data), suffix.lstrip("."))
    elif suffix in PDF_EXTENSIONS:
        yield from _pdf_units(data)
    elif suffix == ".docx":
        yield from _docx_units(data, limits, _archive_budget or _ArchiveBudget())
    elif suffix == ".xlsx":
        yield from _xlsx_units(data, limits, _archive_budget or _ArchiveBudget())
    elif suffix == ".xls":
        yield from _legacy_xls_units(data)
    elif suffix in IMAGE_EXTENSIONS:
        yield from _image_units(data, ocr_language)
    elif suffix in ARCHIVE_EXTENSIONS:
        yield from _archive_units(
            data,
            suffix,
            limits,
            ocr_language,
            depth + 1,
            _archive_budget or _ArchiveBudget(),
        )
    elif suffix in {".doc", *DATABASE_EXTENSIONS}:
        raise ExtractionError("formato dentro de compactado exige processamento independente")


def iter_database_units(path: Path, limits: ExtractionLimits) -> Iterator[ExtractedUnit]:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.DatabaseError as exception:
        raise ExtractionError("nao foi possivel abrir o banco SQLite") from exception
    rows_seen = 0
    try:
        tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        for (table,) in tables:
            quoted = table.replace('"', '""')
            cursor = connection.execute(f'SELECT * FROM "{quoted}"')  # noqa: S608
            headers = [item[0] for item in cursor.description or ()]
            for row_number, row in enumerate(cursor, 1):
                rows_seen += 1
                if rows_seen > limits.max_database_rows:
                    raise ExtractionLimitError("banco excede limite de linhas")
                fields = tuple(
                    ExtractedField(
                        "" if value is None else str(value),
                        headers[index],
                        {"format": "sqlite", "table": table, "row": row_number, "column": headers[index]},
                    )
                    for index, value in enumerate(row)
                )
                yield ExtractedUnit(
                    fields,
                    {"format": "sqlite", "table": table, "row": row_number},
                    "same_structured_record",
                )
    except sqlite3.DatabaseError as exception:
        raise ExtractionError("banco SQLite invalido") from exception
    finally:
        connection.close()


def iter_units_path(path: Path, limits: ExtractionLimits, ocr_language: str) -> Iterator[ExtractedUnit]:
    """Seleciona extrator e preserva a unidade estrutural do formato."""
    suffix = path.suffix.lower()
    if suffix in DATABASE_EXTENSIONS:
        yield from iter_database_units(path, limits)
    elif suffix == ".doc":
        yield from _legacy_doc_units(path)
    else:
        yield from iter_units_bytes(path.read_bytes(), suffix, limits, ocr_language)


def iter_text_bytes(
    data: bytes,
    suffix: str,
    limits: ExtractionLimits,
    ocr_language: str,
    depth: int = 0,
) -> Iterator[str]:
    """Compatibilidade: expoe somente texto efemero para consumidores antigos."""
    for unit in iter_units_bytes(data, suffix, limits, ocr_language, depth):
        yield unit.text + "\n"


def iter_text_path(path: Path, limits: ExtractionLimits, ocr_language: str) -> Iterator[str]:
    """Compatibilidade: expoe somente texto efemero para consumidores antigos."""
    for unit in iter_units_path(path, limits, ocr_language):
        yield unit.text + "\n"
