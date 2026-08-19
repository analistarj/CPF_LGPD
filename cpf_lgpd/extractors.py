"""Extratores de texto com limites para formatos corporativos comuns."""

from __future__ import annotations

import io
import shutil
import sqlite3
import subprocess
import tarfile
import zipfile
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


TEXT_EXTENSIONS = frozenset(
    {
        ".csv",
        ".html",
        ".htm",
        ".json",
        ".log",
        ".md",
        ".rtf",
        ".sql",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
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


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="strict")


def _xml_text(data: bytes) -> str:
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ExtractionError("declaracoes XML potencialmente inseguras nao sao aceitas")
    try:
        root = ElementTree.fromstring(data)  # noqa: S314 - DTD e entidades bloqueados acima
    except ElementTree.ParseError as exception:
        raise ExtractionError("XML interno invalido") from exception
    return " ".join(text for text in root.itertext() if text)


def _office_open_xml(data: bytes, suffix: str, limits: ExtractionLimits) -> Iterator[str]:
    names: tuple[str, ...]
    prefixes: tuple[str, ...]
    if suffix == ".docx":
        names = ()
        prefixes = ("word/document.xml", "word/header", "word/footer", "word/footnotes.xml")
    else:
        names = ("xl/sharedStrings.xml",)
        prefixes = ("xl/worksheets/",)

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.file_size > limits.max_member_size:
                    raise ExtractionLimitError("parte Office excede limite")
                if info.filename in names or info.filename.startswith(prefixes):
                    yield _xml_text(archive.read(info)) + "\n"
    except zipfile.BadZipFile as exception:
        raise ExtractionError("arquivo Office invalido") from exception


def _pdf(data: bytes) -> Iterator[str]:
    try:
        from pypdf import PdfReader
    except ImportError as exception:
        raise MissingDependencyError("instale pypdf") from exception
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        for page in reader.pages:
            yield (page.extract_text() or "") + "\n"
    except Exception as exception:  # pypdf expoe excecoes diferentes por versao
        raise ExtractionError("PDF invalido ou protegido") from exception


def _image(data: bytes, ocr_language: str) -> Iterator[str]:
    try:
        import pytesseract
        from PIL import Image
    except ImportError as exception:
        raise MissingDependencyError("instale Pillow e pytesseract") from exception
    try:
        with Image.open(io.BytesIO(data)) as image:
            yield pytesseract.image_to_string(image, lang=ocr_language) + "\n"
    except pytesseract.TesseractNotFoundError as exception:
        raise MissingDependencyError("executavel tesseract nao encontrado") from exception
    except Exception as exception:
        raise ExtractionError("imagem invalida ou OCR falhou") from exception


def _legacy_xls(data: bytes) -> Iterator[str]:
    try:
        import xlrd
    except ImportError as exception:
        raise MissingDependencyError("instale xlrd") from exception
    try:
        workbook = xlrd.open_workbook(file_contents=data, on_demand=True)
        for sheet in workbook.sheets():
            for row in sheet.get_rows():
                yield " ".join(str(cell.value) for cell in row) + "\n"
    except Exception as exception:
        raise ExtractionError("planilha XLS invalida") from exception


def _legacy_doc(path: Path) -> Iterator[str]:
    executable = shutil.which("antiword")
    if not executable:
        raise MissingDependencyError("executavel antiword nao encontrado")
    try:
        process = subprocess.run(  # noqa: S603 - executavel resolvido e shell desativado
            [executable, str(path)], capture_output=True, check=False, timeout=120, shell=False
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        raise ExtractionError("antiword falhou ou excedeu o tempo limite") from exception
    if process.returncode:
        raise ExtractionError("antiword nao conseguiu ler o documento")
    yield process.stdout.decode("utf-8", errors="replace") + "\n"


def _archive(
    data: bytes,
    suffix: str,
    limits: ExtractionLimits,
    ocr_language: str,
    depth: int,
) -> Iterator[str]:
    if depth > limits.max_archive_depth:
        raise ExtractionLimitError("profundidade maxima de arquivos compactados excedida")
    total = 0
    members = 0

    def validate_member(size: int) -> None:
        nonlocal total, members
        members += 1
        total += size
        if members > limits.max_archive_members or total > limits.max_archive_size:
            raise ExtractionLimitError("arquivo compactado excede limites totais")
        if size > limits.max_member_size:
            raise ExtractionLimitError("membro compactado excede limite individual")

    def consume(name: str, payload: bytes) -> Iterator[str]:
        yield from iter_text_bytes(payload, Path(name).suffix.lower(), limits, ocr_language, depth)
        yield "\n"

    try:
        if suffix == ".zip":
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if not info.is_dir():
                        validate_member(info.file_size)
                        yield from consume(info.filename, archive.read(info))
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for info in archive:
                    if info.isfile():
                        validate_member(info.size)
                        stream = archive.extractfile(info)
                        if stream:
                            yield from consume(info.name, stream.read())
    except (
        RuntimeError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        tarfile.TarError,
        OSError,
    ) as exception:
        raise ExtractionError("arquivo compactado invalido") from exception


def iter_text_bytes(
    data: bytes,
    suffix: str,
    limits: ExtractionLimits,
    ocr_language: str,
    depth: int = 0,
) -> Iterator[str]:
    """Extrai texto de bytes sem escrever membros compactados no disco."""
    if suffix in TEXT_EXTENSIONS:
        yield _decode(data)
    elif suffix in PDF_EXTENSIONS:
        yield from _pdf(data)
    elif suffix in {".docx", ".xlsx"}:
        yield from _office_open_xml(data, suffix, limits)
    elif suffix == ".xls":
        yield from _legacy_xls(data)
    elif suffix in IMAGE_EXTENSIONS:
        yield from _image(data, ocr_language)
    elif suffix in ARCHIVE_EXTENSIONS:
        yield from _archive(data, suffix, limits, ocr_language, depth + 1)
    elif suffix in {".doc", *DATABASE_EXTENSIONS}:
        raise ExtractionError("formato dentro de compactado exige processamento independente")


def iter_database(path: Path, limits: ExtractionLimits) -> Iterator[str]:
    """Le valores de bancos SQLite em modo somente leitura."""
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.DatabaseError as exception:
        raise ExtractionError("nao foi possivel abrir o banco SQLite") from exception
    rows = 0
    try:
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
        for (table,) in tables:
            quoted = table.replace('"', '""')
            for row in connection.execute(f'SELECT * FROM "{quoted}"'):  # noqa: S608
                rows += 1
                if rows > limits.max_database_rows:
                    raise ExtractionLimitError("banco excede limite de linhas")
                yield " ".join(str(value) for value in row if value is not None) + "\n"
    except sqlite3.DatabaseError as exception:
        raise ExtractionError("banco SQLite invalido") from exception
    finally:
        connection.close()


def iter_text_path(path: Path, limits: ExtractionLimits, ocr_language: str) -> Iterator[str]:
    """Seleciona um extrator de acordo com a extensao do arquivo."""
    suffix = path.suffix.lower()
    if suffix in DATABASE_EXTENSIONS:
        yield from iter_database(path, limits)
    elif suffix == ".doc":
        yield from _legacy_doc(path)
    elif suffix in TEXT_EXTENSIONS:
        with path.open("r", encoding="utf-8", errors="strict", newline="") as stream:
            while chunk := stream.read(64 * 1024):
                yield chunk
    else:
        yield from iter_text_bytes(path.read_bytes(), suffix, limits, ocr_language)
