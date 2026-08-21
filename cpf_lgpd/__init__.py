"""Ferramentas para localizar candidatos a CPF com exposicao minima."""

from .scanner import ScanResult, is_valid_cpf, scan_directory
from .version import APPLICATION_VERSION

__all__ = ["ScanResult", "is_valid_cpf", "scan_directory"]
__version__ = APPLICATION_VERSION
