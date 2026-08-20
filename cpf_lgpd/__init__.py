"""Ferramentas para localizar candidatos a CPF com exposicao minima."""

from .scanner import ScanResult, is_valid_cpf, scan_directory

__all__ = ["ScanResult", "is_valid_cpf", "scan_directory"]
__version__ = "2.1.0"
