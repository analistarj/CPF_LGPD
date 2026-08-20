"""Interface de linha de comando segura do CPF LGPD."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .configuration import load_config
from .reporting import (
    write_csv_report,
    write_executive_csv_report,
    write_executive_json_report,
    write_json_report,
)
from .scanner import DEFAULT_EXTENSIONS, scan_directory


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("o valor deve ser maior que zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cpf-lgpd",
        description="Localiza CPFs validos sem exibir ou armazenar os numeros encontrados.",
    )
    parser.add_argument("directory", type=Path, help="diretorio ou compartilhamento UNC autorizado")
    parser.add_argument("--report", type=Path, help="relatorio tecnico JSON protegido")
    parser.add_argument("--csv-report", type=Path, help="relatorio tecnico CSV protegido")
    parser.add_argument(
        "--executive-report", type=Path, help="relatorio executivo JSON sem caminho completo"
    )
    parser.add_argument(
        "--executive-csv-report", type=Path, help="relatorio executivo CSV sem caminho completo"
    )
    parser.add_argument("--root-id", help="identificador logico da raiz autorizada")
    parser.add_argument("--config", type=Path, help="configuracao JSON local")
    parser.add_argument(
        "--mode", choices=("cpf-anchor", "full-discovery"), help="modo de descoberta"
    )
    parser.add_argument(
        "--extension",
        action="append",
        dest="extensions",
        metavar="EXT",
        help="extensao textual permitida; pode ser repetida",
    )
    parser.add_argument(
        "--max-file-size-mb", type=_positive_int, help="limite por arquivo (padrao: 50)"
    )
    parser.add_argument(
        "--ocr-language", default="por", help="idioma instalado no Tesseract (padrao: por)"
    )
    parser.add_argument(
        "--max-processing-seconds", type=_positive_int, help="limite total aproximado da varredura"
    )
    parser.add_argument(
        "--hmac-secret-env",
        default="CPF_LGPD_HMAC_SECRET",
        help="nome da variavel de ambiente com segredo de deduplicacao",
    )
    return parser


def _normalize_extensions(values: list[str] | None) -> frozenset[str]:
    if not values:
        return DEFAULT_EXTENSIONS
    return frozenset(
        value.lower() if value.startswith(".") else f".{value.lower()}" for value in values
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config)
        configured_extensions = args.extensions or list(config.extensions)
        secret_value = os.environ.get(args.hmac_secret_env)
        result = scan_directory(
            args.directory,
            extensions=_normalize_extensions(configured_extensions),
            max_file_size=(args.max_file_size_mb or config.max_file_size_mb) * 1024 * 1024,
            ocr_language=args.ocr_language,
            mode=args.mode or config.mode,
            context_window=config.context_window,
            hmac_secret=secret_value.encode() if secret_value else None,
            governance=config.governance,
            score_weights=config.weights,
            max_processing_seconds=args.max_processing_seconds or config.max_processing_seconds,
            root_id=args.root_id,
        )
        if args.report:
            write_json_report(args.report, result)
        if args.csv_report:
            write_csv_report(args.csv_report, result)
        if args.executive_report:
            write_executive_json_report(args.executive_report, result)
        if args.executive_csv_report:
            write_executive_csv_report(args.executive_csv_report, result)
    except (OSError, ValueError) as exception:
        print(f"Erro operacional: {type(exception).__name__}", file=sys.stderr)
        return 2

    print(f"Arquivos examinados: {result.files_scanned}")
    print(f"Arquivos ignorados: {result.files_skipped}")
    print(f"Arquivos com falha: {result.files_failed}")
    print(f"Arquivos com CPF: {len(result.findings)}")
    print(f"Total de CPFs validos: {result.valid_cpfs}")
    if args.report:
        print("Relatorio protegido gravado com sucesso.")
    if args.csv_report:
        print("Relatorio CSV protegido gravado com sucesso.")
    if args.executive_report:
        print("Relatorio executivo protegido gravado com sucesso.")
    if args.executive_csv_report:
        print("Relatorio executivo CSV protegido gravado com sucesso.")
    return 1 if result.valid_cpfs else 0


if __name__ == "__main__":
    raise SystemExit(main())
