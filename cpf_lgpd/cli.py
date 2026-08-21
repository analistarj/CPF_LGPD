"""Interface de linha de comando segura do CPF LGPD."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .configuration import load_config
from .corporate import preflight_root
from .path_security import validate_report_targets
from .permissions import default_permission_adapter
from .reporting import (
    write_csv_report,
    write_executive_csv_report,
    write_executive_json_report,
    write_json_report,
)
from .scanner import DEFAULT_EXTENSIONS, scan_directory
from .version import APPLICATION_VERSION


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
    parser.add_argument("--version", action="version", version=f"%(prog)s {APPLICATION_VERSION}")
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
        "--permission-mode",
        choices=("strict", "best-effort"),
        help="exigir adaptador ACL nativo no Windows ou aceitar exposicao desconhecida",
    )
    parser.add_argument(
        "--share-acl",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="combinar DACL NTFS com ACL do compartilhamento SMB",
    )
    parser.add_argument(
        "--report-protection-mode",
        choices=("strict", "best-effort"),
        help="falhar se a ACL restritiva do relatorio nao puder ser aplicada",
    )
    parser.add_argument(
        "--allow-report-inside-root",
        action="store_true",
        default=None,
        help="excecao explicita para gravar relatorio dentro da raiz examinada",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="validar raiz, listagem e fonte de permissoes sem examinar arquivos",
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
        permission_mode = args.permission_mode or config.permission_mode
        report_protection_mode = (
            args.report_protection_mode or config.report_protection_mode
        )
        include_share_acl = (
            config.include_share_acl if args.share_acl is None else args.share_acl
        )
        allow_reports_inside = (
            config.allow_reports_inside_root
            if args.allow_report_inside_root is None
            else args.allow_report_inside_root
        )
        report_targets = tuple(
            path
            for path in (
                args.report,
                args.csv_report,
                args.executive_report,
                args.executive_csv_report,
            )
            if path is not None
        )
        if report_targets:
            validate_report_targets(
                args.directory,
                report_targets,
                allow_inside_root=allow_reports_inside,
            )
        permission_adapter = default_permission_adapter(
            include_share_acl=include_share_acl,
            require_windows_acl=permission_mode == "strict",
        )
        preflight = preflight_root(
            args.directory,
            permission_adapter,
            require_absolute_root=config.require_absolute_root,
        )
        if args.preflight_only:
            print("Preflight aprovado.")
            print(f"Tipo de raiz: {preflight.root_kind}")
            print(f"Fonte de permissoes: {preflight.permissions.source}")
            return 0
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
            permission_adapter=permission_adapter,
            include_share_acl=include_share_acl,
            require_windows_acl=permission_mode == "strict",
            require_absolute_root=config.require_absolute_root,
        )
        if args.report:
            write_json_report(
                args.report, result, protection_mode=report_protection_mode
            )
        if args.csv_report:
            write_csv_report(
                args.csv_report, result, protection_mode=report_protection_mode
            )
        if args.executive_report:
            write_executive_json_report(
                args.executive_report,
                result,
                protection_mode=report_protection_mode,
            )
        if args.executive_csv_report:
            write_executive_csv_report(
                args.executive_csv_report,
                result,
                protection_mode=report_protection_mode,
            )
    except (OSError, ValueError) as exception:
        print(f"Erro operacional: {type(exception).__name__}", file=sys.stderr)
        return 2

    print(f"Arquivos examinados: {result.files_scanned}")
    print(f"Arquivos ignorados: {result.files_skipped}")
    print(f"Arquivos com falha: {result.files_failed}")
    print(f"Arquivos com achados: {len(result.findings)}")
    print(f"Total de CPFs validos: {result.valid_cpfs}")
    if result.scan_timed_out:
        print("Erro operacional: ProcessingTimeLimit", file=sys.stderr)
        return 2
    if args.report:
        print("Relatorio protegido gravado com sucesso.")
    if args.csv_report:
        print("Relatorio CSV protegido gravado com sucesso.")
    if args.executive_report:
        print("Relatorio executivo protegido gravado com sucesso.")
    if args.executive_csv_report:
        print("Relatorio executivo CSV protegido gravado com sucesso.")
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
