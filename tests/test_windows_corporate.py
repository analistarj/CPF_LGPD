import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from cpf_lgpd.cli import main
from cpf_lgpd.configuration import load_config
from cpf_lgpd.path_security import (
    UnsafePathError,
    normalize_windows_display_path,
    parse_unc_path,
    validate_root_syntax,
)
from cpf_lgpd.permissions import (
    AccessControlEntry,
    LocalPermissionAdapter,
    ReportProtectionError,
    SecurityDescriptorSnapshot,
    WindowsPermissionAdapter,
    protect_report_path,
)
from cpf_lgpd.reporting import write_json_report
from cpf_lgpd.scanner import ScanResult, scan_directory

CPF = "52998224725"


class FakeWindowsBackend:
    def __init__(self, file_snapshot, share_snapshot=None, *, share_error=False):
        self.file_snapshot = file_snapshot
        self.share_snapshot = share_snapshot
        self.share_error = share_error
        self.share_request = None
        self.share_calls = 0
        self.protected = []

    def read_file_security(self, _path):
        return self.file_snapshot

    def read_share_security(self, server, share):
        self.share_calls += 1
        self.share_request = (server, share)
        if self.share_error:
            raise OSError("sintetico")
        return self.share_snapshot

    def protect_file(self, path):
        self.protected.append(path)


def _snapshot(*aces, owner="S-1-5-21-1-1001", name="DOMINIO\\conta-sintetica", **kwargs):
    return SecurityDescriptorSnapshot(owner, name, tuple(aces), **kwargs)


class WindowsPathPolicyTests(unittest.TestCase):
    def test_unc_normal_and_extended_paths_are_parsed_without_credentials(self):
        standard = parse_unc_path(r"\\servidor\compartilhamento\area")
        extended = parse_unc_path(r"\\?\UNC\servidor\compartilhamento\area")
        self.assertEqual(standard, extended)
        self.assertEqual(standard.server, "servidor")
        self.assertEqual(standard.share, "compartilhamento")
        self.assertEqual(
            normalize_windows_display_path(r"\\?\C:\dados\arquivo.txt"),
            r"C:\dados\arquivo.txt",
        )

    def test_device_url_incomplete_unc_and_relative_roots_are_rejected(self):
        invalid = (
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1",
            r"\\servidor",
            r"\\servidor\IPC$",
            "smb://usuario:senha@servidor/share",
            "pasta-relativa",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(UnsafePathError):
                validate_root_syntax(value)
        validate_root_syntax(r"C:\dados")
        validate_root_syntax(r"\\?\C:\dados")
        validate_root_syntax(r"\\servidor\share")


class WindowsAclTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "integracao pywin32 executa somente no Windows")
    def test_real_pywin32_backend_reads_and_protects_temporary_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text("{}", encoding="utf-8")
            adapter = LocalPermissionAdapter(require_windows_acl=True)
            before = adapter.assess(path)
            self.assertEqual(before.source, "windows_ntfs_dacl")
            self.assertNotEqual(before.owner, "unknown")
            protect_report_path(path)
            after = adapter.assess(path)
            self.assertEqual(after.level, "owner_restricted")
            self.assertFalse(after.unknown)

    def test_ntfs_and_share_acl_use_the_most_restrictive_known_scope(self):
        ntfs = _snapshot(AccessControlEntry("S-1-1-0", "allow", 0x80000000))
        share = _snapshot(
            AccessControlEntry("S-1-5-21-1-1001", "allow", 0x80000000),
            dacl_protected=True,
        )
        backend = FakeWindowsBackend(ntfs, share)
        adapter = WindowsPermissionAdapter(backend=backend)
        result = adapter.assess(Path(r"\\servidor\share\area\arquivo.txt"))
        repeated = adapter.assess(Path(r"\\SERVIDOR\SHARE\area\outro.txt"))
        self.assertEqual(result.level, "owner_restricted")
        self.assertEqual(result.score, 0)
        self.assertFalse(result.unknown)
        self.assertTrue(result.share_acl_evaluated)
        self.assertEqual(backend.share_request, ("servidor", "share"))
        self.assertEqual(backend.share_calls, 1)
        self.assertEqual(repeated, result)
        self.assertEqual(result.source, "windows_ntfs_dacl+windows_smb_share_dacl")

    def test_public_internal_limited_null_and_complex_dacls_are_deterministic(self):
        cases = (
            (_snapshot(null_dacl=True), "public", 30, False),
            (
                _snapshot(AccessControlEntry("S-1-5-11", "allow", 1)),
                "internal_all",
                22,
                False,
            ),
            (
                _snapshot(AccessControlEntry("S-1-5-21-1-2001", "allow", 1)),
                "internal_limited",
                5,
                False,
            ),
            (
                _snapshot(AccessControlEntry("S-1-1-0", "deny", 1)),
                "unknown",
                10,
                True,
            ),
        )
        for snapshot, level, score, unknown in cases:
            with self.subTest(level=level):
                adapter = WindowsPermissionAdapter(
                    include_share_acl=False,
                    backend=FakeWindowsBackend(snapshot),
                )
                first = adapter.assess(Path("C:/dados/arquivo.txt"))
                second = adapter.assess(Path("C:/dados/arquivo.txt"))
                self.assertEqual(first, second)
                self.assertEqual((first.level, first.score, first.unknown), (level, score, unknown))

    def test_unavailable_share_acl_is_explicit_and_never_exposes_error_text(self):
        ntfs = _snapshot(AccessControlEntry("S-1-5-21-1-1001", "allow", 1))
        adapter = WindowsPermissionAdapter(
            backend=FakeWindowsBackend(ntfs, share_error=True)
        )
        result = adapter.assess(Path(r"\\servidor\share\arquivo.txt"))
        self.assertTrue(result.unknown)
        self.assertEqual(result.score, 10)
        self.assertIn("share_dacl_unavailable", result.source)
        self.assertNotIn("sintetico", json.dumps(result.__dict__))

    def test_windows_report_protection_delegates_to_native_backend(self):
        backend = FakeWindowsBackend(_snapshot())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text("{}", encoding="utf-8")
            with mock.patch("cpf_lgpd.permissions.os.name", "nt"):
                source = protect_report_path(path, backend=backend)
        self.assertEqual(source, "windows_protected_dacl")
        self.assertEqual(len(backend.protected), 1)


class CorporateRuntimeTests(unittest.TestCase):
    def test_cli_preflight_and_safe_report_location_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "data.txt").write_text(CPF, encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main([str(root), "--preflight-only"])
            self.assertEqual(exit_code, 0)
            self.assertIn("Preflight aprovado", stdout.getvalue())

            stderr = StringIO()
            with redirect_stderr(stderr):
                exit_code = main([str(root), "--report", str(root / "report.json")])
            self.assertEqual(exit_code, 2)
            self.assertIn("UnsafePathError", stderr.getvalue())
            self.assertNotIn(CPF, stderr.getvalue())

    def test_report_acl_failure_is_fail_closed_and_removes_temporary_file(self):
        result = ScanResult("/synthetic", "root-synthetic")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "report.json"
            with mock.patch(
                "cpf_lgpd.reporting.protect_report_path",
                side_effect=ReportProtectionError("conteudo-proibido"),
            ):
                with self.assertRaises(ReportProtectionError):
                    write_json_report(target, result)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_report_is_protected_before_atomic_publication(self):
        result = ScanResult("/synthetic", "root-synthetic")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "report.json"
            with mock.patch("cpf_lgpd.reporting.protect_report_path") as protect:
                write_json_report(target, result)
            self.assertTrue(target.exists())
            protect.assert_called_once()
            self.assertNotEqual(protect.call_args.args[0], target)

    def test_file_change_during_scan_is_recorded_without_message_or_finding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "data.txt"
            path.write_text(CPF, encoding="utf-8")
            from cpf_lgpd import scanner

            original = scanner._analyze_file

            def analyze_then_change(*args, **kwargs):
                content = original(*args, **kwargs)
                path.write_text(CPF + "0", encoding="utf-8")
                return content

            with mock.patch("cpf_lgpd.scanner._analyze_file", side_effect=analyze_then_change):
                result = scan_directory(root)
            self.assertEqual(result.errors, {"FileChangedDuringScanError": 1})
            self.assertEqual(result.findings, [])
            self.assertNotIn(CPF, json.dumps(result.to_dict()))

    def test_corporate_configuration_is_strict_and_validated(self):
        self.assertEqual(load_config(None).permission_mode, "strict")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text('{"permission_mode":"invalid"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)
            path.write_text('{"include_share_acl":"yes"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
