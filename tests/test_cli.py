import contextlib
import io
import json
import os
import ssl
import tempfile
import unittest

from helpers import CA_FILE, RawServer, TLSServer, free_port, make_cert
from vetls import __version__
from vetls.cli import exit_code_for, main, render_report

V = ssl.TLSVersion


def run(*argv, trust_test_ca=True):
    if trust_test_ca and argv and argv[0] not in ("--version", "--help", "--list-rules"):
        argv = (*argv, "--ca-file", CA_FILE)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def good_server(**cert_kwargs):
    cert, key = make_cert(cn="localhost", san_dns=("localhost",), san_ip=("127.0.0.1",), **cert_kwargs)
    return TLSServer(cert, key, min_version=V.TLSv1_2, ciphers="ECDHE+AESGCM")


class CliTests(unittest.TestCase):
    def test_json_report_for_clean_server(self):
        with good_server() as srv:
            code, out, _ = run("127.0.0.1", "--port", str(srv.port), "--json", "--timeout", "3")
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(report["overall_severity"], "INFO")
        self.assertEqual(report["tool"], "vetls")
        self.assertEqual(report["version"], __version__)
        self.assertIsNone(report["ssh"])
        self.assertEqual(report["tls"]["score"]["severity"], "INFO")
        self.assertEqual(report["tls"]["certificate"]["san_status"], "ok")
        self.assertEqual(report["tls"]["trust"]["status"], "trusted")
        self.assertEqual(report["errors"], [])
        self.assertTrue(report["scanned_at"].endswith("+00:00"))
        self.assertIn("OpenSSL", report["environment"]["openssl"])

    def test_text_report_and_optional_scan_subcommand(self):
        with good_server() as srv:
            code, out, _ = run("scan", f"127.0.0.1:{srv.port}", "--timeout", "3")
        self.assertEqual(code, 0)
        self.assertIn("Certificate", out)
        self.assertIn("TLSv1.3", out)
        self.assertIn("Overall severity: INFO", out)
        self.assertNotIn("\033[", out)  # not a tty: no colour codes

    def test_findings_give_exit_code_1(self):
        cert, key = make_cert(cn="localhost", san_dns=("localhost",), san_ip=("127.0.0.1",), self_signed=True)
        with TLSServer(cert, key, min_version=V.TLSv1_2, ciphers="ECDHE+AESGCM") as srv:
            code, out, _ = run("127.0.0.1", "--port", str(srv.port), "--timeout", "3")
        self.assertEqual(code, 1)
        self.assertIn("Self-signed", out)
        self.assertIn("Overall severity: MEDIUM", out)

    def test_out_file_is_valid_json(self):
        with good_server() as srv, tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.json")
            code, out, _ = run("127.0.0.1", "--port", str(srv.port), "--out", path, "--timeout", "3")
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
        self.assertEqual(code, 0)
        self.assertIn("Overall severity", out)  # human report is still printed
        self.assertEqual(report["tls"]["status"], "ok")

    def test_unwritable_out_path(self):
        with good_server() as srv:
            code, _, err = run(
                "127.0.0.1", "--port", str(srv.port), "--out", "/nonexistent-dir/x.json", "--timeout", "3"
            )
        self.assertEqual(code, 2)
        self.assertIn("cannot write", err)

    def test_closed_port_exit_code_2(self):
        code, out, _ = run("127.0.0.1", "--port", str(free_port()), "--timeout", "2")
        self.assertEqual(code, 2)
        self.assertIn("ERROR", out)

    def test_ssh_banner_only(self):
        with RawServer(b"SSH-2.0-TestSSH\r\n") as srv:
            code, out, _ = run(
                "127.0.0.1", "--no-tls", "--ssh-port", str(srv.port), "--json", "--timeout", "2"
            )
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertIsNone(report["tls"])
        self.assertEqual(report["ssh"]["banner"], "SSH-2.0-TestSSH")
        self.assertEqual(report["ssh"]["score"]["severity"], "INFO")

    def test_old_ssh_protocol_is_reported(self):
        with RawServer(b"SSH-1.5-Ancient\r\n") as srv:
            code, out, _ = run("127.0.0.1", "--no-tls", "--ssh-port", str(srv.port), "--timeout", "2")
        self.assertEqual(code, 1)
        self.assertIn("obsolete", out)

    def test_tls_and_ssh_together(self):
        with good_server() as tls, RawServer(b"SSH-2.0-X\r\n") as ssh:
            code, out, _ = run(
                "127.0.0.1", "--port", str(tls.port), "--ssh-port", str(ssh.port), "--json", "--timeout", "3"
            )
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(report["tls"]["status"], "ok")
        self.assertEqual(report["ssh"]["status"], "ok")

    def test_usage_errors_exit_2(self):
        cases = [
            ["bad host"],
            ["example.com", "--no-tls"],
            ["example.com", "--port", "70000"],
            ["example.com", "--ssh-port", "0"],
            ["example.com", "--timeout", "0"],
            ["example.com", "--bogus-flag"],
            ["example.com", "--concurrency", "0"],
            ["example.com", "--warn-days", "-1"],
            ["example.com", "--fail-on", "SEVERE"],
            ["example.com", "--ignore", "NOPE-RULE"],
            ["example.com", "--sni", "10.0.0.1"],
            ["example.com", "--targets-file", "/nonexistent/targets.txt"],
            ["good.example", "bad host"],
            [],
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                code, _, err = run(*argv, trust_test_ca=False)
                self.assertEqual(code, 2)
                self.assertTrue(err)

    def test_version_and_help_exit_0(self):
        code, out, _ = run("--version")
        self.assertEqual(code, 0)
        self.assertIn(__version__, out)
        code, out, _ = run("--help")
        self.assertEqual(code, 0)
        self.assertIn("permission", out)

    def test_exit_code_mapping(self):
        for severity, code in [
            ("INFO", 0),
            ("LOW", 0),
            ("MEDIUM", 1),
            ("HIGH", 1),
            ("CRITICAL", 1),
            ("ERROR", 2),
        ]:
            self.assertEqual(exit_code_for(severity), code)
        self.assertEqual(exit_code_for("LOW", fail_on="LOW"), 1)
        self.assertEqual(exit_code_for("HIGH", fail_on="CRITICAL"), 0)
        self.assertEqual(exit_code_for("CRITICAL", fail_on="never"), 0)
        self.assertEqual(exit_code_for("ERROR", fail_on="never"), 2)
        self.assertEqual(exit_code_for("INFO", had_errors=True), 2)
        self.assertEqual(exit_code_for("HIGH", had_errors=True), 1)  # findings win

    def test_colour_only_when_requested(self):
        report = {
            "overall_severity": "HIGH",
            "ssh": None,
            "tls": {
                "status": "error",
                "error": "boom",
                "host": "h",
                "port": 1,
                "score": {},
            },
        }
        self.assertIn("\033[", render_report(report, color=True))
        self.assertNotIn("\033[", render_report(report, color=False))


class CliFeatureTests(unittest.TestCase):
    def test_untrusted_chain_without_ca_file(self):
        with good_server() as srv:
            code, out, _ = run(
                "127.0.0.1", "--port", str(srv.port), "--json", "--timeout", "3", trust_test_ca=False
            )
        report = json.loads(out)
        if report["tls"]["trust"]["status"] == "not_checked":
            self.skipTest("no system trust store here")
        self.assertEqual(code, 1)
        self.assertIn("CERT-UNTRUSTED", [i["id"] for i in report["tls"]["score"]["issues"]])

    def test_fail_on_and_ignore(self):
        cert, key = make_cert(cn="localhost", san_dns=("localhost",), san_ip=("127.0.0.1",), self_signed=True)
        with TLSServer(cert, key, min_version=V.TLSv1_2, ciphers="ECDHE+AESGCM") as srv:
            port = ("127.0.0.1", "--port", str(srv.port), "--timeout", "3")
            self.assertEqual(run(*port)[0], 1)
            self.assertEqual(run(*port, "--fail-on", "high")[0], 0)
            code, out, _ = run(*port, "--ignore", "cert-self-signed,TLS-NO-TLS13", "--json")
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(report["overall_severity"], "INFO")
        self.assertEqual([i["id"] for i in report["tls"]["score"]["ignored"]], ["CERT-SELF-SIGNED"])

    def test_warn_days(self):
        with good_server(days=10) as srv:
            port = ("127.0.0.1", "--port", str(srv.port), "--timeout", "3")
            code, out, _ = run(*port)
            self.assertEqual(code, 1)
            self.assertIn("CERT-EXPIRES-SOON", out)
            self.assertEqual(run(*port, "--warn-days", "5")[0], 0)

    def test_sni_option(self):
        cert, key = make_cert(cn="api.example.test", san_dns=("api.example.test",))
        with TLSServer(cert, key, min_version=V.TLSv1_2, ciphers="ECDHE+AESGCM") as srv:
            code, out, _ = run(
                "127.0.0.1", "--port", str(srv.port), "--sni", "api.example.test", "--timeout", "3"
            )
        self.assertEqual(code, 0)
        self.assertIn("SNI api.example.test", out)

    def test_multiple_targets_and_targets_file(self):
        with good_server() as a, good_server(self_signed=True) as b, tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "targets.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"# staging\n127.0.0.1:{b.port}\n\n127.0.0.1:{a.port}  # duplicate\n")
            code, out, _ = run(f"127.0.0.1:{a.port}", "-f", path, "--json", "--timeout", "3")
            text_code, text, _ = run(f"127.0.0.1:{a.port}", "-f", path, "--timeout", "3")
        multi = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(text_code, 1)
        self.assertEqual(
            [r["target"] for r in multi["reports"]], [f"127.0.0.1:{a.port}", f"127.0.0.1:{b.port}"]
        )
        self.assertEqual([r["overall_severity"] for r in multi["reports"]], ["INFO", "MEDIUM"])
        self.assertEqual(multi["overall_severity"], "MEDIUM")
        self.assertIn("Summary", text)
        self.assertIn(f"=== 127.0.0.1:{b.port} ===", text)

    def test_failed_tls_does_not_hide_ssh_finding(self):
        with RawServer(b"SSH-1.5-Ancient\r\n") as ssh:
            code, out, _ = run(
                "127.0.0.1",
                "--port",
                str(free_port()),
                "--ssh-port",
                str(ssh.port),
                "--json",
                "--timeout",
                "2",
            )
        report = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(report["overall_severity"], "HIGH")
        self.assertEqual(len(report["errors"]), 1)
        self.assertTrue(report["errors"][0].startswith("TLS "))

    def test_failed_tls_with_clean_ssh_is_exit_2(self):
        with RawServer(b"SSH-2.0-Fine\r\n") as ssh:
            code, out, _ = run(
                "127.0.0.1", "--port", str(free_port()), "--ssh-port", str(ssh.port), "--timeout", "2"
            )
        self.assertEqual(code, 2)
        self.assertIn("1 scan(s) failed", out)

    def test_sarif_output(self):
        cert, key = make_cert(cn="localhost", san_dns=("localhost",), san_ip=("127.0.0.1",), self_signed=True)
        with (
            TLSServer(cert, key, min_version=V.TLSv1_2, ciphers="ECDHE+AESGCM") as srv,
            tempfile.TemporaryDirectory() as tmp,
        ):
            path = os.path.join(tmp, "out.sarif")
            code, _, _ = run("127.0.0.1", "--port", str(srv.port), "--sarif", path, "--timeout", "3")
            with open(path, encoding="utf-8") as fh:
                sarif = json.load(fh)
        self.assertEqual(code, 1)
        self.assertEqual(sarif["version"], "2.1.0")
        results = sarif["runs"][0]["results"]
        self.assertIn("CERT-SELF-SIGNED", [r["ruleId"] for r in results])

    def test_list_rules(self):
        code, out, _ = run("--list-rules")
        self.assertEqual(code, 0)
        self.assertIn("CERT-UNTRUSTED", out)
        self.assertIn("CIPHER-NO-PFS", out)

    def test_bad_ca_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write("not a certificate")
        try:
            code, _, err = run("example.com", "--ca-file", fh.name, trust_test_ca=False)
        finally:
            os.unlink(fh.name)
        self.assertEqual(code, 2)
        self.assertIn("cannot load --ca-file", err)


class UiTests(unittest.TestCase):
    def test_banner_and_markers_in_text_mode(self):
        with good_server() as srv:
            code, out, _ = run("127.0.0.1", "--port", str(srv.port), "--timeout", "3")
        self.assertEqual(code, 0)
        self.assertIn("\\___|", out)  # ASCII wordmark
        self.assertIn(f"v{__version__}", out)
        self.assertIn("[*] Checking 127.0.0.1 ...", out)
        self.assertIn("[+] TLSv1.3", out)
        self.assertIn("[+] Trust", out)
        self.assertIn("[=] Overall severity: INFO", out)

    def test_no_banner(self):
        with good_server() as srv:
            _, out, _ = run("127.0.0.1", "--port", str(srv.port), "--timeout", "3", "--no-banner")
        self.assertNotIn("\\___|", out)
        self.assertTrue(out.startswith("[*] Checking"))

    def test_json_output_is_pure_json(self):
        with good_server() as srv:
            _, out, _ = run("127.0.0.1", "--port", str(srv.port), "--timeout", "3", "--json")
        self.assertTrue(out.lstrip().startswith("{"))
        json.loads(out)

    def test_force_color_and_no_color(self):
        from vetls.cli import use_color

        env = dict(os.environ)
        try:
            os.environ.pop("NO_COLOR", None)
            os.environ["FORCE_COLOR"] = "1"
            self.assertTrue(use_color())
            self.assertFalse(use_color(no_color=True))
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(use_color())
        finally:
            os.environ.clear()
            os.environ.update(env)

    def test_severity_tags_are_coloured(self):
        from vetls.ui import Painter

        p = Painter(True)
        self.assertEqual(p.severity("HIGH", brackets=True), "\033[1;31m[HIGH]\033[0m")
        self.assertEqual(p.severity("LOW", 8, brackets=True), "\033[1;36m[LOW]\033[0m   ")
        self.assertEqual(Painter(False).severity("LOW", 8, brackets=True), "[LOW]   ")

    def test_expiring_certificate_is_marked(self):
        from vetls.ui import render_report

        with good_server(days=5) as srv:
            _, out, _ = run("127.0.0.1", "--port", str(srv.port), "--timeout", "3", "--json")
        text = render_report(json.loads(out))
        self.assertIn("[!] Valid", text)
        self.assertIn("[MEDIUM]", text)


if __name__ == "__main__":
    unittest.main()
