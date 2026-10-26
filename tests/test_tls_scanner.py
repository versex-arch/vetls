"""Live tests: the scanner talks to real TLS servers on 127.0.0.1."""

import asyncio
import ssl
import time
import unittest
from datetime import datetime, timedelta, timezone

from helpers import CA_FILE, RawServer, TLSServer, free_port, make_cert, pem
from vetls.scorer import score
from vetls.tls_scanner import TLSScanner

V = ssl.TLSVersion


def server_cert(**kwargs):
    kwargs.setdefault("cn", "localhost")
    kwargs.setdefault("san_dns", ("localhost",))
    kwargs.setdefault("san_ip", ("127.0.0.1",))
    return make_cert(**kwargs)


def scan(server, host="127.0.0.1", timeout=3.0, **kwargs):
    kwargs.setdefault("ca_file", CA_FILE)
    return TLSScanner(host, port=server.port, timeout=timeout, **kwargs).scan_sync()


def ids(result):
    return [i["id"] for i in result["issues"]]


class ProtocolTests(unittest.TestCase):
    def test_modern_server(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv)
        self.assertEqual(r["status"], "ok")
        self.assertIsNone(r["error"])
        self.assertEqual(r["accepted_protocols"], ["TLSv1.2", "TLSv1.3"])
        self.assertIn("TLSv1", r["refused_protocols"])
        self.assertIn("TLSv1.1", r["refused_protocols"])
        self.assertTrue(r["negotiated_ciphers_by_protocol"]["TLSv1.3"].startswith("TLS_"))
        self.assertEqual(r["certificate"]["san_status"], "ok")
        self.assertIsNone(r["certificate"]["error"])
        self.assertEqual(r["host"], "127.0.0.1")
        self.assertIsNone(r["sni"])
        self.assertIn(score(r)["severity"], ("INFO", "LOW"))

    def test_tls12_only_server(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2, max_version=V.TLSv1_2) as srv:
            r = scan(srv)
        self.assertEqual(r["accepted_protocols"], ["TLSv1.2"])
        self.assertIn("TLSv1.3", r["refused_protocols"])
        result = score(r)
        self.assertIn("TLS-NO-TLS13", ids(result))
        self.assertEqual(result["severity"], "LOW")

    def test_tls13_only_server(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_3) as srv:
            r = scan(srv)
        self.assertEqual(r["accepted_protocols"], ["TLSv1.3"])
        self.assertIn("TLSv1.2", r["refused_protocols"])

    def test_legacy_tls10_server_is_flagged(self):
        cert, key = server_cert()
        try:
            srv = TLSServer(cert, key, min_version=V.TLSv1, max_version=V.TLSv1, ciphers="ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError) as exc:
            self.skipTest(f"local OpenSSL cannot serve TLS 1.0: {exc}")
        with srv:
            r = scan(srv)
        if "TLSv1" in r["untestable_protocols"]:
            self.skipTest("local OpenSSL cannot probe TLS 1.0")
        self.assertIn("TLSv1", r["accepted_protocols"])
        result = score(r)
        self.assertIn(result["severity"], ("MEDIUM", "HIGH", "CRITICAL"))
        self.assertTrue(any("TLS 1.0" in m for m in result["reasons"]))

    def test_untestable_is_not_reported_as_refused(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv)
        for name in r["untestable_protocols"]:
            self.assertNotIn(name, r["refused_protocols"])
            self.assertNotIn(name, r["accepted_protocols"])
        every = r["accepted_protocols"] + r["refused_protocols"] + r["untestable_protocols"]
        self.assertEqual(sorted(every), sorted(["SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]))


class CipherTests(unittest.TestCase):
    def test_legacy_cbc_cipher_is_found(self):
        cert, key = server_cert()
        try:
            srv = TLSServer(cert, key, max_version=V.TLSv1_2, ciphers="AES128-SHA:@SECLEVEL=0")
        except ssl.SSLError as exc:
            self.skipTest(f"local OpenSSL has no AES128-SHA: {exc}")
        with srv:
            r = scan(srv)
        self.assertEqual(r["weak_ciphers_accepted"], ["AES128-SHA"])
        result = score(r)
        self.assertEqual(result["severity"], "LOW")
        self.assertTrue(any("AES128-SHA" in m for m in result["reasons"]))

    def test_modern_ciphers_only_means_no_weak_ciphers(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2, ciphers="ECDHE+AESGCM") as srv:
            r = scan(srv)
        self.assertEqual(r["weak_ciphers_accepted"], [])
        self.assertEqual(score(r)["severity"], "INFO")

    def test_static_rsa_cipher_has_no_forward_secrecy(self):
        cert, key = server_cert()
        try:
            srv = TLSServer(cert, key, max_version=V.TLSv1_2, ciphers="AES128-GCM-SHA256:@SECLEVEL=0")
        except ssl.SSLError as exc:
            self.skipTest(f"local OpenSSL has no AES128-GCM-SHA256: {exc}")
        with srv:
            r = scan(srv)
        self.assertEqual(r["weak_ciphers_accepted"], ["AES128-GCM-SHA256"])
        self.assertIn("CIPHER-NO-PFS", ids(score(r)))

    def test_ecdhe_cbc_cipher_is_found(self):
        cert, key = server_cert()
        try:
            srv = TLSServer(cert, key, max_version=V.TLSv1_2, ciphers="ECDHE-RSA-AES128-SHA:@SECLEVEL=0")
        except ssl.SSLError as exc:
            self.skipTest(f"local OpenSSL has no ECDHE-RSA-AES128-SHA: {exc}")
        with srv:
            r = scan(srv)
        self.assertEqual(r["weak_ciphers_accepted"], ["ECDHE-RSA-AES128-SHA"])
        self.assertIn("CIPHER-CBC", ids(score(r)))

    def test_locally_unavailable_ciphers_are_listed_separately(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2, ciphers="ECDHE+AESGCM") as srv:
            r = scan(srv)
        self.assertFalse(set(r["ciphers_not_testable_locally"]) & set(r["weak_ciphers_accepted"]))


class CertificateTests(unittest.TestCase):
    def test_expired_certificate_is_critical(self):
        now = datetime.now(timezone.utc)
        cert, key = server_cert(not_before=now - timedelta(days=60), not_after=now - timedelta(days=1))
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv)
        self.assertTrue(r["certificate"]["is_expired"])
        self.assertEqual(score(r)["severity"], "CRITICAL")

    def test_self_signed_certificate_is_medium(self):
        cert, key = server_cert(self_signed=True)
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv)
        self.assertTrue(r["certificate"]["issuer_equals_subject"])
        self.assertEqual(score(r)["severity"], "MEDIUM")

    def test_name_mismatch_is_high(self):
        cert, key = make_cert(cn="other.example", san_dns=("other.example",))
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv)
        self.assertEqual(r["certificate"]["san_status"], "mismatch")
        self.assertEqual(score(r)["severity"], "HIGH")

    def test_hostname_target_uses_sni_and_matches_dns_san(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv, host="localhost")
        self.assertEqual(r["sni"], "localhost")
        self.assertEqual(r["certificate"]["san_status"], "ok")
        # The server only listens on IPv4; if localhost also resolves to ::1
        # the scanner must still pick the address that answers.
        self.assertEqual(r["address"], "127.0.0.1")
        self.assertIn("127.0.0.1", r["resolved_addresses"])

    def test_sni_override_checks_the_given_name(self):
        cert, key = make_cert(cn="api.example.test", san_dns=("api.example.test",))
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            plain = scan(srv)
            named = scan(srv, sni="api.example.test")
        self.assertEqual(plain["certificate"]["san_status"], "mismatch")
        self.assertEqual(named["sni"], "api.example.test")
        self.assertEqual(named["host"], "127.0.0.1")
        self.assertEqual(named["certificate"]["san_status"], "ok")
        self.assertEqual(score(named)["severity"], "INFO")

    def test_sni_is_really_sent(self):
        cert, key = server_cert()
        seen = []
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            srv.ctx.sni_callback = lambda sock, name, ctx: seen.append(name)
            scan(srv, sni="api.example.test")
        self.assertTrue(seen)
        self.assertEqual(set(seen), {"api.example.test"})


class TrustTests(unittest.TestCase):
    def test_trusted_with_ca_file(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv)
        self.assertEqual(r["trust"]["status"], "trusted")
        self.assertEqual(r["trust"]["ca_source"], f"file:{CA_FILE}")

    def test_unknown_ca_is_untrusted(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv, ca_file=None)
        if r["trust"]["status"] == "not_checked":
            self.skipTest(f"no system trust store here: {r['trust']['detail']}")
        self.assertEqual(r["trust"]["status"], "untrusted")
        self.assertEqual(r["trust"]["ca_source"], "system")
        self.assertIsInstance(r["trust"]["verify_code"], int)
        result = score(r)
        self.assertIn("CERT-UNTRUSTED", ids(result))
        self.assertEqual(result["severity"], "MEDIUM")

    def test_self_signed_is_reported_once(self):
        cert, key = server_cert(self_signed=True)
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv, ca_file=None)
        result = score(r)
        self.assertIn("CERT-SELF-SIGNED", ids(result))
        self.assertNotIn("CERT-UNTRUSTED", ids(result))

    def test_explicitly_trusted_self_signed_certificate_is_accepted(self):
        import os
        import tempfile

        cert, key = server_cert(self_signed=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "pinned.pem")
            with open(path, "wb") as fh:
                fh.write(pem(cert))
            with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
                r = scan(srv, ca_file=path)
        self.assertEqual(r["trust"]["status"], "trusted")
        self.assertEqual(score(r)["severity"], "INFO")

    def test_trust_check_can_be_disabled(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv, ca_file=None, check_trust=False)
        self.assertEqual(r["trust"]["status"], "not_checked")
        result = score(r)
        self.assertNotIn("CERT-UNTRUSTED", ids(result))
        self.assertTrue(any("trust was not checked" in n for n in result["notes"]))

    def test_bad_ca_file_is_not_checked_not_untrusted(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = scan(srv, ca_file="/nonexistent/ca.pem")
        self.assertEqual(r["trust"]["status"], "not_checked")
        self.assertIn("cannot load CA", r["trust"]["detail"])


class FailureTests(unittest.TestCase):
    def test_closed_port(self):
        r = TLSScanner("127.0.0.1", port=free_port(), timeout=2).scan_sync()
        self.assertEqual(r["status"], "error")
        self.assertIn("connection refused", r["error"])
        self.assertEqual(score(r)["severity"], "ERROR")

    def test_unresolvable_host(self):
        r = TLSScanner("nonexistent.invalid", timeout=3).scan_sync()
        self.assertEqual(r["status"], "error")
        self.assertIn("cannot resolve nonexistent.invalid", r["error"])
        self.assertEqual(r["resolved_addresses"], [])

    def test_port_that_does_not_speak_tls(self):
        with RawServer(b"HTTP/1.1 400 Bad Request\r\n\r\n") as srv:
            r = scan(srv)
        self.assertEqual(r["status"], "error")
        self.assertIn("may not speak TLS", r["error"])

    def test_silent_server_is_bounded_by_per_probe_timeouts(self):
        with RawServer(None, hold=5.0) as srv:
            started = time.monotonic()
            r = scan(srv, timeout=0.4)
            elapsed = time.monotonic() - started
        self.assertEqual(r["status"], "error")
        self.assertTrue(r["probe_errors"])
        self.assertLess(elapsed, 6.0)

    def test_error_and_ok_results_share_one_schema(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            ok = scan(srv)
        bad = TLSScanner("127.0.0.1", port=free_port(), timeout=1).scan_sync()
        self.assertEqual(set(ok), set(bad))
        self.assertEqual(set(ok["certificate"]), set(bad["certificate"]))
        self.assertEqual(set(ok["trust"]), set(bad["trust"]))

    def test_constructor_validation(self):
        for kwargs in (
            {"target": ""},
            {"target": "exa mple.com"},
            {"target": "example.com", "port": 70000},
            {"target": "example.com", "timeout": 0},
            {"target": "example.com", "concurrency": 0},
            {"target": "10.0.0.1", "sni": "10.0.0.2"},
            {"target": "10.0.0.1", "sni": "bad name"},
        ):
            with self.subTest(**kwargs), self.assertRaises(ValueError):
                TLSScanner(**kwargs)

    def test_explicit_port_overrides_target_port(self):
        self.assertEqual(TLSScanner("example.com:8443", port=9443).port, 9443)
        self.assertEqual(TLSScanner("example.com:8443").port, 8443)
        self.assertEqual(TLSScanner("example.com").port, 443)


class ApiTests(unittest.TestCase):
    def test_async_scan(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            r = asyncio.run(TLSScanner("127.0.0.1", port=srv.port, timeout=3).scan())
        self.assertEqual(r["status"], "ok")

    def test_scanner_can_be_reused(self):
        cert, key = server_cert()
        with TLSServer(cert, key, min_version=V.TLSv1_2) as srv:
            scanner = TLSScanner("127.0.0.1", port=srv.port, timeout=3)
            first = scanner.scan_sync()
            second = scanner.scan_sync()
        self.assertEqual(first["accepted_protocols"], second["accepted_protocols"])

    def test_scan_sync_inside_running_loop_raises(self):
        async def inner():
            with self.assertRaises(RuntimeError):
                TLSScanner("127.0.0.1", port=1).scan_sync()

        asyncio.run(inner())


if __name__ == "__main__":
    unittest.main()
