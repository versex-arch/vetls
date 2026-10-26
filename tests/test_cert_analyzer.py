import unittest
from datetime import datetime, timedelta, timezone

from helpers import der, load_fixture, make_cert, pem
from vetls.cert_analyzer import analyze_certificate, empty_cert_schema, max_lifetime_for


def analyze(host="example.com", **kwargs):
    cert, _ = make_cert(**kwargs)
    return analyze_certificate(der(cert), target_host=host)


class CertificateTests(unittest.TestCase):
    def test_valid_ca_issued_certificate(self):
        c = analyze()
        self.assertIsNone(c["error"])
        self.assertFalse(c["is_expired"])
        self.assertFalse(c["is_not_yet_valid"])
        self.assertFalse(c["issuer_equals_subject"])
        self.assertEqual(c["san_status"], "ok")
        self.assertEqual(c["signature_scheme"], "SHA256")
        self.assertIsNone(c["weak_signature"])
        self.assertIsNone(c["weak_public_key"])
        self.assertEqual(c["public_key"], "RSA 2048")
        self.assertEqual(c["lifetime_days"], 90)
        self.assertEqual(len(c["sha256_fingerprint"]), 64)

    def test_expired(self):
        now = datetime.now(timezone.utc)
        c = analyze(not_before=now - timedelta(days=30), not_after=now - timedelta(days=5))
        self.assertTrue(c["is_expired"])
        self.assertFalse(c["is_not_yet_valid"])
        self.assertLess(c["days_remaining"], 0)

    def test_not_yet_valid(self):
        now = datetime.now(timezone.utc)
        c = analyze(not_before=now + timedelta(days=5), not_after=now + timedelta(days=50))
        self.assertTrue(c["is_not_yet_valid"])
        self.assertFalse(c["is_expired"])

    def test_self_signed_compares_full_names(self):
        self.assertTrue(analyze(self_signed=True)["issuer_equals_subject"])
        self.assertFalse(analyze()["issuer_equals_subject"])

    def test_long_lifetime(self):
        self.assertEqual(analyze(days=825)["lifetime_days"], 825)

    def test_max_lifetime_schedule(self):
        from datetime import date

        cases = [
            (date(2019, 1, 1), 825),
            (date(2020, 9, 1), 398),
            (date(2026, 3, 14), 398),
            (date(2026, 3, 15), 200),
            (date(2027, 3, 15), 100),
            (date(2029, 3, 14), 100),
            (date(2029, 3, 15), 47),
        ]
        for issued, limit in cases:
            with self.subTest(issued=issued):
                self.assertEqual(max_lifetime_for(issued), limit)
        c = analyze(not_before=datetime(2025, 1, 10, tzinfo=timezone.utc), days=90)
        self.assertEqual(c["max_lifetime_days"], 398)

    def test_missing_san_extension(self):
        c = analyze(san_dns=None)
        self.assertEqual(c["san_status"], "missing_extension")

    def test_san_mismatch(self):
        c = analyze(host="other.org")
        self.assertEqual(c["san_status"], "mismatch")
        self.assertIn("other.org", c["san_note"])

    def test_no_target_skips_name_check(self):
        cert, _ = make_cert()
        c = analyze_certificate(der(cert))
        self.assertEqual(c["san_status"], "not_checked")
        self.assertEqual(c["san_entries"], ["DNS:example.com"])

    def test_wildcard_matches_exactly_one_label(self):
        self.assertEqual(analyze("a.example.com", san_dns=("*.example.com",))["san_status"], "ok")
        self.assertEqual(analyze("A.Example.COM.", san_dns=("*.example.com",))["san_status"], "ok")
        self.assertEqual(analyze("a.b.example.com", san_dns=("*.example.com",))["san_status"], "mismatch")
        self.assertEqual(analyze("example.com", san_dns=("*.example.com",))["san_status"], "mismatch")

    def test_wildcard_on_public_suffix_never_matches(self):
        self.assertEqual(analyze("a.com", san_dns=("*.com",))["san_status"], "mismatch")
        self.assertEqual(analyze("a.co.uk", san_dns=("*.co.uk",))["san_status"], "mismatch")

    def test_partial_and_inner_wildcards_are_rejected(self):
        self.assertEqual(analyze("ab.example.com", san_dns=("a*.example.com",))["san_status"], "mismatch")
        self.assertEqual(analyze("x.a.example.com", san_dns=("x.*.example.com",))["san_status"], "mismatch")

    def test_ip_target_matches_ip_san(self):
        c = analyze("127.0.0.1", san_dns=("localhost",), san_ip=("127.0.0.1",))
        self.assertEqual(c["san_status"], "ok")
        self.assertIn("IP:127.0.0.1", c["san_entries"])

    def test_ip_target_with_dns_only_san_is_mismatch(self):
        c = analyze("127.0.0.1", san_dns=("example.com",))
        self.assertEqual(c["san_status"], "mismatch")
        self.assertIn("no IP address SAN", c["san_note"])

    def test_weak_rsa_key(self):
        c = analyze(key_type="rsa1024")
        self.assertIn("1024", c["weak_public_key"])
        self.assertEqual(c["public_key"], "RSA 1024")

    def test_ec_key_is_fine(self):
        c = analyze(key_type="ec")
        self.assertIsNone(c["weak_public_key"])
        self.assertTrue(c["public_key"].startswith("EC secp256r1"))

    def test_sha1_signature_is_flagged(self):
        # cryptography refuses to *create* SHA-1 signatures, so use a fixture
        # generated with `openssl req -x509 -sha1`.
        c = analyze_certificate(load_fixture("sha1_signed.pem"), "example.com")
        self.assertEqual(c["signature_scheme"], "SHA1")
        self.assertEqual(c["weak_signature"], "SHA1")

    def test_ed25519_self_signed_is_not_weak(self):
        c = analyze(key_type="ed25519", self_signed=True)
        self.assertEqual(c["signature_scheme"], "Ed25519")
        self.assertIsNone(c["weak_signature"])
        self.assertEqual(c["public_key"], "Ed25519")

    def test_signature_describes_signer_not_subject_key(self):
        # An Ed25519 leaf signed by an RSA CA is an RSA/SHA-256 signature.
        c = analyze(key_type="ed25519")
        self.assertEqual(c["signature_scheme"], "SHA256")

    def test_pem_and_der_are_equivalent(self):
        cert, _ = make_cert()
        a = analyze_certificate(der(cert), "example.com")
        b = analyze_certificate(pem(cert), "example.com")
        self.assertEqual(a, b)

    def test_garbage_input_yields_complete_error_schema(self):
        c = analyze_certificate(b"definitely not a certificate")
        ok, _ = make_cert()
        self.assertTrue(c["error"])
        self.assertEqual(set(c), set(analyze_certificate(der(ok))))
        self.assertEqual(c["san_status"], "error")

    def test_empty_schema_has_all_keys(self):
        cert, _ = make_cert()
        self.assertEqual(set(empty_cert_schema("boom")), set(analyze_certificate(der(cert))))
        self.assertIsNone(empty_cert_schema()["error"])


if __name__ == "__main__":
    unittest.main()
