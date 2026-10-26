import unittest
from datetime import datetime, timedelta, timezone

from helpers import der, load_fixture, make_cert
from vetls.cert_analyzer import analyze_certificate
from vetls.scorer import RULES, cipher_rule, classify_cipher, normalize_cipher, score, score_ssh


def findings(**overrides):
    cert, _ = make_cert()
    base = {
        "status": "ok",
        "error": None,
        "accepted_protocols": ["TLSv1.2", "TLSv1.3"],
        "refused_protocols": ["TLSv1", "TLSv1.1"],
        "untestable_protocols": [],
        "weak_ciphers_accepted": [],
        "ciphers_not_testable_locally": [],
        "probe_errors": [],
        "certificate": analyze_certificate(der(cert), "example.com"),
    }
    base.update(overrides)
    return base


def severities(result):
    return [i["severity"] for i in result["issues"]]


def ids(result):
    return [i["id"] for i in result["issues"]]


def cert_with(**kwargs):
    cert, _ = make_cert(**kwargs)
    return analyze_certificate(der(cert), "example.com")


def trust(status, code=None, detail="unable to get local issuer certificate"):
    return {"status": status, "detail": detail, "verify_code": code, "ca_source": "system"}


class NormalizeCipherTests(unittest.TestCase):
    def test_inputs(self):
        cases = [
            (("ecdhe-rsa-aes128-gcm-sha256", "TLSv1.2", 128), "ECDHE-RSA-AES128-GCM-SHA256"),
            (["AES128-SHA", "TLSv1.2", 128], "AES128-SHA"),
            ("  des-cbc3-sha\n", "DES-CBC3-SHA"),
            ("TLS_AES_128_GCM_SHA256", "TLS_AES_128_GCM_SHA256"),
            ("", None),
            ("   ", None),
            ((), None),
            (None, None),
            (123, None),
            ((None, "x", 1), None),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(normalize_cipher(raw), expected)


class ClassifyCipherTests(unittest.TestCase):
    def test_classes(self):
        cases = {
            "EXP-RC4-MD5": "CRITICAL",
            "EXP-DES-CBC-SHA": "CRITICAL",
            "ADH-AES128-SHA": "CRITICAL",
            "adh-aes128-sha": "CRITICAL",  # case-insensitive
            "AECDH-AES128-SHA": "CRITICAL",
            "NULL-SHA": "HIGH",
            "NULL-MD5": "HIGH",
            "RC4-SHA": "HIGH",
            "ECDHE-RSA-RC4-SHA": "HIGH",
            "DES-CBC-SHA": "HIGH",
            "DES-CBC3-SHA": "MEDIUM",  # 3DES, not single DES
            "ECDHE-RSA-DES-CBC3-SHA": "MEDIUM",
            "AES128-SHA": "LOW",
            "AES256-SHA": "LOW",
            "AES128-SHA256": "LOW",
            "ECDHE-RSA-AES128-SHA": "LOW",
            "ECDHE-RSA-AES128-GCM-SHA256": None,
            "AES256-GCM-SHA384": "LOW",  # static RSA: no forward secrecy
            "AES128-GCM-SHA256": "LOW",
            "DHE-RSA-AES128-GCM-SHA256": None,
            "ECDHE-RSA-CHACHA20-POLY1305": None,
            "TLS_AES_256_GCM_SHA384": None,
        }
        for name, expected in cases.items():
            with self.subTest(cipher=name):
                rule = classify_cipher(name)
                self.assertEqual(rule[0] if rule else None, expected)

    def test_rule_ids(self):
        self.assertEqual(cipher_rule("AES256-GCM-SHA384")[0], "CIPHER-NO-PFS")
        self.assertEqual(cipher_rule("AES128-SHA")[0], "CIPHER-CBC")
        self.assertEqual(cipher_rule("DES-CBC3-SHA")[0], "CIPHER-3DES")
        self.assertIsNone(cipher_rule("TLS_AES_128_GCM_SHA256"))


class ScoreTests(unittest.TestCase):
    def test_clean_scan_is_info_with_honest_message(self):
        result = score(findings())
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["reasons"], ["No weaknesses detected by the checks performed"])

    def test_successful_certificate_is_not_penalised(self):
        # The "error" key is always present (None on success); only a truthy
        # value may count as a failure.
        result = score(findings())
        self.assertNotIn("Certificate analysis failed", " ".join(result["reasons"]))

    def test_certificate_error_is_medium(self):
        bad = analyze_certificate(b"junk")
        result = score(findings(certificate=bad))
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertIn("Certificate analysis failed", result["reasons"][0])

    def test_expired_certificate_is_critical(self):
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        cert, _ = make_cert(not_before=now - timedelta(days=30), not_after=now - timedelta(days=1))
        result = score(findings(certificate=analyze_certificate(der(cert), "example.com")))
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(any("expired" in r.lower() for r in result["reasons"]))

    def test_name_mismatch_is_high(self):
        cert, _ = make_cert()
        result = score(findings(certificate=analyze_certificate(der(cert), "other.org")))
        self.assertEqual(result["severity"], "HIGH")

    def test_self_signed_is_medium(self):
        cert, _ = make_cert(self_signed=True)
        result = score(findings(certificate=analyze_certificate(der(cert), "example.com")))
        self.assertEqual(result["severity"], "MEDIUM")

    def test_signature_hash_weights(self):
        sha1 = analyze_certificate(load_fixture("sha1_signed.pem"), "example.com")
        result = score(findings(certificate=sha1))
        weak = [i for i in result["issues"] if "SHA1" in i["message"]]
        self.assertEqual([i["severity"] for i in weak], ["MEDIUM"])

    def test_deprecated_protocols_counted_once(self):
        result = score(findings(accepted_protocols=["TLSv1", "TLSv1.2"]))
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertEqual(sum("TLS 1.0" in r for r in result["reasons"]), 1)

    def test_sslv3_is_critical(self):
        self.assertEqual(score(findings(accepted_protocols=["SSLv3", "TLSv1.2"]))["severity"], "CRITICAL")

    def test_weak_ciphers_use_max_and_report_all(self):
        result = score(findings(weak_ciphers_accepted=["AES128-SHA", "DES-CBC3-SHA", "RC4-SHA"]))
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(sorted(severities(result)), ["HIGH", "LOW", "MEDIUM"])

    def test_untestable_items_never_change_severity(self):
        result = score(
            findings(
                untestable_protocols=["SSLv3"],
                ciphers_not_testable_locally=["RC4-SHA"],
                probe_errors=["x: y"],
            )
        )
        self.assertEqual(result["severity"], "INFO")
        notes = " ".join(result["notes"])
        self.assertIn("SSLv3 could not be tested", notes)
        self.assertIn("RC4-SHA", notes)
        self.assertIn("probe error", notes)
        self.assertEqual(result["reasons"], ["No weaknesses detected by the checks performed"])

    def test_error_status(self):
        result = score({"status": "error", "error": "connection refused"})
        self.assertEqual(result["severity"], "ERROR")
        self.assertEqual(result["reasons"], ["connection refused"])
        self.assertEqual(result["ignored"], [])

    def test_every_issue_has_a_registered_rule_id(self):
        now = datetime.now(timezone.utc)
        broken = [
            findings(
                accepted_protocols=["SSLv3", "TLSv1", "TLSv1.1"],
                refused_protocols=["TLSv1.2", "TLSv1.3"],
                weak_ciphers_accepted=[
                    "EXP-RC4-MD5",
                    "ADH-AES128-SHA",
                    "NULL-SHA",
                    "RC4-SHA",
                    "DES-CBC-SHA",
                    "DES-CBC3-SHA",
                    "AES128-SHA",
                    "AES128-GCM-SHA256",
                ],
                certificate=cert_with(self_signed=True, key_type="rsa1024", san_dns=None, days=900),
                trust=trust("untrusted", 20),
            ),
            findings(
                certificate=cert_with(not_before=now - timedelta(days=9), not_after=now - timedelta(days=1))
            ),
            findings(certificate=cert_with(not_before=now + timedelta(days=1), days=30)),
            findings(certificate=analyze_certificate(load_fixture("sha1_signed.pem"), "other.org")),
            findings(certificate=analyze_certificate(b"junk")),
        ]
        seen = set()
        for f in broken:
            for issue in score(f)["issues"]:
                self.assertIn(issue["id"], RULES)
                self.assertEqual(set(issue), {"id", "severity", "message"})
                seen.add(issue["id"])
        self.assertGreaterEqual(len(seen), 20)

    def test_ignore_moves_issues_without_affecting_severity(self):
        f = findings(certificate=cert_with(self_signed=True), weak_ciphers_accepted=["AES128-SHA"])
        result = score(f, ignore=["cert-self-signed"])
        self.assertEqual(result["severity"], "LOW")
        self.assertEqual(ids(result), ["CIPHER-CBC"])
        self.assertEqual([i["id"] for i in result["ignored"]], ["CERT-SELF-SIGNED"])
        everything = score(f, ignore=["CERT-SELF-SIGNED", "CIPHER-CBC"])
        self.assertEqual(everything["severity"], "INFO")
        self.assertEqual(everything["reasons"], ["No weaknesses detected by the checks performed"])


class ExpiryTests(unittest.TestCase):
    def test_expiring_soon_is_medium(self):
        result = score(findings(certificate=cert_with(days=6)))
        self.assertEqual(ids(result), ["CERT-EXPIRES-SOON"])
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertIn("expires in 4 day", result["reasons"][0])

    def test_warn_days_threshold(self):
        cert = cert_with(days=11)
        left = cert["days_remaining"]  # whole days, rounded down
        self.assertEqual(score(findings(certificate=cert), warn_days=left)["severity"], "INFO")
        self.assertEqual(score(findings(certificate=cert), warn_days=left + 1)["severity"], "MEDIUM")
        self.assertEqual(score(findings(certificate=cert), warn_days=0)["severity"], "INFO")

    def test_expired_is_not_also_expiring_soon(self):
        now = datetime.now(timezone.utc)
        cert = cert_with(not_before=now - timedelta(days=9), not_after=now - timedelta(days=1))
        self.assertEqual(ids(score(findings(certificate=cert))), ["CERT-EXPIRED"])


class LifetimeTests(unittest.TestCase):
    def test_limit_depends_on_issuance_date(self):
        now = datetime.now(timezone.utc)
        old = cert_with(not_before=datetime(2025, 6, 1, tzinfo=timezone.utc), days=397)
        new = cert_with(not_before=now - timedelta(days=1), days=397)
        ok = cert_with(not_before=now - timedelta(days=1), days=90)
        self.assertNotIn("CERT-LONG-LIFETIME", ids(score(findings(certificate=old))))
        self.assertNotIn("CERT-LONG-LIFETIME", ids(score(findings(certificate=ok))))
        if now.date() >= datetime(2026, 3, 15).date():
            result = score(findings(certificate=new))
            self.assertIn("CERT-LONG-LIFETIME", ids(result))
            self.assertTrue(any("-day limit" in r for r in result["reasons"]))


class TrustScoreTests(unittest.TestCase):
    def test_untrusted_chain_is_medium(self):
        result = score(findings(trust=trust("untrusted", 20)))
        self.assertEqual(ids(result), ["CERT-UNTRUSTED"])
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertIn("unable to get local issuer", result["reasons"][0])

    def test_trusted_and_missing_trust_are_clean(self):
        self.assertEqual(score(findings(trust=trust("trusted", detail=None)))["severity"], "INFO")
        self.assertEqual(score(findings())["severity"], "INFO")  # library users without a trust check

    def test_not_checked_is_a_note_only(self):
        result = score(findings(trust=trust("not_checked", detail="timed out")))
        self.assertEqual(result["severity"], "INFO")
        self.assertTrue(any("trust was not checked: timed out" in n for n in result["notes"]))

    def test_no_double_reporting(self):
        now = datetime.now(timezone.utc)
        self_signed = findings(certificate=cert_with(self_signed=True), trust=trust("untrusted", 18))
        self.assertEqual(ids(score(self_signed)), ["CERT-SELF-SIGNED"])
        expired_cert = cert_with(not_before=now - timedelta(days=9), not_after=now - timedelta(days=1))
        expired = findings(certificate=expired_cert, trust=trust("untrusted", 10))
        self.assertEqual(ids(score(expired)), ["CERT-EXPIRED"])
        # An expired *intermediate* (leaf still valid) is a real trust problem.
        intermediate = findings(trust=trust("untrusted", 10, "certificate has expired"))
        self.assertEqual(ids(score(intermediate)), ["CERT-UNTRUSTED"])

    def test_trusted_self_signed_is_not_flagged(self):
        result = score(findings(certificate=cert_with(self_signed=True), trust=trust("trusted", detail=None)))
        self.assertEqual(result["severity"], "INFO")


class ProtocolSupportTests(unittest.TestCase):
    def test_missing_tls13_is_low(self):
        result = score(findings(accepted_protocols=["TLSv1.2"], refused_protocols=["TLSv1.3"]))
        self.assertEqual(ids(result), ["TLS-NO-TLS13"])
        self.assertEqual(result["severity"], "LOW")

    def test_no_modern_protocol_is_medium(self):
        result = score(findings(accepted_protocols=["TLSv1"], refused_protocols=["TLSv1.2", "TLSv1.3"]))
        self.assertEqual(sorted(ids(result)), ["TLS-NO-MODERN", "TLS-TLS10"])

    def test_untestable_tls13_is_not_a_finding(self):
        result = score(
            findings(accepted_protocols=["TLSv1.2"], refused_protocols=[], untestable_protocols=["TLSv1.3"])
        )
        self.assertEqual(result["severity"], "INFO")

    def test_multiple_addresses_note(self):
        result = score(
            findings(host="example.com", address="192.0.2.1", resolved_addresses=["192.0.2.1", "192.0.2.2"])
        )
        self.assertTrue(any("resolves to 2 addresses" in n for n in result["notes"]))


class ScoreSshTests(unittest.TestCase):
    def test_modern_banner_is_info(self):
        r = score_ssh({"status": "ok", "protocol_version": "2.0", "note": None})
        self.assertEqual(r["severity"], "INFO")

    def test_ssh1_is_high(self):
        result = score_ssh({"status": "ok", "protocol_version": "1.5"})
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(ids(result), ["SSH-PROTO-1"])
        self.assertEqual(
            score_ssh({"status": "ok", "protocol_version": "1.5"}, ignore=["SSH-PROTO-1"])["severity"], "INFO"
        )

    def test_ssh_1_99_is_medium(self):
        self.assertEqual(score_ssh({"status": "ok", "protocol_version": "1.99"})["severity"], "MEDIUM")

    def test_error(self):
        self.assertEqual(score_ssh({"status": "error", "error": "boom"})["severity"], "ERROR")


if __name__ == "__main__":
    unittest.main()
