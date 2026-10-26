import unittest

from vetls.sarif import build_sarif
from vetls.scorer import RULES


def report(target="example.com", tls_issues=(), ssh=None, tls_error=None):
    tls = {
        "status": "error" if tls_error else "ok",
        "error": tls_error,
        "host": target,
        "port": 443,
        "score": {"issues": list(tls_issues)},
    }
    return {"target": target, "tls": tls, "ssh": ssh}


def issue(rule_id, severity="MEDIUM", message="something"):
    return {"id": rule_id, "severity": severity, "message": message}


class SarifTests(unittest.TestCase):
    def test_structure(self):
        log = build_sarif([report(tls_issues=[issue("CERT-SELF-SIGNED"), issue("TLS-SSLV3", "CRITICAL")])])
        self.assertEqual(log["version"], "2.1.0")
        self.assertIn("sarif", log["$schema"])
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "vetls")
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(set(rules), {"CERT-SELF-SIGNED", "TLS-SSLV3"})
        self.assertEqual(rules["TLS-SSLV3"]["shortDescription"]["text"], RULES["TLS-SSLV3"])
        self.assertEqual(rules["TLS-SSLV3"]["properties"]["security-severity"], "9.5")
        levels = {r["ruleId"]: r["level"] for r in run["results"]}
        self.assertEqual(levels, {"CERT-SELF-SIGNED": "warning", "TLS-SSLV3": "error"})
        location = run["results"][0]["locations"][0]
        self.assertEqual(location["physicalLocation"]["artifactLocation"]["uri"], "tls://example.com:443")
        self.assertTrue(run["invocations"][0]["executionSuccessful"])

    def test_fingerprints_are_stable_and_distinct(self):
        a = build_sarif([report("a.example", [issue("CERT-SELF-SIGNED")])])["runs"][0]["results"][0]
        a2 = build_sarif([report("a.example", [issue("CERT-SELF-SIGNED", message="x")])])["runs"][0][
            "results"
        ][0]
        b = build_sarif([report("b.example", [issue("CERT-SELF-SIGNED")])])["runs"][0]["results"][0]
        self.assertEqual(a["partialFingerprints"], a2["partialFingerprints"])
        self.assertNotEqual(a["partialFingerprints"], b["partialFingerprints"])

    def test_rule_severity_is_the_worst_seen(self):
        log = build_sarif(
            [
                report("a.example", [issue("CERT-WEAK-SIGNATURE", "MEDIUM")]),
                report("b.example", [issue("CERT-WEAK-SIGNATURE", "HIGH")]),
            ]
        )
        rule = log["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], "7.5")

    def test_errors_become_notifications(self):
        log = build_sarif([report(tls_error="connection refused")])
        inv = log["runs"][0]["invocations"][0]
        self.assertFalse(inv["executionSuccessful"])
        self.assertIn("connection refused", inv["toolExecutionNotifications"][0]["message"]["text"])
        self.assertEqual(log["runs"][0]["results"], [])

    def test_ipv6_uri_and_ssh(self):
        ssh = {"status": "ok", "host": "::1", "port": 22, "score": {"issues": [issue("SSH-PROTO-1", "HIGH")]}}
        log = build_sarif([{"target": "::1", "tls": None, "ssh": ssh}])
        result = log["runs"][0]["results"][0]
        self.assertEqual(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "ssh://[::1]:22"
        )
        self.assertEqual(
            log["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"], ["security", "ssh"]
        )


if __name__ == "__main__":
    unittest.main()
