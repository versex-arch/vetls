"""SARIF 2.1.0 export for code-scanning dashboards (e.g. GitHub code scanning)."""

from __future__ import annotations

import hashlib
from typing import Any

from . import __version__
from .scorer import RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/versex-arch/vetls"

_LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
# GitHub maps "security-severity" to critical >= 9.0, high >= 7.0, medium >= 4.0, low > 0.
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "0.0"}


def _scans(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    scans = []
    for kind in ("tls", "ssh"):
        scan = report.get(kind)
        if scan is not None:
            scans.append((kind, scan))
    return scans


def _result(kind: str, scan: dict[str, Any], issue: dict[str, str]) -> dict[str, Any]:
    endpoint = f"{scan['host']}:{scan['port']}"
    uri = f"{kind}://{endpoint}" if ":" not in scan["host"] else f"{kind}://[{scan['host']}]:{scan['port']}"
    fingerprint = hashlib.sha256(f"{issue['id']}|{kind}|{endpoint}".encode()).hexdigest()
    return {
        "ruleId": issue["id"],
        "level": _LEVELS[issue["severity"]],
        "message": {"text": f"{issue['message']} ({kind.upper()} {endpoint})"},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": uri}},
                "logicalLocations": [{"name": endpoint, "kind": "resource"}],
            }
        ],
        "partialFingerprints": {"vetls/v1": fingerprint},
        "properties": {"severity": issue["severity"]},
    }


def build_sarif(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Build one SARIF log from one or more reports made by :func:`vetls.cli.run_scan`."""
    results: list[dict[str, Any]] = []
    notifications: list[dict[str, Any]] = []
    worst: dict[str, str] = {}
    order = list(_LEVELS)
    for report in reports:
        for kind, scan in _scans(report):
            if scan.get("status") == "error":
                notifications.append(
                    {
                        "level": "error",
                        "message": {"text": f"{kind.upper()} {scan['host']}:{scan['port']}: {scan['error']}"},
                    }
                )
                continue
            for issue in scan["score"]["issues"]:
                results.append(_result(kind, scan, issue))
                prev = worst.get(issue["id"])
                if prev is None or order.index(issue["severity"]) < order.index(prev):
                    worst[issue["id"]] = issue["severity"]

    rules = [
        {
            "id": rule_id,
            "name": rule_id.title().replace("-", ""),
            "shortDescription": {"text": RULES[rule_id]},
            "properties": {
                "tags": ["security", "tls" if not rule_id.startswith("SSH") else "ssh"],
                "security-severity": _SECURITY_SEVERITY[worst[rule_id]],
            },
        }
        for rule_id in sorted(worst)
    ]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "vetls",
                "version": __version__,
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": not notifications,
                "toolExecutionNotifications": notifications,
            }
        ],
    }
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
