"""Severity scoring.

Pure functions of a findings dict: no network, no clock, no randomness.
The overall severity is the maximum over all triggered rules, and every
triggered rule is reported with a stable rule ID (see :data:`RULES`).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_ORDER = {name: i for i, name in enumerate(SEVERITIES)}

#: Days before expiry at which a certificate is reported as expiring soon.
DEFAULT_WARN_DAYS = 14

#: Every rule this module can emit: ``rule id -> short description``.
#: IDs are stable across releases; use them with ``ignore=`` / ``--ignore``.
RULES: dict[str, str] = {
    "TLS-SSLV3": "SSLv3 accepted",
    "TLS-TLS10": "TLS 1.0 accepted",
    "TLS-TLS11": "TLS 1.1 accepted",
    "TLS-NO-TLS13": "TLS 1.3 not supported",
    "TLS-NO-MODERN": "Neither TLS 1.2 nor TLS 1.3 supported",
    "CIPHER-EXPORT": "Export-grade cipher accepted",
    "CIPHER-ANON": "Anonymous cipher accepted",
    "CIPHER-NULL": "NULL cipher accepted",
    "CIPHER-RC4": "RC4 cipher accepted",
    "CIPHER-3DES": "3DES cipher accepted",
    "CIPHER-DES": "Single-DES cipher accepted",
    "CIPHER-CBC": "Legacy CBC cipher suite accepted",
    "CIPHER-NO-PFS": "Cipher suite without forward secrecy accepted",
    "CERT-ANALYSIS-FAILED": "Certificate could not be analysed",
    "CERT-EXPIRED": "Certificate expired",
    "CERT-NOT-YET-VALID": "Certificate not yet valid",
    "CERT-EXPIRES-SOON": "Certificate expires soon",
    "CERT-WEAK-KEY": "Weak public key",
    "CERT-WEAK-SIGNATURE": "Weak signature hash",
    "CERT-UNKNOWN-SIGNATURE": "Unrecognised signature algorithm",
    "CERT-SELF-SIGNED": "Self-signed certificate",
    "CERT-UNTRUSTED": "Certificate chain not trusted",
    "CERT-LONG-LIFETIME": "Validity period exceeds the CA/B Forum limit",
    "CERT-NAME-MISMATCH": "Certificate does not match the target",
    "CERT-NO-SAN": "No Subject Alternative Name extension",
    "CERT-SAN-EMPTY": "SAN has no DNS or IP entries",
    "CERT-SAN-ERROR": "SAN could not be evaluated",
    "SSH-PROTO-1": "Obsolete SSH protocol 1.x",
    "SSH-PROTO-1-99": "SSH protocol 1 still accepted (1.99)",
}

# Patterns are matched against UPPER-CASE OpenSSL cipher names.
_PAT_EXPORT = re.compile(r"(^|-)EXP-|EXPORT")
_PAT_ANON = re.compile(r"^(ADH|AECDH)-|\bANON\b")
_PAT_NULL = re.compile(r"^NULL-|-NULL-|^NULL$|\bENULL\b")
_PAT_RC4 = re.compile(r"RC4")
_PAT_3DES = re.compile(r"3DES|DES-CBC3")
_PAT_DES = re.compile(r"(^|-)DES-CBC-")
_PAT_CBC = re.compile(r"AES(128|256)-SHA(256|384)?$|CAMELLIA(128|256)-SHA(256)?$|-CBC")
# OpenSSL names without a key-exchange prefix use static RSA key exchange.
_PAT_NO_PFS = re.compile(r"^(AES|CAMELLIA|ARIA|SEED|IDEA)")

# Order matters: the first matching rule decides the class of *one* cipher.
# 3DES must come before single DES, which is why "DES-CBC3-SHA" is MEDIUM.
CIPHER_RULES: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    (_PAT_EXPORT, "CIPHER-EXPORT", "CRITICAL", "Export-grade cipher accepted"),
    (_PAT_ANON, "CIPHER-ANON", "CRITICAL", "Anonymous cipher accepted (no server authentication)"),
    (_PAT_NULL, "CIPHER-NULL", "HIGH", "NULL cipher accepted (no encryption)"),
    (_PAT_RC4, "CIPHER-RC4", "HIGH", "RC4 cipher accepted"),
    (_PAT_3DES, "CIPHER-3DES", "MEDIUM", "3DES cipher accepted (SWEET32)"),
    (_PAT_DES, "CIPHER-DES", "HIGH", "Single-DES cipher accepted"),
    (_PAT_CBC, "CIPHER-CBC", "LOW", "Legacy CBC cipher suite accepted"),
    (_PAT_NO_PFS, "CIPHER-NO-PFS", "LOW", "No forward secrecy (static RSA key exchange)"),
)

DEPRECATED_PROTOCOLS = {
    "SSLv3": ("TLS-SSLV3", "CRITICAL", "SSLv3 accepted (POODLE)"),
    "TLSv1": ("TLS-TLS10", "MEDIUM", "TLS 1.0 accepted (deprecated, RFC 8996)"),
    "TLSv1.1": ("TLS-TLS11", "MEDIUM", "TLS 1.1 accepted (deprecated, RFC 8996)"),
}

_HIGH_WEAK_HASHES = {"MD2", "MD4", "MD5"}

# OpenSSL X509_V_ERR_* codes whose cause another rule already reports.
_X509_CERT_NOT_YET_VALID = 9
_X509_CERT_HAS_EXPIRED = 10
_X509_DEPTH_ZERO_SELF_SIGNED = 18


def normalize_cipher(cipher: Any) -> str | None:
    """Return an upper-case cipher name from a tuple, a string, or ``None``.

    ``ssl.SSLObject.cipher()`` returns a ``(name, protocol, bits)`` tuple;
    anything unusable yields ``None``.
    """
    if isinstance(cipher, (tuple, list)) and cipher:
        cipher = cipher[0]
    if isinstance(cipher, str) and cipher.strip():
        return cipher.strip().upper()
    return None


def cipher_rule(name: str) -> tuple[str, str, str] | None:
    """Return ``(rule_id, severity, description)`` for a cipher name, or ``None``."""
    normalized = normalize_cipher(name)
    if normalized is None:
        return None
    for pattern, rule_id, severity, description in CIPHER_RULES:
        if pattern.search(normalized):
            return rule_id, severity, description
    return None


def classify_cipher(name: str) -> tuple[str, str] | None:
    """Return ``(severity, description)`` for a cipher name, or ``None``."""
    rule = cipher_rule(name)
    return (rule[1], rule[2]) if rule else None


def severity_rank(severity: str) -> int:
    """Position of ``severity`` in :data:`SEVERITIES` (``ValueError`` if unknown)."""
    try:
        return _ORDER[severity]
    except KeyError:
        raise ValueError(f"unknown severity {severity!r}") from None


def max_severity(severities: Iterable[str]) -> str:
    items = list(severities)
    return max(items, key=_ORDER.__getitem__) if items else "INFO"


def _issue(rule_id: str, severity: str, message: str) -> dict[str, str]:
    return {"id": rule_id, "severity": severity, "message": message}


def _certificate_issues(
    cert: dict[str, Any], trust: dict[str, Any] | None, warn_days: int
) -> list[dict[str, str]]:
    # "error" is always present in the schema; only a truthy value is a failure.
    if cert.get("error"):
        return [_issue("CERT-ANALYSIS-FAILED", "MEDIUM", f"Certificate analysis failed: {cert['error']}")]

    issues: list[dict[str, str]] = []
    days_left = cert.get("days_remaining")
    if cert.get("is_expired"):
        issues.append(_issue("CERT-EXPIRED", "CRITICAL", f"Certificate expired on {cert.get('not_after')}"))
    elif isinstance(days_left, int) and days_left < warn_days and not cert.get("is_not_yet_valid"):
        issues.append(
            _issue(
                "CERT-EXPIRES-SOON",
                "MEDIUM",
                f"Certificate expires in {days_left} day(s), on {cert.get('not_after')}",
            )
        )
    if cert.get("is_not_yet_valid"):
        issues.append(
            _issue("CERT-NOT-YET-VALID", "HIGH", f"Certificate is not valid before {cert.get('not_before')}")
        )
    if cert.get("weak_public_key"):
        issues.append(_issue("CERT-WEAK-KEY", "MEDIUM", f"Weak public key: {cert['weak_public_key']}"))

    weak_hash = cert.get("weak_signature")
    if weak_hash:
        severity = "HIGH" if weak_hash in _HIGH_WEAK_HASHES else "MEDIUM"
        issues.append(
            _issue("CERT-WEAK-SIGNATURE", severity, f"Certificate signed with weak hash {weak_hash}")
        )
    scheme = cert.get("signature_scheme") or ""
    if scheme.startswith("unknown"):
        issues.append(
            _issue(
                "CERT-UNKNOWN-SIGNATURE", "MEDIUM", f"Unrecognised certificate signature algorithm: {scheme}"
            )
        )

    trust_status = (trust or {}).get("status")
    # A self-signed certificate that verifies was put in the trust store on
    # purpose (e.g. with --ca-file), so it is not reported as self-signed.
    if cert.get("issuer_equals_subject") and trust_status != "trusted":
        issues.append(_issue("CERT-SELF-SIGNED", "MEDIUM", "Self-signed certificate (issuer equals subject)"))
    if trust_status == "untrusted":
        code = trust.get("verify_code") if trust else None
        already_reported = (
            (code == _X509_DEPTH_ZERO_SELF_SIGNED and cert.get("issuer_equals_subject"))
            or (code == _X509_CERT_HAS_EXPIRED and cert.get("is_expired"))
            or (code == _X509_CERT_NOT_YET_VALID and cert.get("is_not_yet_valid"))
        )
        if not already_reported:
            detail = (trust or {}).get("detail") or "verification failed"
            issues.append(_issue("CERT-UNTRUSTED", "MEDIUM", f"Certificate chain is not trusted: {detail}"))

    lifetime = cert.get("lifetime_days") or 0
    limit = cert.get("max_lifetime_days") or 398
    if lifetime > limit:
        issues.append(
            _issue(
                "CERT-LONG-LIFETIME",
                "LOW",
                f"Certificate validity of {lifetime} days exceeds the {limit}-day limit "
                "for publicly trusted certificates issued at that date",
            )
        )

    san_status = cert.get("san_status")
    note = cert.get("san_note")
    if san_status == "mismatch":
        issues.append(
            _issue(
                "CERT-NAME-MISMATCH",
                "HIGH",
                "Certificate does not match the target" + (f": {note}" if note else ""),
            )
        )
    elif san_status == "missing_extension":
        issues.append(
            _issue("CERT-NO-SAN", "MEDIUM", "Certificate has no Subject Alternative Name extension")
        )
    elif san_status == "empty_or_unsupported":
        issues.append(_issue("CERT-SAN-EMPTY", "MEDIUM", "SAN extension contains no DNS or IP entries"))
    elif san_status == "error":
        issues.append(_issue("CERT-SAN-ERROR", "MEDIUM", f"SAN could not be evaluated: {note}"))
    return issues


def _protocol_issues(accepted: list[str], refused: list[str]) -> list[dict[str, str]]:
    issues = [_issue(*DEPRECATED_PROTOCOLS[p]) for p in accepted if p in DEPRECATED_PROTOCOLS]
    # Only a definite refusal counts; "untestable" or a probe error proves nothing.
    if "TLSv1.3" in refused and "TLSv1.2" in refused:
        issues.append(_issue("TLS-NO-MODERN", "MEDIUM", "Neither TLS 1.2 nor TLS 1.3 is accepted"))
    elif "TLSv1.3" in refused:
        issues.append(_issue("TLS-NO-TLS13", "LOW", "TLS 1.3 is not supported"))
    return issues


def _cipher_issues(ciphers: list[str]) -> list[dict[str, str]]:
    issues = []
    for name in ciphers:
        rule = cipher_rule(name)
        if rule:
            issues.append(_issue(rule[0], rule[1], f"{rule[2]}: {name}"))
    return issues


def _error_result(findings: dict[str, Any]) -> dict[str, Any]:
    message = findings.get("error") or "scan failed"
    return {"severity": "ERROR", "reasons": [message], "issues": [], "ignored": [], "notes": []}


def _finish(issues: list[dict[str, str]], notes: list[str], ignore: Iterable[str]) -> dict[str, Any]:
    skip = {rule.upper() for rule in ignore}
    kept = [i for i in issues if i["id"] not in skip]
    ignored = [i for i in issues if i["id"] in skip]
    severity = max_severity(i["severity"] for i in kept)
    reasons = [i["message"] for i in kept] or ["No weaknesses detected by the checks performed"]
    return {"severity": severity, "reasons": reasons, "issues": kept, "ignored": ignored, "notes": notes}


def score(
    findings: dict[str, Any],
    *,
    warn_days: int = DEFAULT_WARN_DAYS,
    ignore: Iterable[str] = (),
) -> dict[str, Any]:
    """Score a TLS findings dict as produced by :class:`vetls.TLSScanner`.

    ``warn_days``: report a certificate expiring in fewer days as MEDIUM.
    ``ignore``: rule IDs (see :data:`RULES`) to move from ``issues`` to
    ``ignored``; ignored issues do not affect the severity.
    """
    if findings.get("status") == "error":
        return _error_result(findings)

    trust = findings.get("trust")
    issues: list[dict[str, str]] = []
    issues += _certificate_issues(findings.get("certificate") or {}, trust, warn_days)
    issues += _protocol_issues(findings.get("accepted_protocols", []), findings.get("refused_protocols", []))
    issues += _cipher_issues(findings.get("weak_ciphers_accepted", []))

    # Things we could not check are reported but never affect the severity:
    # "unchecked" is not "insecure" and not "secure" either.
    notes: list[str] = []
    for proto in findings.get("untestable_protocols", []):
        notes.append(f"{proto} could not be tested with the local OpenSSL build")
    unchecked = findings.get("ciphers_not_testable_locally", [])
    if unchecked:
        notes.append(f"{len(unchecked)} weak cipher(s) could not be tested locally: {', '.join(unchecked)}")
    for err in findings.get("probe_errors", []):
        notes.append(f"probe error: {err}")
    if trust and trust.get("status") == "not_checked":
        notes.append(f"certificate chain trust was not checked: {trust.get('detail') or 'unknown reason'}")
    addresses = findings.get("resolved_addresses") or []
    if len(addresses) > 1:
        notes.append(
            f"{findings.get('host')} resolves to {len(addresses)} addresses; only {findings.get('address')} "
            "was scanned (scan the others by IP with --sni)"
        )
    notes.append("TLS 1.3 cipher suites are not enumerated")
    return _finish(issues, notes, ignore)


def score_ssh(findings: dict[str, Any], *, ignore: Iterable[str] = ()) -> dict[str, Any]:
    """Score an SSH banner findings dict from :class:`vetls.SSHScanner`."""
    if findings.get("status") == "error":
        return _error_result(findings)

    issues: list[dict[str, str]] = []
    proto = findings.get("protocol_version")
    if proto and proto.startswith("1.") and proto != "1.99":
        issues.append(_issue("SSH-PROTO-1", "HIGH", f"SSH protocol version {proto} is obsolete and insecure"))
    elif proto == "1.99":
        issues.append(
            _issue("SSH-PROTO-1-99", "MEDIUM", "Server accepts the obsolete SSH protocol 1 (version 1.99)")
        )
    notes = ["SSH check is limited to the identification banner; no vulnerability assessment is made"]
    if findings.get("note"):
        notes.append(findings["note"])
    return _finish(issues, notes, ignore)
