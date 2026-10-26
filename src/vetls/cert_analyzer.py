"""X.509 certificate analysis with a fixed, complete result schema.

``analyze_certificate`` never raises: a certificate that cannot be parsed
yields the same keys as a successful analysis, with ``error`` set.
"""

from __future__ import annotations

import ipaddress
from datetime import date, datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID

from .suffixes import is_public_suffix

#: Hash algorithms in certificate signatures that are considered broken.
WEAK_HASHES = {"md2": "MD2", "md4": "MD4", "md5": "MD5", "sha1": "SHA1"}

#: CA/Browser Forum Baseline Requirements (ballot SC-081): maximum validity
#: of publicly trusted TLS certificates, by issuance date. Newest first.
LIFETIME_LIMITS: tuple[tuple[date, int], ...] = (
    (date(2029, 3, 15), 47),
    (date(2027, 3, 15), 100),
    (date(2026, 3, 15), 200),
    (date(2020, 9, 1), 398),
)
#: Limit for certificates issued before the first entry above.
LEGACY_LIFETIME_DAYS = 825

MIN_RSA_BITS = 2048
MIN_DSA_BITS = 2048
MIN_EC_BITS = 224

SAN_STATUSES = (
    "ok",
    "mismatch",
    "missing_extension",
    "empty_or_unsupported",
    "not_checked",
    "error",
)


def max_lifetime_for(issued: date) -> int:
    """Maximum validity in days allowed for a public certificate issued on ``issued``."""
    for since, days in LIFETIME_LIMITS:
        if issued >= since:
            return days
    return LEGACY_LIFETIME_DAYS


def empty_cert_schema(error: str | None = None) -> dict[str, Any]:
    """Return the full result schema with neutral values.

    Error results carry exactly the same keys as successful ones so callers
    never have to branch on ``KeyError``.
    """
    return {
        "error": error,
        "subject": None,
        "issuer": None,
        "subject_cn": None,
        "issuer_cn": None,
        "not_before": None,
        "not_after": None,
        "lifetime_days": 0,
        "max_lifetime_days": None,
        "days_remaining": None,
        "is_expired": False,
        "is_not_yet_valid": False,
        "issuer_equals_subject": False,
        "signature_scheme": None,
        "weak_signature": None,
        "public_key": None,
        "weak_public_key": None,
        "san_entries": [],
        "san_status": "error" if error else "not_checked",
        "san_note": None,
        "sha256_fingerprint": None,
    }


def load_certificate(data: bytes) -> x509.Certificate:
    """Load a certificate from PEM or DER bytes (sniffed from the first byte)."""
    stripped = data.lstrip()
    if stripped[:1] == b"-":  # 0x2D, "-----BEGIN CERTIFICATE-----"
        return x509.load_pem_x509_certificate(stripped)
    return x509.load_der_x509_certificate(data)


def _common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _signature_info(cert: x509.Certificate) -> tuple[str, str | None]:
    """Return ``(scheme, weak_hash_name)`` for the certificate's *signature*.

    The scheme describes how the certificate was signed (by its issuer), not
    what kind of key the certificate itself contains. Ed25519/Ed448 signatures
    legitimately have no separate hash algorithm.
    """
    oid = cert.signature_algorithm_oid
    if oid == SignatureAlgorithmOID.ED25519:
        return "Ed25519", None
    if oid == SignatureAlgorithmOID.ED448:
        return "Ed448", None
    try:
        hash_alg = cert.signature_hash_algorithm
    except (UnsupportedAlgorithm, ValueError):
        hash_alg = None
    if hash_alg is None:
        return f"unknown ({oid.dotted_string})", None
    return hash_alg.name.upper(), WEAK_HASHES.get(hash_alg.name.lower())


def _public_key_info(pub: Any) -> tuple[str, str | None]:
    """Return ``(description, weakness_or_None)`` for a public key."""
    if isinstance(pub, rsa.RSAPublicKey):
        desc = f"RSA {pub.key_size}"
        weak = f"RSA key of {pub.key_size} bits (< {MIN_RSA_BITS})" if pub.key_size < MIN_RSA_BITS else None
        return desc, weak
    if isinstance(pub, ec.EllipticCurvePublicKey):
        bits = pub.curve.key_size
        desc = f"EC {pub.curve.name} ({bits})"
        weak = f"EC key of {bits} bits (< {MIN_EC_BITS})" if bits < MIN_EC_BITS else None
        return desc, weak
    if isinstance(pub, dsa.DSAPublicKey):
        desc = f"DSA {pub.key_size}"
        weak = f"DSA key of {pub.key_size} bits (< {MIN_DSA_BITS})" if pub.key_size < MIN_DSA_BITS else None
        return desc, weak
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519", None
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448", None
    return type(pub).__name__, None


def _dns_name_matches(pattern: str, host: str) -> bool:
    """RFC 6125-style match: a wildcard is only valid as the whole leftmost
    label, covers exactly one label, and never sits directly under a public
    suffix (``*.com``)."""
    pattern = pattern.lower().rstrip(".")
    host = host.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == host
    labels = pattern.split(".")
    base = ".".join(labels[1:])
    if labels[0] != "*" or "*" in base or "." not in base or is_public_suffix(base):
        return False
    host_labels = host.split(".")
    return len(host_labels) == len(labels) and bool(host_labels[0]) and ".".join(host_labels[1:]) == base


def _san_entries(san: x509.SubjectAlternativeName) -> list[str]:
    out: list[str] = []
    for entry in san:
        if isinstance(entry, x509.DNSName):
            out.append(f"DNS:{entry.value}")
        elif isinstance(entry, x509.IPAddress):
            out.append(f"IP:{entry.value}")
        else:
            out.append(f"{type(entry).__name__}:{entry.value}")
    return out


def _evaluate_san(cert: x509.Certificate, target_host: str | None) -> tuple[list[str], str, str | None]:
    """Return ``(entries, status, note)`` for the SAN extension."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return [], "missing_extension", None
    except ValueError as exc:  # duplicated / malformed extension
        return [], "error", f"unreadable SAN extension: {exc}"

    entries = _san_entries(san)
    dns_names = san.get_values_for_type(x509.DNSName)
    ip_addrs = san.get_values_for_type(x509.IPAddress)
    if not dns_names and not ip_addrs:
        return entries, "empty_or_unsupported", None
    if not target_host:
        return entries, "not_checked", None

    try:
        want_ip = ipaddress.ip_address(target_host)
    except ValueError:
        want_ip = None

    if want_ip is not None:
        if want_ip in ip_addrs:
            return entries, "ok", None
        note = (
            "certificate has DNS names only, no IP address SAN"
            if not ip_addrs
            else f"{want_ip} is not among the certificate's IP address SANs"
        )
        return entries, "mismatch", note

    if any(_dns_name_matches(name, target_host) for name in dns_names):
        return entries, "ok", None
    return entries, "mismatch", f"{target_host} does not match any DNS SAN"


def analyze_certificate(data: bytes, target_host: str | None = None) -> dict[str, Any]:
    """Analyse a PEM or DER certificate.

    ``target_host`` is the hostname or IP address the certificate is expected
    to be valid for; pass ``None`` to skip the name check.
    """
    try:
        cert = load_certificate(data)
    except Exception as exc:
        return empty_cert_schema(error=f"certificate parse failed: {exc}")

    try:
        now = datetime.now(timezone.utc)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        scheme, weak_hash = _signature_info(cert)
        key_desc, weak_key = _public_key_info(cert.public_key())
        entries, san_status, san_note = _evaluate_san(cert, target_host)
        return {
            "error": None,  # key is always present; None means success
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "subject_cn": _common_name(cert.subject),
            "issuer_cn": _common_name(cert.issuer),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "lifetime_days": (not_after - not_before).days,
            "max_lifetime_days": max_lifetime_for(not_before.date()),
            "days_remaining": (not_after - now).days,
            "is_expired": not_after < now,
            "is_not_yet_valid": not_before > now,
            # Compare full distinguished names, not just the CN.
            "issuer_equals_subject": cert.subject == cert.issuer,
            "signature_scheme": scheme,
            "weak_signature": weak_hash,
            "public_key": key_desc,
            "weak_public_key": weak_key,
            "san_entries": entries,
            "san_status": san_status,
            "san_note": san_note,
            "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        }
    except Exception as exc:
        return empty_cert_schema(error=f"certificate analysis failed: {exc}")
