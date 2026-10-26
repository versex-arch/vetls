"""vetls: non-invasive TLS and SSH-banner security auditing."""

__version__ = "1.1.0"

from .cert_analyzer import analyze_certificate, empty_cert_schema, load_certificate, max_lifetime_for
from .sarif import build_sarif
from .scorer import RULES, classify_cipher, normalize_cipher, score, score_ssh
from .ssh_scanner import SSHScanner, parse_banner, scan_ssh
from .target import ParsedTarget, normalize_hostname, parse_target
from .tls_scanner import TLSScanner

__all__ = [
    "RULES",
    "ParsedTarget",
    "SSHScanner",
    "TLSScanner",
    "__version__",
    "analyze_certificate",
    "build_sarif",
    "classify_cipher",
    "empty_cert_schema",
    "load_certificate",
    "max_lifetime_for",
    "normalize_cipher",
    "normalize_hostname",
    "parse_banner",
    "parse_target",
    "scan_ssh",
    "score",
    "score_ssh",
]
