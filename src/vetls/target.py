"""Parsing and normalisation of scan targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

DEFAULT_PORT = 443
ALLOWED_SCHEMES = frozenset({"https", "tls", "ssl"})

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


@dataclass(frozen=True)
class ParsedTarget:
    """A validated scan target.

    ``sni`` is ``None`` for IP literals: an IP address must never be sent as
    a Server Name Indication value.
    """

    host: str
    port: int
    sni: str | None

    @property
    def is_ip(self) -> bool:
        return self.sni is None


def normalize_hostname(host: str) -> str:
    """Lower-case, strip a trailing dot, IDNA-encode and validate a hostname.

    Internationalised names are encoded with IDNA 2008 plus UTS #46 mapping
    (non-transitional), as browsers do: ``faß.de`` becomes ``xn--fa-hia.de``,
    not ``fass.de`` as Python's built-in IDNA 2003 codec would produce.
    """
    host = host.strip().rstrip(".")
    if not host:
        raise ValueError("empty hostname")
    if host.isascii():
        host = host.lower()
    else:
        try:
            host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
        except (idna.IDNAError, UnicodeError) as exc:
            raise ValueError(f"invalid internationalized hostname: {host!r}") from exc
    if len(host) > 253:
        raise ValueError("hostname is longer than 253 characters")
    for label in host.split("."):
        if not _LABEL_RE.match(label):
            raise ValueError(f"invalid hostname: {host!r}")
    return host


_normalize_hostname = normalize_hostname  # backwards-compatible private alias


def parse_target(target: str, default_port: int = DEFAULT_PORT) -> ParsedTarget:
    """Parse ``host``, ``host:port``, ``[ipv6]:port`` or ``https://host[:port]/path``.

    Paths, queries and fragments are ignored. The port is always returned as
    an ``int`` in the range 1-65535. Raises :class:`ValueError` on bad input.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValueError("empty target")
    raw = target.strip()

    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        if scheme not in ALLOWED_SCHEMES:
            raise ValueError(
                f"unsupported scheme {scheme!r} (expected one of: {', '.join(sorted(ALLOWED_SCHEMES))})"
            )
        to_split = raw
    else:
        # A bare IPv6 literal such as "::1" has no brackets and no port.
        try:
            bare_ip = ipaddress.ip_address(raw)
        except ValueError:
            bare_ip = None
        if bare_ip is not None:
            return ParsedTarget(host=str(bare_ip), port=default_port, sni=None)
        to_split = "//" + raw

    try:
        parts = urlsplit(to_split)
        host_part = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid target {target!r}: {exc}") from exc

    if "@" in parts.netloc:
        raise ValueError("credentials in a target are not supported")
    if not host_part:
        raise ValueError(f"no host in target {target!r}")

    if port is None:
        port = default_port
    if not 0 < port <= 65535:
        raise ValueError(f"port out of range: {port}")

    try:
        ip = ipaddress.ip_address(host_part)
    except ValueError:
        host = normalize_hostname(host_part)
        return ParsedTarget(host=host, port=port, sni=host)
    return ParsedTarget(host=str(ip), port=port, sni=None)
