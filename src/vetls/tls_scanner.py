"""Asynchronous TLS scanner.

Every probe has its own timeout and the probes run concurrently, so the total
runtime is bounded by roughly ``timeout * ceil(probes / concurrency)`` and a
single slow probe never discards the results of the others.

The host name is resolved once and every probe goes to the same address, so
a DNS round-robin or load balancer cannot mix results from different
backends. One extra handshake verifies the certificate chain against the
system trust store (or ``ca_file``).

Limitations (see the README): detection is bounded by the local OpenSSL
build, TLS 1.3 cipher suites cannot be enumerated through ``ssl``, and weak
cipher probing is done at TLS 1.2 and below.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import ssl
import warnings
from dataclasses import dataclass
from typing import Any

from ._aio import run_sync
from .cert_analyzer import analyze_certificate, empty_cert_schema
from .scorer import normalize_cipher
from .target import ParsedTarget, normalize_hostname, parse_target

DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 6

# (name, ssl.TLSVersion member name). Looked up lazily: a Python built
# without a legacy version simply lacks the member.
PROTOCOLS: tuple[tuple[str, str], ...] = (
    ("SSLv3", "SSLv3"),
    ("TLSv1", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
)

#: OpenSSL names of weak or legacy suites we try to negotiate at TLS <= 1.2.
WEAK_CIPHERS: tuple[str, ...] = (
    "EXP-RC4-MD5",
    "EXP-DES-CBC-SHA",
    "ADH-AES128-SHA",
    "AECDH-AES128-SHA",
    "NULL-SHA",
    "NULL-MD5",
    "RC4-SHA",
    "RC4-MD5",
    "DES-CBC-SHA",
    "DES-CBC3-SHA",
    "AES128-SHA",
    "AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES128-SHA",
    "DHE-RSA-AES128-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
)

TRUST_STATUSES = ("trusted", "untrusted", "not_checked")

OUTCOMES = ("accepted", "refused", "locally_unavailable", "error")

# Substrings of OpenSSL errors that mean "*we* cannot do this", not "the
# server said no".
_LOCAL_ERROR_MARKERS = (
    "NO_PROTOCOLS_AVAILABLE",
    "NO PROTOCOLS AVAILABLE",
    "NO_CIPHERS_AVAILABLE",
    "NO CIPHERS AVAILABLE",
    "NO CIPHER CAN BE SELECTED",
    "SECLEVEL",
    "CA MD TOO WEAK",
    "EE KEY TOO SMALL",
    "CA KEY TOO SMALL",
)


@dataclass
class ProbeResult:
    name: str
    outcome: str
    cipher: str | None = None
    der: bytes | None = None
    detail: str | None = None


def describe_error(exc: BaseException) -> str:
    """Short, actionable description of a network error."""
    if isinstance(exc, asyncio.TimeoutError):
        return "timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc.reason or exc}"
    if isinstance(exc, OSError):
        # socket.gaierror and friends
        return f"network error: {exc.strerror or exc}"
    return f"{type(exc).__name__}: {exc}"


def classify_exception(exc: BaseException) -> tuple[str, str]:
    """Map a handshake failure to ``(outcome, detail)``."""
    if isinstance(exc, ssl.SSLError):
        text = f"{exc.reason or ''} {exc}".upper()
        if any(marker in text for marker in _LOCAL_ERROR_MARKERS):
            return "locally_unavailable", describe_error(exc)
        return "refused", describe_error(exc)
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, EOFError)):
        # The port was reachable (checked beforehand), so the peer hung up
        # during the handshake: that is how many servers refuse legacy hellos.
        return "refused", "connection closed during handshake"
    return "error", describe_error(exc)


def _make_context(
    min_version: ssl.TLSVersion,
    max_version: ssl.TLSVersion,
    ciphers: str,
) -> ssl.SSLContext:
    """Audit context: verification is off on purpose.

    We are an analyser, not a trusting client: expired, self-signed and
    mismatched certificates must be retrievable instead of failing the
    handshake. ``@SECLEVEL=0`` lets the local OpenSSL attempt legacy suites.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        # Pinning SSLv3/TLS 1.0/1.1 is exactly the point of this tool.
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = min_version
        ctx.maximum_version = max_version
    ctx.set_ciphers(ciphers)
    legacy_connect = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
    if legacy_connect:
        ctx.options |= legacy_connect
    return ctx


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _system_store_available(ctx: ssl.SSLContext) -> bool:
    """Best-effort check that ``load_default_certs`` found *some* CA store.

    With a hashed CA directory OpenSSL loads certificates lazily, so an empty
    ``cert_store_stats()`` alone does not mean "no store".
    """
    if ctx.cert_store_stats().get("x509_ca", 0):
        return True
    paths = ssl.get_default_verify_paths()
    return any(p and os.path.exists(p) for p in (paths.cafile, paths.capath))


def make_trust_context(ca_file: str | None = None) -> ssl.SSLContext:
    """Verifying context for the chain-trust handshake.

    The host name is *not* checked here (that is the SAN check's job) and the
    security level is 0, so a weak key is reported by its own rule instead of
    hiding the trust result. Raises ``OSError``/``ssl.SSLError`` for a bad
    ``ca_file``.
    """
    try:
        ctx = _make_context(ssl.TLSVersion.TLSv1, ssl.TLSVersion.MAXIMUM_SUPPORTED, "ALL:@SECLEVEL=0")
    except ValueError:
        ctx = _make_context(ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.MAXIMUM_SUPPORTED, "ALL:@SECLEVEL=0")
    ctx.verify_mode = ssl.CERT_REQUIRED
    partial = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    if partial:  # lets --ca-file name an intermediate as the trust anchor
        ctx.verify_flags |= partial
    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
    else:
        ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return ctx


class TLSScanner:
    """Scan one TLS endpoint.

    ``target`` accepts ``host``, ``host:port``, ``[ipv6]:port`` and
    ``https://host[:port]/path``. An explicit ``port`` overrides the target's.

    ``sni`` overrides the Server Name Indication and the name the certificate
    must match, e.g. to audit one backend by IP: ``TLSScanner("10.0.0.5",
    sni="api.example.com")``. ``ca_file`` replaces the system trust store for
    the chain check; ``check_trust=False`` skips that check.
    """

    def __init__(
        self,
        target: str,
        port: int | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        *,
        sni: str | None = None,
        ca_file: str | None = None,
        check_trust: bool = True,
    ):
        parsed: ParsedTarget = parse_target(target)
        self.host = parsed.host
        self.sni = parsed.sni
        if sni is not None:
            if _is_ip(sni):
                raise ValueError(f"SNI must be a host name, not an IP address: {sni!r}")
            self.sni = normalize_hostname(sni)
        self.port = port if port is not None else parsed.port
        if not 0 < self.port <= 65535:
            raise ValueError(f"port out of range: {self.port}")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        self.timeout = timeout
        self.concurrency = concurrency
        self.ca_file = ca_file
        self.check_trust = check_trust
        #: The name the certificate has to match (SNI if any, else the IP).
        self.expected_name = self.sni or self.host
        self.address: str | None = None
        self.resolved_addresses: list[str] = []

    # -- public API -----------------------------------------------------

    async def scan(self) -> dict[str, Any]:
        """Run all probes and return the findings dict."""
        self.address = None
        try:
            self.resolved_addresses = await self._resolve()
        except (OSError, asyncio.TimeoutError) as exc:
            self.resolved_addresses = []
            return self._empty_findings("error", f"cannot resolve {self.host}: {describe_error(exc)}")
        try:
            self.address = await self._pick_reachable_address()
        except (OSError, asyncio.TimeoutError) as exc:
            return self._empty_findings("error", f"cannot connect: {describe_error(exc)}")

        sem = asyncio.Semaphore(self.concurrency)
        protocol_probes = [self._probe_protocol(sem, name, member) for name, member in PROTOCOLS]
        cipher_probes = [self._probe_cipher(sem, name) for name in WEAK_CIPHERS]
        results, trust = await asyncio.gather(
            asyncio.gather(*protocol_probes, *cipher_probes), self._probe_trust(sem)
        )
        return self._assemble(results[: len(PROTOCOLS)], results[len(PROTOCOLS) :], trust)

    def scan_sync(self) -> dict[str, Any]:
        """Blocking wrapper around :meth:`scan`."""
        return run_sync(self.scan())

    # -- internals ------------------------------------------------------

    def _empty_findings(self, status: str, error: str | None) -> dict[str, Any]:
        return {
            "status": status,
            "error": error,
            "host": self.host,
            "port": self.port,
            "sni": self.sni,
            "address": self.address,
            "resolved_addresses": list(self.resolved_addresses),
            "accepted_protocols": [],
            "refused_protocols": [],
            "untestable_protocols": [],
            "negotiated_ciphers_by_protocol": {},
            "weak_ciphers_accepted": [],
            "ciphers_not_testable_locally": [],
            "probe_errors": [],
            "certificate": empty_cert_schema(error="no certificate retrieved"),
            "trust": self._trust("not_checked", "no certificate retrieved"),
        }

    def _trust(self, status: str, detail: str | None = None, code: int | None = None) -> dict[str, Any]:
        return {
            "status": status,
            "detail": detail,
            "verify_code": code,
            "ca_source": f"file:{self.ca_file}" if self.ca_file else "system",
        }

    async def _resolve(self) -> list[str]:
        """Resolve the host once; IP literals resolve to themselves."""
        if _is_ip(self.host):
            return [self.host]
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM), self.timeout
        )
        addresses: list[str] = []
        for info in infos:
            addr = str(info[4][0])
            if addr not in addresses:
                addresses.append(addr)
        if not addresses:
            raise OSError(f"no addresses for {self.host}")
        return addresses

    async def _pick_reachable_address(self) -> str:
        """Return the first resolved address that accepts a TCP connection."""
        last: BaseException | None = None
        for addr in self.resolved_addresses:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(addr, self.port), self.timeout)
            except (OSError, asyncio.TimeoutError) as exc:
                last = exc
                continue
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 2.0)
            return addr
        assert last is not None
        raise last

    async def _handshake(self, ctx: ssl.SSLContext) -> tuple[str | None, bytes | None]:
        """Connect with ``ctx``; return ``(negotiated_cipher, peer_cert_der)``."""
        # An IP address is passed as server_hostname too: OpenSSL does not
        # send it as SNI, but asyncio requires a value when ssl is set.
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.address or self.host,
                self.port,
                ssl=ctx,
                server_hostname=self.sni or self.host,
                ssl_handshake_timeout=self.timeout,
            ),
            self.timeout,
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            cipher = normalize_cipher(ssl_obj.cipher()) if ssl_obj else None
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None  # before closing
            return cipher, der
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 2.0)

    async def _probe_protocol(self, sem: asyncio.Semaphore, name: str, member: str) -> ProbeResult:
        version = getattr(ssl.TLSVersion, member, None)
        if version is None:
            return ProbeResult(name, "locally_unavailable", detail="not supported by this Python")
        try:
            ctx = _make_context(version, version, "ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError) as exc:
            return ProbeResult(name, "locally_unavailable", detail=f"local OpenSSL: {exc}")
        async with sem:
            try:
                cipher, der = await self._handshake(ctx)
            except asyncio.TimeoutError:
                return ProbeResult(name, "error", detail=f"timed out after {self.timeout}s")
            except Exception as exc:
                outcome, detail = classify_exception(exc)
                return ProbeResult(name, outcome, detail=detail)
        return ProbeResult(name, "accepted", cipher=cipher, der=der)

    async def _probe_cipher(self, sem: asyncio.Semaphore, cipher_name: str) -> ProbeResult:
        try:
            try:
                low = ssl.TLSVersion.TLSv1
                ctx = _make_context(low, ssl.TLSVersion.TLSv1_2, f"{cipher_name}:@SECLEVEL=0")
            except ValueError:
                # TLS 1.0 is compiled out locally; probe from the default floor.
                ctx = _make_context(
                    ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, f"{cipher_name}:@SECLEVEL=0"
                )
        except ssl.SSLError as exc:
            return ProbeResult(cipher_name, "locally_unavailable", detail=str(exc))
        except ValueError as exc:
            return ProbeResult(cipher_name, "locally_unavailable", detail=str(exc))
        async with sem:
            try:
                negotiated, _ = await self._handshake(ctx)
            except asyncio.TimeoutError:
                return ProbeResult(cipher_name, "error", detail=f"timed out after {self.timeout}s")
            except Exception as exc:
                outcome, detail = classify_exception(exc)
                return ProbeResult(cipher_name, outcome, detail=detail)
        return ProbeResult(cipher_name, "accepted", cipher=negotiated)

    async def _probe_trust(self, sem: asyncio.Semaphore) -> dict[str, Any]:
        """Verify the chain with one extra handshake."""
        if not self.check_trust:
            return self._trust("not_checked", "disabled")
        try:
            ctx = make_trust_context(self.ca_file)
        except (OSError, ssl.SSLError) as exc:
            return self._trust("not_checked", f"cannot load CA certificates: {exc}")
        if not self.ca_file and not _system_store_available(ctx):
            return self._trust("not_checked", "no system CA store found; use --ca-file")
        async with sem:
            try:
                await self._handshake(ctx)
            except ssl.SSLCertVerificationError as exc:
                return self._trust("untrusted", exc.verify_message or str(exc), exc.verify_code)
            except asyncio.TimeoutError:
                return self._trust("not_checked", f"timed out after {self.timeout}s")
            except Exception as exc:
                return self._trust("not_checked", describe_error(exc))
        return self._trust("trusted")

    def _assemble(
        self, protocols: list[ProbeResult], ciphers: list[ProbeResult], trust: dict[str, Any]
    ) -> dict[str, Any]:
        findings = self._empty_findings("ok", None)
        der: bytes | None = None
        # Prefer the certificate from the newest accepted protocol.
        for probe in protocols:
            if probe.outcome == "accepted":
                findings["accepted_protocols"].append(probe.name)
                findings["negotiated_ciphers_by_protocol"][probe.name] = probe.cipher
                if probe.der:
                    der = probe.der
            elif probe.outcome == "refused":
                findings["refused_protocols"].append(probe.name)
            elif probe.outcome == "locally_unavailable":
                findings["untestable_protocols"].append(probe.name)
            else:
                findings["probe_errors"].append(f"{probe.name}: {probe.detail}")

        for probe in ciphers:
            if probe.outcome == "accepted":
                findings["weak_ciphers_accepted"].append(probe.name)
            elif probe.outcome == "locally_unavailable":
                findings["ciphers_not_testable_locally"].append(probe.name)
            elif probe.outcome == "error":
                findings["probe_errors"].append(f"cipher {probe.name}: {probe.detail}")

        if not findings["accepted_protocols"] and not findings["weak_ciphers_accepted"]:
            findings["status"] = "error"
            findings["error"] = "no TLS handshake succeeded; the port may not speak TLS"
            return findings
        if der:
            findings["certificate"] = analyze_certificate(der, target_host=self.expected_name)
        findings["trust"] = trust
        return findings
