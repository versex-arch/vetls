"""Shared test helpers: certificate factory and real local TLS/SSH servers."""

from __future__ import annotations

import atexit
import contextlib
import ipaddress
import os
import socket
import ssl
import tempfile
import threading
import time
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

DATA_DIR = Path(__file__).parent / "data"
_CA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])


def _make_ca() -> x509.Certificate:
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_CA_NAME)
        .issuer_name(_CA_NAME)
        .public_key(_CA_KEY.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(_CA_KEY.public_key()), critical=False)
        .sign(_CA_KEY, hashes.SHA256())
    )


#: The test CA that issues every non-self-signed test certificate.
CA_CERT = _make_ca()
_ca_fd, _ca_path = tempfile.mkstemp(suffix=".pem", prefix="vetls-test-ca-")
with os.fdopen(_ca_fd, "wb") as _fh:
    _fh.write(CA_CERT.public_bytes(serialization.Encoding.PEM))
#: PEM file with :data:`CA_CERT`, for ``ca_file=`` / ``--ca-file``.
CA_FILE = _ca_path
atexit.register(lambda: os.path.exists(_ca_path) and os.unlink(_ca_path))


def _new_key(key_type: str):
    if key_type == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "rsa1024":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    if key_type == "ec":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(key_type)


def make_cert(
    *,
    cn: str = "example.com",
    san_dns: tuple[str, ...] | None = ("example.com",),
    san_ip: tuple[str, ...] = (),
    days: int = 90,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    key_type: str = "rsa2048",
    self_signed: bool = False,
):
    """Build a certificate. Returns ``(certificate, private_key)``.

    By default the leaf is issued by :data:`CA_CERT`, so issuer != subject and
    the chain verifies against :data:`CA_FILE`.
    ``san_dns=None`` (and no ``san_ip``) omits the SAN extension entirely.
    """
    key = _new_key(key_type)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if self_signed else _CA_NAME
    signer = key if self_signed else _CA_KEY
    now = datetime.now(timezone.utc)
    nb = not_before or now - timedelta(days=1)
    na = not_after or nb + timedelta(days=days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
    )
    names: list[x509.GeneralName] = [x509.DNSName(d) for d in (san_dns or ())]
    names += [x509.IPAddress(ipaddress.ip_address(i)) for i in san_ip]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    if not self_signed:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(_CA_KEY.public_key()), critical=False
        )
    algorithm = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(signer, algorithm), key


def load_fixture(name: str) -> bytes:
    """Read a file from tests/data (e.g. a SHA-1 certificate the library refuses to sign)."""
    return (DATA_DIR / name).read_bytes()


def der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


class TLSServer:
    """A real TLS server on 127.0.0.1 that completes a handshake and hangs up."""

    def __init__(self, cert, key, *, min_version=None, max_version=None, ciphers=None):
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        (tmp / "cert.pem").write_bytes(pem(cert))
        (tmp / "key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(tmp / "cert.pem", tmp / "key.pem")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            if min_version is not None:
                self.ctx.minimum_version = min_version
            if max_version is not None:
                self.ctx.maximum_version = max_version
        if ciphers:
            self.ctx.set_ciphers(ciphers)
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            with self.ctx.wrap_socket(conn, server_side=True):
                pass
        except (ssl.SSLError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def __enter__(self) -> TLSServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._listener.close()
        self._tmp.cleanup()


class RawServer:
    """A plain TCP server: sends ``payload``, keeps the socket open for ``hold`` seconds, closes.

    ``payload=None`` means "accept and say nothing" (a silent peer).
    """

    def __init__(self, payload: bytes | None = None, *, hold: float = 0.5):
        self.payload = payload
        self.hold = hold
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self.port = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            if self.payload:
                conn.sendall(self.payload)
            time.sleep(self.hold)  # ignore whatever the client sends
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def __enter__(self) -> RawServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._listener.close()


def free_port() -> int:
    """A port with nothing listening on it."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
