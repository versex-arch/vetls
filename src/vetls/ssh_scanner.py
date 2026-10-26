"""SSH identification-banner scanner.

The banner is reported as information only. There is deliberately no
version-to-vulnerability table: without an authoritative CVE feed any such
list would be guesswork. The only judgement made is about the *protocol*
version (SSH-1.x is obsolete).
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from ._aio import run_sync
from .target import parse_target

DEFAULT_SSH_PORT = 22
MAX_BANNER_LENGTH = 255  # RFC 4253 section 4.2


def parse_banner(line: str) -> dict[str, Any]:
    """Parse an SSH identification string ``SSH-protoversion-softwareversion [comments]``."""
    result: dict[str, Any] = {
        "is_ssh": False,
        "raw": None,
        "protocol_version": None,
        "software_version": None,
        "comments": None,
    }
    line = line.rstrip("\r\n")
    if not line:
        return result
    result["raw"] = line
    if not line.startswith("SSH-"):
        return result
    proto, sep, rest = line[4:].partition("-")
    if not sep or not proto or not rest:
        return result
    software, _, comments = rest.partition(" ")
    result.update(
        is_ssh=True,
        protocol_version=proto,
        software_version=software or None,
        comments=comments or None,
    )
    return result


def _error(host: str, port: int, message: str) -> dict[str, Any]:
    result = _empty(host, port)
    result.update(status="error", error=message)
    return result


def _empty(host: str, port: int) -> dict[str, Any]:
    return {
        "status": "ok",
        "error": None,
        "host": host,
        "port": port,
        "banner": None,
        "protocol_version": None,
        "software_version": None,
        "comments": None,
        "pre_banner_lines": [],
        "note": None,
        "vulnerability_assessment": "not performed: banner display only, no CVE mapping",
    }


async def scan_ssh(
    host: str,
    port: int = DEFAULT_SSH_PORT,
    timeout: float = 5.0,
    max_pre_banner: int = 8,
) -> dict[str, Any]:
    """Connect, read the identification string, disconnect.

    RFC 4253 lets a server send text lines before the banner; up to
    ``max_pre_banner`` of them are collected. No authentication is attempted.
    """
    result = _empty(host, port)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return _error(host, port, f"connection timed out after {timeout}s")
    except OSError as exc:
        return _error(host, port, f"connection failed: {exc}")

    try:
        banner_line: str | None = None
        for _ in range(max_pre_banner + 1):
            try:
                raw = await asyncio.wait_for(reader.readline(), timeout)
            except asyncio.TimeoutError:
                result["note"] = "timed out waiting for an SSH banner"
                break
            except (ValueError, asyncio.LimitOverrunError):
                result["note"] = "received an over-long line instead of an SSH banner"
                break
            if not raw:
                break
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if text.startswith("SSH-"):
                banner_line = text[:MAX_BANNER_LENGTH]
                break
            result["pre_banner_lines"].append(text[:MAX_BANNER_LENGTH])

        parsed = parse_banner(banner_line or "")
        result["banner"] = parsed["raw"]
        result["protocol_version"] = parsed["protocol_version"]
        result["software_version"] = parsed["software_version"]
        result["comments"] = parsed["comments"]
        if not parsed["is_ssh"] and result["note"] is None:
            result["note"] = "no SSH banner received; the port may not speak SSH"
    except OSError as exc:
        result.update(status="error", error=f"banner read failed: {exc}")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 2.0)
    return result


class SSHScanner:
    """Banner scanner with the same target handling as :class:`TLSScanner`."""

    def __init__(self, target: str, port: int | None = None, timeout: float = 5.0):
        parsed = parse_target(target, default_port=DEFAULT_SSH_PORT)
        self.host = parsed.host
        self.port = port if port is not None else parsed.port
        if not 0 < self.port <= 65535:
            raise ValueError(f"port out of range: {self.port}")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout

    async def scan(self) -> dict[str, Any]:
        return await scan_ssh(self.host, self.port, self.timeout)

    def scan_sync(self) -> dict[str, Any]:
        return run_sync(self.scan())
