"""Terminal rendering: banner, ``[*]``/``[+]``/``[!]`` markers and coloured severities.

Markers, as in the classic OSINT tools:

``[*]`` progress / section, ``[+]`` good, ``[!]`` problem, ``[?]`` not tested here,
``[i]`` information, ``[=]`` verdict.
"""

from __future__ import annotations

from typing import Any

from . import __version__
from .scorer import SEVERITIES

BANNER = r"""
              _    _
__   __  ___ | |_ | | ___
\ \ / / / _ \| __|| |/ __|
 \ V / |  __/| |_ | |\__ \
  \_/   \___| \__||_||___/
"""

TAGLINE = "TLS, certificate & SSH-banner audit"

_SEVERITY_COLORS = {
    "CRITICAL": "1;97;41",  # bold white on red
    "HIGH": "1;31",
    "MEDIUM": "1;33",
    "LOW": "1;36",
    "INFO": "1;32",
    "ERROR": "1;35",
}

_MARKERS = {
    "*": "1;34",  # blue
    "+": "1;32",  # green
    "!": "1;31",  # red
    "?": "2",  # dim
    "i": "1;36",  # cyan
    "=": "1;37",  # white
}

# Width of the label column in "  [+] TLSv1.2     accepted".
_LABEL = 10


class Painter:
    """Wraps text in ANSI SGR codes when enabled."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self.paint(text, "1")

    def dim(self, text: str) -> str:
        return self.paint(text, "2")

    def green(self, text: str) -> str:
        return self.paint(text, "32")

    def red(self, text: str) -> str:
        return self.paint(text, "31")

    def yellow(self, text: str) -> str:
        return self.paint(text, "33")

    def cyan(self, text: str) -> str:
        return self.paint(text, "36")

    def marker(self, kind: str) -> str:
        return self.paint(f"[{kind}]", _MARKERS[kind])

    def severity(self, severity: str, width: int = 0, brackets: bool = False) -> str:
        """``severity`` in its colour; ``brackets`` gives ``[HIGH]``; ``width`` pads after the colour."""
        text = f"[{severity}]" if brackets else severity
        padding = " " * max(0, width - len(text))
        return self.paint(text, _SEVERITY_COLORS.get(severity, "0")) + padding


def banner(color: bool = False) -> str:
    """The ASCII wordmark with version and tagline."""
    p = Painter(color)
    art = BANNER.strip("\n").splitlines()
    lines = [p.paint(line, "1;36") for line in art]
    lines[-1] += "  " + p.dim(f"v{__version__}")
    lines.append(p.dim(f"  {TAGLINE}"))
    return "\n".join(lines) + "\n"


def _line(p: Painter, kind: str, label: str, value: str = "") -> str:
    text = f"  {p.marker(kind)} {label:<{_LABEL}}"
    return (text + " " + value).rstrip() if value else text.rstrip()


def _section(p: Painter, title: str) -> str:
    return f"\n  {p.bold(title)}"


# ---------------------------------------------------------------- TLS


_DEPRECATED = {"SSLv3", "TLSv1", "TLSv1.1"}


def _protocol_lines(f: dict[str, Any], p: Painter, out: list[str]) -> None:
    out.append(_section(p, "Protocols"))
    for name in ("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        cipher = (f.get("negotiated_ciphers_by_protocol") or {}).get(name)
        if name in f["accepted_protocols"]:
            if name in _DEPRECATED:
                out.append(_line(p, "!", name, p.red("accepted") + p.dim("  deprecated")))
            else:
                out.append(
                    _line(p, "+", name, p.green("accepted") + (p.dim(f"  {cipher}") if cipher else ""))
                )
        elif name in f["refused_protocols"]:
            if name in _DEPRECATED or (name == "TLSv1.2" and "TLSv1.3" in f["accepted_protocols"]):
                out.append(_line(p, "+", name, p.dim("refused")))
            else:
                out.append(_line(p, "!", name, p.yellow("not supported")))
        elif name in f["untestable_protocols"]:
            out.append(_line(p, "?", name, p.dim("not testable with the local OpenSSL")))
        else:
            out.append(_line(p, "?", name, p.dim("probe failed")))


def _cipher_lines(f: dict[str, Any], s: dict[str, Any], p: Painter, out: list[str]) -> None:
    out.append(_section(p, "Weak ciphers"))
    by_cipher = {
        i["message"].rsplit(": ", 1)[-1]: i["severity"] for i in s["issues"] if i["id"].startswith("CIPHER-")
    }
    if not f["weak_ciphers_accepted"]:
        out.append(_line(p, "+", "none", p.dim("of the probed weak suites was accepted")))
    for name in f["weak_ciphers_accepted"]:
        severity = by_cipher.get(name)
        tag = p.severity(severity) if severity else p.dim("ignored")
        out.append(f"  {p.marker('!')} {name:<24} {tag}")
    untested = f["ciphers_not_testable_locally"]
    if untested:
        out.append(_line(p, "?", f"{len(untested)} more", p.dim("not testable with the local OpenSSL")))


def _certificate_lines(f: dict[str, Any], s: dict[str, Any], p: Painter, out: list[str]) -> None:
    cert = f["certificate"]
    out.append(_section(p, "Certificate"))
    if cert["error"]:
        out.append(_line(p, "!", "Error", cert["error"]))
        return
    days = cert["days_remaining"]
    days_text = f"{days} days left"
    if cert["is_expired"]:
        validity = ("!", p.red(f"expired {cert['not_after']}"))
    elif cert["is_not_yet_valid"]:
        validity = ("!", p.red(f"not valid before {cert['not_before']}"))
    else:
        soon = any(i["id"] == "CERT-EXPIRES-SOON" for i in s["issues"])
        left = p.yellow(f"({days_text})") if soon else p.dim(f"({days_text})")
        validity = ("!" if soon else "+", f"{cert['not_before'][:10]} -> {cert['not_after'][:10]}  {left}")
    san_ok = cert["san_status"] in ("ok", "not_checked")
    trust = f.get("trust") or {}
    out.append(_line(p, "i", "Subject", cert["subject"] or "-"))
    out.append(_line(p, "i", "Issuer", cert["issuer"] or "-"))
    out.append(_line(p, validity[0], "Valid", validity[1]))
    out.append(_line(p, "!" if cert["weak_public_key"] else "+", "Key", cert["public_key"] or "-"))
    out.append(_line(p, "!" if cert["weak_signature"] else "+", "Signature", cert["signature_scheme"] or "-"))
    san = ", ".join(cert["san_entries"]) or "-"
    status = (
        p.green("match") if cert["san_status"] == "ok" else p.yellow(cert["san_status"].replace("_", " "))
    )
    out.append(_line(p, "+" if san_ok else "!", "SAN", f"{san}  {status}"))
    if trust:
        state = trust["status"]
        if state == "trusted":
            out.append(_line(p, "+", "Trust", p.green("trusted") + p.dim(f"  ({trust['ca_source']})")))
        elif state == "untrusted":
            out.append(_line(p, "!", "Trust", p.red("untrusted") + p.dim(f"  ({trust['detail']})")))
        else:
            out.append(_line(p, "?", "Trust", p.dim(f"not checked ({trust['detail']})")))
    out.append(_line(p, "i", "SHA-256", p.dim(cert["sha256_fingerprint"] or "-")))


def _findings_lines(s: dict[str, Any], p: Painter, out: list[str]) -> None:
    out.append(_section(p, "Findings"))
    if s["issues"]:
        width = max(len(i["severity"]) for i in s["issues"]) + 2
        for issue in sorted(s["issues"], key=lambda i: -SEVERITIES.index(i["severity"])):
            tag = p.severity(issue["severity"], width, brackets=True)
            out.append(f"  {tag} {issue['message']}  {p.dim(issue['id'])}")
    else:
        out.append(f"  {p.marker('+')} {p.green(s['reasons'][0])}")
    for issue in s.get("ignored", []):
        out.append(f"  {p.marker('?')} {p.dim('ignored: ' + issue['message'] + '  ' + issue['id'])}")
    for note in s["notes"]:
        out.append(f"  {p.marker('?')} {p.dim(note)}")


def _target_header(kind: str, f: dict[str, Any], p: Painter) -> str:
    where = f"{f['host']}:{f['port']}"
    extra = []
    if f.get("address") and f["address"] != f["host"]:
        extra.append(f["address"])
    if f.get("sni") and f["sni"] != f["host"]:
        extra.append(f"SNI {f['sni']}")
    suffix = p.dim(f"  ({', '.join(extra)})") if extra else ""
    return f"{p.marker('*')} {p.bold(kind)}  {p.cyan(where)}{suffix}"


def render_tls(f: dict[str, Any], p: Painter) -> list[str]:
    out = [_target_header("TLS", f, p)]
    if f["status"] == "error":
        out.append(f"  {p.marker('!')} {p.severity('ERROR')} {f['error']}")
        return out
    s = f["score"]
    _protocol_lines(f, p, out)
    _cipher_lines(f, s, p, out)
    _certificate_lines(f, s, p, out)
    _findings_lines(s, p, out)
    return out


def render_ssh(f: dict[str, Any], p: Painter) -> list[str]:
    out = [_target_header("SSH", f, p)]
    if f["status"] == "error":
        out.append(f"  {p.marker('!')} {p.severity('ERROR')} {f['error']}")
        return out
    proto = f["protocol_version"]
    bad = bool(proto and proto.startswith("1."))
    out.append(_section(p, "Banner"))
    out.append(_line(p, "i", "Banner", f["banner"] or "-"))
    out.append(_line(p, "!" if bad else "+", "Protocol", proto or "-"))
    out.append(_line(p, "i", "Software", f["software_version"] or "-"))
    for line in f.get("pre_banner_lines") or []:
        out.append(_line(p, "i", "Pre-banner", p.dim(line)))
    _findings_lines(f["score"], p, out)
    return out


def overall_line(report: dict[str, Any], p: Painter) -> str:
    severity = report["overall_severity"]
    line = f"{p.marker('=')} Overall severity: {p.severity(severity)}"
    failed = len(report.get("errors", []))
    if failed and severity != "ERROR":
        line += p.dim(f"  ({failed} scan(s) failed)")
    return line


def render_report(report: dict[str, Any], color: bool = False) -> str:
    """Human-readable report for one target, from :func:`vetls.cli.run_scan`."""
    p = Painter(color)
    out: list[str] = []
    if report["tls"] is not None:
        out += render_tls(report["tls"], p)
    if report["ssh"] is not None:
        if out:
            out.append("")
        out += render_ssh(report["ssh"], p)
    out.append("")
    out.append(overall_line(report, p))
    return "\n".join(out)


def render_multi_report(multi: dict[str, Any], color: bool = False) -> str:
    """Human-readable report for several targets, from :func:`vetls.cli.run_scans`."""
    p = Painter(color)
    sections = []
    for report in multi["reports"]:
        rule = p.dim("=" * 3)
        sections.append(f"{rule} {p.bold(report['target'])} {rule}\n" + render_report(report, color=color))
    width = max(len(r["target"]) for r in multi["reports"])
    summary = [f"{p.marker('*')} {p.bold('Summary')}"]
    for report in multi["reports"]:
        severity = report["overall_severity"]
        kind = "+" if severity in ("INFO", "LOW") else "!"
        summary.append(f"  {p.marker(kind)} {report['target']:<{width}}  {p.severity(severity)}")
    summary.append("")
    summary.append(overall_line(multi, p))
    return "\n\n".join(sections) + "\n\n" + "\n".join(summary)


def scanning_line(targets: list[str], color: bool = False) -> str:
    """The ``[*] Checking ...`` line printed before the scan starts."""
    p = Painter(color)
    what = p.cyan(targets[0]) if len(targets) == 1 else f"{len(targets)} targets"
    return f"{p.marker('*')} Checking {what} ...\n"
