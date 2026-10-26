"""Command-line interface: ``vetls [scan] TARGET [TARGET ...]`` / ``python -m vetls``."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import ssl
import sys
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .sarif import build_sarif
from .scorer import DEFAULT_WARN_DAYS, RULES, max_severity, score, score_ssh, severity_rank
from .ssh_scanner import DEFAULT_SSH_PORT, SSHScanner
from .target import parse_target
from .tls_scanner import DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT, TLSScanner, make_trust_context
from .ui import banner, render_multi_report, render_report, scanning_line

__all__ = ["exit_code_for", "main", "render_multi_report", "render_report", "run_scan", "run_scans"]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130

#: How many targets are scanned at the same time.
TARGET_PARALLELISM = 4

FAIL_ON_CHOICES = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "never")

EPILOGUE = (
    "Exit codes: 0 = nothing at or above --fail-on (default MEDIUM), 1 = at least one finding at or\n"
    "above --fail-on, 2 = scan or usage error (findings take precedence), 130 = interrupted.\n"
    "Use --list-rules to see the rule IDs accepted by --ignore.\n"
    "Only scan systems you own or have explicit permission to test."
)


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _non_negative_int(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vetls",
        description=f"vetls v{__version__}: non-invasive TLS configuration, certificate and SSH-banner audit.",
        epilog=EPILOGUE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="host, host:port, [ipv6]:port or https://host[:port]; several may be given",
    )
    parser.add_argument(
        "-f", "--targets-file", metavar="FILE", help="read targets from FILE, one per line ('#' comments)"
    )

    scan = parser.add_argument_group("scan options")
    scan.add_argument("--port", type=int, help="TLS port for every target (overrides TARGET; default 443)")
    scan.add_argument("--sni", metavar="NAME", help="send NAME as SNI and check the certificate against it")
    scan.add_argument(
        "--ssh", action="store_true", help=f"also read the SSH banner on port {DEFAULT_SSH_PORT}"
    )
    scan.add_argument("--ssh-port", type=int, metavar="N", help="also read the SSH banner on port N")
    scan.add_argument("--no-tls", action="store_true", help="skip the TLS scan (use with --ssh/--ssh-port)")
    scan.add_argument(
        "--ca-file", metavar="FILE", help="trust the CA certificates in FILE instead of the system store"
    )
    scan.add_argument("--no-trust-check", action="store_true", help="do not verify the certificate chain")
    scan.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="per-probe timeout in seconds (default: %(default)s)",
    )
    scan.add_argument(
        "--concurrency",
        type=_positive_int,
        default=DEFAULT_CONCURRENCY,
        metavar="N",
        help="parallel handshakes per target (default: %(default)s)",
    )

    policy = parser.add_argument_group("policy")
    policy.add_argument(
        "--warn-days",
        type=_non_negative_int,
        default=DEFAULT_WARN_DAYS,
        metavar="N",
        help="report certificates expiring in fewer than N days as MEDIUM (default: %(default)s)",
    )
    policy.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="MEDIUM",
        type=lambda s: "never" if s.lower() == "never" else s.upper(),
        help="lowest severity that makes the exit code 1 (default: %(default)s)",
    )
    policy.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE",
        help="ignore a rule ID (repeatable, or comma-separated); see --list-rules",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "--json", action="store_true", help="print machine-readable JSON instead of the report"
    )
    output.add_argument("--out", metavar="FILE", help="also write the JSON report to FILE")
    output.add_argument("--sarif", metavar="FILE", help="also write a SARIF 2.1.0 log to FILE")
    output.add_argument("--no-color", action="store_true", help="disable colored output")
    output.add_argument("--no-banner", action="store_true", help="do not print the banner")
    output.add_argument("--list-rules", action="store_true", help="list rule IDs and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _normalize_argv(argv: list[str]) -> list[str]:
    """Allow an optional leading ``scan`` subcommand."""
    return argv[1:] if argv and argv[0] == "scan" else argv


def read_targets_file(path: str) -> list[str]:
    """Targets from a file: one per line, blank lines and ``#`` comments ignored."""
    targets = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(line)
    return targets


def _split_rules(values: Iterable[str]) -> list[str]:
    return [part.strip().upper() for value in values for part in value.split(",") if part.strip()]


def _environment() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "openssl": ssl.OPENSSL_VERSION,
        "platform": platform.platform(),
    }


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _overall(severities: Sequence[str]) -> str:
    """Worst severity of the scans that succeeded; ERROR only if *every* scan failed."""
    ok = [s for s in severities if s != "ERROR"]
    if not ok:
        return "ERROR" if severities else "INFO"
    return max_severity(ok)


async def run_scan(
    target: str,
    *,
    port: int | None = None,
    sni: str | None = None,
    ssh_port: int | None = None,
    tls: bool = True,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    ca_file: str | None = None,
    check_trust: bool = True,
    warn_days: int = DEFAULT_WARN_DAYS,
    ignore: Iterable[str] = (),
) -> dict[str, Any]:
    """Run the requested scans of one target concurrently and build its report dict.

    ``overall_severity`` is the worst finding over the scans that succeeded,
    or ``ERROR`` when every requested scan failed; failed scans are listed in
    ``errors`` so a TLS failure never hides an SSH finding (or vice versa).
    """
    ignore = list(ignore)
    started = _now()
    tls_scanner = (
        TLSScanner(
            target,
            port=port,
            timeout=timeout,
            concurrency=concurrency,
            sni=sni,
            ca_file=ca_file,
            check_trust=check_trust,
        )
        if tls
        else None
    )
    ssh_scanner = SSHScanner(target, port=ssh_port, timeout=timeout) if ssh_port is not None else None
    tls_findings, ssh_findings = await asyncio.gather(
        tls_scanner.scan() if tls_scanner else _none(),
        ssh_scanner.scan() if ssh_scanner else _none(),
    )

    severities: list[str] = []
    errors: list[str] = []
    if tls_findings is not None:
        tls_findings["score"] = score(tls_findings, warn_days=warn_days, ignore=ignore)
        severities.append(tls_findings["score"]["severity"])
        if tls_findings["status"] == "error":
            errors.append(f"TLS {tls_findings['host']}:{tls_findings['port']}: {tls_findings['error']}")
    if ssh_findings is not None:
        ssh_findings["score"] = score_ssh(ssh_findings, ignore=ignore)
        severities.append(ssh_findings["score"]["severity"])
        if ssh_findings["status"] == "error":
            errors.append(f"SSH {ssh_findings['host']}:{ssh_findings['port']}: {ssh_findings['error']}")
    overall = _overall(severities)
    return {
        "tool": "vetls",
        "version": __version__,
        "target": target,
        "scanned_at": started,
        "environment": _environment(),
        "overall_severity": overall,
        "errors": errors,
        "tls": tls_findings,
        "ssh": ssh_findings,
    }


async def run_scans(targets: Sequence[str], **options: Any) -> dict[str, Any]:
    """Scan several targets (a few at a time) and wrap the reports."""
    started = _now()
    sem = asyncio.Semaphore(TARGET_PARALLELISM)

    async def one(target: str) -> dict[str, Any]:
        async with sem:
            return await run_scan(target, **options)

    reports = await asyncio.gather(*(one(t) for t in targets))
    overall = _overall([r["overall_severity"] for r in reports])
    errors = [f"{r['target']}: {e}" for r in reports for e in r["errors"]]
    return {
        "tool": "vetls",
        "version": __version__,
        "scanned_at": started,
        "environment": _environment(),
        "overall_severity": overall,
        "errors": errors,
        "reports": list(reports),
    }


async def _none() -> None:
    return None


def exit_code_for(severity: str, fail_on: str = "MEDIUM", had_errors: bool = False) -> int:
    """Exit code for an overall severity.

    A finding at or above ``fail_on`` gives 1 even when some scans failed: a
    real problem is more important than an incomplete scan. Otherwise any
    failure gives 2.
    """
    if severity != "ERROR" and fail_on != "never" and severity_rank(severity) >= severity_rank(fail_on):
        return EXIT_FINDINGS
    if severity == "ERROR" or had_errors:
        return EXIT_ERROR
    return EXIT_OK


def _usage_error(message: str) -> int:
    print(f"vetls: {message}", file=sys.stderr)
    return EXIT_ERROR


def _write_json(path: str, data: dict[str, Any]) -> str | None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    except OSError as exc:
        return f"cannot write {path}: {exc}"
    return None


def use_color(no_color: bool = False) -> bool:
    """Colour on a terminal; ``NO_COLOR`` disables it, ``FORCE_COLOR`` forces it."""
    if no_color or "NO_COLOR" in os.environ:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def _list_rules() -> str:
    width = max(len(rule) for rule in RULES)
    return "\n".join(f"{rule:<{width}}  {text}" for rule, text in RULES.items())


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(_normalize_argv(list(sys.argv[1:] if argv is None else argv)))
    except SystemExit as exc:  # argparse exits with 0 for --help/--version, 2 for usage errors
        return exc.code if isinstance(exc.code, int) else EXIT_ERROR

    if args.list_rules:
        print(_list_rules())
        return EXIT_OK

    targets = list(args.targets)
    if args.targets_file:
        try:
            targets += read_targets_file(args.targets_file)
        except (OSError, UnicodeDecodeError) as exc:
            return _usage_error(f"cannot read {args.targets_file}: {exc}")
    targets = list(dict.fromkeys(targets))  # drop duplicates, keep order
    if not targets:
        return _usage_error("no target given (pass TARGET or --targets-file)")

    ssh_port = args.ssh_port if args.ssh_port is not None else (DEFAULT_SSH_PORT if args.ssh else None)
    if args.no_tls and ssh_port is None:
        return _usage_error("--no-tls needs --ssh or --ssh-port")
    for name, value in (("--port", args.port), ("--ssh-port", ssh_port)):
        if value is not None and not 0 < value <= 65535:
            return _usage_error(f"{name} must be between 1 and 65535")
    if args.timeout <= 0:
        return _usage_error("--timeout must be positive")
    ignore = _split_rules(args.ignore)
    unknown = [rule for rule in ignore if rule not in RULES]
    if unknown:
        return _usage_error(f"unknown rule ID(s) for --ignore: {', '.join(unknown)} (see --list-rules)")
    for target in targets:
        try:
            parse_target(target)
        except ValueError as exc:
            return _usage_error(str(exc))
    if args.sni is not None:
        try:
            TLSScanner("localhost", sni=args.sni)
        except ValueError as exc:
            return _usage_error(f"--sni: {exc}")
    if args.ca_file:
        try:
            make_trust_context(args.ca_file)
        except (OSError, ssl.SSLError) as exc:
            return _usage_error(f"cannot load --ca-file {args.ca_file}: {exc}")

    options: dict[str, Any] = {
        "port": args.port,
        "sni": args.sni,
        "ssh_port": ssh_port,
        "tls": not args.no_tls,
        "timeout": args.timeout,
        "concurrency": args.concurrency,
        "ca_file": args.ca_file,
        "check_trust": not args.no_trust_check,
        "warn_days": args.warn_days,
        "ignore": ignore,
    }
    color = use_color(args.no_color)
    if not args.json:
        if not args.no_banner:
            print(banner(color))
        print(scanning_line(targets, color), flush=True)
    try:
        if len(targets) == 1:
            report = asyncio.run(run_scan(targets[0], **options))
            reports = [report]
        else:
            report = asyncio.run(run_scans(targets, **options))
            reports = report["reports"]
    except KeyboardInterrupt:
        print("vetls: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED

    for path, data in ((args.out, report), (args.sarif, build_sarif(reports) if args.sarif else None)):
        if path and data is not None:
            error = _write_json(path, data)
            if error:
                return _usage_error(error)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        renderer = render_report if len(targets) == 1 else render_multi_report
        print(renderer(report, color=color))
    return exit_code_for(report["overall_severity"], args.fail_on, bool(report["errors"]))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
