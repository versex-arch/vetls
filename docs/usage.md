# vetls: full reference

[← Back to README](../README.md) · [Русская версия](usage.ru.md)

- [Options](#options)
- [How a scan works](#how-a-scan-works)
- [Exit codes](#exit-codes)
- [Severity and rules](#severity-and-rules)
- [Output formats](#output-formats)
- [Use in CI](#use-in-ci)
- [Use as a library](#use-as-a-library)
- [Limitations](#limitations)
- [Development](#development)

## Options

| Option | Meaning |
|---|---|
| `TARGET ...` | `host`, `host:port`, `[ipv6]:port` or `https://host[:port]/path` (path, query and fragment are ignored) |
| `-f`, `--targets-file FILE` | read targets from FILE, one per line, `#` starts a comment |
| `--port PORT` | TLS port for every target, overrides the one in the target (default 443) |
| `--sni NAME` | send NAME as SNI and check the certificate against it (handy for IP targets) |
| `--ssh`, `--ssh-port N` | also read the SSH banner (port 22 or N) |
| `--no-tls` | skip the TLS scan, e.g. SSH only |
| `--ca-file FILE` | verify the chain against the CAs in FILE instead of the system store |
| `--no-trust-check` | skip the chain verification handshake |
| `--timeout SECONDS` | per-probe timeout, default 5 |
| `--concurrency N` | parallel handshakes per target, default 6 (lower it for rate-limited hosts) |
| `--warn-days N` | report certificates expiring in fewer than N days as `MEDIUM`, default 14 |
| `--fail-on LEVEL` | lowest severity that gives exit code 1: `LOW`, `MEDIUM` (default), `HIGH`, `CRITICAL` or `never` |
| `--ignore RULE` | accept a known risk: the rule is listed as *ignored* and does not count (repeatable or comma-separated) |
| `--list-rules` | print every rule ID and exit |
| `--json` | print JSON instead of the human report (no banner) |
| `--out FILE` | also write the JSON report to FILE |
| `--sarif FILE` | also write a SARIF 2.1.0 log to FILE |
| `--no-color` | disable colours (`NO_COLOR` is honoured too; `FORCE_COLOR=1` forces them) |
| `--no-banner` | do not print the ASCII banner |

Terminal markers: `[*]` progress, `[+]` fine, `[!]` problem, `[?]` not tested here, `[i]` information,
`[=]` verdict.

## How a scan works

For every target vetls:

1. resolves the host name **once** and picks the first address that accepts a TCP connection; all probes go to that
   address, so a DNS round-robin cannot mix results from different backends (the report notes when a name has
   several addresses: scan the others by IP with `--sni`);
2. tries a handshake pinned to each protocol version (SSLv3 to TLS 1.3);
3. tries a handshake offering exactly one weak cipher suite, for 17 suites, at TLS 1.2 and below;
4. verifies the certificate chain in one more handshake, against the system trust store or `--ca-file`;
5. analyses the leaf certificate (validity, key, signature, SAN, lifetime) and scores everything.

That is about 23 short TCP connections per target, 6 at a time by default.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | nothing at or above `--fail-on` and every scan succeeded |
| `1` | at least one finding at or above `--fail-on` (default `MEDIUM`), even if another scan failed |
| `2` | a scan failed (host unreachable, no TLS on the port, ...) or invalid arguments |
| `130` | interrupted |

A failed scan never hides a finding: if TLS is unreachable but the SSH banner shows protocol 1.5, the overall
severity is `HIGH` and the exit code is 1. `overall_severity` is `ERROR` only when every requested scan failed.

## Severity and rules

The overall severity is the maximum over all triggered rules; every triggered rule is listed with a stable ID.
`vetls --list-rules` prints them all.

| Severity | Rules |
|---|---|
| `CRITICAL` | `TLS-SSLV3`, `CIPHER-EXPORT`, `CIPHER-ANON`, `CERT-EXPIRED` |
| `HIGH` | `CIPHER-RC4`, `CIPHER-NULL`, `CIPHER-DES`, `CERT-NAME-MISMATCH`, `CERT-NOT-YET-VALID`, MD5 `CERT-WEAK-SIGNATURE`, `SSH-PROTO-1` |
| `MEDIUM` | `TLS-TLS10`, `TLS-TLS11`, `TLS-NO-MODERN`, `CIPHER-3DES`, `CERT-UNTRUSTED`, `CERT-SELF-SIGNED`, `CERT-EXPIRES-SOON`, `CERT-WEAK-KEY`, SHA-1 `CERT-WEAK-SIGNATURE`, `CERT-NO-SAN`, `CERT-SAN-EMPTY`, `CERT-SAN-ERROR`, `CERT-UNKNOWN-SIGNATURE`, `CERT-ANALYSIS-FAILED`, `SSH-PROTO-1-99` |
| `LOW` | `TLS-NO-TLS13`, `CIPHER-CBC`, `CIPHER-NO-PFS`, `CERT-LONG-LIFETIME` |
| `INFO` | nothing found: *"No weaknesses detected by the checks performed"* |

**Certificate lifetime.** The limit depends on when the certificate was issued, following CA/B Forum ballot
SC-081: 398 days from September 2020, 200 days from 15 March 2026, 100 days from 15 March 2027 and 47 days from
15 March 2029.

**Trust.** A self-signed certificate is reported once (as `CERT-SELF-SIGNED`, not also as untrusted); an expired
leaf is reported as expired, not also as untrusted. A self-signed certificate that verifies (because you passed it
with `--ca-file`) is not flagged at all.

Absence of findings is not proof of security. Things vetls could not test are listed as `[?]` notes and never
change the severity.

## Output formats

**JSON** (`--json`, `--out`). One target gives one report:

```json
{
  "tool": "vetls", "version": "1.1.0", "target": "example.com",
  "scanned_at": "2026-10-25T17:30:00+00:00",
  "environment": {"python": "3.13.1", "openssl": "OpenSSL 3.5.0 ...", "platform": "..."},
  "overall_severity": "LOW", "errors": [],
  "tls": {"host": "...", "address": "...", "accepted_protocols": ["..."], "certificate": {},
          "trust": {"status": "trusted"},
          "score": {"severity": "LOW", "issues": [], "ignored": [], "notes": []}},
  "ssh": null
}
```

Several targets give `{"tool", "version", "scanned_at", "environment", "overall_severity", "errors", "reports": [...]}`
with one report per target. Every issue is `{"id", "severity", "message"}`. Error results carry the same keys as
successful ones, so consumers never have to guard against missing keys.

**SARIF 2.1.0** (`--sarif`) for code-scanning dashboards: one result per issue, levels `error` (CRITICAL/HIGH),
`warning` (MEDIUM) and `note` (LOW), with `security-severity` and stable fingerprints. Failed scans are reported as
tool notifications.

## Use in CI

```yaml
# GitHub Actions
- run: pipx install vetls
- run: vetls -f deploy/endpoints.txt --sarif vetls.sarif --out vetls.json --ignore CIPHER-CBC
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: vetls.sarif
```

## Use as a library

```python
from vetls import TLSScanner, score

findings = TLSScanner("example.com", timeout=5).scan_sync()  # or: await TLSScanner(...).scan()
result = score(findings, warn_days=21, ignore=["CIPHER-CBC"])
print(result["severity"])  # "INFO" ... "CRITICAL" / "ERROR"
for issue in result["issues"]:
    print(issue["id"], issue["severity"], issue["message"])
```

`TLSScanner(target, port=None, timeout=5, concurrency=6, *, sni=None, ca_file=None, check_trust=True)`.
`scan_sync()` raises `RuntimeError` inside a running event loop; use `await scan()` there. Other entry points:
`analyze_certificate(pem_or_der_bytes, target_host=None)`, `SSHScanner(host).scan_sync()`, `parse_target(str)`,
`build_sarif(reports)`, `RULES`.

## Limitations

- **Detection is bounded by your local OpenSSL.** Many distributions compile out SSLv3, RC4, DES and export
  ciphers. Those probes are reported as *not testable here*, not as "server refused". Run vetls from a machine or
  container with a permissive OpenSSL build when you need them.
- **TLS 1.3 cipher suites are not enumerated.** Python's `ssl` module cannot select them.
- **DH parameter size is not measured** (Python's `ssl` does not expose it), so Logjam-style weak DH groups are not
  detected.
- **No revocation checks** (OCSP/CRL) and no Certificate Transparency checks.
- **Cipher probing is heuristic.** A server with unusual cipher-selection logic can yield false negatives.
- **Public suffixes are a built-in subset**, not the full Public Suffix List.
- **SSH is banner-only.** No key-exchange, host-key or MAC enumeration, and no version-to-CVE mapping.
- Probes are plain TCP connections from your machine. Rate limiters or IDS on the target may notice them.

## Development

```bash
pip install -e ".[dev]"
pytest              # real TLS/SSH-banner servers on 127.0.0.1, no internet needed
ruff check . && ruff format --check .
mypy
```

```
src/vetls/
  target.py         target parsing (IPv6, ports, IDNA 2008)
  tls_scanner.py    resolution, protocol, cipher and chain-trust probes
  cert_analyzer.py  X.509 analysis
  scorer.py         severity rules and rule IDs
  sarif.py          SARIF export
  ssh_scanner.py    SSH banner reader
  ui.py             terminal output (banner, markers, colours)
  cli.py            command line
docs/images/        logo and demo screenshot
tests/              unit tests plus live tests against local servers
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) and [CHANGELOG.md](../CHANGELOG.md).
