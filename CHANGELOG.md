# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-25

### Renamed
- The project is now **vetls** (previously `secaudit-tls`): PyPI package `vetls`, import `vetls`,
  command `vetls`, home https://github.com/versex-arch/vetls.

### Added
- New terminal look: ASCII banner, `[*]`/`[+]`/`[!]`/`[?]` markers, coloured severity tags and a per-protocol
  table; `--no-banner`; `FORCE_COLOR=1` forces colours. Rendering lives in `vetls.ui`.
- README redesigned (logo, demo screenshot, install table, `--help`, disclaimer); the full
  reference moved to `docs/usage.md` and `docs/usage.ru.md`.
- Certificate chain trust check: one verifying handshake against the system trust store, or against
  `--ca-file`. Unknown CAs, expired intermediates and similar are reported as `CERT-UNTRUSTED` (MEDIUM);
  `--no-trust-check` skips it. Results are in the new `trust` object of the TLS findings.
- Expiry warning: `--warn-days N` (default 14) reports certificates close to expiry as `CERT-EXPIRES-SOON`.
- `--sni NAME` to audit a specific backend by IP while sending and checking a host name.
- Several targets on the command line and `-f/--targets-file`, scanned in parallel, with a summary.
- `--fail-on LOW|MEDIUM|HIGH|CRITICAL|never` and `--ignore RULE` for CI policies; `--list-rules`.
- Stable rule IDs on every issue (`{"id", "severity", "message"}`), exported as `vetls.RULES`.
- SARIF 2.1.0 output (`--sarif FILE`, `vetls.build_sarif`).
- `--concurrency N` in the CLI.
- New rules: `TLS-NO-TLS13` (LOW), `TLS-NO-MODERN` (MEDIUM), `CIPHER-NO-PFS` (LOW, static RSA key exchange).
- New cipher probes: `ECDHE-RSA-AES128-SHA`, `ECDHE-ECDSA-AES128-SHA`, `DHE-RSA-AES128-SHA`,
  `AES128-GCM-SHA256`, `AES256-GCM-SHA384`.
- Report metadata: `scanned_at`, `environment` (Python, OpenSSL, platform), `errors`.
- TLS findings include `address` and `resolved_addresses`.
- Python 3.14 in CI; package build check; release workflow with PyPI Trusted Publishing.

### Changed
- The host name is resolved once and every probe goes to the same address (the first one that accepts a
  connection), so DNS round-robin can no longer mix results from different backends.
- Certificate lifetime limit follows the CA/B Forum schedule by issuance date (398 / 200 / 100 / 47 days)
  instead of a fixed 398 days; the certificate result has a new `max_lifetime_days` key.
- Internationalised names use IDNA 2008 with UTS #46 (`faß.de` is `xn--fa-hia.de`, not `fass.de`).
  New dependency: `idna>=3`.
- A failed scan no longer hides findings of another scan: `overall_severity` is the worst finding of the
  scans that succeeded, `ERROR` only when all failed. Findings at or above `--fail-on` give exit code 1
  even if another scan failed.
- Name-resolution failures say `cannot resolve HOST: ...` instead of `cannot connect: ...`.
- `CIPHER_RULES` entries now carry a rule ID: `(pattern, rule_id, severity, description)`.
  `classify_cipher()` is unchanged; `cipher_rule()` returns the ID too.
- Score results have an `ignored` list.
- `SSHScanner` rejects a non-positive timeout; `TLSScanner` rejects `concurrency < 1`.

## [1.0.0] - 2026-10-22

First public release.

### Added
- TLS scanner: per-version protocol probes (SSLv3 to TLS 1.3) and weak-cipher probes (TLS 1.2 and below),
  run concurrently with a timeout per probe.
- Three-way probe outcome: `accepted`, `refused` and `locally_unavailable`. What the local OpenSSL build
  cannot test is reported as unchecked, never as "not accepted".
- X.509 analysis: validity window, key strength, signature hash, full-name self-signed detection,
  SAN/hostname matching (RFC 6125 wildcards, IP SANs, public-suffix wildcards rejected), 398-day lifetime check.
- Severity scoring (`INFO` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`) with the full list of reasons.
- SSH identification-banner reader (banner only, no vulnerability claims).
- CLI: `vetls TARGET [--port] [--ssh | --ssh-port N] [--no-tls] [--timeout] [--json] [--out FILE]`,
  CI-friendly exit codes.
- Test suite that runs against real TLS and SSH-banner servers on localhost.

[1.1.0]: https://github.com/versex-arch/vetls/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/versex-arch/vetls/releases/tag/v1.0.0
