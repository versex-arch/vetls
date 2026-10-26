<p align="center">
  <a href="https://github.com/versex-arch/vetls">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="docs/images/logo-dark.png">
      <img src="docs/images/logo-light.png" alt="vetls" width="440">
    </picture>
  </a>
  <br>
  <span>Audit TLS protocols, weak ciphers, certificates and SSH banners of your servers, without touching them</span>
  <br>
</p>

<p align="center">
  <a href="#installation">Installation</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="#usage">Usage</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="docs/usage.md">Documentation</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="CONTRIBUTING.md">Contributing</a>
  &nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;
  <a href="README.ru.md">Русский</a>
</p>

<p align="center">
  <a href="https://github.com/versex-arch/vetls/actions/workflows/ci.yml"><img src="https://github.com/versex-arch/vetls/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT"></a>
</p>

<p align="center">
  <a href="docs/images/demo.png"><img src="docs/images/demo.png" alt="vetls demo" width="760"></a>
</p>

## Installation

| Method | Notes |
|---|---|
| `pipx install vetls` | `pip` or `uv tool install` may be used in place of `pipx` |
| `pip install git+https://github.com/versex-arch/vetls` | Latest development version |
| `git clone https://github.com/versex-arch/vetls && cd vetls && pip install .` | From source |

Requires Python 3.10+. Dependencies (`cryptography`, `idna`) are installed automatically.

> [!NOTE]
> Checks for SSLv3, RC4, DES and export ciphers depend on your **local OpenSSL**. Most modern systems compile them
> out; vetls then reports them as *not testable here*, never as "refused".

## Usage

**Check a server**
```console
vetls example.com
```

**Several servers, or a list from a file**
```console
vetls example.com mail.example.com:993
vetls -f targets.txt
```

**One backend behind a load balancer**
```console
vetls 10.0.0.5 --sni api.example.com
```

**Also read the SSH banner**
```console
vetls example.com --ssh
```

**In CI: JSON + SARIF, fail on HIGH and above**
```console
vetls -f targets.txt --fail-on HIGH --out report.json --sarif report.sarif
```

```console
$ vetls --help
usage: vetls [-h] [-f FILE] [--port PORT] [--sni NAME] [--ssh] [--ssh-port N] [--no-tls] [--ca-file FILE]
             [--no-trust-check] [--timeout TIMEOUT] [--concurrency N] [--warn-days N]
             [--fail-on {LOW,MEDIUM,HIGH,CRITICAL,never}] [--ignore RULE] [--json] [--out FILE]
             [--sarif FILE] [--no-color] [--no-banner] [--list-rules] [--version]
             [TARGET ...]

vetls v1.1.0: non-invasive TLS configuration, certificate and SSH-banner audit.

positional arguments:
  TARGET                host, host:port, [ipv6]:port or https://host[:port]; several may be given

options:
  -h, --help            show this help message and exit
  -f, --targets-file FILE
                        read targets from FILE, one per line ('#' comments)
  --version             show program's version number and exit

scan options:
  --port PORT           TLS port for every target (overrides TARGET; default 443)
  --sni NAME            send NAME as SNI and check the certificate against it
  --ssh                 also read the SSH banner on port 22
  --ssh-port N          also read the SSH banner on port N
  --no-tls              skip the TLS scan (use with --ssh/--ssh-port)
  --ca-file FILE        trust the CA certificates in FILE instead of the system store
  --no-trust-check      do not verify the certificate chain
  --timeout TIMEOUT     per-probe timeout in seconds (default: 5.0)
  --concurrency N       parallel handshakes per target (default: 6)

policy:
  --warn-days N         report certificates expiring in fewer than N days as MEDIUM (default: 14)
  --fail-on {LOW,MEDIUM,HIGH,CRITICAL,never}
                        lowest severity that makes the exit code 1 (default: MEDIUM)
  --ignore RULE         ignore a rule ID (repeatable, or comma-separated); see --list-rules

output:
  --json                print machine-readable JSON instead of the report
  --out FILE            also write the JSON report to FILE
  --sarif FILE          also write a SARIF 2.1.0 log to FILE
  --no-color            disable colored output
  --no-banner           do not print the banner
  --list-rules          list rule IDs and exit

Exit codes: 0 = nothing at or above --fail-on (default MEDIUM), 1 = at least one finding at or
above --fail-on, 2 = scan or usage error (findings take precedence), 130 = interrupted.
Use --list-rules to see the rule IDs accepted by --ignore.
Only scan systems you own or have explicit permission to test.
```

The full reference (what each check means, severities, rule IDs, JSON and SARIF formats, using vetls as a Python
library, limitations) is in **[docs/usage.md](docs/usage.md)**.

## What it checks

| | |
|---|---|
| 🔒 **Protocols** | SSLv3 · TLS 1.0 · 1.1 · 1.2 · 1.3, missing TLS 1.3 |
| 🧩 **Ciphers** | export, anonymous, NULL, RC4, DES, 3DES, legacy CBC, no forward secrecy |
| 📜 **Certificate** | expired / expiring soon, weak key, MD5 / SHA-1 signature, self-signed, lifetime over the CA/B Forum limit |
| 🔗 **Trust & name** | chain verified against the system store or `--ca-file`, SAN / wildcard / IP matching, IDNA 2008 |
| 🖥️ **SSH** | identification banner, obsolete protocol 1.x |

## Disclaimer

```
vetls is meant for auditing systems you own or have explicit
written permission to test. It performs ordinary TLS handshakes
and reads public banners: it does not exploit anything, force
downgrades or try credentials. Scanning third-party systems
without permission may be illegal or break a provider's terms.
The author takes no responsibility for misuse.
```

## License

MIT © [versex-arch](https://github.com/versex-arch). See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
