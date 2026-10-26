# Security policy

## Responsible use

`vetls` opens TCP connections and performs TLS handshakes with deliberately legacy settings. It does not
exploit anything, but scanning systems you do not own can still be against the law or a provider's terms.
**Only scan hosts you own or have written permission to test.**

## Reporting a vulnerability in vetls

Please do not open a public issue. Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository ("Security" tab, "Report a vulnerability"). You will get a first response within a week.

## Scope notes

- The probing TLS contexts turn certificate verification off **on purpose**: the tool must be able to read expired,
  self-signed and mismatched certificates. Chain trust is judged by one separate handshake with verification on.
  The tool never sends credentials or other secrets.
- Only the latest released version receives fixes.
