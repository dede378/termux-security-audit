# termux-security-audit

Lightweight HTTP security configuration auditor for Termux.

## Purpose

`termux-security-audit` checks a website's HTTP response for common security controls and configuration weaknesses. It is designed as a fast first-pass audit before deeper testing with tools such as Nmap, Nuclei, Nikto, or manual application testing.

This project is **defensive and educational**. Use it only against systems you own or are explicitly authorized to test.

## Current checks

- HTTP status and final URL
- HTTPS
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- Clickjacking protection via X-Frame-Options or CSP frame-ancestors
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy (COOP)
- Cross-Origin-Resource-Policy (CORP)
- CORS wildcard detection
- Basic cookie security flags: Secure, HttpOnly, SameSite
- Server / X-Powered-By information disclosure
- PASS / WARN / FAIL / INFO summary
- Basic configuration score

## Important classification rule

The scanner does **not** claim that a missing security header automatically proves a vulnerability.

For example, missing CSP is reported as a configuration weakness/indicator, not automatically as confirmed XSS. Application-level vulnerabilities require separate evidence and testing.

## Requirements

Termux with:

- bash
- curl
- standard Unix utilities

Install the main dependency with:

```bash
pkg update
pkg install curl
```

## Installation

Clone the repository:

```bash
git clone https://github.com/dede378/termux-security-audit.git
cd termux-security-audit
chmod +x audit_headers.sh
```

## Usage

Audit a single HTTPS target:

```bash
./audit_headers.sh https://example.com
```

HTTP targets are also accepted:

```bash
./audit_headers.sh http://example.com
```

## Example output

```text
SECURITY HEADERS
──────────────────────────────────────────────
[PASS] HSTS                         configured
[WARN] Content-Security-Policy      missing
[PASS] Clickjacking protection      X-Frame-Options
[PASS] X-Content-Type-Options       nosniff
[PASS] Referrer-Policy              configured
[FAIL] Permissions-Policy           missing

CORS
──────────────────────────────────────────────
[WARN] CORS                        wildcard (*)

SUMMARY
══════════════════════════════════════════════
PASS : 4
WARN : 2
FAIL : 1
INFO : 2

Score  : 71/100
Rating : NEEDS IMPROVEMENT
```

## Finding severity

The first version intentionally focuses on **configuration evidence** rather than aggressive exploitation.

Typical findings include:

- Security Misconfiguration
- Missing browser security controls
- CORS configuration weakness
- Cookie security weakness
- Information disclosure indicators

Future versions can add structured CWE mappings, evidence records, batch scanning, JSON output, HTML reports, and integration with other authorized security tools.

## Project roadmap

### v1.0

- Single-target HTTP header audit
- Clear terminal output
- Basic score
- Cookie/CORS checks
- README and safe output exclusions

### Planned

- Batch domain input
- JSON reports
- HTML reports
- CWE mapping
- Severity and confidence fields
- Evidence collection
- TLS checks
- Additional exposure checks
- Optional integration with Nuclei/Nmap

## Legal and ethical use

Only scan systems for which you have permission. Do not use this project to bypass authentication, exploit vulnerabilities, access private data, or disrupt services.

## License

MIT License.
