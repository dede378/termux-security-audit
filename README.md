# termux-security-audit

Lightweight web security auditor for Termux, with a Nmap + Nuclei + SearchSploit pipeline.

## v0.6

Version 0.6 adds endpoint discovery, Nmap service enumeration, Nuclei scanning, CVE extraction, and local Exploit-DB/SearchSploit correlation.

The scanner reports evidence and candidates. It does **not** automatically exploit targets.

## Pipeline

\`\`\`text
TARGET
  |
  +-- HTTP endpoint discovery
  +-- Nmap service/version scan
  +-- Nuclei direct scan
  +-- Nuclei discovered-endpoint scan
  +-- Deduplication + classification
  +-- CVE extraction
  +-- SearchSploit / Exploit-DB correlation
  +-- audit-report.json
\`\`\`

A discovery failure no longer prevents the direct Nuclei scan. The target itself is always included.

## Requirements

Termux with:

- Python 3
- Nmap
- Nuclei
- SearchSploit / Exploit-DB

## Installation

\`\`\`bash
git clone https://github.com/dede378/termux-security-audit.git
cd termux-security-audit
chmod +x audit.py
\`\`\`

Update later:

\`\`\`bash
git pull --ff-only
\`\`\`

## Usage

\`\`\`bash
python3 audit.py https://example.com
\`\`\`

Custom report:

\`\`\`bash
python3 audit.py https://example.com -o reports/example.json
\`\`\`

Temporary files are kept under \`.audit-v0.6/\`.

## Discovery

The HTTP discovery layer:

- follows same-origin links
- reads form actions
- keeps query parameters such as \`?id=1\`
- removes URL fragments
- probes a small list of common paths
- limits crawling to 150 URLs and depth 2
- records errors without aborting the audit

## Report

The JSON report contains:

- discovered URLs and discovery errors
- Nmap open ports and service fingerprints
- Nuclei findings
- severity and category
- repeated-finding count
- detected CVEs
- SearchSploit results for detected CVEs
- low-confidence SearchSploit fingerprint candidates
- raw command results
- summary counts

## Interpretation

A Nuclei finding is evidence from a template, not automatically proof of an exploitable vulnerability.

A SearchSploit product/version match is only a candidate. Verify the affected product, exact version, configuration, and applicability before treating an exploit as relevant.

Only scan systems you own or have explicit permission to test.

## License

MIT License.
