# GitHub Repository Security Scanner

Scan any GitHub repository for malicious code, secrets, vulnerabilities, and trust signals **before** downloading or installing it.

## Quick Start

### macOS
```bash
./mac/install.sh
```

### Windows
Right-click `windows\install.bat` → Run as Administrator

---

## Usage (after install)

```bash
# Full scan (recommended)
repo-scan https://github.com/owner/repo

# Quick scan — remote only, no clone
repo-scan https://github.com/owner/repo --quick

# Output as JSON
repo-scan https://github.com/owner/repo --json
```

## What it checks

| Tool | What it finds |
|------|--------------|
| OpenSSF Scorecard | 18-point trust score — branch protection, code review, CI, signed releases |
| TruffleHog | Live/verified secrets and credentials in repo history |
| GuardDog | Malicious install scripts, data exfiltration, crypto miners, typosquatting |
| Semgrep | Code vulnerabilities (1,000+ SAST rules) |
| Gitleaks | Hardcoded secrets in source files |
| OSV-Scanner | Known CVEs in dependencies |
| Grype | Dependency vulnerability scan with severity grading |

## Verdict

Every scan ends with one of three verdicts:

- **SAFE** — Scorecard > 6.0, no critical findings
- **REVIEW NEEDED** — moderate issues found, use with caution
- **DO NOT INSTALL** — live secrets, malicious code, or critical CVEs detected

## Requirements

- macOS: Homebrew (installed automatically if missing)
- Windows: Windows 10/11 with winget or Scoop
- GitHub CLI (`gh`) must be authenticated: run `gh auth login` once after install

## Scan history

Results are saved to `~/.repo-scanner/scans/` as JSON files for reference.
