---
name: repo-scanner
description: Pre-install GitHub repository security scanner. Scans repos for malicious code, vulnerabilities, secrets, and trust signals before downloading or installing. USE WHEN scan repo, check repo, is this safe, security scan, before install, audit github, supply chain.
category: security
triggers:
  - scan repo
  - check repo
  - is this safe
  - security scan
  - before install
  - audit github
  - supply chain
  - scan before install
---

# Repo Scanner — Pre-Install Security Audit

Scan any GitHub repository for security risks BEFORE downloading or installing it.

## Quick Usage

```
scan <github-url>
scan <github-url> --quick    # Phase 1 only (no clone)
scan <github-url> --deep     # All phases + Semgrep custom rules
```

## Tool Requirements

Install all tools (one-time):
```bash
brew install scorecard grype syft gitleaks trufflehog semgrep osv-scanner
pip install guarddog
```

## Three-Phase Pipeline

### Phase 1: Remote Analysis (no clone needed)

Fast trust assessment without downloading anything:

```bash
# 1. OpenSSF Scorecard — repo trust score (0-10 across 18 checks)
scorecard --repo=github.com/{owner}/{repo} --format=json

# 2. TruffleHog — scan remote repo for live secrets
trufflehog git https://github.com/{owner}/{repo} --json --only-verified

# 3. GitHub API — stars, forks, last commit, open issues, license
gh api repos/{owner}/{repo} --jq '{stars: .stargazers_count, forks: .forks_count, open_issues: .open_issues_count, license: .license.spdx_id, pushed_at: .pushed_at, archived: .archived, default_branch: .default_branch}'
```

**Quick verdict signals:**
- Scorecard overall < 4.0 = HIGH RISK
- Scorecard overall 4.0-6.0 = REVIEW NEEDED
- Scorecard overall > 6.0 = REASONABLE TRUST
- Live secrets found = CRITICAL (never install)
- No commits in 12+ months = ABANDONED
- < 10 stars + < 3 contributors = LOW TRUST (not inherently bad, but verify)

### Phase 2: Shallow Clone + Static Analysis

Clone minimally and scan the actual code:

```bash
# Clone depth=1 to temp directory
SCAN_DIR=$(mktemp -d)/scan-target
git clone --depth=1 https://github.com/{owner}/{repo}.git "$SCAN_DIR"
cd "$SCAN_DIR"

# 4. GuardDog — malicious package detection (npm/PyPI)
#    Detects: install scripts, data exfiltration, crypto miners, typosquatting
guarddog npm scan .  # or: guarddog pypi scan .

# 5. Semgrep — 1000+ SAST rules for code vulnerabilities
semgrep scan --config auto --json .

# 6. Gitleaks — hardcoded secrets in source code
gitleaks detect --source=. --report-format=json --report-path=/tmp/gitleaks-report.json

# 7. OSV-Scanner — known CVEs in dependencies
osv-scanner scan -r . --format=json

# 8. Grype — dependency vulnerability scan
grype dir:. -o json

# 9. Syft — SBOM + license inventory
syft . -o spdx-json > /tmp/sbom.json
```

### Phase 3: Risk Report

Aggregate all findings into a structured verdict:

```
## Security Scan Report: {owner}/{repo}

### Trust Score
- Scorecard: X.X/10 (18 checks)
- Stars: N | Forks: N | Contributors: N
- Last commit: YYYY-MM-DD
- License: MIT/Apache/GPL/NONE

### Critical Findings
- [ ] Live secrets detected (TruffleHog)
- [ ] Malicious code patterns (GuardDog)
- [ ] High/Critical CVEs (OSV-Scanner + Grype)

### Warnings
- [ ] Hardcoded secrets in source (Gitleaks)
- [ ] SAST issues (Semgrep) — count by severity
- [ ] Dependency vulnerabilities — count by severity
- [ ] Missing security practices (Scorecard checks)

### License
- Primary: {license}
- Dependencies: {license summary from SBOM}

### VERDICT: SAFE / REVIEW NEEDED / DO NOT INSTALL

Reasoning: [1-3 sentences explaining the verdict]
```

## Verdict Logic

| Condition | Verdict |
|-----------|---------|
| Live secrets OR malicious code detected | DO NOT INSTALL |
| Critical CVEs with no fix available | DO NOT INSTALL |
| Scorecard < 4.0 AND high CVE count | DO NOT INSTALL |
| Scorecard 4.0-6.0 OR moderate CVEs | REVIEW NEEDED |
| Scorecard > 6.0 AND no critical findings | SAFE |
| Archived repo with known CVEs | DO NOT INSTALL |

## Agent Integration

This skill is designed for Rook Blackburn (Pentester agent) to run. When invoked through the agent system:

```json
{"agent": "pentester", "voice_id": "pentester"}
```

Rook reports findings with his characteristic excited, conspiratorial energy when vulns are found.

## Custom Semgrep Rules

For deeper scans (`--deep` mode), use custom rules targeting:

```yaml
# ~/.claude/skills/repo-scanner/rules/malicious-patterns.yaml
rules:
  - id: suspicious-eval
    patterns:
      - pattern: eval($X)
    message: Dynamic code execution detected
    severity: WARNING

  - id: base64-decode-exec
    patterns:
      - pattern: |
          $X = base64.b64decode(...)
          ...
          exec($X)
    message: Base64-decoded code execution (potential backdoor)
    severity: ERROR

  - id: reverse-shell
    patterns:
      - pattern: socket.socket(...)
    message: Socket creation detected (review for reverse shell)
    severity: WARNING

  - id: env-exfiltration
    patterns:
      - pattern: os.environ[...]
      - pattern: process.env[...]
    message: Environment variable access (check for data exfiltration)
    severity: INFO
```

## Scan History

Store scan results for reference:
```
~/.claude/skills/repo-scanner/scans/
  {owner}-{repo}-{date}.json
```

## Notes

- Scorecard requires a GitHub token for rate limits: `export GITHUB_TOKEN=...`
- GuardDog works best with npm and PyPI packages
- TruffleHog can scan remote URLs without cloning (Phase 1)
- All tools output JSON for easy aggregation
- Bun projects: use `bun audit` as additional check
