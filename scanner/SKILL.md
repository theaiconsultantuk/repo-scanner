---
name: repo-scanner
description: Pre-install GitHub repository security scanner. Runs a 4-phase automated pipeline (trust signals, SAST, code quality, verdict) against any GitHub repo. USE WHEN scan repo, check repo, is this safe, security scan, before install, audit github, supply chain, scan before install.
---

# Repo Scanner v2

Scan any GitHub repository for security risks before downloading or installing.

## Usage

```bash
bun ~/.claude/skills/repo-scanner/scan.ts <github-url>
bun ~/.claude/skills/repo-scanner/scan.ts <github-url> --quick   # Phase 1 only (~15s, no clone)
bun ~/.claude/skills/repo-scanner/scan.ts <github-url> --json    # JSON output to stdout
bun ~/.claude/skills/repo-scanner/scan.ts <github-url> --resume  # Continue interrupted scan
bun ~/.claude/skills/repo-scanner/scan.ts <github-url> --fresh   # Ignore saved state
```

Accepts URLs in any form: `https://github.com/owner/repo`, `github.com/owner/repo`, or `owner/repo`.

## What It Does

4-phase automated pipeline — all tool orchestration is handled internally:

1. **Remote Analysis** — OpenSSF Scorecard, TruffleHog (live secrets), GitHub API metadata
2. **Shallow Clone + SAST** — GuardDog, Semgrep, Gitleaks, OSV-Scanner, Grype
3. **Code Quality Signals** — 10 automated checks (CI, tests, docs, lock files, dep surface)
4. **Verdict** — Aggregates to Security Score (0-10), Maturity Score (0-10), and final verdict

Verdicts: **SAFE** / **REVIEW NEEDED** / **DO NOT INSTALL**

Each finding includes a plain-English explanation for non-technical users.

## Prerequisites

Tools (one-time, handled by installer):
```bash
brew install scorecard grype syft gitleaks trufflehog semgrep osv-scanner
pipx install guarddog
```

Scorecard needs a GitHub token. The scanner auto-detects `gh auth token` as fallback, but for reliability:
```bash
export GITHUB_TOKEN=your_token_here
```

## File Locations

- Scan history: `~/.repo-scanner/scans/{owner}-{repo}-{date}.json`
- Resume state: `~/.repo-scanner/state/`
- Scanner source: `~/.claude/skills/repo-scanner/scan.ts`

## Agent Integration

Designed for Rook Blackburn (Pentester agent). Voice profile resolved automatically from `~/.claude/agents/voices.json`.
