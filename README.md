# GitHub Repository Security Scanner v2

Scan any GitHub repository for malicious code, secrets, vulnerabilities, and trust signals **before** downloading or installing it.

> Runs eight security tools across a four-phase pipeline — remote trust checks with no download required, shallow-clone security analysis, code quality assessment, and an aggregated **SAFE / REVIEW NEEDED / DO NOT INSTALL** verdict with separate security and maturity scores.

## What's new in v2

- **Code quality phase** — 10 signals: CI/CD, test suite, README depth, SECURITY.md, CHANGELOG, TypeScript strict mode, lock files, dependency surface, suspicious CI pipelines
- **Maturity score** (0-10) alongside the security score — know if a repo is secure *and* well-maintained
- **AI false-positive filter** for gitleaks — strips test fixtures, placeholder values, and env-var references before reporting (inspired by [Kem's kem-sec research](https://campfire.aura-intel.net/blog/deterministic-skills))
- **State persistence** — interrupted scans resume from the last completed phase with `--resume`
- **Structured type contracts** — each phase outputs a validated schema
- **Project type detection** — npm library, Python package, CLI, Go, Rust, web app — skip irrelevant checks automatically

## How it works

```
Phase 1 — Remote (parallel, no clone)
  OpenSSF Scorecard · TruffleHog · GitHub API
        ↓
Phase 2 — Shallow clone + security SAST (parallel)
  GuardDog · Semgrep · Gitleaks (FP-filtered) · OSV-Scanner · Grype
        ↓
Phase 3 — Code quality signals (10 checks)
  CI/CD · Tests · README · SECURITY.md · CHANGELOG
  TypeScript strict · Lock files · Dep surface · Workflow safety
        ↓
Phase 4 — Aggregate + Verdict
  Security Score (0-10)   Maturity Score (0-10)
  SAFE / REVIEW NEEDED / DO NOT INSTALL
```

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
# Full scan — all 4 phases (recommended)
repo-scan https://github.com/owner/repo

# Quick scan — Phase 1 remote only, no clone (~15s)
repo-scan https://github.com/owner/repo --quick

# Resume an interrupted scan
repo-scan https://github.com/owner/repo --resume

# Force fresh scan (ignore saved state)
repo-scan https://github.com/owner/repo --fresh

# Output as JSON
repo-scan https://github.com/owner/repo --json
```

## What it checks

| Phase | Tool | What it finds |
|-------|------|--------------|
| 1 | OpenSSF Scorecard | 18-point trust score — branch protection, code review, CI, signed releases |
| 1 | TruffleHog | Live/verified secrets and credentials in repo history |
| 1 | GitHub API | Stars, forks, license, activity, project type detection |
| 2 | GuardDog | Malicious install scripts, data exfiltration, crypto miners, typosquatting |
| 2 | Semgrep | Code vulnerabilities (1,000+ SAST rules) |
| 2 | Gitleaks | Hardcoded secrets in source files (false-positive filtered) |
| 2 | OSV-Scanner | Known CVEs in dependencies (OSV database) |
| 2 | Grype | Dependency vulnerability scan with severity grading |
| 3 | Quality signals | CI, tests, docs, lock files, TypeScript strict, workflow safety |

## Verdict

Every scan ends with one of three verdicts:

| Verdict | Meaning |
|---------|---------|
| **SAFE** | Scorecard > 6.0, no critical findings, clean dependency graph |
| **REVIEW NEEDED** | Moderate issues found — read warnings before installing |
| **DO NOT INSTALL** | Live secrets, malicious code, or critical CVEs detected |

## Requirements

- macOS: Homebrew (installed automatically if missing)
- Windows: Windows 10/11 with winget or Scoop
- GitHub CLI (`gh`) authenticated — run `gh auth login` once after install

## Scan history

Results saved to `~/.repo-scanner/scans/` as JSON. Interrupted scan state at `~/.repo-scanner/state/`.

## Note on installers

The macOS installer uses `curl | bash` to install Homebrew and Bun — the same method recommended in their official documentation. If you prefer, install those tools manually first and the script will skip them.

## Credits

- Security tools: see [CREDITS.md](CREDITS.md)
- v2 architecture inspired by [Kem](https://campfire.aura-intel.net) — his [kem-sec](https://github.com/aura-intel/kem-sec) tool and [research into deterministic Claude Code skills](https://campfire.aura-intel.net/blog/deterministic-skills) informed the false-positive filter, state persistence, and structured phase contracts
