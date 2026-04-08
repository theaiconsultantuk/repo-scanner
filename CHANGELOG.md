# Changelog

## v2.1.0 — 2026-04-07

### New features

- **Plain-English finding explanations** — every critical and warning finding now shows a "Why it matters:" or "What this means:" sentence written for non-technical users. Covers TruffleHog verified secrets, GuardDog malware signals, shell-spawning scripts, CVE severity tiers, hardcoded secrets, low OpenSSF Scorecard, archived/abandoned repos, and more (16 patterns total)
- **Semgrep false-positive filter** — findings in `skills/`, `prompts/`, `templates/`, `workflows/`, `.yaml`, `.yml`, `.md`, `.txt` paths are stripped before scoring. Eliminates noise from repos that are skill/prompt collections where security rules fire on example code

---

## v2.0.0 — 2026-04-06

### New features

- **Phase 3: Code quality analysis** — 10 signals across CI/CD, testing, documentation, and dependency hygiene, producing a Maturity Score (0-10) alongside the existing Security Score
- **Project type detection** — automatically identifies npm library, Python package, CLI, Go, Rust, or web app and runs appropriate checks
- **Gitleaks false-positive filter** (`scanner/lib/filter-fp.ts`) — strips test fixtures, placeholder values, and env-var references before reporting, directly reducing noise (pattern from Kem's kem-sec)
- **State persistence** — scan state saved after each phase; interrupted scans resume with `--resume`
- **`--fresh` flag** — force a clean scan ignoring any saved checkpoint
- **Structured TypeScript types** — `types.ts` defines contracts for all phase outputs
- **Maturity score** — weighted 0-10 from quality signals (CI: HIGH, strict mode: MEDIUM, CHANGELOG: LOW, etc.)
- **kem-sec style ASCII display** — ━━ box format for phase headers and final report

### Changed

- Scanner split into `scanner/phases/` and `scanner/lib/` — single-file v1 `scan.ts` is replaced
- Scan archive directory: `~/.repo-scanner/scans/` (was `~/.claude/skills/repo-scanner/scans/`)
- State directory: `~/.repo-scanner/state/`
- `--deep` flag removed — Phase 3 quality analysis runs by default (use `--quick` to skip clone-based phases)

### Architecture credits

v2 architecture inspired by [Kem's kem-sec](https://github.com/aura-intel/kem-sec) and his article [*You think Claude is using your skills but it's mostly pretending*](https://campfire.aura-intel.net/blog/deterministic-skills).

---

## v1.0.0 — 2026-03-31

- Initial release
- 3-phase pipeline: remote trust signals, shallow clone SAST, verdict
- Tools: OpenSSF Scorecard, TruffleHog, GuardDog, Semgrep, Gitleaks, OSV-Scanner, Grype
- Mac/Windows one-command installers
- SAFE / REVIEW NEEDED / DO NOT INSTALL verdict
