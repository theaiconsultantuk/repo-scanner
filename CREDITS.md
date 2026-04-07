# Credits

This project orchestrates the following open-source security tools. All credit for the
actual security analysis goes to these projects and their contributors.

## Wrapped Tools

| Tool | Purpose | License | Repository |
|------|---------|---------|------------|
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | 18-point supply chain trust score | Apache-2.0 | github.com/ossf/scorecard |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Live/verified secret detection in git history | AGPL-3.0 | github.com/trufflesecurity/trufflehog |
| [GuardDog](https://github.com/DataDog/guarddog) | Malicious package detection (install scripts, exfil, miners) | Apache-2.0 | github.com/DataDog/guarddog |
| [Semgrep](https://github.com/semgrep/semgrep) | Static analysis / SAST (1,000+ rules) | LGPL-2.1 | github.com/semgrep/semgrep |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Hardcoded secrets in source files | MIT | github.com/gitleaks/gitleaks |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Known CVEs in dependencies (OSV database) | Apache-2.0 | github.com/google/osv-scanner |
| [Grype](https://github.com/anchore/grype) | Dependency vulnerability scanning with severity grading | Apache-2.0 | github.com/anchore/grype |
| [Syft](https://github.com/anchore/syft) | Software bill of materials (SBOM) generation | Apache-2.0 | github.com/anchore/syft |

## GitHub CLI

The GitHub API queries (stars, forks, license, activity) use the [GitHub CLI](https://github.com/cli/cli) (`gh`),
licensed under MIT by GitHub, Inc.

## Runtime

The scanner script runs on [Bun](https://github.com/oven-sh/bun), licensed under MIT.

---

## Architecture Inspiration

**[kem-sec](https://github.com/aura-intel/kem-sec)** by [Kem / aura-intel](https://campfire.aura-intel.net)
MIT License | [campfire.aura-intel.net/blog/deterministic-skills](https://campfire.aura-intel.net/blog/deterministic-skills)

Kem's kem-sec (148-check pre-launch audit for Claude Code projects) and his article *"You think Claude is using your skills but it's mostly pretending"* informed three v2 features:

1. **Gitleaks false-positive filter** (`scanner/lib/filter-fp.ts`) — discrete filtering step with explicit rules for test files, placeholder values, and env-var references, directly adapted from kem-sec's AI agent filter pattern
2. **State persistence** (`scanner/lib/state.ts`) — checkpoint/resume architecture so long scans survive interruption or `/clear`
3. **Structured phase contracts** (`scanner/types.ts`) — each phase returns a validated JSON schema, aggregated cleanly rather than passed as untyped text

If you scan your own code before shipping it, [kem-sec](https://github.com/aura-intel/kem-sec) is the complement to this tool.
