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
