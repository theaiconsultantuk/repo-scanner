# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | Yes       |

## Reporting a Vulnerability

If you discover a security issue in this project, please report it privately:

1. **Do not** open a public GitHub issue
2. Email: security@theaiconsultant.co.uk
3. Include: description, steps to reproduce, potential impact

You can expect an acknowledgement within 48 hours and a fix or mitigation plan within 14 days.

## Scope

This project is an orchestration wrapper around third-party security tools. Vulnerabilities
in the wrapped tools (scorecard, grype, gitleaks, trufflehog, semgrep, osv-scanner, guarddog, syft)
should be reported directly to those projects.

Vulnerabilities in this orchestration layer — e.g. command injection via crafted GitHub URLs,
path traversal in clone directories, or insecure handling of tool output — are in scope here.
