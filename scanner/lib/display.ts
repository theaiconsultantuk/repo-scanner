// scanner/lib/display.ts
import type { ScanState, Verdict } from "../types.ts";

// Plain-English translations of technical findings for non-technical users.
// Each entry: [regex to match the finding string, plain-English explanation]
const FINDING_TRANSLATIONS: Array<[RegExp, string]> = [
  // Critical
  [/live.+secret.+TruffleHog/i,
    "Real API keys or passwords were found in the code history. Anyone who knows could use them to access accounts or services."],
  [/malicious.+GuardDog|GuardDog.+malicious/i,
    "The install process tries to run hidden commands on your computer — a red flag for malware."],
  [/SHELLING_OUT|CMD_OVERWRITE/i,
    "This package runs system commands during install, which malicious software commonly does to take control of a machine."],
  [/EXFILTRATE|exfiltrat/i,
    "Code patterns suggest this may try to send your data (environment variables, credentials) to an external server."],
  [/DOWNLOAD_EXECUTABLE/i,
    "The install script downloads and runs an executable from the internet — a risk if that URL is ever compromised."],
  [/critical CVE/i,
    "One or more known security holes (CVEs) were found in the software this depends on. Attackers have documented ways to exploit these."],
  // Semgrep rule-specific
  [/spawn-shell-true|detect-child-process/i,
    "This code runs terminal/shell commands from within scripts (e.g. hook files). Not always dangerous, but it means code on your machine will be executing system commands — review what those scripts do before running them."],
  [/sql.injection|sqli/i,
    "The code constructs database queries in a way that could let attackers manipulate or steal data."],
  [/xss|cross.site.script/i,
    "The code outputs user-provided content without safety checks, which could let attackers inject malicious scripts."],
  [/hardcoded.password|hardcoded.secret/i,
    "A password or secret key appears to be written directly in the code rather than stored securely."],
  [/path.traversal/i,
    "The code may allow access to files outside its intended directory — a common way attackers read sensitive system files."],
  [/open.redirect/i,
    "Links in this app could be used to silently redirect users to malicious websites."],

  // Warnings
  [/high.+CVE|CVE.+high/i,
    "Some dependencies have known vulnerabilities that haven't been fixed yet."],
  [/low.+medium.+CVE|CVE.+low.+medium/i,
    "Minor known vulnerabilities exist in some dependencies — low risk but worth noting."],
  [/secret.+source|gitleaks/i,
    "Possible passwords or API keys found written directly in the source code."],
  [/low OpenSSF Scorecard|very low OpenSSF/i,
    "This repo doesn't follow standard security practices: things like requiring code review before merging, protecting the main branch, or signing releases. Common in solo/hobby projects but means less oversight."],
  [/ARCHIVED/i,
    "This project is no longer maintained. Security vulnerabilities found in the future won't be fixed."],
  [/abandoned|no commits in/i,
    "No updates for a long time. Bugs and security issues may go unpatched indefinitely."],
  [/no license/i,
    "Without a license, you technically don't have legal permission to use this software. Most commonly an oversight, but worth checking."],
  [/high.+CVE.+dependenc|Grype.*high/i,
    "The libraries this project uses have serious known security holes. These may or may not affect how you use it."],
];

function explain(finding: string): string | null {
  // Semgrep SAST count findings get a combined explanation
  if (/\d+\s+high.+SAST.*Semgrep/i.test(finding)) {
    return "The automated code scanner found patterns commonly associated with security vulnerabilities in the actual source files. This could be legitimate code (e.g. a tool that intentionally runs commands) or genuine issues — the details are in the JSON output.";
  }
  for (const [pattern, text] of FINDING_TRANSLATIONS) {
    if (pattern.test(finding) && text) return text;
  }
  return null;
}

export function box(title: string, lines: string[]): string {
  const width = 57;
  const bar = "━".repeat(width);
  const inner = lines.map((l) => `║  ${l}`).join("\n");
  return `\n\n${bar}\n║  ${title}\n${bar}\n${inner}\n${bar}\n`;
}

export function verdictLine(verdict: Verdict): string {
  const icons: Record<Verdict, string> = {
    SAFE: "✓  SAFE",
    "REVIEW NEEDED": "?  REVIEW NEEDED",
    "DO NOT INSTALL": "✗  DO NOT INSTALL",
  };
  return icons[verdict];
}

export function displayPhaseHeader(phase: string, detail: string): void {
  console.log(`\n${"━".repeat(57)}\n║  ${phase}\n║  ${detail}\n${"━".repeat(57)}`);
}

export function displayFinalReport(state: ScanState): void {
  const { phase1, phase3, verdict, criticalFindings, warnings, securityScore, maturityScore } = state;
  const p1 = phase1!;

  const lines: string[] = [
    `Repo:      ${state.owner}/${state.name}`,
    `Language:  ${p1.ghInfo.language ?? "?"}  |  License: ${p1.ghInfo.license ?? "NONE"}`,
    `Stars:     ${p1.ghInfo.stars}  |  Forks: ${p1.ghInfo.forks}`,
    `Last push: ${p1.ghInfo.pushedAt?.slice(0, 10) ?? "?"}${p1.ghInfo.archived ? "  [ARCHIVED]" : ""}`,
    `Type:      ${p1.projectType}`,
    ``,
    `Security Score:  ${securityScore.toFixed(1)}/10  (OpenSSF Scorecard basis)`,
    `Maturity Score:  ${maturityScore.toFixed(1)}/10  (code quality signals)`,
    ``,
  ];

  if (criticalFindings.length > 0) {
    lines.push("CRITICAL FINDINGS:");
    for (const f of criticalFindings) {
      lines.push(`  [✗] ${f}`);
      const why = explain(f);
      if (why) lines.push(`      Why it matters: ${why}`);
    }
    lines.push(``);
  }

  if (warnings.length > 0) {
    lines.push("WARNINGS:");
    for (const w of warnings) {
      lines.push(`  [!] ${w}`);
      const why = explain(w);
      if (why) lines.push(`      What this means: ${why}`);
    }
    lines.push(``);
  }

  if (phase3 && phase3.signals.length > 0) {
    const failed = phase3.signals.filter((s) => !s.passed);
    if (failed.length > 0) {
      lines.push("CODE QUALITY:");
      failed.forEach((s) => lines.push(`  [-] ${s.label}${s.detail ? ` — ${s.detail}` : ""}`));
      lines.push(``);
    }
  }

  if (criticalFindings.length === 0 && warnings.length === 0) {
    lines.push("No significant security issues found.");
    lines.push(``);
  }

  lines.push(`VERDICT:  ${verdictLine(verdict!)}`);

  console.log(box(`SCAN REPORT: ${state.owner}/${state.name}`, lines));
}
