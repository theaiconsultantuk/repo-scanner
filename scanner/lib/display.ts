// scanner/lib/display.ts
import type { ScanState, Verdict } from "../types.ts";

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
    lines.push("CRITICAL:");
    criticalFindings.forEach((f) => lines.push(`  [✗] ${f}`));
    lines.push(``);
  }

  if (warnings.length > 0) {
    lines.push("WARNINGS:");
    warnings.forEach((w) => lines.push(`  [!] ${w}`));
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
