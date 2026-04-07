// scanner/phases/phase4-aggregate.ts
import type { ScanState } from "../types.ts";

export function computeVerdict(state: ScanState): void {
  const { phase1, phase2, phase3 } = state;
  if (!phase1) return;

  let securityScore = phase1.scorecardScore;

  // Live secrets = DO NOT INSTALL
  if (phase1.secrets.length > 0) {
    state.verdict = "DO NOT INSTALL";
    state.criticalFindings.push(
      `${phase1.secrets.length} live/verified secret(s) detected by TruffleHog`
    );
    securityScore -= 3;
  }

  // Archived
  if (phase1.ghInfo.archived) {
    state.warnings.push("Repository is ARCHIVED — no longer maintained");
  }

  // Stale
  if (phase1.ghInfo.pushedAt) {
    const mo = (Date.now() - new Date(phase1.ghInfo.pushedAt).getTime()) / (1000 * 60 * 60 * 24 * 30);
    if (mo > 24) {
      state.warnings.push(`No commits in ${Math.round(mo)} months — likely abandoned`);
      securityScore -= 1;
    } else if (mo > 12) {
      state.warnings.push(`No commits in ${Math.round(mo)} months — possibly stale`);
    }
  }

  // No license
  if (!phase1.ghInfo.license) {
    state.warnings.push("No license — usage rights unclear (default: all rights reserved)");
  }

  // Low scorecard
  if (phase1.scorecardScore < 3.0) {
    state.warnings.push(`Very low OpenSSF Scorecard: ${phase1.scorecardScore}/10`);
  } else if (phase1.scorecardScore < 5.0) {
    state.warnings.push(`Low OpenSSF Scorecard: ${phase1.scorecardScore}/10`);
  }

  if (phase2) {
    // Malicious code
    if (phase2.guarddogFindings.length > 0) {
      state.verdict = "DO NOT INSTALL";
      phase2.guarddogFindings.forEach((f) => state.criticalFindings.push(f));
      securityScore -= 5;
    }

    // Semgrep high/critical
    const semgrepHigh = phase2.semgrepFindings.filter(
      (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
    );
    if (semgrepHigh.length > 10) {
      state.criticalFindings.push(`${semgrepHigh.length} high/critical SAST findings (Semgrep)`);
      securityScore -= 2;
    } else if (semgrepHigh.length > 0) {
      state.warnings.push(`${semgrepHigh.length} high/critical SAST issue(s) (Semgrep)`);
      securityScore -= Math.min(semgrepHigh.length * 0.5, 2);
    }

    // Gitleaks secrets
    if (phase2.gitleaksFindings.length > 0) {
      const filtered = phase2.gitleaksRawCount - phase2.gitleaksFindings.length;
      state.warnings.push(
        `${phase2.gitleaksFindings.length} potential secret(s) in source` +
        (filtered > 0 ? ` (${filtered} FP removed)` : "")
      );
      securityScore -= Math.min(phase2.gitleaksFindings.length, 2);
    }

    // CVEs — deduplicate by CVE ID across OSV + Grype
    const allVulns = [...phase2.osvVulns, ...phase2.grypeVulns];
    const seenCves = new Set<string>();
    const uniqueVulns = allVulns.filter((v) => {
      if (seenCves.has(v.cve)) return false;
      seenCves.add(v.cve);
      return true;
    });

    const critCves = uniqueVulns.filter((v) => v.severity === "CRITICAL");
    const highCves = uniqueVulns.filter((v) => v.severity === "HIGH");

    if (critCves.length > 0) {
      state.criticalFindings.push(
        `${critCves.length} critical CVE(s): ` +
        critCves.slice(0, 3).map((v) => v.cve).join(", ") +
        (critCves.length > 3 ? `... (+${critCves.length - 3} more)` : "")
      );
      securityScore -= 3;
    }
    if (highCves.length > 0) {
      state.warnings.push(`${highCves.length} high-severity CVE(s) in dependencies`);
      securityScore -= Math.min(highCves.length * 0.3, 2);
    }
    if (uniqueVulns.length > 0 && critCves.length === 0 && highCves.length === 0) {
      state.warnings.push(`${uniqueVulns.length} low/medium CVE(s) in dependencies`);
    }
  }

  state.securityScore = Math.max(0, Math.min(10, securityScore));
  state.maturityScore = phase3?.maturityScore ?? 0;

  // Final verdict
  if (state.verdict !== "DO NOT INSTALL") {
    if (state.criticalFindings.length > 0) {
      state.verdict = "DO NOT INSTALL";
    } else if (
      state.warnings.length > 4 ||
      phase1.scorecardScore < 3.0 ||
      state.securityScore < 3.0
    ) {
      state.verdict = "DO NOT INSTALL";
    } else if (
      state.warnings.length > 1 ||
      phase1.scorecardScore < 6.0 ||
      state.securityScore < 6.0
    ) {
      state.verdict = "REVIEW NEEDED";
    } else {
      state.verdict = "SAFE";
    }
  }
}
