#!/usr/bin/env bun
/**
 * repo-scanner — Pre-install GitHub repository security scanner
 * Orchestrates multiple security tools into a unified scan pipeline.
 *
 * Usage:
 *   bun ~/.claude/skills/repo-scanner/scan.ts <github-url> [--quick] [--deep] [--json]
 */

import { $ } from "bun";
import { mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir, tmpdir } from "os";

const SCANS_DIR = join(homedir(), ".claude/skills/repo-scanner/scans");
mkdirSync(SCANS_DIR, { recursive: true });

// When --json, progress goes to stderr so stdout is clean JSON
const isJsonMode = process.argv.includes("--json");
function log(msg: string): void {
  if (isJsonMode) {
    process.stderr.write(msg + "\n");
  } else {
    console.log(msg);
  }
}

interface ScanResult {
  repo: string;
  owner: string;
  name: string;
  timestamp: string;
  phase1: {
    scorecard: any;
    scorecardScore: number;
    secrets: any[];
    ghInfo: any;
  };
  phase2?: {
    guarddog: any;
    semgrep: any;
    gitleaks: any;
    osv: any;
    grype: any;
    sbom: any;
  };
  verdict: "SAFE" | "REVIEW NEEDED" | "DO NOT INSTALL";
  reasons: string[];
  criticalFindings: string[];
  warnings: string[];
}

function parseGithubUrl(input: string): { owner: string; name: string } {
  // Handle: https://github.com/owner/repo, github.com/owner/repo, owner/repo
  const cleaned = input.replace(/\.git$/, "").replace(/\/$/, "");
  const match = cleaned.match(/(?:github\.com\/)?([^\/]+)\/([^\/]+)$/);
  if (!match) throw new Error(`Cannot parse GitHub URL: ${input}`);
  return { owner: match[1], name: match[2] };
}

async function runTool(name: string, args: string[], timeoutMs: number = 60000): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const proc = Bun.spawn(args, { stdout: "pipe", stderr: "pipe", env: { ...process.env } });

    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => {
        proc.kill();
        reject(new Error(`${name} timed out after ${timeoutMs / 1000}s`));
      }, timeoutMs)
    );

    const result = Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);

    const [stdout, stderr, exitCode] = await Promise.race([result, timeout]) as [string, string, number];
    return { stdout, stderr, exitCode };
  } catch (error: any) {
    return { stdout: "", stderr: error.message, exitCode: 1 };
  }
}

async function checkTool(name: string): Promise<boolean> {
  const result = await runTool(name, [name, "--version"]);
  return result.exitCode === 0;
}

// Phase 1: Remote analysis
async function phase1(owner: string, name: string): Promise<ScanResult["phase1"]> {
  log("\n--- Phase 1: Remote Analysis (no clone) ---\n");

  // Run all Phase 1 checks in parallel
  const [scorecardResult, trufflehogResult, ghResult] = await Promise.all([
    (async () => {
      log("  Running OpenSSF Scorecard...");
      return runTool("scorecard", [
        "scorecard", `--repo=github.com/${owner}/${name}`, "--format=json",
      ], 90000);
    })(),
    (async () => {
      log("  Running TruffleHog (remote secret scan)...");
      return runTool("trufflehog", [
        "trufflehog", "git", `https://github.com/${owner}/${name}`,
        "--json", "--only-verified", "--no-update",
      ], 90000);
    })(),
    (async () => {
      log("  Querying GitHub API...");
      return runTool("gh", [
        "gh", "api", `repos/${owner}/${name}`,
        "--jq", `{stars: .stargazers_count, forks: .forks_count, open_issues: .open_issues_count, license: .license.spdx_id, pushed_at: .pushed_at, archived: .archived, topics: .topics, language: .language}`,
      ]);
    })(),
  ]);

  let scorecard: any = {};
  let scorecardScore = 0;
  try {
    scorecard = JSON.parse(scorecardResult.stdout);
    scorecardScore = scorecard.score ?? scorecard.aggregate_score ?? 0;
  } catch { /* parse failed */ }

  const secrets = trufflehogResult.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => { try { return JSON.parse(line); } catch { return null; } })
    .filter(Boolean);

  let ghInfo: any = {};
  try { ghInfo = JSON.parse(ghResult.stdout); } catch { /* parse failed */ }

  // Display Phase 1 results
  log(`\n  Scorecard: ${scorecardScore}/10`);
  log(`  Stars: ${ghInfo.stars ?? "?"} | Forks: ${ghInfo.forks ?? "?"}`);
  log(`  License: ${ghInfo.license ?? "NONE"}`);
  log(`  Last push: ${ghInfo.pushed_at ?? "?"}`);
  log(`  Archived: ${ghInfo.archived ?? false}`);
  log(`  Live secrets found: ${secrets.length}`);

  return { scorecard, scorecardScore, secrets, ghInfo };
}

// Phase 2: Clone and scan
async function phase2(owner: string, name: string): Promise<ScanResult["phase2"]> {
  log("\n--- Phase 2: Shallow Clone + Static Analysis ---\n");

  const scanDir = join(tmpdir(), `repo-scan-${owner}-${name}-${Date.now()}`);
  log(`  Cloning to ${scanDir}...`);

  const cloneResult = await runTool("git", [
    "git", "clone", "--depth=1", `https://github.com/${owner}/${name}.git`, scanDir,
  ]);

  if (cloneResult.exitCode !== 0) {
    console.error("  Clone failed:", cloneResult.stderr);
    return undefined;
  }

  // Run all Phase 2 tools in parallel
  const [guarddogResult, semgrepResult, gitleaksResult, osvResult, grypeResult] = await Promise.all([
    (async () => {
      log("  Running GuardDog...");
      // Detect ecosystem from package files
      const hasPackageJson = existsSync(join(scanDir, "package.json"));
      const hasRequirements = existsSync(join(scanDir, "requirements.txt")) || existsSync(join(scanDir, "setup.py"));
      const eco = hasPackageJson ? "npm" : hasRequirements ? "pypi" : "npm";
      return runTool("guarddog", ["guarddog", eco, "scan", scanDir]);
    })(),
    (async () => {
      log("  Running Semgrep...");
      return runTool("semgrep", ["semgrep", "scan", "--config=auto", "--json", "--quiet", scanDir]);
    })(),
    (async () => {
      log("  Running Gitleaks...");
      return runTool("gitleaks", [
        "gitleaks", "detect", `--source=${scanDir}`, "--report-format=json",
        `--report-path=${join(tmpdir(), "gitleaks-report.json")}`,
      ]);
    })(),
    (async () => {
      log("  Running OSV-Scanner...");
      return runTool("osv-scanner", ["osv-scanner", "scan", "-r", scanDir, "--format=json"]);
    })(),
    (async () => {
      log("  Running Grype...");
      return runTool("grype", ["grype", `dir:${scanDir}`, "-o", "json"]);
    })(),
  ]);

  // Parse results
  const parse = (r: { stdout: string }) => { try { return JSON.parse(r.stdout); } catch { return null; } };

  // Cleanup clone
  await runTool("rm", ["rm", "-rf", scanDir]);

  return {
    guarddog: guarddogResult.stdout || guarddogResult.stderr,
    semgrep: parse(semgrepResult),
    gitleaks: parse(gitleaksResult) ?? gitleaksResult.stdout,
    osv: parse(osvResult),
    grype: parse(grypeResult),
    sbom: null, // Skip SBOM for speed; Grype covers deps
  };
}

// Determine verdict
function computeVerdict(result: ScanResult): void {
  const { phase1, phase2 } = result;

  // Critical: live secrets
  if (phase1.secrets.length > 0) {
    result.verdict = "DO NOT INSTALL";
    result.criticalFindings.push(`${phase1.secrets.length} live secret(s) detected by TruffleHog`);
  }

  // Critical: archived + old
  if (phase1.ghInfo.archived) {
    result.warnings.push("Repository is ARCHIVED");
  }

  // Scorecard-based
  if (phase1.scorecardScore < 4.0) {
    result.warnings.push(`Low Scorecard trust score: ${phase1.scorecardScore}/10`);
  }

  // Last push age
  if (phase1.ghInfo.pushed_at) {
    const monthsAgo = (Date.now() - new Date(phase1.ghInfo.pushed_at).getTime()) / (1000 * 60 * 60 * 24 * 30);
    if (monthsAgo > 12) {
      result.warnings.push(`No commits in ${Math.round(monthsAgo)} months (potentially abandoned)`);
    }
  }

  // No license
  if (!phase1.ghInfo.license) {
    result.warnings.push("No license detected");
  }

  if (phase2) {
    // GuardDog findings — check for actual detections, not the word "malicious" in "0 potentially malicious"
    if (typeof phase2.guarddog === "string" &&
        phase2.guarddog.includes("malicious") &&
        !phase2.guarddog.match(/Found 0 potentially malicious/)) {
      result.verdict = "DO NOT INSTALL";
      result.criticalFindings.push("GuardDog detected malicious code patterns");
    }

    // Semgrep high/critical
    if (phase2.semgrep?.results) {
      const high = phase2.semgrep.results.filter((r: any) =>
        r.extra?.severity === "ERROR" || r.extra?.severity === "WARNING"
      );
      if (high.length > 0) {
        result.warnings.push(`Semgrep: ${high.length} high/warning issue(s)`);
      }
    }

    // OSV critical CVEs
    if (phase2.osv?.results) {
      const vulns = phase2.osv.results.flatMap((r: any) => r.packages?.flatMap((p: any) => p.vulnerabilities) ?? []);
      const critical = vulns.filter((v: any) =>
        v?.database_specific?.severity === "CRITICAL" ||
        v?.database_specific?.cvss_score >= 9.0
      );
      if (critical.length > 0) {
        result.criticalFindings.push(`${critical.length} critical CVE(s) in dependencies`);
      }
      if (vulns.length > 0) {
        result.warnings.push(`${vulns.length} known vulnerability/ies in dependencies`);
      }
    }

    // Grype high/critical
    if (phase2.grype?.matches) {
      const critGrype = phase2.grype.matches.filter((m: any) =>
        m.vulnerability?.severity === "Critical" || m.vulnerability?.severity === "High"
      );
      if (critGrype.length > 0) {
        result.warnings.push(`Grype: ${critGrype.length} high/critical vulnerability/ies`);
      }
    }

    // Gitleaks
    if (Array.isArray(phase2.gitleaks) && phase2.gitleaks.length > 0) {
      result.warnings.push(`${phase2.gitleaks.length} potential secret(s) in source code`);
    }
  }

  // Final verdict if not already set to DO NOT INSTALL
  if (result.verdict !== "DO NOT INSTALL") {
    if (result.criticalFindings.length > 0) {
      result.verdict = "DO NOT INSTALL";
    } else if (result.warnings.length > 3 || phase1.scorecardScore < 4.0) {
      result.verdict = "REVIEW NEEDED";
    } else if (phase1.scorecardScore >= 6.0 && result.warnings.length <= 1) {
      result.verdict = "SAFE";
    } else {
      result.verdict = "REVIEW NEEDED";
    }
  }

  result.reasons = [
    ...result.criticalFindings.map((f) => `CRITICAL: ${f}`),
    ...result.warnings,
  ];
}

// Display report
function displayReport(result: ScanResult): void {
  const { phase1 } = result;

  console.log("\n" + "=".repeat(60));
  console.log(`SECURITY SCAN: ${result.owner}/${result.name}`);
  console.log("=".repeat(60));

  console.log(`\nTrust Score: ${phase1.scorecardScore}/10 (OpenSSF Scorecard)`);
  console.log(`Stars: ${phase1.ghInfo.stars ?? "?"} | Forks: ${phase1.ghInfo.forks ?? "?"}`);
  console.log(`License: ${phase1.ghInfo.license ?? "NONE"}`);
  console.log(`Last push: ${phase1.ghInfo.pushed_at ?? "?"}`);
  console.log(`Language: ${phase1.ghInfo.language ?? "?"}`);

  if (result.criticalFindings.length > 0) {
    console.log("\nCRITICAL FINDINGS:");
    result.criticalFindings.forEach((f) => console.log(`  [X] ${f}`));
  }

  if (result.warnings.length > 0) {
    console.log("\nWARNINGS:");
    result.warnings.forEach((w) => console.log(`  [!] ${w}`));
  }

  if (result.criticalFindings.length === 0 && result.warnings.length === 0) {
    console.log("\nNo significant issues found.");
  }

  console.log("\n" + "-".repeat(60));
  const icon = result.verdict === "SAFE" ? "OK" : result.verdict === "REVIEW NEEDED" ? "??" : "XX";
  console.log(`VERDICT: [${icon}] ${result.verdict}`);
  console.log("-".repeat(60));
}

// Main
async function main() {
  const args = process.argv.slice(2);
  const url = args.find((a) => !a.startsWith("--"));
  const quick = args.includes("--quick");
  const jsonOutput = args.includes("--json");

  if (!url) {
    console.log("Usage: bun scan.ts <github-url> [--quick] [--deep] [--json]");
    console.log("\n  --quick   Phase 1 only (remote, no clone)");
    console.log("  --deep    All phases + custom Semgrep rules");
    console.log("  --json    Output results as JSON");
    process.exit(1);
  }

  const { owner, name } = parseGithubUrl(url);
  log(`\nScanning: github.com/${owner}/${name}`);

  // Ensure GITHUB_TOKEN is set (scorecard needs it; gh has keyring auth)
  if (!process.env.GITHUB_TOKEN) {
    try {
      const ghProc = Bun.spawn(["gh", "auth", "token"], { stdout: "pipe", stderr: "pipe" });
      const token = (await new Response(ghProc.stdout).text()).trim();
      if (token) {
        process.env.GITHUB_TOKEN = token;
        log("  Set GITHUB_TOKEN from gh auth");
      }
    } catch { /* gh not available */ }
  }

  const result: ScanResult = {
    repo: `${owner}/${name}`,
    owner,
    name,
    timestamp: new Date().toISOString(),
    phase1: { scorecard: {}, scorecardScore: 0, secrets: [], ghInfo: {} },
    verdict: "REVIEW NEEDED",
    reasons: [],
    criticalFindings: [],
    warnings: [],
  };

  // Phase 1
  result.phase1 = await phase1(owner, name);

  // Phase 2 (unless --quick)
  if (!quick) {
    result.phase2 = await phase2(owner, name);
  }

  // Compute verdict
  computeVerdict(result);

  // Output
  if (jsonOutput) {
    // Write JSON to stdout cleanly (all progress already went to stderr)
    process.stdout.write(JSON.stringify(result));
  } else {
    displayReport(result);
  }

  // Save scan result
  const scanFile = join(SCANS_DIR, `${owner}-${name}-${new Date().toISOString().slice(0, 10)}.json`);
  await Bun.write(scanFile, JSON.stringify(result, null, 2));
  log(`\nScan saved: ${scanFile}`);
}

main().catch((err) => {
  console.error("Scan failed:", err.message);
  process.exit(1);
});
