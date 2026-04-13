// scanner/phases/phase2-sast.ts
import { join } from "path";
import { tmpdir } from "os";
import { existsSync } from "fs";
import { runTool, safeParseJson } from "../lib/tools.ts";
import { filterGitleaksFindings, filterSemgrepFindings } from "../lib/filter-fp.ts";
import type { Phase2Result, SastFinding, VulnFinding, ProjectType } from "../types.ts";

const isJsonMode = () => process.argv.includes("--json");
const log = (msg: string) => {
  if (isJsonMode()) process.stderr.write(msg + "\n");
  else console.log(msg);
};

function mapSemgrepSeverity(s: string): SastFinding["severity"] {
  const m: Record<string, SastFinding["severity"]> = {
    ERROR: "HIGH", WARNING: "MEDIUM", INFO: "LOW",
  };
  return m[s.toUpperCase()] ?? "LOW";
}

function mapGrypeSeverity(s: string): VulnFinding["severity"] {
  const valid = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
  const up = s.toUpperCase() as any;
  return valid.includes(up) ? up : "LOW";
}

export async function runPhase2(
  owner: string,
  name: string,
  _projectType: ProjectType
): Promise<Phase2Result> {
  console.log(`\n${"━".repeat(57)}\n║  PHASE 2: SECURITY ANALYSIS\n║  Cloning at depth=1, then 5 tools in parallel\n${"━".repeat(57)}`);

  const scanDir = join(tmpdir(), `repo-scan-${owner}-${name}-${Date.now()}`); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  log(`  Cloning to ${scanDir}...`);

  const cloneResult = await runTool("git", [
    "git", "clone", "--depth=1",
    `https://github.com/${owner}/${name}.git`, scanDir,
  ], 90000);

  if (cloneResult.exitCode !== 0) {
    log(`  Clone failed: ${cloneResult.stderr.slice(0, 200)}`);
    return {
      guarddogFindings: ["Clone failed — SAST tools skipped"],
      semgrepFindings: [], gitleaksFindings: [], gitleaksRawCount: 0,
      osvVulns: [], grypeVulns: [], cloneDir: null,
    };
  }

  const hasPackageJson = existsSync(join(scanDir, "package.json")); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  const hasPyProject =
    existsSync(join(scanDir, "pyproject.toml")) || // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
    existsSync(join(scanDir, "requirements.txt")) || // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
    existsSync(join(scanDir, "setup.py")); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal

  const [guarddogR, semgrepR, gitleaksR, osvR, grypeR] = await Promise.all([
    (async () => {
      log("  [1/5] GuardDog (malicious install scripts, exfil, miners)...");
      if (hasPackageJson) {
        const pkg = safeParseJson(
          await Bun.file(join(scanDir, "package.json")).text().catch(() => "{}")
        );
        if (pkg?.name) {
          return runTool("guarddog", ["guarddog", "npm", "verify", pkg.name], 60000);
        }
      }
      const eco = hasPyProject ? "pypi" : "npm";
      return runTool("guarddog", ["guarddog", eco, "scan", scanDir], 60000);
    })(),
    (async () => {
      log("  [2/5] Semgrep (1,000+ SAST rules)...");
      return runTool("semgrep", [
        "semgrep", "scan", "--config=auto", "--json", "--quiet", scanDir,
      ], 180000);
    })(),
    (async () => {
      log("  [3/5] Gitleaks (hardcoded secrets in source)...");
      const reportPath = join(tmpdir(), `gitleaks-${owner}-${name}.json`); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
      await runTool("gitleaks", [
        "gitleaks", "detect", `--source=${scanDir}`,
        "--report-format=json", `--report-path=${reportPath}`,
        "--no-git",
      ], 60000);
      const file = Bun.file(reportPath);
      if (await file.exists()) {
        return { stdout: await file.text(), stderr: "", exitCode: 0 };
      }
      return { stdout: "[]", stderr: "", exitCode: 0 };
    })(),
    (async () => {
      log("  [4/5] OSV-Scanner (dependency CVEs)...");
      return runTool("osv-scanner", [
        "osv-scanner", "scan", "-r", scanDir, "--format=json",
      ], 90000);
    })(),
    (async () => {
      log("  [5/5] Grype (vulnerability severity grading)...");
      return runTool("grype", ["grype", `dir:${scanDir}`, "-o", "json"], 120000);
    })(),
  ]);

  // GuardDog: look for specific rule names in output
  const guarddogFindings: string[] = [];
  const gdText = guarddogR.stdout + guarddogR.stderr;
  const suspiciousRules = ["CMD_OVERWRITE", "OBFUSCATED_SETUP", "EXFILTRATE_SENSITIVE_DATA", "SHELLING_OUT", "DOWNLOAD_EXECUTABLE"];
  for (const rule of suspiciousRules) {
    if (gdText.includes(rule)) guarddogFindings.push(`GuardDog: ${rule}`);
  }
  if (
    gdText.toLowerCase().includes("malicious") &&
    !gdText.match(/0 potentially malicious/i) &&
    guarddogFindings.length === 0
  ) {
    guarddogFindings.push("GuardDog: potentially malicious patterns detected");
  }

  // Semgrep + FP filter (strips findings in docs, skills, prompts, YAML, markdown)
  const semgrepData = safeParseJson(semgrepR.stdout);
  const semgrepRaw: SastFinding[] = (semgrepData?.results ?? []).map((r: any) => ({
    tool: "semgrep",
    severity: mapSemgrepSeverity(r.extra?.severity ?? "INFO"),
    file: (r.path ?? "").replace(scanDir + "/", ""),
    line: r.start?.line,
    message: r.extra?.message ?? r.check_id ?? "unknown",
    ruleId: r.check_id,
  }));
  const { findings: semgrepFindings, removedCount: semgrepFpRemoved } = filterSemgrepFindings(semgrepRaw);
  if (semgrepFpRemoved > 0) {
    log(`  Semgrep FP: ${semgrepRaw.length} raw → ${semgrepFindings.length} after filter (${semgrepFpRemoved} in docs/skills/yaml removed)`);
  }

  // Gitleaks + FP filter
  const rawGitleaks = safeParseJson(gitleaksR.stdout) ?? [];
  const rawArr = Array.isArray(rawGitleaks) ? rawGitleaks : [];
  const { findings: gitleaksFindings, removedCount } = filterGitleaksFindings(rawArr);
  log(`  Gitleaks: ${rawArr.length} raw → ${gitleaksFindings.length} after FP filter (${removedCount} removed)`);

  // OSV
  const osvData = safeParseJson(osvR.stdout);
  const osvVulns: VulnFinding[] = (osvData?.results ?? [])
    .flatMap((r: any) => r.packages ?? [])
    .flatMap((p: any) =>
      (p.vulnerabilities ?? []).map((v: any) => ({
        pkg: p.package?.name ?? "unknown",
        version: p.package?.version ?? "?",
        cve: v.id ?? "?",
        severity: mapGrypeSeverity(v.database_specific?.severity ?? "LOW"),
        fixVersion: v.affected?.[0]?.ranges?.[0]?.events
          ?.find((e: any) => e.fixed)?.fixed ?? null,
      }))
    );

  // Grype
  const grypeData = safeParseJson(grypeR.stdout);
  const grypeVulns: VulnFinding[] = (grypeData?.matches ?? []).map((m: any) => ({
    pkg: m.artifact?.name ?? "unknown",
    version: m.artifact?.version ?? "?",
    cve: m.vulnerability?.id ?? "?",
    severity: mapGrypeSeverity(m.vulnerability?.severity ?? "Low"),
    fixVersion: m.vulnerability?.fix?.versions?.[0] ?? null,
  }));

  // Cleanup
  await runTool("rm", ["rm", "-rf", scanDir], 30000);

  log(`  Semgrep:  ${semgrepFindings.filter(f => f.severity === "HIGH" || f.severity === "CRITICAL").length} high/critical (${semgrepRaw.length} raw)`);
  log(`  OSV:      ${osvVulns.length} vulnerabilities`);
  log(`  Grype:    ${grypeVulns.filter(v => v.severity === "CRITICAL" || v.severity === "HIGH").length} high/critical`);

  return {
    guarddogFindings,
    semgrepFindings,
    gitleaksFindings,
    gitleaksRawCount: rawArr.length,
    osvVulns,
    grypeVulns,
    cloneDir: null,
  };
}
