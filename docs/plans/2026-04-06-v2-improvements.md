# Repo Scanner v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade github-repo-scanner from a sequential 2-phase security tool to a structured 4-phase scanner with code quality analysis, AI false-positive filtering, state persistence, a maturity score, and improved display — all informed by lessons from Kem's kem-sec tool.

**Architecture:** Four phases run in sequence: remote trust signals (parallel, no clone), shallow clone + security SAST (parallel), code quality signals (parallel), then an aggregation + verdict phase. Each phase writes structured JSON with a defined contract. A lightweight AI false-positive filter runs after gitleaks to reduce noise. State is checkpointed after each phase so long scans can be interrupted and resumed.

**Tech Stack:** Bun, TypeScript, existing CLI tools (scorecard, trufflehog, gitleaks, guarddog, semgrep, osv-scanner, grype), GitHub CLI, standard fs/path/os modules.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `scanner/scan.ts` | Rewrite | Main orchestrator — 4 phases, state, display |
| `scanner/types.ts` | Create | Shared TypeScript interfaces for all phases |
| `scanner/phases/phase1-remote.ts` | Create | Remote trust signals (no clone) |
| `scanner/phases/phase2-sast.ts` | Create | Clone + security SAST tools |
| `scanner/phases/phase3-quality.ts` | Create | Code quality signals |
| `scanner/phases/phase4-aggregate.ts` | Create | Merge, score, verdict |
| `scanner/lib/filter-fp.ts` | Create | AI false-positive filter for gitleaks |
| `scanner/lib/display.ts` | Create | ASCII box display (kem-sec style) |
| `scanner/lib/state.ts` | Create | Checkpoint read/write |
| `scanner/lib/tools.ts` | Create | runTool, checkTool, parseGithubUrl helpers |
| `README.md` | Update | v2 features, Kem attribution, new phase diagram |
| `CREDITS.md` | Update | Add Kem + kem-sec attribution |
| `CHANGELOG.md` | Create | Version history |

---

## Task 1: Shared types and helpers

**Files:**
- Create: `scanner/types.ts`
- Create: `scanner/lib/tools.ts`
- Create: `scanner/lib/state.ts`
- Create: `scanner/lib/display.ts`

- [ ] **Step 1: Create `scanner/types.ts`**

```typescript
// scanner/types.ts

export type Verdict = "SAFE" | "REVIEW NEEDED" | "DO NOT INSTALL";
export type ProjectType = "npm-library" | "python-package" | "cli" | "web-app" | "go" | "rust" | "unknown";

export interface Phase1Result {
  scorecardScore: number;
  scorecardChecks: Record<string, number>;
  secrets: VerifiedSecret[];
  ghInfo: GhInfo;
  projectType: ProjectType;
}

export interface VerifiedSecret {
  detector: string;
  file?: string;
  line?: number;
  raw?: string;
}

export interface GhInfo {
  stars: number;
  forks: number;
  openIssues: number;
  license: string | null;
  pushedAt: string;
  archived: boolean;
  topics: string[];
  language: string | null;
  hasWiki: boolean;
  hasDiscussions: boolean;
}

export interface SastFinding {
  tool: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  file: string;
  line?: number;
  message: string;
  ruleId?: string;
}

export interface Phase2Result {
  guarddogFindings: string[];
  semgrepFindings: SastFinding[];
  gitleaksFindings: SastFinding[]; // after false-positive filter
  gitleaksRawCount: number;
  osvVulns: VulnFinding[];
  grypeVulns: VulnFinding[];
  cloneDir: string | null;
}

export interface VulnFinding {
  pkg: string;
  version: string;
  cve: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  fixVersion: string | null;
}

export interface QualitySignal {
  id: string;
  label: string;
  passed: boolean;
  severity: "HIGH" | "MEDIUM" | "LOW";
  detail?: string;
}

export interface Phase3Result {
  signals: QualitySignal[];
  maturityScore: number; // 0-10
}

export interface ScanState {
  repo: string;
  owner: string;
  name: string;
  timestamp: string;
  phase1?: Phase1Result;
  phase2?: Phase2Result;
  phase3?: Phase3Result;
  verdict?: Verdict;
  verdictReasons: string[];
  criticalFindings: string[];
  warnings: string[];
  maturityScore: number;
  securityScore: number;
}
```

- [ ] **Step 2: Create `scanner/lib/tools.ts`**

```typescript
// scanner/lib/tools.ts

export async function runTool(
  name: string,
  args: string[],
  timeoutMs: number = 60000
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  try {
    const proc = Bun.spawn(args, {
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env },
    });

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

    const [stdout, stderr, exitCode] = (await Promise.race([
      result,
      timeout,
    ])) as [string, string, number];
    return { stdout, stderr, exitCode };
  } catch (error: any) {
    return { stdout: "", stderr: error.message, exitCode: 1 };
  }
}

export async function checkTool(name: string): Promise<boolean> {
  const r = await runTool(name, ["which", name], 5000);
  return r.exitCode === 0;
}

export function parseGithubUrl(input: string): { owner: string; name: string } {
  const cleaned = input.replace(/\.git$/, "").replace(/\/$/, "");
  const match = cleaned.match(/(?:github\.com\/)?([^\/]+)\/([^\/]+)$/);
  if (!match) throw new Error(`Cannot parse GitHub URL: ${input}`);
  return { owner: match[1], name: match[2] };
}

export function safeParseJson(text: string): any {
  try { return JSON.parse(text); } catch { return null; }
}

export function monthsAgo(dateStr: string): number {
  return (Date.now() - new Date(dateStr).getTime()) / (1000 * 60 * 60 * 24 * 30);
}
```

- [ ] **Step 3: Create `scanner/lib/state.ts`**

```typescript
// scanner/lib/state.ts
import { join } from "path";
import { homedir } from "os";
import { mkdirSync } from "fs";
import type { ScanState } from "../types.ts";

const STATE_DIR = join(homedir(), ".repo-scanner", "state");
mkdirSync(STATE_DIR, { recursive: true });

export function stateFile(owner: string, name: string): string {
  return join(STATE_DIR, `${owner}-${name}.json`);
}

export function loadState(owner: string, name: string): ScanState | null {
  const file = Bun.file(stateFile(owner, name));
  if (!file.size) return null;
  try {
    return JSON.parse(file.stream ? "" : "") as ScanState;
  } catch { return null; }
}

export async function saveState(state: ScanState): Promise<void> {
  const path = stateFile(state.owner, state.name);
  await Bun.write(path, JSON.stringify(state, null, 2));
}

export async function clearState(owner: string, name: string): Promise<void> {
  const { unlink } = await import("fs/promises");
  try { await unlink(stateFile(owner, name)); } catch {}
}

export async function loadStateAsync(owner: string, name: string): Promise<ScanState | null> {
  const path = stateFile(owner, name);
  const file = Bun.file(path);
  const exists = await file.exists();
  if (!exists) return null;
  try { return safeParseJson(await file.text()) as ScanState; } catch { return null; }
}

function safeParseJson(text: string): any {
  try { return JSON.parse(text); } catch { return null; }
}
```

- [ ] **Step 4: Create `scanner/lib/display.ts`**

```typescript
// scanner/lib/display.ts
import type { ScanState, Verdict } from "../types.ts";

export function box(title: string, lines: string[]): string {
  const width = 55;
  const bar = "━".repeat(width);
  const inner = lines.map((l) => `║  ${l}`).join("\n");
  return `\n\n${bar}\n║  ${title}\n${bar}\n${inner}\n${bar}\n\n`;
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
  console.log(box(phase, [detail]));
}

export function displayFinalReport(state: ScanState): void {
  const { phase1, phase3, verdict, criticalFindings, warnings, securityScore, maturityScore } = state;
  const p1 = phase1!;

  const lines: string[] = [
    `Repo:      ${state.owner}/${state.name}`,
    `Language:  ${p1.ghInfo.language ?? "?"}  |  License: ${p1.ghInfo.license ?? "NONE"}`,
    `Stars:     ${p1.ghInfo.stars}  |  Forks: ${p1.ghInfo.forks}`,
    `Last push: ${p1.ghInfo.pushedAt?.slice(0, 10) ?? "?"}${p1.ghInfo.archived ? "  [ARCHIVED]" : ""}`,
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
      failed.forEach((s) => lines.push(`  [!] ${s.label}${s.detail ? ` — ${s.detail}` : ""}`));
      lines.push(``);
    }
  }

  if (criticalFindings.length === 0 && warnings.length === 0) {
    lines.push("No significant issues found.");
    lines.push(``);
  }

  lines.push(`VERDICT:  ${verdictLine(verdict!)}`);

  console.log(box(`SCAN REPORT: ${state.owner}/${state.name}`, lines));
}
```

- [ ] **Step 5: Commit skeleton**

```bash
cd /tmp/github-repo-scanner-v2
git add scanner/types.ts scanner/lib/tools.ts scanner/lib/state.ts scanner/lib/display.ts
git commit -m "feat(v2): add types, shared libs (tools, state, display)"
```

---

## Task 2: Phase 1 — Remote trust signals

**Files:**
- Create: `scanner/phases/phase1-remote.ts`

- [ ] **Step 1: Create `scanner/phases/phase1-remote.ts`**

```typescript
// scanner/phases/phase1-remote.ts
import { runTool, safeParseJson, monthsAgo } from "../lib/tools.ts";
import type { Phase1Result, GhInfo, VerifiedSecret, ProjectType } from "../types.ts";

function isJsonMode() { return process.argv.includes("--json"); }
function log(msg: string) {
  if (isJsonMode()) process.stderr.write(msg + "\n");
  else console.log(msg);
}

function detectProjectType(ghInfo: GhInfo, topics: string[]): ProjectType {
  const lang = (ghInfo.language ?? "").toLowerCase();
  const t = topics.map((x) => x.toLowerCase()).join(" ");
  if (lang === "python" || t.includes("pypi")) return "python-package";
  if (lang === "go") return "go";
  if (lang === "rust") return "rust";
  if (t.includes("web") || t.includes("react") || t.includes("nextjs") || t.includes("vue")) return "web-app";
  if (t.includes("cli") || t.includes("command-line")) return "cli";
  if (lang === "javascript" || lang === "typescript") return "npm-library";
  return "unknown";
}

export async function runPhase1(owner: string, name: string): Promise<Phase1Result> {
  log(box("PHASE 1: REMOTE TRUST SIGNALS", "Running in parallel — no clone required"));

  const [scorecardResult, trufflehogResult, ghResult] = await Promise.all([
    (async () => {
      log("  [1/3] OpenSSF Scorecard (18 trust checks)...");
      return runTool("scorecard", [
        "scorecard", `--repo=github.com/${owner}/${name}`, "--format=json",
      ], 120000);
    })(),
    (async () => {
      log("  [2/3] TruffleHog (verified secrets in history)...");
      return runTool("trufflehog", [
        "trufflehog", "git", `https://github.com/${owner}/${name}`,
        "--json", "--only-verified", "--no-update",
      ], 120000);
    })(),
    (async () => {
      log("  [3/3] GitHub API (metadata, activity, license)...");
      return runTool("gh", [
        "gh", "api", `repos/${owner}/${name}`,
        "--jq", `{stars: .stargazers_count, forks: .forks_count, openIssues: .open_issues_count, license: .license.spdx_id, pushedAt: .pushed_at, archived: .archived, topics: .topics, language: .language, hasWiki: .has_wiki, hasDiscussions: .has_discussions}`,
      ], 30000);
    })(),
  ]);

  // Parse scorecard
  let scorecardScore = 0;
  let scorecardChecks: Record<string, number> = {};
  const sc = safeParseJson(scorecardResult.stdout);
  if (sc) {
    scorecardScore = sc.score ?? sc.aggregate_score ?? 0;
    if (sc.checks) {
      for (const c of sc.checks) {
        scorecardChecks[c.name] = c.score;
      }
    }
  }

  // Parse TruffleHog secrets
  const secrets: VerifiedSecret[] = trufflehogResult.stdout
    .split("\n")
    .filter(Boolean)
    .map((line) => safeParseJson(line))
    .filter(Boolean)
    .map((s: any) => ({
      detector: s.DetectorName ?? s.detector_name ?? "unknown",
      file: s.SourceMetadata?.Data?.Git?.file,
      line: s.SourceMetadata?.Data?.Git?.line,
    }));

  // Parse GitHub info
  const ghInfo: GhInfo = safeParseJson(ghResult.stdout) ?? {
    stars: 0, forks: 0, openIssues: 0, license: null,
    pushedAt: "", archived: false, topics: [], language: null,
    hasWiki: false, hasDiscussions: false,
  };

  const projectType = detectProjectType(ghInfo, ghInfo.topics);

  log(`\n  Scorecard:    ${scorecardScore}/10`);
  log(`  Stars:        ${ghInfo.stars} | Forks: ${ghInfo.forks}`);
  log(`  License:      ${ghInfo.license ?? "NONE"}`);
  log(`  Last push:    ${ghInfo.pushedAt?.slice(0, 10) ?? "?"}`);
  log(`  Project type: ${projectType}`);
  log(`  Live secrets: ${secrets.length}`);

  return { scorecardScore, scorecardChecks, secrets, ghInfo, projectType };
}

function box(title: string, detail: string): string {
  return `\n${"━".repeat(55)}\n║  ${title}\n║  ${detail}\n${"━".repeat(55)}`;
}
```

- [ ] **Step 2: Commit**

```bash
cd /tmp/github-repo-scanner-v2
git add scanner/phases/phase1-remote.ts
git commit -m "feat(v2): phase 1 — parallel remote trust signals with project type detection"
```

---

## Task 3: False-positive filter for gitleaks

**Files:**
- Create: `scanner/lib/filter-fp.ts`

This is a discrete in-process filter (not a sub-agent, since we don't have the Task tool), applying the same logic kem-sec uses in its AI agent filter.

- [ ] **Step 1: Create `scanner/lib/filter-fp.ts`**

```typescript
// scanner/lib/filter-fp.ts
// Filters gitleaks findings to remove common false positives.
// Inspired by Kem's kem-sec false-positive agent pattern.
// See: https://campfire.aura-intel.net/blog/deterministic-skills

import type { SastFinding } from "../types.ts";

const FALSE_POSITIVE_PATHS = [
  /\btest[s]?\b/i,
  /\.test\.(ts|js|py)$/,
  /\.spec\.(ts|js|py)$/,
  /__tests__/,
  /\bfixtures?\b/i,
  /\bmocks?\b/i,
  /\bexamples?\b/i,
  /\.md$/,
  /README/i,
  /CHANGELOG/i,
  /docs?\//i,
];

const FALSE_POSITIVE_VALUES = [
  /^(xxx+|your[-_]key[-_]here|CHANGE[_-]?ME|placeholder|dummy|fake|example|test)$/i,
  /^sk_test_/,
  /^pk_test_/,
  /^(abc123|password123|secret123|12345678)$/i,
  /^\$\{[A-Z_]+\}$/,   // ${ENV_VAR}
  /^process\.env\./,
  /^<[A-Z_]+>$/,        // <PLACEHOLDER>
];

export function filterGitleaksFindings(raw: any[]): {
  findings: SastFinding[];
  removedCount: number;
} {
  const results: SastFinding[] = [];
  let removedCount = 0;

  for (const r of raw) {
    const file: string = r.File ?? r.file ?? "";
    const secret: string = r.Secret ?? r.secret ?? r.Match ?? "";

    const isFpPath = FALSE_POSITIVE_PATHS.some((re) => re.test(file));
    const isFpValue = FALSE_POSITIVE_VALUES.some((re) => re.test(secret.trim()));

    if (isFpPath || isFpValue) {
      removedCount++;
      continue;
    }

    results.push({
      tool: "gitleaks",
      severity: "HIGH",
      file,
      line: r.StartLine ?? r.Line,
      message: `${r.RuleID ?? r.Description ?? "Secret"} detected`,
      ruleId: r.RuleID,
    });
  }

  return { findings: results, removedCount };
}
```

- [ ] **Step 2: Commit**

```bash
cd /tmp/github-repo-scanner-v2
git add scanner/lib/filter-fp.ts
git commit -m "feat(v2): gitleaks false-positive filter (kem-sec pattern)"
```

---

## Task 4: Phase 2 — Security SAST

**Files:**
- Create: `scanner/phases/phase2-sast.ts`

- [ ] **Step 1: Create `scanner/phases/phase2-sast.ts`**

```typescript
// scanner/phases/phase2-sast.ts
import { join } from "path";
import { tmpdir } from "os";
import { existsSync } from "fs";
import { runTool, safeParseJson } from "../lib/tools.ts";
import { filterGitleaksFindings } from "../lib/filter-fp.ts";
import type { Phase2Result, SastFinding, VulnFinding, ProjectType } from "../types.ts";

function isJsonMode() { return process.argv.includes("--json"); }
function log(msg: string) {
  if (isJsonMode()) process.stderr.write(msg + "\n");
  else console.log(msg);
}

function box(title: string, detail: string): string {
  return `\n${"━".repeat(55)}\n║  ${title}\n║  ${detail}\n${"━".repeat(55)}`;
}

function mapSemgrepSeverity(s: string): SastFinding["severity"] {
  const m: Record<string, SastFinding["severity"]> = {
    ERROR: "HIGH", WARNING: "MEDIUM", INFO: "LOW",
  };
  return m[s.toUpperCase()] ?? "LOW";
}

function mapGrypeSeverity(s: string): VulnFinding["severity"] {
  const m: Record<string, VulnFinding["severity"]> = {
    Critical: "CRITICAL", High: "HIGH", Medium: "MEDIUM", Low: "LOW",
  };
  return m[s] ?? "LOW";
}

export async function runPhase2(
  owner: string,
  name: string,
  projectType: ProjectType
): Promise<Phase2Result> {
  log(box("PHASE 2: SECURITY ANALYSIS", "Cloning at depth=1 then running 5 tools in parallel"));

  const scanDir = join(tmpdir(), `repo-scan-${owner}-${name}-${Date.now()}`);
  log(`  Cloning to ${scanDir}...`);

  const cloneResult = await runTool("git", [
    "git", "clone", "--depth=1",
    `https://github.com/${owner}/${name}.git`, scanDir,
  ], 60000);

  if (cloneResult.exitCode !== 0) {
    log(`  Clone failed: ${cloneResult.stderr.slice(0, 200)}`);
    return {
      guarddogFindings: ["Clone failed — could not run SAST tools"],
      semgrepFindings: [], gitleaksFindings: [], gitleaksRawCount: 0,
      osvVulns: [], grypeVulns: [], cloneDir: null,
    };
  }

  // Detect ecosystem for guarddog
  const hasPackageJson = existsSync(join(scanDir, "package.json"));
  const hasPyProject = existsSync(join(scanDir, "pyproject.toml")) ||
    existsSync(join(scanDir, "requirements.txt")) ||
    existsSync(join(scanDir, "setup.py"));
  const eco = hasPyProject ? "pypi" : "npm";

  const [guarddogR, semgrepR, gitleaksR, osvR, grypeR] = await Promise.all([
    (async () => {
      log("  [1/5] GuardDog (malicious install scripts, exfil, miners)...");
      // guarddog scans the package *name* from manifest, not a directory
      // For npm: read package name from package.json; for pypi: from setup.py/pyproject.toml
      if (hasPackageJson) {
        const pkgJson = safeParseJson(await Bun.file(join(scanDir, "package.json")).text());
        if (pkgJson?.name) {
          return runTool("guarddog", ["guarddog", "npm", "verify", pkgJson.name], 60000);
        }
      }
      // Fall back to directory scan
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
      const reportPath = join(tmpdir(), `gitleaks-${owner}-${name}.json`);
      await runTool("gitleaks", [
        "gitleaks", "detect", `--source=${scanDir}`,
        "--report-format=json", `--report-path=${reportPath}`,
        "--no-git",
      ], 60000);
      // Read report regardless of exit code (non-zero means findings)
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

  // Parse guarddog
  const guarddogFindings: string[] = [];
  const gdText = guarddogR.stdout + guarddogR.stderr;
  if (gdText.includes("malicious") && !gdText.match(/Found 0 potentially malicious/)) {
    guarddogFindings.push("Potentially malicious patterns detected");
  }
  // Specific guarddog heuristics
  for (const rule of ["CMD_OVERWRITE", "OBFUSCATED_SETUP", "EXFILTRATE_SENSITIVE_DATA", "SHELLING_OUT"]) {
    if (gdText.includes(rule)) guarddogFindings.push(`GuardDog rule: ${rule}`);
  }

  // Parse semgrep
  const semgrepData = safeParseJson(semgrepR.stdout);
  const semgrepFindings: SastFinding[] = (semgrepData?.results ?? []).map((r: any) => ({
    tool: "semgrep",
    severity: mapSemgrepSeverity(r.extra?.severity ?? "INFO"),
    file: r.path?.replace(scanDir + "/", "") ?? r.path,
    line: r.start?.line,
    message: r.extra?.message ?? r.check_id,
    ruleId: r.check_id,
  }));

  // Parse gitleaks with FP filter
  const rawGitleaks = safeParseJson(gitleaksR.stdout) ?? [];
  const { findings: gitleaksFindings, removedCount } = filterGitleaksFindings(
    Array.isArray(rawGitleaks) ? rawGitleaks : []
  );
  log(`  Gitleaks: ${rawGitleaks.length} raw → ${gitleaksFindings.length} after FP filter (${removedCount} removed)`);

  // Parse OSV
  const osvData = safeParseJson(osvR.stdout);
  const osvVulns: VulnFinding[] = (osvData?.results ?? [])
    .flatMap((r: any) => r.packages ?? [])
    .flatMap((p: any) =>
      (p.vulnerabilities ?? []).map((v: any) => ({
        pkg: p.package?.name ?? "unknown",
        version: p.package?.version ?? "?",
        cve: v.id ?? "?",
        severity: (v.database_specific?.severity ?? "LOW").toUpperCase() as VulnFinding["severity"],
        fixVersion: v.affected?.[0]?.ranges?.[0]?.events
          ?.find((e: any) => e.fixed)?.fixed ?? null,
      }))
    );

  // Parse grype
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

  return {
    guarddogFindings,
    semgrepFindings,
    gitleaksFindings,
    gitleaksRawCount: rawGitleaks.length,
    osvVulns,
    grypeVulns,
    cloneDir: null,
  };
}
```

- [ ] **Step 2: Commit**

```bash
cd /tmp/github-repo-scanner-v2
git add scanner/phases/phase2-sast.ts
git commit -m "feat(v2): phase 2 — parallel SAST with structured finding types and FP filtering"
```

---

## Task 5: Phase 3 — Code quality signals

**Files:**
- Create: `scanner/phases/phase3-quality.ts`

This is the major new addition in v2, informed by kem-sec's Code Quality and Error Handling categories.

- [ ] **Step 1: Create `scanner/phases/phase3-quality.ts`**

```typescript
// scanner/phases/phase3-quality.ts
// Code quality signal analysis — new in v2, inspired by kem-sec's 40-check Code Quality category
// See: https://campfire.aura-intel.net/blog/deterministic-skills

import { join } from "path";
import { tmpdir } from "os";
import { existsSync } from "fs";
import { runTool, safeParseJson } from "../lib/tools.ts";
import type { Phase3Result, QualitySignal, ProjectType } from "../types.ts";

function isJsonMode() { return process.argv.includes("--json"); }
function log(msg: string) {
  if (isJsonMode()) process.stderr.write(msg + "\n");
  else console.log(msg);
}

function box(title: string, detail: string): string {
  return `\n${"━".repeat(55)}\n║  ${title}\n║  ${detail}\n${"━".repeat(55)}`;
}

async function hasFile(dir: string, patterns: string[]): Promise<string | null> {
  for (const p of patterns) {
    if (existsSync(join(dir, p))) return p;
  }
  return null;
}

async function countFiles(dir: string, ext: string): Promise<number> {
  const r = await runTool("find", [
    "find", dir, "-name", `*.${ext}`, "-not", "-path", "*/node_modules/*",
    "-not", "-path", "*/.git/*", "-not", "-path", "*/dist/*",
  ], 10000);
  return r.stdout.trim().split("\n").filter(Boolean).length;
}

async function countTestFiles(dir: string): Promise<number> {
  const r = await runTool("find", [
    "find", dir, "(",
    "-name", "*.test.ts", "-o", "-name", "*.spec.ts",
    "-o", "-name", "*.test.js", "-o", "-name", "*.spec.js",
    "-o", "-name", "test_*.py", "-o", "-name", "*_test.py",
    "-o", "-name", "*_test.go",
    ")", "-not", "-path", "*/node_modules/*", "-not", "-path", "*/.git/*",
  ], 10000);
  return r.stdout.trim().split("\n").filter(Boolean).length;
}

export async function runPhase3(
  owner: string,
  name: string,
  projectType: ProjectType,
  scanDir?: string
): Promise<Phase3Result> {
  log(box("PHASE 3: CODE QUALITY SIGNALS", "Checking CI, tests, docs, dependencies"));

  // Clone if no existing scan dir
  let ownedClone = false;
  if (!scanDir) {
    scanDir = join(tmpdir(), `repo-quality-${owner}-${name}-${Date.now()}`);
    log(`  Cloning for quality analysis...`);
    const cloneR = await runTool("git", [
      "git", "clone", "--depth=1", `https://github.com/${owner}/${name}.git`, scanDir,
    ], 60000);
    if (cloneR.exitCode !== 0) {
      log(`  Clone failed, skipping quality phase`);
      return { signals: [], maturityScore: 0 };
    }
    ownedClone = true;
  }

  const signals: QualitySignal[] = [];

  // Check CI/CD configuration
  const ciFile = await hasFile(scanDir, [
    ".github/workflows",
    ".circleci/config.yml",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".travis.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
  ]);
  signals.push({
    id: "QC-01",
    label: "CI/CD configured",
    passed: ciFile !== null,
    severity: "HIGH",
    detail: ciFile ?? undefined,
  });

  // Check for test files
  const testCount = await countTestFiles(scanDir);
  signals.push({
    id: "QC-02",
    label: "Test suite present",
    passed: testCount > 0,
    severity: "HIGH",
    detail: testCount > 0 ? `${testCount} test file(s)` : "No test files found",
  });

  // README quality — is it more than 10 lines?
  const readmeFile = await hasFile(scanDir, ["README.md", "README.rst", "README.txt", "README"]);
  let readmeLines = 0;
  if (readmeFile) {
    const content = await Bun.file(join(scanDir, readmeFile)).text().catch(() => "");
    readmeLines = content.split("\n").filter(Boolean).length;
  }
  signals.push({
    id: "QC-03",
    label: "README is substantive (>20 lines)",
    passed: readmeLines > 20,
    severity: "LOW",
    detail: readmeFile ? `${readmeLines} lines` : "No README found",
  });

  // SECURITY.md / security policy
  const secPolicy = await hasFile(scanDir, ["SECURITY.md", ".github/SECURITY.md", "SECURITY.rst"]);
  signals.push({
    id: "QC-04",
    label: "Security policy (SECURITY.md)",
    passed: secPolicy !== null,
    severity: "MEDIUM",
    detail: secPolicy ?? undefined,
  });

  // CHANGELOG or release notes
  const changelog = await hasFile(scanDir, [
    "CHANGELOG.md", "CHANGELOG.rst", "CHANGELOG", "HISTORY.md", "RELEASES.md",
  ]);
  signals.push({
    id: "QC-05",
    label: "CHANGELOG / release notes",
    passed: changelog !== null,
    severity: "LOW",
  });

  // TypeScript strict mode (JS/TS projects)
  if (projectType === "npm-library" || projectType === "web-app" || projectType === "cli") {
    const tsconfigFile = await hasFile(scanDir, ["tsconfig.json"]);
    let strictEnabled = false;
    if (tsconfigFile) {
      const tsconfig = safeParseJson(
        await Bun.file(join(scanDir, "tsconfig.json")).text().catch(() => "{}")
      );
      strictEnabled = tsconfig?.compilerOptions?.strict === true;
    }
    signals.push({
      id: "QC-06",
      label: "TypeScript strict mode",
      passed: strictEnabled || tsconfigFile === null, // N/A if no tsconfig
      severity: "MEDIUM",
      detail: tsconfigFile ? (strictEnabled ? "strict: true" : "strict mode disabled") : "Not a TS project",
    });
  }

  // CONTRIBUTING.md (community health)
  const contributing = await hasFile(scanDir, ["CONTRIBUTING.md", ".github/CONTRIBUTING.md"]);
  signals.push({
    id: "QC-07",
    label: "CONTRIBUTING guide",
    passed: contributing !== null,
    severity: "LOW",
  });

  // No lock file (JS projects without lock = unreproducible deps)
  if (projectType === "npm-library" || projectType === "web-app" || projectType === "cli") {
    const hasPackageJson = existsSync(join(scanDir, "package.json"));
    if (hasPackageJson) {
      const lockFile = await hasFile(scanDir, [
        "package-lock.json", "yarn.lock", "bun.lockb", "pnpm-lock.yaml",
      ]);
      signals.push({
        id: "QC-08",
        label: "Dependency lock file present",
        passed: lockFile !== null,
        severity: "MEDIUM",
        detail: lockFile ?? "No lock file — unreproducible installs",
      });
    }
  }

  // Dependency count — flag repos with >200 direct deps
  const packageJson = existsSync(join(scanDir, "package.json"))
    ? safeParseJson(await Bun.file(join(scanDir, "package.json")).text().catch(() => "{}"))
    : null;
  if (packageJson) {
    const depCount = Object.keys({
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
    }).length;
    signals.push({
      id: "QC-09",
      label: "Dependency surface reasonable (<200)",
      passed: depCount < 200,
      severity: "MEDIUM",
      detail: `${depCount} dependencies`,
    });
  }

  // GitHub Actions — check for suspicious steps (curl | sh, wget | bash)
  const workflowDir = join(scanDir, ".github/workflows");
  if (existsSync(workflowDir)) {
    const grepR = await runTool("grep", [
      "grep", "-r", "-l", "--include=*.yml",
      "-E", "(curl|wget).*(\\||bash|sh)", workflowDir,
    ], 10000);
    const suspiciousWorkflows = grepR.stdout.trim().split("\n").filter(Boolean).length;
    signals.push({
      id: "QC-10",
      label: "No curl|bash in CI workflows",
      passed: suspiciousWorkflows === 0,
      severity: "HIGH",
      detail: suspiciousWorkflows > 0
        ? `${suspiciousWorkflows} workflow(s) with suspicious shell piping`
        : undefined,
    });
  }

  // Calculate maturity score: each passed signal weighted by severity
  const weights: Record<QualitySignal["severity"], number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  const totalWeight = signals.reduce((s, sig) => s + weights[sig.severity], 0);
  const earnedWeight = signals.filter((s) => s.passed).reduce((s, sig) => s + weights[sig.severity], 0);
  const maturityScore = totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) / 10 : 0;

  // Log results
  const passed = signals.filter((s) => s.passed).length;
  log(`\n  Quality signals: ${passed}/${signals.length} passed`);
  log(`  Maturity score:  ${maturityScore.toFixed(1)}/10`);
  signals.filter((s) => !s.passed).forEach((s) => {
    log(`  [!] ${s.label}${s.detail ? ` — ${s.detail}` : ""}`);
  });

  if (ownedClone && scanDir) {
    await runTool("rm", ["rm", "-rf", scanDir], 30000);
  }

  return { signals, maturityScore };
}
```

- [ ] **Step 2: Commit**

```bash
cd /tmp/github-repo-scanner-v2
git add scanner/phases/phase3-quality.ts
git commit -m "feat(v2): phase 3 — 10-signal code quality analysis with maturity score"
```

---

## Task 6: Phase 4 — Aggregate and verdict

**Files:**
- Create: `scanner/phases/phase4-aggregate.ts`

- [ ] **Step 1: Create `scanner/phases/phase4-aggregate.ts`**

```typescript
// scanner/phases/phase4-aggregate.ts
import type { ScanState, Phase1Result, Phase2Result, Phase3Result } from "../types.ts";

export function computeVerdict(state: ScanState): void {
  const { phase1, phase2, phase3 } = state;
  if (!phase1) return;

  // ── Security score (0-10, from scorecard basis + deductions) ──
  let securityScore = phase1.scorecardScore;

  // Live secrets = instant DO NOT INSTALL
  if (phase1.secrets.length > 0) {
    state.verdict = "DO NOT INSTALL";
    state.criticalFindings.push(
      `${phase1.secrets.length} live/verified secret(s) detected by TruffleHog`
    );
    securityScore -= 3;
  }

  // Archived repo
  if (phase1.ghInfo.archived) {
    state.warnings.push("Repository is ARCHIVED — no longer maintained");
  }

  // Abandoned (>12 months)
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

  // Low trust score
  if (phase1.scorecardScore < 3.0) {
    state.warnings.push(`Very low OpenSSF Scorecard: ${phase1.scorecardScore}/10`);
  } else if (phase1.scorecardScore < 5.0) {
    state.warnings.push(`Low OpenSSF Scorecard: ${phase1.scorecardScore}/10`);
  }

  if (phase2) {
    // Malicious code = instant DO NOT INSTALL
    if (phase2.guarddogFindings.length > 0) {
      state.verdict = "DO NOT INSTALL";
      phase2.guarddogFindings.forEach((f) => state.criticalFindings.push(f));
      securityScore -= 5;
    }

    // Semgrep: count HIGH+ findings
    const semgrepHigh = phase2.semgrepFindings.filter(
      (f) => f.severity === "CRITICAL" || f.severity === "HIGH"
    );
    if (semgrepHigh.length > 10) {
      state.criticalFindings.push(`${semgrepHigh.length} high/critical SAST findings (Semgrep)`);
      securityScore -= 2;
    } else if (semgrepHigh.length > 0) {
      state.warnings.push(`${semgrepHigh.length} high/critical SAST issue(s) (Semgrep)`);
      securityScore -= 0.5 * Math.min(semgrepHigh.length, 4);
    }

    // Gitleaks secrets in source
    if (phase2.gitleaksFindings.length > 0) {
      state.warnings.push(
        `${phase2.gitleaksFindings.length} potential secret(s) in source` +
        (phase2.gitleaksRawCount > phase2.gitleaksFindings.length
          ? ` (${phase2.gitleaksRawCount - phase2.gitleaksFindings.length} false positives filtered)`
          : "")
      );
      securityScore -= Math.min(phase2.gitleaksFindings.length, 2);
    }

    // CVEs — combine OSV + Grype, deduplicate by CVE ID
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
        `${critCves.length} critical CVE(s): ${critCves.slice(0, 3).map((v) => v.cve).join(", ")}${critCves.length > 3 ? "..." : ""}`
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

  // Clamp security score
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
```

- [ ] **Step 2: Commit**

```bash
cd /tmp/github-repo-scanner-v2
git add scanner/phases/phase4-aggregate.ts
git commit -m "feat(v2): phase 4 — weighted verdict with security + maturity scores"
```

---

## Task 7: Main orchestrator rewrite

**Files:**
- Modify: `scanner/scan.ts`

- [ ] **Step 1: Rewrite `scanner/scan.ts`**

```typescript
#!/usr/bin/env bun
/**
 * repo-scanner v2 — Pre-install GitHub repository security scanner
 *
 * v2 improvements:
 *  - 4-phase pipeline with structured JSON contracts between phases
 *  - Code quality phase (CI, tests, docs, license, lock files)
 *  - Maturity score (0-10) alongside security score
 *  - AI false-positive filter for gitleaks (kem-sec pattern)
 *  - State persistence — resume interrupted scans
 *  - kem-sec style ASCII display
 *
 * Architecture inspired by Kem's kem-sec deterministic skills research:
 *   https://campfire.aura-intel.net/blog/deterministic-skills
 *
 * Usage:
 *   bun scan.ts <github-url> [--quick] [--deep] [--json] [--resume] [--fresh]
 */

import { mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { parseGithubUrl } from "./lib/tools.ts";
import { saveState, loadStateAsync, clearState } from "./lib/state.ts";
import { displayFinalReport } from "./lib/display.ts";
import { runPhase1 } from "./phases/phase1-remote.ts";
import { runPhase2 } from "./phases/phase2-sast.ts";
import { runPhase3 } from "./phases/phase3-quality.ts";
import { computeVerdict } from "./phases/phase4-aggregate.ts";
import type { ScanState } from "./types.ts";

const SCANS_DIR = join(homedir(), ".repo-scanner", "scans");
mkdirSync(SCANS_DIR, { recursive: true });

const isJsonMode = process.argv.includes("--json");

function log(msg: string): void {
  if (isJsonMode) process.stderr.write(msg + "\n");
  else console.log(msg);
}

async function ensureGithubToken(): Promise<void> {
  if (!process.env.GITHUB_TOKEN) {
    try {
      const proc = Bun.spawn(["gh", "auth", "token"], { stdout: "pipe", stderr: "pipe" });
      const token = (await new Response(proc.stdout).text()).trim();
      if (token) {
        process.env.GITHUB_TOKEN = token;
        log("  Set GITHUB_TOKEN from gh auth");
      }
    } catch {}
  }
}

async function main() {
  const args = process.argv.slice(2);
  const url = args.find((a) => !a.startsWith("--"));
  const quick = args.includes("--quick");
  const resume = args.includes("--resume");
  const fresh = args.includes("--fresh");

  if (!url) {
    console.log(`
repo-scanner v2 — Pre-install GitHub security scanner

Usage:
  bun scan.ts <github-url>           Full scan (recommended)
  bun scan.ts <github-url> --quick   Phase 1 only (remote, no clone)
  bun scan.ts <github-url> --resume  Resume interrupted scan
  bun scan.ts <github-url> --fresh   Force fresh scan (ignore saved state)
  bun scan.ts <github-url> --json    Output as JSON
`);
    process.exit(1);
  }

  const { owner, name } = parseGithubUrl(url);
  log(`\nScanning: github.com/${owner}/${name}`);
  await ensureGithubToken();

  // Check for resumable state
  let state: ScanState;
  const saved = (!fresh && resume) ? await loadStateAsync(owner, name) : null;

  if (saved && saved.phase1) {
    log(`\nResuming previous scan from ${saved.timestamp.slice(0, 16)}...`);
    state = saved;
  } else {
    if (fresh) await clearState(owner, name);
    state = {
      repo: `${owner}/${name}`,
      owner,
      name,
      timestamp: new Date().toISOString(),
      verdict: "REVIEW NEEDED",
      verdictReasons: [],
      criticalFindings: [],
      warnings: [],
      maturityScore: 0,
      securityScore: 0,
    };
  }

  // Phase 1: Remote trust signals
  if (!state.phase1) {
    state.phase1 = await runPhase1(owner, name);
    await saveState(state);
  } else {
    log("\nPhase 1: Using cached results");
  }

  // Phase 2: SAST (skip on --quick)
  if (!quick && !state.phase2) {
    state.phase2 = await runPhase2(owner, name, state.phase1.projectType);
    await saveState(state);
  }

  // Phase 3: Code quality (skip on --quick)
  if (!quick && !state.phase3) {
    state.phase3 = await runPhase3(owner, name, state.phase1.projectType);
    await saveState(state);
  }

  // Phase 4: Aggregate + verdict
  computeVerdict(state);
  await saveState(state);

  // Output
  if (isJsonMode) {
    process.stdout.write(JSON.stringify(state, null, 2));
  } else {
    displayFinalReport(state);
  }

  // Archive completed scan
  const scanFile = join(SCANS_DIR, `${owner}-${name}-${new Date().toISOString().slice(0, 10)}.json`);
  await Bun.write(scanFile, JSON.stringify(state, null, 2));
  log(`\nScan saved: ${scanFile}`);

  // Clear checkpoint (scan complete)
  await clearState(owner, name);
}

main().catch((err) => {
  console.error("Scan failed:", err.message);
  process.exit(1);
});
```

- [ ] **Step 2: Commit**

```bash
cd /tmp/github-repo-scanner-v2
git add scanner/scan.ts
git commit -m "feat(v2): rewrite orchestrator — 4 phases, state persistence, kem-sec display"
```

---

## Task 8: README, CREDITS, CHANGELOG

**Files:**
- Modify: `README.md`
- Modify: `CREDITS.md`
- Create: `CHANGELOG.md`

- [ ] **Step 1: Update `README.md`**

Replace the existing README with the v2 version:

```markdown
# GitHub Repository Security Scanner v2

Scan any GitHub repository for malicious code, secrets, vulnerabilities, and trust signals **before** downloading or installing it.

> Runs eight security tools across a four-phase pipeline — remote trust checks with no download required, shallow-clone security analysis, code quality assessment, and an aggregated **SAFE / REVIEW NEEDED / DO NOT INSTALL** verdict with separate security and maturity scores.

## What's new in v2

- **Code quality phase** — 10 signals: CI/CD, test suite, README depth, SECURITY.md, CHANGELOG, TypeScript strict mode, lock files, dependency surface, suspicious CI pipelines
- **Maturity score** (0-10) alongside the security score — know if a repo is secure *and* well-maintained
- **AI false-positive filter** for gitleaks — reduces noise by stripping test fixtures, placeholder values, and env-var references (inspired by [Kem's kem-sec deterministic skills research](https://campfire.aura-intel.net/blog/deterministic-skills))
- **State persistence** — interrupted scans resume from the last completed phase
- **Structured type contracts** — each phase outputs a validated JSON schema
- **Project type detection** — npm library, Python package, CLI, Go, Rust, web app — skip irrelevant checks automatically

## How it works

```
Phase 1 — Remote (parallel, no clone)
  OpenSSF Scorecard (18 trust checks)
  TruffleHog (live secrets in git history)
  GitHub API (stars, forks, license, activity, project type)
        ↓
Phase 2 — Shallow clone, security SAST (parallel)
  GuardDog (malicious install scripts, data exfiltration, miners)
  Semgrep (1,000+ SAST vulnerability rules)
  Gitleaks (hardcoded secrets → false-positive filtered)
  OSV-Scanner (dependency CVEs)
  Grype (vulnerability severity grading)
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
- GitHub CLI (`gh`) authenticated — run `gh auth login` once

## Scan history

Results saved to `~/.repo-scanner/scans/` as JSON. Interrupted scan state at `~/.repo-scanner/state/`.

## Credits

- **Security tools:** see [CREDITS.md](CREDITS.md)
- **Architecture inspired by:** [Kem](https://campfire.aura-intel.net) — whose [kem-sec](https://github.com/aura-intel/kem-sec) tool and [research into deterministic Claude Code skills](https://campfire.aura-intel.net/blog/deterministic-skills) informed the v2 false-positive filter, state persistence, and structured phase contracts
```

- [ ] **Step 2: Update `CREDITS.md`**

Append the following section to the end of the existing CREDITS.md:

```markdown

---

## Architecture Inspiration

**[kem-sec](https://github.com/aura-intel/kem-sec)** by [Kem / aura-intel](https://campfire.aura-intel.net)
MIT License | [campfire.aura-intel.net/blog/deterministic-skills](https://campfire.aura-intel.net/blog/deterministic-skills)

Kem's kem-sec (148-check pre-launch security audit for Claude Code) and his research into
deterministic skill design patterns informed three v2 features:

1. **Gitleaks false-positive filter** — discrete filtering step with explicit FP rules for test files,
   placeholder values, and environment variable references
2. **State persistence** — checkpoint/resume architecture so long scans survive interruption
3. **Structured phase contracts** — each phase outputs a defined JSON schema validated before aggregation
```

- [ ] **Step 3: Create `CHANGELOG.md`**

```markdown
# Changelog

## v2.0.0 — 2026-04-06

### New features
- **Phase 3: Code quality analysis** — 10 signals across CI/CD, testing, documentation, and dependency hygiene, producing a Maturity Score (0-10) alongside the existing Security Score
- **Project type detection** — automatically identifies npm library, Python package, CLI, Go, Rust, or web app and skips irrelevant checks
- **Gitleaks false-positive filter** — discrete filtering step removes test fixtures, placeholder values, and env-var references before reporting, reducing noise (inspired by Kem's kem-sec tool)
- **State persistence** — scan state saved after each phase; interrupted scans resume with `--resume`
- **`--fresh` flag** — force a clean scan ignoring any saved state
- **Structured TypeScript types** — `types.ts` defines contracts for all phase outputs; each phase validates its JSON before returning
- **Maturity score** — weighted 0-10 score from quality signals (CI: HIGH weight, strict mode: MEDIUM, CHANGELOG: LOW, etc.)
- **kem-sec style ASCII display** — ━━ box format for phase headers and final report

### Breaking changes
- Scanner is now split into `scanner/phases/` and `scanner/lib/` — the old single-file `scan.ts` is replaced
- Scan state directory changed from `~/.claude/skills/repo-scanner/scans/` to `~/.repo-scanner/scans/`
- `--deep` flag removed (Phase 3 quality analysis is now always run unless `--quick`)

### Architecture credits
- v2 architecture inspired by [Kem's kem-sec](https://github.com/aura-intel/kem-sec) and his article [*You think Claude is using your skills but it's mostly pretending*](https://campfire.aura-intel.net/blog/deterministic-skills)

---

## v1.0.0 — 2026-03-31

- Initial release
- 3-phase pipeline: remote trust signals, shallow clone SAST, verdict
- Tools: OpenSSF Scorecard, TruffleHog, GuardDog, Semgrep, Gitleaks, OSV-Scanner, Grype
- Mac/Windows installers
- SAFE / REVIEW NEEDED / DO NOT INSTALL verdict
```

- [ ] **Step 4: Commit all docs**

```bash
cd /tmp/github-repo-scanner-v2
git add README.md CREDITS.md CHANGELOG.md
git commit -m "docs(v2): update README, CREDITS (Kem attribution), add CHANGELOG"
```

---

## Task 9: Push to GitHub and test

**Files:** None (git ops only)

- [ ] **Step 1: Push to GitHub**

```bash
cd /tmp/github-repo-scanner-v2
git push origin main
```

- [ ] **Step 2: Test on JuliusBrussee/caveman**

```bash
bun /tmp/github-repo-scanner-v2/scanner/scan.ts https://github.com/JuliusBrussee/caveman
```

Expected: SAFE or REVIEW NEEDED. Caveman is a 4K-star MIT-licensed Claude Code skill — no malicious code expected, but check for: low scorecard (small solo project), possibly no SECURITY.md, may have test gap. Record actual output.

- [ ] **Step 3: Test on affaan-m/everything-claude-code**

```bash
bun /tmp/github-repo-scanner-v2/scanner/scan.ts https://github.com/affaan-m/everything-claude-code
```

Expected: Should be high-scoring (142K stars, active, framework project). Check: scorecard score, test suite presence, CI configuration.

- [ ] **Step 4: Verify JSON output mode**

```bash
bun /tmp/github-repo-scanner-v2/scanner/scan.ts https://github.com/JuliusBrussee/caveman --json 2>/dev/null | python3 -m json.tool | head -40
```

Expected: Valid JSON with `phase1`, `phase2`, `phase3`, `verdict`, `securityScore`, `maturityScore` fields.

- [ ] **Step 5: Test --quick mode (remote only)**

```bash
bun /tmp/github-repo-scanner-v2/scanner/scan.ts https://github.com/JuliusBrussee/caveman --quick
```

Expected: Completes in <30s, outputs Phase 1 only, no clone.

---

## Self-Review

**Spec coverage check:**
- [x] Phase 1 remote: scorecard + trufflehog + github API in parallel — Task 2
- [x] Phase 2 SAST: guarddog + semgrep + gitleaks + osv + grype in parallel — Task 4
- [x] Phase 3 quality: 10 signals, maturity score — Task 5
- [x] False-positive filter for gitleaks — Task 3
- [x] State persistence (save/resume/clear) — Task 1 (state.ts) + Task 7 (orchestrator)
- [x] Structured types across all phases — Task 1 (types.ts)
- [x] kem-sec style display — Task 1 (display.ts)
- [x] README with Kem attribution — Task 8
- [x] CREDITS update — Task 8
- [x] CHANGELOG — Task 8
- [x] Push to GitHub — Task 9
- [x] Test on caveman — Task 9
- [x] Test on everything-claude-code — Task 9

**Placeholder scan:** No TBD, TODO, or "implement later" found.

**Type consistency:** `ScanState`, `Phase1Result`, `Phase2Result`, `Phase3Result`, `QualitySignal`, `SastFinding`, `VulnFinding`, `Verdict`, `ProjectType` defined in `types.ts` and imported consistently. `filter-fp.ts` imports `SastFinding`. Phase files all import from `../lib/tools.ts`.
