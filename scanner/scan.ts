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
 *   bun scan.ts <github-url>            Full scan (recommended)
 *   bun scan.ts <github-url> --quick    Phase 1 only (remote, no clone)
 *   bun scan.ts <github-url> --resume   Resume interrupted scan
 *   bun scan.ts <github-url> --fresh    Force fresh scan
 *   bun scan.ts <github-url> --json     Output as JSON
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
      if (token) process.env.GITHUB_TOKEN = token;
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
  bun scan.ts <github-url>           Full scan — all 4 phases (recommended)
  bun scan.ts <github-url> --quick   Phase 1 only — remote checks, no clone
  bun scan.ts <github-url> --resume  Resume an interrupted scan
  bun scan.ts <github-url> --fresh   Force fresh scan (ignore saved state)
  bun scan.ts <github-url> --json    Output results as JSON

Examples:
  bun scan.ts https://github.com/owner/repo
  bun scan.ts owner/repo --quick
  bun scan.ts owner/repo --json 2>/dev/null | jq '.verdict'
`);
    process.exit(1);
  }

  const { owner, name } = parseGithubUrl(url);
  log(`\nScanning: github.com/${owner}/${name}`);
  await ensureGithubToken();

  let state: ScanState;
  const saved = resume && !fresh ? await loadStateAsync(owner, name) : null;

  if (saved?.phase1) {
    log(`\nResuming previous scan from ${saved.timestamp.slice(0, 16)}...`);
    state = saved;
    state.criticalFindings = [];
    state.warnings = [];
    state.verdictReasons = [];
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

  // Phase 2: Security SAST (skip if --quick)
  if (!quick && !state.phase2) {
    state.phase2 = await runPhase2(owner, name, state.phase1.projectType);
    await saveState(state);
  }

  // Phase 3: Code quality (skip if --quick)
  if (!quick && !state.phase3) {
    state.phase3 = await runPhase3(owner, name, state.phase1.projectType);
    await saveState(state);
  }

  // Phase 4: Aggregate + verdict
  computeVerdict(state);
  await saveState(state);

  if (isJsonMode) {
    process.stdout.write(JSON.stringify(state, null, 2));
  } else {
    displayFinalReport(state);
  }

  const scanFile = join(
    SCANS_DIR,
    `${owner}-${name}-${new Date().toISOString().slice(0, 10)}.json`
  );
  await Bun.write(scanFile, JSON.stringify(state, null, 2));
  log(`\nScan saved: ${scanFile}`);

  await clearState(owner, name);
}

main().catch((err) => {
  console.error("Scan failed:", err.message);
  process.exit(1);
});
