// scanner/phases/phase3-quality.ts
// Code quality signal analysis — new in v2
// Inspired by Kem's kem-sec 40-check Code Quality category
// See: https://campfire.aura-intel.net/blog/deterministic-skills

import { join } from "path";
import { tmpdir } from "os";
import { existsSync } from "fs";
import { runTool, safeParseJson } from "../lib/tools.ts";
import type { Phase3Result, QualitySignal, ProjectType } from "../types.ts";

const isJsonMode = () => process.argv.includes("--json");
const log = (msg: string) => {
  if (isJsonMode()) process.stderr.write(msg + "\n");
  else console.log(msg);
};

async function hasFile(dir: string, paths: string[]): Promise<string | null> {
  for (const p of paths) {
    if (existsSync(join(dir, p))) return p;
  }
  return null;
}

async function countTestFiles(dir: string): Promise<number> {
  const r = await runTool("find", [
    "find", dir, "(",
    "-name", "*.test.ts", "-o", "-name", "*.spec.ts",
    "-o", "-name", "*.test.js", "-o", "-name", "*.spec.js",
    "-o", "-name", "test_*.py", "-o", "-name", "*_test.py",
    "-o", "-name", "*_test.go", "-o", "-name", "*.test.rb",
    ")", "-not", "-path", "*/node_modules/*", "-not", "-path", "*/.git/*",
    "-not", "-path", "*/dist/*", "-not", "-path", "*/build/*",
  ], 15000);
  return r.stdout.trim().split("\n").filter(Boolean).length;
}

export async function runPhase3(
  owner: string,
  name: string,
  projectType: ProjectType,
  existingScanDir?: string
): Promise<Phase3Result> {
  console.log(`\n${"━".repeat(57)}\n║  PHASE 3: CODE QUALITY SIGNALS\n║  10 checks: CI, tests, docs, deps, workflow safety\n${"━".repeat(57)}`);

  let scanDir = existingScanDir ?? "";
  let ownedClone = false;

  if (!scanDir || !existsSync(scanDir)) {
    scanDir = join(tmpdir(), `repo-quality-${owner}-${name}-${Date.now()}`);
    log(`  Cloning for quality analysis...`);
    const r = await runTool("git", [
      "git", "clone", "--depth=1",
      `https://github.com/${owner}/${name}.git`, scanDir,
    ], 90000);
    if (r.exitCode !== 0) {
      log(`  Clone failed, skipping quality phase`);
      return { signals: [], maturityScore: 0 };
    }
    ownedClone = true;
  }

  const signals: QualitySignal[] = [];

  // QC-01: CI/CD configured
  const ciFile = await hasFile(scanDir, [
    ".github/workflows",
    ".circleci/config.yml",
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".travis.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".woodpecker.yml",
  ]);
  signals.push({
    id: "QC-01",
    label: "CI/CD configured",
    passed: ciFile !== null,
    severity: "HIGH",
    detail: ciFile ?? undefined,
  });

  // QC-02: Test suite present
  const testCount = await countTestFiles(scanDir);
  signals.push({
    id: "QC-02",
    label: "Test suite present",
    passed: testCount > 0,
    severity: "HIGH",
    detail: testCount > 0 ? `${testCount} test file(s) found` : "No test files found",
  });

  // QC-03: README substantive (>20 lines)
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

  // QC-04: Security policy
  const secPolicy = await hasFile(scanDir, ["SECURITY.md", ".github/SECURITY.md", "SECURITY.rst"]);
  signals.push({
    id: "QC-04",
    label: "Security policy (SECURITY.md)",
    passed: secPolicy !== null,
    severity: "MEDIUM",
    detail: secPolicy ?? undefined,
  });

  // QC-05: CHANGELOG
  const changelog = await hasFile(scanDir, [
    "CHANGELOG.md", "CHANGELOG.rst", "CHANGELOG", "HISTORY.md", "RELEASES.md", "CHANGES.md",
  ]);
  signals.push({
    id: "QC-05",
    label: "CHANGELOG / release notes",
    passed: changelog !== null,
    severity: "LOW",
    detail: changelog ?? undefined,
  });

  // QC-06: TypeScript strict mode (JS/TS projects only)
  const isJsTs = projectType === "npm-library" || projectType === "web-app" || projectType === "cli" || projectType === "unknown";
  if (isJsTs && existsSync(join(scanDir, "tsconfig.json"))) {
    const tsconfig = safeParseJson(
      await Bun.file(join(scanDir, "tsconfig.json")).text().catch(() => "{}")
    );
    const strictEnabled = tsconfig?.compilerOptions?.strict === true;
    signals.push({
      id: "QC-06",
      label: "TypeScript strict mode enabled",
      passed: strictEnabled,
      severity: "MEDIUM",
      detail: strictEnabled ? "strict: true" : "strict mode not enabled in tsconfig.json",
    });
  }

  // QC-07: CONTRIBUTING guide
  const contributing = await hasFile(scanDir, ["CONTRIBUTING.md", ".github/CONTRIBUTING.md", "CONTRIBUTING.rst"]);
  signals.push({
    id: "QC-07",
    label: "CONTRIBUTING guide",
    passed: contributing !== null,
    severity: "LOW",
    detail: contributing ?? undefined,
  });

  // QC-08: Lock file (JS/TS projects)
  if ((isJsTs || projectType === "unknown") && existsSync(join(scanDir, "package.json"))) {
    const lockFile = await hasFile(scanDir, [
      "package-lock.json", "yarn.lock", "bun.lockb", "pnpm-lock.yaml",
    ]);
    signals.push({
      id: "QC-08",
      label: "Dependency lock file present",
      passed: lockFile !== null,
      severity: "MEDIUM",
      detail: lockFile ?? "No lock file — installs may not be reproducible",
    });
  }

  // QC-09: Dependency surface reasonable (<200)
  if (existsSync(join(scanDir, "package.json"))) { // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
    const pkgJson = safeParseJson(
      await Bun.file(join(scanDir, "package.json")).text().catch(() => "{}") // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
    );
    const depCount = Object.keys({
      ...(pkgJson?.dependencies ?? {}),
      ...(pkgJson?.devDependencies ?? {}),
    }).length;
    signals.push({
      id: "QC-09",
      label: "Dependency surface reasonable (<200 total)",
      passed: depCount < 200,
      severity: "MEDIUM",
      detail: `${depCount} dependencies`,
    });
  }

  // QC-10: No curl|bash in GitHub Actions workflows
  const workflowDir = join(scanDir, ".github/workflows"); // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  if (existsSync(workflowDir)) {
    const grepR = await runTool("grep", [
      "grep", "-r", "-l", "--include=*.yml", "--include=*.yaml",
      "-E", "(curl|wget).{0,30}(\\||bash|sh )", workflowDir,
    ], 10000);
    const suspicious = grepR.stdout.trim().split("\n").filter(Boolean).length;
    signals.push({
      id: "QC-10",
      label: "No curl|bash piping in CI workflows",
      passed: suspicious === 0,
      severity: "HIGH",
      detail: suspicious > 0
        ? `${suspicious} workflow file(s) contain suspicious shell piping`
        : undefined,
    });
  }

  // Maturity score: weighted by severity
  const weights: Record<QualitySignal["severity"], number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
  const totalWeight = signals.reduce((s, sig) => s + weights[sig.severity], 0);
  const earnedWeight = signals.filter((s) => s.passed).reduce((s, sig) => s + weights[sig.severity], 0);
  const maturityScore = totalWeight > 0
    ? Math.round((earnedWeight / totalWeight) * 100) / 10
    : 0;

  const passed = signals.filter((s) => s.passed).length;
  log(`\n  Quality signals: ${passed}/${signals.length} passed`);
  log(`  Maturity score:  ${maturityScore.toFixed(1)}/10`);
  signals.filter((s) => !s.passed).forEach((s) =>
    log(`  [-] ${s.label}${s.detail ? ` — ${s.detail}` : ""}`)
  );

  if (ownedClone) {
    await runTool("rm", ["rm", "-rf", scanDir], 30000);
  }

  return { signals, maturityScore };
}
