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
  /\.md$/i,
  /README/i,
  /CHANGELOG/i,
  /docs?\//i,
];

const FALSE_POSITIVE_VALUES = [
  /^(x{3,}|your[-_]key[-_]here|CHANGE[_-]?ME|placeholder|dummy|fake|example|test)$/i,
  /^sk_test_/,
  /^pk_test_/,
  /^(abc123|password123|secret123|12345678|hunter2)$/i,
  /^\$\{[A-Z_]+\}$/,     // ${ENV_VAR}
  /^process\.env\./,
  /^<[A-Z_]+>$/,          // <PLACEHOLDER>
  /^https?:\/\//,         // URLs aren't secrets
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
