// scanner/phases/phase1-remote.ts
import { runTool, safeParseJson } from "../lib/tools.ts";
import type { Phase1Result, GhInfo, VerifiedSecret, ProjectType } from "../types.ts";

const isJsonMode = () => process.argv.includes("--json");
const log = (msg: string) => {
  if (isJsonMode()) process.stderr.write(msg + "\n");
  else console.log(msg);
};

function detectProjectType(ghInfo: GhInfo): ProjectType {
  const lang = (ghInfo.language ?? "").toLowerCase();
  const topics = ghInfo.topics.map((x) => x.toLowerCase()).join(" ");
  if (lang === "python" || topics.includes("pypi")) return "python-package";
  if (lang === "go") return "go";
  if (lang === "rust") return "rust";
  if (
    topics.includes("web") || topics.includes("react") ||
    topics.includes("nextjs") || topics.includes("vue") || topics.includes("svelte")
  ) return "web-app";
  if (topics.includes("cli") || topics.includes("command-line") || topics.includes("terminal")) return "cli";
  if (lang === "javascript" || lang === "typescript") return "npm-library";
  return "unknown";
}

export async function runPhase1(owner: string, name: string): Promise<Phase1Result> {
  console.log(`\n${"━".repeat(57)}\n║  PHASE 1: REMOTE TRUST SIGNALS\n║  Running in parallel — no clone required\n${"━".repeat(57)}`);

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
  const scorecardChecks: Record<string, number> = {};
  const sc = safeParseJson(scorecardResult.stdout);
  if (sc) {
    scorecardScore = sc.score ?? sc.aggregate_score ?? 0;
    if (Array.isArray(sc.checks)) {
      for (const c of sc.checks) {
        scorecardChecks[c.name] = c.score;
      }
    }
  }

  // Parse TruffleHog — one JSON object per line
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

  // Parse GitHub API
  const ghInfo: GhInfo = safeParseJson(ghResult.stdout) ?? {
    stars: 0, forks: 0, openIssues: 0, license: null,
    pushedAt: "", archived: false, topics: [], language: null,
    hasWiki: false, hasDiscussions: false,
  };

  const projectType = detectProjectType(ghInfo);

  log(`\n  Scorecard:    ${scorecardScore}/10`);
  log(`  Stars:        ${ghInfo.stars} | Forks: ${ghInfo.forks}`);
  log(`  License:      ${ghInfo.license ?? "NONE"}`);
  log(`  Last push:    ${ghInfo.pushedAt?.slice(0, 10) ?? "?"}`);
  log(`  Project type: ${projectType}`);
  log(`  Live secrets: ${secrets.length}`);

  return { scorecardScore, scorecardChecks, secrets, ghInfo, projectType };
}
