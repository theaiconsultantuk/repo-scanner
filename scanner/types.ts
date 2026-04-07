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
  gitleaksFindings: SastFinding[];
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
  maturityScore: number;
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
