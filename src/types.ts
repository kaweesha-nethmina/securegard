export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory = "sast" | "sca" | "secret" | "iac" | "container";

export type VulnStatus =
  | "open"
  | "triaged"
  | "false_positive"
  | "wont_fix"
  | "fixed"
  | "todo";

export type IdentitySource = "setting" | "gh" | "git" | "prompt";

export interface StatusHistoryEntry {
  status: VulnStatus;
  changedBy: string;
  changedByEmail?: string;
  changedAt: string; // ISO timestamp
  note?: string;
  source?: IdentitySource; // where the username came from (for UI labeling, e.g. unverified git identity)
}

export interface Vulnerability {
  id: string; // stable hash of rule+file+line+snippet
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  cvss?: number;
  cwe: string[];
  owasp?: string;
  category: FindingCategory;
  language: string;
  file: string; // workspace-relative path
  startLine: number;
  endLine: number;
  startCol?: number;
  endCol?: number;
  codeSnippet: string;
  sourceScanner: string;
  aiExplanation?: string;
  aiConfidence?: number; // 0-1
  suggestedFix?: string;
  status: VulnStatus;
  firstDetected: string; // ISO timestamp
  lastSeen: string;
  assignee?: string;
  notes?: string[];
  linkedTodoId?: string;
  falsePositiveReason?: string;
  baseline?: boolean; // true if found on the very first scan
  statusHistory: StatusHistoryEntry[];
}

export interface RawFinding {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string[];
  owasp?: string;
  category: FindingCategory;
  language: string;
  file: string;
  startLine: number;
  endLine: number;
  startCol?: number;
  endCol?: number;
  codeSnippet: string;
  sourceScanner: string;
  remediation?: string;
}

export interface ScanResult {
  findings: RawFinding[];
  scanner: string;
  durationMs: number;
  filesScanned: number;
  error?: string;
}

export interface ScannerAdapter {
  name: string;
  isAvailable(): Promise<boolean>;
  scan(targetPaths: string[], workspaceRoot: string): Promise<ScanResult>;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#e93147",
  high: "#f0883e",
  medium: "#e3b341",
  low: "#58a6ff",
  info: "#8b949e",
};
