/**
 * Evidence model for a security finding.
 *
 * The old engine emitted a rule id, a line and a canned description, so a user
 * had no way to judge whether a finding was real. Every finding produced here
 * must answer four questions in the UI:
 *
 *   1. What is the exact source->sink path?      (evidence.trace)
 *   2. Why is it exploitable?                    (exploitability)
 *   3. What did the engine check before reporting? (falsePositiveNotes)
 *   4. How much do we trust it?                  (confidence + label)
 */

import { Severity, FindingCategory } from "../types";

export type ConfidenceLabel = "high" | "medium" | "low";

export interface EvidenceStep {
  kind: "source" | "propagation" | "sanitizer" | "sink" | "guard";
  line: number;
  label: string;
  detail?: string;
}

export interface SecurityFinding {
  ruleId: string;
  title: string;
  description: string;
  /** Base severity from the rule; may be adjusted by exploitability. */
  baseSeverity: Severity;
  /** Severity after exploitability/reachability adjustment. */
  severity: Severity;
  cwe: string[];
  owasp?: string;
  category: FindingCategory;
  /** Workspace-relative path. */
  file: string;
  startLine: number;
  endLine: number;
  startCol?: number;
  endCol?: number;
  codeSnippet: string;
  sourceScanner: string;
  remediation?: string;
  /** File extension. Assigned by the scanner, which knows the walked path. */
  language?: string;

  /** 0-1. Findings below the configured threshold are hidden, not deleted. */
  confidence: number;
  confidenceLabel: ConfidenceLabel;
  /** Ordered source -> propagation -> sink path. */
  evidence: EvidenceStep[];
  /** Why an attacker can actually reach this. */
  exploitability: string;
  /** What the engine verified to avoid a false positive. */
  falsePositiveNotes: string[];
  /** True when the sink is reached from an unauthenticated HTTP route. */
  reachableFromHttp: boolean;
  /** File is a test/seed/migration — caps severity unless exploitability is proven. */
  testish: boolean;
}

/** Maps a 0-1 score onto the three user-facing buckets. */
export function confidenceLabel(score: number): ConfidenceLabel {
  if (score >= 0.85) return "high";
  if (score >= 0.7) return "medium";
  return "low";
}

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}

export function lowerSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b) ? a : b;
}

/**
 * Adjusts severity using exploitability rather than trusting the rule's constant.
 *
 * The rule author states the worst case; this function states the actual case.
 * A genuine SQLi in a migration script is not the same risk as one in an
 * unauthenticated route, and reporting both as `critical` is how a tool loses
 * its user's trust.
 */
export function scoreSeverity(input: {
  base: Severity;
  reachableFromHttp: boolean;
  testish: boolean;
  confidence: number;
  /** Number of independent guards found (auth middleware, validation, allow-list). */
  guardCount: number;
}): { severity: Severity; rationale: string } {
  const reasons: string[] = [];

  if (input.testish) {
    // Test/seed/migration files are not shipped, so a finding there is capped
    // regardless of what the taint trace says: `req.query` inside a test is a
    // literal fixture, not an attacker-controlled route parameter.
    const cap = input.confidence >= 0.9 ? "low" : "info";
    reasons.push(
      input.reachableFromHttp
        ? "located in test/seed/migration code; the HTTP source is a fixture, not a live route"
        : "located in test/seed/migration code with no HTTP reachability"
    );
    return { severity: cap, rationale: reasons.join("; ") };
  }

  let severity = input.base;

  if (input.reachableFromHttp) {
    reasons.push("sink is reachable from an HTTP route");
    severity = maxSeverity(severity, severity === "medium" ? "high" : severity);
  } else {
    severity = lowerSeverity(severity, "high");
    if (SEVERITY_ORDER.indexOf(severity) <= SEVERITY_ORDER.indexOf("high")) {
      reasons.push("no HTTP reachability proven");
    }
  }

  if (input.guardCount > 0) {
    reasons.push(`${input.guardCount} guard(s) found upstream`);
    severity = lowerSeverity(severity, "low");
  }

  if (input.confidence < 0.7) {
    severity = lowerSeverity(severity, "low");
    reasons.push("confidence below the reporting threshold — reported as review item");
  }

  return { severity, rationale: reasons.join("; ") || "no adjustment" };
}