import * as crypto from "crypto";
import { RawFinding, Vulnerability, VulnStatus } from "../types";

function stableId(f: RawFinding): string {
  const basis = `${f.ruleId}::${f.file}::${f.startLine}::${f.codeSnippet.trim().slice(0, 80)}`;
  return "sg-" + crypto.createHash("sha1").update(basis).digest("hex").slice(0, 16);
}

/**
 * Converts raw scanner output into the unified Vulnerability model, merging
 * findings from different scanners that point at the same file+line into one
 * record (keeping the higher severity and combining rule/CWE info).
 */
export function normalize(
  raw: RawFinding[],
  existing: Map<string, Vulnerability>,
  now: string,
  baselineMode: boolean
): Vulnerability[] {
  const byLocation = new Map<string, RawFinding[]>();
  for (const f of raw) {
    const key = `${f.file}::${f.startLine}`;
    if (!byLocation.has(key)) byLocation.set(key, []);
    byLocation.get(key)!.push(f);
  }

  const severityRank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const results: Vulnerability[] = [];

  for (const [, group] of byLocation) {
    // within a location, one Vulnerability per distinct ruleId (different rules = different issues,
    // even on the same line — e.g. hardcoded secret + weak hash on one line)
    const byRule = new Map<string, RawFinding[]>();
    for (const f of group) {
      if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, []);
      byRule.get(f.ruleId)!.push(f);
    }

    for (const [, dupes] of byRule) {
      const primary = dupes.reduce((best, cur) =>
        severityRank[cur.severity] > severityRank[best.severity] ? cur : best
      );
      const id = stableId(primary);
      const prior = existing.get(id);

      const status: VulnStatus = prior ? prior.status : baselineMode ? "todo" : "open";

      results.push({
        id,
        ruleId: primary.ruleId,
        title: primary.title,
        description: primary.description,
        severity: primary.severity,
        cwe: primary.cwe,
        owasp: primary.owasp,
        category: primary.category,
        language: primary.language,
        file: primary.file,
        startLine: primary.startLine,
        endLine: primary.endLine,
        startCol: primary.startCol,
        endCol: primary.endCol,
        codeSnippet: primary.codeSnippet,
        sourceScanner: dupes.map((d) => d.sourceScanner).join(", "),
        suggestedFix: primary.remediation,
        status: prior?.status === "false_positive" ? "false_positive" : status,
        firstDetected: prior?.firstDetected ?? now,
        lastSeen: now,
        assignee: prior?.assignee,
        notes: prior?.notes ?? [],
        linkedTodoId: prior?.linkedTodoId,
        aiExplanation: prior?.aiExplanation,
        aiConfidence: prior?.aiConfidence,
        falsePositiveReason: prior?.falsePositiveReason,
        baseline: prior?.baseline ?? baselineMode,
      });
    }
  }

  return results;
}
