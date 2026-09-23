import { Vulnerability } from "../types";

export function toSarif(vulns: Vulnerability[], toolVersion: string): object {
  const ruleIds = Array.from(new Set(vulns.map((v) => v.ruleId)));
  const rules = ruleIds.map((id) => {
    const sample = vulns.find((v) => v.ruleId === id)!;
    return {
      id,
      name: sample.title,
      shortDescription: { text: sample.title },
      fullDescription: { text: sample.description },
      helpUri: sample.cwe[0] ? `https://cwe.mitre.org/data/definitions/${sample.cwe[0].replace(/\D/g, "")}.html` : undefined,
      properties: { cwe: sample.cwe, owasp: sample.owasp, tags: [sample.category] },
    };
  });

  const results = vulns
    .filter((v) => v.status !== "false_positive")
    .map((v) => ({
      ruleId: v.ruleId,
      level: sarifLevel(v.severity),
      message: { text: v.description },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: v.file },
            region: { startLine: v.startLine, endLine: v.endLine },
          },
        },
      ],
      partialFingerprints: { secuguardId: v.id },
      properties: { severity: v.severity, status: v.status, cwe: v.cwe },
    }));

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SecuGuard",
            informationUri: "https://example.com/secuguard",
            version: toolVersion,
            rules,
          },
        },
        results,
      },
    ],
  };
}

function sarifLevel(severity: string): string {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "note";
  }
}

export function toMarkdownReport(vulns: Vulnerability[]): string {
  const active = vulns.filter((v) => v.status !== "false_positive");
  const bySeverity: Record<string, Vulnerability[]> = {};
  for (const v of active) {
    (bySeverity[v.severity] ||= []).push(v);
  }
  const order = ["critical", "high", "medium", "low", "info"];
  let out = `# SecuGuard Security Report\n\nGenerated: ${new Date().toISOString()}\n\n`;
  out += `**Total findings:** ${active.length}\n\n`;
  out += `| Severity | Count |\n|---|---|\n`;
  for (const s of order) out += `| ${s} | ${(bySeverity[s] || []).length} |\n`;
  out += `\n---\n\n`;

  for (const s of order) {
    const list = bySeverity[s];
    if (!list || list.length === 0) continue;
    out += `## ${s.toUpperCase()}\n\n`;
    for (const v of list) {
      out += `### ${v.title}\n`;
      out += `- **File:** \`${v.file}:${v.startLine}\`\n`;
      out += `- **CWE:** ${v.cwe.join(", ")}${v.owasp ? ` · **OWASP:** ${v.owasp}` : ""}\n`;
      out += `- **Status:** ${v.status}\n`;
      out += `- **Description:** ${v.description}\n`;
      if (v.suggestedFix) out += `- **Suggested fix:** ${v.suggestedFix}\n`;
      out += `\n`;
    }
  }
  return out;
}
