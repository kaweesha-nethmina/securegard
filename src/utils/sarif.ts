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
  const count = (s: string) => (bySeverity[s] || []).length;
  const cHigh = count("critical") + count("high");
  const cMed = count("medium") + count("low") + count("info");

  let out = `# SecuGuard Security QA Report\n\n`;
  out += `> Professional security assessment of the workspace. Generated ${new Date().toISOString()}.\n\n`;
  out += `| Summary | |\n|---|---|\n`;
  out += `| Total active findings | ${active.length} |\n`;
  out += `| Critical / High | ${cHigh} |\n`;
  out += `| Medium / Low / Info | ${cMed} |\n`;
  out += `\n## Executive summary\n\n`;
  out += `This report documents the security findings detected by SecuGuard in the current workspace. Each finding lists the affected file and line, the class of attack (CWE/OWASP), a description of how it can be exploited, its current triage status, and guidance on how to remediate it. Findings are grouped from most to least severe.\n\n`;
  out += `### Severity breakdown\n\n| Severity | Count |\n|---|---|\n`;
  for (const s of order) out += `| ${s} | ${count(s)} |\n`;
  out += `\n---\n\n`;

  let idx = 0;
  for (const s of order) {
    const list = (bySeverity[s] || []).sort((a, b) => (a.file + a.startLine).localeCompare(b.file + b.startLine));
    if (list.length === 0) continue;
    out += `## ${s.toUpperCase()} — ${list.length} finding(s)\n\n`;
    for (const v of list) {
      idx++;
      out += `### ${idx}. ${v.title}\n\n`;
      out += `| Field | Value |\n|---|---|\n`;
      out += `| Finding ID | \`${v.id}\` |\n`;
      out += `| Severity | **${v.severity.toUpperCase()}** |\n`;
      out += `| Status | ${v.status}${v.assignee ? ` (assigned to ${v.assignee})` : ""} |\n`;
      out += `| Location | \`${v.file}:${v.startLine}\` |\n`;
      out += `| Language | ${v.language} |\n`;
      out += `| Category | ${v.category} |\n`;
      out += `| CWE | ${v.cwe.join(", ")}${v.owasp ? ` |\n| OWASP | ${v.owasp}` : ""} |\n`;
      out += `| First detected | ${v.firstDetected} |\n`;
      out += `| Last seen | ${v.lastSeen} |\n\n`;
      out += `**What the attack is:** ${v.description}\n\n`;
      if (v.suggestedFix) out += `**Recommended fix:** ${v.suggestedFix}\n\n`;
      if (v.codeSnippet) {
        out += `**Affected snippet:**\n\n\`\`\`\n${v.codeSnippet}\n\`\`\`\n\n`;
      }
      out += `---\n\n`;
    }
  }
  return out;
}

function csvCell(s: string): string {
  const t = String(s ?? "");
  return /[",\r\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
}

export function toCsvReport(vulns: Vulnerability[]): string {
  const active = vulns.filter((v) => v.status !== "false_positive");
  const header = [
    "Finding ID",
    "Severity",
    "Status",
    "Title",
    "Rule",
    "Language",
    "Category",
    "File",
    "Start Line",
    "End Line",
    "CWE",
    "OWASP",
    "Attack / Description",
    "Suggested Fix",
    "Assignee",
    "First Detected",
    "Last Seen",
  ];
  const lines = [header.join(",")];
  for (const v of active) {
    lines.push(
      [
        v.id,
        v.severity.toUpperCase(),
        v.status,
        v.title,
        v.ruleId,
        v.language,
        v.category,
        v.file,
        String(v.startLine),
        String(v.endLine),
        v.cwe.join("; "),
        v.owasp || "",
        v.description,
        v.suggestedFix || "",
        v.assignee || "",
        v.firstDetected,
        v.lastSeen,
      ]
        .map(csvCell)
        .join(",")
    );
  }
  return lines.join("\r\n") + "\r\n";
}
