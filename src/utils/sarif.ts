import { Vulnerability, Severity } from "../types";

export interface QaChecklistItem {
  label: string;
  ok: boolean;
  count: number;
}

/**
 * QA Health Score (0–100). Starts at 100 and subtracts weighted penalties:
 * critical 10, high 6, medium 3, low 1, info 0.5; quality long-function 3,
 * nesting/debug 1; missing tests 0.5; missing docs 0.25. Clamped at the floor.
 */
export function computeQaHealthScore(vulns: Vulnerability[]): number {
  const active = vulns.filter((v) => !["fixed", "false_positive", "wont_fix"].includes(v.status));
  let penalty = 0;
  for (const v of active) {
    switch (v.severity) {
      case "critical": penalty += 10; break;
      case "high": penalty += 6; break;
      case "medium": penalty += 3; break;
      case "low": penalty += 1; break;
      default: penalty += 0.5; break;
    }
    if (v.ruleId === "sg-quality-long-function") penalty += 3;
    else if (v.ruleId === "sg-quality-nesting" || v.ruleId === "sg-quality-debug") penalty += 1;
    if (v.category === "test-coverage") penalty += 0.5;
    if (v.category === "documentation") penalty += 0.25;
  }
  return Math.max(0, Math.round(100 - penalty));
}

export const QA_HEALTH_SCORE_FORMULA = "Starts at 100; −10 critical, −6 high, −3 medium, −1 low, −0.5 info; −3 oversized functions; −1 deep nesting/debug; −0.5 missing tests; −0.25 missing docs. Clamped at 0.";

export interface QaReportData {
  generatedAt: string;
  activeCount: number;
  fixedCount: number;
  suppressedCount: number;
  todoCount: number;
  severityCounts: Record<Severity, number>;
  categoryCounts: Record<string, number>;
  /** sast/sca/secret/iac/container (active) */
  securityFindings: Vulnerability[];
  qualityFindings: Vulnerability[];
  coverageFindings: Vulnerability[];
  docFindings: Vulnerability[];
  teamActivity: { user: string; changes: number; lastAt: string }[];
  checklist: QaChecklistItem[];
}

export interface FinalReportMeta {
  userName?: string;
  aiNarrative?: string;
}

const ACTIVE_FILTER = (v: Vulnerability) => !["fixed", "false_positive", "wont_fix"].includes(v.status);
const SECURITY_CATEGORY = new Set(["sast", "sca", "secret", "iac", "container"]);

export function buildQaReportData(vulns: Vulnerability[]): QaReportData {
  const active = vulns.filter(ACTIVE_FILTER);
  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  const categoryCounts: Record<string, number> = {};
  for (const v of active) {
    severityCounts[v.severity]++;
    categoryCounts[v.category] = (categoryCounts[v.category] || 0) + 1;
  }

  const byRule = (ruleId: string) => active.filter((v) => v.ruleId === ruleId).length;
  const checklist: QaChecklistItem[] = [
    { label: "No unresolved critical/high security findings", ok: active.filter((v) => v.severity === "critical" || v.severity === "high").length === 0, count: active.filter((v) => v.severity === "critical" || v.severity === "high").length },
    { label: "No TODO/FIXME/HACK markers left", ok: byRule("sg-quality-todo") === 0, count: byRule("sg-quality-todo") },
    { label: "Every exported symbol has a test", ok: byRule("sg-test-coverage-missing") === 0, count: byRule("sg-test-coverage-missing") },
    { label: "No debug statements", ok: byRule("sg-quality-debug") === 0, count: byRule("sg-quality-debug") },
    { label: "No functions past the max-lines threshold", ok: byRule("sg-quality-long-function") === 0, count: byRule("sg-quality-long-function") },
  ];

  const userActivity = new Map<string, { changes: number; lastAt: string }>();
  for (const v of vulns) {
    for (const h of v.statusHistory ?? []) {
      const cur = userActivity.get(h.changedBy) || { changes: 0, lastAt: h.changedAt };
      cur.changes++;
      if (h.changedAt > cur.lastAt) cur.lastAt = h.changedAt;
      userActivity.set(h.changedBy, cur);
    }
  }
  const teamActivity = Array.from(userActivity.entries())
    .map(([user, u]) => ({ user, changes: u.changes, lastAt: u.lastAt }))
    .sort((a, b) => b.changes - a.changes);

  return {
    generatedAt: new Date().toISOString(),
    activeCount: active.length,
    fixedCount: vulns.filter((v) => v.status === "fixed").length,
    suppressedCount: vulns.filter((v) => v.status === "false_positive" || v.status === "wont_fix").length,
    todoCount: vulns.filter((v) => v.status === "todo").length,
    severityCounts,
    categoryCounts,
    securityFindings: active.filter((v) => SECURITY_CATEGORY.has(v.category)),
    qualityFindings: active.filter((v) => v.category === "quality"),
    coverageFindings: active.filter((v) => v.category === "test-coverage"),
    docFindings: active.filter((v) => v.category === "documentation"),
    teamActivity,
    checklist,
  };
}

function findingLines(list: Vulnerability[]): string {
  if (list.length === 0) return "_None._\n";
  const rows = list
    .map(
      (v) =>
        `| \`${v.id}\` | **${v.severity.toUpperCase()}** | ${v.status} | \`${v.file}:${v.startLine}\` | ${escMd(v.title)} | ${v.cwe.join(", ") || "—"} |`
    )
    .join("\n");
  return `\n| ID | Sev | Status | Location | Finding | CWE |\n|---|---|---|---|---|---|\n${rows}\n`;
}

function escMd(s: string): string {
  return String(s).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

export function toFinalQaReport(data: QaReportData, meta: FinalReportMeta = {}): string {
  const sevRow = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((s) => `| ${s} | ${data.severityCounts[s]} |`)
    .join("\n");
  const catRow = Object.entries(data.categoryCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([c, n]) => `| ${c} | ${n} |`)
    .join("\n");

  let out = `# SecuGuard Final QA Report\n\n`;
  out += `> Consolidated quality + security assessment · generated ${data.generatedAt}${meta.userName ? ` · by ${meta.userName}` : ""}\n\n`;

  out += `## Executive Summary\n\n`;
  const cHigh = data.severityCounts.critical + data.severityCounts.high;
  out += `**${data.activeCount}** active finding(s) across **${Object.keys(data.categoryCounts).length}** category(ies) — **${cHigh}** critical/high. `;
  out += `**${data.fixedCount}** fixed, **${data.suppressedCount}** suppressed, **${data.todoCount}** tracked as TODO.\n\n`;
  if (meta.aiNarrative) {
    out += `> **AI executive summary:** ${escMd(meta.aiNarrative)}\n\n`;
  }

  out += `### Severity breakdown\n| Severity | Count |\n|---|---|\n${sevRow}\n\n`;
  out += `### By category\n| Category | Count |\n|---|---|\n${catRow || "| _none_ | 0 |"}\n\n`;

  out += `---\n\n## 1. Security Findings\n${findingLines(data.securityFindings)}`;
  out += `\n## 2. Quality Debt\n${findingLines(data.qualityFindings)}`;
  out += `\n## 3. Test Coverage Gaps\n${findingLines(data.coverageFindings)}`;
  out += `\n## 4. Documentation Gaps\n${findingLines(data.docFindings)}`;

  out += `\n## 5. Team Activity\n\n`;
  if (data.teamActivity.length === 0) {
    out += "_No status changes recorded yet._\n";
  } else {
    out += `| User | Changes | Last change |\n|---|---|---|\n`;
    for (const a of data.teamActivity) out += `| @${a.user} | ${a.changes} | ${a.lastAt} |\n`;
    out += "\n";
  }

  out += `\n## 6. Sign-off Checklist\n\n`;
  for (const c of data.checklist) {
    out += `- ${c.ok ? "✅" : "❌"} ${c.label}${c.count > 0 ? ` (${c.count})` : ""}\n`;
  }
  out += `\n${data.checklist.every((c) => c.ok) ? "\n✅ All checks pass — ready to sign off.\n" : "\n❌ ${data.checklist.filter((c) => !c.ok).length} check(s) failing — review before sign-off.\n"}`;
  return out;
}

export function toFinalQaHtmlReport(data: QaReportData, meta: FinalReportMeta = {}): string {
  const sevOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
  const sevColor: Record<Severity, string> = {
    critical: "#e93147", high: "#f0883e", medium: "#e3b341", low: "#58a6ff", info: "#8b949e",
  };
  const chips = (list: Vulnerability[]) =>
    list.length === 0
      ? `<p class="muted">None.</p>`
      : list
          .map(
            (v) =>
              `<div class="chip"><span class="sev sev-${v.severity}">${v.severity}</span> <b>${html(v.title)}</b> <span class="mono">${html(v.file)}:${v.startLine}</span> <span class="muted">${v.status}${v.cwe.length ? " · " + html(v.cwe.join(", ")) : ""}</span></div>`
          )
          .join("\n");
  const catRows = Object.entries(data.categoryCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([c, n]) => `<div class="bar-row"><span>${html(c)}</span><div class="bar-track"><div class="bar"></div><span>${n}</span></div></div>`)
    .join("\n");
  const checklistHtml = data.checklist
    .map((c) => `<li class="${c.ok ? "ok" : "fail"}">${c.ok ? "✅" : "❌"} ${html(c.label)}${c.count ? ` <span class="count">${c.count}</span>` : ""}</li>`)
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SecuGuard Final QA Report</title>
<style>
  :root {
    --bg: var(--vscode-editor-background, #0d1117);
    --fg: var(--vscode-editor-foreground, #e6edf3);
    --card: #161b22; --border: #30363d; --accent: #4da3ff; --muted: #9aa0a6;
  }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, sans-serif; margin: 0; padding: 32px 40px 80px; background: var(--bg); color: var(--fg); }
  h1 { font-size: 24px; margin: 0 0 6px; }
  .subtitle { color: var(--muted); margin-bottom: 24px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 28px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .card .num { font-size: 26px; font-weight: 700; }
  .card .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; margin-top: 2px; }
  .narrative { background: var(--card); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 8px; padding: 14px 16px; margin-bottom: 28px; font-size: 14px; line-height: 1.6; }
  section { margin-bottom: 28px; }
  section h2 { font-size: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  td, th { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); text-transform: uppercase; font-size: 11px; }
  .chip { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 9px 12px; margin-bottom: 8px; font-size: 13px; }
  .sev { display: inline-block; padding: 1px 8px; border-radius: 20px; font-size: 10px; text-transform: uppercase; font-weight: 700; }
  .sev-critical { background: #e9314722; color: #ff6b7d; }
  .sev-high { background: #f0883e22; color: #f0883e; }
  .sev-medium { background: #e3b34122; color: #e3b341; }
  .sev-low { background: #58a6ff22; color: #58a6ff; }
  .sev-info { background: #8b949e22; color: #8b949e; }
  .mono { font-family: monospace; font-size: 12px; }
  .muted { color: var(--muted); }
  ul.check { list-style: none; padding: 0; }
  ul.check li { padding: 8px 12px; border-radius: 8px; margin-bottom: 6px; background: var(--card); border: 1px solid var(--border); font-size: 13px; }
  ul.check li.ok { border-left-color: #2da44e; border-left-width: 3px; }
  ul.check li.fail { border-left-color: #e93147; border-left-width: 3px; }
  .count { background: var(--border); border-radius: 12px; padding: 0 8px; font-size: 11px; }
  .bar-row { display: flex; align-items: center; gap: 10px; margin: 6px 0; font-size: 12px; }
  .bar-row span:first-child { width: 120px; }
  .bar-track { flex: 1; height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; display: flex; }
  .bar-track span { font-size: 11px; color: var(--muted); margin-left: 8px; }
  .bar { height: 100%; background: var(--accent); border-radius: 4px; }
</style>
</head>
<body>
  <h1>🛡 SecuGuard Final QA Report</h1>
  <div class="subtitle">Consolidated quality + security assessment · ${html(data.generatedAt)}${meta.userName ? ` · by ${html(meta.userName)}` : ""}</div>

  <div class="cards">
    <div class="card"><div class="num">${data.activeCount}</div><div class="lbl">Active findings</div></div>
    <div class="card"><div class="num" style="color:${data.severityCounts.critical + data.severityCounts.high > 0 ? "#ff6b7d" : sevColor.info}">${data.severityCounts.critical + data.severityCounts.high}</div><div class="lbl">Critical / High</div></div>
    <div class="card"><div class="num">${data.fixedCount}</div><div class="lbl">Fixed</div></div>
    <div class="card"><div class="num">${data.suppressedCount}</div><div class="lbl">Suppressed</div></div>
    <div class="card"><div class="num">${data.todoCount}</div><div class="lbl">TODOs</div></div>
  </div>

  ${meta.aiNarrative ? `<div class="narrative"><b>AI executive summary</b><br/>${html(meta.aiNarrative)}</div>` : ""}

  <section>
    <h2>Executive Summary</h2>
    <table>
      <tr><th>Severity</th>${sevOrder.map((s) => `<th>${s}</th>`).join("")}</tr>
      <tr><td>Count</td>${sevOrder.map((s) => `<td style="color:${sevColor[s]};font-weight:600">${data.severityCounts[s]}</td>`).join("")}</tr>
    </table>
    ${catRows ? `<h3 style="margin-top:18px">By Category</h3>${catRows}` : ""}
  </section>

  <section><h2>1. Security Findings (${data.securityFindings.length})</h2>${chips(data.securityFindings)}</section>
  <section><h2>2. Quality Debt (${data.qualityFindings.length})</h2>${chips(data.qualityFindings)}</section>
  <section><h2>3. Test Coverage Gaps (${data.coverageFindings.length})</h2>${chips(data.coverageFindings)}</section>
  <section><h2>4. Documentation Gaps (${data.docFindings.length})</h2>${chips(data.docFindings)}</section>

  <section>
    <h2>5. Team Activity</h2>
    ${data.teamActivity.length === 0 ? `<p class="muted">No status changes recorded yet.</p>` : `<table><tr><th>User</th><th>Changes</th><th>Last change</th></tr>${data.teamActivity.map((a) => `<tr><td>@${html(a.user)}</td><td>${a.changes}</td><td>${html(a.lastAt)}</td></tr>`).join("")}</table>`}
  </section>

  <section>
    <h2>6. Sign-off Checklist</h2>
    <ul class="check">${checklistHtml}</ul>
    <p>${data.checklist.every((c) => c.ok) ? "✅ All checks pass — ready to sign off." : `❌ ${data.checklist.filter((c) => !c.ok).length} check(s) failing — review before sign-off.`}</p>
  </section>
</body>
</html>`;
}

function html(s: string): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

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
