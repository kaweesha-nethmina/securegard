import * as vscode from "vscode";
import * as path from "path";
import { Vulnerability, Severity, SEVERITY_COLOR } from "../types";
import { computeQaHealthScore, QA_HEALTH_SCORE_FORMULA } from "../utils/sarif";

export class DashboardPanel {
  static current: DashboardPanel | undefined;
  private panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  static show(
    context: vscode.ExtensionContext,
    getVulns: () => Vulnerability[],
    workspaceRoot: string,
    onMessage: (msg: any) => void
  ) {
    if (DashboardPanel.current) {
      DashboardPanel.current.panel.reveal();
      DashboardPanel.current.update(getVulns());
      return;
    }
    const panel = vscode.window.createWebviewPanel("secuguardDashboard", "SecuGuard Dashboard", vscode.ViewColumn.Active, {
      enableScripts: true,
      retainContextWhenHidden: true,
    });
    panel.iconPath = vscode.Uri.joinPath(context.extensionUri, "resources", "shield.svg");
    DashboardPanel.current = new DashboardPanel(panel, getVulns, workspaceRoot, onMessage);
  }

  static refreshIfOpen(vulns: Vulnerability[]) {
    DashboardPanel.current?.update(vulns);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    private getVulns: () => Vulnerability[],
    private workspaceRoot: string,
    onMessage: (msg: any) => void
  ) {
    this.panel = panel;
    this.update(getVulns());
    this.panel.webview.onDidReceiveMessage(onMessage, null, this.disposables);
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  update(vulns: Vulnerability[]) {
    this.panel.webview.html = renderHtml(vulns);
  }

  dispose() {
    DashboardPanel.current = undefined;
    this.disposables.forEach((d) => d.dispose());
    this.panel.dispose();
  }
}

function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

const SECURITY_CATEGORIES = new Set(["sast", "sca", "secret", "iac", "container"]);

function renderHtml(vulns: Vulnerability[]): string {
  const active = vulns.filter((v) => v.status !== "false_positive" && v.status !== "fixed" && v.status !== "wont_fix");
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of active) counts[v.severity]++;
  const total = active.length || 1;

  const security = active.filter((v) => SECURITY_CATEGORIES.has(v.category));
  const quality = active.filter((v) => v.category === "quality");
  const coverage = active.filter((v) => v.category === "test-coverage");
  const docs = active.filter((v) => v.category === "documentation");
  const qaScore = computeQaHealthScore(vulns);

  // donut chart geometry
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const arcs = order
    .filter((s) => counts[s] > 0)
    .map((s) => {
      const frac = counts[s] / total;
      const len = frac * circumference;
      const dasharray = `${len} ${circumference - len}`;
      const dashoffset = -offset;
      offset += len;
      return `<circle r="${radius}" cx="90" cy="90" fill="transparent" stroke="${SEVERITY_COLOR[s]}" stroke-width="26"
        stroke-dasharray="${dasharray}" stroke-dashoffset="${dashoffset}" transform="rotate(-90 90 90)" />`;
    })
    .join("\n");

  // category breakdown (bar)
  const categoryCounts: Record<string, number> = {};
  for (const v of active) categoryCounts[v.category] = (categoryCounts[v.category] || 0) + 1;
  const maxCat = Math.max(1, ...Object.values(categoryCounts));

  // trend: findings by day first-detected (last 14 days)
  const days: string[] = [];
  const today = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    days.push(d.toISOString().slice(0, 10));
  }
  const trendCounts = days.map((day) => vulns.filter((v) => v.firstDetected.slice(0, 10) === day).length);
  const maxTrend = Math.max(1, ...trendCounts);
  const trendPoints = trendCounts
    .map((c, i) => `${(i / (days.length - 1)) * 560},${80 - (c / maxTrend) * 70}`)
    .join(" ");

  const row = (v: Vulnerability) => `
    <tr data-severity="${v.severity}" data-category="${v.category}" data-status="${v.status}"
        data-quality-type="${v.ruleId}"
        data-search="${esc((v.title + " " + v.file + " " + v.cwe.join(" ")).toLowerCase())}">
      <td><span class="badge sev-${v.severity}">${v.severity}</span></td>
      <td class="title-cell">
        <div class="finding-title">${esc(v.title)}</div>
        <div class="finding-meta">${esc(v.cwe.join(", "))}${v.owasp ? " · " + esc(v.owasp) : ""}${v.effort ? " · effort: " + v.effort : ""}</div>
      </td>
      <td class="mono">${esc(v.file)}:${v.startLine}</td>
      <td>${esc(v.category)}</td>
      <td class="actions-cell">
        <select class="status-select tip" data-id="${v.id}" data-tooltip="Change status of this finding">
          ${["open", "triaged", "todo", "false_positive", "wont_fix", "fixed"]
            .map((s) => `<option value="${s}" ${s === v.status ? "selected" : ""}>${s.replace("_", " ")}</option>`)
            .join("")}
        </select>
        <button class="icon-btn tip" data-action="open" data-id="${v.id}" data-tooltip="Open in editor">↗</button>
        <button class="icon-btn tip" data-action="explain" data-id="${v.id}" data-tooltip="Explain & fix — attack info, AI triage, fix guide">🧠</button>
        ${v.aiExplanation ? `<button class="icon-btn tip" data-action="refreshAi" data-id="${v.id}" data-tooltip="Re-run AI analysis">🔄</button>` : ""}
        ${v.category === "test-coverage" ? `<button class="icon-btn tip" data-action="generateTest" data-id="${v.id}" data-tooltip="Generate a unit test for this symbol">🧪</button>` : ""}
        <button class="icon-btn tip" data-action="showHistory" data-id="${v.id}" data-tooltip="View status history">🕘</button>
      </td>
    </tr>`;

  const tableFor = (list: Vulnerability[]) => `
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Category</th><th>Status & Actions</th></tr></thead>
      <tbody>${list
        .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || a.file.localeCompare(b.file) || a.startLine - b.startLine)
        .map(row)
        .join("\n")}</tbody>
    </table>`;

  const emptyTable = (msg: string) => `<div class="empty-state">${msg}</div>`;

  const kpi = (num: number, label: string, tooltip?: string) =>
    `<div class="stat ${tooltip ? "tip" : ""}" ${tooltip ? `data-tooltip="${esc(tooltip)}"` : ""}><div class="num">${num}</div><div class="lbl">${label}</div></div>`;

  const qualityTypeLabels: Record<string, string> = {
    all: "All quality findings",
    "sg-quality-todo": "TODO/FIXME/HACK markers",
    "sg-quality-long-function": "Oversized functions",
    "sg-quality-nesting": "Deeply nested code",
    "sg-quality-debug": "Debug statements",
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SecuGuard Dashboard</title>
<style>
  :root {
    --bg: var(--vscode-editor-background);
    --fg: var(--vscode-editor-foreground);
    --card: var(--vscode-sideBar-background, #1e1e1e);
    --border: var(--vscode-panel-border, #3a3a3a);
    --accent: var(--vscode-focusBorder, #4da3ff);
    --muted: var(--vscode-descriptionForeground, #9aa0a6);
  }
  * { box-sizing: border-box; }
  body {
    font-family: var(--vscode-font-family, -apple-system, sans-serif);
    background: var(--bg); color: var(--fg);
    margin: 0; padding: 24px 28px 60px;
  }
  h1 { font-size: 20px; margin: 0 0 4px; display:flex; align-items:center; gap:8px; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 18px; }

  .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin-bottom: 20px; flex-wrap: wrap; }
  .tab {
    background: transparent; border: none; border-bottom: 2px solid transparent; color: var(--muted);
    padding: 9px 14px; font-size: 12.5px; font-weight: 600; cursor: pointer;
  }
  .tab:hover { color: var(--fg); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab .badge-tab { background: var(--border); border-radius: 12px; padding: 0 7px; font-size: 10px; margin-left: 5px; }
  .tab.active .badge-tab { background: var(--accent); color: #08121f; }

  .grid-top { display: grid; grid-template-columns: 220px 1fr 1fr; gap: 16px; margin-bottom: 22px; }
  .card {
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 16px; transition: transform .15s ease, box-shadow .15s ease;
  }
  .card:hover { box-shadow: 0 4px 18px rgba(0,0,0,.25); }
  .card h3 { margin: 0 0 10px; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  .donut-wrap { display:flex; align-items:center; gap:14px; }
  .legend { font-size: 12px; }
  .legend div { display:flex; align-items:center; gap:6px; margin: 3px 0; }
  .dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
  .stat-row { display:flex; gap: 10px; flex-wrap: wrap; }
  .stat {
    flex: 1; min-width: 100px; text-align:center; border-radius: 8px; padding: 12px 6px;
    background: color-mix(in srgb, var(--card) 60%, transparent);
    border: 1px solid var(--border);
  }
  .stat .num { font-size: 22px; font-weight: 700; }
  .stat .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; }
  .score-num { font-size: 34px; font-weight: 800; color: var(--accent); }
  .bar-row { display:flex; align-items:center; gap:8px; margin:6px 0; font-size:12px; }
  .bar-track { flex:1; height:8px; background: var(--border); border-radius:4px; overflow:hidden; }
  .bar-fill { height:100%; background: var(--accent); border-radius:4px; }

  .actions-row { display: flex; gap: 10px; margin: 0 0 22px; flex-wrap: wrap; }
  .quick-btn {
    background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: 6px;
    padding: 9px 14px; font-size: 12px; cursor: pointer;
  }
  .quick-btn:hover { border-color: var(--accent); }
  .quick-btn.primary { border-color: var(--accent); }

  .toolbar { display:flex; gap:10px; align-items:center; margin: 0 0 12px; flex-wrap: wrap; }
  input[type=text] {
    background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: 6px;
    padding: 7px 10px; font-size: 13px; min-width: 240px;
  }
  select.filter, button.action {
    background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: 6px;
    padding: 7px 10px; font-size: 12px; cursor: pointer;
  }
  button.action:hover, select.filter:hover { border-color: var(--accent); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align:left; padding: 8px 10px; color: var(--muted); font-weight:600; font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--border); position: sticky; top:0; background: var(--bg); }
  td { padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:hover td { background: color-mix(in srgb, var(--card) 50%, transparent); }
  .mono { font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; color: var(--muted); }
  .finding-title { font-weight: 600; }
  .finding-meta { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .badge { padding: 2px 8px; border-radius: 20px; font-size: 10px; text-transform: uppercase; font-weight:700; letter-spacing:.03em; }
  .sev-critical { background: #e9314722; color: #ff6b7d; border:1px solid #e9314755; }
  .sev-high { background: #f0883e22; color: #f0883e; border:1px solid #f0883e55; }
  .sev-medium { background: #e3b34122; color: #e3b341; border:1px solid #e3b34155; }
  .sev-low { background: #58a6ff22; color: #58a6ff; border:1px solid #58a6ff55; }
  .sev-info { background: #8b949e22; color: #8b949e; border:1px solid #8b949e55; }
  .status-select { background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: 5px; padding: 3px 6px; font-size: 11px; }
  .actions-cell { display: flex; align-items: center; gap: 4px; white-space: nowrap; }
  .icon-btn { background: transparent; border: 1px solid var(--border); border-radius: 5px; cursor:pointer; padding: 3px 7px; margin-right:4px; color: var(--fg); position: relative; }
  .icon-btn:hover { border-color: var(--accent); }
  .tip { position: relative; }
  .tip::after {
    content: attr(data-tooltip);
    position: absolute; bottom: calc(100% + 6px); left: 50%;
    transform: translateX(-50%);
    background: var(--vscode-editorWidget-background, #252526);
    color: var(--vscode-editorWidget-foreground, #cccccc);
    border: 1px solid var(--vscode-widget-border, #454545);
    padding: 4px 8px; border-radius: 4px; font-size: 11px; white-space: nowrap;
    opacity: 0; pointer-events: none; z-index: 10;
    transition: opacity .12s ease; box-shadow: 0 2px 8px rgba(0,0,0,.3);
  }
  .tip:hover::after { opacity: 1; }
  .empty-state { text-align:center; padding: 50px 20px; color: var(--muted); }
  .trend-svg text { fill: var(--muted); font-size: 9px; }

  .chip-row { display: flex; gap: 6px; margin-bottom: 12px; flex-wrap: wrap; }
  .chip {
    background: var(--card); color: var(--muted); border: 1px solid var(--border); border-radius: 20px;
    padding: 5px 12px; font-size: 11.5px; cursor: pointer;
  }
  .chip.active { color: var(--accent); border-color: var(--accent); }

  .coverage-summary { display:flex; align-items:center; gap:16px; margin-bottom: 14px; }
  .coverage-summary .ratio { font-size: 24px; font-weight: 700; }
  .coverage-summary .lbl { color: var(--muted); font-size: 12px; }

  .report-options { display: flex; flex-direction: column; gap: 10px; max-width: 560px; }
  .report-options label { display: flex; gap: 10px; align-items: center; font-size: 13px; cursor: pointer; background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; }
  .report-options input { accent-color: var(--accent); }
  .divider { border: none; border-top: 1px solid var(--border); margin: 22px 0; }
</style>
</head>
<body>
  <h1>🛡 SecuGuard Dashboard</h1>
  <div class="subtitle">${active.length} active finding${active.length === 1 ? "" : "s"} · updated ${new Date().toLocaleString()}</div>

  <div class="tabs">
    <button class="tab" data-tab="overview">Overview</button>
    <button class="tab" data-tab="security">Security<span class="badge-tab">${security.length}</span></button>
    <button class="tab" data-tab="quality">Quality<span class="badge-tab">${quality.length}</span></button>
    <button class="tab" data-tab="coverage">Test Coverage<span class="badge-tab">${coverage.length}</span></button>
    <button class="tab" data-tab="docs">Documentation<span class="badge-tab">${docs.length}</span></button>
    <button class="tab" data-tab="reports">Reports</button>
  </div>

  <!-- OVERVIEW -->
  <section class="tab-section" id="tab-overview">
    <div class="stat-row" style="margin-bottom:18px">
      ${kpi(active.length, "Active findings")}
      ${kpi(counts.critical + counts.high, "Critical / High", "Critical deblends 10, high 6 from the QA health score")}
      ${kpi(security.length, "Security")}
      ${kpi(quality.length, "Quality debt")}
      ${kpi(coverage.length, "Missing tests")}
      ${kpi(docs.length, "Missing docs")}
    </div>

    <div class="grid-top" style="grid-template-columns: 220px 1fr 1fr">
      <div class="card">
        <h3>QA Health Score</h3>
        <div class="tip" data-tooltip="${esc(QA_HEALTH_SCORE_FORMULA)}" style="display:flex;flex-direction:column;align-items:center;gap:4px;padding:8px 0">
          <div class="score-num">${qaScore}</div>
          <div class="stat lbl">/ 100</div>
          <div class="finding-meta">${qaScore >= 85 ? "Healthy" : qaScore >= 60 ? "Needs attention" : "High risk"}</div>
        </div>
      </div>
      <div class="card">
        <h3>By Category</h3>
        ${Object.entries(categoryCounts)
          .sort((a, b) => b[1] - a[1])
          .map(
            ([cat, c]) =>
              `<div class="bar-row"><div style="width:110px">${esc(cat)}</div><div class="bar-track"><div class="bar-fill" style="width:${(c / maxCat) * 100}%"></div></div><div style="width:24px;text-align:right">${c}</div></div>`
          )
          .join("") || `<div class="empty-state">No data</div>`}
      </div>
      <div class="card">
        <h3>New Findings — Last 14 Days</h3>
        <svg class="trend-svg" width="100%" height="100" viewBox="0 0 580 100" preserveAspectRatio="none">
          <polyline fill="none" stroke="var(--accent)" stroke-width="2" points="${trendPoints}" />
          <line x1="0" y1="80" x2="560" y2="80" stroke="var(--border)" stroke-width="1"/>
        </svg>
        <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--muted)">
          <span>${days[0]}</span><span>${days[days.length - 1]}</span>
        </div>
      </div>
    </div>

    <div class="card" style="max-width:560px">
      <h3>Severity Breakdown</h3>
      <div class="donut-wrap">
        <svg width="180" height="180" viewBox="0 0 180 180">
          ${arcs || `<circle r="${radius}" cx="90" cy="90" fill="transparent" stroke="var(--border)" stroke-width="26" />`}
          <text x="90" y="86" text-anchor="middle" font-size="26" font-weight="700" fill="var(--fg)">${active.length}</text>
          <text x="90" y="104" text-anchor="middle" font-size="10" fill="var(--muted)">FINDINGS</text>
        </svg>
        <div class="legend">
          ${order
            .filter((s) => counts[s] > 0)
            .map((s) => `<div><span class="dot" style="background:${SEVERITY_COLOR[s]}"></span>${s} — ${counts[s]}</div>`)
            .join("")}
        </div>
      </div>
    </div>
  </section>

  <!-- SECURITY / QUALITY / COVERAGE / DOCS (shared table shell) -->
  <section class="tab-section" id="tab-security" hidden>
    <div class="toolbar">
      <input type="text" id="search" placeholder="Search title, file, CWE…" />
      <select class="filter" id="severityFilter">
        <option value="">All severities</option>
        ${order.map((s) => `<option value="${s}">${s}</option>`).join("")}
      </select>
      <select class="filter" id="categoryFilter">
        <option value="">All categories</option>
        ${Object.keys(categoryCounts).map((c) => `<option value="${c}">${c}</option>`).join("")}
      </select>
      <button class="action tip" id="rescan" data-tooltip="Re-run a full workspace scan to refresh findings">Rescan Workspace</button>
    </div>
    ${security.length === 0 ? emptyTable("No active security findings. Run <b>SecuGuard: Scan Workspace</b> to rescan.") : tableFor(security)}
  </section>

  <section class="tab-section" id="tab-quality" hidden>
    <div class="chip-row" id="qualityChips">
      ${Object.entries(qualityTypeLabels)
        .map(([id, label], i) => `<button class="chip ${i === 0 ? "active" : ""}" data-qtype="${id}">${label} <span class="badge-tab">${id === "all" ? quality.length : quality.filter((q) => q.ruleId === id).length}</span></button>`)
        .join("")}
    </div>
    ${quality.length === 0 ? emptyTable("No quality debt found. Nice job keeping the codebase tidy.") : tableFor(quality)}
  </section>

  <section class="tab-section" id="tab-coverage" hidden>
    <div class="coverage-summary card">
      <div class="ratio">${coverage.length === 0 ? "100%" : `${active.length - coverage.length}/${active.length}`}</div>
      <div class="lbl">exported symbol${coverage.length === 1 ? "" : "s"} with an associated test found across all categories</div>
      <button class="quick-btn primary" id="genAllTests">🧪 Generate All Missing Tests (${coverage.length})</button>
    </div>
    ${coverage.length === 0 ? emptyTable("Every exported symbol has a test. Excellent.") : tableFor(coverage)}
  </section>

  <section class="tab-section" id="tab-docs" hidden>
    ${docs.length === 0 ? emptyTable("Every exported symbol is documented. Impressive.") : tableFor(docs)}
  </section>

  <!-- REPORTS -->
  <section class="tab-section" id="tab-reports" hidden>
    <div class="card report-options">
      <h3>Final QA Report (Markdown + self-contained HTML)</h3>
      <label><input type="checkbox" id="optMd" checked /> Markdown (.md)</label>
      <label><input type="checkbox" id="optHtml" checked /> HTML (.html)</label>
      <label><input type="checkbox" id="optAi" /> Include AI executive summary <span class="finding-meta">(uses ${"secuguard.ai"} settings; skips if AI disabled)</span></label>
      <div><button class="quick-btn primary" id="genFinalReport">Generate Final QA Report</button></div>
    </div>

    <hr class="divider" />
    <div class="card" style="max-width:320px">
      <h3>Raw exports (unchanged format)</h3>
      <div style="display:flex;flex-direction:column;gap:8px">
        <button class="quick-btn" data-export="markdown">Markdown summary (.md)</button>
        <button class="quick-btn" data-export="csv">CSV spreadsheet (.csv)</button>
        <button class="quick-btn" data-export="sarif">SARIF (.sarif)</button>
        <button class="quick-btn" data-export="json">JSON (.json)</button>
      </div>
    </div>
  </section>

<script>
  const vscode = acquireVsCodeApi();
  const state = vscode.getState() || {};
  let currentTab = state.tab || 'overview';

  function switchTab(tab) {
    currentTab = tab;
    vscode.setState({ tab });
    document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    document.querySelectorAll('.tab-section').forEach(s => { s.hidden = s.id !== 'tab-' + tab; });
    applyFilters();
  }
  document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
  switchTab(currentTab);

  const search = document.getElementById('search');
  const sevFilter = document.getElementById('severityFilter');
  const catFilter = document.getElementById('categoryFilter');

  function visibleSection() {
    return document.querySelector('.tab-section:not([hidden])');
  }
  function applyFilters() {
    const section = visibleSection();
    if (!section) return;
    const q = (search && search.value || '').toLowerCase();
    const sev = sevFilter ? sevFilter.value : '';
    const cat = catFilter ? catFilter.value : '';
    const qtype = document.querySelector('#qualityChips .chip.active')?.dataset.qtype || 'all';
    section.querySelectorAll('tbody tr').forEach(tr => {
      const okSearch = !q || tr.dataset.search.includes(q);
      const okSev = !sev || tr.dataset.severity === sev;
      const okCat = !cat || tr.dataset.category === cat;
      const okQtype = qtype === 'all' || tr.dataset.qualityType === qtype;
      tr.style.display = (okSearch && okSev && okCat && okQtype) ? '' : 'none';
    });
  }
  search?.addEventListener('input', applyFilters);
  sevFilter?.addEventListener('change', applyFilters);
  catFilter?.addEventListener('change', applyFilters);
  document.querySelectorAll('#qualityChips .chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('#qualityChips .chip').forEach(c => c.classList.toggle('active', c === chip));
      applyFilters();
    });
  });

  document.querySelectorAll('.icon-btn').forEach(btn => {
    btn.addEventListener('click', () => vscode.postMessage({ type: btn.dataset.action, id: btn.dataset.id }));
  });
  document.querySelectorAll('.status-select').forEach(sel => {
    sel.addEventListener('change', () => vscode.postMessage({ type: 'setStatus', id: sel.dataset.id, status: sel.value }));
  });
  document.getElementById('rescan')?.addEventListener('click', () => vscode.postMessage({ type: 'rescan' }));
  document.getElementById('genAllTests')?.addEventListener('click', () => vscode.postMessage({ type: 'generateAllTests' }));

  document.getElementById('genFinalReport')?.addEventListener('click', () => vscode.postMessage({
    type: 'generateFinalReport',
    formats: [ ...(document.getElementById('optMd').checked ? ['markdown'] : []), ...(document.getElementById('optHtml').checked ? ['html'] : []) ],
    includeAi: document.getElementById('optAi').checked
  }));
  document.querySelectorAll('[data-export]').forEach(btn => {
    btn.addEventListener('click', () => vscode.postMessage({ type: 'exportRaw', format: btn.dataset.export }));
  });
</script>
</body>
</html>`;
}