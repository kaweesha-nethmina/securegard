import * as vscode from "vscode";
import * as path from "path";
import { Vulnerability, Severity, SEVERITY_COLOR } from "../types";

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

function renderHtml(vulns: Vulnerability[]): string {
  const active = vulns.filter((v) => v.status !== "false_positive" && v.status !== "fixed" && v.status !== "wont_fix");
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of active) counts[v.severity]++;
  const total = active.length || 1;

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

  const rows = active
    .sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))
    .map(
      (v) => `
    <tr data-severity="${v.severity}" data-category="${v.category}" data-status="${v.status}"
        data-search="${esc((v.title + " " + v.file + " " + v.cwe.join(" ")).toLowerCase())}">
      <td><span class="badge sev-${v.severity}">${v.severity}</span></td>
      <td class="title-cell">
        <div class="finding-title">${esc(v.title)}</div>
        <div class="finding-meta">${esc(v.cwe.join(", "))}${v.owasp ? " · " + esc(v.owasp) : ""}</div>
      </td>
      <td class="mono">${esc(v.file)}:${v.startLine}</td>
      <td>${esc(v.category)}</td>
      <td>
        <select class="status-select" data-id="${v.id}">
          ${["open", "triaged", "todo", "false_positive", "wont_fix", "fixed"]
            .map((s) => `<option value="${s}" ${s === v.status ? "selected" : ""}>${s.replace("_", " ")}</option>`)
            .join("")}
        </select>
      </td>
      <td>
        <button class="icon-btn" data-action="open" data-id="${v.id}" title="Open in editor">↗</button>
        <button class="icon-btn" data-action="explain" data-id="${v.id}" title="Explain">💡</button>
        <button class="icon-btn" data-action="fix" data-id="${v.id}" title="Generate fix">🛠</button>
      </td>
    </tr>`
    )
    .join("\n");

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
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 20px; }
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
    flex: 1; min-width: 90px; text-align:center; border-radius: 8px; padding: 10px 6px;
    background: color-mix(in srgb, var(--card) 60%, transparent);
    border: 1px solid var(--border);
  }
  .stat .num { font-size: 22px; font-weight: 700; }
  .stat .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; }
  .bar-row { display:flex; align-items:center; gap:8px; margin:6px 0; font-size:12px; }
  .bar-track { flex:1; height:8px; background: var(--border); border-radius:4px; overflow:hidden; }
  .bar-fill { height:100%; background: var(--accent); border-radius:4px; }
  .toolbar { display:flex; gap:10px; align-items:center; margin: 20px 0 12px; flex-wrap: wrap; }
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
  .icon-btn { background: transparent; border: 1px solid var(--border); border-radius: 5px; cursor:pointer; padding: 3px 7px; margin-right:4px; color: var(--fg); }
  .icon-btn:hover { border-color: var(--accent); }
  .empty-state { text-align:center; padding: 60px 20px; color: var(--muted); }
  .trend-svg text { fill: var(--muted); font-size: 9px; }
</style>
</head>
<body>
  <h1>🛡 SecuGuard Dashboard</h1>
  <div class="subtitle">${active.length} active finding${active.length === 1 ? "" : "s"} · updated ${new Date().toLocaleString()}</div>

  <div class="grid-top">
    <div class="card">
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

    <div class="card">
      <h3>By Category</h3>
      ${Object.entries(categoryCounts)
        .sort((a, b) => b[1] - a[1])
        .map(
          ([cat, c]) =>
            `<div class="bar-row"><div style="width:80px">${esc(cat)}</div><div class="bar-track"><div class="bar-fill" style="width:${(c / maxCat) * 100}%"></div></div><div style="width:24px;text-align:right">${c}</div></div>`
        )
        .join("") || `<div class="empty-state">No data</div>`}
      <h3 style="margin-top:18px">Quick Stats</h3>
      <div class="stat-row">
        <div class="stat"><div class="num">${vulns.filter((v) => v.status === "fixed").length}</div><div class="lbl">Fixed</div></div>
        <div class="stat"><div class="num">${vulns.filter((v) => v.status === "todo").length}</div><div class="lbl">TODOs</div></div>
        <div class="stat"><div class="num">${vulns.filter((v) => v.status === "false_positive").length}</div><div class="lbl">Suppressed</div></div>
      </div>
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

  <div class="toolbar">
    <input type="text" id="search" placeholder="Search title, file, CWE…" />
    <select class="filter" id="severityFilter">
      <option value="">All severities</option>
      ${order.map((s) => `<option value="${s}">${s}</option>`).join("")}
    </select>
    <select class="filter" id="categoryFilter">
      <option value="">All categories</option>
      ${Object.keys(categoryCounts)
        .map((c) => `<option value="${c}">${c}</option>`)
        .join("")}
    </select>
    <button class="action" id="exportSarif">Export SARIF</button>
    <button class="action" id="exportMd">Export Markdown</button>
    <button class="action" id="rescan">Rescan Workspace</button>
  </div>

  ${
    active.length === 0
      ? `<div class="empty-state">✅ No active findings. Run <b>SecuGuard: Scan Workspace</b> to check for vulnerabilities.</div>`
      : `<table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Category</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody id="rows">${rows}</tbody>
  </table>`
  }

<script>
  const vscode = acquireVsCodeApi();
  const search = document.getElementById('search');
  const sevFilter = document.getElementById('severityFilter');
  const catFilter = document.getElementById('categoryFilter');

  function applyFilters() {
    const q = (search.value || '').toLowerCase();
    const sev = sevFilter.value;
    const cat = catFilter.value;
    document.querySelectorAll('#rows tr').forEach(tr => {
      const matchesSearch = !q || tr.dataset.search.includes(q);
      const matchesSev = !sev || tr.dataset.severity === sev;
      const matchesCat = !cat || tr.dataset.category === cat;
      tr.style.display = (matchesSearch && matchesSev && matchesCat) ? '' : 'none';
    });
  }
  search?.addEventListener('input', applyFilters);
  sevFilter?.addEventListener('change', applyFilters);
  catFilter?.addEventListener('change', applyFilters);

  document.querySelectorAll('.icon-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      vscode.postMessage({ type: btn.dataset.action, id: btn.dataset.id });
    });
  });
  document.querySelectorAll('.status-select').forEach(sel => {
    sel.addEventListener('change', () => {
      vscode.postMessage({ type: 'setStatus', id: sel.dataset.id, status: sel.value });
    });
  });
  document.getElementById('exportSarif')?.addEventListener('click', () => vscode.postMessage({ type: 'exportSarif' }));
  document.getElementById('exportMd')?.addEventListener('click', () => vscode.postMessage({ type: 'exportMd' }));
  document.getElementById('rescan')?.addEventListener('click', () => vscode.postMessage({ type: 'rescan' }));
</script>
</body>
</html>`;
}
