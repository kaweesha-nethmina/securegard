import * as vscode from "vscode";
import { ReadinessReport } from "../engine/readiness";

export class ReadinessPanel {
  static current: ReadinessPanel | undefined;
  private panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  static show(context: vscode.ExtensionContext, report: ReadinessReport, onMessage: (msg: any) => void) {
    if (ReadinessPanel.current) {
      ReadinessPanel.current.panel.reveal();
      ReadinessPanel.current.update(report);
      return;
    }
    const panel = vscode.window.createWebviewPanel("secuguardReadiness", "SecuGuard QA Readiness", vscode.ViewColumn.Active, {
      enableScripts: true,
      retainContextWhenHidden: true,
    });
    panel.iconPath = vscode.Uri.joinPath(context.extensionUri, "resources", "shield.svg");
    ReadinessPanel.current = new ReadinessPanel(panel, report, onMessage);
  }

  static refreshIfOpen(report: ReadinessReport) {
    ReadinessPanel.current?.update(report);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    report: ReadinessReport,
    onMessage: (msg: any) => void
  ) {
    this.panel = panel;
    this.update(report);
    this.panel.webview.onDidReceiveMessage(onMessage, null, this.disposables);
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  update(report: ReadinessReport) {
    this.panel.webview.html = renderHtml(report);
  }

  dispose() {
    ReadinessPanel.current = undefined;
    this.disposables.forEach((d) => d.dispose());
    this.panel.dispose();
  }
}

function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function renderHtml(report: ReadinessReport): string {
  const overallOk = report.notGitRepo ? false : report.checks.every((c) => c.ok);
  const passed = report.checks.filter((c) => c.ok).length;

  const rows = report.checks
    .map(
      (c) => `
    <details ${c.items.length > 0 && !c.ok ? "open" : ""} class="check ${c.ok ? "ok" : "fail"}">
      <summary>
        <span class="mark">${c.ok ? "✅" : "❌"}</span>
        <span class="label">${esc(c.label)}</span>
        ${c.items.length > 0 ? `<span class="count">${c.items.length}</span>` : ""}
      </summary>
      ${
        c.items.length === 0
          ? `<div class="clean">No issues — clean.</div>`
          : `<ul>${c.items
              .map(
                (it) =>
                  `<li><a href="#" class="link" data-file="${esc(it.file)}" data-line="${it.line}" title="Open in editor">${esc(it.file)}:${it.line}</a> — ${esc(it.title)}</li>`
              )
              .join("")}</ul>`
      }
    </details>`
    )
    .join("\n");

  const pw = report.projectWide;
  const pwAll = pw ? pw.counts.reduce((s, c) => s + c.count, 0) : 0;
  const projectWideCard = pw
    ? `<div class="meta pw" style="margin-top:18px">Project-wide QA state — <b>entire workspace</b> scanned (${pw.filesScanned} files, ${pw.durationMs}ms), not just changed files:</div>
  <div class="card titled">
    <div class="pwhead">${pwAll === 0 ? "No active findings across any category." : `${pwAll} active findings across ${pw.counts.length} categories`}</div>
    <div class="chips">${pw.counts.map((c) => `<span class="chip">${esc(c.category)}: ${c.count}</span>`).join("")}</div>
    <button class="action" id="openDashboard" style="margin-top:10px">Open QA Dashboard</button>
  </div>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SecuGuard QA Readiness</title>
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
  body { font-family: var(--vscode-font-family, -apple-system, sans-serif); background: var(--bg); color: var(--fg); margin: 0; padding: 24px 28px 60px; }
  h1 { font-size: 20px; margin: 0 0 4px; display: flex; align-items: center; gap: 8px; }
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 20px; }
  .banner { border-radius: 10px; padding: 14px 16px; margin-bottom: 16px; border: 1px solid; font-size: 13px; }
  .banner.pass { background: #2da44e22; border-color: #2da44e55; color: #57ab5a; }
  .banner.fail { background: #e9314722; border-color: #e9314755; color: #ff6b7d; }
  .banner.info { background: #58a6ff22; border-color: #58a6ff55; color: #58a6ff; }
  .meta { color: var(--muted); font-size: 12px; margin-bottom: 18px; }
  .meta b { color: var(--fg); font-weight: 600; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 8px 4px; }
  details.check { border-left: 3px solid var(--border); margin-bottom: 6px; padding: 6px 10px; border-radius: 6px; }
  details.check.ok { border-left-color: #2da44e; }
  details.check.fail { border-left-color: #e93147; }
  details summary { display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 13px; padding: 4px 0; list-style: none; }
  details summary::-webkit-details-marker { display: none; }
  .mark { font-size: 14px; }
  .label { font-weight: 600; }
  .count { margin-left: auto; background: var(--border); border-radius: 12px; padding: 1px 9px; font-size: 11px; }
  ul { margin: 4px 0 4px 28px; padding: 0; font-size: 12.5px; }
  li { margin: 5px 0; line-height: 1.4; }
  .link { color: var(--accent); text-decoration: none; font-family: var(--vscode-editor-font-family, monospace); font-size: 12px; }
  .link:hover { text-decoration: underline; }
  .clean { margin: 2px 0 4px 26px; color: var(--muted); font-size: 12px; }
  .pw { margin-bottom: 8px; }
  .pwhead { font-weight: 600; font-size: 13px; padding: 6px 10px; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; padding: 0 10px; }
  .chip { background: var(--border); border-radius: 12px; padding: 2px 10px; font-size: 11px; color: var(--fg); }
  .toolbar { display: flex; gap: 10px; margin-bottom: 14px; justify-content: flex-end; }
  button.action {
    background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 12px; font-size: 12px; cursor: pointer;
  }
  button.action:hover { border-color: var(--accent); }
</style>
</head>
<body>
  <h1>🛡 SecuGuard QA Readiness</h1>
  <div class="subtitle">Automated pre-PR quality gate for the changes in your working tree</div>

  <div class="toolbar">
    <button class="action" id="genTests" title="Generate unit tests for every exported symbol without a test">Generate Missing Tests</button>
    <button class="action" id="copy" disabled="${report.notGitRepo ? "disabled" : ""}">Copy as PR comment</button>
  </div>

  ${
    report.notGitRepo
      ? `<div class="banner info">Not a git repository or git is unavailable — the readiness checks were skipped. Run the check inside a git worktree.</div>`
      : `<div class="banner ${overallOk ? "pass" : "fail"}"><b>${overallOk ? "Ready to merge ✅" : "Not ready — fix before merging"}</b> · ${passed}/${report.checks.length} checks passed</div>`
  }

  <div class="meta">Base branch: <b>${esc(report.baseBranch)}</b> · Changed files: <b>${report.changedFiles.length}</b></div>

  <div class="card">${rows}</div>

  ${projectWideCard}

<script>
  const vscode = acquireVsCodeApi();
  document.getElementById('copy')?.addEventListener('click', () => vscode.postMessage({ type: 'copy' }));
  document.getElementById('genTests')?.addEventListener('click', () => vscode.postMessage({ type: 'generateMissingTests' }));
  document.getElementById('openDashboard')?.addEventListener('click', () => vscode.postMessage({ type: 'openDashboard' }));
  document.querySelectorAll('.link').forEach(a => {
    a.addEventListener('click', (e) => {
      e.preventDefault();
      vscode.postMessage({ type: 'open', file: a.dataset.file, line: Number(a.dataset.line) });
    });
  });
</script>
</body>
</html>`;
}