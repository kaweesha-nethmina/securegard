import * as vscode from "vscode";

export interface ReviewTestRow {
  findingId: string;
  findingTitle: string;
  sourceFile: string;
  testFilePath: string;
  testCode: string;
  via: string;
  usedFallback: boolean;
}

export class TestReviewPanel {
  static current: TestReviewPanel | undefined;
  private panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  static show(context: vscode.ExtensionContext, rows: ReviewTestRow[], onMessage: (msg: any) => void) {
    if (TestReviewPanel.current) {
      TestReviewPanel.current.panel.reveal();
      TestReviewPanel.current.update(rows);
      return;
    }
    const panel = vscode.window.createWebviewPanel("secuguardTestReview", "SecuGuard — Review Generated Tests", vscode.ViewColumn.Active, {
      enableScripts: true,
      retainContextWhenHidden: true,
    });
    panel.iconPath = vscode.Uri.joinPath(context.extensionUri, "resources", "shield.svg");
    TestReviewPanel.current = new TestReviewPanel(panel, rows, onMessage);
  }

  static refreshIfOpen(rows: ReviewTestRow[]) {
    TestReviewPanel.current?.update(rows);
  }

  private constructor(panel: vscode.WebviewPanel, rows: ReviewTestRow[], onMessage: (msg: any) => void) {
    this.panel = panel;
    this.update(rows);
    this.panel.webview.onDidReceiveMessage(onMessage, null, this.disposables);
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  update(rows: ReviewTestRow[]) {
    this.panel.webview.html = renderHtml(rows);
  }

  dispose() {
    TestReviewPanel.current = undefined;
    this.disposables.forEach((d) => d.dispose());
    this.panel.dispose();
  }
}

function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

function renderHtml(rows: ReviewTestRow[]): string {
  const rowsHtml = rows
    .map(
      (r) => `
  <div class="row" data-finding="${esc(r.findingId)}" data-path="${esc(r.testFilePath)}" data-via="${esc(r.via)}">
    <div class="row-head">
      <div>
        <div class="title">${esc(r.findingTitle)} <span class="via">generated with ${esc(r.via)}${r.usedFallback ? " (via quota failover)" : ""}</span></div>
        <div class="meta">${esc(r.sourceFile)} → <b>${esc(r.testFilePath)}</b></div>
      </div>
      <div class="row-actions">
        <button class="action accept">Accept</button>
        <button class="action preview">Preview</button>
        <button class="action skip">Skip</button>
      </div>
    </div>
    <textarea spellcheck="false" class="code" rows="14">${esc(r.testCode)}</textarea>
  </div>`
    )
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SecuGuard — Review Generated Tests</title>
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
  .subtitle { color: var(--muted); font-size: 13px; margin-bottom: 18px; }
  .toolbar { display: flex; gap: 10px; align-items: center; margin-bottom: 14px; flex-wrap: wrap; }
  button.action {
    background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: 6px;
    padding: 8px 12px; font-size: 12px; cursor: pointer;
  }
  button.action:hover { border-color: var(--accent); }
  button.action.primary { border-color: var(--accent); }
  .stats { color: var(--muted); font-size: 12px; margin-left: auto; }
  .row { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 12px 14px; margin-bottom: 12px; }
  .row.accepted { border-color: #2da44e; }
  .row.skipped { opacity: .45; }
  .row-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; margin-bottom: 8px; }
  .title { font-weight: 600; font-size: 13px; }
  .via { color: var(--muted); font-size: 11px; font-weight: 400; }
  .meta { color: var(--muted); font-size: 12px; margin-top: 2px; }
  .meta b { color: var(--accent); font-weight: 600; }
  .row-actions { display: flex; gap: 6px; flex-shrink: 0; }
  .code {
    width: 100%; background: var(--vscode-editor-background, #1e1e1e); color: var(--fg);
    border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-family: var(--vscode-editor-font-family, monospace);
    font-size: 12px; line-height: 1.5; resize: vertical; white-space: pre;
  }
  .empty { color: var(--muted); text-align: center; padding: 50px 20px; }
</style>
</head>
<body>
  <h1>🧪 SecuGuard — Review Generated Tests</h1>
  <div class="subtitle">AI-drafted unit tests, generated for exported symbols with no test yet. Review, edit, accept, and insert.</div>

  <div class="toolbar">
    <button class="action primary" id="acceptAll">Accept All</button>
    <button class="action primary" id="insertAccepted">Insert Accepted (0)</button>
    <span class="stats" id="stats">0 accepted</span>
  </div>

  ${rows.length === 0 ? `<div class="empty">No generated tests to review.</div>` : rowsHtml}

<script>
  const vscode = acquireVsCodeApi();
  let accepted = new Set();
  let skipped = new Set();

  function refresh() {
    document.querySelectorAll('.row').forEach(row => {
      const id = row.dataset.finding;
      row.classList.toggle('accepted', accepted.has(id));
      row.classList.toggle('skipped', skipped.has(id));
      const code = row.querySelector('textarea');
      if (code) code.disabled = accepted.has(id) || skipped.has(id);
    });
    document.getElementById('insertAccepted').textContent = "Insert Accepted (" + accepted.size + ")";
    document.getElementById('stats').textContent = accepted.size + " accepted" +
      (skipped.size ? " · " + skipped.size + " skipped" : "");
  }

  document.querySelectorAll('.row').forEach(row => {
    const id = row.dataset.finding;
    row.querySelector('.accept').addEventListener('click', () => { accepted.add(id); skipped.delete(id); refresh(); });
    row.querySelector('.skip').addEventListener('click', () => { skipped.add(id); accepted.delete(id); refresh(); });
    row.querySelector('.preview').addEventListener('click', () => {
      vscode.postMessage({ type: 'preview', code: row.querySelector('textarea').value, testFilePath: row.dataset.finding });
    });
  });

  document.getElementById('acceptAll').addEventListener('click', () => {
    document.querySelectorAll('.row').forEach(row => { accepted.add(row.dataset.finding); skipped.delete(row.dataset.finding); });
    refresh();
  });

  document.getElementById('insertAccepted').addEventListener('click', () => {
    const tests = [];
    document.querySelectorAll('.row').forEach(row => {
      const id = row.dataset.finding;
      if (!accepted.has(id)) return;
      const textarea = row.querySelector('textarea');
      const meta = {};
      tests.push({
        findingId: id,
        testCode: textarea.value,
        testFilePath: textarea.dataset  && textarea.dataset.path ? textarea.dataset.path : String(row.querySelector('.meta b').textContent),
        via: row.querySelector('.via').textContent.replace(/^generated with /, '').replace(/ \(via quota failover\)$/, '')
      });
    });
    if (tests.length) vscode.postMessage({ type: 'insertAccepted', tests });
  });

  refresh();
</script>
</body>
</html>`;
}