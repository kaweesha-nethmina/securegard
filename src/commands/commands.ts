import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { Database } from "../storage/database";
import { Orchestrator } from "../engine/orchestrator";
import { StatusHistoryEntry, Vulnerability, VulnStatus } from "../types";
import { triageVulnerability } from "../ai/triageService";
import { toSarif, toMarkdownReport } from "../utils/sarif";
import { resolveIdentity, clearIdentityCache } from "../utils/identity";
import { DiagnosticsProvider } from "../providers/diagnosticsProvider";
import { SecurityExplorerProvider, SummaryProvider } from "../providers/treeViewProvider";
import { SecuGuardCodeLensProvider } from "../providers/codeLensProvider";
import { DashboardPanel } from "../webview/dashboardPanel";

export interface Wiring {
  db: Database;
  orchestrator: Orchestrator;
  diagnostics: DiagnosticsProvider;
  explorer: SecurityExplorerProvider;
  summary: SummaryProvider;
  codeLens: SecuGuardCodeLensProvider;
  workspaceRoot: string;
  outputChannel: vscode.OutputChannel;
  context: vscode.ExtensionContext;
}

function config() {
  return vscode.workspace.getConfiguration("secuguard");
}

function refreshAll(w: Wiring, stats?: { filesScanned: number; durationMs: number; scannersRun: string[] }) {
  const vulns = w.db.getAll();
  const minSeverity = config().get<any>("severityThreshold", "low");
  w.diagnostics.refresh(vulns, w.workspaceRoot, minSeverity);
  w.explorer.refresh();
  w.summary.refresh(stats);
  w.codeLens.refresh();
  DashboardPanel.refreshIfOpen(vulns);
}

async function runScan(w: Wiring, targets: string[], label: string) {
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: `SecuGuard: ${label}`, cancellable: false },
    async (progress) => {
      progress.report({ message: "Running scanners…" });
      const { vulnerabilities, stats } = await w.orchestrator.runScan(targets);
      w.outputChannel.appendLine(
        `[${new Date().toISOString()}] Scan complete — ${stats.filesScanned} files, ${stats.durationMs}ms, scanners: ${stats.scannersRun.join(", ")}, findings: ${vulnerabilities.length}`
      );
      const identity = await resolveIdentity(w.context, w.workspaceRoot);
      w.db.addAuditEntry("scan", `${label}: ${stats.filesScanned} files scanned via [${stats.scannersRun.join(", ")}], ${vulnerabilities.length} findings`, identity.username);
      refreshAll(w, stats);

      const newCritical = vulnerabilities.filter((v) => v.severity === "critical" && v.status === "open").length;
      if (newCritical > 0) {
        vscode.window.showWarningMessage(`SecuGuard found ${newCritical} CRITICAL issue(s). Open the Security Explorer to review.`);
      } else {
        vscode.window.showInformationMessage(`SecuGuard scan complete: ${vulnerabilities.length} active finding(s).`);
      }
    }
  );
}

function findVuln(w: Wiring, id: string | undefined): Vulnerability | undefined {
  if (!id) {
    vscode.window.showErrorMessage("SecuGuard: no finding selected.");
    return undefined;
  }
  const v = w.db.get(id);
  if (!v) vscode.window.showErrorMessage("SecuGuard: finding not found (it may have been resolved by a rescan).");
  return v;
}

async function updateStatus(w: Wiring, v: Vulnerability, status: VulnStatus, note?: string): Promise<void> {
  const identity = await resolveIdentity(w.context, w.workspaceRoot);
  const entry: StatusHistoryEntry = {
    status,
    changedBy: identity.username,
    changedAt: new Date().toISOString(),
    ...(identity.email ? { changedByEmail: identity.email } : {}),
    ...(identity.source ? { source: identity.source } : {}),
    ...(note !== undefined ? { note } : {}),
  };
  w.db.update(v.id, { status, statusHistory: [...(v.statusHistory ?? []), entry] });
  w.db.addAuditEntry("status_change", `@${identity.username} set ${v.id} (${v.title}) → ${status}${note ? ` — ${note}` : ""}`, identity.username);
}

function reloadFromDisk(w: Wiring): void {
  w.db.reload();
  refreshAll(w);
  w.outputChannel.appendLine(`[${new Date().toISOString()}] SecuGuard reloaded findings from disk.`);
}

function showHistoryQuickPick(v: Vulnerability): void {
  const entries = [...(v.statusHistory ?? [])].reverse();
  const items: vscode.QuickPickItem[] = entries.map((e) => ({
    label: `$(circle-outline) ${e.status.replace("_", " ")}`,
    description: `@${e.changedBy}${e.changedByEmail ? ` <${e.changedByEmail}>` : ""}${e.source === "git" ? " (git identity)" : ""} · ${new Date(e.changedAt).toLocaleString()}`,
    detail: e.note ?? v.title,
  }));
  if (items.length === 0) {
    items.push({ label: "No status changes recorded", description: undefined, detail: `Status: ${v.status}` });
  }
  vscode.window.showQuickPick(items, { placeHolder: `History — ${v.title}`, matchOnDetail: true });
}

async function getApiKey(w: Wiring): Promise<string | undefined> {
  const envVar = config().get<string>("ai.apiKeyEnvVar", "ANTHROPIC_API_KEY");
  const key = process.env[envVar];
  if (!key) {
    const choice = await vscode.window.showWarningMessage(
      `SecuGuard AI triage needs the ${envVar} environment variable set (or enable it in Settings). Open Settings?`,
      "Open Settings"
    );
    if (choice === "Open Settings") vscode.commands.executeCommand("workbench.action.openSettings", "secuguard.ai");
    return undefined;
  }
  return key;
}

export function registerCommands(w: Wiring): vscode.Disposable[] {
  const disposables: vscode.Disposable[] = [];

  disposables.push(
    vscode.commands.registerCommand("secuguard.scanWorkspace", async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showErrorMessage("SecuGuard: open a folder/workspace first.");
        return;
      }
      await runScan(w, [w.workspaceRoot], "Scanning workspace");
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.scanCurrentFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showErrorMessage("SecuGuard: no active file.");
        return;
      }
      await runScan(w, [editor.document.uri.fsPath], `Scanning ${path.basename(editor.document.uri.fsPath)}`);
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.refreshTree", () => refreshAll(w))
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.filterBySeverity", async () => {
      const pick = await vscode.window.showQuickPick(["critical", "high", "medium", "low", "info"], {
        placeHolder: "Show findings at or above severity…",
      });
      if (pick) w.explorer.setMinSeverity(pick as any);
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.saveToBacklog", async (id?: string) => {
      const v = findVuln(w, id);
      if (!v) return;
      await updateStatus(w, v, "triaged", "Saved to backlog");
      refreshAll(w);
      vscode.window.showInformationMessage(`Saved "${v.title}" to the vulnerability backlog.`);
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.addTodo", async (id?: string) => {
      const v = findVuln(w, id);
      if (!v) return;
      const absPath = path.join(w.workspaceRoot, v.file);
      try {
        const doc = await vscode.workspace.openTextDocument(absPath);
        const editor = await vscode.window.showTextDocument(doc);
        const line = Math.max(0, v.startLine - 1);
        const lineText = doc.lineAt(line);
        const indent = lineText.text.match(/^\s*/)?.[0] ?? "";
        const commentPrefix = commentPrefixFor(v.language);
        const todoLine = `${indent}${commentPrefix} TODO(security): [${v.id.slice(0, 8).toUpperCase()}] ${v.title} - ${v.cwe.join(
          ", "
        )} - see SecuGuard dashboard\n`;
        await editor.edit((editBuilder) => {
          editBuilder.insert(new vscode.Position(line, 0), todoLine);
        });
        const todoId = `TODO-${v.id.slice(0, 8)}`;
        await updateStatus(w, v, "todo", `TODO ${todoId} inserted`);
        w.db.update(v.id, { linkedTodoId: todoId });
        const identity = await resolveIdentity(w.context, w.workspaceRoot);
        w.db.addAuditEntry("add_todo", `Inserted TODO ${todoId} for ${v.id} at ${v.file}:${v.startLine}`, identity.username);
        refreshAll(w);
      } catch (e: any) {
        vscode.window.showErrorMessage(`SecuGuard: couldn't insert TODO — ${e.message}`);
      }
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.markFalsePositive", async (id?: string) => {
      const v = findVuln(w, id);
      if (!v) return;
      const reason = await vscode.window.showInputBox({
        prompt: `Why is "${v.title}" a false positive / won't fix? (this improves future triage)`,
        placeHolder: "e.g. input is validated upstream by middleware X",
      });
      if (reason === undefined) return; // cancelled
      await updateStatus(w, v, "false_positive", reason || "(no reason given)");
      w.db.update(v.id, { falsePositiveReason: reason || "(no reason given)" });
      w.db.addIgnoreRule({ ruleId: v.ruleId, reason: reason || "(no reason given)", createdAt: new Date().toISOString(), file: v.file });
      const identity = await resolveIdentity(w.context, w.workspaceRoot);
      w.db.addAuditEntry("suppress", `Suppressed ${v.id} (${v.ruleId}) — reason: ${reason}`, identity.username);
      refreshAll(w);
      vscode.window.showInformationMessage(`Marked "${v.title}" as false positive. Reason saved to .secuguard/ignore.yml.`);
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.markFixed", async (id?: string) => {
      const v = findVuln(w, id);
      if (!v) return;
      await updateStatus(w, v, "fixed");
      refreshAll(w);
      vscode.window.showInformationMessage(`Marked "${v.title}" as fixed.`);
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.reloadFromDisk", () => {
      reloadFromDisk(w);
      vscode.window.showInformationMessage("SecuGuard: findings reloaded from disk.");
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.setGithubUsername", async () => {
      const answer = await vscode.window.showInputBox({
        prompt: "What's your GitHub username? Used to attribute SecuGuard status changes.",
        placeHolder: "GitHub username",
        ignoreFocusOut: true,
      });
      if (answer?.trim()) {
        await w.context.globalState.update("secuguard.githubUsername", answer.trim());
        clearIdentityCache();
        vscode.window.showInformationMessage(`SecuGuard will attribute changes to @${answer.trim()}.`);
      }
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.explainVulnerability", async (id?: string) => {
      const v = findVuln(w, id);
      if (!v) return;
      if (v.aiExplanation) {
        showExplainPanel(v);
        return;
      }
      if (!config().get<boolean>("ai.enabled", false)) {
        vscode.window.showWarningMessage("SecuGuard AI triage is disabled. Enable `secuguard.ai.enabled` in Settings, or read the built-in rule description in the hover/tooltip.");
        showExplainPanel(v);
        return;
      }
      const apiKey = await getApiKey(w);
      if (!apiKey) return;
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "SecuGuard: asking AI triage…" }, async () => {
        try {
          const result = await triageVulnerability(v, apiKey, config().get<string>("ai.model", "claude-sonnet-4-6"));
          w.db.update(v.id, {
            aiExplanation: result.explanation,
            aiConfidence: result.confidence,
            suggestedFix: result.suggestedFix || v.suggestedFix,
            status: result.isLikelyFalsePositive && v.status === "open" ? v.status : v.status,
          });
          const aiIdentity = await resolveIdentity(w.context, w.workspaceRoot);
          w.db.addAuditEntry("ai_triage", `AI triage run for ${v.id} — confidence ${result.confidence}`, aiIdentity.username);
          refreshAll(w);
          showExplainPanel(w.db.get(v.id)!);
          if (result.isLikelyFalsePositive) {
            vscode.window.showInformationMessage(`AI triage suspects "${v.title}" may be a false positive — review and suppress if confirmed.`);
          }
        } catch (e: any) {
          vscode.window.showErrorMessage(`SecuGuard AI triage failed: ${e.message}`);
        }
      });
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.generateFix", async (id?: string) => {
      const v = findVuln(w, id);
      if (!v) return;
      if (v.suggestedFix && !config().get<boolean>("ai.enabled", false)) {
        vscode.window.showInformationMessage(v.suggestedFix, { modal: true });
        return;
      }
      if (config().get<boolean>("ai.enabled", false)) {
        const apiKey = await getApiKey(w);
        if (apiKey) {
          await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: "SecuGuard: generating fix…" }, async () => {
            try {
              const result = await triageVulnerability(v, apiKey, config().get<string>("ai.model", "claude-sonnet-4-6"));
              w.db.update(v.id, { suggestedFix: result.suggestedFix, aiExplanation: result.explanation, aiConfidence: result.confidence });
              refreshAll(w);
              vscode.window.showInformationMessage(result.suggestedFix, { modal: true });
            } catch (e: any) {
              vscode.window.showErrorMessage(`SecuGuard: fix generation failed — ${e.message}`);
            }
          });
          return;
        }
      }
      vscode.window.showInformationMessage(v.suggestedFix || "No fix suggestion available for this rule yet.", { modal: true });
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.exportReport", async () => {
      const format = await vscode.window.showQuickPick(["SARIF (.sarif)", "Markdown (.md)", "JSON (.json)"], {
        placeHolder: "Export format",
      });
      if (!format) return;
      const vulns = w.db.getAll();
      let content: string;
      let defaultName: string;
      if (format.startsWith("SARIF")) {
        content = JSON.stringify(toSarif(vulns, "0.1.0"), null, 2);
        defaultName = "secuguard-report.sarif";
      } else if (format.startsWith("Markdown")) {
        content = toMarkdownReport(vulns);
        defaultName = "secuguard-report.md";
      } else {
        content = JSON.stringify(vulns, null, 2);
        defaultName = "secuguard-report.json";
      }
      const uri = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.file(path.join(w.workspaceRoot, defaultName)) });
      if (!uri) return;
      fs.writeFileSync(uri.fsPath, content, "utf8");
      const exportIdentity = await resolveIdentity(w.context, w.workspaceRoot);
      w.db.addAuditEntry("export", `Exported ${format} report to ${uri.fsPath}`, exportIdentity.username);
      vscode.window.showInformationMessage(`SecuGuard report saved to ${uri.fsPath}`);
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.openDashboard", () => {
      DashboardPanel.show(w.context, () => w.db.getAll(), w.workspaceRoot, async (msg) => {
        switch (msg.type) {
          case "open": {
            const v = w.db.get(msg.id);
            if (v) {
              const doc = await vscode.workspace.openTextDocument(path.join(w.workspaceRoot, v.file));
              await vscode.window.showTextDocument(doc, { selection: new vscode.Range(v.startLine - 1, 0, v.startLine - 1, 0) });
            }
            break;
          }
          case "explain":
            vscode.commands.executeCommand("secuguard.explainVulnerability", msg.id);
            break;
          case "fix":
            vscode.commands.executeCommand("secuguard.generateFix", msg.id);
            break;
          case "setStatus": {
            const v = w.db.get(msg.id);
            if (v && typeof msg.status === "string") {
              await updateStatus(w, v, msg.status as VulnStatus);
            }
            refreshAll(w);
            break;
          }
          case "showHistory": {
            const v = w.db.get(msg.id);
            if (v) showHistoryQuickPick(v);
            break;
          }
          case "exportSarif":
            vscode.commands.executeCommand("secuguard.exportReport");
            break;
          case "exportMd":
            vscode.commands.executeCommand("secuguard.exportReport");
            break;
          case "rescan":
            vscode.commands.executeCommand("secuguard.scanWorkspace");
            break;
        }
      });
    })
  );

  disposables.push(
    vscode.commands.registerCommand("secuguard.clearBaseline", async () => {
      const confirm = await vscode.window.showWarningMessage(
        "This clears all SecuGuard findings and history for this workspace. Continue?",
        { modal: true },
        "Clear"
      );
      if (confirm !== "Clear") return;
      w.db.resetAll();
      refreshAll(w);
      vscode.window.showInformationMessage("SecuGuard: local vulnerability database cleared.");
    })
  );

  // Auto-refresh when .secuguard/findings/ changes out-of-band (e.g. after a
  // `git pull` brings in teammates' status updates). Debounced to coalesce the
  // burst of file events that a single check/commit causes.
  let reloadTimer: NodeJS.Timeout | undefined;
  const scheduleReload = () => {
    if (reloadTimer) clearTimeout(reloadTimer);
    reloadTimer = setTimeout(() => reloadFromDisk(w), 200);
  };
  const findingsWatcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(w.workspaceRoot, ".secuguard/findings/*.json")
  );
  findingsWatcher.onDidCreate(scheduleReload);
  findingsWatcher.onDidChange(scheduleReload);
  findingsWatcher.onDidDelete(scheduleReload);
  disposables.push(findingsWatcher);

  return disposables;
}

function commentPrefixFor(lang: string): string {
  switch (lang) {
    case "py":
    case "rb":
      return "#";
    case "html":
      return "<!--";
    default:
      return "//";
  }
}

function showExplainPanel(v: Vulnerability) {
  const panel = vscode.window.createWebviewPanel("secuguardExplain", `Explain: ${v.title}`, vscode.ViewColumn.Beside, {});
  const esc = (s: string) => String(s || "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
  panel.webview.html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
    body{font-family:var(--vscode-font-family);padding:20px;line-height:1.5;color:var(--vscode-editor-foreground);background:var(--vscode-editor-background);}
    h2{margin-top:0} .tag{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;background:#e9314722;color:#ff6b7d;margin-right:6px}
    pre{background:var(--vscode-textCodeBlock-background,#1e1e1e);padding:10px;border-radius:6px;overflow:auto}
    section{margin-bottom:18px} h4{margin-bottom:4px;color:var(--vscode-descriptionForeground)}
  </style></head><body>
    <h2>${esc(v.title)}</h2>
    <div><span class="tag">${esc(v.severity.toUpperCase())}</span><span class="tag">${esc(v.cwe.join(", "))}</span>${v.owasp ? `<span class="tag">${esc(v.owasp)}</span>` : ""}</div>
    <section><h4>Location</h4><code>${esc(v.file)}:${v.startLine}</code></section>
    <section><h4>Description</h4><p>${esc(v.description)}</p></section>
    ${v.aiExplanation ? `<section><h4>AI Triage${typeof v.aiConfidence === "number" ? ` (confidence ${(v.aiConfidence * 100).toFixed(0)}%)` : ""}</h4><p>${esc(v.aiExplanation)}</p></section>` : ""}
    <section><h4>Code</h4><pre>${esc(v.codeSnippet)}</pre></section>
    ${v.suggestedFix ? `<section><h4>Suggested Fix</h4><p>${esc(v.suggestedFix)}</p></section>` : ""}
  </body></html>`;
}
