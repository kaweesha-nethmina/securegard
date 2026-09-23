import * as vscode from "vscode";
import { Database } from "./storage/database";
import { Orchestrator } from "./engine/orchestrator";
import { ScannerAdapter } from "./types";
import { PatternScanner } from "./scanners/patternScanner";
import { SecretsScanner } from "./scanners/secretsScanner";
import { SemgrepAdapter } from "./scanners/semgrepAdapter";
import { QualityScanner } from "./scanners/qualityScanner";
import { TestCoverageScanner } from "./scanners/testCoverageScanner";
import { DocScanner } from "./scanners/docScanner";
import { DiagnosticsProvider } from "./providers/diagnosticsProvider";
import { SecurityExplorerProvider, SummaryProvider } from "./providers/treeViewProvider";
import { SecuGuardCodeLensProvider } from "./providers/codeLensProvider";
import { SecuGuardHoverProvider } from "./providers/hoverProvider";
import { SecuGuardCodeActionProvider } from "./providers/codeActionProvider";
import { registerCommands, Wiring } from "./commands/commands";

const SUPPORTED_LANG_SELECTOR: vscode.DocumentSelector = [
  { scheme: "file", language: "javascript" },
  { scheme: "file", language: "typescript" },
  { scheme: "file", language: "javascriptreact" },
  { scheme: "file", language: "typescriptreact" },
  { scheme: "file", language: "python" },
  { scheme: "file", language: "java" },
  { scheme: "file", language: "go" },
  { scheme: "file", language: "php" },
  { scheme: "file", language: "ruby" },
  { scheme: "file", language: "csharp" },
];

export function activate(context: vscode.ExtensionContext) {
  const folders = vscode.workspace.workspaceFolders;
  const workspaceRoot = folders && folders.length > 0 ? folders[0].uri.fsPath : "";
  const outputChannel = vscode.window.createOutputChannel("SecuGuard");
  context.subscriptions.push(outputChannel);

  if (!workspaceRoot) {
    outputChannel.appendLine("SecuGuard: no workspace folder open — activation deferred until a folder is opened.");
    return;
  }

  const cfg = vscode.workspace.getConfiguration("secuguard");
  const excludeGlobs = cfg.get<string[]>("excludeGlobs", []);
  const useSemgrep = cfg.get<boolean>("useSemgrepIfAvailable", true);
  const baselineOnFirstRun = cfg.get<boolean>("baselineOnFirstRun", true);

  const db = new Database(workspaceRoot, baselineOnFirstRun);

  const scanners: ScannerAdapter[] = [
    new PatternScanner(excludeGlobs),
    new SecretsScanner(excludeGlobs),
  ];
  if (useSemgrep) scanners.push(new SemgrepAdapter());

  const qualityEnabled = cfg.get<boolean>("quality.enabled", true);
  if (qualityEnabled) {
    scanners.push(
      new QualityScanner(
        excludeGlobs,
        {
          maxFunctionLines: cfg.get<number>("quality.maxFunctionLines", 80),
          maxNestingDepth: cfg.get<number>("quality.maxNestingDepth", 4),
        }
      )
    );
  }

  const testCoverageEnabled = cfg.get<boolean>("testCoverage.enabled", true);
  if (testCoverageEnabled) {
    scanners.push(
      new TestCoverageScanner({
        excludeGlobs,
        testFileGlobs: cfg.get<string[]>("testCoverage.testFileGlobs", ["**/*.test.*", "**/*.spec.*", "**/test_*.py", "**/__tests__/**"]),
      })
    );
  }

  const docsEnabled = cfg.get<boolean>("docs.enabled", true);
  if (docsEnabled) {
    scanners.push(new DocScanner(excludeGlobs));
  }

  const orchestrator = new Orchestrator(scanners, db, workspaceRoot);
  const diagnostics = new DiagnosticsProvider();
  const explorer = new SecurityExplorerProvider(db, workspaceRoot);
  const summary = new SummaryProvider(db);
  const codeLens = new SecuGuardCodeLensProvider(db, workspaceRoot);
  const hover = new SecuGuardHoverProvider(db, workspaceRoot);
  const codeActions = new SecuGuardCodeActionProvider(db, workspaceRoot);

  context.subscriptions.push(diagnostics);
  context.subscriptions.push(vscode.window.registerTreeDataProvider("secuguard.explorer", explorer));
  context.subscriptions.push(vscode.window.registerTreeDataProvider("secuguard.summary", summary));
  context.subscriptions.push(vscode.languages.registerCodeLensProvider(SUPPORTED_LANG_SELECTOR, codeLens));
  context.subscriptions.push(vscode.languages.registerHoverProvider(SUPPORTED_LANG_SELECTOR, hover));
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(SUPPORTED_LANG_SELECTOR, codeActions, {
      providedCodeActionKinds: SecuGuardCodeActionProvider.providedCodeActionKinds,
    })
  );

  const wiring: Wiring = { db, orchestrator, diagnostics, explorer, summary, codeLens, workspaceRoot, outputChannel, context };
  context.subscriptions.push(...registerCommands(wiring));

  // Render whatever is already in the local DB immediately on activation (fast reload, no rescan needed).
  const minSeverity = cfg.get<any>("severityThreshold", "low");
  diagnostics.refresh(db.getAll(), workspaceRoot, minSeverity);

  // Scan-on-save (incremental — current file only, so it stays fast on large repos).
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const enabled = vscode.workspace.getConfiguration("secuguard").get<boolean>("scanOnSave", true);
      if (!enabled) return;
      if (!doc.uri.fsPath.startsWith(workspaceRoot)) return;
      try {
        await orchestrator.runScan([doc.uri.fsPath]);
        const sev = vscode.workspace.getConfiguration("secuguard").get<any>("severityThreshold", "low");
        diagnostics.refresh(db.getAll(), workspaceRoot, sev);
        explorer.refresh();
        summary.refresh();
        codeLens.refresh();
      } catch (e: any) {
        outputChannel.appendLine(`Scan-on-save failed for ${doc.uri.fsPath}: ${e.message}`);
      }
    })
  );

  outputChannel.appendLine(`SecuGuard activated for workspace: ${workspaceRoot}`);
  vscode.window.setStatusBarMessage("$(shield) SecuGuard ready", 3000);
}

export function deactivate() {
  // Diagnostics/webview disposables are cleaned up via context.subscriptions.
}
