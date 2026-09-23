import * as vscode from "vscode";
import * as path from "path";
import { Database } from "../storage/database";
import { SECUGUARD_SOURCE } from "./diagnosticsProvider";

export class SecuGuardCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private db: Database, private workspaceRoot: string) {}

  provideCodeActions(document: vscode.TextDocument, range: vscode.Range | vscode.Selection): vscode.CodeAction[] {
    const relFile = path.relative(this.workspaceRoot, document.uri.fsPath).split(path.sep).join("/");
    const line = range.start.line + 1;
    const vuln = this.db.getAll().find((v) => v.file === relFile && line >= v.startLine && line <= v.endLine);
    if (!vuln) return [];

    const actions: vscode.CodeAction[] = [];

    const explain = new vscode.CodeAction(`SecuGuard: Explain "${vuln.title}"`, vscode.CodeActionKind.QuickFix);
    explain.command = { command: "secuguard.explainVulnerability", title: "Explain", arguments: [vuln.id] };
    actions.push(explain);

    const fix = new vscode.CodeAction(`SecuGuard: Generate fix for "${vuln.title}"`, vscode.CodeActionKind.QuickFix);
    fix.command = { command: "secuguard.generateFix", title: "Generate Fix", arguments: [vuln.id] };
    fix.isPreferred = true;
    actions.push(fix);

    const suppress = new vscode.CodeAction(`SecuGuard: Suppress with reason…`, vscode.CodeActionKind.QuickFix);
    suppress.command = { command: "secuguard.markFalsePositive", title: "Suppress", arguments: [vuln.id] };
    actions.push(suppress);

    const todo = new vscode.CodeAction(`SecuGuard: Add as TODO`, vscode.CodeActionKind.QuickFix);
    todo.command = { command: "secuguard.addTodo", title: "Add TODO", arguments: [vuln.id] };
    actions.push(todo);

    const dashboard = new vscode.CodeAction(`SecuGuard: Open in dashboard`, vscode.CodeActionKind.QuickFix);
    dashboard.command = { command: "secuguard.openDashboard", title: "Open Dashboard" };
    actions.push(dashboard);

    return actions;
  }
}

export const CODE_ACTION_SOURCE = SECUGUARD_SOURCE;
