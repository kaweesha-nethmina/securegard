import * as vscode from "vscode";
import * as path from "path";
import { Database } from "../storage/database";

export class SecuGuardCodeLensProvider implements vscode.CodeLensProvider {
  private _onDidChangeCodeLenses = new vscode.EventEmitter<void>();
  readonly onDidChangeCodeLenses = this._onDidChangeCodeLenses.event;

  constructor(private db: Database, private workspaceRoot: string) {}

  refresh() {
    this._onDidChangeCodeLenses.fire();
  }

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    const relFile = path.relative(this.workspaceRoot, document.uri.fsPath).split(path.sep).join("/");
    const vulns = this.db
      .getAll()
      .filter((v) => v.file === relFile && v.status !== "false_positive" && v.status !== "fixed" && v.status !== "wont_fix");

    const lenses: vscode.CodeLens[] = [];
    for (const v of vulns) {
      const line = Math.max(0, v.startLine - 1);
      const range = new vscode.Range(line, 0, line, 0);

      lenses.push(
        new vscode.CodeLens(range, {
          title: `$(shield) ${v.title} (${v.severity})`,
          command: "",
        })
      );
      lenses.push(
        new vscode.CodeLens(range, { title: "Explain", command: "secuguard.explainVulnerability", arguments: [v.id] })
      );
      lenses.push(
        new vscode.CodeLens(range, { title: "Generate Fix", command: "secuguard.generateFix", arguments: [v.id] })
      );
      lenses.push(
        new vscode.CodeLens(range, { title: "Save", command: "secuguard.saveToBacklog", arguments: [v.id] })
      );
      lenses.push(
        new vscode.CodeLens(range, { title: "Add TODO", command: "secuguard.addTodo", arguments: [v.id] })
      );
      lenses.push(
        new vscode.CodeLens(range, { title: "Suppress", command: "secuguard.markFalsePositive", arguments: [v.id] })
      );
    }
    return lenses;
  }
}
