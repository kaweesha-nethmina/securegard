import * as vscode from "vscode";
import * as path from "path";
import { Vulnerability, Severity, SEVERITY_ORDER } from "../types";

const SEVERITY_MAP: Record<Severity, vscode.DiagnosticSeverity> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  info: vscode.DiagnosticSeverity.Hint,
};

export const SECUGUARD_SOURCE = "SecuGuard";

export class DiagnosticsProvider {
  readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection("secuguard");
  }

  refresh(vulns: Vulnerability[], workspaceRoot: string, minSeverity: Severity = "info") {
    this.collection.clear();
    const byFile = new Map<string, Vulnerability[]>();
    for (const v of vulns) {
      if (v.status === "false_positive" || v.status === "wont_fix" || v.status === "fixed") continue;
      if (SEVERITY_ORDER[v.severity] < SEVERITY_ORDER[minSeverity]) continue;
      const abs = path.join(workspaceRoot, v.file);
      if (!byFile.has(abs)) byFile.set(abs, []);
      byFile.get(abs)!.push(v);
    }

    for (const [absPath, findings] of byFile) {
      const uri = vscode.Uri.file(absPath);
      const diagnostics = findings.map((v) => {
        const line = Math.max(0, v.startLine - 1);
        const startCol = v.startCol ?? 0;
        const endCol = v.endCol ?? 200;
        const range = new vscode.Range(line, startCol, line, endCol);
        const diag = new vscode.Diagnostic(
          range,
          `[${v.severity.toUpperCase()}] ${v.title} (${v.cwe.join(", ")})`,
          SEVERITY_MAP[v.severity]
        );
        diag.source = SECUGUARD_SOURCE;
        diag.code = v.ruleId;
        (diag as any).secuguardId = v.id;
        return diag;
      });
      this.collection.set(uri, diagnostics);
    }
  }

  clear() {
    this.collection.clear();
  }

  dispose() {
    this.collection.dispose();
  }
}
