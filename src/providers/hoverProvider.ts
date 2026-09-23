import * as vscode from "vscode";
import * as path from "path";
import { Database } from "../storage/database";

export class SecuGuardHoverProvider implements vscode.HoverProvider {
  constructor(private db: Database, private workspaceRoot: string) {}

  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
    const relFile = path.relative(this.workspaceRoot, document.uri.fsPath).split(path.sep).join("/");
    const vuln = this.db
      .getAll()
      .find((v) => v.file === relFile && position.line + 1 >= v.startLine && position.line + 1 <= v.endLine);
    if (!vuln) return undefined;

    const md = new vscode.MarkdownString();
    md.isTrusted = true;
    md.supportHtml = true;
    md.appendMarkdown(`### $(shield) ${vuln.title}\n\n`);
    md.appendMarkdown(`**Severity:** ${vuln.severity.toUpperCase()} &nbsp;|&nbsp; **CWE:** ${vuln.cwe.join(", ")}`);
    if (vuln.owasp) md.appendMarkdown(` &nbsp;|&nbsp; **OWASP:** ${vuln.owasp}`);
    md.appendMarkdown(`\n\n${vuln.description}\n\n`);

    const lastChange = vuln.statusHistory && vuln.statusHistory.length > 0 ? vuln.statusHistory[vuln.statusHistory.length - 1] : undefined;
    if (lastChange) {
      const date = new Date(lastChange.changedAt).toLocaleString();
      const gitLabel = lastChange.source === "git" ? " _(git identity, not verified GitHub username)_" : "";
      md.appendMarkdown(`_Marked ${lastChange.status.replace("_", " ")} by @${lastChange.changedBy} on ${date}${gitLabel}_\n\n`);
    }

    if (vuln.aiExplanation) {
      md.appendMarkdown(`---\n**AI Triage:** ${vuln.aiExplanation}\n\n`);
      if (typeof vuln.aiConfidence === "number") {
        md.appendMarkdown(`_Confidence: ${(vuln.aiConfidence * 100).toFixed(0)}%_\n\n`);
      }
    }

    if (vuln.suggestedFix) {
      md.appendMarkdown(`---\n**Suggested fix:** ${vuln.suggestedFix}\n\n`);
    }

    const cweLink = vuln.cwe[0]
      ? `https://cwe.mitre.org/data/definitions/${vuln.cwe[0].replace(/\D/g, "")}.html`
      : undefined;
    if (cweLink) md.appendMarkdown(`[View ${vuln.cwe[0]} on MITRE →](${cweLink})`);

    return new vscode.Hover(md);
  }
}
