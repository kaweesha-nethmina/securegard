import * as vscode from "vscode";
import * as path from "path";
import { Vulnerability, Severity, SEVERITY_ORDER, SEVERITY_COLOR, FindingCategory } from "../types";
import { Database } from "../storage/database";

type TreeNode = CategoryGroupNode | SeverityGroupNode | FileGroupNode | FindingNode;

class CategoryGroupNode {
  constructor(public category: FindingCategory, public count: number) {}
}
class SeverityGroupNode {
  constructor(public severity: Severity, public count: number) {}
}
class FileGroupNode {
  constructor(public file: string, public findings: Vulnerability[]) {}
}
class FindingNode {
  constructor(public vuln: Vulnerability) {}
}

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "info",
  info: "circle-small",
};

export class SecurityExplorerProvider implements vscode.TreeDataProvider<TreeNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  minSeverity: Severity = "info";

  constructor(private db: Database, private workspaceRoot: string) {}

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  setMinSeverity(sev: Severity) {
    this.minSeverity = sev;
    this.refresh();
  }

  private activeVulns(): Vulnerability[] {
    return this.db
      .getAll()
      .filter((v) => v.status !== "false_positive" && v.status !== "wont_fix" && v.status !== "fixed")
      .filter((v) => SEVERITY_ORDER[v.severity] >= SEVERITY_ORDER[this.minSeverity]);
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    if (element instanceof CategoryGroupNode) {
      const item = new vscode.TreeItem(
        `${element.category.toUpperCase()} (${element.count})`,
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.iconPath = new vscode.ThemeIcon("shield");
      item.contextValue = "categoryGroup";
      return item;
    }
    if (element instanceof SeverityGroupNode) {
      const item = new vscode.TreeItem(
        `${element.severity.toUpperCase()} (${element.count})`,
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.iconPath = new vscode.ThemeIcon(SEVERITY_ICONS[element.severity], new vscode.ThemeColor(sevColorId(element.severity)));
      item.contextValue = "severityGroup";
      return item;
    }
    if (element instanceof FileGroupNode) {
      const item = new vscode.TreeItem(
        `${path.basename(element.file)} (${element.findings.length})`,
        vscode.TreeItemCollapsibleState.Collapsed
      );
      item.description = path.dirname(element.file);
      item.iconPath = vscode.ThemeIcon.File;
      item.resourceUri = vscode.Uri.file(path.join(this.workspaceRoot, element.file));
      item.contextValue = "fileGroup";
      return item;
    }
    // FindingNode
    const v = element.vuln;
    const item = new vscode.TreeItem(`${v.title}`, vscode.TreeItemCollapsibleState.None);
    item.description = `L${v.startLine} · ${v.cwe.join(", ")}${v.status === "todo" ? " · TODO" : ""}`;
    const lastChange = v.statusHistory && v.statusHistory.length > 0 ? v.statusHistory[v.statusHistory.length - 1] : undefined;
    const byLine = lastChange
      ? ` · last change by @${lastChange.changedBy} on ${new Date(lastChange.changedAt).toLocaleDateString()}`
      : "";
    item.tooltip = new vscode.MarkdownString(
      `**${v.title}**\n\n${v.description}\n\n_Status: ${v.status} · Source: ${v.sourceScanner}${byLine}_`
    );
    item.iconPath = new vscode.ThemeIcon(SEVERITY_ICONS[v.severity], new vscode.ThemeColor(sevColorId(v.severity)));
    item.contextValue = "finding";
    item.command = {
      command: "vscode.open",
      title: "Open",
      arguments: [
        vscode.Uri.file(path.join(this.workspaceRoot, v.file)),
        { selection: new vscode.Range(v.startLine - 1, 0, v.startLine - 1, 0) },
      ],
    };
    (item as any).vulnId = v.id;
    return item;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    const vulns = this.activeVulns();

    if (!element) {
      // Group by category at the top level only when several categories have findings;
      // otherwise keep the familiar Severity → File → Finding hierarchy.
      const categories = Array.from(new Set(vulns.map((v) => v.category)));
      if (categories.length > 1) {
        return categories
          .sort((a, b) => categoryIndex(a) - categoryIndex(b))
          .map((cat) => new CategoryGroupNode(cat, vulns.filter((v) => v.category === cat).length));
      }

      const order: Severity[] = ["critical", "high", "medium", "low", "info"];
      return order
        .map((sev) => new SeverityGroupNode(sev, vulns.filter((v) => v.severity === sev).length))
        .filter((g) => g.count > 0);
    }

    if (element instanceof CategoryGroupNode) {
      const order: Severity[] = ["critical", "high", "medium", "low", "info"];
      return order
        .map((sev) => new SeverityGroupNode(sev, vulns.filter((v) => v.category === element.category && v.severity === sev).length))
        .filter((g) => g.count > 0);
    }

    if (element instanceof SeverityGroupNode) {
      const files = new Map<string, Vulnerability[]>();
      for (const v of vulns.filter((v) => v.severity === element.severity)) {
        if (!files.has(v.file)) files.set(v.file, []);
        files.get(v.file)!.push(v);
      }
      return Array.from(files.entries())
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([file, findings]) => new FileGroupNode(file, findings));
    }

    if (element instanceof FileGroupNode) {
      return element.findings.sort((a, b) => a.startLine - b.startLine).map((v) => new FindingNode(v));
    }

    return [];
  }
}

function categoryIndex(cat: FindingCategory): number {
  const order: FindingCategory[] = ["sast", "sca", "secret", "iac", "container", "quality", "test-coverage", "documentation"];
  const i = order.indexOf(cat);
  return i === -1 ? 99 : i;
}

function sevColorId(sev: Severity): string {
  switch (sev) {
    case "critical":
    case "high":
      return "problemsErrorIcon.foreground";
    case "medium":
      return "problemsWarningIcon.foreground";
    default:
      return "problemsInfoIcon.foreground";
  }
}

/** Simple summary view shown above the explorer: counts + last scan time. */
export class SummaryProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  lastScan: { filesScanned: number; durationMs: number; scannersRun: string[] } | null = null;

  constructor(private db: Database) {}

  refresh(lastScan?: typeof this.lastScan) {
    if (lastScan) this.lastScan = lastScan;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    const vulns = this.db.getAll().filter((v) => v.status !== "false_positive" && v.status !== "fixed" && v.status !== "wont_fix");
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of vulns) counts[v.severity]++;

    const items: vscode.TreeItem[] = (Object.keys(counts) as Severity[])
      .filter((s) => counts[s] > 0)
      .map((s) => {
        const item = new vscode.TreeItem(`${s.toUpperCase()}: ${counts[s]}`);
        item.iconPath = new vscode.ThemeIcon(SEVERITY_ICONS[s], new vscode.ThemeColor(sevColorId(s)));
        return item;
      });

    if (this.lastScan) {
      const info = new vscode.TreeItem(
        `Last scan: ${this.lastScan.filesScanned} files, ${this.lastScan.durationMs}ms (${this.lastScan.scannersRun.join(", ")})`
      );
      info.iconPath = new vscode.ThemeIcon("history");
      items.push(info);
    }

    if (items.length === 0) {
      items.push(new vscode.TreeItem("No findings yet — run a scan"));
    }

    const genTests = new vscode.TreeItem("Generate Missing Tests", vscode.TreeItemCollapsibleState.None);
    genTests.iconPath = new vscode.ThemeIcon("beaker");
    genTests.command = { command: "secuguard.generateAllTests", title: "Generate Missing Tests" };
    genTests.contextValue = "actionItem";
    items.push(genTests);

    return items;
  }
}
