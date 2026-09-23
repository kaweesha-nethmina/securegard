import * as vscode from "vscode";
import * as path from "path";
import { Vulnerability, Severity, ScanProgressState, ScanStageStatus, SEVERITY_ORDER, FindingCategory } from "../types";
import { Database } from "../storage/database";
import { computeQaHealthScore } from "../utils/sarif";

export type GroupBy = "category" | "severity" | "file";

const GROUP_BY_KEY = "secuguard.explorer.groupBy";
const SEVERITY_ORDER_LIST: Severity[] = ["critical", "high", "medium", "low", "info"];

type TreeNode = StatusNode | StageNode | FilterNode | GroupNode | FileGroupNode | FindingNode;

/** At-a-glance banner at the top of the explorer (also the scan animation host). */
class StatusNode {
  constructor(public kind: "scanning" | "findings" | "clear", public detail: string, public extra?: string) {}
}
/** One scanner row of the animated scan checklist. */
class StageNode {
  constructor(public name: string, public status: ScanStageStatus, public index: number) {}
}
/** Interactive control row (severity filter, grouping). */
class FilterNode {
  constructor(public kind: "severity" | "grouping", public value: string, public active: boolean) {}
}
/** Findings grouped by category or severity. */
class GroupNode {
  constructor(public kind: "category" | "severity", public key: string, public count: number, public files: number) {}
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

const CATEGORY_ICONS: Record<string, string> = {
  sast: "code",
  sca: "package",
  secret: "key",
  iac: "server-process",
  container: "server-environment",
  quality: "sparkle",
  "test-coverage": "beaker",
  documentation: "book",
};

const STAGE_LABELS: Record<ScanStageStatus, string> = {
  pending: "waiting",
  running: "scanning…",
  done: "done",
  skipped: "skipped",
};

export class SecurityExplorerProvider implements vscode.TreeDataProvider<TreeNode> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  minSeverity: Severity = "info";
  groupBy: GroupBy = "category";
  private scanState: ScanProgressState | null = null;

  constructor(private db: Database, private workspaceRoot: string, private context?: vscode.ExtensionContext) {
    const saved = context?.workspaceState.get<GroupBy>(GROUP_BY_KEY);
    if (saved === "category" || saved === "severity" || saved === "file") this.groupBy = saved;
  }

  refresh(): void {
    // Context keys let package.json menus adapt (e.g. only offer "clear filter" when one is set).
    void vscode.commands.executeCommand("setContext", "secuguard.hasFindings", this.activeVulns().length > 0);
    void vscode.commands.executeCommand("setContext", "secuguard.severityFilterActive", this.minSeverity !== "info");
    void vscode.commands.executeCommand("setContext", "secuguard.scanning", !!this.scanState?.active);
    void vscode.commands.executeCommand("setContext", "secuguard.neverScanned", !this.db.hasScannedBefore());
    this._onDidChangeTreeData.fire();
  }

  setMinSeverity(sev: Severity) {
    this.minSeverity = sev;
    this.refresh();
  }

  setGroupBy(groupBy: GroupBy) {
    this.groupBy = groupBy;
    void this.context?.workspaceState.update(GROUP_BY_KEY, groupBy);
    this.refresh();
  }

  /** Drives the animated checklist while a scan runs, and stops the spinners after. */
  setScanState(state: ScanProgressState | null) {
    this.scanState = state;
    this.refresh();
  }

  isScanning(): boolean {
    return !!this.scanState?.active;
  }

  activeVulns(): Vulnerability[] {
    return this.db
      .getAll()
      .filter((v) => v.status !== "false_positive" && v.status !== "wont_fix" && v.status !== "fixed")
      .filter((v) => SEVERITY_ORDER[v.severity] >= SEVERITY_ORDER[this.minSeverity]);
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    if (element instanceof StatusNode) return this.statusItem(element);
    if (element instanceof StageNode) return this.stageItem(element);
    if (element instanceof FilterNode) return this.filterItem(element);
    if (element instanceof GroupNode) return this.groupItem(element);
    if (element instanceof FileGroupNode) return this.fileItem(element);
    return this.findingItem(element as FindingNode);
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (!element) return this.rootChildren();
    if (element instanceof GroupNode) return this.childrenOfGroup(element);
    if (element instanceof FileGroupNode) {
      return element.findings.sort((a, b) => a.startLine - b.startLine).map((v) => new FindingNode(v));
    }
    return [];
  }
  // ---- tree construction -------------------------------------------------

  private rootChildren(): TreeNode[] {
    const vulns = this.activeVulns();
    const scanning = !!this.scanState?.active;

    // Nothing stored and never scanned → return zero rows so the friendly
    // `viewsWelcome` onboarding screen owns the empty state.
    if (!scanning && vulns.length === 0 && !this.db.hasScannedBefore()) return [];

    if (scanning && this.scanState) {
      const state = this.scanState;
      const current = state.stages.find((s) => s.status === "running");
      const nodes: TreeNode[] = [
        new StatusNode("scanning", `${state.index || 1}/${state.total} · ${current ? current.name : "preparing"}`, state.label),
      ];
      state.stages.forEach((s, i) => nodes.push(new StageNode(s.name, s.status, i + 1)));
      if (state.filesScanned > 0) nodes.push(new StageNode(`${state.filesScanned} files scanned so far`, "skipped", 0));
      return nodes;
    }

    const nodes: TreeNode[] = [];
    if (vulns.length === 0) {
      nodes.push(new StatusNode("clear", "no active findings", "Run a rescan to re-check the workspace"));
    } else {
      const critical = vulns.filter((v) => v.severity === "critical").length;
      const high = vulns.filter((v) => v.severity === "high").length;
      const score = computeQaHealthScore(this.db.getAll());
      nodes.push(
        new StatusNode(
          "findings",
          `${vulns.length} finding${vulns.length === 1 ? "" : "s"} · QA ${score}/100`,
          critical + high > 0 ? `${critical} critical · ${high} high` : "no critical or high findings"
        )
      );
    }

    nodes.push(new FilterNode("severity", this.minSeverity, this.minSeverity !== "info"));
    nodes.push(new FilterNode("grouping", this.groupBy, false));
    nodes.push(...this.groupedChildren(vulns));
    return nodes;
  }

  private groupedChildren(vulns: Vulnerability[]): TreeNode[] {
    if (this.groupBy === "file") {
      return this.byFile(vulns);
    }

    if (this.groupBy === "severity") {
      return SEVERITY_ORDER_LIST.map((sev) => {
        const matching = vulns.filter((v) => v.severity === sev);
        return new GroupNode("severity", sev, matching.length, new Set(matching.map((v) => v.file)).size);
      }).filter((g) => g.count > 0);
    }

    const categories = Array.from(new Set(vulns.map((v) => v.category)));
    return categories
      .sort((a, b) => categoryIndex(a) - categoryIndex(b))
      .map((cat) => {
        const matching = vulns.filter((v) => v.category === cat);
        return new GroupNode("category", cat, matching.length, new Set(matching.map((v) => v.file)).size);
      });
  }

  private childrenOfGroup(group: GroupNode): TreeNode[] {
    const vulns = this.activeVulns().filter((v) =>
      group.kind === "severity" ? v.severity === group.key : v.category === group.key
    );
    return this.byFile(vulns);
  }

  private byFile(vulns: Vulnerability[]): FileGroupNode[] {
    const files = new Map<string, Vulnerability[]>();
    for (const v of vulns) {
      if (!files.has(v.file)) files.set(v.file, []);
      files.get(v.file)!.push(v);
    }
    return Array.from(files.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([file, findings]) => new FileGroupNode(file, findings));
  }
  // ---- item rendering ----------------------------------------------------

  private statusItem(node: StatusNode): vscode.TreeItem {
    if (node.kind === "scanning") {
      const item = new vscode.TreeItem("Scanning…", vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon("sync~spin"); // natively animated in the Explorer
      item.description = node.detail;
      const md = new vscode.MarkdownString(
        `**${node.extra || "SecuGuard scan in progress"}**\n\nRuns fully locally — nothing leaves your machine.\n\n[Watch progress in the dashboard](command:secuguard.openDashboard)`
      );
      md.isTrusted = { enabledCommands: ["secuguard.openDashboard"] };
      item.tooltip = md;
      item.contextValue = "sgScanning";
      item.command = { command: "secuguard.openDashboard", title: "Open Dashboard" };
      return item;
    }

    if (node.kind === "clear") {
      const item = new vscode.TreeItem("All clear", vscode.TreeItemCollapsibleState.None);
      item.iconPath = new vscode.ThemeIcon("pass-filled", new vscode.ThemeColor("charts.green"));
      item.description = node.detail;
      item.tooltip = new vscode.MarkdownString(`No active findings at this severity threshold.\n\n_${node.extra || ""}_`);
      item.contextValue = "sgClear";
      item.command = { command: "secuguard.scanWorkspace", title: "Scan Workspace" };
      return item;
    }

    const item = new vscode.TreeItem("SecuGuard status", vscode.TreeItemCollapsibleState.None);
    item.iconPath = new vscode.ThemeIcon("shield");
    item.description = node.detail;
    const md = new vscode.MarkdownString(`**${node.extra || ""}**\n\n`);
    md.appendMarkdown(`[Open dashboard](command:secuguard.openDashboard) · [Rescan](command:secuguard.scanWorkspace)`);
    md.isTrusted = { enabledCommands: ["secuguard.openDashboard", "secuguard.scanWorkspace"] };
    item.tooltip = md;
    item.contextValue = "sgStatus";
    item.command = { command: "secuguard.openDashboard", title: "Open Dashboard" };
    return item;
  }

  private stageItem(node: StageNode): vscode.TreeItem {
    const item = new vscode.TreeItem(node.name, vscode.TreeItemCollapsibleState.None);
    if (node.index === 0) {
      item.iconPath = new vscode.ThemeIcon("files");
      item.contextValue = "sgStage";
      return item;
    }
    item.description = STAGE_LABELS[node.status];
    item.iconPath =
      node.status === "running"
        ? new vscode.ThemeIcon("sync~spin")
        : node.status === "done"
          ? new vscode.ThemeIcon("check")
          : new vscode.ThemeIcon("circle-outline");
    item.contextValue = "sgStage";
    return item;
  }

  private filterItem(node: FilterNode): vscode.TreeItem {
    if (node.kind === "severity") {
      const item = new vscode.TreeItem(
        node.active ? `Severity: ≥ ${node.value}` : "Severity: all",
        vscode.TreeItemCollapsibleState.None
      );
      item.iconPath = new vscode.ThemeIcon(
        node.active ? "filter-filled" : "filter",
        node.active ? new vscode.ThemeColor("charts.blue") : undefined
      );
      item.description = node.active ? "click to change" : "click to filter";
      item.contextValue = node.active ? "sgSeverityFilterActive" : "sgSeverityFilter";
      const md = new vscode.MarkdownString(
        node.active
          ? `Showing findings at **${node.value}** and above.\n\n[Clear filter](command:secuguard.clearSeverityFilter)`
          : "Hide everything below a severity so the tree stays readable."
      );
      md.isTrusted = { enabledCommands: ["secuguard.clearSeverityFilter"] };
      item.tooltip = md;
      item.command = { command: "secuguard.filterBySeverity", title: "Filter by Severity" };
      return item;
    }

    const item = new vscode.TreeItem(`Group by: ${node.value}`, vscode.TreeItemCollapsibleState.None);
    item.iconPath = new vscode.ThemeIcon("list-selection");
    item.description = "click to change";
    item.contextValue = "sgGrouping";
    item.tooltip = new vscode.MarkdownString("Group findings by **category**, **severity** or **file**.");
    item.command = { command: "secuguard.groupBy", title: "Change Grouping" };
    return item;
  }
  private groupItem(node: GroupNode): vscode.TreeItem {
    const label = node.kind === "severity" ? node.key.toUpperCase() : node.key;
    const item = new vscode.TreeItem(`${label} (${node.count})`, vscode.TreeItemCollapsibleState.Expanded);
    item.description = `${node.files} file${node.files === 1 ? "" : "s"}`;
    item.iconPath =
      node.kind === "severity"
        ? new vscode.ThemeIcon(SEVERITY_ICONS[node.key as Severity], new vscode.ThemeColor(sevColorId(node.key as Severity)))
        : new vscode.ThemeIcon(CATEGORY_ICONS[node.key] || "shield");
    item.contextValue = node.kind === "severity" ? "severityGroup" : "categoryGroup";
    item.id = `${node.kind}:${node.key}`;

    const md = new vscode.MarkdownString(
      `**${label}** — ${node.count} finding${node.count === 1 ? "" : "s"} in ${node.files} file${node.files === 1 ? "" : "s"}\n\n`
    );
    if (node.kind === "severity") {
      md.appendMarkdown(
        `[Filter the explorer to ${node.key}](command:secuguard.filterToSeverity?${encodeURIComponent(JSON.stringify([node.key]))})`
      );
      md.isTrusted = { enabledCommands: ["secuguard.filterToSeverity"] };
    } else {
      md.appendMarkdown(`[Copy these findings as Markdown](command:secuguard.copyFindings)`);
      md.isTrusted = { enabledCommands: ["secuguard.copyFindings"] };
    }
    item.tooltip = md;
    return item;
  }

  private fileItem(node: FileGroupNode): vscode.TreeItem {
    const item = new vscode.TreeItem(
      `${path.basename(node.file)} (${node.findings.length})`,
      vscode.TreeItemCollapsibleState.Collapsed
    );
    item.description = path.dirname(node.file);
    item.iconPath = vscode.ThemeIcon.File;
    item.resourceUri = vscode.Uri.file(path.join(this.workspaceRoot, node.file));
    item.contextValue = "fileGroup";
    item.id = `file:${node.file}`;
    const md = new vscode.MarkdownString(
      `**${node.file}** — ${node.findings.length} finding${node.findings.length === 1 ? "" : "s"}\n\n` +
        `[Rescan this file](command:secuguard.rescanFile?${encodeURIComponent(JSON.stringify([node.file]))})`
    );
    md.isTrusted = { enabledCommands: ["secuguard.rescanFile"] };
    item.tooltip = md;
    return item;
  }

  private findingItem(node: FindingNode): vscode.TreeItem {
    const v = node.vuln;
    const item = new vscode.TreeItem(v.title, vscode.TreeItemCollapsibleState.None);
    item.description = `L${v.startLine} · ${v.cwe.join(", ") || "no CWE"}${v.status === "todo" ? " · TODO" : ""}${
      v.aiExplanation ? " · 🧠" : ""
    }`;
    item.iconPath = new vscode.ThemeIcon(SEVERITY_ICONS[v.severity], new vscode.ThemeColor(sevColorId(v.severity)));
    item.contextValue = "finding";
    item.id = v.id;
    item.accessibilityInformation = {
      label: `${v.severity} finding: ${v.title}, line ${v.startLine}, status ${v.status}`,
    };

    const lastChange = v.statusHistory && v.statusHistory.length > 0 ? v.statusHistory[v.statusHistory.length - 1] : undefined;
    const byLine = lastChange
      ? `last change by @${lastChange.changedBy} on ${new Date(lastChange.changedAt).toLocaleDateString()}`
      : "no status changes yet";

    const md = new vscode.MarkdownString();
    md.appendMarkdown(`**${v.title}**\n\n${v.description}\n\n`);
    md.appendMarkdown(`**${v.severity.toUpperCase()}** · \`${v.category}\` · \`${v.file}:${v.startLine}\`\n\n`);
    if (v.aiExplanation) md.appendMarkdown(`**AI insight** — ${v.aiExplanation}\n\n`);
    md.appendMarkdown(`_Status: ${v.status} · Source: ${v.sourceScanner} · ${byLine}_\n\n`);
    md.appendMarkdown(
      `[🧠 Explain & Fix](command:secuguard.explainVulnerability?${encodeURIComponent(
        JSON.stringify([v.id])
      )}) · [✓ Mark fixed](command:secuguard.markFixed?${encodeURIComponent(JSON.stringify([v.id]))})`
    );
    md.isTrusted = { enabledCommands: ["secuguard.explainVulnerability", "secuguard.markFixed"] };
    item.tooltip = md;

    item.command = {
      command: "vscode.open",
      title: "Open",
      arguments: [
        vscode.Uri.file(path.join(this.workspaceRoot, v.file)),
        { selection: new vscode.Range(v.startLine - 1, 0, v.startLine - 1, 0) },
      ],
    };
    return item;
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

function actionItem(label: string, icon: string, command: string, tooltip: string, args?: unknown[]): vscode.TreeItem {
  const item = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
  item.iconPath = new vscode.ThemeIcon(icon);
  item.contextValue = "sgAction";
  item.tooltip = new vscode.MarkdownString(tooltip);
  item.command = { command, title: label, arguments: args as any[] | undefined };
  return item;
}

function stageRow(name: string, status: ScanStageStatus): vscode.TreeItem {
  const item = new vscode.TreeItem(name, vscode.TreeItemCollapsibleState.None);
  item.description = STAGE_LABELS[status];
  item.contextValue = "sgStage";
  item.iconPath =
    status === "running"
      ? new vscode.ThemeIcon("sync~spin")
      : status === "done"
        ? new vscode.ThemeIcon("check")
        : new vscode.ThemeIcon("circle-outline");
  return item;
}
/**
 * The Summary view doubles as the SecuGuard control panel: live scan progress,
 * clickable severity filters that drive the explorer, and one-click actions.
 */
export class SummaryProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  lastScan: { filesScanned: number; durationMs: number; scannersRun: string[] } | null = null;
  private scanState: ScanProgressState | null = null;

  constructor(private db: Database, private getSeverityFilter: () => Severity) {}

  refresh(lastScan?: { filesScanned: number; durationMs: number; scannersRun: string[] }) {
    if (lastScan) this.lastScan = lastScan;
    this._onDidChangeTreeData.fire();
  }

  setScanState(state: ScanProgressState | null) {
    this.scanState = state;
    this.refresh();
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    const state = this.scanState;

    // While a scan runs the panel becomes a live, animated checklist.
    if (state?.active) {
      const current = state.stages.find((s) => s.status === "running");
      const banner = new vscode.TreeItem(
        state.firstScan ? "First scan in progress…" : "Scanning…",
        vscode.TreeItemCollapsibleState.None
      );
      banner.iconPath = new vscode.ThemeIcon("sync~spin");
      banner.description = `${state.index || 1}/${state.total} · ${current ? current.name : "preparing"}`;
      banner.contextValue = "sgScanning";
      const md = new vscode.MarkdownString(
        `**${state.label}**\n\nScans run locally — nothing is uploaded.\n\n[Watch progress in the dashboard](command:secuguard.openDashboard)`
      );
      md.isTrusted = { enabledCommands: ["secuguard.openDashboard"] };
      banner.tooltip = md;
      banner.command = { command: "secuguard.openDashboard", title: "Open Dashboard" };

      const rows: vscode.TreeItem[] = [banner];
      state.stages.forEach((s) => rows.push(stageRow(s.name, s.status)));
      if (state.filesScanned > 0) {
        const files = new vscode.TreeItem(`${state.filesScanned} files scanned`, vscode.TreeItemCollapsibleState.None);
        files.iconPath = new vscode.ThemeIcon("files");
        files.contextValue = "sgStage";
        rows.push(files);
      }
      return rows;
    }

    const all = this.db.getAll();
    const active = all.filter((v) => v.status !== "false_positive" && v.status !== "fixed" && v.status !== "wont_fix");
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const v of active) counts[v.severity]++;

    const items: vscode.TreeItem[] = [];

    if (!this.db.hasScannedBefore()) {
      items.push(
        actionItem(
          "Run your first scan",
          "rocket",
          "secuguard.scanWorkspace",
          "SecuGuard checks this workspace locally in about a second and stores findings under `.secuguard/`."
        )
      );
    }
    // Clickable severity rows: click one to filter the Security Explorer.
    for (const sev of SEVERITY_ORDER_LIST) {
      if (counts[sev] === 0) continue;
      const row = new vscode.TreeItem(sev.charAt(0).toUpperCase() + sev.slice(1), vscode.TreeItemCollapsibleState.None);
      row.iconPath = new vscode.ThemeIcon(SEVERITY_ICONS[sev], new vscode.ThemeColor(sevColorId(sev)));
      row.description = `${counts[sev]} · click to filter`;
      row.contextValue = "sgSummarySeverity";
      const md = new vscode.MarkdownString(
        `**${counts[sev]}** active **${sev}** finding(s).\n\n[Show only ${sev} and above](command:secuguard.filterToSeverity?${encodeURIComponent(
          JSON.stringify([sev])
        )})`
      );
      md.isTrusted = { enabledCommands: ["secuguard.filterToSeverity"] };
      row.tooltip = md;
      row.command = { command: "secuguard.filterToSeverity", title: `Filter to ${sev}`, arguments: [sev] };
      items.push(row);
    }

    const filter = this.getSeverityFilter();
    if (filter !== "info") {
      const row = new vscode.TreeItem(`Filter: ≥ ${filter}`, vscode.TreeItemCollapsibleState.None);
      row.iconPath = new vscode.ThemeIcon("filter-filled", new vscode.ThemeColor("charts.blue"));
      row.description = "explorer only · click to clear";
      row.contextValue = "sgSummaryFilterActive";
      row.tooltip = new vscode.MarkdownString(`The Security Explorer only shows findings at **${filter}** and above.`);
      row.command = { command: "secuguard.clearSeverityFilter", title: "Clear Severity Filter" };
      items.push(row);
    }

    const score = computeQaHealthScore(all);
    const scoreRow = new vscode.TreeItem("QA health score", vscode.TreeItemCollapsibleState.None);
    scoreRow.description = `${score}/100 · ${score >= 85 ? "healthy" : score >= 60 ? "needs attention" : "high risk"}`;
    scoreRow.iconPath = new vscode.ThemeIcon(
      score >= 85 ? "pass-filled" : score >= 60 ? "warning" : "error",
      new vscode.ThemeColor(score >= 85 ? "charts.green" : score >= 60 ? "charts.yellow" : "charts.red")
    );
    scoreRow.contextValue = "sgSummaryScore";
    scoreRow.command = { command: "secuguard.openDashboard", title: "Open Dashboard" };
    items.push(scoreRow);

    if (active.length === 0 && this.db.hasScannedBefore()) {
      items.push(actionItem("All clear — no active findings", "pass-filled", "secuguard.scanWorkspace", "Rescan anytime."));
    }

    if (this.lastScan) {
      const info = new vscode.TreeItem("Last scan", vscode.TreeItemCollapsibleState.None);
      info.description = `${this.lastScan.filesScanned} files · ${this.lastScan.durationMs}ms · ${this.lastScan.scannersRun.length} scanners`;
      info.iconPath = new vscode.ThemeIcon("history");
      info.contextValue = "sgSummaryLastScan";
      info.tooltip = new vscode.MarkdownString(`Scanners: ${this.lastScan.scannersRun.join(", ") || "none"}`);
      items.push(info);
    }

    items.push(actionItem("Rescan workspace", "refresh", "secuguard.scanWorkspace", "Re-run every scanner over the workspace."));
    items.push(actionItem("Open dashboard", "dashboard", "secuguard.openDashboard", "Tabs, charts, sorting and filtering for every finding."));
    items.push(actionItem("Generate missing tests", "beaker", "secuguard.generateAllTests", "Draft unit tests for exported symbols that have none."));
    items.push(actionItem("Export report", "export", "secuguard.exportReport", "Write a Markdown/CSV/SARIF/JSON report."));
    items.push(actionItem("Copy findings as Markdown", "clippy", "secuguard.copyFindings", "Copy the current findings for a PR or issue."));

    return items;
  }
}

