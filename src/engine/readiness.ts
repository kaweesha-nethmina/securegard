import { spawn } from "child_process";
import * as path from "path";
import { Orchestrator } from "./orchestrator";
import { Vulnerability, VulnStatus } from "../types";
import { isCodeFile } from "../scanners/shared/exportedSymbols";

export interface ReadyItem {
  title: string;
  file: string;
  line: number;
}

export interface ReadyCheck {
  id: string;
  label: string;
  ok: boolean;
  items: ReadyItem[];
}

export interface ReadinessReport {
  baseBranch: string;
  changedFiles: string[];
  notGitRepo: boolean;
  checks: ReadyCheck[];
  /** Project-wide QA state from a full-workspace scan (not limited to changed files). */
  projectWide?: ProjectWideQa;
}

export interface ProjectWideQa {
  filesScanned: number;
  durationMs: number;
  counts: { category: string; count: number }[];
}

export function runGit(cmd: string, args: string[], cwd: string): Promise<{ stdout: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, shell: false });
    let stdout = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.on("error", () => resolve({ stdout: "", code: -1 }));
    child.on("close", (code) => resolve({ stdout, code: code ?? -1 }));
  });
}

function listOut(stdout: string): string[] {
  return stdout
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Files changed vs the configured base branch. Tries `git diff --name-only <base>`,
 * then falls back to `git diff --name-only HEAD`. Returns null when not a git repo.
 */
export async function gitChangedFiles(workspaceRoot: string, base: string): Promise<string[] | null> {
  const isRepo = await runGit("git", ["rev-parse", "--is-inside-work-tree"], workspaceRoot);
  if (isRepo.code !== 0) return null;

  const againstBase = await runGit("git", ["diff", "--name-only", base], workspaceRoot);
  if (againstBase.code === 0 && againstBase.stdout.trim()) return listOut(againstBase.stdout);

  const againstHead = await runGit("git", ["diff", "--name-only", "HEAD"], workspaceRoot);
  if (againstHead.code === 0 && againstHead.stdout.trim()) return listOut(againstHead.stdout);

  return [];
}

export async function runReadinessCheck(
  workspaceRoot: string,
  orchestrator: Orchestrator,
  config: { get: (key: string, def?: unknown) => any }
): Promise<ReadinessReport> {
  const base = config.get("readinessCheck.baseBranch", "main");
  const changed = await gitChangedFiles(workspaceRoot, base);

  const checks: ReadyCheck[] = [
    { id: "critical", label: "No new critical/high severity findings", ok: true, items: [] },
    { id: "todos", label: "No new TODO/FIXME/HACK markers", ok: true, items: [] },
    { id: "tests", label: "Every new exported symbol has a test", ok: true, items: [] },
    { id: "debug", label: "No debug statements", ok: true, items: [] },
    { id: "long", label: "No functions past the max-lines threshold", ok: true, items: [] },
  ];

  if (changed === null) {
    return { baseBranch: base, changedFiles: [], notGitRepo: true, checks };
  }

  // Scan the ENTIRE workspace so the QA section (Quality / Test Coverage / Documentation
  // dashboard tabs and the project-wide summary below) always reflects the whole project,
  // not just the files about to be committed.
  let vulns: Vulnerability[] = [];
  let filesScanned = 0;
  let durationMs = 0;
  try {
    const result = await orchestrator.runScan([workspaceRoot]);
    vulns = result.vulnerabilities;
    filesScanned = result.stats.filesScanned;
    durationMs = result.stats.durationMs;
  } catch {
    vulns = [];
  }

  const closed: VulnStatus[] = ["fixed", "false_positive", "wont_fix"];
  const active = vulns.filter((v) => !closed.includes(v.status));

  // Diff-scoped "new" items: only findings in the files slated for this change.
  const changedAbs = new Set(
    changed
      .filter((f) => isCodeFile(f))
      .map((f) => path.join(workspaceRoot, f).replace(/\\/g, "/"))
  );
  const inChanged = active.filter((v) => changedAbs.has(path.join(workspaceRoot, v.file).replace(/\\/g, "/")));

  const toItems = (list: Vulnerability[]): ReadyItem[] =>
    list.map((v) => ({ title: v.title, file: v.file, line: v.startLine }));

  const check = (id: string, list: Vulnerability[]) => {
    const c = checks.find((x) => x.id === id)!;
    c.items = toItems(list);
    c.ok = c.items.length === 0;
  };

  check("critical", inChanged.filter((v) => v.severity === "critical" || v.severity === "high"));
  check("todos", inChanged.filter((v) => v.ruleId === "sg-quality-todo"));
  check("tests", inChanged.filter((v) => v.ruleId === "sg-test-coverage-missing"));
  check("debug", inChanged.filter((v) => v.ruleId === "sg-quality-debug"));
  check("long", inChanged.filter((v) => v.ruleId === "sg-quality-long-function"));

  // Project-wide QA counts (whole workspace, active findings per category).
  const categoryCounts: { category: string; count: number }[] = [];
  for (const v of active) {
    const entry = categoryCounts.find((c) => c.category === v.category);
    if (entry) entry.count++;
    else categoryCounts.push({ category: v.category, count: 1 });
  }
  categoryCounts.sort((a, b) => b.count - a.count);

  return {
    baseBranch: base,
    changedFiles: changed,
    notGitRepo: false,
    checks,
    projectWide: { filesScanned, durationMs, counts: categoryCounts },
  };
}

function vscodeSettings(config: any) {
  return {
    maxFunctionLines: config.get("quality.maxFunctionLines", 80),
    maxNestingDepth: config.get("quality.maxNestingDepth", 4),
  };
}

/** Renders the report as a ready-to-paste GitHub PR comment. */
export function buildPrComment(report: ReadinessReport, scanDurationMs?: number): string {
  const overall = report.notGitRepo ? false : report.checks.every((c) => c.ok);
  const lines: string[] = [];
  lines.push(`## 🛡 SecuGuard QA Readiness${report.notGitRepo ? " — skipped (not a git repo)" : overall ? " ✅ PASS" : " ❌ FAIL"}`);
  lines.push("");
  if (!report.notGitRepo) {
    lines.push(`**Base branch:** \`${report.baseBranch}\` · **Changed files:** ${report.changedFiles.length}${scanDurationMs ? ` · Scan: ${scanDurationMs}ms` : ""}`);
    lines.push("");
    for (const c of report.checks) {
      lines.push(`- ${c.ok ? "✅" : "❌"} ${c.label} (${c.items.length})`);
    }
    lines.push("");
    lines.push("<details>");
    lines.push("<summary>Details</summary>");
    lines.push("");
    for (const c of report.checks) {
      lines.push(`### ${c.label}`);
      if (c.items.length === 0) {
        lines.push("_Clean._");
        lines.push("");
        continue;
      }
      for (const it of c.items) {
        lines.push(`- \`${it.file}:${it.line}\` — ${it.title}`);
      }
      lines.push("");
    }
    lines.push("</details>");
    lines.push("");
    if (report.projectWide) {
      const { projectWide } = report;
      const all = projectWide.counts.reduce((s, c) => s + c.count, 0);
      lines.push("### Project-wide QA state");
      lines.push("");
      lines.push(`Beyond this diff — the full workspace was scanned (${projectWide.filesScanned} files, ${projectWide.durationMs}ms), so the QA section reflects the whole project, not just changed files.`);
      lines.push("");
      if (all === 0) {
        lines.push("_No active findings across any category._");
      } else {
        lines.push(`- **${all}** active findings across ${projectWide.counts.length} category(ies):`);
        for (const c of projectWide.counts) {
          lines.push(`  - ${c.category}: ${c.count}`);
        }
      }
    }
  }
  return lines.join("\n");
}