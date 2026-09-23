import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanResult, ScannerAdapter, Effort } from "../types";
import { relPath, walkFiles, isCodeFile } from "./shared/exportedSymbols";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const TODO_RE = /\b(TODO|FIXME|HACK|XXX)\b/;
const DEBUG_JS = /\bconsole\.(log|debug)\(|\bdebugger\b/;
const DEBUG_PY = /\bpdb\.set_trace\(|\bbreakpoint\(\)|print\(\s*(?!["'])/;
const FUNC_START_JS = /(?:function\s+[\w$]*\s*\([^)]*\)|\b[\w$]+\s*=\s*(?:async\s+)?\([^)]*\)\s*=>|\([^)]*\)\s*=>)/;
const SYNTAX_EXT = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs"]);

interface ScanSettings {
  maxFunctionLines: number;
  maxNestingDepth: number;
}

function stripStrings(line: string): string {
  return line.replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, "");
}

export class QualityScanner implements ScannerAdapter {
  name = "secuguard-quality-scanner";

  constructor(
    private excludeGlobs: string[] = [],
    private settings: ScanSettings = { maxFunctionLines: 80, maxNestingDepth: 4 }
  ) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async scan(targetPaths: string[], workspaceRoot: string): Promise<ScanResult> {
    const start = Date.now();
    const files: string[] = [];
    for (const p of targetPaths) {
      if (!fs.existsSync(p)) continue;
      const stat = fs.statSync(p);
      if (stat.isDirectory()) walkFiles(p, this.excludeGlobs, files);
      else if (!p.split(path.sep).join("/").includes("/.secuguard/")) files.push(p);
    }

    const findings: RawFinding[] = [];
    for (const f of files) {
      if (!isCodeFile(f)) continue;
      try {
        findings.push(...scanFile(f, workspaceRoot, this.settings));
      } catch {
        // skip unreadable files
      }
    }
    return { findings, scanner: this.name, durationMs: Date.now() - start, filesScanned: files.length };
  }
}

function scanFile(filePath: string, workspaceRoot: string, cfg: ScanSettings): RawFinding[] {
  const buf = fs.readFileSync(filePath);
  if (buf.length > MAX_FILE_BYTES) return [];
  const content = buf.toString("utf8");
  const lines = content.split(/\r?\n/);
  const rel = relPath(filePath, workspaceRoot);
  const ext = rel.split(".").pop()?.toLowerCase() ?? "";
  const isPy = ext === "py";
  const findings: RawFinding[] = [];

  let depth = 0;
  let seenFixedTodo = false;
  let seenDeepNesting = false;
  let longestStart = -1;

  const push = (ruleId: string, title: string, lineIdx: number, effort: Effort, remediation: string, description: string, severity: "low" | "info") => {
    findings.push({
      ruleId,
      title,
      description,
      severity,
      cwe: [],
      category: "quality",
      language: ext,
      file: rel,
      startLine: lineIdx + 1,
      endLine: lineIdx + 1,
      codeSnippet: snippetAround(lines, lineIdx, 1),
      sourceScanner: "secuguard-quality-scanner",
      remediation,
      effort,
    });
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // TODOs / markers
    const m = TODO_RE.exec(line);
    if (m) {
      const marker = m[1];
      const note = line.slice(line.indexOf(marker) + marker.length).trim().replace(/^[:/-]\s*/, "");
      if (!seenFixedTodo) {
        push(
          "sg-quality-todo",
          `${marker} marker left in code`,
          i,
          "trivial",
          "Resolve the TODO before merging, or track it as a SecuGuard Todo.",
          note
            ? `Found a \`${marker}\` marker: “${note.slice(0, 140)}”. Leftover notes and unfinished work are a common source of tech debt.`
            : `Found a bare \`${marker}\` marker with no notes attached.`,
          "info"
        );
        seenFixedTodo = true;
      }
    }

    if (isPy) {
      if (DEBUG_PY.test(line)) {
        push(
          "sg-quality-debug",
          "Debug statement left in code",
          i,
          "trivial",
          "Remove the debug output before merging, or route it through a proper logger.",
          "A debug hook (`print`, `pdb.set_trace`, or `breakpoint()`) was found in a non-test file.",
          "low"
        );
      }
    } else if (DEBUG_JS.test(line)) {
      push(
        "sg-quality-debug",
        "Debug statement left in code",
        i,
        "trivial",
        "Remove the debug output before merging, or route it through a proper logger.",
        "A debug statement (`console.log`, `console.debug`, or `debugger`) was found.",
        "low"
      );
    }

    if (isPy || SYNTAX_EXT.has(ext)) {
      // track brace depth (JS/TS) to spot deep nesting + long functions
      const cleaned = isPy ? line : stripStrings(line);
      const opens = (cleaned.match(/[{([]/g) || []).length;
      const closes = (cleaned.match(/[})]/g) || []).length;
      depth += opens - closes;
      if (isPy) {
        // python: depth from indentation
        depth = Math.max(depth, Math.floor((line.match(/^(\s*)/)![1].replace(/\t/g, "  ").length) / 2));
      }

      if (depth > cfg.maxNestingDepth && !seenDeepNesting) {
        push(
          "sg-quality-nesting",
          "Deeply nested code",
          i,
          "small",
          "Flatten deeply nested conditions with early returns / guard clauses, or extract nested blocks into functions.",
          `Code reaches a nesting depth of ${depth}, above the configured threshold of ${cfg.maxNestingDepth} (secuguard.quality.maxNestingDepth).`,
          "low"
        );
        seenDeepNesting = true;
      }

      // long function tracking
      if (longestStart < 0 && FUNC_START_JS.test(line)) {
        longestStart = i;
      }
      if (longestStart >= 0 && depth <= 0 && i > longestStart) {
        const span = i - longestStart;
        if (span >= cfg.maxFunctionLines) {
          push(
            "sg-quality-long-function",
            `Function is ${span} lines long (threshold ${cfg.maxFunctionLines})`,
            longestStart,
            "medium",
            "Split this function into smaller, single-purpose functions and extract shared logic.",
            `This function spans ${span} lines, at or above the configured threshold of ${cfg.maxFunctionLines} (secuguard.quality.maxFunctionLines). Long functions are harder to read, test, and review.`,
            "low"
          );
        }
        longestStart = -1;
      }
      if (depth < 0) depth = 0;
    }
  }

  return findings;
}

function snippetAround(lines: string[], lineIdx: number, radius: number): string {
  const s = Math.max(0, lineIdx - radius);
  const e = Math.min(lines.length, lineIdx + radius + 1);
  return lines.slice(s, e).map((l, i) => `${s + i + 1}| ${l}`).join("\n");
}