import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanResult, ScannerAdapter } from "../types";
import { rulesForLanguage, extOf } from "../rules/rules";

const MAX_FILE_BYTES = 2 * 1024 * 1024; // skip files over 2MB (likely generated/binary)
const CONTEXT_LINES = 2;

function snippetAround(lines: string[], lineIdx: number): string {
  const start = Math.max(0, lineIdx - CONTEXT_LINES);
  const end = Math.min(lines.length, lineIdx + CONTEXT_LINES + 1);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1}| ${l}`)
    .join("\n");
}

function isLikelyBinary(buf: Buffer): boolean {
  const len = Math.min(buf.length, 8000);
  for (let i = 0; i < len; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function scanFile(filePath: string, workspaceRoot: string): RawFinding[] {
  const ext = extOf(filePath);
  const rules = rulesForLanguage(ext);
  if (rules.length === 0) return [];

  let buf: Buffer;
  try {
    buf = fs.readFileSync(filePath);
  } catch {
    return [];
  }
  if (buf.length > MAX_FILE_BYTES || isLikelyBinary(buf)) return [];

  const content = buf.toString("utf8");
  const lines = content.split(/\r?\n/);
  const relFile = path.relative(workspaceRoot, filePath).split(path.sep).join("/");
  const findings: RawFinding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip obvious comment-only lines for a handful of noisy rules to cut false positives
    for (const rule of rules) {
      const match = rule.pattern.exec(line);
      if (!match) continue;
      if (rule.excludeIfMatches && rule.excludeIfMatches.test(line)) continue;

      findings.push({
        ruleId: rule.id,
        title: rule.title,
        description: rule.description,
        severity: rule.severity,
        cwe: rule.cwe,
        owasp: rule.owasp,
        category: rule.category,
        language: ext,
        file: relFile,
        startLine: i + 1,
        endLine: i + 1,
        startCol: match.index,
        endCol: match.index + match[0].length,
        codeSnippet: snippetAround(lines, i),
        sourceScanner: "secuguard-pattern-engine",
        remediation: rule.remediation,
      });
    }
  }
  return findings;
}

function walk(dir: string, excludeGlobs: string[], out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (shouldExclude(full, excludeGlobs)) continue;
    if (entry.isDirectory()) {
      walk(full, excludeGlobs, out);
    } else if (entry.isFile()) {
      out.push(full);
    }
  }
}

function shouldExclude(fullPath: string, globs: string[]): boolean {
  const normalized = fullPath.split(path.sep).join("/");
  return globs.some((g) => {
    const core = g.replace(/^\*\*\//, "").replace(/\/\*\*$/, "").replace(/\*/g, "");
    return core.length > 0 && normalized.includes(core);
  });
}

export class PatternScanner implements ScannerAdapter {
  name = "secuguard-pattern-engine";

  constructor(private excludeGlobs: string[] = []) {}

  async isAvailable(): Promise<boolean> {
    return true; // always available, pure JS
  }

  async scan(targetPaths: string[], workspaceRoot: string): Promise<ScanResult> {
    const start = Date.now();
    const files: string[] = [];
    for (const p of targetPaths) {
      const stat = fs.existsSync(p) ? fs.statSync(p) : null;
      if (!stat) continue;
      if (stat.isDirectory()) {
        walk(p, this.excludeGlobs, files);
      } else {
        files.push(p);
      }
    }

    const findings: RawFinding[] = [];
    for (const f of files) {
      try {
        findings.push(...scanFile(f, workspaceRoot));
      } catch {
        // skip unreadable files, don't fail the whole scan
      }
    }

    return {
      findings,
      scanner: this.name,
      durationMs: Date.now() - start,
      filesScanned: files.length,
    };
  }
}
