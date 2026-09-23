import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanResult, ScannerAdapter } from "../types";
import { extOf } from "../rules/rules";

const SKIP_EXT = new Set(["png", "jpg", "jpeg", "gif", "ico", "svg", "woff", "woff2", "ttf", "eot", "lock", "map"]);
const ASSIGNMENT_RE = /\b([A-Za-z_][A-Za-z0-9_]{2,40})\s*[:=]\s*["'`]([A-Za-z0-9+/_\-=.]{20,120})["'`]/g;
const LOOKS_LIKE_TOKEN_NAME = /(key|secret|token|password|pwd|passwd|credential|auth|apikey|signature)/i;
const PLACEHOLDER_RE = /(example|placeholder|xxxx|changeme|your[_-]?|dummy|sample|test[_-]?key|<.*>|\.\.\.)/i;

function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function scanFile(filePath: string, workspaceRoot: string): RawFinding[] {
  const ext = extOf(filePath);
  if (SKIP_EXT.has(ext)) return [];
  let content: string;
  try {
    const buf = fs.readFileSync(filePath);
    if (buf.length > 1.5 * 1024 * 1024) return [];
    content = buf.toString("utf8");
  } catch {
    return [];
  }

  const lines = content.split(/\r?\n/);
  const relFile = path.relative(workspaceRoot, filePath).split(path.sep).join("/");
  const findings: RawFinding[] = [];

  lines.forEach((line, idx) => {
    let m: RegExpExecArray | null;
    ASSIGNMENT_RE.lastIndex = 0;
    while ((m = ASSIGNMENT_RE.exec(line)) !== null) {
      const [, varName, value] = m;
      if (PLACEHOLDER_RE.test(value) || PLACEHOLDER_RE.test(varName)) continue;
      if (/^(process\.env|os\.environ|getenv)/.test(value)) continue;

      const entropy = shannonEntropy(value);
      const nameHints = LOOKS_LIKE_TOKEN_NAME.test(varName);
      // High confidence: variable name hints AND high entropy.
      // Medium confidence: very high entropy alone (looks like a real random secret regardless of name).
      const isHighConfidence = nameHints && entropy > 3.3;
      const isMediumConfidence = !nameHints && entropy > 4.3 && value.length >= 24;

      if (isHighConfidence || isMediumConfidence) {
        findings.push({
          ruleId: "sg-entropy-secret",
          title: isHighConfidence ? "Likely hardcoded secret (high entropy)" : "Possible embedded secret (very high entropy string)",
          description: `The value assigned to \`${varName}\` has entropy ${entropy.toFixed(
            2
          )} bits/char, consistent with a random API key, token, or credential rather than ordinary text (CWE-798).`,
          severity: isHighConfidence ? "critical" : "medium",
          cwe: ["CWE-798"],
          owasp: "A07:2021 - Identification and Authentication Failures",
          category: "secret",
          language: ext,
          file: relFile,
          startLine: idx + 1,
          endLine: idx + 1,
          codeSnippet: `${idx + 1}| ${line.trim().slice(0, 160)}`,
          sourceScanner: "secuguard-entropy-scanner",
          remediation: "Move this value to an environment variable or secrets manager, remove it from git history, and rotate the credential.",
        });
      }
    }
  });

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
    const normalized = full.split(path.sep).join("/");
    if (excludeGlobs.some((g) => normalized.includes(g.replace(/^\*\*\//, "").replace(/\/\*\*$/, "").replace(/\*/g, "")))) {
      continue;
    }
    if (entry.isDirectory()) walk(full, excludeGlobs, out);
    else if (entry.isFile()) out.push(full);
  }
}

export class SecretsScanner implements ScannerAdapter {
  name = "secuguard-entropy-scanner";
  constructor(private excludeGlobs: string[] = []) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async scan(targetPaths: string[], workspaceRoot: string): Promise<ScanResult> {
    const start = Date.now();
    const files: string[] = [];
    for (const p of targetPaths) {
      if (!fs.existsSync(p)) continue;
      const stat = fs.statSync(p);
      if (stat.isDirectory()) walk(p, this.excludeGlobs, files);
      else files.push(p);
    }
    const findings: RawFinding[] = [];
    for (const f of files) {
      try {
        findings.push(...scanFile(f, workspaceRoot));
      } catch {
        /* skip */
      }
    }
    return { findings, scanner: this.name, durationMs: Date.now() - start, filesScanned: files.length };
  }
}
