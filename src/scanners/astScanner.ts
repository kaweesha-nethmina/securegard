/**
 * AST security scanner.
 *
 * Replaces the line-by-line regex engine. Every rule here must prove that a real
 * sink receives real untrusted data; text that merely *looks* like a dangerous
 * call is not a finding.
 *
 * The scanner owns file eligibility (via `eligibility.ts`), so documentation,
 * lockfiles, bundles and SecuGuard's own output never reach a rule.
 */

import * as fs from "fs";
import * as path from "path";
import { ScanResult, ScannerAdapter } from "../types";
import { createFileContext } from "../analysis/context";
import { SecurityFinding } from "../analysis/finding";
import {
  ExcludeMatcher,
  collectAnalysableFiles,
  readIgnoreFile,
  checkFileEligibility,
  AST_EXTENSIONS,
} from "./eligibility";
import { detectCommandInjection, detectShellTrueSpawn } from "../rules/commandInjection";
import { detectWeakCipher } from "../rules/weakCipher";
import { detectSqlInjection } from "../rules/sqlInjection";
import { detectHardcodedSecret } from "../rules/secrets";
import { detectInsecureRandom } from "../rules/insecureRandom";
import { detectRedos } from "../rules/redos";

const MAX_FILE_BYTES = 2 * 1024 * 1024;

export interface AstScannerOptions {
  excludeGlobs: string[];
  /** Findings below this confidence are dropped from the report. */
  minConfidence: number;
  mode: "strict" | "balanced" | "paranoid";
}

export interface AnalysisOutput extends ScanResult {
  /** Findings with the full evidence model attached. */
  typedFindings: SecurityFinding[];
  /** Files skipped, with the reason — surfaced in the dashboard for trust. */
  skipped: { file: string; reason: string }[];
}

/** Per-mode confidence floor. */
const MODE_FLOOR: Record<AstScannerOptions["mode"], number> = {
  paranoid: 0.9,
  strict: 0.85,
  balanced: 0.7,
};

export class AstSecurityScanner implements ScannerAdapter {
  name = "secuguard-ast-engine";

  constructor(private opts: AstScannerOptions) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async scan(targetPaths: string[], workspaceRoot: string): Promise<AnalysisOutput> {
    const start = Date.now();
    const matcher = new ExcludeMatcher({
      excludeGlobs: this.opts.excludeGlobs,
      ignoreFilePaths: readIgnoreFile(workspaceRoot),
    });

    const files = new Set<string>();
    const skipped: { file: string; reason: string }[] = [];
    const recordSkip = (file: string, reason: string) => skipped.push({ file, reason });

    for (const p of targetPaths) {
      const stat = fs.existsSync(p) ? fs.statSync(p) : null;
      if (!stat) continue;
      if (stat.isDirectory()) {
        for (const f of collectAnalysableFiles(p, workspaceRoot, matcher, MAX_FILE_BYTES, recordSkip)) {
          files.add(f);
        }
      } else {
        const rel = path.relative(workspaceRoot, p).split(path.sep).join("/");
        let content = "";
        try {
          content = fs.readFileSync(p, "utf8");
        } catch {
          /* ignore */
        }
        const check = checkFileEligibility(p, rel, content, matcher);
        if (check.eligible) files.add(p);
        else recordSkip(rel, check.reason ?? "excluded");
      }
    }

    const findings: SecurityFinding[] = [];
    const floor = Math.max(this.opts.minConfidence, MODE_FLOOR[this.opts.mode]);

    for (const abs of files) {
      const rel = path.relative(workspaceRoot, abs).split(path.sep).join("/");

      let content: string;
      try {
        const buf = fs.readFileSync(abs);
        if (buf.length > MAX_FILE_BYTES) {
          skipped.push({ file: rel, reason: "file larger than 2MB" });
          continue;
        }
        content = buf.toString("utf8");
      } catch {
        skipped.push({ file: rel, reason: "unreadable" });
        continue;
      }

      const check = checkFileEligibility(abs, rel, content, matcher);
      if (!check.eligible) {
        skipped.push({ file: rel, reason: check.reason ?? "excluded" });
        continue;
      }
      const ext = (rel.split(".").pop() ?? "").toLowerCase();
      if (!AST_EXTENSIONS.has(ext)) {
        skipped.push({ file: rel, reason: "language not yet supported by the AST engine" });
        continue;
      }

      const ctx = createFileContext(content, rel);
      if (!ctx) {
        // Unparseable files are reported as skipped rather than silently clean.
        skipped.push({ file: rel, reason: "could not be parsed — not analysed" });
        continue;
      }

      let found: SecurityFinding[] = [];
      try {
        found = [
          ...detectCommandInjection(ctx),
          ...detectShellTrueSpawn(ctx),
          ...detectWeakCipher(ctx),
          ...detectSqlInjection(ctx),
          ...detectHardcodedSecret(ctx),
          ...detectInsecureRandom(ctx),
          ...detectRedos(ctx),
        ];
      } catch (e) {
        skipped.push({ file: rel, reason: `rule error: ${(e as Error).message}` });
        continue;
      }

      // Hidden, never deleted: the dashboard can still show what was filtered.
      const language = (rel.split(".").pop() ?? "").toLowerCase();
      for (const f of found) {
        if (f.confidence < floor) continue;
        f.language = language;
        findings.push(f);
      }
    }

    findings.sort((a, b) => b.confidence - a.confidence || a.file.localeCompare(b.file) || a.startLine - b.startLine);

    return {
      // The legacy contract carries no evidence fields; consumers that need
      // them read `typedFindings` instead of re-deriving anything.
      findings: findings as unknown as ScanResult["findings"],
      typedFindings: findings,
      scanner: this.name,
      durationMs: Date.now() - start,
      filesScanned: files.size,
      skipped,
    } as AnalysisOutput;
  }
}

export type { SecurityFinding };