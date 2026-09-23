import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanResult, ScannerAdapter } from "../types";
import {
  exportedSymbolsFromSource,
  isCodeFile,
  isTestFile,
  relPath,
  walkFiles,
} from "./shared/exportedSymbols";

const MAX_FILE_BYTES = 2 * 1024 * 1024;

interface TestCoverageOptions {
  testFileGlobs: string[];
  excludeGlobs: string[];
}

export class TestCoverageScanner implements ScannerAdapter {
  name = "secuguard-test-coverage-scanner";

  constructor(private options: TestCoverageOptions) {}

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async scan(targetPaths: string[], workspaceRoot: string): Promise<ScanResult> {
    const start = Date.now();

    // 1. Harvest every test file in the workspace (relative paths).
    const allWorkspaceFiles: string[] = [];
    walkFiles(workspaceRoot, this.options.excludeGlobs, allWorkspaceFiles);
    const testFiles = allWorkspaceFiles.filter((f) => isTestFile(relPath(f, workspaceRoot), this.options.testFileGlobs));
    let testsBlob = "";
    for (const t of testFiles) {
      try {
        testsBlob += fs.readFileSync(t, "utf8");
      } catch {
        // unreadable test file — ignore
      }
    }

    // 2. Enumerate source symbols from the scanned paths.
    const sourceFiles: string[] = [];
    for (const p of targetPaths) {
      if (!fs.existsSync(p)) continue;
      const stat = fs.statSync(p);
      if (stat.isDirectory()) walkFiles(p, this.options.excludeGlobs, sourceFiles);
      else if (!p.split(path.sep).join("/").includes("/.secuguard/")) sourceFiles.push(p);
    }

    const findings: RawFinding[] = [];
    for (const f of sourceFiles) {
      if (!isCodeFile(f)) continue;
      if (isTestFile(relPath(f, workspaceRoot), this.options.testFileGlobs)) continue; // don't demand tests for test files
      let content: string;
      try {
        const buf = fs.readFileSync(f);
        if (buf.length > MAX_FILE_BYTES) continue;
        content = buf.toString("utf8");
      } catch {
        continue;
      }
      const rel = relPath(f, workspaceRoot);
      const symbols = exportedSymbolsFromSource(content, rel);
      const ext = rel.split(".").pop()?.toLowerCase() ?? "";
      for (const sym of symbols) {
        // crude but reliable: a test file must reference the symbol by name somewhere
        const referenced = new RegExp(`\\b${escapeRegExp(sym.name)}\\b`).test(testsBlob);
        if (referenced) continue;
        findings.push({
          ruleId: "sg-test-coverage-missing",
          title: `No test found for exported \`${sym.name}\``,
          description: `${sym.kind} \`${sym.name}\` is exported from this module but is not referenced by any test file under the configured test globs (${this.options.testFileGlobs.join(", ")}). Consider adding a unit test covering its main behavior and edge cases.`,
          severity: "low",
          cwe: [],
          category: "test-coverage",
          language: ext,
          file: rel,
          startLine: sym.line,
          endLine: sym.line,
          codeSnippet: sym.codeSnippet,
          sourceScanner: "secuguard-test-coverage-scanner",
          remediation: `Write a unit test for \`${sym.name}\`. Use "SecuGuard: Generate Test" to draft one, then review and insert it.`,
          effort: "small",
        });
      }
    }

    return { findings, scanner: this.name, durationMs: Date.now() - start, filesScanned: sourceFiles.length };
  }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}