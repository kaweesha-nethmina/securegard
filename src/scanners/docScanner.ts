import * as fs from "fs";
import * as path from "path";
import { RawFinding, ScanResult, ScannerAdapter } from "../types";
import { exportedSymbolsFromSource, isCodeFile, looksLikeDocs, relPath, walkFiles } from "./shared/exportedSymbols";

const MAX_FILE_BYTES = 2 * 1024 * 1024;

export class DocScanner implements ScannerAdapter {
  name = "secuguard-doc-scanner";

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
      if (stat.isDirectory()) walkFiles(p, this.excludeGlobs, files);
      else if (!p.split(path.sep).join("/").includes("/.secuguard/")) files.push(p);
    }

    const findings: RawFinding[] = [];
    for (const f of files) {
      if (!isCodeFile(f)) continue;
      let content: string;
      try {
        const buf = fs.readFileSync(f);
        if (buf.length > MAX_FILE_BYTES) continue;
        content = buf.toString("utf8");
      } catch {
        continue;
      }
      const rel = relPath(f, workspaceRoot);
      const ext = rel.split(".").pop()?.toLowerCase() ?? "";
      for (const sym of exportedSymbolsFromSource(content, rel)) {
        if (looksLikeDocs(sym.docLine)) continue;
        findings.push({
          ruleId: "sg-doc-missing",
          title: `Missing documentation for exported \`${sym.name}\``,
          description: `The exported ${sym.kind} \`${sym.name}\` has no JSDoc/docstring directly above its definition. Public API surface should document its purpose, parameters, and return value.`,
          severity: "info",
          cwe: [],
          category: "documentation",
          language: ext,
          file: rel,
          startLine: sym.line,
          endLine: sym.line,
          codeSnippet: sym.codeSnippet,
          sourceScanner: "secuguard-doc-scanner",
          remediation: `Add a brief doc comment above \`${sym.name}\` describing what it does, its inputs, and its output.`,
          effort: "trivial",
        });
      }
    }

    return { findings, scanner: this.name, durationMs: Date.now() - start, filesScanned: files.length };
  }
}