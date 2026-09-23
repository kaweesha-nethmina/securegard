import { spawn } from "child_process";
import * as path from "path";
import { RawFinding, ScanResult, ScannerAdapter, Severity } from "../types";

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    default:
      return "low";
  }
}

function run(cmd: string, args: string[], cwd: string): Promise<{ stdout: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", () => resolve({ stdout: "", code: -1 }));
    child.on("close", (code) => resolve({ stdout, code: code ?? -1 }));
  });
}

export class SemgrepAdapter implements ScannerAdapter {
  name = "semgrep";

  async isAvailable(): Promise<boolean> {
    const result = await run("semgrep", ["--version"], process.cwd());
    return result.code === 0;
  }

  async scan(targetPaths: string[], workspaceRoot: string): Promise<ScanResult> {
    const start = Date.now();
    const args = [
      "--config",
      "p/security-audit",
      "--config",
      "p/owasp-top-ten",
      "--json",
      "--quiet",
      "--timeout",
      "60",
      ...targetPaths,
    ];
    const { stdout, code } = await run("semgrep", args, workspaceRoot);

    if (code !== 0 && !stdout) {
      return { findings: [], scanner: this.name, durationMs: Date.now() - start, filesScanned: 0, error: "semgrep exited with an error" };
    }

    let parsed: any;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      return { findings: [], scanner: this.name, durationMs: Date.now() - start, filesScanned: 0, error: "failed to parse semgrep output" };
    }

    const findings: RawFinding[] = (parsed.results || []).map((r: any) => {
      const relFile = path.relative(workspaceRoot, r.path).split(path.sep).join("/");
      const cwe: string[] = r.extra?.metadata?.cwe
        ? Array.isArray(r.extra.metadata.cwe)
          ? r.extra.metadata.cwe
          : [r.extra.metadata.cwe]
        : [];
      return {
        ruleId: r.check_id,
        title: r.extra?.metadata?.shortlink || r.check_id.split(".").pop() || r.check_id,
        description: r.extra?.message || "Semgrep finding — see rule for details.",
        severity: mapSeverity(r.extra?.severity),
        cwe,
        owasp: r.extra?.metadata?.owasp ? String(r.extra.metadata.owasp) : undefined,
        category: "sast",
        language: path.extname(r.path).replace(".", ""),
        file: relFile,
        startLine: r.start?.line ?? 1,
        endLine: r.end?.line ?? r.start?.line ?? 1,
        codeSnippet: (r.extra?.lines || "").slice(0, 500),
        sourceScanner: "semgrep",
        remediation: r.extra?.metadata?.fix || undefined,
      } as RawFinding;
    });

    return { findings, scanner: this.name, durationMs: Date.now() - start, filesScanned: (parsed.paths?.scanned || []).length };
  }
}
