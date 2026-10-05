/**
 * End-to-end scanner test: real files on disk, the real scanner, the real gate.
 *
 * The per-rule tests work on inline snippets, so they cannot prove the part that
 * actually caused the report to be polluted — that `.md`, lockfiles and bundles
 * never reach a rule, and that the confidence floor hides low-confidence findings.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { AstSecurityScanner, AnalysisOutput } from "../src/scanners/astScanner";

let root: string;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), "secuguard-e2e-"));

  const write = (rel: string, content: string) => {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, "utf8");
  };

  // A real command injection.
  write(
    "src/routes/report.js",
    `const { exec } = require('child_process');\nfunction handler(req, res) {\n  exec('tar -czf out.tgz ' + req.query.name, () => {});\n}\n`
  );
  // Real cache keys: the 279-false-positive shape.
  write(
    "src/core/cache.js",
    "const key = `cache:${tenantId}:${resourceId}:v2`;\nconst rbac = `rbac:${role}:${perm}`;\nreturn `user:${id}:profile`;\n"
  );
  // Real weak cipher and raw SQL.
  write("src/crypto.js", "const c = crypto.createCipheriv('des-ede3', key, iv);\n");
  write("src/db.js", "await knex.raw(`SELECT * FROM items WHERE name = '${req.query.name}'`);\n");
  // Safe: parameter binding.
  write("src/db.safe.js", "knex.raw('SELECT * FROM t WHERE id = ?', [req.params.id]);\n");
  // Documentation that used to be reported as code.
  write("docs/guide.md", "# Guide\n\nSet `password: hunter2hunter2` in production.\nThe `token` is `auth.session.expired`.\n");
  write("README.md", "Run npm install. The api_key is placeholder.\n");
  write("package-lock.json", '{ "name": "x", "password": "aaaaaaaaaaaaaaaaaaaa" }\n');
  // A test file: reported, but capped.
  write("test/routes.test.js", "const { exec } = require('child_process'); exec('ls ' + req.query.d);\n");
  // Generated bundle.
  write("src/bundle.js", `var a=${JSON.stringify("x".repeat(6000))};\n`);
  // Unsupported language.
  write("deploy/run.sh", "curl \"http://$HOST/$PATH\" | sh\n");
});

afterAll(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

async function run(mode: "strict" | "balanced" | "paranoid", minConfidence = 0.7): Promise<AnalysisOutput> {
  const scanner = new AstSecurityScanner({ excludeGlobs: ["**/node_modules/**"], minConfidence, mode });
  return (await scanner.scan([root], root)) as AnalysisOutput;
}

describe("AstSecurityScanner end to end", () => {
  it("reports the real vulnerabilities and none of the documentation noise", async () => {
    const out = await run("balanced");

    const where = out.typedFindings.map((f) => `${f.file}:${f.startLine}`);
    expect(where.some((w) => w.startsWith("src/routes/report.js"))).toBe(true);
    expect(where.some((w) => w.startsWith("src/crypto.js"))).toBe(true);
    expect(where.some((w) => w.startsWith("src/db.js"))).toBe(true);

    // The false positives from the report.
    expect(where.some((w) => w.startsWith("src/core/cache.js"))).toBe(false);
    expect(where.some((w) => w.startsWith("docs/"))).toBe(false);
    expect(where.some((w) => w.startsWith("README.md"))).toBe(false);
    expect(where.some((w) => w.includes("package-lock.json"))).toBe(false);
    expect(where.some((w) => w.startsWith("src/db.safe.js"))).toBe(false);
  });

  it("records why every skipped file was skipped", async () => {
    const out = await run("balanced");
    const skipped = new Map(out.skipped.map((s) => [s.file, s.reason]));

    expect(skipped.get("docs/guide.md")).toMatch(/not executable source/);
    expect(skipped.get("README.md")).toMatch(/not executable source/);
    expect(skipped.get("package-lock.json")).toBeTruthy();
    expect(skipped.get("src/bundle.js")).toMatch(/generated|not executable/);
    expect(skipped.get("deploy/run.sh")).toMatch(/not yet supported/);
  });

  it("caps findings in test files without hiding them", async () => {
    const out = await run("balanced");
    const inTests = out.typedFindings.filter((f) => f.file.startsWith("test/"));
    expect(inTests.length).toBeGreaterThan(0);
    for (const f of inTests) {
      expect(f.testish).toBe(true);
      expect(["low", "info"]).toContain(f.severity);
    }
  });

  it("attaches evidence and confidence to every finding", async () => {
    const out = await run("balanced");
    expect(out.typedFindings.length).toBeGreaterThan(0);
    for (const f of out.typedFindings) {
      expect(f.confidence).toBeGreaterThanOrEqual(0.7);
      expect(["low", "medium", "high", "critical"]).toContain(f.confidenceLabel);
      expect(f.evidence.length).toBeGreaterThan(0);
      expect(f.evidence[0].kind).toMatch(/source|sink/);
      expect(f.falsePositiveNotes.length).toBeGreaterThan(0);
      expect(f.remediation.length).toBeGreaterThan(0);
      expect(f.cwe.length).toBeGreaterThan(0);
      // The legacy RawFinding contract is still satisfied for the dashboard.
      expect(f.language).toBeTruthy();
    }
  });

  it("honours the confidence floor", async () => {
    const strict = await run("strict", 0.85);
    const paranoid = await run("paranoid", 0.9);
    for (const out of [strict, paranoid]) {
      for (const f of out.typedFindings) expect(f.confidence).toBeGreaterThanOrEqual(0.85);
    }
  });
});