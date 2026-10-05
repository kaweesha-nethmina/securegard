/**
 * Recall guard on the repository's own vulnerable corpus.
 *
 * `test-corpus/vulnerable.js` is a checked-in fixture with labelled
 * vulnerabilities. The refactor routes CWE-78/89/327/338/798 to the AST engine
 * and leaves the rest to the pattern engine, so this test asserts the *union*
 * still finds every planted issue — i.e. precision was not bought with recall.
 */

import { describe, it, expect } from "vitest";
import * as fs from "fs";
import * as path from "path";
import { createFileContext } from "../src/analysis/context";
import { detectCommandInjection, detectShellTrueSpawn } from "../src/rules/commandInjection";
import { detectWeakCipher } from "../src/rules/weakCipher";
import { detectSqlInjection } from "../src/rules/sqlInjection";
import { detectHardcodedSecret } from "../src/rules/secrets";
import { detectInsecureRandom } from "../src/rules/insecureRandom";
import { detectRedos } from "../src/rules/redos";
import { RULES, rulesForLanguage } from "../src/rules/rules";

const ROOT = path.resolve(__dirname, "..");

/** Every detector, AST and legacy, as the orchestrator would run them. */
function allDetections(file: string): { ruleId: string; line: number }[] {
  const abs = path.join(ROOT, file);
  const content = fs.readFileSync(abs, "utf8");
  const out: { ruleId: string; line: number }[] = [];

  const ctx = createFileContext(content, file);
  if (ctx) {
    const ast = [
      ...detectCommandInjection(ctx),
      ...detectShellTrueSpawn(ctx),
      ...detectWeakCipher(ctx),
      ...detectSqlInjection(ctx),
      ...detectHardcodedSecret(ctx),
      ...detectInsecureRandom(ctx),
      ...detectRedos(ctx),
    ];
    for (const f of ast) out.push({ ruleId: f.ruleId, line: f.startLine });
  }

  // The legacy engine, skipping rules the AST engine superseded.
  const ext = file.split(".").pop() ?? "";
  for (const rule of rulesForLanguage(ext)) {
    if (rule.supersededForJsTsBy) continue;
    content.split(/\r?\n/).forEach((line, i) => {
      if (!rule.pattern.test(line)) return;
      if (rule.excludeIfMatches && rule.excludeIfMatches.test(line)) return;
      out.push({ ruleId: rule.id, line: i + 1 });
    });
  }
  return out;
}

/** CWE groups that must still be reported somewhere in the corpus. */
const REQUIRED: { label: string; cwe: string[] }[] = [
  { label: "SQL injection", cwe: ["CWE-89"] },
  { label: "hardcoded AWS key", cwe: ["CWE-798"] },
  { label: "hardcoded Stripe key", cwe: ["CWE-798"] },
  { label: "command injection", cwe: ["CWE-78"] },
  { label: "weak hash", cwe: ["CWE-327", "CWE-328"] },
  { label: "insecure randomness", cwe: ["CWE-338"] },
  { label: "XSS via innerHTML", cwe: ["CWE-79"] },
  { label: "eval of input", cwe: ["CWE-95", "CWE-94"] },
  { label: "CORS wildcard", cwe: ["CWE-942"] },
];

describe("recall on test-corpus/vulnerable.js", () => {
  it("still reports every planted vulnerability", () => {
    const found = allDetections("test-corpus/vulnerable.js");
    const covered = new Set(found.flatMap((f) => RULES.find((r) => r.id === f.ruleId)?.cwe ?? []));
    // AST rule ids are not in RULES, so map them too.
    const AST_CWE: Record<string, string[]> = {
      "sg-hardcoded-secret": ["CWE-798"],
      "sg-command-injection": ["CWE-78"],
      "sg-sql-injection-taint": ["CWE-89"],
      "sg-insecure-random-context": ["CWE-338"],
      "sg-weak-cipher-ast": ["CWE-327"],
      "sg-redos": ["CWE-1333"],
    };
    for (const f of found) for (const c of AST_CWE[f.ruleId] ?? []) covered.add(c);

    const missing = REQUIRED.filter((r) => !r.cwe.some((c) => covered.has(c))).map((r) => r.label);
    expect(missing).toEqual([]);
  });

  it("localises findings to the right lines", () => {
    const found = allDetections("test-corpus/vulnerable.js");
    const lines = new Set(found.map((f) => f.line));
    // sql injection (6/7), AWS key (11), Stripe key (12), exec (27), token (38)
    for (const line of [7, 11, 12, 27, 38]) expect(lines.has(line)).toBe(true);
  });
});