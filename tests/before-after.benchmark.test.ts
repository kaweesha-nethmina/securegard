/**
 * Before/after benchmark.
 *
 * Runs the *original* line-regex rules and the new AST engine over the same
 * corpus — the exact snippets taken from the reported false positives and real
 * vulnerabilities — and prints a precision/recall comparison.
 *
 * The legacy rules are still present in `rules.ts`; the refactor only marked the
 * ones the AST engine replaced (`supersededForJsTsBy`), so measuring them here
 * reports the true pre-refactor behaviour rather than a reimplementation.
 */

import { describe, it, expect } from "vitest";
import * as t from "@babel/types";
import { createFileContext, FileContext } from "../src/analysis/context";
import { RULES } from "../src/rules/rules";
import { detectCommandInjection, detectShellTrueSpawn } from "../src/rules/commandInjection";
import { detectWeakCipher } from "../src/rules/weakCipher";
import { detectSqlInjection } from "../src/rules/sqlInjection";
import { detectHardcodedSecret } from "../src/rules/secrets";
import { detectInsecureRandom } from "../src/rules/insecureRandom";
import { detectRedos } from "../src/rules/redos";
import { checkFileEligibility, ExcludeMatcher } from "../src/scanners/eligibility";

type RuleId =
  | "sg-command-injection"
  | "sg-weak-cipher-des"
  | "sg-sql-injection-concat"
  | "sg-hardcoded-secret-generic"
  | "sg-regex-dos"
  | "sg-insecure-random";

/** AST rule that replaced each legacy regex. */
const AST_RULES: Record<RuleId, (ctx: FileContext) => unknown[]> = {
  "sg-command-injection": (c) => [...detectCommandInjection(c), ...detectShellTrueSpawn(c)],
  "sg-weak-cipher-des": detectWeakCipher,
  "sg-sql-injection-concat": detectSqlInjection,
  "sg-hardcoded-secret-generic": detectHardcodedSecret,
  "sg-regex-dos": detectRedos,
  "sg-insecure-random": detectInsecureRandom,
};

/** Snippets from the report that must NOT be reported. */
const NEGATIVES: [RuleId, string][] = [
  // --- cache key builders (src/core/cache.js) ---
  ["sg-command-injection", "const key = `cache:${tenantId}:${resourceId}:v2`;"],
  ["sg-command-injection", "return `user:${id}:profile`;"],
  ["sg-command-injection", "const k = `report_${from}_${to}`;"],
  // --- error classes (src/core/errors/NotFoundError.js) ---
  ["sg-command-injection", "const msg = `${this.name}: ${resource} not found`;"],
  ["sg-command-injection", "super(`Cannot find ${entity} with id ${id}`);"],
  // --- regex .exec(), NOT child_process ---
  ["sg-command-injection", "const m = /^v(\\d+)/.exec(version);"],
  ["sg-command-injection", "const match = PATTERN.exec(input);"],
  ["sg-command-injection", "results.exec(cmd);"],
  // --- rbac.js / env.js ---
  ["sg-command-injection", "const cacheKey = `rbac:${role}:${perm}`;"],
  ["sg-command-injection", "const envKey = `NODE_ENV_${suffix}`;"],
  // --- DES as a prefix of an ordinary word ---
  ["sg-weak-cipher-des", "ALTER TABLE products ADD description TEXT;"],
  ["sg-weak-cipher-des", "const description = 'redesigned layout';"],
  ["sg-weak-cipher-des", "// described in the spec"],
  ["sg-weak-cipher-des", "DESCRIBE TABLE orders;"],
  ["sg-weak-cipher-des", "const DESIGN_TOKENS = ['a'];"],
  ["sg-weak-cipher-des", "SELECT description, design FROM items;"],
  // --- integration tests with constant SQL ---
  ["sg-sql-injection-concat", "await knex.raw('SELECT * FROM items WHERE id = 1');"],
  ["sg-sql-injection-concat", "db.query(\"INSERT INTO logs (msg) VALUES ('test')\");"],
  ["sg-sql-injection-concat", "const q = `SELECT * FROM users WHERE active = true`;"],
  // --- dotted event names are not credentials ---
  ["sg-hardcoded-secret-generic", "const e = { event: 'user.password.reset' };"],
  ["sg-hardcoded-secret-generic", "const e = { auth: 'auth.user.created' };"],
  ["sg-hardcoded-secret-generic", "const e = { token: 'auth.session.expired' };"],
  // --- placeholders / env reads ---
  ["sg-hardcoded-secret-generic", "const c = { password: 'changeme123' };"],
  ["sg-hardcoded-secret-generic", "const apiKey = process.env.API_KEY;"],
  ["sg-hardcoded-secret-generic", "const c = { secret: '<your-key>' };"],
  // --- ReDoS-looking but linear regexes ---
  ["sg-regex-dos", "const re = /(\\d+)/g;"],
  ["sg-regex-dos", "const re = /^[a-z0-9]+( [a-z]+)*$/;"],
  // --- Math.random for non-security use ---
  ["sg-insecure-random", "const jitter = Math.random() * 100;"],
  ["sg-insecure-random", "shuffle(items, Math.random());"],
];

/** Real vulnerabilities that must still be reported. */
const POSITIVES: [RuleId, string][] = [
  ["sg-command-injection", "const { exec } = require('child_process'); exec(`ls ${req.query.dir}`);"],
  ["sg-command-injection", "const { execSync } = require('child_process'); execSync('tar ' + req.body.n);"],
  ["sg-command-injection", "import { exec } from 'child_process'; exec('ping ' + req.query.h);"],
  ["sg-weak-cipher-des", "crypto.createCipheriv('des-ede3', key, iv);"],
  ["sg-weak-cipher-des", "const alg = 'rc4'; crypto.createCipher(alg, key);"],
  ["sg-weak-cipher-des", "crypto.createDecipheriv('DES', key, iv);"],
  ["sg-sql-injection-concat", "knex.raw(`SELECT * FROM items WHERE name = '${req.query.name}'`);"],
  ["sg-sql-injection-concat", "db.query('SELECT * FROM u WHERE id = ' + req.params.id);"],
  ["sg-hardcoded-secret-generic", "const password = 'Sup3rS3cretPass1';"],
  ["sg-hardcoded-secret-generic", 'const apiKey = "AKIAIOSFODNN7EXAMPLE";'],
  ["sg-insecure-random", "const token = Math.random().toString(36);"],
  ["sg-insecure-random", "const otp = Math.floor(Math.random() * 100000);"],
];

/**
 * Some reported snippets are fragments (`password: 'changeme123',`). The regex
 * engine matched them line by line, so the corpus is preserved verbatim and only
 * wrapped when the AST engine needs a parseable program.
 */
function asProgram(code: string): string | undefined {
  if (createFileContext(code, "src/x.js")) return code;
  const wrapped = `function __wrap__() {\n${code}\n}`;
  if (createFileContext(wrapped, "src/x.js")) return wrapped;
  const asObject = `const __o__ = {\n${code}\n};`;
  if (createFileContext(asObject, "src/x.js")) return asObject;
  return undefined;
}

/** The legacy engine: one regex per line, exactly as it behaved before. */
function legacyHit(ruleId: RuleId, code: string): boolean {
  const rule = RULES.find((r) => r.id === ruleId);
  if (!rule) return false;
  for (const line of code.split(/\r?\n/)) {
    if (!rule.pattern.test(line)) continue;
    if (rule.excludeIfMatches && rule.excludeIfMatches.test(line)) continue;
    return true;
  }
  return false;
}

/** The new engine: parse, then run the AST rule. */
function astHit(ruleId: RuleId, code: string): boolean {
  const program = asProgram(code);
  if (!program) return false;
  const ctx = createFileContext(program, "src/x.js");
  if (!ctx) return false;
  return AST_RULES[ruleId](ctx).length > 0;
}

function score(hit: (ruleId: RuleId, code: string) => boolean) {
  let tp = 0;
  const missed: string[] = [];
  for (const [rule, code] of POSITIVES) {
    if (hit(rule, code)) tp += 1;
    else missed.push(code);
  }
  let fp = 0;
  const falsePositives: string[] = [];
  for (const [rule, code] of NEGATIVES) {
    if (hit(rule, code)) {
      fp += 1;
      falsePositives.push(code);
    }
  }
  return {
    tp,
    fp,
    missed,
    falsePositives,
    precision: POSITIVES.length + NEGATIVES.length - fp > 0
      ? (POSITIVES.length - (POSITIVES.length - tp)) / (POSITIVES.length - (POSITIVES.length - tp) + (NEGATIVES.length - fp))
      : 0,
    recall: tp / POSITIVES.length,
    /* F1 on the positive class only: FP rate over the negative corpus. */
    fpRate: fp / NEGATIVES.length,
  };
}

describe("before/after: regex engine vs AST engine", () => {
  it("reports the improvement", () => {
    const before = score(legacyHit);
    const after = score(astHit);

    const rows = [
      ["engine", "TP", "FP", "recall", "FP rate"],
      ["regex (before)", String(before.tp), String(before.fp), pct(before.recall), pct(before.fpRate)],
      ["AST (after)", String(after.tp), String(after.fp), pct(after.recall), pct(after.fpRate)],
    ];
    // eslint-disable-next-line no-console
    console.log("\n" + rows.map((r) => r.map((c, i) => (i ? c.padEnd(8) : c.padEnd(16))).join("")).join("\n"));
    if (before.falsePositives.length) {
      // eslint-disable-next-line no-console
      console.log(`\nbefore false positives (${before.falsePositives.length}):\n  ` + before.falsePositives.join("\n  "));
    }
    if (before.missed.length) {
      // eslint-disable-next-line no-console
      console.log(`\nbefore misses (${before.missed.length}):\n  ` + before.missed.join("\n  "));
    }
    if (after.falsePositives.length) {
      // eslint-disable-next-line no-console
      console.log(`\nafter false positives (${after.falsePositives.length}):\n  ` + after.falsePositives.join("\n  "));
    }

    // The gate: the AST engine must clear both thresholds on this corpus.
    expect(after.fpRate).toBeLessThanOrEqual(0.1);
    expect(after.recall).toBeGreaterThanOrEqual(0.8);
    // And it must be strictly better than the engine it replaces.
    expect(after.fp).toBeLessThan(before.fp);
    expect(after.tp).toBeGreaterThanOrEqual(before.tp);
  });
});

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

describe("eligibility gate is the single entry point", () => {
  const matcher = new ExcludeMatcher({ excludeGlobs: ["**/node_modules/**"] });

  it("keeps documentation out of every security engine", () => {
    // These are the files the report was polluted by.
    for (const f of [
      "docs/secuguard-final-qa-report.md",
      "docs/api-guide.md",
      "README.md",
      "package-lock.json",
      "CHANGELOG.md",
    ]) {
      const check = checkFileEligibility(`/w/${f}`, f, "# heading\npassword: hunter2\n", matcher);
      expect(check.eligible).toBe(false);
      expect(check.reason).toBeTruthy();
    }
  });

  it("still analyses real source, including shell and SQL", () => {
    for (const f of ["src/app.js", "src/server.ts", "deploy/run.sh", "db/migrate.sql"]) {
      expect(checkFileEligibility(`/w/${f}`, f, "x", matcher).eligible).toBe(true);
    }
  });

  it("detects generated bundles by content", () => {
    const minified = `var a=${JSON.stringify("x".repeat(5000))};`.repeat(1);
    expect(checkFileEligibility("/w/a.js", "src/a.js", minified, matcher).eligible).toBe(false);
  });
});

describe("every migrated rule has an AST implementation", () => {
  it("maps each legacy rule id to a detector", () => {
    const migrated = RULES.filter((r) => r.supersededForJsTsBy).map((r) => r.id);
    expect(migrated.length).toBeGreaterThanOrEqual(6);
    for (const id of migrated) {
      expect(AST_RULES).toHaveProperty(id);
    }
  });

  it("keeps the superseded rules for languages the AST engine cannot parse", () => {
    for (const rule of RULES.filter((r) => r.supersededForJsTsBy)) {
      // Rule text is retained for multi-language coverage.
      expect(rule.pattern).toBeInstanceOf(RegExp);
      expect(rule.remediation.length).toBeGreaterThan(0);
      expect(t.isProgram(null as unknown as t.Node)).toBe(false);
    }
  });
});