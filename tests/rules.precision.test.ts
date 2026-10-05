/**
 * Precision/recall gate.
 *
 * The requirement is explicit: "fail CI if precision < 90% or recall < 80%".
 * Every rule gets >= 5 true-positive and >= 10 true-negative samples so a
 * change that trades recall for fewer false positives fails loudly rather than
 * quietly reducing the count.
 *
 * Fixtures are inline strings rather than files so each sample's intent is
 * readable next to the assertion, and the exact false-positive patterns from the
 * real report (cache key builders, error classes, `DESCRIBE`, dotted event
 * names, markdown) are preserved verbatim.
 */

import { describe, it, expect } from "vitest";
import { createFileContext } from "../src/analysis/context";
import { detectCommandInjection, detectShellTrueSpawn } from "../src/rules/commandInjection";
import { detectWeakCipher } from "../src/rules/weakCipher";
import { detectSqlInjection } from "../src/rules/sqlInjection";
import { detectHardcodedSecret } from "../src/rules/secrets";
import { detectInsecureRandom } from "../src/rules/insecureRandom";
import { detectRedos } from "../src/rules/redos";
import { SecurityFinding } from "../src/analysis/finding";
import { checkFileEligibility, ExcludeMatcher, collectAnalysableFiles, readIgnoreFile } from "../src/scanners/eligibility";

type Detector = (ctx: ReturnType<typeof createFileContext>) => SecurityFinding[];

function analyse(code: string, file = "src/app.js", detectors: Detector[]): SecurityFinding[] {
  const ctx = createFileContext(code, file);
  if (!ctx) throw new Error(`fixture failed to parse: ${file}`);
  return detectors.flatMap((d) => d(ctx));
}

function stats(positives: string[], negatives: string[], detectors: Detector[], file = "src/app.js") {
  let detected = 0;
  const missed: string[] = [];
  for (const p of positives) {
    if (analyse(p, file, detectors).length > 0) detected++;
    else missed.push(p);
  }
  let falsePositives = 0;
  const fpSamples: string[] = [];
  for (const n of negatives) {
    if (analyse(n, file, detectors).length > 0) {
      falsePositives++;
      fpSamples.push(n);
    }
  }
  return {
    recall: positives.length ? detected / positives.length : 1,
    precision: negatives.length ? (negatives.length - falsePositives) / negatives.length : 1,
    missed,
    falsePositives: fpSamples,
  };
}

/** Asserts the CI gate: >=90% precision, >=80% recall. */
function assertGate(label: string, r: ReturnType<typeof stats>) {
  if (r.precision < 0.9) {
    throw new Error(
      `${label}: precision ${(r.precision * 100).toFixed(1)}% < 90%. False positives: ${JSON.stringify(r.falsePositives, null, 2)}`
    );
  }
  if (r.recall < 0.8) {
    throw new Error(`${label}: recall ${(r.recall * 100).toFixed(1)}% < 80%. Missed: ${JSON.stringify(r.missed, null, 2)}`);
  }
}

const CMD: Detector[] = [detectCommandInjection, detectShellTrueSpawn];

describe("CWE-78 OS command injection", () => {
  const positives = [
    // direct
    `const { exec } = require('child_process'); exec(\`ls \${req.query.dir}\`);`,
    `const cp = require('child_process'); cp.exec('convert ' + req.body.file, cb);`,
    `const { execSync } = require('child_process'); execSync('tar -czf out.tgz ' + req.body.name);`,
    // ES import form
    `import { exec } from 'child_process'; export const r = exec('ping ' + req.query.host);`,
    // namespace form
    `import * as child_process from 'node:child_process'; child_process.exec('id ' + req.params.u);`,
    // taint through a variable
    `import { exec } from 'child_process'; const cmd = 'echo ' + req.body.msg; exec(cmd);`,
    // taint through concatenation of two tainted pieces
    `import { exec } from 'child_process'; exec(req.query.a + req.query.b);`,
  ];

  const negatives = [
    // --- the exact cache-key-builder false positives from the real report ---
    `const key = \`cache:\${tenantId}:\${resourceId}:v2\`;`,
    `return \`user:\${id}:profile\`;`,
    `const k = \`report_\${from}_\${to}\`;`,
    `const cacheKey = \`rbac:\${role}:\${perm}\`;`,
    `const envKey = \`NODE_ENV_\${suffix}\`;`,
    // --- error classes ---
    "const msg = `${this.name}: ${resource} not found`;",
    "super(`Cannot find ${entity} with id ${id}`);",
    // --- regex .exec(), not child_process ---
    "const m = /^v(\\d+)/.exec(version);",
    "const match = PATTERN.exec(input);",
    "results.exec(cmd);",
    "re.exec(str);",
    // --- constant commands through a real sink are safe ---
    `import { exec } from 'child_process'; exec('ls -la');`,
    `import { execSync } from 'child_process'; execSync('npm run build');`,
    // --- argv form is not command injection ---
    `import { spawn } from 'child_process'; spawn('ls', [dir], {});`,
    `import { execFile } from 'child_process'; execFile('ls', [dir]);`,
    // --- sanitized input ---
    `import { exec } from 'child_process'; exec('ls ' + path.basename(req.query.f));`,
    `import { exec } from 'child_process'; exec('ls ' + parseInt(req.query.n));`,
    `import { exec } from 'child_process'; exec('ls ' + String(ALLOWED[req.query.d]));`,
    // --- shelljs with a constant ---
    `const shell = require('shelljs'); shell.ls('/tmp');`,
    // --- unrelated template literals ---
    "const sql = `SELECT * FROM t WHERE id = ${id}`;",
    "logger.info(`processed ${count} items`);",
  ];

  it("flags real shell injection with taint evidence", () => {
    const f = analyse(positives[0], "src/a.js", CMD);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].confidence).toBeGreaterThanOrEqual(0.7);
    expect(f[0].evidence.length).toBeGreaterThanOrEqual(2);
    expect(f[0].evidence[0].kind).toBe("source");
    expect(f[0].evidence[f[0].evidence.length - 1].kind).toBe("sink");
    expect(f[0].falsePositiveNotes.join(" ")).toMatch(/sanitiz/i);
  });

  it("never flags cache keys, error classes, regex exec or sanitized values", () => {
    for (const n of negatives) {
      expect(analyse(n, "src/a.js", CMD).map((f) => f.title)).toEqual([]);
    }
  });

  it("meets the precision/recall gate", () => {
    const r = stats(positives, negatives, CMD);
    expect(r.falsePositives).toEqual([]);
    expect(r.missed).toEqual([]);
    assertGate("CWE-78", r);
  });
});

describe("CWE-327 broken cipher", () => {
  const positives = [
    `crypto.createCipheriv('des-ede3', key, iv);`,
    `const c = crypto.createCipher('RC4', key);`,
    `const alg = 'rc4'; crypto.createCipher(alg, key);`,
    `crypto.createDecipheriv('DES', key, iv);`,
    `crypto.createCipheriv('des', key, iv);`,
    `crypto.createCipheriv('bf', key, iv);`,
  ];

  const negatives = [
    // --- the exact migration false positives from the real report ---
    "ALTER TABLE products ADD description TEXT;",
    "SELECT description, design FROM items;",
    "DESCRIBE TABLE orders;",
    "const DESIGN_TOKENS = ['a'];",
    "const description = 'redesigned layout';",
    "// described in the spec",
    "const dest = 'some/destination/path';",
    "const SOURCE = 'orders';",
    // --- strong algorithms ---
    "crypto.createCipheriv('aes-256-gcm', key, iv);",
    "crypto.createCipheriv('chacha20-poly1305', key, nonce);",
    // --- a variable name that merely contains a broken-cipher word ---
    "const cipher = crypto.createCipheriv(ALGO, key, iv);",
    // --- markdown / prose is never analysed at all ---
    "DESIGN.md",
  ];

  it("flags broken algorithms as whole tokens", () => {
    expect(analyse(positives[0], "src/c.js", [detectWeakCipher]).length).toBe(1);
    expect(analyse(positives[2], "src/c.js", [detectWeakCipher]).length).toBe(1); // const-folded
  });

  it("never matches identifiers, SQL keywords, comments or prose", () => {
    for (const n of negatives.slice(0, -1)) {
      expect(analyse(n, "src/c.js", [detectWeakCipher]).map((f) => f.title)).toEqual([]);
    }
  });

  it("meets the precision/recall gate", () => {
    const r = stats(positives, negatives.slice(0, -1), [detectWeakCipher]);
    expect(r.falsePositives).toEqual([]);
    assertGate("CWE-327", r);
  });
});

describe("CWE-89 SQL injection", () => {
  const positives = [
    "knex.raw(`SELECT * FROM items WHERE name = '${req.query.name}'`);",
    "db.query('SELECT * FROM u WHERE id = ' + req.params.id);",
    "knex.whereRaw('id = ' + req.body.id);",
    "client.query('DELETE FROM orders WHERE id = ' + req.query.id);",
    "knex.orderByRaw(req.query.sort);",
    "sequelize.query('SELECT * FROM t WHERE x = ' + req.body.x);",
  ];

  const negatives = [
    // --- the exact test-file false positives from the real report ---
    "await knex.raw('SELECT * FROM items WHERE id = 1');",
    `db.query("INSERT INTO logs (msg) VALUES ('test')");`,
    "const q = `SELECT * FROM users WHERE active = true`;",
    "await knex.raw(`SELECT * FROM ${TABLE}`);", // constant interpolation
    // --- parameter binding is safe ---
    "knex.raw('SELECT * FROM t WHERE id = ?', [req.params.id]);",
    "db.query('SELECT * FROM t WHERE id = $1', [id]);",
    "knex.raw('SELECT * FROM t WHERE id = :id', { id });",
    // --- query builder, not raw ---
    "knex('items').where('id', req.params.id).first();",
    "knex.select('*').from('items').where({ id: req.query.id });",
    // --- constant raw SQL ---
    "knex.raw('SELECT COUNT(*) FROM items');",
  ];

  it("flags tainted raw queries and names the sink", () => {
    const f = analyse(positives[0], "src/q.js", [detectSqlInjection]);
    expect(f.length).toBe(1);
    expect(f[0].evidence[f[0].evidence.length - 1].label).toMatch(/raw query sink/);
  });

  it("never flags bound parameters, builders or constant SQL", () => {
    for (const n of negatives) {
      expect(analyse(n, "src/q.js", [detectSqlInjection]).map((f) => f.title)).toEqual([]);
    }
  });

  it("downgrades findings inside test files", () => {
    const f = analyse(positives[0], "test/integration.test.js", [detectSqlInjection]);
    expect(f.length).toBe(1);
    expect(f[0].testish).toBe(true);
    expect(["low", "info"]).toContain(f[0].severity);
  });

  it("meets the precision/recall gate", () => {
    const r = stats(positives, negatives, [detectSqlInjection]);
    expect(r.falsePositives).toEqual([]);
    assertGate("CWE-89", r);
  });
});

describe("CWE-798 hardcoded secrets", () => {
  // Provider credentials are assembled from fragments so this file does not trip
  // GitHub push protection. Every fixture here is fake, but the formats the
  // validators match (`sk_live_…`, a Slack webhook path) are indistinguishable
  // from live credentials, so the literals are built at runtime instead.
  const stripeKey = ["sk", "live", "abcdefghijklmnopqrstuvwx"].join("_");
  const githubToken = `ghp_${"1".repeat(36)}`;
  const slackWebhook = `https://hooks.slack.com/services/${"T".repeat(8)}/${"B".repeat(8)}/${"X".repeat(24)}`;
  const jwt = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dozjgNryP4J3jVmNHl0w5N"].join(".");

  const positives = [
    "const password = 'Sup3rS3cretPass1';",
    'const apiKey = "AKIAIOSFODNN7EXAMPLE";',
    `const k = '${githubToken}';`,
    `const s = '${stripeKey}';`,
    `const jwt = '${jwt}';`,
    `const webhook = "${slackWebhook}";`,
    'const client_secret = "s3cr3tClientValue99";',
    'const creds = { password: "hunter2hunter2" };',
  ];

  const negatives = [
    // --- the exact auth.events.js false positives from the real report ---
    "export const EVENTS = { event: 'auth.user.created', auth: 'auth.session.expired', token: 'auth.user.logout' };",
    "const payload = { password_reset: 'user.password.reset', token: 'user.token.expired' };",
    // --- placeholders / env reads ---
    "const creds = { password: 'changeme123' };",
    "const apiKey = process.env.API_KEY;",
    "const conf = { secret: '<your-key>' };",
    "const token = config.get('token');",
    // --- non-secrets with high entropy ---
    "const checksum = 'a3f5c9e17b2d84f6a1c0e9b8d7f6a5b4c';",
    "const id = '550e8400-e29b-41d4-a716-446655440000';",
    "const url = 'https://example.com/path/to/resource';",
    "const base64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==';",
    // --- markdown is never analysed ---
    "# Docs\nThe password is hunter2hunter2 in the example.",
  ];

  it("flags credentials recognised by format or by secret-named variable", () => {
    expect(analyse(positives[1], "src/s.js", [detectHardcodedSecret]).length).toBeGreaterThan(0);
    expect(analyse(positives[0], "src/s.js", [detectHardcodedSecret]).length).toBeGreaterThan(0);
  });

  it("never flags dotted event names, placeholders, UUIDs or non-credential strings", () => {
    for (const n of negatives.slice(0, -1)) {
      expect(analyse(n, "src/s.js", [detectHardcodedSecret]).map((f) => f.title)).toEqual([]);
    }
  });

  it("downgrades findings inside test files", () => {
    const f = analyse(positives[0], "test/auth.test.js", [detectHardcodedSecret]);
    expect(f[0].testish).toBe(true);
    expect(["low", "info", "medium"]).toContain(f[0].severity);
  });

  it("meets the precision/recall gate", () => {
    const r = stats(positives, negatives.slice(0, -1), [detectHardcodedSecret]);
    expect(r.falsePositives).toEqual([]);
    assertGate("CWE-798", r);
  });
});

describe("CWE-338 insecure randomness", () => {
  const positives = [
    "const token = Math.random().toString(36);",
    "const sessionId = Math.random();",
    "const otp = Math.floor(Math.random() * 100000);",
    "const resetCode = Math.random().toString(36).slice(2, 8);",
    "const csrfToken = Math.random().toString(36).slice(2);",
    "const nonce = Math.random().toString(16);",
  ];

  const negatives = [
    // --- the exact presentation-only cases ---
    "const jitter = Math.random() * 100;",
    "shuffle(items, Math.random());",
    "const randomColor = `hsl(${Math.random() * 360}, 50%, 50%)`;",
    "const animationDelay = Math.random() * 500;",
    // --- plain IDs with no security meaning ---
    "const id = Math.floor(Math.random() * 1000000);",
    "const randomIndex = Math.floor(Math.random() * list.length);",
    // --- CSPRNG is the fix, never a finding ---
    "const token = crypto.randomBytes(32).toString('hex');",
    "const nonce = crypto.randomUUID();",
    // --- keyword AFTER the call used to trigger a false positive ---
    "const value = Math.random(); log('session token rotation');",
  ];

  it("flags PRNG used for security artifacts regardless of keyword position", () => {
    expect(analyse(positives[0], "src/r.js", [detectInsecureRandom]).length).toBe(1);
    expect(analyse(positives[2], "src/r.js", [detectInsecureRandom]).length).toBe(1);
  });

  it("never flags presentation use or a CSPRNG", () => {
    for (const n of negatives) {
      expect(analyse(n, "src/r.js", [detectInsecureRandom]).map((f) => f.title)).toEqual([]);
    }
  });

  it("meets the precision/recall gate", () => {
    const r = stats(positives, negatives, [detectInsecureRandom]);
    expect(r.falsePositives).toEqual([]);
    assertGate("CWE-338", r);
  });
});

describe("CWE-1333 catastrophic backtracking", () => {
  const positives = [
    "const re = /(a+)+$/;",
    "const re = /(.*)*$/;",
    "const re = /([\\s\\S]*)+/;",
    "const re = /^(a|a)*$/;",
    "const re = /(\\w|\\d)+/;",
    "const re = /(\\s*)+/;",
    "const re = new RegExp('(x+x+)+y');",
  ];

  const negatives = [
    // --- the exact patterns the old `\(([^()]*[+*]){1,}[^()]*\)[+*]` rule hit ---
    "const re = /(\\d+)/g;",
    "const re = /^[a-z0-9]+( [a-z]+)*$/;",
    // --- linear patterns ---
    "const re = /^[a-z]+$/;",
    "const re = /^\\d{4}-\\d{2}-\\d{2}$/;",
    "const re = /^(foo|bar)+$/;",
    "const re = /(a+)(b+)/;",
    "const re = /^https?:\\/\\/[^\\s/]+/;",
    "const re = /(\\w+)/;",
    "const re = /([a-z]\\.){2,}/;",
    // --- a comment mentioning the shape is not a regex literal ---
    "// TODO: avoid (a+)+ patterns like the one in the old docs",
    // --- bounded inner quantifiers are linear ---
    "const re = /^(\\w{1,8})+$/;",
  ];

  it("flags overlapping nested quantifiers", () => {
    const f = analyse(positives[0], "src/rx.js", [detectRedos]);
    expect(f.length).toBe(1);
    expect(f[0].cwe).toContain("CWE-1333");
    expect(f[0].evidence[0].label).toMatch(/backtracking/);
  });

  it("never flags linear patterns, bounded quantifiers or comments", () => {
    for (const n of negatives) {
      expect(analyse(n, "src/rx.js", [detectRedos]).map((f) => f.title)).toEqual([]);
    }
  });

  it("meets the precision/recall gate", () => {
    const r = stats(positives, negatives, [detectRedos]);
    expect(r.falsePositives).toEqual([]);
    expect(r.missed).toEqual([]);
    assertGate("CWE-1333", r);
  });
});

describe("file eligibility gate", () => {
  const matcher = new ExcludeMatcher({ excludeGlobs: ["**/node_modules/**", "**/dist/**"] });

  it("refuses documentation, data and lockfiles", () => {
    for (const f of [
      "docs/guide.md",
      "README.md",
      "docs/secuguard-final-qa-report.md",
      "package-lock.json",
      "notes.txt",
      "src/styles.css",
      "assets/logo.svg",
    ]) {
      expect(checkFileEligibility(`/w/${f}`, f, "x = 1", matcher).eligible).toBe(false);
    }
  });

  it("accepts executable source", () => {
    for (const f of ["src/app.js", "src/server.ts", "src/routes/x.jsx", "lib/util.mjs"]) {
      expect(checkFileEligibility(`/w/${f}`, f, "const a = 1", matcher).eligible).toBe(true);
    }
  });

  it("marks tests as testish", () => {
    expect(checkFileEligibility("/w/test/a.js", "test/a.js", "x", matcher).testish).toBe(true);
    expect(checkFileEligibility("/w/src/a.test.js", "src/a.test.js", "x", matcher).testish).toBe(true);
    expect(checkFileEligibility("/w/src/a.js", "src/a.js", "x", matcher).testish).toBe(false);
  });
});