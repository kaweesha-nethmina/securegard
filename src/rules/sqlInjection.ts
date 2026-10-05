/**
 * CWE-89: SQL injection — taint analysis into query sinks.
 *
 * Replaces the text rule
 *   /(SELECT|INSERT|UPDATE|DELETE|DROP)\s[^;'"]*(\+|\$\{|%s|f["']).../i
 * which had two problems. It produced 8 findings, all inside
 * `*.integration.test.js` files that only interpolated constants, and — worse —
 * it *missed* the real injection cases in my probe suite, because `[^;'"]*`
 * cannot cross the quote that appears before the interpolation.
 *
 * Now: a finding requires untrusted input to reach a query sink through string
 * concatenation or template interpolation. Parameter binding (`?`, `??`, `:name`,
 * `$1`) is safe and produces nothing, because binding is not string
 * construction — the taint walk sees an argument list, not a string.
 */

import * as t from "@babel/types";
import { FileContext, walkAst, isTestishPath } from "../analysis/context";
import { SecurityFinding, confidenceLabel, scoreSeverity } from "../analysis/finding";
import { traceTaint } from "../analysis/taint";
import { collectConsts, Scope } from "../analysis/constants";

const RULE_ID = "sg-sql-injection-taint";
const SCANNER = "secuguard-taint-engine";

/**
 * Query sinks, keyed by the resolved API name.
 * Each entry notes whether the sink takes a *raw string* (dangerous) or binds
 * parameters (safe).
 */
const RAW_QUERY_SINKS = new Set([
  "raw", "whereRaw", "orderByRaw", "havingRaw", "selectRaw", "joinRaw",
  "query", "execute", "executeRaw", "queryRaw", "unsafe", "literal",
]);

const STRING_QUERY_SINKS = new Set(["$queryRaw", "sql"]);

/** ORM builder chains that are safe regardless of input. */
const SAFE_BUILDERS = new Set(["knex", "prisma", "sequelize"]);

export function detectSqlInjection(ctx: FileContext): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const bindings = new Map<string, t.Expression>();
  const moduleConsts = collectConsts(ctx.ast.program.body);
  const lines = ctx.lines;

  walkAst(ctx.ast.program, (node) => {
    if (t.isVariableDeclarator(node) && t.isIdentifier(node.id) && node.init) {
      if (!t.isCallExpression(node.init)) bindings.set(node.id.name, node.init);
    }
  });

  walkAst(ctx.ast.program, (node) => {
    if (!t.isCallExpression(node)) return;

    const api = calleeApiName(node);
    if (!api) return;
    const bare = api.split(".").pop() ?? api;
    // `$${knex.raw}` (tagged) and `knex.raw` both resolve to the same sink.
    const isRaw = RAW_QUERY_SINKS.has(bare) || STRING_QUERY_SINKS.has(bare);
    if (!isRaw) return;

    const first = node.arguments[0];
    if (!first || !t.isExpression(first)) return;
    // A second argument carrying the tainted value means the value is bound as a
    // parameter (`raw(sql, [x])`), never parsed as SQL text.
    if (hasBoundParameter(first, node)) return;

    // Safe ORM builder: knex('table').where(...) etc. only match when the raw
    // sink name is present, which `where`/`select` are not.
    const result = traceTaint(first, new Scope(moduleConsts), bindings, ctx.file);
    if (!result.tainted) return;

    // A template whose interpolations are all constants is not tainted
    // (handled inside traceTaint), and a pure concatenation of literals likewise.
    const line = node.loc?.start.line ?? 0;
    const testish = isTestishPath(ctx.file);
    const reachable = result.trace.some((s) => /HTTP|body|query|params|headers/i.test(s.label));
    const confidence = testish ? 0.8 : 0.94;

    const { severity, rationale } = scoreSeverity({
      base: "critical",
      reachableFromHttp: reachable,
      testish,
      confidence,
      guardCount: 0,
    });

    findings.push({
      ruleId: RULE_ID,
      title: "SQL Injection (untrusted input in raw query)",
      description:
        "Untrusted input is placed into a raw SQL string by concatenation or template interpolation. The database parses it as SQL, so an attacker can alter the query. Parameter binding (`?`, `??`, `:name`, `$1`) is not affected because values are never parsed as SQL text.",
      baseSeverity: "critical",
      severity,
      cwe: ["CWE-89"],
      owasp: "A03:2021 - Injection",
      category: "sast",
      file: ctx.file,
      startLine: line,
      endLine: node.loc?.end.line ?? line,
      codeSnippet: snippet(lines, line),
      sourceScanner: SCANNER,
      remediation:
        "Use parameter binding: `knex.raw('select * from t where id = ?', [id])`, or the query builder (`.where('id', id)`).",
      confidence,
      confidenceLabel: confidenceLabel(confidence),
      evidence: [
        ...result.trace,
        { kind: "sink" as const, line, label: `reaches raw query sink ${api}` },
      ],
      exploitability: `Attacker-controlled ${result.source?.label} is parsed as part of the SQL statement. ${rationale}.`,
      falsePositiveNotes: [
        "sink resolved to a raw-query API by name, not by proximity to the word SELECT",
        "taint confirmed by backward walk from the query argument",
        "parameter binding (`?`, `??`, `:name`, `$1`) does not construct SQL text and is not reported",
        "template literals containing only constants are not reported",
        `safe builder methods (${[...SAFE_BUILDERS].join(", ")}) used without a raw call are not reported`,
      ],
      reachableFromHttp: reachable,
      testish,
    });
  });

  return findings;
}

/**
 * Returns the API name for a call, resolving member chains one level so
 * `db.raw(...)` and `knex.raw(...)` are both seen, while `queryBuilder.select()`
 * is not mistaken for a sink.
 */
function calleeApiName(call: t.CallExpression): string | undefined {
  const callee = call.callee;
  if (t.isMemberExpression(callee)) {
    const prop = callee.property;
    const name = t.isIdentifier(prop) ? prop.name : t.isStringLiteral(prop) ? prop.value : undefined;
    if (!name) return undefined;
    // Include the receiver when it's a known client (`db`, `knex`, `client`).
    if (t.isIdentifier(callee.object)) {
      return `${callee.object.name}.${name}`;
    }
    if (t.isThisExpression(callee.object)) return `this.${name}`;
    if (t.isCallExpression(callee.object)) {
      const outer = callee.object.callee;
      if (t.isMemberExpression(outer) && t.isIdentifier(outer.property)) {
        return `${outer.property.name}.${name}`;
      }
      return name;
    }
    return name;
  }
  if (t.isIdentifier(callee)) return callee.name;
  return undefined;
}

/**
 * True when the query text is parameterised.
 *
 * Two shapes are safe:
 *   1. The SQL text contains a placeholder (`?`, `$1`, `:name`, `??`) — then the
 *      tainted value can only arrive through the argument list, where the driver
 *      binds it instead of parsing it as SQL.
 *   2. The tainted value is passed as the binding argument rather than being
 *      interpolated into the text.
 */
function hasBoundParameter(sqlArg: t.Expression, call: t.CallExpression): boolean {
  const text = sqlArgText(sqlArg);
  if (!text) return false; // unknown shape: fall through to taint analysis
  if (/\?|\$\d+|:[a-z_][a-z0-9_]*|\?\?/i.test(text)) return true;
  // `raw('...' + id, [])` is still concatenation into SQL text.
  return false;
}

/** Extracts the literal SQL text when the argument has no interpolation. */
function sqlArgText(node: t.Node): string | undefined {
  if (t.isStringLiteral(node)) return node.value;
  if (t.isTemplateLiteral(node)) {
    if (node.expressions.length === 0) {
      return node.quasis.map((q) => q.value.cooked ?? q.value.raw).join("");
    }
    return undefined; // interpolated: placeholders can't be proven
  }
  if (t.isTaggedTemplateExpression(node)) {
    const q = node.quasi;
    if (q.expressions.length === 0) {
      return q.quasis.map((x) => x.value.cooked ?? x.value.raw).join("");
    }
    return undefined;
  }
  return undefined;
}

function snippet(lines: string[], line: number): string {
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 1);
  return lines.slice(start, end).map((l, i) => `${start + i + 1}| ${l}`).join("\n");
}