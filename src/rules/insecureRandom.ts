/**
 * CWE-338: insecure randomness in a security-relevant context.
 *
 * Replaces
 *   /(Math\.random\(\)|random\.random\(\)|rand\(\))\s*.{0,40}(token|password|secret|key|session|csrf|otp)/i
 * which searched only *forward* from `Math.random()` for a keyword on the same
 * line. That both over- and under-fires: `Math.random() * 100` with a keyword
 * 30 characters later was reported, while `const token = Math.random()...` — the
 * keyword *before* the call — was missed.
 *
 * Now the direction is irrelevant because the assignment is read structurally:
 * `Math.random()` is reported only when its value flows into an identifier whose
 * name denotes a security artifact (token, password, session id, OTP, reset
 * code, key, nonce). Presentation uses — shuffling, jitter, animation, plain
 * numeric IDs — are not security-relevant and produce nothing.
 */

import * as t from "@babel/types";
import { FileContext, walkAst, isTestishPath } from "../analysis/context";
import { SecurityFinding, confidenceLabel } from "../analysis/finding";
import { collectConsts } from "../analysis/constants";

const RULE_ID = "sg-insecure-random-context";
const SCANNER = "secuguard-taint-engine";

/** Identifiers whose value must be unpredictable. */
const SECURITY_NAMES =
  /(?:^|[^a-z])(token|password|passwd|pwd|secret|apikey|api_key|sessionid|session_id|nonce|otp|resetcode|reset_code|resetlink|recoverycode|recovery_code|csrftoken|csrf_token|verificationcode|verifycode|mfa|pin|seed|iv|initializationvector|cookievalue|randomseed)(?:$|[^a-z])/i;

/** Explicitly non-security uses of randomness. */
const NON_SECURITY_NAMES =
  /(?:^|[^a-z])(jitter|shuffle|shuffled|randomindex|randomcolor|randomangle|animation|delay|delayms|timeout|preview|placeholder|dummyname|fakename|sample|variation|scatter|offset|sparkline|retries?)(?:$|[^a-z])/i;

/** PRNG functions that are not cryptographically secure. */
const INSECURE_PRNG = new Set(["random", "Math.random", "rand", "mt_rand", "shuffle"]);

export function detectInsecureRandom(ctx: FileContext): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const testish = isTestishPath(ctx.file);
  const bindings = new Map<string, t.Expression>();
  const moduleConsts = collectConsts(ctx.ast.program.body);

  // Case 1: a PRNG call assigned (directly or via const) to a security name.
  walkAst(ctx.ast.program, (node) => {
    if (!t.isVariableDeclarator(node) || !t.isIdentifier(node.id) || !node.init) return;
    const name = node.id.name;
    if (NON_SECURITY_NAMES.test(name)) return;
    if (!SECURITY_NAMES.test(name)) return;
    if (!usesInsecurePrng(node.init, moduleConsts)) return;

    const line = node.loc?.start.line ?? 0;
    const confidence = testish ? 0.72 : 0.9;
    findings.push(
      build(ctx, {
        line,
        endLine: node.loc?.end.line ?? line,
        name,
        expr: node.init,
        testish,
        confidence,
        path: describePath(node.init, moduleConsts),
      })
    );
    bindings.set(name, node.init);
  });

  // Case 2: an object property or function argument that is security-named and
  // receives a PRNG value inline.
  walkAst(ctx.ast.program, (node) => {
    if (t.isObjectProperty(node) && !node.computed) {
      const key = t.isIdentifier(node.key) ? node.key.name : t.isStringLiteral(node.key) ? node.key.value : undefined;
      if (!key || NON_SECURITY_NAMES.test(key) || !SECURITY_NAMES.test(key)) return;
      if (!usesInsecurePrng(node.value as t.Expression, moduleConsts)) return;
      const line = node.loc?.start.line ?? 0;
      findings.push(
        build(ctx, {
          line,
          endLine: node.loc?.end.line ?? line,
          name: key,
          expr: node.value as t.Expression,
          testish,
          confidence: testish ? 0.7 : 0.86,
          path: describePath(node.value as t.Expression, moduleConsts),
        })
      );
    }
  });

  return findings;
}

/** True when the expression's PRNG calls feed a value (directly or via a const). */
function usesInsecurePrng(node: t.Node, moduleConsts: Map<string, t.Expression>, depth = 0): boolean {
  if (depth > 6) return false;
  if (t.isCallExpression(node)) {
    const callee = node.callee;
    const name = t.isMemberExpression(callee)
      ? `${t.isIdentifier(callee.object) ? callee.object.name : ""}.${t.isIdentifier(callee.property) ? callee.property.name : ""}`
      : t.isIdentifier(callee)
        ? callee.name
        : "";
    if (INSECURE_PRNG.has(name)) return true;
    // `Math.random().toString(36)` — the PRNG is the receiver of the callee.
    if (t.isMemberExpression(callee) && usesInsecurePrng(callee.object, moduleConsts, depth + 1)) return true;
    if (t.isMemberExpression(callee) && usesInsecurePrng(callee.property, moduleConsts, depth + 1)) return true;
  }
  if (t.isIdentifier(node)) {
    const bound = moduleConsts.get(node.name);
    return bound ? usesInsecurePrng(bound, moduleConsts, depth + 1) : false;
  }
  if (t.isTemplateLiteral(node)) {
    return node.expressions.some((e) => usesInsecurePrng(e, moduleConsts, depth + 1));
  }
  if (t.isBinaryExpression(node)) {
    return usesInsecurePrng(node.left, moduleConsts, depth + 1) || usesInsecurePrng(node.right, moduleConsts, depth + 1);
  }
  if (t.isCallExpression(node)) {
    return node.arguments.some((a) => t.isExpression(a) && usesInsecurePrng(a, moduleConsts, depth + 1));
  }
  if (t.isObjectExpression(node)) {
    return node.properties.some((p) => t.isObjectProperty(p) && usesInsecurePrng(p.value as t.Expression, moduleConsts, depth + 1));
  }
  return false;
}

function describePath(node: t.Node, moduleConsts: Map<string, t.Expression>): string {
  if (t.isCallExpression(node)) return `Math.random()${node.loc ? ` (line ${node.loc.start.line})` : ""}`;
  if (t.isIdentifier(node)) {
    const bound = moduleConsts.get(node.name);
    if (bound) return `${node.name} → ${describePath(bound, moduleConsts)}`;
    return node.name;
  }
  return node.type;
}

function build(
  ctx: FileContext,
  input: {
    line: number;
    endLine: number;
    name: string;
    expr: t.Node;
    testish: boolean;
    confidence: number;
    path: string;
  }
): SecurityFinding {
  const start = Math.max(0, input.line - 2);
  const end = Math.min(ctx.lines.length, input.line + 1);
  return {
    ruleId: RULE_ID,
    title: `Insecure randomness used for \`${input.name}\``,
    description:
      "`Math.random()` is a non-cryptographic PRNG whose output is predictable. When used for a security artifact, an attacker who observes a few values can predict the rest and forge the value.",
    baseSeverity: "medium",
    severity: input.testish ? "low" : "medium",
    cwe: ["CWE-338"],
    owasp: "A02:2021 - Cryptographic Failures",
    category: "sast",
    file: ctx.file,
    startLine: input.line,
    endLine: input.endLine,
    codeSnippet: ctx.lines.slice(start, end).map((l, i) => `${start + i + 1}| ${l}`).join("\n"),
    sourceScanner: SCANNER,
    remediation: "Use `crypto.randomBytes(n)`, `crypto.randomUUID()`, or `crypto.getRandomValues()` from Node's `crypto` module.",
    confidence: input.confidence,
    confidenceLabel: confidenceLabel(input.confidence),
    evidence: [
      { kind: "source" as const, line: input.line, label: `\`${input.name}\` requires unpredictability`, detail: input.path },
      { kind: "sink" as const, line: input.line, label: "value produced by Math.random()" },
    ],
    exploitability: "An attacker who observes output from a seeded PRNG can recover the generator state and predict future security values.",
    falsePositiveNotes: [
      "assignment read structurally, so the identifier can appear before or after the call",
      "presentation-only names (jitter, shuffle, animation) are excluded",
      "non-security numeric IDs are not reported",
      input.testish ? "downgraded: test/fixture/seed file" : "not a test/fixture/seed file",
    ],
    reachableFromHttp: false,
    testish: input.testish,
  };
}