/**
 * CWE-327: broken symmetric cipher (DES/RC4/RC2/Blowfish) and ECB mode.
 *
 * Replaces `/\b(DES|RC4|Cipher\.getInstance\(\s*["']DES)/`, which reported 26
 * findings in database migrations and markdown. Two defects:
 *
 *   1. `\bDES` matches the *prefix* of any identifier — `DESCRIBE TABLE orders`
 *      and `DESIGN_TOKENS` both matched, because the pattern never required a
 *      token boundary after the algorithm name.
 *   2. It was case-sensitive while real calls use lowercase `'des-ede3'`, so
 *      genuine vulnerabilities were missed while these were reported.
 *
 * The fix is structural: only a *resolved algorithm string* counts. The argument
 * must be a literal, or a const-folded variable, and must match a broken
 * algorithm as a whole token. Identifiers, column names, SQL and prose are not
 * string literals in an argument position, so they cannot match at all.
 */

import * as t from "@babel/types";
import { FileContext, walkAst, isTestishPath } from "../analysis/context";
import { SecurityFinding, confidenceLabel, scoreSeverity } from "../analysis/finding";
import { collectConsts, resolveConstantString, Scope } from "../analysis/constants";
import { Severity } from "../types";

const RULE_ID = "sg-weak-cipher";
const SCANNER = "secuguard-taint-engine";

/** Broken algorithms, matched as a whole token with a word boundary after. */
const BROKEN_CIPHER = /^(des|des-ede3|des-ede|rc4|rc2|bf|blowfish|idea)$/i;

/** Cipher APIs that take an algorithm name as their first argument. */
const CIPHER_APIS = new Set([
  "createCipher", "createCipheriv", "createDecipher", "createDecipheriv",
  "Cipher", "Decipher", "Cipheriv", "Decipheriv",
]);

interface CipherHit {
  algo: string;
  api: string;
  line: number;
  node: t.CallExpression;
  isEcb: boolean;
}

export function detectWeakCipher(ctx: FileContext): SecurityFinding[] {
  const hits: CipherHit[] = [];
  const moduleConsts = collectConsts(ctx.ast.program.body);

  walkAst(ctx.ast.program, (node) => {
    if (!t.isCallExpression(node)) return;
    const api = calleeName(node.callee);
    if (!api || !CIPHER_APIS.has(api)) return;

    const first = node.arguments[0];
    if (!first || !t.isExpression(first)) return;

    // Only a literal (or const-folded variable) is an algorithm name.
    const scope = new Scope(moduleConsts);
    const algo = resolveConstantString(first, scope);
    if (!algo) return;

    const line = node.loc?.start.line ?? 0;
    hits.push({ algo, api, line, node, isEcb: isEcbMode(node, scope) });
  });

  return hits.map((hit) => {
    const testish = isTestishPath(ctx.file);
    const confidence = testish ? 0.8 : 0.93;
    const { severity, rationale } = scoreSeverity({
      base: hit.isEcb ? "high" : "high",
      reachableFromHttp: false,
      testish,
      confidence,
      guardCount: 0,
    });

    const broken = BROKEN_CIPHER.test(hit.algo);
    if (!broken && !hit.isEcb) return null as unknown as SecurityFinding;

    return {
      ruleId: RULE_ID,
      title: broken ? `Broken cipher: ${hit.algo}` : `ECB block cipher mode (${hit.algo})`,
      description: broken
        ? `\`${hit.algo}\` is a cryptographically broken algorithm. It should not protect any data, because keys can be recovered or plaintext recovered from ciphertext.`
        : "ECB mode encrypts identical plaintext blocks to identical ciphertext blocks, leaking structure of the plaintext. Use an authenticated mode such as GCM.",
      baseSeverity: "high" as Severity,
      severity,
      cwe: ["CWE-327"],
      owasp: "A02:2021 - Cryptographic Failures",
      category: "sast" as const,
      file: ctx.file,
      startLine: hit.line,
      endLine: hit.node.loc?.end.line ?? hit.line,
      codeSnippet: snippet(ctx.lines, hit.line),
      sourceScanner: SCANNER,
      remediation: "Use AES-256-GCM (or ChaCha20-Poly1305) with a random IV per message.",
      confidence,
      confidenceLabel: confidenceLabel(confidence),
      evidence: [
        { kind: "sink" as const, line: hit.line, label: `${hit.api}("${hit.algo}")`, detail: "algorithm resolved from a literal argument" },
      ],
      exploitability: `Attacker-obtained ciphertext can be decrypted without the key using known-plaintext attacks against ${hit.algo}. ${rationale}.`,
      falsePositiveNotes: [
        "algorithm taken from a string literal or const-folded variable, never from an identifier or prose",
        `whole-token match against known broken algorithms (pattern: ${BROKEN_CIPHER.source})`,
        "identifiers, SQL keywords and comments cannot reach an argument position",
      ],
      reachableFromHttp: false,
      testish,
    } satisfies SecurityFinding;
  }).filter(Boolean) as SecurityFinding[];
}

/** Detects an explicit ECB mode string, which is insecure for block ciphers. */
function isEcbMode(call: t.CallExpression, scope: Scope): boolean {
  for (const arg of call.arguments) {
    if (!t.isExpression(arg)) continue;
    const v = resolveConstantString(arg, scope);
    if (v && /^ecb$/i.test(v.trim())) return true;
  }
  return false;
}

function calleeName(callee: t.Node): string | undefined {
  if (t.isIdentifier(callee)) return callee.name;
  if (t.isMemberExpression(callee)) {
    const p = callee.property;
    return t.isIdentifier(p) ? p.name : t.isStringLiteral(p) ? p.value : undefined;
  }
  return undefined;
}

function snippet(lines: string[], line: number): string {
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 1);
  return lines.slice(start, end).map((l, i) => `${start + i + 1}| ${l}`).join("\n");
}