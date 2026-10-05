/**
 * CWE-798: hardcoded credentials.
 *
 * Two old rules produced 4 findings on `auth.events.js` lines 8-9 and a test
 * file, where the "secret" was actually a dotted event name such as
 * `"auth.user.created"`.
 *
 *   1. `sg-hardcoded-secret-generic` matched `password:`/`token:` followed by
 *      8+ word characters — an event-name string qualifies. Its
 *      `excludeIfMatches` only looked for `changeme`-style words on the same
 *      line, which never matches a dotted event name.
 *   2. `sg-entropy-secret` flagged *any* 20+ character assignment above an
 *      entropy threshold. Markdown prose averages ~4.3 bits/char, so
 *      documentation was reported as embedded credentials.
 *
 * A finding now needs at least one *positive* format signal: a recognised
 * provider prefix with correct length, a PEM block, a JWT, or a secret-named
 * variable holding a value that is not a dotted identifier/event name, UUID,
 * URL, path, or placeholder. Entropy is only ever a secondary signal that can
 * promote a named secret — it can never create a finding on its own.
 */

import * as t from "@babel/types";
import { FileContext, walkAst, isTestishPath } from "../analysis/context";
import { SecurityFinding, confidenceLabel } from "../analysis/finding";
import { collectConsts, resolveConstantString, Scope } from "../analysis/constants";

const RULE_ID = "sg-hardcoded-secret";
const SCANNER = "secuguard-secret-engine";

/** Variable/key names that indicate a credential is expected here. */
const SECRET_NAME = /(pass(word|wd|phrase)?|pwd|secret|api[_-]?key|apikey|token|private[_-]?key|client[_-]?secret|access[_-]?key|auth[_-]?token|credential|salt|signing[_-]?key)/i;

/**
 * Names that *look* secret-ish but denote something else entirely. This is the
 * fix for `auth.events.js`: an event constant is not a credential.
 */
const NON_SECRET_NAME = /(event|eventname|event_?type|topic|channel|queue|route|method|status|code|type|kind|category|label|name|reason|error|message|title|description|pattern|regex|format|version|mode|algorithm|cipher|provider|region|bucket|table|column|index|field|scope|role|action|command|event_name)/i;

interface FormatValidator {
  id: string;
  label: string;
  severity: "critical" | "high" | "medium";
  test: (value: string) => boolean;
  note: string;
}

/** Positive format signals — each proves a credential shape, not just entropy. */
const VALIDATORS: FormatValidator[] = [
  {
    id: "aws-access-key",
    label: "AWS access key ID",
    severity: "critical",
    test: (v) => /\b(AKIA|ASIA)[0-9A-Z]{16}\b/.test(v),
    note: "matches the AWS Access Key ID format (AKIA/ASIA + 16 uppercase alphanumerics)",
  },
  {
    id: "github-token",
    label: "GitHub token",
    severity: "critical",
    test: (v) => /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/.test(v),
    note: "matches a GitHub personal access / OAuth token format",
  },
  {
    id: "stripe-key",
    label: "Stripe secret key",
    severity: "critical",
    test: (v) => /\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b/.test(v),
    note: "matches a Stripe live or test secret key format",
  },
  {
    id: "slack-token",
    label: "Slack token",
    severity: "high",
    test: (v) => /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/.test(v),
    note: "matches a Slack API token format",
  },
  {
    id: "google-api-key",
    label: "Google API key",
    severity: "high",
    test: (v) => /\bAIza[0-9A-Za-z_-]{35}\b/.test(v),
    note: "matches a Google API key format (AIza + 35 chars)",
  },
  {
    id: "jwt",
    label: "JSON Web Token",
    severity: "high",
    test: (v) => /^ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}$/.test(v.trim()),
    note: "parses as a JWT with three base64url segments",
  },
  {
    id: "pem-private-key",
    label: "PEM private key",
    severity: "critical",
    test: (v) => /-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(v),
    note: "PEM private key block",
  },
  {
    id: "slack-webhook",
    label: "Slack webhook URL",
    severity: "high",
    test: (v) => /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/.test(v),
    note: "Slack incoming-webhook URL, which can post without further auth",
  },
  {
    id: "basic-auth-url",
    label: "URL with embedded credentials",
    severity: "high",
    test: (v) => /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s:@]{4,}@/i.test(v),
    note: "URL contains an inline username:password pair",
  },
];

/**
 * Structural exclusions: the value's *shape* proves it is not a credential.
 * These veto a finding unconditionally.
 */
const NOT_A_SECRET: { id: string; test: (v: string) => boolean; reason: string }[] = [
  { id: "dotted-identifier", test: (v) => /^[a-z0-9]+(\.[a-z0-9_-]+){1,}$/i.test(v), reason: "dotted identifier/event name, not a credential" },
  { id: "uuid", test: (v) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v), reason: "UUID" },
  { id: "url-no-creds", test: (v) => /^(https?|ftp):\/\/[^\s:@/]+(\/[^\s]*)?$/.test(v), reason: "URL without embedded credentials" },
  { id: "file-path", test: (v) => /^(\.{0,2}\/|[A-Za-z]:\\|[\w-]+\/){1,}[\w.-]+$/.test(v), reason: "file path" },
  { id: "env-read", test: (v) => /^(process\.env|os\.environ|import\.meta\.env)/.test(v), reason: "environment variable read" },
  { id: "base64-image", test: (v) => /^(data:image\/|\/\*\*\s*@license|iVBORw0KGgo)/.test(v), reason: "embedded image data" },
  { id: "bracket-placeholder", test: (v) => /^<[^>]+>$/.test(v), reason: "angle-bracket placeholder" },
  {
    id: "css-class",
    test: (v) => v.length < 48 && /^[a-z][a-z0-9]*(?:[- ][a-z0-9]+)*$/.test(v) && /[- ]/.test(v),
    reason: "hyphen/space separated lowercase identifier or CSS class list",
  },
];

/**
 * Placeholder hints: words that suggest a sample value, but which also occur
 * inside otherwise well-formed secrets (AWS's own documented key is
 * `AKIAIOSFODNN7EXAMPLE`, and the word "example" also appears in real base64
 * blobs). These therefore *downgrade* a finding rather than suppressing it,
 * because a matching provider format is the stronger signal.
 */
const PLACEHOLDER_HINTS: { id: string; test: (v: string) => boolean; reason: string }[] = [
  { id: "placeholder", test: (v) => /(changeme|placeholder|your[_-]?\w+|dummy|sample|redacted|<[^>]+>|\bxxx+\b|insert[_-]?\w*|\bfixme\b|\bTODO\b|example)/i.test(v), reason: "value contains a placeholder word" },
  { id: "test-literal", test: (v) => /^(test|dummy|fake|sample|mock|stub|foo|bar|baz)/i.test(v), reason: "conventional sample value" },
];

/** All non-credential signals, for the evidence trail. */
function nonSecretReasons(value: string): string[] {
  return [
    ...NOT_A_SECRET.filter((n) => n.test(value)).map((n) => n.reason),
    ...PLACEHOLDER_HINTS.filter((n) => n.test(value)).map((n) => n.reason),
  ];
}

const MIN_SECRET_LENGTH = 8;

export function detectHardcodedSecret(ctx: FileContext): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const moduleConsts = collectConsts(ctx.ast.program.body);
  const scope = new Scope(moduleConsts);
  const testish = isTestishPath(ctx.file);

  walkAst(ctx.ast.program, (node) => {
    // 1. A string literal anywhere: check for a positive format match.
    if (t.isStringLiteral(node)) {
      const validator = VALIDATORS.find((v) => v.test(node.value));
      if (validator) {
        // Placeholders can still match a prefix pattern; confirm.
        if (!isPlaceholderShape(node.value)) {
          findings.push(
            build({
              ctx,
              testish,
              value: node.value,
              validator,
              nameHint: undefined,
              line: node.loc?.start.line ?? 0,
              endLine: node.loc?.end.line ?? node.loc?.start.line ?? 0,
              confidence: placeholderAdjusted(testish ? 0.75 : 0.95, node.value),
              extraNotes: [`format validator: ${validator.note}`],
            })
          );
        }
      }
      return;
    }

    // 2. Assignments to a secret-named identifier.
    if (t.isVariableDeclarator(node) && t.isIdentifier(node.id) && node.init) {
      const name = node.id.name;
      const value = resolveConstantString(node.init, scope);
      if (!value) return;
      if (value.length < MIN_SECRET_LENGTH) return;

      // A recognised format always wins, whatever the variable is called.
      const validator = VALIDATORS.find((v) => v.test(value));
      if (validator && !isPlaceholderShape(value)) {
        findings.push(
          build({
            ctx,
            testish,
            value,
            validator,
            nameHint: name,
            line: node.loc?.start.line ?? 0,
            endLine: node.loc?.end.line ?? node.loc?.start.line ?? 0,
            confidence: placeholderAdjusted(testish ? 0.75 : 0.95, value),
            extraNotes: [`format validator: ${validator.note}`],
          })
        );
        return;
      }

      // Otherwise: require a secret-named variable that is NOT a known
      // non-secret pattern. This is what excludes `token: 'auth.session.expired'`.
      if (!SECRET_NAME.test(name)) return;
      if (NON_SECRET_NAME.test(name) && !/secret|password|passwd|pwd/i.test(name)) return;
      if (NOT_A_SECRET.some((n) => n.test(value))) return;
      if (isPlaceholderOnly(value)) return;

      // Entropy is only a tie-breaker here, never the trigger.
      const entropy = shannonEntropy(value);
      const confidence = placeholderAdjusted(testish ? 0.7 : entropy >= 3.5 ? 0.88 : 0.75, value);

      findings.push(
        build({
          ctx,
          testish,
          value,
          validator: undefined,
          nameHint: name,
          line: node.loc?.start.line ?? 0,
          endLine: node.loc?.end.line ?? node.loc?.start.line ?? 0,
          confidence,
          extraNotes: [
            `variable name matches a credential pattern (${name})`,
            `entropy ${entropy.toFixed(2)} bits/char used only as a secondary signal`,
          ],
        })
      );
      return;
    }

    // 3. Object properties: `password: 'literal'` — the auth.events.js shape.
    if (t.isObjectProperty(node) && !node.computed) {
      const key = t.isIdentifier(node.key) ? node.key.name : t.isStringLiteral(node.key) ? node.key.value : undefined;
      if (!key) return;
      const value = resolveConstantString(node.value as t.Expression, scope);
      if (!value || value.length < MIN_SECRET_LENGTH) return;

      const validator = VALIDATORS.find((v) => v.test(value));
      if (validator && !isPlaceholderShape(value)) {
        findings.push(
          build({
            ctx,
            testish,
            value,
            validator,
            nameHint: key,
            line: node.loc?.start.line ?? 0,
            endLine: node.loc?.end.line ?? node.loc?.start.line ?? 0,
            confidence: placeholderAdjusted(testish ? 0.72 : 0.9, value),
            extraNotes: [`format validator: ${validator.note}`],
          })
        );
        return;
      }

      if (!SECRET_NAME.test(key)) return;
      // Event/status/code keys are explicitly not credentials even when the key
      // text contains "token"/"password" as a substring (e.g. `password_reset`).
      if (NON_SECRET_NAME.test(key) && !/^(password|passwd|pwd|secret|client_secret|api_key)$/i.test(key)) return;
      if (NOT_A_SECRET.some((n) => n.test(value))) return;
      if (isPlaceholderOnly(value)) return;

      findings.push(
        build({
          ctx,
          testish,
          value,
          validator: undefined,
          nameHint: key,
          line: node.loc?.start.line ?? 0,
          endLine: node.loc?.end.line ?? node.loc?.start.line ?? 0,
          confidence: testish ? 0.7 : 0.85,
          extraNotes: [`property key \`${key}\` denotes a credential`],
        })
      );
    }
  });

  return dedupe(findings);
}

function build(input: {
  ctx: FileContext;
  testish: boolean;
  value: string;
  validator?: FormatValidator;
  nameHint?: string;
  line: number;
  endLine: number;
  confidence: number;
  extraNotes: string[];
}): SecurityFinding {
  const severity = input.validator?.severity ?? (input.testish ? "low" : "high");
  const masked = mask(input.value);
  const benignReasons = nonSecretReasons(input.value);

  return {
    ruleId: RULE_ID,
    title: input.validator
      ? `${input.validator.label} hardcoded in source`
      : `Hardcoded credential in \`${input.nameHint}\``,
    description: input.validator
      ? `A string matching the ${input.validator.label} format is embedded in source. Anyone with repository access can use it; rotating it requires a redeploy.`
      : `A literal credential is assigned to \`${input.nameHint}\`. It is committed alongside the code and readable by anyone with repository access.`,
    baseSeverity: "critical",
    severity,
    cwe: ["CWE-798"],
    owasp: "A07:2021 - Identification and Authentication Failures",
    category: "secret",
    file: input.ctx.file,
    startLine: input.line,
    endLine: input.endLine,
    codeSnippet: masked,
    sourceScanner: SCANNER,
    remediation: "Load the value from an environment variable or a secrets manager, then rotate the exposed credential.",
    confidence: input.confidence,
    confidenceLabel: confidenceLabel(input.confidence),
    evidence: [
      {
        kind: "sink" as const,
        line: input.line,
        label: input.nameHint ? `literal assigned to \`${input.nameHint}\`` : "credential literal in source",
        detail: mask(input.value),
      },
    ],
    exploitability: input.validator
      ? `The value is a valid ${input.validator.label}, so it can be used directly against the provider.`
      : "Credential is readable in source and usable until rotated.",
    falsePositiveNotes: [
      ...input.extraNotes,
      benignReasons.length ? `excluded patterns matched: ${benignReasons.join(", ")}` : "no non-secret pattern matched",
      "entropy alone never creates a finding; a name or format signal is required",
      input.testish ? "downgraded: file is a test/fixture/seed" : "not a test/fixture/seed file",
    ],
    reachableFromHttp: false,
    testish: input.testish,
  };
}

/** Masks the middle of a credential so it is not echoed in the report. */
function mask(value: string): string {
  if (value.length <= 8) return `${value.slice(0, 2)}…`;
  return `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`;
}

function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/**
 * True when the value only looks like a credential because of its variable name.
 * A placeholder word (`changeme`, `<your-key>`) then rules it out, whereas the
 * same word inside `AKIAIOSFODNN7EXAMPLE` is outweighed by the provider format.
 */
function isPlaceholderOnly(value: string): boolean {
  return isPlaceholderShape(value) || PLACEHOLDER_HINTS.some((n) => n.test(value));
}

/**
 * Lowers confidence when a placeholder word is present. Never drops below 0.6,
 * because a recognised provider format is positive evidence on its own.
 */
function placeholderAdjusted(base: number, value: string): number {
  return PLACEHOLDER_HINTS.some((n) => n.test(value)) ? Math.max(0.6, base - 0.25) : base;
}

/** Placeholder shapes: stronger evidence than any format validator. */
function isPlaceholderShape(value: string): boolean {
  return /^<[^>]+>$/.test(value.trim()) || /^(x{3,}|\.\.\.)$/i.test(value.trim());
}

/** Collapses duplicate reports of the same value on the same line. */
function dedupe(findings: SecurityFinding[]): SecurityFinding[] {
  const seen = new Set<string>();
  const out: SecurityFinding[] = [];
  for (const f of findings) {
    const key = `${f.file}:${f.startLine}:${f.ruleId}:${f.title}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}