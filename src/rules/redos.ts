/**
 * CWE-1333: regular expression denial of service.
 *
 * The old rule was `/\(([^()]*[+*]){1,}[^()]*\)[+*]/`, which flags any group
 * whose body contains a quantifier followed by an outer quantifier. That shape is
 * only catastrophic when the inner and outer quantifiers can match the *same*
 * characters; `(a+)+`, `(.*)*` and `([\s\S]*)+` backtrack exponentially, while
 * `(\d+)` and `(abc*)` do not.
 *
 * Detection therefore requires one of:
 *   1. a quantified group whose body ends in an unbounded quantifier over a
 *      character class that overlaps the separator (`(x+)+`, `(.*)*`),
 *   2. an ambiguous alternation under a quantifier — `(a|a)*`, `(\w|\d)+`,
 *   3. a quantified group that can match the empty string (`(\s*)+`).
 *
 * `RegexLiteral` nodes are read structurally, so a commented-out pattern or a
 * string that merely mentions `+` is never reported.
 */

import * as t from "@babel/types";
import { FileContext, walkAst, isTestishPath } from "../analysis/context";
import { SecurityFinding, confidenceLabel } from "../analysis/finding";

const RULE_ID = "sg-redos";
const SCANNER = "secuguard-ast-engine";

/** Quantifiers that can consume input without an upper bound. */
const UNBOUNDED = ["*", "+", "{,}", "{"];
const BOUNDED_MAX = 32;

/** Quantifier suffix at `pattern[i..]`, or undefined. */
function quantifierAt(
  pattern: string,
  i: number
): { text: string; unbounded: boolean; min: number; max: number } | undefined {
  const ch = pattern[i];
  if (ch === "*") return { text: ch, unbounded: true, min: 0, max: Number.POSITIVE_INFINITY };
  if (ch === "+") return { text: ch, unbounded: true, min: 1, max: Number.POSITIVE_INFINITY };
  if (ch === "?") return { text: ch, unbounded: false, min: 0, max: 1 };
  if (ch === "{") {
    const close = pattern.indexOf("}", i);
    if (close === -1) return undefined;
    const body = pattern.slice(i + 1, close);
    const m = /^(\d*)(,(\d*))?$/.exec(body);
    if (!m) return undefined;
    const min = m[1] ? Number(m[1]) : 0;
    const max = m[2] === undefined ? min : m[3] ? Number(m[3]) : Number.POSITIVE_INFINITY;
    return { text: pattern.slice(i, close + 1), unbounded: max === Number.POSITIVE_INFINITY, min, max };
  }
  return undefined;
}

/** The set of characters a fragment can match, coarse but sufficient. */
interface CharClass {
  any: boolean;
  literal: Set<string>;
  classes: string[];
}

function charClassOf(fragment: string): CharClass {
  const out: CharClass = { any: false, literal: new Set(), classes: [] };
  if (fragment === ".") {
    out.any = true;
    return out;
  }
  let i = 0;
  while (i < fragment.length) {
    if (fragment[i] === "\\") {
      const esc = fragment.slice(i, i + 2);
      if (esc === "\\d") out.classes.push("digit");
      else if (esc === "\\w") out.classes.push("word");
      else if (esc === "\\s") out.classes.push("space");
      else if (esc === "\\W") out.classes.push("nonword");
      else if (esc === "\\S") out.classes.push("nonspace");
      else if (esc === "\\D") out.classes.push("nondigit");
      else out.literal.add(esc[1] ?? esc);
      i += 2;
      continue;
    }
    if (fragment[i] === "[") {
      const close = fragment.indexOf("]", i + 1);
      if (close === -1) {
        out.literal.add(fragment[i]);
        i += 1;
        continue;
      }
      const raw = fragment.slice(i + 1, close);
      const negated = raw.startsWith("^");
      const body = negated ? raw.slice(1) : raw;
      const cls: string[] = [];
      if (negated) {
        // A negated class can consume almost anything, which is precisely the
        // shape that makes `(.*)*` and `([^x]*)*` catastrophic.
        cls.push(`negated:${body}`);
      } else {
        if (body.includes("\\d")) cls.push("digit");
        if (body.includes("\\w")) cls.push("word");
        if (body.includes("\\s")) cls.push("space");
        if (/[a-zA-Z]/.test(body)) cls.push("letter");
        if (/[^\\d\\w\\sa-zA-Z]/.test(body)) cls.push("punct");
      }
      out.classes.push(cls.length ? cls.join("+") : `set:${body}`);
      i = close + 1;
      continue;
    }
    out.literal.add(fragment[i]);
    i += 1;
  }
  return out;
}

function classesOverlap(a: CharClass, b: CharClass): boolean {
  if (a.any || b.any) return true;
  for (const l of a.literal) if (b.literal.has(l)) return true;
  if (a.classes.some((x) => b.classes.includes(x))) return true;
  // A broad class in one side overlaps a narrow class in the other
  // (e.g. `\w` against `[a-z]`), which is the common catastrophic case. A
  // concrete class such as `[- ]` is *not* broad: `(?:[- ][a-z]+)*` is linear
  // because every repetition must begin with a separator.
  const broad = (c: string) =>
    c === "word" || c === "nonspace" || c === "nonword" || c.startsWith("negated:");
  if (a.classes.some(broad) && b.classes.length > 0) return true;
  if (b.classes.some(broad) && a.classes.length > 0) return true;
  return false;
}

/** Splits a pattern into top-level alternation branches. */
function splitAlternation(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  let inClass = false;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === "\\") {
      current += body.slice(i, i + 2);
      i += 1;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "]") inClass = false;
    if (!inClass) {
      if (ch === "(") depth += 1;
      else if (ch === ")") depth -= 1;
      else if (ch === "|" && depth === 0) {
        parts.push(current);
        current = "";
        continue;
      }
    }
    current += ch;
  }
  parts.push(current);
  return parts;
}

/** Length of the atom ending at `end`, reading escapes and classes correctly. */
function precedingAtom(body: string, end: number): string {
  if (end <= 0) return "";
  const last = body[end - 1];
  if (last === "]") {
    const open = body.lastIndexOf("[", end - 1);
    return open === -1 ? last : body.slice(open, end);
  }
  if (last === "\\" || /[A-Za-z0-9]/.test(last)) {
    // `\w` is two characters; a plain literal is one.
    const two = body.slice(Math.max(0, end - 2), end);
    if (two[0] === "\\") return two;
    return last;
  }
  return last;
}

/** Reads the atom at `i`, advancing past it. */
function atomAt(body: string, i: number): { text: string; next: number } {
  const ch = body[i];
  if (ch === "\\") return { text: body.slice(i, i + 2), next: i + 2 };
  if (ch === "[") {
    const close = body.indexOf("]", i + 1);
    return close === -1 ? { text: ch, next: i + 1 } : { text: body.slice(i, close + 1), next: close + 1 };
  }
  if (ch === "(") {
    const close = matchGroup(body, i);
    return close === -1 ? { text: ch, next: i + 1 } : { text: body.slice(i, close + 1), next: close + 1 };
  }
  if (ch === ".") return { text: ch, next: i + 1 };
  return { text: ch, next: i + 1 };
}

/**
 * The class of the *first* character the body can consume.
 *
 * This is what separates `(a+)+` (catastrophic: a repetition can restart on the
 * same `a`) from `( [a-z]+)*` (linear: every repetition must begin with a space,
 * so two repetitions can never match the same text).
 */
function firstCharClass(body: string): CharClass | undefined {
  let i = 0;
  while (i < body.length) {
    if (body[i] === "^" || body[i] === "$") {
      i += 1;
      continue;
    }
    if (body.startsWith("?:", i) || body.startsWith("?<", i)) {
      i += 2;
      continue;
    }
    break;
  }
  if (i >= body.length) return undefined;
  if (quantifierAt(body, i)) return undefined; // body starts with a quantifier
  return charClassOf(atomAt(body, i).text);
}

/**
 * True when the body can match the empty string, which makes any outer
 * quantifier loop forever: `(\s*)+`, `(a?)+`.
 */
function canMatchEmpty(body: string): boolean {
  const branches = splitAlternation(body);
  if (branches.some((b) => canMatchEmptySeq(b))) return true;
  return false;
}

function canMatchEmptySeq(body: string): boolean {
  let i = 0;
  while (i < body.length) {
    if (body[i] === "^" || body[i] === "$") {
      i += 1;
      continue;
    }
    if (body.startsWith("?:", i) || body.startsWith("?<", i)) {
      i += 2;
      continue;
    }
    break;
  }
  if (i >= body.length) return true;
  const atom = atomAt(body, i);
  const q = quantifierAt(body, atom.next);
  if (!q) return false; // a mandatory atom: the body cannot be empty
  // `{1,8}` still requires one character, so it cannot make the body optional.
  return q.min === 0;
}

/** Index of the group closing at `start`, or -1. */
function matchGroup(pattern: string, start: number): number {
  let depth = 0;
  let inClass = false;
  for (let i = start; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "\\") {
      i += 1;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "]") inClass = false;
    else if (!inClass && ch === "(") depth += 1;
    else if (!inClass && ch === ")") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

export interface RedosHit {
  reason: string;
  detail: string;
}

/**
 * Returns a reason when `pattern` can backtrack catastrophically.
 * Returning undefined means "not proven dangerous" — precision over recall.
 */
export function analyseRedosPattern(pattern: string): RedosHit | undefined {
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === "\\") {
      i += 2;
      continue;
    }
    if (ch !== "(") {
      i += 1;
      continue;
    }
    // Skip lookarounds and non-capturing groups only if they cannot backtrack;
    // lookarounds are analysed too because they can contain nested quantifiers.
    const close = matchGroup(pattern, i);
    if (close === -1) return undefined;

    const after = close + 1;
    const outer = quantifierAt(pattern, after);
    if (!outer || !outer.unbounded) {
      i = after;
      continue;
    }

    const body = pattern.slice(i + 1, close);
    const isAssertion = /^\?<?[=!]/.test(body);

    if (!isAssertion) {
      // Case 1: empty-matchable body under an outer quantifier — `(\s*)+`.
      if (canMatchEmpty(body)) {
        return { reason: "quantified group that can match the empty string", detail: pattern };
      }
      // Case 2: ambiguous alternation — `(a|a)*`, `(\w|\d)+`.
      const branches = splitAlternation(body);
      if (branches.length > 1) {
        const classes = branches.map(charClassOf);
        for (let a = 0; a < classes.length; a++) {
          for (let b = a + 1; b < classes.length; b++) {
            if (classesOverlap(classes[a], classes[b])) {
              return { reason: "overlapping alternatives inside a quantified group", detail: pattern };
            }
          }
        }
      }
      // Case 3: inner unbounded quantifier over a class the group can re-match —
      // the classic `(a+)+` / `(.*)*` shape.
      const head = firstCharClass(body);
      for (let j = 0; j < body.length; j++) {
        if (body[j] === "\\") {
          j += 1;
          continue;
        }
        const q = quantifierAt(body, j);
        if (!q || !q.unbounded) continue;
        // Only an unbounded inner quantifier can repeat the whole group.
        if (q.max <= BOUNDED_MAX) continue;
        const innerClass = charClassOf(precedingAtom(body, j) || body);
        if (!head) continue;
        // Backtracking explodes only when a later repetition can start where the
        // inner quantifier left off.
        if (classesOverlap(innerClass, head)) {
          return {
            reason: "nested unbounded quantifiers over overlapping characters",
            detail: pattern,
          };
        }
      }
    }
    i = after;
  }
  return undefined;
}

export function detectRedos(ctx: FileContext): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const testish = isTestishPath(ctx.file);

  walkAst(ctx.ast.program, (node) => {
    let pattern: string | undefined;
    let line: number;

    if (t.isRegExpLiteral(node)) {
      pattern = node.pattern;
      line = node.loc?.start.line ?? 0;
    } else if (
      t.isNewExpression(node) &&
      t.isIdentifier(node.callee, { name: "RegExp" }) &&
      t.isStringLiteral(node.arguments[0])
    ) {
      pattern = node.arguments[0].value;
      line = node.loc?.start.line ?? 0;
    } else {
      return;
    }

    const hit = analyseRedosPattern(pattern);
    if (!hit) return;

    const start = Math.max(0, line - 2);
    const end = Math.min(ctx.lines.length, line + 1);
    findings.push({
      ruleId: RULE_ID,
      title: "Regular expression can backtrack catastrophically (ReDoS)",
      description: `The pattern has ${hit.reason}. A crafted input can force the engine to explore exponentially many partitions, blocking the event loop.`,
      baseSeverity: "high",
      severity: testish ? "low" : "high",
      cwe: ["CWE-1333", "CWE-400"],
      owasp: "A05:2021 - Security Misconfiguration",
      category: "sast",
      file: ctx.file,
      startLine: line,
      endLine: line,
      codeSnippet: ctx.lines.slice(start, end).map((l, i) => `${start + i + 1}| ${l}`).join("\n"),
      sourceScanner: SCANNER,
      remediation:
        "Make the inner quantifiers unambiguous: use `[^x]*` instead of `.*`, anchor the pattern, or replace the regex with a linear-time matcher.",
      confidence: testish ? 0.75 : 0.9,
      confidenceLabel: confidenceLabel(testish ? 0.75 : 0.9),
      evidence: [
        { kind: "sink" as const, line, label: "regex literal with exponential backtracking", detail: hit.detail },
      ],
      exploitability:
        "Any request path that evaluates this pattern against attacker-supplied text can block the Node.js event loop for the whole process.",
      falsePositiveNotes: [
        "requires overlapping quantifiers, not merely a quantifier inside a group",
        "`(\\d+)`, `(abc*)` and `[a-z]+` are linear and are not reported",
        testish ? "downgraded: test/fixture/seed file" : "not a test/fixture/seed file",
      ],
      reachableFromHttp: false,
      testish,
    });
  });

  return findings;
}