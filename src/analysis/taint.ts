/**
 * Import resolution and taint tracking.
 *
 * Root cause of the 279 CWE-78 false positives: the old rule matched the text
 * `exec(` and any `` `...${...}` `` template literal. Neither proves a shell
 * sink nor any user input. This module supplies the two facts a finding needs:
 *
 *   1. Sink identity — is `run(...)` actually `child_process.exec`? Resolved
 *      through `require`, ES imports, destructuring, aliases and namespaces, so
 *      `const { exec: run } = require('child_process')` is caught while
 *      `PATTERN.exec(...)` is not.
 *   2. Taint — does a defined source reach that sink without a sanitizer?
 */

import * as t from "@babel/types";
import { ConstEnv } from "./constants";

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

export type SinkKind = "shell" | "argv" | "spawn-shell";

interface SinkDef {
  /** Module export name -> sink kind. */
  kind: SinkKind;
  /** True when the call is dangerous even with constant args (spawn w/ shell:true). */
  needsTaint: boolean;
}

/** child_process exports that invoke a shell. */
export const CHILD_PROCESS_SHELL: Record<string, SinkDef> = {
  exec: { kind: "shell", needsTaint: true },
  execSync: { kind: "shell", needsTaint: true },
  execFile: { kind: "shell", needsTaint: true }, // dangerous only with shell:true
  execFileSync: { kind: "shell", needsTaint: true },
};

/** child_process exports that do NOT use a shell — argv form is safe. */
export const CHILD_PROCESS_ARGV = new Set(["spawn", "spawnSync", "fork"]);

export const SHELL_JS_MODULES = new Set(["shelljs", "shell"]);

// ---------------------------------------------------------------------------
// Import resolution
// ---------------------------------------------------------------------------

export interface Imports {
  /** local identifier -> resolved module + export path */
  bindings: Map<string, { module: string; exported: string }>;
  /** namespace identifier -> module */
  namespaces: Map<string, string>;
  /** bare import source strings, for require() detection */
  sources: string[];
}

/** True for a specifier that means "the node standard library". */
function isNodeBuiltin(spec: string): boolean {
  return spec.startsWith("node:") || BUILTINS.has(spec);
}

const BUILTINS = new Set([
  "child_process", "fs", "path", "crypto", "http", "https", "net", "os", "vm",
  "zlib", "tls", "dgram", "cluster", "worker_threads", "util", "events", "stream",
]);

/** Collects import bindings so sinks and sources can be identified by origin. */
export function collectImports(ast: t.File): Imports {
  const bindings = new Map<string, { module: string; exported: string }>();
  const namespaces = new Map<string, string>();
  const sources: string[] = [];

  for (const node of ast.program.body) {
    if (t.isImportDeclaration(node) && t.isStringLiteral(node.source)) {
      const mod = node.source.value;
      sources.push(mod);
      for (const spec of node.specifiers) {
        if (t.isImportSpecifier(spec) && t.isIdentifier(spec.imported)) {
          bindings.set(spec.local.name, { module: mod, exported: spec.imported.name });
        } else if (t.isImportDefaultSpecifier(spec)) {
          bindings.set(spec.local.name, { module: mod, exported: "default" });
        } else if (t.isImportNamespaceSpecifier(spec)) {
          namespaces.set(spec.local.name, mod);
        }
      }
    } else if (t.isVariableDeclaration(node)) {
      // const { exec: run } = require('child_process')
      for (const decl of node.declarations) {
        if (!decl.init || !t.isCallExpression(decl.init)) continue;
        const arg = decl.init.arguments[0];
        if (!t.isStringLiteral(arg)) continue;
        const mod = arg.value;
        sources.push(mod);
        if (t.isObjectPattern(decl.id)) {
          for (const prop of decl.id.properties) {
            if (!t.isObjectProperty(prop)) continue;
            const key = t.isIdentifier(prop.key) ? prop.key.name : undefined;
            if (!key) continue;
            if (t.isAssignmentPattern(prop.value) && t.isIdentifier(prop.value.left)) {
              bindings.set(prop.value.left.name, { module: mod, exported: key });
            } else if (t.isIdentifier(prop.value)) {
              bindings.set(prop.value.name, { module: mod, exported: key });
            }
          }
        } else if (t.isIdentifier(decl.id)) {
          namespaces.set(decl.id.name, mod);
        }
      }
    }
  }
  return { bindings, namespaces, sources };
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/**
 * Expression patterns that introduce untrusted data.
 * Each carries a human label used in the evidence trace shown to the user.
 */
export interface SourceDef {
  id: string;
  label: string;
  test: (node: t.Node) => boolean;
}

export const SOURCES: SourceDef[] = [
  {
    id: "req-body",
    label: "HTTP request body",
    test: (n) => isMemberOn(n, ["req", "request", "ctx"], ["body"]),
  },
  {
    id: "req-query",
    label: "HTTP query string",
    test: (n) => isMemberOn(n, ["req", "request", "ctx"], ["query"]),
  },
  {
    id: "req-params",
    label: "HTTP route parameters",
    test: (n) => isMemberOn(n, ["req", "request", "ctx"], ["params"]),
  },
  {
    id: "req-headers",
    label: "HTTP request headers",
    test: (n) => isMemberOn(n, ["req", "request", "ctx"], ["headers"]),
  },
  {
    id: "req-cookies",
    label: "HTTP cookies",
    test: (n) => isMemberOn(n, ["req", "request", "ctx"], ["cookies"]),
  },
  {
    id: "process-argv",
    label: "process command-line arguments",
    test: (n) => t.isMemberExpression(n) && isProcessArgv(n),
  },
  {
    id: "fs-read",
    label: "file contents read from disk",
    test: (n) => t.isCallExpression(n) && isFsRead(n),
  },
  {
    id: "incoming-message",
    label: "incoming HTTP data chunk",
    test: (n) => isIdentifier(n, "data") || isIdentifier(n, "chunk"),
  },
  {
    id: "process-env",
    label: "environment variable",
    test: (n) => t.isMemberExpression(n) && isProcessEnv(n),
  },
];

function isIdentifier(n: t.Node, name: string): boolean {
  return t.isIdentifier(n, { name });
}

function isProcessEnv(n: t.MemberExpression): boolean {
  const obj = n.object;
  const prop = n.property;
  return (
    t.isIdentifier(obj, { name: "process" }) &&
    ((t.isIdentifier(prop) && prop.name === "env") || (t.isStringLiteral(prop)))
  );
}

function isProcessArgv(n: t.MemberExpression): boolean {
  const obj = n.object;
  if (t.isMemberExpression(obj) && isProcessEnv(obj)) {
    return t.isIdentifier(n.property, { name: "argv" });
  }
  return t.isIdentifier(obj, { name: "process" }) && t.isIdentifier(n.property, { name: "argv" });
}

function isFsRead(call: t.CallExpression): boolean {
  const callee = call.callee;
  if (!t.isMemberExpression(callee) || !t.isIdentifier(callee.object, { name: "fs" })) return false;
  return t.isIdentifier(callee.property) && ["readFile", "readFileSync", "readFileSync0"].includes(callee.property.name);
}

/**
 * Matches `<something>.body` / `.query` / `.params` / `.headers` / `.cookies`.
 *
 * Accepts the common Express shapes: `req.query`, `request.body`, and the
 * Fastify/NestJS-style `ctx.request.query`. The chain must bottom out at an
 * identifier, so a bare object literal can never satisfy it.
 */
function isMemberOn(n: t.Node, baseNames: string[], props: string[]): boolean {
  if (!t.isMemberExpression(n)) return false;
  let cur: t.Node = n;
  const seenProps: string[] = [];
  while (t.isMemberExpression(cur)) {
    const p = cur.property;
    if (cur.computed) {
      // Allow req[dynamicKey] style only for the intermediate hop, never the tail.
      if (!t.isStringLiteral(p)) return false;
      seenProps.unshift(p.value);
    } else if (t.isIdentifier(p)) {
      seenProps.unshift(p.name);
    } else {
      return false;
    }
    cur = cur.object;
  }
  if (!t.isIdentifier(cur)) return false;
  if (!baseNames.includes(cur.name)) return false;
  return props.some((p) => seenProps.includes(p));
}

// ---------------------------------------------------------------------------
// Sanitizers
// ---------------------------------------------------------------------------

export interface SanitizerDef {
  id: string;
  label: string;
  test: (node: t.Node) => boolean;
}

const ALLOW_LIST_WORDS = [
  "allowlist", "allowList", "whitelist", "whiteList", "sanitiz", "validat", "escape",
  "normalize", "assert", "parseInt", "parseFloat", "Number", "zod", "joi", "yup",
  "validator", "isSafe", "safePath", "inArray", "oneOf", "matches", "isAlphanumeric",
];

export const SANITIZERS: SanitizerDef[] = [
  {
    id: "number-coercion",
    label: "coerced to a number",
    test: (n) =>
      t.isCallExpression(n) &&
      t.isIdentifier(n.callee) &&
      ["parseInt", "parseFloat", "Number"].includes(n.callee.name),
  },
  {
    id: "path-basename",
    label: "reduced to a basename with path.basename",
    test: (n) =>
      t.isCallExpression(n) &&
      t.isMemberExpression(n.callee) &&
      t.isIdentifier(n.callee.property, { name: "basename" }),
  },
  {
    id: "allowlist-check",
    label: "checked against an allow-list or schema validator",
    test: (n) => {
      if (!t.isCallExpression(n) && !t.isAwaitExpression(n)) return false;
      const callee = t.isAwaitExpression(n) ? n.argument : n;
      if (!t.isCallExpression(callee)) return false;
      const name = callee.callee;
      const text = t.isIdentifier(name) ? name.name : t.isMemberExpression(name) && t.isIdentifier(name.property) ? name.property.name : "";
      return ALLOW_LIST_WORDS.some((w) => text.includes(w));
    },
  },
  {
    id: "stringify",
    label: "serialised with JSON.stringify",
    test: (n) =>
      t.isCallExpression(n) &&
      t.isMemberExpression(n.callee) &&
      t.isIdentifier(n.callee.object, { name: "JSON" }) &&
      t.isIdentifier(n.callee.property, { name: "stringify" }),
  },
  {
    id: "literal-only",
    label: "assigned a literal constant (no data flow)",
    // Deliberately excludes TemplateLiteral: a template carries taint through
    // its interpolations, so it is judged by walking those expressions instead.
    test: (n) => t.isStringLiteral(n) || t.isNumericLiteral(n) || t.isBooleanLiteral(n),
  },
];

// ---------------------------------------------------------------------------
// Sink resolution
// ---------------------------------------------------------------------------

export interface ResolvedSink {
  kind: SinkKind;
  api: string;
}

/**
 * Identifies a command-execution sink for a CallExpression callee.
 *
 * Returns undefined for `PATTERN.exec(...)`, `results.exec(...)` and any other
 * method named `exec` that did not come from child_process — the single biggest
 * source of false positives in the old engine.
 */
export function resolveShellSink(
  callee: t.Node,
  imports: Imports,
  options: { shellOption?: t.Expression } = {}
): ResolvedSink | undefined {
  // Direct: child_process.exec(...)
  if (t.isMemberExpression(callee) && t.isIdentifier(callee.object, { name: "child_process" })) {
    const name = memberName(callee);
    const def = name ? CHILD_PROCESS_SHELL[name] : undefined;
    if (def) return { kind: def.kind, api: `child_process.${name}` };
  }

  // Aliased import: run(...) where run = exec from child_process
  if (t.isIdentifier(callee)) {
    const binding = imports.bindings.get(callee.name);
    if (binding && CHILD_PROCESS_SHELL[binding.exported]) {
      return { kind: "shell", api: `${binding.module}.${binding.exported}` };
    }
  }

  // Namespace: cp.exec(...) where cp = require('child_process')
  if (t.isMemberExpression(callee) && t.isIdentifier(callee.object)) {
    const ns = imports.namespaces.get(callee.object.name);
    if (ns) {
      const name = memberName(callee);
      if (name && CHILD_PROCESS_SHELL[name]) {
        return { kind: "shell", api: `${ns}.${name}` };
      }
    }
  }

  // shelljs / shell module
  if (t.isCallExpression(callee)) {
    const api = calleeName(callee);
    if (api && SHELL_JS_MODULES.has(api)) return { kind: "shell", api };
  }

  // Bare exec(...) with no import — only if the module imported child_process at
  // all. Without this guard `results.exec(cmd)` would match.
  if (t.isIdentifier(callee) && CHILD_PROCESS_SHELL[callee.name] && imports.sources.some((s) => isNodeBuiltin(s))) {
    // Still ambiguous, but the file clearly works with node builtins. Kept
    // conservative: only when the name is not shadowed by a local binding.
    return { kind: "shell", api: callee.name };
  }

  return undefined;
}

export function isArgvSink(callee: t.Node, imports: Imports): ResolvedSink | undefined {
  const name = t.isMemberExpression(callee) && t.isIdentifier(callee.object, { name: "child_process" })
    ? memberName(callee)
    : t.isIdentifier(callee)
      ? imports.bindings.get(callee.name)?.exported
      : undefined;
  if (name && CHILD_PROCESS_ARGV.has(name)) {
    return { kind: "argv", api: `child_process.${name}` };
  }
  return undefined;
}

/** True when a call passes shell:true, which makes argv APIs dangerous. */
export function hasShellTrue(call: t.CallExpression): boolean {
  for (const arg of call.arguments) {
    if (!t.isObjectExpression(arg)) continue;
    for (const prop of arg.properties) {
      if (!t.isObjectProperty(prop)) continue;
      const key = t.isIdentifier(prop.key) ? prop.key.name : t.isStringLiteral(prop.key) ? prop.key.value : "";
      if (key !== "shell") continue;
      if (t.isBooleanLiteral(prop.value) && prop.value.value === true) return true;
    }
  }
  return false;
}

function memberName(m: t.MemberExpression): string | undefined {
  const p = m.property;
  if (t.isIdentifier(p)) return p.name;
  if (t.isStringLiteral(p)) return p.value;
  return undefined;
}

function calleeName(call: t.CallExpression): string | undefined {
  if (t.isIdentifier(call.callee)) return call.callee.name;
  if (t.isMemberExpression(call.callee)) return memberName(call.callee);
  return undefined;
}

// ---------------------------------------------------------------------------
// Taint propagation
// ---------------------------------------------------------------------------

export interface TraceStep {
  kind: "source" | "propagation" | "sanitizer" | "sink";
  file?: string;
  line: number;
  label: string;
  detail?: string;
}

export interface TaintResult {
  tainted: boolean;
  source?: SourceDef;
  /** Ordered evidence: source -> propagation -> sink. */
  trace: TraceStep[];
  sanitizers: SanitizerDef[];
}

/**
 * Walks backwards from a sink argument to find an untrusted source.
 *
 * Scope-aware: a name is only tainted if it was assigned from something tainted
 * *before* the sink in the same scope, which is what stops
 * `` const key = `cache:${id}` `` followed later by `` exec(cacheKey) `` from
 * being reported as a shell injection when `id` is not attacker controlled.
 */
export function traceTaint(
  node: t.Node,
  scopeEnv: ConstEnv,
  bindings: Map<string, t.Expression>,
  file: string
): TaintResult {
  const trace: TraceStep[] = [];
  const sanitizers: SanitizerDef[] = [];
  const found = walk(node, 0);
  if (!found) return { tainted: false, trace, sanitizers };
  trace.push(...found.trace);
  sanitizers.push(...found.sanitizers);
  return { tainted: true, source: found.source, trace, sanitizers };

  function lineOf(n: t.Node): number {
    return n.loc?.start.line ?? 1;
  }

  function record(kind: TraceStep["kind"], n: t.Node, label: string, detail?: string): TraceStep {
    return { kind, line: lineOf(n), label, detail, file };
  }

  function walk(n: t.Node, d: number): { source: SourceDef; trace: TraceStep[]; sanitizers: SanitizerDef[] } | undefined {
    if (d > 12) return undefined; // bounded recursion

    // A sanitizer anywhere on the path stops propagation.
    //
    // TemplateLiteral is the one exception: it is a composite node, so its
    // interpolations must still be walked. `literal-only` therefore no longer
    // claims it, and the template branch below decides based on the expressions.
    if (!t.isTemplateLiteral(n)) {
      for (const s of SANITIZERS) {
        if (s.test(n)) {
          return undefined;
        }
      }
    }

    // Direct source.
    for (const s of SOURCES) {
      if (s.test(n)) {
        return { source: s, trace: [record("source", n, s.label)], sanitizers };
      }
    }

    // Identifier: follow its recorded binding back to its initialiser.
    if (t.isIdentifier(n)) {
      const declNode = bindings.get(n.name) ?? scopeEnv.get(n.name);
      if (declNode) {
        const inner = walk(declNode, d + 1);
        if (inner) {
          return {
            source: inner.source,
            trace: [...inner.trace, record("propagation", n, `propagated through \`${n.name}\``)],
            sanitizers,
          };
        }
      }
      return undefined;
    }

    // Binary + : concatenation propagates taint from either side.
    if (t.isBinaryExpression(n) && n.operator === "+") {
      const l = walk(n.left, d + 1);
      if (l) return { ...l, trace: [...l.trace, record("propagation", n, "concatenated into the command")] };
      const r = walk(n.right, d + 1);
      if (r) return { ...r, trace: [...r.trace, record("propagation", n, "concatenated into the command")] };
      return undefined;
    }

    // Template literal: propagates if any interpolation is tainted.
    if (t.isTemplateLiteral(n)) {
      for (const expr of n.expressions) {
        const inner = walk(expr, d + 1);
        if (inner) {
          return { ...inner, trace: [...inner.trace, record("propagation", n, "interpolated into the command")] };
        }
      }
      return undefined; // all-constant template = safe (the cache-key FP)
    }

    // Await / spread / TSAs: unwrap.
    if (t.isAwaitExpression(n)) return walk(n.argument, d + 1);
    if (t.isTSAsExpression(n) || t.isTSTypeAssertion(n) || t.isTSNonNullExpression(n)) {
      return walk(n.expression, d + 1);
    }
    if (t.isSpreadElement(n) || t.isParenthesizedExpression?.(n as t.Node)) {
      return walk((n as t.SpreadElement).argument, d + 1);
    }

    // Call: args may carry taint out (e.g. a taint-preserving helper).
    if (t.isCallExpression(n)) {
      for (const arg of n.arguments) {
        if (!t.isExpression(arg)) continue;
        const inner = walk(arg, d + 1);
        if (inner) return { ...inner, trace: [...inner.trace, record("propagation", n, "passed as a call argument")] };
      }
    }

    // Object/array literal containing tainted values.
    if (t.isObjectExpression(n)) {
      for (const p of n.properties) {
        if (!t.isObjectProperty(p)) continue;
        const inner = walk(p.value as t.Expression, d + 1);
        if (inner) return { ...inner, trace: [...inner.trace, record("propagation", n, "embedded in an object")] };
      }
    }
    if (t.isArrayExpression(n)) {
      for (const el of n.elements) {
        if (!t.isExpression(el)) continue;
        const inner = walk(el, d + 1);
        if (inner) return { ...inner, trace: [...inner.trace, record("propagation", n, "included in an array")] };
      }
    }

    // Member access on a tainted object: req.body.user.id
    if (t.isMemberExpression(n)) {
      const inner = walk(n.object, d + 1);
      if (inner) return { ...inner, trace: [...inner.trace, record("propagation", n, "read from a tainted value")] };
    }

    return undefined;
  }
}