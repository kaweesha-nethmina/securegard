/**
 * Analysis context for a single file.
 *
 * Rule authors should not re-walk the AST or rebuild constant/import tables per
 * rule: that was the structural reason every rule was text-only before. This
 * module parses once and exposes the derived tables plus a scope-aware binder.
 */

import * as t from "@babel/types";
import { parseSource, hasRecoverableErrors } from "./parser";
import { collectConsts, Scope, ConstEnv } from "./constants";
import { collectImports, Imports } from "./taint";

/** Babel does not type `parent`, but `@babel/traverse` sets it during a walk. */
type WithParent = t.Node & { parent?: t.Node };

const parentOf = (node: t.Node): t.Node | undefined => (node as WithParent).parent;

export interface FileContext {
  file: string;
  ast: t.File;
  lines: string[];
  imports: Imports;
  /** True when the parser had to recover — findings should be marked less certain. */
  recovered: boolean;
  /**
   * Resolves an identifier to its binding expression within the innermost scope
   * containing `node`.
   */
  scopeAt(node: t.Node): ConstEnv;
}

export function createFileContext(code: string, filePath: string): FileContext | null {
  const ast = parseSource(code, filePath);
  if (!ast) return null;
  const program: t.Program = ast.program;
  const lines = code.split(/\r?\n/);
  const imports = collectImports(ast);
  const moduleConsts = collectConsts(program.body);

  // Per-function constant tables, keyed by the function node. Built lazily but
  // cached, so a rule that visits a function twice pays for it once.
  const scopeCache = new Map<t.Node, Scope>();

  function findEnclosingFunctionBody(node: t.Node): t.Node[] {
    let cur: t.Node | undefined = node;
    while (cur) {
      if (t.isFunction(cur) && t.isBlockStatement(cur.body)) return cur.body.body;
      cur = parentOf(cur);
    }
    return program.body;
  }

  function scopeFor(node: t.Node): Scope {
    const body = findEnclosingFunctionBody(node);
    const owner = (body === program.body ? program : body) as t.Node;
    let scope = scopeCache.get(owner);
    if (!scope) {
      const parentScope = body === program.body ? undefined : scopeFor(owner);
      scope = new Scope(collectConsts(body), parentScope);
      scopeCache.set(owner, scope);
    }
    return scope;
  }

  return {
    file: filePath,
    ast,
    lines,
    imports,
    recovered: hasRecoverableErrors(ast),
    scopeAt: scopeFor,
  };
}

/** Depth-first walk over every node in the program. */
export function walkAst(root: t.Node, visit: (node: t.Node, parent?: t.Node) => void | boolean): void {
  const stack: { node: t.Node; parent?: t.Node }[] = [{ node: root }];
  while (stack.length) {
    const { node, parent } = stack.pop()!;
    const res = visit(node, parent);
    if (res === false) continue; // subtree pruned
    const children = childNodes(node);
    for (let i = children.length - 1; i >= 0; i--) {
      stack.push({ node: children[i], parent: node });
    }
  }
}

const SKIP_KEYS = new Set(["loc", "start", "end", "range", "extra", "leadingComments", "trailingComments", "innerComments", "comments"]);

/** Enumerable child nodes, excluding position/comment metadata. */
export function childNodes(node: t.Node): t.Node[] {
  const out: t.Node[] = [];
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(value)) {
      for (const v of value) {
        if (v && typeof v === "object" && typeof (v as t.Node).type === "string") {
          out.push(v as t.Node);
        }
      }
    } else if (value && typeof value === "object" && typeof (value as t.Node).type === "string") {
      out.push(value as t.Node);
    }
  }
  return out;
}

/** Enclosing function, used for reachability and cross-function taint. */
export function enclosingFunction(node: t.Node): t.Function | undefined {
  let cur: t.Node | undefined = node;
  while (cur) {
    if (t.isFunction(cur)) return cur;
    cur = parentOf(cur);
  }
  return undefined;
}

/** True when the node sits inside a test/fixture/seed/migration file context. */
export function isTestishPath(file: string): boolean {
  const lower = file.toLowerCase();
  return (
    /(^|\/)(test|tests|__tests__|spec|specs|e2e|__mocks__|mocks|fixtures|seeds?|migrations?|__snapshots__)(\/|$)/.test(lower) ||
    /\.(test|spec)\.[a-z]+$/.test(lower) ||
    /(^|\/)test_[^/]*\.[a-z]+$/.test(lower) ||
    /_test\.[a-z]+$/.test(lower) ||
    /(conftest|setuptests?)\.[a-z]+$/.test(lower)
  );
}

/** True when the file is documentation, data or generated output, never code. */
export function isNonCodePath(file: string): boolean {
  const lower = file.toLowerCase();
  const ext = lower.split(".").pop() ?? "";
  const NON_CODE = new Set([
    "md", "markdown", "mdx", "txt", "rst", "adoc", "csv", "tsv", "lock", "log",
    "yml", "yaml", "toml", "ini", "conf", "cfg", "png", "jpg", "jpeg", "gif",
    "svg", "ico", "webp", "pdf", "zip", "gz", "tar", "woff", "woff2", "ttf",
    "eot", "mp4", "mp3", "map", "snap", "html", "htm", "css", "scss", "less",
    "json", "jsonl", "xml",
  ]);
  if (NON_CODE.has(ext)) return true;
  if (/(^|\/)(docs?|documentation|reports?|coverage|dist|build|out|vendor|node_modules|\.git)\//.test(lower)) {
    // Files under these dirs are excluded even when the extension looks like code.
    return true;
  }
  if (/\.min\.(js|css)$/.test(lower)) return true;
  if (/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|composer\.lock)$/.test(lower)) {
    return true;
  }
  return false;
}