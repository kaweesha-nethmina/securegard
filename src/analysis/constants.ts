/**
 * Constant folding over the AST.
 *
 * Two detectors need the same capability: the command-injection rule must know
 * that `` `cache:${id}` `` is a *derived* value rather than raw user input, and
 * the weak-cipher rule must resolve `const ALGO = 'des'` before checking it.
 *
 * A `const` is folded only within the function (or module) where it is declared.
 * Re-declaring a name in a nested scope produces different constants, so a
 * single module-wide map would let a local shadow change a call site's meaning —
 * the classic source of confident-but-wrong security findings.
 */

import * as t from "@babel/types";

export interface ConstEnv {
  /** Resolves an identifier to its literal value, or undefined if unknown. */
  get(name: string): t.Expression | undefined;
}

/** Builds a per-scope constant table for a function/program body. */
export function collectConsts(body: t.Node[]): Map<string, t.Expression> {
  const map = new Map<string, t.Expression>();
  for (const node of body) {
    if (!t.isVariableDeclaration(node)) continue;
    for (const decl of node.declarations) {
      if (!t.isIdentifier(decl.id) || !decl.init) continue;
      // Only fold literal-ish initialisers; a call result is not a constant.
      if (isStaticExpression(decl.init)) map.set(decl.id.name, decl.init);
    }
  }
  return map;
}

export class Scope implements ConstEnv {
  constructor(private consts: Map<string, t.Expression>, private parent?: ConstEnv) {}

  get(name: string): t.Expression | undefined {
    const own = this.consts.get(name);
    return own !== undefined ? own : this.parent?.get(name);
  }
}

/** An expression whose value is knowable without executing anything. */
export function isStaticExpression(node: t.Node): boolean {
  switch (node.type) {
    case "StringLiteral":
    case "NumericLiteral":
    case "BooleanLiteral":
    case "NullLiteral":
    case "RegExpLiteral":
      return true;
    case "UnaryExpression":
      return isStaticExpression(node.argument);
    case "TemplateLiteral": {
      // Only constant when every interpolation is itself constant.
      return node.expressions.every((e) => isStaticExpression(e));
    }
    case "ArrayExpression":
      return node.elements.every((e) => e === null || (t.isExpression(e) && isStaticExpression(e)));
    case "ObjectExpression":
      return node.properties.every(
        (p) => t.isObjectProperty(p) && !p.computed && isStaticExpression(p.value as t.Expression)
      );
    default:
      return false;
  }
}

/**
 * Strips concatenation and template interpolation down to its literal parts.
 *
 * Returns a list of literal segments; a non-empty list means the string is
 * *built from* constants, which is what makes `des-ede3` or a cache key
 * identifiable even though it never appears as one literal token.
 */
export function literalSegments(node: t.Node, env: ConstEnv, depth = 0): string[] | undefined {
  if (depth > 8) return undefined; // guard against pathological self-reference
  switch (node.type) {
    case "StringLiteral":
      return [node.value];
    case "TemplateLiteral": {
      const out: string[] = [];
      for (const quasi of node.quasis) out.push(quasi.value.cooked ?? quasi.value.raw);
      return out;
    }
    case "BinaryExpression": {
      if (node.operator !== "+") return undefined;
      const l = literalSegments(node.left, env, depth + 1);
      const r = literalSegments(node.right, env, depth + 1);
      return l && r ? [...l, ...r] : undefined;
    }
    case "Identifier": {
      const resolved = env.get(node.name);
      return resolved ? literalSegments(resolved, env, depth + 1) : undefined;
    }
    default:
      return undefined;
  }
}

/** Resolves an expression to a single string when it is fully constant. */
export function resolveConstantString(node: t.Node, env: ConstEnv): string | undefined {
  if (t.isStringLiteral(node)) return node.value;
  if (t.isIdentifier(node)) {
    const r = env.get(node.name);
    return r ? resolveConstantString(r, env) : undefined;
  }
  const segs = literalSegments(node, env);
  if (!segs || segs.length === 0) return undefined;
  // Concatenation of literals is only constant if every segment is literal —
  // which literalSegments already guarantees.
  return segs.join("");
}