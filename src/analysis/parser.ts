/**
 * Babel parser bootstrap.
 *
 * Parsing is the foundation of evidence-based detection: regexes cannot tell a
 * `child_process.exec` sink from a `RegExp.prototype.exec` call, so every rule
 * that matters now works on a real AST.
 *
 * Several syntactic forms are tolerated rather than rejected (a file we cannot
 * parse must not crash a scan or silently lose coverage):
 *   - `errorRecovery` collects recoverable syntax errors instead of throwing.
 *   - plugins cover JSX, TypeScript, decorators and class properties, which are
 *     ubiquitous in Express/NestJS codebases.
 */

import { parse as babelParse, ParserOptions, ParserPlugin } from "@babel/parser";
import * as t from "@babel/types";

export type ParsedFile = t.File;

/** Plugins for JS/TS/JSX. Babel 8 requires explicit opt-in per syntax. */
function pluginsFor(filePath: string): ParserPlugin[] {
  // Babel 8 enables class properties, private members, import attributes,
  // import.meta and top-level await by default; only opt in to the extras.
  const plugins: ParserPlugin[] = ["decorators-legacy"];
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".tsx") || lower.endsWith(".mts") || lower.endsWith(".cts")) {
    plugins.push("typescript");
  }
  if (lower.endsWith(".jsx") || lower.endsWith(".tsx")) {
    plugins.push("jsx");
  }
  return plugins;
}

const BASE_OPTIONS: Omit<ParserOptions, "sourceFilename"> = {
  errorRecovery: true,
  // Positions are reported in findings, so they must be 1-based lines.
  ranges: false,
  attachComment: true,
  createParenthesizedExpressions: false,
};

/**
 * Parses source text. Returns null when the file cannot be parsed at all, which
 * callers treat as "skip" rather than "clean" so we never claim false safety.
 */
export function parseSource(code: string, filePath: string): ParsedFile | null {
  const options: ParserOptions = {
    ...BASE_OPTIONS,
    sourceType: "unambiguous",
    sourceFilename: filePath,
    plugins: pluginsFor(filePath),
  };
  try {
    return babelParse(code, options);
  } catch {
    // Fall back to script mode: module-only syntax (import/export at top level)
    // in a CJS-ish file, or vice versa, shouldn't lose the whole file.
    try {
      return babelParse(code, { ...options, sourceType: "script" });
    } catch {
      try {
        return babelParse(code, { ...options, sourceType: "module" });
      } catch {
        return null;
      }
    }
  }
}

/** True when the parser recovered from syntax errors (treat findings as suspect). */
export function hasRecoverableErrors(ast: ParsedFile): boolean {
  const errs = (ast as unknown as { errors?: unknown[] }).errors;
  return Array.isArray(errs) && errs.length > 0;
}

export { t as types };