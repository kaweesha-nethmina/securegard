/**
 * Central file-eligibility gate.
 *
 * Root cause of the self-scan loop and the "ReDoS/insecure-random inside
 * docs/*.md" findings: `patternScanner` and `secretsScanner` had no notion of
 * what kind of file they were reading. `rulesForLanguage()` returns rules whose
 * `languages` is `["*"]` for *any* extension, and the only filters were file size
 * and a null-byte check. A markdown file therefore walked into the regex engine.
 *
 * This module is the single place that decides whether a file is analysed at all.
 */

import * as fs from "fs";
import * as path from "path";
import { isNonCodePath, isTestishPath } from "../analysis/context";

export interface ExcludeOptions {
  /** User globs from `secuguard.excludeGlobs`. */
  excludeGlobs: string[];
  /** Absolute paths of report/doc output that must never be scanned. */
  reportPaths?: string[];
  /** Extra paths from a `.secuguardignore` file. */
  ignoreFilePaths?: string[];
}

export interface Eligibility {
  eligible: boolean;
  reason?: string;
}

/** Extensions that can never contain analysable source. */
const NEVER_ANALYSE = new Set([
  "png", "jpg", "jpeg", "gif", "ico", "webp", "bmp", "tiff",
  "woff", "woff2", "ttf", "eot", "otf",
  "mp3", "mp4", "avi", "mov", "wav",
  "pdf", "zip", "gz", "tar", "bz2", "xz", "7z", "rar",
  "lock", "map", "snap", "so", "dylib", "dll", "exe", "wasm", "node",
]);

/** Directories never descended into. */
const EXCLUDED_DIRS = new Set([
  "node_modules", "dist", "build", "out", "coverage", "vendor", ".git", ".svn",
  ".hg", ".next", ".nuxt", ".cache", ".turbo", ".yarn", "bower_components",
  "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
  "bin", "obj", "target", ".gradle", "Pods", ".idea",
]);

/**
 * SecuGuard's own output. The extension previously scanned
 * `docs/secuguard-final-qa-report.md` and reported findings about its own
 * report — including the literal `${data.checklist...}` bug — which is pure noise.
 */
export function isSelfGeneratedPath(file: string): boolean {
  const lower = file.toLowerCase();
  if (/(^|\/)\.secuguard\//.test(lower)) return true;
  if (/(^|\/)(secuguard-final-qa-report|secuguard-report|qa-report|security-report)\.(md|html|json|csv)$/.test(lower)) {
    return true;
  }
  return false;
}

/** Converts a glob to a regex, honouring `**`, `*` and `?`. */
function globToRegExp(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === "*") {
      if (glob[i + 1] === "*") {
        // `**/` matches any number of path segments (including none).
        if (glob[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else {
        out += "[^/]*";
      }
    } else if (ch === "?") {
      out += "[^/]";
    } else if ("\\^$+.()|{}[]".includes(ch)) {
      out += `\\${ch}`;
    } else {
      out += ch;
    }
  }
  return new RegExp(`^${out}$`, "i");
}

export class ExcludeMatcher {
  private patterns: RegExp[];

  constructor(private opts: ExcludeOptions) {
    const globs = [...opts.excludeGlobs, ...(opts.ignoreFilePaths ?? [])];
    this.patterns = globs.map(globToRegExp);
  }

  /** Tests a workspace-relative path against the configured globs. */
  matches(relPath: string): boolean {
    const normalized = relPath.split(path.sep).join("/");
    // Match both the full path and each path segment, so `**/dist/**` also
    // excludes a top-level `dist/foo.js`.
    const segments = normalized.split("/");
    return this.patterns.some((re) => {
      if (re.test(normalized)) return true;
      return segments.some((seg, i) => {
        const partial = segments.slice(0, i + 1).join("/");
        return re.test(partial) || re.test(partial + "/");
      });
    });
  }

  /** True when a directory should not be descended into. */
  isExcludedDir(relDir: string): boolean {
    const name = relDir.split("/").pop() ?? relDir;
    if (EXCLUDED_DIRS.has(name)) return true;
    return this.matches(relDir);
  }

  /**
   * True when the file looks generated/bundled: minified, or a single very long
   * line, which is what esbuild/webpack/terser output looks like.
   */
  looksGenerated(content: string): boolean {
    const lines = content.split("\n");
    if (lines.length <= 2 && lines.some((l) => l.length > 4000)) return true;
    return false;
  }
}

/** Extensions the Babel-based AST engine can parse. */
export const AST_EXTENSIONS = new Set(["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"]);

/** Reads `.secuguardignore` (gitignore syntax) if present. */
export function readIgnoreFile(root: string): string[] {
  const p = path.join(root, ".secuguardignore");
  try {
    if (!fs.existsSync(p)) return [];
    return fs
      .readFileSync(p, "utf8")
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
  } catch {
    return [];
  }
}

/** Bundles and hash-named outputs, identified by path shape alone. */
function looksGeneratedPath(relPath: string): boolean {
  const lower = relPath.toLowerCase();
  if (/\.min\.(js|mjs|cjs|css)$/.test(lower)) return true;
  if (/(^|\/)(bundles?|chunk|generated)(?:\/|\.|$)/.test(lower)) return true;
  if (/^[a-f0-9]{8,}\.(js|mjs|cjs)$/.test(lower.split("/").pop() ?? "")) return true;
  return false;
}

export interface FileEligibility extends Eligibility {
  testish: boolean;
}

/**
 * Decides whether a file should be analysed by the security engine.
 *
 * Note this is a *gate*, not a severity filter: a finding can be downgraded or
 * hidden later, but a file that is documentation must never reach a regex that
 * was written for executable code.
 */
export function checkFileEligibility(
  absPath: string,
  relPath: string,
  content: string,
  matcher: ExcludeMatcher
): FileEligibility {
  const ext = (relPath.split(".").pop() ?? "").toLowerCase();

  if (NEVER_ANALYSE.has(ext)) return { eligible: false, reason: "binary/asset extension", testish: false };
  if (looksGeneratedPath(relPath)) return { eligible: false, reason: "generated/minified bundle", testish: false };
  if (isSelfGeneratedPath(relPath)) return { eligible: false, reason: "SecuGuard's own output", testish: false };
  if (isNonCodePath(relPath)) return { eligible: false, reason: "not executable source", testish: false };
  if (matcher.matches(relPath)) return { eligible: false, reason: "matched excludeGlobs", testish: false };
  if (matcher.looksGenerated(content)) return { eligible: false, reason: "generated/minified bundle", testish: false };

  return { eligible: true, testish: isTestishPath(relPath) };
}

/**
 * Recursively collects analysable files.
 *
 * Replaces the hand-rolled walk() in patternScanner/secretsScanner, whose glob
 * handling stripped glob metacharacters and degraded a directory pattern into a
 * bare substring check, and which had no concept of excluded directories.
 */
export function collectAnalysableFiles(
  root: string,
  workspaceRoot: string,
  matcher: ExcludeMatcher,
  maxBytes = 2 * 1024 * 1024,
  /** Called for every file that was rejected, so callers can report the reason. */
  onSkip?: (relPath: string, reason: string) => void
): string[] {
  const out: string[] = [];

  const visit = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      const rel = path.relative(workspaceRoot, abs).split(path.sep).join("/");
      if (entry.isDirectory()) {
        if (matcher.isExcludedDir(rel)) continue;
        visit(abs);
        continue;
      }
      if (!entry.isFile()) continue;

      let stat: fs.Stats;
      try {
        stat = fs.statSync(abs);
      } catch {
        continue;
      }
      if (stat.size > maxBytes) {
        onSkip?.(rel, `file larger than ${Math.round(maxBytes / 1024 / 1024)}MB`);
        continue;
      }

      // The generated-output check needs the text, so read a bounded head only:
      // bundlers emit one enormous line and nothing else needs the body here.
      let head = "";
      try {
        const fd = fs.openSync(abs, "r");
        try {
          const buf = Buffer.alloc(64 * 1024);
          const read = fs.readSync(fd, buf, 0, buf.length, 0);
          head = buf.subarray(0, read).toString("utf8");
        } finally {
          fs.closeSync(fd);
        }
      } catch {
        continue;
      }

      const check = checkFileEligibility(abs, rel, head, matcher);
      if (check.eligible) {
        out.push(abs);
      } else {
        onSkip?.(rel, check.reason ?? "excluded");
      }
    }
  };

  visit(root);
  return out;
}