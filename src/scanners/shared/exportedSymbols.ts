import * as fs from "fs";
import * as path from "path";

/** A symbol exported from a module, plus the line right above it (used for doc checks). */
export interface ExportedSymbol {
  name: string;
  kind: "function" | "class" | "const";
  /** workspace-relative path */
  file: string;
  /** 1-based line of the export/definition */
  line: number;
  /** definition line + neighbours, for display */
  codeSnippet: string;
  /** trimmed content of the nearest non-blank line above the definition, if any */
  docLine: string | undefined;
  /** true if the nearest comment-looking line above the definition looks like docs */
  hasDocs: boolean;
}

const CODE_EXT = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs", "py"]);

export function isCodeFile(filePath: string): boolean {
  return CODE_EXT.has(filePath.split(".").pop()?.toLowerCase() ?? "");
}

/** Workspace-relative path with forward slashes. */
export function relPath(filePath: string, workspaceRoot: string): string {
  return path.relative(workspaceRoot, filePath).split(path.sep).join("/");
}

/** Recursive walk over files, skipping SecuGuard's own data dir and excludeGlobs. */
export function walkFiles(dir: string, excludeGlobs: string[], out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    const normalized = full.split(path.sep).join("/");
    if (normalized.includes("/.secuguard/")) continue;
    if (excludeGlobs.some((g) => matchesGlob(normalized, g))) continue;
    if (entry.isDirectory()) walkFiles(full, excludeGlobs, out);
    else if (entry.isFile()) out.push(full);
  }
}

function matchesGlob(normalizedPath: string, glob: string): boolean {
  const core = glob.replace(/^\*\*\//, "").replace(/\/\*\*$/, "").replace(/\*/g, "");
  return core.length > 0 && normalizedPath.includes(core);
}

/** True if the workspace-relative path matches one of the test-file globs. */
export function isTestFile(relPathToCheck: string, testGlobs: string[]): boolean {
  const n = relPathToCheck.split(path.sep).join("/");
  return testGlobs.some((g) => matchesGlob(n, g));
}

/** Extract the exported symbols from a JS/TS or Python source file. */
export function exportedSymbolsFromSource(
  content: string,
  relFile: string
): Omit<ExportedSymbol, "hasDocs">[] {
  const lines = content.split(/\r?\n/);
  const ext = (relFile.split(".").pop() || "").toLowerCase();
  const symbols: Omit<ExportedSymbol, "hasDocs">[] = [];

  const add = (name: string, kind: "function" | "class" | "const", lineIdx: number) => {
    const start = Math.max(0, lineIdx - 1);
    const end = Math.min(lines.length, lineIdx + 2);
    symbols.push({
      name,
      kind,
      file: relFile,
      line: lineIdx + 1,
      codeSnippet: lines
        .slice(start, end)
        .map((l, i) => `${start + i + 1}| ${l}`)
        .join("\n"),
      docLine: docLineFor(lines, lineIdx),
    });
  };

  if (ext === "py") {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\S/.test(line) === false) continue; // must be top-level (no leading whitespace)
      let m: RegExpExecArray | null;
      m = /^(?:async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/.exec(line);
      if (m && !m[1].startsWith("_")) {
        add(m[1], "function", i);
        continue;
      }
      m = /^class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[:/(]/.exec(line);
      if (m && !m[1].startsWith("_")) {
        add(m[1], "class", i);
      }
    }
  } else {
    const re =
      /export\s+(?:async\s+)?(function|class)\s+([A-Za-z_$][\w$]*)\s*[\(<{]|export\s+(?:async\s+)?const\s+([A-Za-z_$][\w$]*)\s*=/g;
    for (let i = 0; i < lines.length; i++) {
      let m: RegExpExecArray | null;
      re.lastIndex = 0;
      while ((m = re.exec(lines[i])) !== null) {
        if (m[1] === "function") add(m[2], "function", i);
        else if (m[1] === "class") add(m[2], "class", i);
        else if (m[3]) add(m[3], "const", i);
      }
    }
  }
  return symbols;
}

/** Nearest non-blank line above a definition, for documentation checks. */
function docLineFor(lines: string[], lineIdx: number): string | undefined {
  for (let i = lineIdx - 1; i >= 0; i--) {
    const t = lines[i].trim();
    if (t.length > 0) return t;
  }
  return undefined;
}

/** Heuristic: does the trimmed line above the definition look like docs (JSDoc / comment / docstring)? */
export function looksLikeDocs(trimmedPrevLine: string | undefined): boolean {
  if (!trimmedPrevLine) return false;
  const prefixes = ["/**", "/*", "//", "///", "#", '"""', "'''"];
  return prefixes.some((p) => trimmedPrevLine.startsWith(p));
}