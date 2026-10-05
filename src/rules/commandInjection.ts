/**
 * CWE-78: OS command injection — AST + taint.
 *
 * Replaces the text rule `/(child_process\.exec\(|exec\(|...|`.*\$\{.*\}.*`)/`
 * which produced 279 findings in a real Node/Express codebase. Two independent
 * defects in that pattern caused it:
 *
 *   1. `exec(` matched ANY method named exec — `PATTERN.exec(input)` and
 *      `results.exec(cmd)` are not shell execution.
 *   2. `` `.*\$\{.*\}.*` `` matched every template literal containing one
 *      interpolation, so `` `cache:${tenantId}:v2` `` in a cache-key builder was
 *      reported as command injection. No shell sink existed in those files.
 *
 * A finding now requires BOTH:
 *   (a) the callee resolves to a real shell-executing API through imports and
 *       aliases (child_process.exec/execSync/execFile, shelljs, os.system), and
 *   (b) the command string carries a tainted value that has passed through no
 *       sanitizer.
 *
 * A constant command, a fully-interpolated template of constants, and a
 * `RegExp.exec()` call are all provably safe and are never reported.
 */

import * as t from "@babel/types";
import { FileContext, walkAst, isTestishPath } from "../analysis/context";
import { SecurityFinding, confidenceLabel, scoreSeverity } from "../analysis/finding";
import { resolveShellSink, isArgvSink, hasShellTrue, traceTaint, SANITIZERS } from "../analysis/taint";
import { collectConsts, Scope } from "../analysis/constants";
import { Severity } from "../types";

const RULE_ID = "sg-command-injection";
const SCANNER = "secuguard-taint-engine";

/** Functions that, when a tainted value is passed, are already safe. */
const SANITIZER_CALLS = SANITIZERS;

export function detectCommandInjection(ctx: FileContext): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const lines = ctx.lines;
  const imports = ctx.imports;

  // Bindings for identifiers assigned anywhere in scope (let/const/var), so
  // `const cmd = \`ls ${req.query.d}\`` is followed to its source.
  const bindings = new Map<string, t.Expression>();
  const moduleConsts = collectConsts(ctx.ast.program.body);

  walkAst(ctx.ast.program, (node) => {
    if (!t.isVariableDeclarator(node) || !t.isIdentifier(node.id) || !node.init) return;
    if (t.isCallExpression(node.init) || t.isAwaitExpression(node.init)) return; // call results are not raw data
    bindings.set(node.id.name, node.init);
  });

  walkAst(ctx.ast.program, (node) => {
    if (!t.isCallExpression(node)) return;
    const sink = resolveShellSink(node.callee, imports);
    if (!sink) return;

    const shellOpt = hasShellTrue(node);
    // execFile is only a shell sink with shell:true; argv form is safe.
    const isExecFile = /execFile/.test(sink.api);
    if (isExecFile && !shellOpt) return;

    // Try to find taint in any argument.
    let best:
      | { arg: t.Node; result: ReturnType<typeof traceTaint> }
      | undefined;
    for (const arg of node.arguments) {
      if (!t.isExpression(arg)) continue;
      if (t.isSpreadElement(arg)) continue;
      const result = traceTaint(arg, new Scope(moduleConsts), bindings, ctx.file);
      if (result.tainted && (!best || result.trace.length < best.result.trace.length)) {
        best = { arg, result };
      }
    }

    if (!best) return; // constant command: safe

    const trace = best.result.trace;
    const sinkLine = node.loc?.start.line ?? 0;
    const evidence = [
      ...trace,
      { kind: "sink" as const, line: sinkLine, label: `reaches ${sink.api}`, detail: sourceText(node) },
    ];

    const notes = [
      `resolved sink via import analysis: ${sink.api}`,
      `taint source: ${best.result.source?.label}`,
      `checked for sanitizers: ${SANITIZER_CALLS.map((s) => s.id).join(", ")} (none matched)`,
    ];
    if (ctx.recovered) notes.push("file had recoverable syntax errors — review column positions");

    const testish = isTestishPath(ctx.file);
    const confidence = testish ? 0.75 : 0.95;

    const { severity, rationale } = scoreSeverity({
      base: "critical",
      reachableFromHttp: trace.some((s) => /HTTP|route|body|query|params/i.test(s.label)),
      testish,
      confidence,
      guardCount: 0,
    });

    findings.push({
      ruleId: RULE_ID,
      title: "OS Command Injection",
      description:
        "Untrusted input reaches a shell command without sanitization. An attacker controlling this value can append additional commands, since the value is interpreted by a shell rather than passed as a discrete argument.",
      baseSeverity: "critical" as Severity,
      severity,
      cwe: ["CWE-78"],
      owasp: "A03:2021 - Injection",
      category: "sast",
      file: ctx.file,
      startLine: sinkLine,
      endLine: node.loc?.end.line ?? sinkLine,
      startCol: node.loc?.start.column,
      endCol: node.loc?.end.column,
      codeSnippet: snippet(lines, sinkLine),
      sourceScanner: SCANNER,
      remediation:
        "Avoid the shell entirely: pass an argv array (`execFile`/`spawn` with `shell:false`), and allow-list any value that must reach a command.",
      confidence,
      confidenceLabel: confidenceLabel(confidence),
      evidence,
      exploitability: `Attacker-controlled ${best.result.source?.label} is interpolated into a string executed by a shell. ${rationale}.`,
      falsePositiveNotes: notes,
      reachableFromHttp: evidence.some((e) => /HTTP|body|query|params|headers/i.test(e.label)),
      testish,
    });
  });

  return findings;
}

/**
 * Second pass: spawn/spawnSync/fork are argv-based and therefore NOT command
 * injection — but become dangerous when shell:true is set.
 */
export function detectShellTrueSpawn(ctx: FileContext): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  walkAst(ctx.ast.program, (node) => {
    if (!t.isCallExpression(node)) return;
    const sink = isArgvSink(node.callee, ctx.imports);
    if (!sink) return;
    if (!hasShellTrue(node)) return; // argv form without shell is safe

    // With shell:true the first argument is a command line, so it needs taint.
    const first = node.arguments[0];
    if (!first || !t.isExpression(first)) return;
    const bindings = new Map<string, t.Expression>();
    const moduleConsts = collectConsts(ctx.ast.program.body);
    const result = traceTaint(first, new Scope(moduleConsts), bindings, ctx.file);
    if (!result.tainted) return;

    const line = node.loc?.start.line ?? 0;
    const confidence = 0.9;
    const testish = isTestishPath(ctx.file);
    const reachableFromHttp = result.trace.some((s) => /HTTP|body|query|params/i.test(s.label));
    const { severity } = scoreSeverity({
      base: "high",
      reachableFromHttp,
      testish,
      confidence,
      guardCount: 0,
    });
    findings.push({
      ruleId: "sg-spawn-shell-taint",
      title: "Command injection via spawn with shell:true",
      description:
        "`spawn`/`spawnSync` with `shell:true` runs the first argument through a shell, which reintroduces command injection that the argv form normally prevents.",
      baseSeverity: "high",
      severity,
      cwe: ["CWE-78"],
      owasp: "A03:2021 - Injection",
      category: "sast",
      file: ctx.file,
      startLine: line,
      endLine: node.loc?.end.line ?? line,
      codeSnippet: snippet(ctx.lines, line),
      sourceScanner: SCANNER,
      remediation: "Drop `shell:true` and pass arguments as an array; the shell is not required to run the command.",
      confidence,
      confidenceLabel: confidenceLabel(confidence),
      evidence: [...result.trace, { kind: "sink", line, label: "reaches spawn with shell:true" }],
      exploitability: "Shell interpretation of attacker-influenced input.",
      falsePositiveNotes: [
        "confirmed argv API called with shell:true",
        "taint confirmed by backward walk from the first argument",
        `argv form without shell:true is not reported`,
      ],
      reachableFromHttp,
      testish,
    });
  });
  return findings;
}

function snippet(lines: string[], line: number): string {
  const start = Math.max(0, line - 2);
  const end = Math.min(lines.length, line + 1);
  return lines
    .slice(start, end)
    .map((l, i) => `${start + i + 1}| ${l}`)
    .join("\n");
}

function sourceText(node: t.CallExpression): string {
  const arg = node.arguments[0];
  if (!arg || !t.isExpression(arg)) return node.callee.type;
  const text = t.isStringLiteral(arg) ? arg.value : arg.type;
  return String(text).slice(0, 120);
}