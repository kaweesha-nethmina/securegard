# SecuGuard — Personal QA Engineer for VS Code

An embedded security + quality engineer for VS Code: scans your workspace for vulnerabilities *and* quality debt, explains exploitability in plain English, generates unit tests, drafts a pre-PR **QA Readiness Check**, and produces a consolidated **Final QA Report** — all local-first, dependency-free, and mindful of free-tier AI quotas.

## What's inside

### Security scanning (built-in)
- **Zero-dependency scan engine** (`src/scanners/patternScanner.ts`) — 25+ rules covering SQL/command/LDAP/NoSQL injection, XSS, insecure deserialization, weak crypto, insecure randomness, path traversal, SSRF, CORS misconfig, JWT `alg:none`, open redirect, ReDoS, and more.
- **Entropy-based secrets scanner** (`src/scanners/secretsScanner.ts`) — catches high-entropy hardcoded tokens/keys using Shannon entropy scoring.
- **Optional Semgrep adapter** (`src/scanners/semgrepAdapter.ts`) — layers `p/security-audit` + `p/owasp-top-ten` when `semgrep` is on your `PATH`.

### QA scanning (new)
- **Quality scanner** (`qualityScanner.ts`) — INFO/LOW findings for TODO/FIXME/HACK/XXX markers, oversized functions (> `secuguard.quality.maxFunctionLines`, default 80), deeply nested code (> `maxNestingDepth`, default 4), and leftover debug statements (`console.log`/`debugger`/`print`/`pdb.set_trace`).
- **Test-coverage scanner** (`testCoverageScanner.ts`) — for every exported symbol (JS/TS `export function/class/const`; Python top-level `def`/`class`), checks whether any test file (per `secuguard.testCoverage.testFileGlobs`) references it by name. Flags gaps as `.test-coverage` findings with effort ≈ *small*.
- **Doc scanner** (`docScanner.ts`) — flags exported symbols without a JSDoc/docstring above the definition (INFO, effort *trivial*).
- Each scanner has its own enabled setting (`secuguard.quality.enabled`, `secuguard.testCoverage.enabled`, `secuguard.docs.enabled`).

### AI (opt-in, provider-swappable, quota-resilient)
`src/ai/triageService.ts` talks to **Gemini**, **Groq**, or **Anthropic** with per-task token budgets and model hints:

| Task | Budget (tokens) | Gemini hint | Groq hint |
|---|---|---|---|
| `explain` / `classify` | 350 | `gemini-2.5-flash-lite` | `llama-3.3-70b-versatile` |
| `testGeneration` | 900 | `gemini-2.5-flash` | `llama-3.3-70b-versatile` |
| `reportSection` | 1200 | `gemini-2.5-flash` | `llama-3.3-70b-versatile` |

An explicit `secuguard.ai.model` **always wins** over the hints. Only the flagged snippet + minimal context is ever sent — never full files — and snippets are framed as *data, not instructions* to resist prompt injection.

**Gemini + Groq together (failover + batching):** if the primary provider returns a 429/quota error, SecuGuard retries once against `secuguard.ai.fallbackProvider` (automatic default: gemini→groq, groq→gemini; not used for anthropic). A one-time status-bar notice reports the fallback, and the audit log records `ai_triage (via groq, gemini quota exceeded)`. Batch generation is concurrency-limited by `secuguard.ai.maxConcurrentCalls` (default 2) so free tiers aren't hammered. "Refresh AI Analysis" is exposed in CodeLens, the dashboard, the tree, and the Explain & Fix panel.

## Getting started

```bash
npm install
npm run build     # bundles src/extension.ts -> dist/extension.js
```

Press **F5** in VS Code (with this folder open) to launch an Extension Development Host. Open the `test-corpus/` folder inside that host window and run **SecuGuard: Scan Workspace**.

### Enable optional AI (triage, tests, narrative)

| Provider | Model | Default env var | Key |
|---|---|---|---|
| **Gemini** (default, free tier) | `gemini-2.5-flash` | `GEMINI_API_KEY` | https://aistudio.google.com/apikey |
| **Groq** (free tier) | `llama-3.3-70b-versatile` | `GROQ_API_KEY` | https://console.groq.com/keys |
| **Anthropic** | `claude-sonnet-4-6` | `ANTHROPIC_API_KEY` | https://console.anthropic.com/ |

1. Set the API key(s) as environment variables. The extension reads `process.env`: export in your shell, or add to the project's `.env` — pressing **F5** auto-loads it via `envFile` in `.vscode/launch.json` (the file is gitignored).
2. Pick the primary provider (`secuguard.ai.provider`), optionally the fallback (`secuguard.ai.fallbackProvider`).
3. Turn on `secuguard.ai.enabled`.
4. Click **Explain & Fix** on any finding.

## The QA workflow

### 1. Scan → interactive dashboard
**SecuGuard: Open Dashboard** renders a single live webview shell: refreshing findings pushes a `data` message and the page swaps only the dynamic regions, so your tab, search, sort, filters, expanded rows and scroll position all survive a rescan or a status change.

- **Tabs** — **Overview** (clickable KPI cards, QA Health Score ring, severity donut, category bars, 14-day trend, quick actions), **Security**, **Quality**, **Test Coverage**, **Documentation**, **Reports**.
- **Interactions** — sort any column; click a row (or its chevron) to expand an inline detail panel with description, facts, AI insight + exploitability, line-numbered code, suggested fix and the full status timeline; click KPI cards, donut slices/legend or category bars to jump to a tab pre-filtered; multi-select severity chips; quality-debt sub-chips; live *x of y shown* counter; compact/comfortable density toggle; toasts; copy a finding, the filtered list or a QA snapshot as Markdown.
- **Keyboard** — `/` search, `Esc` clear, `1`–`6` tabs, `Enter` expand the focused finding, `d` density, `r` rescan, `?` shortcut help.
- The webview runs under a strict `Content-Security-Policy` with a per-panel script nonce; state persists via `setState`.

**QA Health Score** (0–100, tooltip explains the formula): starts at 100; −10 critical, −6 high, −3 medium, −1 low, −0.5 info; −3 oversized functions; −1 deep nesting/debug; −0.5 missing tests; −0.25 missing docs; clamped at 0.

### 2. QA Readiness Check (pre-PR gate)
**SecuGuard: QA Readiness Check** scans the **entire workspace** and gates on the **whole project's** QA state (not just the files being committed). It diffs your working tree against the base branch (`secuguard.readinessCheck.baseBranch`, default `main`, falling back to `git diff --name-only HEAD`) to show how many files this change touches, then reports a 5-row ✅/❌ checklist evaluated across all active findings:

1. No critical/high severity findings (project-wide)
2. No TODO/FIXME/HACK markers (project-wide)
3. Every exported symbol has a test (project-wide)
4. No debug statements (project-wide)
5. No functions past the max-lines threshold (project-wide)

A **Project-wide QA state** card shows per-category counts with an **Open QA Dashboard** shortcut, and **Copy as PR comment** produces a ready-to-paste GitHub/PR comment with the full checklist:

```
## 🛡 SecuGuard QA Readiness ❌ FAIL

**Base branch:** `main` · **Changed files:** 3 · Scan: 412ms

- ✅ No new critical/high severity findings (0)
- ❌ No new TODO/FIXME/HACK markers (1)
- ...

<details>
<summary>Details</summary>

### No new TODO/FIXME/HACK markers
- `src/auth.ts:42` — TODO marker left in code
```
The command also runs from the Command Palette, a button in the sidebar **Summary** tree, and a button in the readiness panel.

### 3. Unit tests, single or batch
- **SecuGuard: Generate Test for Finding** (🧪 button on test-coverage rows, code lens / tree) — drafts a test in a preview editor, then *Insert into file*. Style is matched from a nearby existing test when one exists.
- **SecuGuard: Generate All Missing Tests** — batches all test-coverage gaps (batch size `secuguard.ai.testGenBatchSize`, default 6), groups by source file, and runs with a cancellable progress notification (`Generating tests: batch X of Y (provider: gemini)`). Results land in the **test review webview**: edit any test inline, Accept / Skip per row, Accept All, then **Insert Accepted** writes each file (appending to an existing test file) and marks the finding triaged with a status-history note: `test generated by AI (<provider>), inserted by @<user>`.

### 4. Final QA report
**SecuGuard: Generate Final QA Report** (or the **Reports** tab) produces a deterministic consolidated report — Executive Summary, Security Findings, Quality Debt, Test Coverage Gaps, Documentation Gaps, Team Activity (from `statusHistory`), and a 5-point Sign-off checklist matching the readiness rows — with an **optional AI-written executive summary** (task `reportSection`) behind a checkbox. Exported as Markdown (`toFinalQaReport()`) and/or a self-contained HTML report (same theming, zero CDNs). Raw CSV / SARIF / JSON exports remain unchanged.

## Team workflow with git

`.secuguard/` is meant to be committed so every teammate shares the same board (findings, status, who changed them).

```bash
git add .secuguard .gitattributes
git commit -m "chore(secuguard): track findings"
```

- Every status change appends to that finding's `statusHistory` (status, `@username`, timestamp, note), attributed via `secuguard.attribution.githubUsername` → `gh` CLI → `git config user.name`.
- **Rescans are non-destructive** — status/notes/history survive. Regression-detection reopens a `fixed` finding if it reappears; a moved line becomes a new ID while the old record stays.
- After `git pull`, findings auto-reload; conflicts are scoped per finding (one JSON file each), and the audit log merges with `merge=union`.

## Key commands

| Command | What it does |
|---|---|
| `SecuGuard: Scan Workspace` | Full scan across all scanners |
| `SecuGuard: Scan Current File` | Fast incremental scan (also on save) |
| `SecuGuard: Open Dashboard` | Tabbed dashboard: Overview/Security/Quality/Test Coverage/Documentation/Reports |
| `SecuGuard: QA Readiness Check` | Pre-PR gate against the base branch + copy-as-PR-comment |
| `SecuGuard: Explain & Fix This Vulnerability` | Attack type + fix guide + AI triage (if enabled) |
| `SecuGuard: Refresh AI Analysis` | Re-run AI triage on an already-explained finding |
| `SecuGuard: Generate Test for Finding` | AI-draft a unit test, preview, insert |
| `SecuGuard: Generate All Missing Tests` | Batch-generate tests for every gap with a review panel |
| `SecuGuard: Generate Final QA Report` | Markdown + HTML consolidated report (optional AI summary) |
| `SecuGuard: Export Report` | Raw export — Markdown QA / CSV / SARIF / JSON |
| `SecuGuard: Save to Vulnerability List` / `Add as TODO` / `Mark False Positive` / `Mark Fixed` | Lifecycle management |
| `SecuGuard: Reload Findings from Disk` | Re-read `.secuguard/findings/` after `git pull` |
| `SecuGuard: Set GitHub Username` | Username used to attribute status changes |

## Settings

Key settings (all under `secuguard.*`): `quality.enabled`, `quality.maxFunctionLines` (80), `quality.maxNestingDepth` (4), `testCoverage.enabled`, `testCoverage.testFileGlobs` (`**/*.test.*`, `**/*.spec.*`, `**/test_*.py`, `**/__tests__/**`), `docs.enabled`, `readinessCheck.baseBranch` (`main`), `ai.enabled`, `ai.provider`, `ai.model`, `ai.fallbackProvider`, `ai.maxConcurrentCalls` (2), `ai.testGenBatchSize` (6), `ai.apiKeyEnvVar`, `scanOnSave`, `severityThreshold`, `excludeGlobs`, `useSemgrepIfAvailable`, `attribution.githubUsername`, `attribution.autoDetect`, `baselineOnFirstRun`.

## Architecture

Detection (`Orchestrator` + `ScannerAdapter`) is decoupled from the VS Code API — scanners just implement `scan(paths, root) -> RawFinding[]`, so the same `src/engine` + `src/scanners` + `src/storage` could run headless later.

```
Orchestrator
 ├─ PatternScanner         (security, always available)
 ├─ SecretsScanner         (entropy, always available)
 ├─ QualityScanner         (TODO/long/nesting/debug — gated by setting)
 ├─ TestCoverageScanner    (exported-symbol coverage — gated by setting)
 ├─ DocScanner             (missing docs — gated by setting)
 └─ SemgrepAdapter         (optional, auto-detected)
        ↓
   Normalizer  (dedupes by file+line+rule, stable hash IDs, merges scanner names)
        ↓
   Database    (.secuguard/findings/<id>.json + meta.json + audit-log.ndjson)
        ↓
 Diagnostics / TreeView (Category→Severity→File→Finding when mixed) / CodeLens /
 Hover / CodeActions / Dashboard / ReadinessPanel / TestReviewPanel
```

## Extending

- **Rules:** add entries to `src/rules/rules.ts` (regex + CWE/OWASP + remediation, scoped per extension or `"*"`).
- **Scanners:** implement `ScannerAdapter` (`isAvailable()` + `scan()`), then register in `src/extension.ts` behind a setting.

## Roadmap ideas (not yet implemented)

- Per-language adapters (SpotBugs/FindSecBugs, gosec, Brakeman, Security Code Scan)
- SCA / dependency scanning (OSV-Scanner, npm audit, pip-audit)
- IaC (Checkov/tfsec) and container (Trivy/Grype) adapters
- CI headless mode (`secuguard scan --fail-on critical`)
- SQLite backend if a workspace's `.secuguard/findings/` grows very large