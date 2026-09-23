# SecuGuard — VS Code Security Vulnerability Detector

An embedded security QA engineer for VS Code: scans your workspace across languages, classifies findings by severity/CWE/OWASP, explains exploitability in plain English, and manages the full remediation lifecycle (save, TODO, suppress, fix, re-verify) — not just a one-shot report.

## What's inside

- **Zero-dependency built-in scan engine** (`src/scanners/patternScanner.ts`) — 25+ rules covering SQL/command/LDAP/NoSQL injection, XSS, insecure deserialization, weak crypto, insecure randomness, path traversal, SSRF, CORS misconfig, JWT `alg:none`, open redirect, ReDoS, and more. Works immediately, no external tools required.
- **Entropy-based secrets scanner** (`src/scanners/secretsScanner.ts`) — catches high-entropy hardcoded tokens/keys that plain regexes miss, using Shannon entropy scoring.
- **Optional Semgrep adapter** (`src/scanners/semgrepAdapter.ts`) — if `semgrep` is on your `PATH`, SecuGuard automatically layers in `p/security-audit` + `p/owasp-top-ten` for much broader multi-language coverage.
- **AI triage** (`src/ai/triageService.ts`, opt-in) — sends only the flagged snippet (never full files) to Claude for a contextual exploitability assessment, confidence score, and suggested fix. Prompt-injection-resistant: code is explicitly framed as data, not instructions.
- **Full VS Code UI**: Problems panel diagnostics, a "Security Explorer" tree view (Severity → File → Finding), inline CodeLens actions, hover explanations, Quick Fix actions (`Ctrl+.`), and an interactive HTML dashboard (charts, search, filters, inline status changes) — all built with a modern, VS Code–theme-aware design and zero external CDN dependencies.
- **Lifecycle management**: Save to backlog, insert a linked `// TODO(security): ...` comment, or suppress with a required reason (written to `.secuguard/ignore.yml` so the team can see *why*).
- **SARIF / Markdown / JSON export** for CI, GitHub/GitLab security tabs, or sharing with a team.
- **Local-first, team-shared**: everything is stored in `.secuguard/` — one small JSON file per finding (`findings/<id>.json`), plus `meta.json` and an append-only `audit-log.ndjson`. Commit the folder so teammates see the same findings and status history. No code leaves your machine unless you explicitly enable AI triage — and even then only the flagged snippet is sent, not the file.

## Getting started

```bash
npm install
npm run build     # bundles src/extension.ts -> dist/extension.js
```

Then press **F5** in VS Code (with this folder open) to launch an Extension Development Host. Open the `test-corpus/` folder inside that host window and run **SecuGuard: Scan Workspace** from the Command Palette — it's pre-seeded with realistic vulnerable snippets so you'll see findings immediately.

### Enable optional AI triage

AI triage is provider-swappable and is **free** by default via Google Gemini. Three providers are supported:

| Provider | Default model | Default env var | Get a key |
|---|---|---|---|
| **Gemini** (default, free tier) | `gemini-2.5-flash` | `GEMINI_API_KEY` | https://aistudio.google.com/apikey |
| **Groq** (free tier) | `llama-3.3-70b-versatile` | `GROQ_API_KEY` | https://console.groq.com/keys |
| **Anthropic** | `claude-sonnet-4-6` | `ANTHROPIC_API_KEY` | https://console.anthropic.com/ |

1. Set the API key for your chosen provider as an environment variable. The extension reads `process.env`, so export it in your shell (or in a VS Code `launch.json` `env` block for the Extension Development Host — a `.env` file is *not* auto-loaded).
2. Pick the provider: `secuguard.ai.provider` (`gemini`/`groq`/`anthropic`, default `gemini`). The env var defaults per provider unless you set `secuguard.ai.apiKeyEnvVar`.
3. Turn on `secuguard.ai.enabled` in Settings.
4. Click **Explain** or **Generate Fix** on any finding (CodeLens, Quick Fix, Tree View context menu, or the dashboard). Only the flagged snippet + minimal context is sent — never full files.

### Enable Semgrep for deeper coverage (optional)

```bash
pip install semgrep   # or: brew install semgrep
```
SecuGuard detects it automatically on the next scan — no configuration needed.

## Team workflow with git

`.secuguard/` is meant to be committed to your repository so every teammate shares the same vulnerability board (findings, status changes, and who made them).

```bash
git add .secuguard .gitattributes
git commit -m "chore(secuguard): track vulnerability findings"
```

**The loop:**

1. Scan / change status as usual (Status dropdown in the dashboard, **Explain**, **Generate Fix**, **Save to Backlog**, **Add as TODO**, **Mark False Positive**, **Mark Fixed**, or the tree-view context menu).
2. Every status change appends an entry to that finding's `statusHistory` (status, `@username`, timestamp, optional note) and is attributed to your GitHub username — resolved from `secuguard.attribution.githubUsername`, then the `gh` CLI, then `git config user.name` (shown as unverified), with a one-time prompt as a last resort. Change it anytime via **SecuGuard: Set GitHub Username**.
3. Commit the changed files: `git add .secuguard && git commit -m "fix(secuguard): triage SG-xxx as fixed"`.

**Rescans never lose your work.** Re-running *SecuGuard: Scan Workspace* is non-destructive: statuses, notes, assignees, and `statusHistory` are all preserved, findings that disappeared from the latest scan are kept (history stays verifiable), and only genuinely changed findings are rewritten. Two extra behaviors on rescan:

- **Regression detection** — if a finding you marked **fixed** is still detected by the next scan, SecuGuard automatically reopens it (`status: open`) and appends a `secuguard (auto)` history entry saying the vulnerability is still present.
- **Stale-code IDs** — if you edit the file so a vulnerability moves lines, that appears as a *new* finding (IDs are anchored to file+line+snippet), while the old one stays for the record.

The dashboard also has a **Status** filter (Active / All / per-status) so you can view **fixed**, suppressed, and won't-fix findings — not just the open backlog.

**Pulling teammates' updates:** after `git pull`, SecuGuard auto-watches `.secuguard/findings/` and refreshes; you can also run **SecuGuard: Reload Findings from Disk** to force it.

**Conflicts are scoped per finding.** Because each finding lives in its own file, two people editing *different* findings never conflict. The only conflict is when two people change the *same* finding's status in the same window — resolve it like any Git conflict: pick the file's version and keep both history entries if you like, then commit. The audit log uses `merge=union` (see `.gitattributes`), so concurrent appends merge line-by-line without conflict.

## Key commands

| Command | What it does |
|---|---|
| `SecuGuard: Scan Workspace` | Full scan across all scanners |
| `SecuGuard: Scan Current File` | Fast incremental scan (also runs automatically on save) |
| `SecuGuard: Open Dashboard` | Interactive charts, search/filter, inline status changes |
| `SecuGuard: Explain This Vulnerability` | Rule explanation, or AI-contextual triage if enabled |
| `SecuGuard: Generate Fix` | Rule-based remediation guidance, or AI-suggested fix |
| `SecuGuard: Save to Vulnerability List` | Marks as triaged/tracked |
| `SecuGuard: Add as TODO` | Inserts a linked `// TODO(security): [SG-xxxx] ...` comment |
| `SecuGuard: Mark False Positive` | Requires a reason; persisted to `.secuguard/ignore.yml` |
| `SecuGuard: Mark Fixed` | Attribute and record that a finding is fixed |
| `SecuGuard: Reload Findings from Disk` | Re-read `.secuguard/findings/` after a `git pull` (also auto-watched) |
| `SecuGuard: Set GitHub Username` | Change the username used to attribute status changes |
| `SecuGuard: Export Report` | SARIF / Markdown / JSON |

## Architecture

The detection engine (`Orchestrator` + `ScannerAdapter` interface) is intentionally decoupled from the VS Code API — every scanner just implements `scan(paths, root) -> RawFinding[]`. That means the same `src/engine` + `src/scanners` + `src/storage` code could be lifted into a headless CLI or CI action later without rewriting detection logic, exactly as recommended in the original project brief.

```
Orchestrator
 ├─ PatternScanner        (built-in, always available)
 ├─ SecretsScanner        (built-in, always available)
 └─ SemgrepAdapter        (optional, auto-detected)
        ↓
   Normalizer  (dedupes by file+line+rule, stable hash IDs, merges scanner names)
        ↓
   Database    (.secuguard/findings/<id>.json + meta.json + audit-log.ndjson)
        ↓
 Diagnostics / TreeView / CodeLens / Hover / CodeActions / Dashboard
```

## Extending the rule set

Add entries to `src/rules/rules.ts` — each rule is a regex + CWE/OWASP mapping + remediation string, scoped to one or more file extensions (or `"*"` for all languages). No build-system changes needed.

## Roadmap ideas (not yet implemented)

- Java/Go/Ruby/C# dedicated scanner adapters (SpotBugs+FindSecBugs, gosec, Brakeman, Security Code Scan) alongside the Semgrep fallback
- SCA / dependency scanning (OSV-Scanner, npm audit, pip-audit) as additional adapters
- IaC scanning (Checkov/tfsec) and container scanning (Trivy/Grype) adapters
- CI headless mode (`secuguard scan --fail-on critical`) by extracting `src/engine` + `src/scanners` into a standalone CLI package
- Swap the per-finding JSON files under `.secuguard/findings/` for SQLite if a workspace grows very large
