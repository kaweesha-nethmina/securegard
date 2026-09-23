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
- **Local-first**: everything is stored in `.secuguard/db.json` inside your workspace. No code leaves your machine unless you explicitly enable AI triage — and even then only the flagged snippet is sent, not the file.

## Getting started

```bash
npm install
npm run build     # bundles src/extension.ts -> dist/extension.js
```

Then press **F5** in VS Code (with this folder open) to launch an Extension Development Host. Open the `test-corpus/` folder inside that host window and run **SecuGuard: Scan Workspace** from the Command Palette — it's pre-seeded with realistic vulnerable snippets so you'll see findings immediately.

### Enable optional AI triage

1. Set the `ANTHROPIC_API_KEY` environment variable (or change the env var name via `secuguard.ai.apiKeyEnvVar`).
2. Turn on `secuguard.ai.enabled` in Settings.
3. Click **Explain** or **Generate Fix** on any finding (CodeLens, Quick Fix, Tree View context menu, or the dashboard).

### Enable Semgrep for deeper coverage (optional)

```bash
pip install semgrep   # or: brew install semgrep
```
SecuGuard detects it automatically on the next scan — no configuration needed.

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
   Database    (.secuguard/db.json — status, notes, audit log, ignore rules)
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
- Swap `.secuguard/db.json` for SQLite if a workspace grows very large
