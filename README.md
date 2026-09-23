# SecuGuard

SecuGuard is a local-first security and QA assistant for VS Code. Scan a whole workspace or the current file, review findings in Security Explorer and the dashboard, optionally ask an AI provider for triage, generate tests for coverage gaps, and export reports for QA or security workflows.

## Features

- Workspace scanning and fast current-file scanning on demand or on save.
- Built-in security, secrets, quality, test-coverage, and documentation scanners.
- Optional Semgrep integration when Semgrep is installed on `PATH`.
- Security Explorer with severity filtering, status tracking, history, diagnostics, hover details, and code actions.
- Dashboard views for findings, QA health, trends, test coverage, documentation, and reports.
- Optional AI triage, fix suggestions, test generation, and executive report summaries.
- AI provider auto-detection from the API key prefix for Gemini, Groq, and Anthropic.
- Markdown, CSV, SARIF, JSON, and final Markdown/HTML QA report export.
- Findings and audit history stored locally in `.secuguard/`.

## Setup

1. Install dependencies and build the extension:

   ```bash
   npm install
   npm run build
   ```

2. Press `F5` in VS Code to launch an Extension Development Host, or install the packaged `.vsix`.
3. Open a workspace and run **SecuGuard: Scan Workspace** or **SecuGuard: Scan Current File**.
4. To enable AI features, set `secuguard.ai.enabled` to `true` and paste an API key into `secuguard.ai.apiKey` in user settings. The provider is auto-detected from the key prefix. Supported providers are Gemini, Groq, and Anthropic.
5. Optionally paste a second provider key into `secuguard.ai.fallbackApiKey` for quota failover. API key settings are application-scoped and cannot be overridden by a workspace.

## Commands

| Command | Purpose |
| --- | --- |
| SecuGuard: Scan Workspace | Scan the open workspace with enabled scanners. |
| SecuGuard: Scan Current File | Scan the active editor file. |
| SecuGuard: Open Dashboard | Open the interactive dashboard. |
| SecuGuard: Explain & Fix This Vulnerability | Show rule guidance and optional AI triage. |
| SecuGuard: Refresh AI Analysis | Re-run AI triage for a finding. |
| SecuGuard: Generate Test for Finding | Generate and review a test for a coverage finding. |
| SecuGuard: Generate All Missing Tests | Generate tests for all outstanding coverage findings. |
| SecuGuard: Generate Final QA Report | Export a consolidated QA report. |
| SecuGuard: Export Report | Export findings as Markdown, CSV, SARIF, or JSON. |
| SecuGuard: Save to Vulnerability List | Mark a finding as triaged/backlog. |
| SecuGuard: Add as TODO | Insert a security TODO beside a finding. |
| SecuGuard: Mark False Positive / Mark Fixed | Update finding status. |
| SecuGuard: Reload Findings from Disk | Reload local findings after external changes. |
| SecuGuard: Set GitHub Username | Set the identity used in status history. |
| SecuGuard: Refresh | Refresh the Security Explorer. |
| SecuGuard: Clear Baseline / Reset | Clear local findings and history. |

## Settings

All settings use the `secuguard.*` namespace.

| Setting | Default | Description |
| --- | --- | --- |
| `scanOnSave` | `true` | Scan the current file after it is saved. |
| `severityThreshold` | `low` | Minimum severity shown in diagnostics and Security Explorer. |
| `excludeGlobs` | Common build/dependency folders | Glob patterns excluded from scanning. |
| `useSemgrepIfAvailable` | `true` | Use a local Semgrep binary when available. |
| `ai.enabled` | `false` | Enable optional AI features. |
| `ai.provider` | `gemini` | Preferred AI provider when the key prefix is not detected. |
| `ai.apiKey` | Empty | Primary API key, stored in user settings only. |
| `ai.fallbackApiKey` | Empty | Fallback API key, stored in user settings only. |
| `ai.model` | `gemini-2.5-flash` | Optional model override for the primary provider. |
| `ai.fallbackProvider` | Empty | Provider used for quota failover when it cannot be inferred. |
| `ai.maxConcurrentCalls` | `2` | Maximum simultaneous AI calls during batch work. |
| `ai.testGenBatchSize` | `6` | Findings processed in each test-generation batch. |
| `quality.enabled` | `true` | Enable quality findings. |
| `quality.maxFunctionLines` | `80` | Maximum function length before a finding is raised. |
| `quality.maxNestingDepth` | `4` | Maximum nesting depth before a finding is raised. |
| `testCoverage.enabled` | `true` | Check exported symbols for matching tests. |
| `testCoverage.testFileGlobs` | Test filename globs | Patterns used to identify test files. |
| `docs.enabled` | `true` | Check exported symbols for documentation. |
| `attribution.githubUsername` | Empty | Username recorded for status changes when set. |
| `attribution.autoDetect` | `true` | Detect identity from `gh` or Git configuration. |
| `baselineOnFirstRun` | `true` | Treat first-scan findings as existing backlog. |

## Privacy & data

Scanning and finding storage are local. When AI is enabled, SecuGuard sends only the flagged code snippet plus minimal surrounding context to the chosen AI provider for the requested operation. It does not send full files or the workspace. When AI is disabled, nothing is sent to an AI provider. API keys are read from user settings only and are not read from environment variables or workspace settings.

## Development

```bash
npm install
npm run build
npm run compile-check
npm run package
```

The compiled extension entry point is `dist/extension.js`. The activity bar icon remains `resources/shield.svg`; the Marketplace package also includes `resources/icon.png`.

## License

MIT. See [LICENSE](LICENSE).