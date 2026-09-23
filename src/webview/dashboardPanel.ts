import * as vscode from "vscode";
import { Vulnerability, Severity, SEVERITY_COLOR, SEVERITY_ORDER, FindingCategory } from "../types";
import { computeQaHealthScore, QA_HEALTH_SCORE_FORMULA } from "../utils/sarif";

/**
 * SecuGuard dashboard — a single webview that stays alive while findings change.
 *
 * The HTML shell (chrome, filters, keyboard handling, table behaviour) is rendered
 * once. Every later refresh is pushed as a `data` message and the webview swaps the
 * dynamic regions in place, so tab, search, sort, expanded rows and scroll position
 * all survive a rescan or a status change.
 */

/** Most-severe-first ordering used by the chips, counts and the severity donut. */
const SEVERITY_LIST: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Categories that represent a security finding — everything else is QA debt. */
const SECURITY_CATEGORIES = new Set<FindingCategory>(["sast", "sca", "secret", "iac", "container"]);

const CATEGORY_ICON: Record<string, string> = {
  sast: "🧨",
  sca: "📦",
  secret: "🔑",
  iac: "🧱",
  container: "🐳",
  quality: "🧹",
  "test-coverage": "🧪",
  documentation: "📖",
};

/** Chip definitions for the quality-debt sub-filter. */
const QUALITY_CHIPS: { id: string; label: string }[] = [
  { id: "all", label: "All quality" },
  { id: "sg-quality-todo", label: "TODO / FIXME / HACK" },
  { id: "sg-quality-long-function", label: "Oversized functions" },
  { id: "sg-quality-nesting", label: "Deep nesting" },
  { id: "sg-quality-debug", label: "Debug statements" },
];

interface DashboardModel {
  active: Vulnerability[];
  counts: Record<Severity, number>;
  security: Vulnerability[];
  quality: Vulnerability[];
  coverage: Vulnerability[];
  docs: Vulnerability[];
  categories: { name: string; count: number }[];
  qualityCounts: Record<string, number>;
  qaScore: number;
  trend: { day: string; count: number }[];
  tested: number;
  testedTotal: number;
}

interface DashboardPayload {
  type: "data";
  meta: { summaryHtml: string; qaScore: number; formula: string };
  sevChipsHtml: string;
  qualityChipsHtml: string;
  tabCounts: { security: number; quality: number; coverage: number; docs: number };
  sections: {
    overview: string;
    security: string;
    quality: string;
    coverage: string;
    docs: string;
    reports: string;
  };
}

export class DashboardPanel {
  static current: DashboardPanel | undefined;
  private panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];
  private readonly nonce = makeNonce();
  private vulns: Vulnerability[] = [];
  private ready = false;

  static show(
    context: vscode.ExtensionContext,
    getVulns: () => Vulnerability[],
    workspaceRoot: string,
    onMessage: (msg: any) => void
  ) {
    if (DashboardPanel.current) {
      DashboardPanel.current.panel.reveal();
      DashboardPanel.current.update(getVulns());
      return;
    }
    const panel = vscode.window.createWebviewPanel("secuguardDashboard", "SecuGuard Dashboard", vscode.ViewColumn.Active, {
      enableScripts: true,
      retainContextWhenHidden: true,
    });
    panel.iconPath = vscode.Uri.joinPath(context.extensionUri, "resources", "shield.svg");
    DashboardPanel.current = new DashboardPanel(panel, getVulns, workspaceRoot, onMessage);
  }

  static refreshIfOpen(vulns: Vulnerability[]) {
    DashboardPanel.current?.update(vulns);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    private getVulns: () => Vulnerability[],
    private workspaceRoot: string,
    onMessage: (msg: any) => void
  ) {
    this.panel = panel;
    // The shell is rendered exactly once; after that the page is never reloaded.
    panel.webview.html = renderShell(panel.webview, this.nonce);
    this.vulns = getVulns();
    panel.webview.onDidReceiveMessage(
      (msg) => {
        if (msg && msg.type === "ready") {
          this.ready = true;
          this.pushData();
          return;
        }
        onMessage(msg);
      },
      null,
      this.disposables
    );
    panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  update(vulns: Vulnerability[]) {
    this.vulns = vulns;
    if (this.ready) this.pushData();
  }

  private pushData() {
    void this.panel.webview.postMessage(buildPayload(this.vulns));
  }

  dispose() {
    DashboardPanel.current = undefined;
    this.disposables.forEach((d) => d.dispose());
    this.panel.dispose();
  }
}

function makeNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < 32; i++) out += chars.charAt(Math.floor(Math.random() * chars.length));
  return out;
}

function esc(s: string): string {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
}

/** Findings persisted by older builds (or hand-edited JSON) may miss optional arrays. */
function cweList(v: Vulnerability): string[] {
  return Array.isArray(v.cwe) ? v.cwe : [];
}

function statusLabel(v: Vulnerability): string {
  return String(v.status || "open").replace(/_/g, " ");
}

function formatWhen(iso: string): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

function riskClass(score: number): string {
  return score >= 85 ? "ok" : score >= 60 ? "warn" : "bad";
}

function riskLabel(score: number): string {
  return score >= 85 ? "Healthy" : score >= 60 ? "Needs attention" : "High risk";
}
function buildModel(vulns: Vulnerability[]): DashboardModel {
  const active = vulns.filter((v) => v.status !== "false_positive" && v.status !== "fixed" && v.status !== "wont_fix");
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of active) counts[v.severity]++;

  const security = active.filter((v) => SECURITY_CATEGORIES.has(v.category));
  const quality = active.filter((v) => v.category === "quality");
  const coverage = active.filter((v) => v.category === "test-coverage");
  const docs = active.filter((v) => v.category === "documentation");

  const categoryCounts: Record<string, number> = {};
  for (const v of active) categoryCounts[v.category] = (categoryCounts[v.category] || 0) + 1;
  const categories = Object.entries(categoryCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

  const qualityCounts: Record<string, number> = {};
  for (const q of quality) qualityCounts[q.ruleId] = (qualityCounts[q.ruleId] || 0) + 1;

  const today = new Date();
  const trend: { day: string; count: number }[] = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const day = d.toISOString().slice(0, 10);
    trend.push({ day, count: vulns.filter((v) => String(v.firstDetected || "").slice(0, 10) === day).length });
  }

  return {
    active,
    counts,
    security,
    quality,
    coverage,
    docs,
    categories,
    qualityCounts,
    qaScore: computeQaHealthScore(vulns),
    trend,
    tested: Math.max(0, active.length - coverage.length),
    testedTotal: active.length,
  };
}

function buildPayload(vulns: Vulnerability[]): DashboardPayload {
  const m = buildModel(vulns);
  const critHigh = m.counts.critical + m.counts.high;
  const risk = riskLabel(m.qaScore);
  const summaryHtml =
    `<b>${m.active.length}</b> active finding${m.active.length === 1 ? "" : "s"}` +
    `<span class="sep">·</span><b>${critHigh}</b> critical / high` +
    `<span class="sep">·</span>QA score <b>${m.qaScore}</b> <span class="risk ${riskClass(m.qaScore)}">${risk}</span>` +
    `<span class="sep">·</span>updated ${esc(new Date().toLocaleString())}`;

  return {
    type: "data",
    meta: { summaryHtml, qaScore: m.qaScore, formula: QA_HEALTH_SCORE_FORMULA },
    sevChipsHtml: renderSevChips(m),
    qualityChipsHtml: renderQualityChips(m),
    tabCounts: {
      security: m.security.length,
      quality: m.quality.length,
      coverage: m.coverage.length,
      docs: m.docs.length,
    },
    sections: {
      overview: renderOverview(m),
      security: listSection(m.security, {
        title: "No active security findings",
        hint: "Every SAST, dependency, secret, IaC and container check came back clean.",
        action: "rescan",
        actionLabel: "🔁 Scan workspace",
      }),
      quality: listSection(m.quality, {
        title: "No quality debt detected",
        hint: "No TODO markers, oversized functions, deep nesting or stray debug statements.",
      }),
      coverage: listSection(m.coverage, {
        title: "Every exported symbol has a test",
        hint: "The coverage scanner found a test file referencing each exported symbol.",
        action: "generateAllTests",
        actionLabel: "🧪 Re-check coverage",
      }),
      docs: listSection(m.docs, {
        title: "Every exported symbol is documented",
        hint: "No exported symbol is missing a JSDoc block or docstring.",
      }),
      reports: renderReports(m),
    },
  };
}

function renderSevChips(m: DashboardModel): string {
  const all = `<button class="chip" data-sev-clear="1">All<span class="chip-count">${m.active.length}</span></button>`;
  const chips = SEVERITY_LIST.map(
    (s) =>
      `<button class="chip" data-sev-toggle="${s}" data-tooltip="${esc(
        `${s} · ${m.counts[s]} finding${m.counts[s] === 1 ? "" : "s"}`
      )}"><span class="dot" style="background:${SEVERITY_COLOR[s]}"></span>${s}<span class="chip-count">${
        m.counts[s]
      }</span></button>`
  ).join("");
  return all + chips;
}

function renderQualityChips(m: DashboardModel): string {
  return QUALITY_CHIPS.map((c) => {
    const count = c.id === "all" ? m.quality.length : m.qualityCounts[c.id] || 0;
    return `<button class="chip" data-qtype="${esc(c.id)}">${esc(c.label)}<span class="chip-count">${count}</span></button>`;
  }).join("");
}
function renderOverview(m: DashboardModel): string {
  const kpis: { label: string; value: number; tab: string; sevs: string; tip: string; tone: string }[] = [
    {
      label: "Active findings",
      value: m.active.length,
      tab: "overview",
      sevs: "",
      tip: "Everything that is not marked fixed, false positive or won't fix.",
      tone: "neutral",
    },
    {
      label: "Critical / High",
      value: m.counts.critical + m.counts.high,
      tab: "security",
      sevs: "critical,high",
      tip: "Critical costs 10 points and high 6 points from the QA health score.",
      tone: "bad",
    },
    {
      label: "Security",
      value: m.security.length,
      tab: "security",
      sevs: "",
      tip: "SAST, dependency, secret, IaC and container findings.",
      tone: "warn",
    },
    {
      label: "Quality debt",
      value: m.quality.length,
      tab: "quality",
      sevs: "",
      tip: "TODO markers, oversized functions, deep nesting and debug statements.",
      tone: "info",
    },
    {
      label: "Missing tests",
      value: m.coverage.length,
      tab: "coverage",
      sevs: "",
      tip: "Exported symbols no test file references yet.",
      tone: "info",
    },
    {
      label: "Missing docs",
      value: m.docs.length,
      tab: "docs",
      sevs: "",
      tip: "Exported symbols without a JSDoc block or docstring.",
      tone: "info",
    },
  ];

  const kpiHtml = kpis
    .map(
      (k) => `<button class="stat kpi tone-${k.tone} tip" data-action="kpi" data-tab="${k.tab}" data-sevs="${k.sevs}"
      data-tooltip="${esc(k.tip)}" aria-label="${esc(`${k.label}: ${k.value}`)}">
      <span class="num" data-num="${esc(k.label)}" data-value="${k.value}">${k.value}</span>
      <span class="lbl">${esc(k.label)}</span>
    </button>`
    )
    .join("");

  const summarySrc = [
    `# SecuGuard QA snapshot`,
    ``,
    `- QA health score: **${m.qaScore}/100** (${riskLabel(m.qaScore)})`,
    `- Active findings: **${m.active.length}**`,
    `- Critical/High: **${m.counts.critical + m.counts.high}** (critical ${m.counts.critical}, high ${m.counts.high})`,
    `- Security: **${m.security.length}** · Quality debt: **${m.quality.length}** · Missing tests: **${m.coverage.length}** · Missing docs: **${m.docs.length}**`,
    `- Per category: ${m.categories.map((c) => `${c.name} ${c.count}`).join(", ") || "none"}`,
  ].join("\n");

  return `
  <div class="stat-row">${kpiHtml}</div>

  <div class="actions-row">
    <button class="btn primary tip" data-action="rescan" data-tooltip="Re-run a full workspace scan to refresh findings">🔁 Rescan workspace</button>
    <button class="btn tip" data-action="generateAllTests" data-tooltip="Draft unit tests for every exported symbol that has none">🧪 Generate all missing tests (${m.coverage.length})</button>
    <button class="btn" data-action="kpi" data-tab="reports">📄 Reports &amp; exports</button>
    <button class="btn tip" data-action="copySummary" data-tooltip="Copy a QA snapshot digest as Markdown">📋 Copy snapshot</button>
  </div>

  <div class="grid-top">
    <div class="card score-card">
      <h3>QA health score</h3>
      <div class="score-ring tip" data-tooltip="${esc(QA_HEALTH_SCORE_FORMULA)}">
        <svg viewBox="0 0 120 120" class="ring">
          <circle cx="60" cy="60" r="52" class="ring-track" />
          <circle cx="60" cy="60" r="52" class="ring-value" style="stroke-dashoffset:${(1 - m.qaScore / 100) * 326.7}" />
        </svg>
        <div class="score-center">
          <span class="score-num">${m.qaScore}</span>
          <span class="score-out">/ 100</span>
        </div>
      </div>
      <div class="score-foot risk ${riskClass(m.qaScore)}">${riskLabel(m.qaScore)}</div>
    </div>

    <div class="card">
      <h3>Findings by category <span class="hint">click to filter</span></h3>
      <div class="bars">
        ${m.categories
          .map(
            (c) =>
              `<button class="bar-row tip" data-bar-cat="${esc(c.name)}" data-tooltip="Show ${esc(c.name)} findings">
                 <span class="bar-label">${CATEGORY_ICON[c.name] || "•"} ${esc(c.name)}</span>
                 <span class="bar-track"><span class="bar-fill" style="width:${(c.count / (m.categories[0]?.count || 1)) * 100}%"></span></span>
                 <span class="bar-count">${c.count}</span>
               </button>`
          )
          .join("") || `<div class="muted">No findings to chart yet.</div>`}
      </div>
    </div>

    <div class="card">
      <h3>New findings — last 14 days</h3>
      ${renderTrend(m)}
    </div>
  </div>
  <div class="grid-bottom">
    <div class="card">
      <h3>Severity breakdown <span class="hint">click a slice or legend to filter</span></h3>
      ${renderDonut(m)}
    </div>

    <div class="card">
      <h3>Test coverage</h3>
      <div class="coverage">
        <div class="ratio">${m.testedTotal === 0 ? "100%" : `${Math.round((m.tested / m.testedTotal) * 100)}%`}</div>
        <div>
          <div class="coverage-line"><b>${m.tested}</b> of <b>${m.testedTotal}</b> active findings are not missing a test</div>
          <div class="muted">${m.coverage.length} exported symbol${m.coverage.length === 1 ? "" : "s"} still need coverage</div>
        </div>
        <button class="btn primary" data-action="generateAllTests">🧪 Generate (${m.coverage.length})</button>
      </div>
      <hr class="divider" />
      <h3>Quality debt mix</h3>
      <div class="bars">
        ${QUALITY_CHIPS.filter((c) => c.id !== "all")
          .map((c) => {
            const count = m.qualityCounts[c.id] || 0;
            return `<button class="bar-row tip" data-qtype-jump="${esc(c.id)}" data-tooltip="Jump to these findings">
              <span class="bar-label">${esc(c.label)}</span>
              <span class="bar-track"><span class="bar-fill" style="width:${m.quality.length ? (count / m.quality.length) * 100 : 0}%"></span></span>
              <span class="bar-count">${count}</span>
            </button>`;
          })
          .join("")}
      </div>
    </div>
  </div>

  <hr class="divider" />
  <h3>All active findings <span class="hint">${m.active.length} across every category</span></h3>
  ${listSection(m.active, {
    title: "No active findings",
    hint: "Every finding has been fixed, marked false positive or won't fix.",
    action: "rescan",
    actionLabel: "🔁 Scan workspace",
  })}

  <textarea class="copy-src" id="summarySrc" readonly hidden>${esc(summarySrc)}</textarea>
`;
}
function renderTrend(m: DashboardModel): string {
  const W = 580;
  const H = 120;
  const top = 14;
  const bottom = H - 22;
  const counts = m.trend.map((t) => t.count);
  const max = Math.max(1, ...counts);
  const x = (i: number) => (counts.length <= 1 ? W / 2 : (i / (counts.length - 1)) * W);
  const y = (c: number) => bottom - (c / max) * (bottom - top);
  const line = counts.map((c, i) => `${x(i).toFixed(1)},${y(c).toFixed(1)}`).join(" ");
  const area = `${x(0).toFixed(1)},${bottom} ${line} ${x(counts.length - 1).toFixed(1)},${bottom}`;
  const grid = [0, 0.5, 1]
    .map((f) => {
      const yy = bottom - f * (bottom - top);
      return `<line class="grid" x1="0" y1="${yy.toFixed(1)}" x2="${W}" y2="${yy.toFixed(1)}" />`;
    })
    .join("");
  const pts = counts
    .map(
      (c, i) =>
        `<circle class="pt" cx="${x(i).toFixed(1)}" cy="${y(c).toFixed(1)}" r="9" data-day="${esc(
          m.trend[i].day
        )}" data-count="${c}" />`
    )
    .join("");

  return `<div class="chart-wrap">
      <svg class="chart" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" height="120" aria-hidden="true">
        <defs>
          <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--accent)" stop-opacity="0.38" />
            <stop offset="100%" stop-color="var(--accent)" stop-opacity="0" />
          </linearGradient>
        </defs>
        ${grid}
        <polygon class="trend-area" points="${area}" fill="url(#trendGrad)" />
        <polyline class="trend-line" points="${line}" vector-effect="non-scaling-stroke" />
        ${pts}
      </svg>
      <div class="chart-tip" id="trendTip" hidden></div>
    </div>
    <div class="axis"><span>${esc(m.trend[0].day)}</span><span>peak ${max}/day</span><span>${esc(
      m.trend[m.trend.length - 1].day
    )}</span></div>`;
}

function renderDonut(m: DashboardModel): string {
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const total = m.active.length || 1;
  let offset = 0;
  const arcs = SEVERITY_LIST.filter((s) => m.counts[s] > 0)
    .map((s) => {
      const len = (m.counts[s] / total) * circumference;
      const dasharray = `${len} ${circumference - len}`;
      const dashoffset = -offset;
      offset += len;
      return `<circle class="arc" r="${radius}" cx="90" cy="90" fill="transparent" stroke="${SEVERITY_COLOR[s]}"
        stroke-width="26" stroke-dasharray="${dasharray}" stroke-dashoffset="${dashoffset}"
        transform="rotate(-90 90 90)" data-legend-sev="${s}" data-tooltip="${esc(
          `${s} · ${m.counts[s]} (${Math.round((m.counts[s] / total) * 100)}%)`
        )}" />`;
    })
    .join("\n");

  const legend = SEVERITY_LIST.map(
    (s) => `<button class="legend-item" data-legend-sev="${s}" ${m.counts[s] === 0 ? "disabled" : ""}>
        <span class="dot" style="background:${SEVERITY_COLOR[s]}"></span>
        <span class="legend-label">${s}</span>
        <span class="legend-count">${m.counts[s]}</span>
      </button>`
  ).join("");

  return `<div class="donut-wrap">
      <svg width="180" height="180" viewBox="0 0 180 180" class="donut">
        ${arcs || `<circle r="${radius}" cx="90" cy="90" fill="transparent" stroke="var(--border)" stroke-width="26" />`}
        <text x="90" y="86" text-anchor="middle" font-size="26" font-weight="700" fill="var(--fg)">${m.active.length}</text>
        <text x="90" y="104" text-anchor="middle" font-size="10" fill="var(--muted)">FINDINGS</text>
      </svg>
      <div class="legend">${legend}</div>
    </div>`;
}
function renderReports(m: DashboardModel): string {
  const rows: [string, string][] = [
    ["Active findings", String(m.active.length)],
    ["Critical", String(m.counts.critical)],
    ["High", String(m.counts.high)],
    ["Medium", String(m.counts.medium)],
    ["Low", String(m.counts.low)],
    ["Info", String(m.counts.info)],
    ["Security", String(m.security.length)],
    ["Quality debt", String(m.quality.length)],
    ["Missing tests", String(m.coverage.length)],
    ["Missing docs", String(m.docs.length)],
    ["QA health score", `${m.qaScore}/100`],
  ];
  const cells = rows
    .map(([label, value]) => `<div class="snap-cell"><span class="snap-lbl">${esc(label)}</span><span class="snap-num">${esc(value)}</span></div>`)
    .join("");

  return `<div class="card">
      <h3>Current snapshot <span class="hint">what a generated report contains right now</span></h3>
      <div class="snap-grid">${cells}</div>
      <div class="muted" style="margin-top:12px">Reports are written locally (Markdown + self-contained HTML) and never leave your machine.</div>
    </div>`;
}

function listSection(
  list: Vulnerability[],
  empty: { title: string; hint: string; action?: string; actionLabel?: string }
): string {
  if (list.length === 0) {
    return `<div class="empty-state">
        <div class="empty-icon">✅</div>
        <div class="empty-title">${empty.title}</div>
        <div class="empty-hint">${empty.hint}</div>
        ${empty.action ? `<button class="btn primary" data-action="${empty.action}">${empty.actionLabel || "Run"}</button>` : ""}
      </div>`;
  }
  return `<div class="table-wrap">${tableFor(list)}</div>`;
}
function tableFor(list: Vulnerability[]): string {
  const sorted = [...list].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.file.localeCompare(b.file) ||
      a.startLine - b.startLine
  );

  return `<table class="findings">
    <thead><tr>
      <th class="sortable" data-key="severity" style="width:112px">Severity<span class="sort-ind"></span></th>
      <th class="sortable" data-key="title">Finding<span class="sort-ind"></span></th>
      <th class="sortable" data-key="location" style="width:220px">Location<span class="sort-ind"></span></th>
      <th class="sortable" data-key="category" style="width:150px">Category<span class="sort-ind"></span></th>
      <th class="sortable" data-key="status" style="width:296px">Status &amp; actions<span class="sort-ind"></span></th>
      <th style="width:34px"></th>
    </tr></thead>
    <tbody>${sorted.map(findingRow).join("\n")}</tbody>
  </table>`;
}

function findingRow(v: Vulnerability): string {
  const cwe = cweList(v);
  const search = [v.title, v.file, cwe.join(" "), v.category, v.owasp || "", v.ruleId, v.language]
    .join(" ")
    .toLowerCase();
  return `<tr class="finding-row" tabindex="0" data-id="${esc(v.id)}" data-severity="${v.severity}"
      data-sev-rank="${SEVERITY_ORDER[v.severity]}" data-category="${v.category}" data-status="${esc(statusLabel(v))}"
      data-quality-type="${esc(v.ruleId)}" data-title="${esc(v.title)}" data-file="${esc(v.file)}"
      data-line="${v.startLine}" data-search="${esc(search)}">
    <td><span class="badge sev-${v.severity}">${v.severity}</span></td>
    <td class="title-cell">
      <div class="finding-title">${esc(v.title)}</div>
      <div class="finding-meta">${esc(cwe.join(", ") || "no CWE")}${v.owasp ? " · " + esc(v.owasp) : ""}${
    v.effort ? " · effort: " + esc(v.effort) : ""
  }</div>
    </td>
    <td class="mono">${esc(v.file)}:${v.startLine}</td>
    <td><span class="cat-tag">${CATEGORY_ICON[v.category] || "•"} ${esc(v.category)}</span></td>
    <td class="actions-cell">${statusCell(v)}</td>
    <td class="chev-cell"><button class="chev-btn tip" data-action="toggle" data-id="${esc(
      v.id
    )}" data-tooltip="Show details"><span class="chev">▸</span></button></td>
  </tr>
${detailRow(v)}`;
}

function statusCell(v: Vulnerability): string {
  const options = ["open", "triaged", "todo", "false_positive", "wont_fix", "fixed"]
    .map((s) => `<option value="${s}" ${s === v.status ? "selected" : ""}>${s.replace("_", " ")}</option>`)
    .join("");
  return `<select class="status-select tip" data-id="${esc(v.id)}" data-tooltip="Change the status of this finding">${options}</select>
    <button class="icon-btn tip" data-action="open" data-id="${esc(v.id)}" data-tooltip="Open in editor">↗</button>
    <button class="icon-btn tip" data-action="explain" data-id="${esc(v.id)}" data-tooltip="Explain &amp; fix — attack info, AI triage, fix guide">🧠</button>
    ${
      v.aiExplanation
        ? `<button class="icon-btn tip" data-action="refreshAi" data-id="${esc(v.id)}" data-tooltip="Re-run AI analysis">🔄</button>`
        : ""
    }
    ${
      v.category === "test-coverage"
        ? `<button class="icon-btn tip" data-action="generateTest" data-id="${esc(
            v.id
          )}" data-tooltip="Generate a unit test for this symbol">🧪</button>`
        : ""
    }
    <button class="icon-btn tip" data-action="showHistory" data-id="${esc(v.id)}" data-tooltip="View status history">🕘</button>`;
}

function snippetWithLineNumbers(v: Vulnerability): string {
  const raw = (v.codeSnippet || "").replace(/\s+$/, "");
  if (!raw.trim()) return "(no snippet captured for this finding)";
  const start = v.startLine || 1;
  return raw
    .split(/\r?\n/)
    .map((l, i) => `${String(start + i).padStart(4, " ")} │ ${l}`)
    .join("\n");
}

function findingMarkdown(v: Vulnerability): string {
  const cwe = cweList(v);
  const bits: string[] = [
    `- **[${String(v.severity || "info").toUpperCase()}] ${v.title}**`,
    `  - Location: \`${v.file}:${v.startLine}\``,
    `  - Category: ${v.category} · Rule: \`${v.ruleId}\` · Scanner: ${v.sourceScanner} · Status: ${statusLabel(v)}`,
  ];
  if (cwe.length || v.owasp) bits.push(`  - CWE: ${cwe.join(", ") || "—"}${v.owasp ? ` · ${v.owasp}` : ""}`);
  if (v.cvss !== undefined) bits.push(`  - CVSS: ${v.cvss}`);
  if (v.effort) bits.push(`  - Effort: ${v.effort}`);
  return bits.join("\n");
}
function detailRow(v: Vulnerability): string {
  const blocks: string[] = [];

  blocks.push(
    `<div class="detail-block span2">
       <h4>Description</h4>
       <p>${esc(v.description || "No description provided by the scanner.")}</p>
     </div>`
  );

  const facts: [string, string][] = [
    ["Rule", v.ruleId],
    ["Scanner", v.sourceScanner],
    ["Language", v.language],
    ["CWE", cweList(v).join(", ") || "—"],
    ["OWASP", v.owasp || "—"],
    ["CVSS", v.cvss !== undefined ? String(v.cvss) : "—"],
    ["Effort", v.effort || "—"],
    ["First seen", formatWhen(v.firstDetected)],
    ["Last seen", formatWhen(v.lastSeen)],
    ["Assignee", v.assignee || "—"],
    ["Baseline", v.baseline ? "yes" : "no"],
    ["Status", statusLabel(v)],
  ];
  blocks.push(
    `<div class="detail-block">
       <h4>Facts</h4>
       <dl class="facts">${facts
         .map(([k, val]) => `<div><dt>${esc(k)}</dt><dd>${esc(val)}</dd></div>`)
         .join("")}</dl>
     </div>`
  );

  if (v.aiExplanation) {
    blocks.push(
      `<div class="detail-block">
         <h4>AI insight${
           v.aiConfidence !== undefined ? ` <span class="pill">confidence ${Math.round(v.aiConfidence * 100)}%</span>` : ""
         }</h4>
         <p>${esc(v.aiExplanation)}</p>
         ${
           v.aiExploitability
             ? `<p class="exploit"><span class="tag-label">Exploitability</span> ${esc(v.aiExploitability)}</p>`
             : ""
         }
       </div>`
    );
  } else {
    blocks.push(
      `<div class="detail-block muted">
         <h4>AI insight</h4>
         <p>No AI insight yet — run <b>Explain &amp; Fix</b> to generate triage notes for this finding.</p>
       </div>`
    );
  }

  blocks.push(
    `<div class="detail-block span2">
       <h4>Code</h4>
       <pre class="code">${esc(snippetWithLineNumbers(v))}</pre>
     </div>`
  );

  if (v.suggestedFix) {
    blocks.push(
      `<div class="detail-block span2">
         <h4>Suggested fix</h4>
         <pre class="code">${esc(v.suggestedFix)}</pre>
       </div>`
    );
  }

  const history =
    v.statusHistory && v.statusHistory.length
      ? `<ol class="timeline">${v.statusHistory
          .map(
            (h) =>
              `<li><span class="tl-dot"></span><div>
                 <div class="tl-status">${esc(String(h.status || "unknown").replace(/_/g, " "))}</div>
                 <div class="tl-meta">${esc(h.changedBy || "unknown")}${h.changedAt ? " · " + esc(formatWhen(h.changedAt)) : ""}${
                h.note ? " · " + esc(h.note) : ""
              }</div>
               </div></li>`
          )
          .join("")}</ol>`
      : `<div class="muted">No status changes recorded yet.</div>`;
  blocks.push(`<div class="detail-block span2"><h4>Status history</h4>${history}</div>`);

  const openBtn = `<button class="btn" data-action="open" data-id="${esc(v.id)}">↗ Open in editor</button>`;
  const explainBtn = `<button class="btn" data-action="explain" data-id="${esc(v.id)}">🧠 Explain &amp; Fix</button>`;
  const refreshBtn = v.aiExplanation
    ? `<button class="btn" data-action="refreshAi" data-id="${esc(v.id)}">🔄 Refresh AI</button>`
    : "";
  const testBtn =
    v.category === "test-coverage"
      ? `<button class="btn" data-action="generateTest" data-id="${esc(v.id)}">🧪 Generate test</button>`
      : "";
  const historyBtn = `<button class="btn" data-action="showHistory" data-id="${esc(v.id)}">🕘 History picker</button>`;
  const copyBtn = `<button class="btn tip" data-action="copyFinding" data-id="${esc(
    v.id
  )}" data-tooltip="Copy this finding as Markdown">📋 Copy as Markdown</button>`;

  return `<tr class="detail-row" data-parent="${esc(v.id)}">
    <td colspan="6">
      <div class="detail">
        <div class="detail-grid">${blocks.join("")}</div>
        <div class="detail-foot">${openBtn}${explainBtn}${refreshBtn}${testBtn}${historyBtn}${copyBtn}</div>
        <textarea class="copy-src" readonly hidden>${esc(findingMarkdown(v))}</textarea>
      </div>
    </td>
  </tr>`;
}

function renderShell(webview: vscode.Webview, nonce: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${webview.cspSource} data:;" />
<title>SecuGuard Dashboard</title>
<style>
  :root {
    --bg: var(--vscode-editor-background);
    --fg: var(--vscode-editor-foreground);
    --card: var(--vscode-sideBar-background, #1e1e1e);
    --card-2: color-mix(in srgb, var(--vscode-sideBar-background, #1e1e1e) 55%, var(--vscode-editor-background));
    --border: var(--vscode-panel-border, #3a3a3a);
    --border-soft: color-mix(in srgb, var(--border) 60%, transparent);
    --accent: var(--vscode-focusBorder, #4da3ff);
    --muted: var(--vscode-descriptionForeground, #9aa0a6);
    --ok: #3fb950;
    --warn: #e3b341;
    --bad: #f85149;
    --radius: 12px;
    --radius-sm: 8px;
    --shadow: 0 8px 26px rgba(0, 0, 0, .30);
    --shadow-sm: 0 3px 12px rgba(0, 0, 0, .20);
    --mono: var(--vscode-editor-font-family, ui-monospace, SFMono-Regular, Menlo, monospace);
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, sans-serif);
    font-size: var(--vscode-font-size, 13px);
    background:
      radial-gradient(1200px 340px at 12% -8%, color-mix(in srgb, var(--accent) 12%, transparent), transparent 70%),
      var(--bg);
    color: var(--fg);
    margin: 0;
    padding: 0;
  }
  .page { padding: 18px 22px 70px; max-width: 1560px; margin: 0 auto; }
  h1 { font-size: 19px; margin: 0; letter-spacing: -.01em; }
  h3 { margin: 0 0 10px; font-size: 11.5px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
  h4 { margin: 0 0 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
  .mono { font-family: var(--mono); font-size: 11.5px; color: var(--muted); }
  .muted { color: var(--muted); font-size: 12px; }
  .hint { color: var(--muted); font-weight: 400; text-transform: none; letter-spacing: 0; opacity: .8; }
  .sep { color: var(--muted); margin: 0 7px; opacity: .45; }
  :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 6px; }

  /* ---------- header ---------- */
  .topbar { display: flex; align-items: center; justify-content: space-between; gap: 18px; flex-wrap: wrap; margin-bottom: 16px; }
  .brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
  .shield {
    display: grid; place-items: center; width: 40px; height: 40px; border-radius: 12px; font-size: 20px; flex: none;
    background: linear-gradient(145deg, color-mix(in srgb, var(--accent) 32%, transparent), color-mix(in srgb, var(--accent) 5%, transparent));
    border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
    box-shadow: var(--shadow-sm);
  }
  .meta { color: var(--muted); font-size: 12px; margin-top: 3px; }
  .meta b { color: var(--fg); }
  .risk { font-weight: 700; padding: 1px 8px; border-radius: 20px; font-size: 10.5px; }
  .risk.ok { color: var(--ok); background: color-mix(in srgb, var(--ok) 16%, transparent); }
  .risk.warn { color: var(--warn); background: color-mix(in srgb, var(--warn) 16%, transparent); }
  .risk.bad { color: var(--bad); background: color-mix(in srgb, var(--bad) 16%, transparent); }
  .top-actions { display: flex; align-items: center; gap: 8px; }

  /* ---------- buttons ---------- */
  .btn, .ghost-btn {
    font: inherit; font-size: 12px; cursor: pointer; border-radius: var(--radius-sm);
    border: 1px solid var(--border); background: var(--card); color: var(--fg);
    padding: 7px 12px; transition: transform .12s ease, border-color .12s ease, box-shadow .12s ease;
  }
  .btn:hover, .ghost-btn:hover { border-color: color-mix(in srgb, var(--accent) 60%, var(--border)); box-shadow: var(--shadow-sm); }
  .btn:active, .ghost-btn:active { transform: translateY(1px); }
  .btn.primary {
    border-color: color-mix(in srgb, var(--accent) 70%, transparent);
    background: linear-gradient(180deg, color-mix(in srgb, var(--accent) 26%, var(--card)), var(--card));
  }
  .ghost-btn { background: transparent; color: var(--muted); padding: 6px 10px; }
  .ghost-btn:hover { color: var(--fg); }
  .ghost-btn[hidden] { display: none; }
  /* ---------- sticky chrome ---------- */
  .stick {
    position: sticky; top: 0; z-index: 6; margin: 0 -22px 18px; padding: 0 22px;
    background: color-mix(in srgb, var(--bg) 90%, transparent);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--border-soft);
  }
  .tabs { display: flex; gap: 2px; flex-wrap: wrap; }
  .tab {
    background: transparent; border: none; border-bottom: 2px solid transparent; color: var(--muted);
    padding: 10px 13px; font: inherit; font-size: 12.5px; font-weight: 600; cursor: pointer;
    transition: color .12s ease, border-color .12s ease;
  }
  .tab:hover { color: var(--fg); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab .badge-tab {
    background: var(--border); border-radius: 12px; padding: 0 7px; font-size: 10px; margin-left: 6px;
    display: inline-block; min-width: 18px; text-align: center;
  }
  .tab.active .badge-tab { background: var(--accent); color: #06121f; }

  .filterbar { display: flex; flex-direction: column; gap: 8px; padding: 10px 0 12px; }
  .filterbar[hidden] { display: none; }
  .filter-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .search-wrap { position: relative; display: flex; align-items: center; }
  .search-icon { position: absolute; left: 9px; font-size: 11px; opacity: .7; pointer-events: none; }
  input[type=text] {
    background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: var(--radius-sm);
    padding: 7px 10px 7px 28px; font: inherit; font-size: 12.5px; min-width: 290px;
    transition: border-color .12s ease, box-shadow .12s ease;
  }
  input[type=text]:focus { border-color: var(--accent); outline: none; box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent); }
  select.filter {
    background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: var(--radius-sm);
    padding: 7px 10px; font: inherit; font-size: 12px; cursor: pointer;
  }
  .result-count { color: var(--muted); font-size: 12px; }
  .result-count b { color: var(--fg); }

  .chip-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
  .chip-row[hidden] { display: none; }
  .chip-group-label { font-size: 10.5px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); margin-right: 4px; }
  .chip-inline { display: inline-flex; gap: 6px; flex-wrap: wrap; }
  .chip {
    display: inline-flex; align-items: center; gap: 6px;
    background: var(--card); color: var(--muted); border: 1px solid var(--border); border-radius: 20px;
    padding: 4px 11px; font: inherit; font-size: 11.5px; cursor: pointer;
    transition: color .12s ease, border-color .12s ease, background .12s ease, transform .12s ease;
  }
  .chip:hover { color: var(--fg); transform: translateY(-1px); }
  .chip.active { color: var(--accent); border-color: var(--accent); background: color-mix(in srgb, var(--accent) 12%, var(--card)); }
  .chip-count { font-size: 10px; opacity: .85; background: var(--border); border-radius: 10px; padding: 0 6px; }
  .chip.active .chip-count { background: color-mix(in srgb, var(--accent) 35%, transparent); }
  .chip.is-empty { opacity: .4; }
  .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex: none; }
  /* ---------- cards & stats ---------- */
  .card {
    background: linear-gradient(180deg, color-mix(in srgb, var(--card) 92%, var(--bg)), var(--card));
    border: 1px solid var(--border); border-radius: var(--radius);
    padding: 16px; position: relative; overflow: hidden;
    transition: transform .16s ease, box-shadow .16s ease, border-color .16s ease;
  }
  .card:hover { box-shadow: var(--shadow); border-color: color-mix(in srgb, var(--accent) 26%, var(--border)); }
  .card::before {
    content: ""; position: absolute; inset: 0 0 auto; height: 1px;
    background: linear-gradient(90deg, transparent, color-mix(in srgb, var(--accent) 45%, transparent), transparent);
    opacity: .7;
  }
  .stat-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; margin-bottom: 16px; }
  .stat {
    font: inherit; text-align: left; cursor: pointer; border-radius: var(--radius);
    background: var(--card-2); border: 1px solid var(--border); padding: 12px 14px;
    display: flex; flex-direction: column; gap: 2px;
    transition: transform .14s ease, border-color .14s ease, box-shadow .14s ease;
  }
  .stat:hover { transform: translateY(-2px); box-shadow: var(--shadow-sm); }
  .stat .num { font-size: 24px; font-weight: 750; letter-spacing: -.02em; font-variant-numeric: tabular-nums; }
  .stat .lbl { font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
  .stat.tone-bad { border-left: 3px solid var(--bad); }
  .stat.tone-warn { border-left: 3px solid var(--warn); }
  .stat.tone-info { border-left: 3px solid var(--accent); }
  .stat.tone-neutral { border-left: 3px solid var(--muted); }
  .stat.tone-bad .num { color: var(--bad); }
  .stat.tone-warn .num { color: var(--warn); }

  .actions-row { display: flex; gap: 8px; margin: 0 0 18px; flex-wrap: wrap; }

  .grid-top { display: grid; grid-template-columns: 230px minmax(280px, 1fr) minmax(320px, 1.15fr); gap: 14px; margin-bottom: 14px; }
  .grid-bottom { display: grid; grid-template-columns: minmax(320px, 1fr) minmax(320px, 1fr); gap: 14px; }
  @media (max-width: 1080px) {
    .grid-top, .grid-bottom { grid-template-columns: 1fr; }
  }

  /* ---------- QA score ring ---------- */
  .score-card { display: flex; flex-direction: column; align-items: center; }
  .score-card h3 { align-self: flex-start; }
  .score-ring { position: relative; width: 132px; height: 132px; }
  .score-ring .ring { width: 100%; height: 100%; transform: rotate(-90deg); }
  .ring-track { fill: none; stroke: var(--border); stroke-width: 9; }
  .ring-value {
    fill: none; stroke: var(--accent); stroke-width: 9; stroke-linecap: round;
    stroke-dasharray: 326.7; transition: stroke-dashoffset .7s cubic-bezier(.22,.7,.3,1);
  }
  .score-center { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }
  .score-num { font-size: 32px; font-weight: 800; line-height: 1; font-variant-numeric: tabular-nums; }
  .score-out { font-size: 10.5px; color: var(--muted); }
  .score-foot { margin-top: 10px; font-size: 11.5px; }

  /* ---------- bars ---------- */
  .bars { display: flex; flex-direction: column; gap: 7px; }
  .bar-row {
    display: grid; grid-template-columns: 148px 1fr 34px; align-items: center; gap: 10px;
    background: none; border: none; padding: 3px 4px; border-radius: var(--radius-sm);
    font: inherit; font-size: 12px; color: var(--fg); cursor: pointer; text-align: left;
    transition: background .12s ease;
  }
  .bar-row:hover { background: var(--card-2); }
  .bar-label { color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { height: 9px; background: color-mix(in srgb, var(--border) 70%, transparent); border-radius: 6px; overflow: hidden; }
  .bar-fill {
    display: block; height: 100%; border-radius: 6px;
    background: linear-gradient(90deg, color-mix(in srgb, var(--accent) 65%, transparent), var(--accent));
    transition: width .5s cubic-bezier(.22,.7,.3,1);
  }
  .bar-count { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
  /* ---------- trend chart ---------- */
  .chart-wrap { position: relative; }
  .chart { width: 100%; display: block; overflow: visible; }
  .chart .grid { stroke: var(--border); stroke-width: 1; opacity: .55; vector-effect: non-scaling-stroke; }
  .trend-line { stroke: var(--accent); stroke-width: 2.2; stroke-linejoin: round; stroke-linecap: round; }
  .chart .pt { fill: transparent; cursor: crosshair; transition: fill .12s ease; }
  .chart .pt:hover { fill: color-mix(in srgb, var(--accent) 55%, transparent); }
  .chart-tip {
    position: absolute; transform: translate(-50%, -135%); pointer-events: none; z-index: 4;
    background: var(--vscode-editorWidget-background, #252526); color: var(--vscode-editorWidget-foreground, #ccc);
    border: 1px solid var(--vscode-widget-border, #454545); border-radius: 7px;
    padding: 4px 9px; font-size: 11px; white-space: nowrap; box-shadow: var(--shadow-sm);
    display: flex; flex-direction: column; gap: 1px;
  }
  .axis { display: flex; justify-content: space-between; font-size: 10px; color: var(--muted); margin-top: 4px; }

  /* ---------- donut ---------- */
  .donut-wrap { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }
  .donut { animation: pop .4s cubic-bezier(.22,.7,.3,1); flex: none; }
  .donut .arc { cursor: pointer; transition: opacity .14s ease, stroke-width .14s ease; }
  .donut .arc:hover { stroke-width: 32; }
  .donut-wrap:hover .arc { opacity: .5; }
  .donut-wrap .arc:hover { opacity: 1; }
  .legend { display: flex; flex-direction: column; gap: 2px; min-width: 172px; }
  .legend-item {
    display: grid; grid-template-columns: 14px 1fr auto; align-items: center; gap: 8px;
    background: none; border: none; font: inherit; font-size: 12px; color: var(--fg);
    padding: 4px 6px; border-radius: 6px; cursor: pointer; text-align: left;
    transition: background .12s ease, opacity .12s ease;
  }
  .legend-item:hover { background: var(--card-2); }
  .legend-item:disabled { opacity: .38; cursor: default; }
  .legend-label { text-transform: capitalize; }
  .legend-count { color: var(--muted); font-variant-numeric: tabular-nums; }
  @keyframes pop { from { opacity: 0; transform: scale(.94); } to { opacity: 1; transform: none; } }
  /* ---------- tables ---------- */
  .table-wrap { border: 1px solid var(--border); border-radius: var(--radius); overflow: auto; background: var(--card-2); }
  table.findings { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  table.findings th {
    text-align: left; padding: 9px 12px; color: var(--muted); font-weight: 700; font-size: 10.5px;
    text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid var(--border);
    position: sticky; top: 0; background: var(--card); z-index: 2; white-space: nowrap;
  }
  table.findings th.sortable { cursor: pointer; user-select: none; }
  table.findings th.sortable:hover { color: var(--fg); }
  .sort-ind { margin-left: 5px; opacity: .5; font-size: 9px; }
  th.sorted .sort-ind { opacity: 1; color: var(--accent); }
  table.findings td { padding: var(--row-pad) 12px; border-bottom: 1px solid var(--border-soft); vertical-align: top; }
  tr.finding-row { cursor: pointer; transition: background .1s ease; }
  tr.finding-row:hover td { background: color-mix(in srgb, var(--accent) 7%, transparent); }
  tr.finding-row.open td { background: color-mix(in srgb, var(--accent) 9%, transparent); }
  tr.finding-row.hidden-row { display: none; }
  tr.detail-row { display: none; }
  tr.detail-row.open { display: table-row; }
  .title-cell { min-width: 240px; }
  .finding-title { font-weight: 600; }
  .finding-meta { font-size: 11px; color: var(--muted); margin-top: 2px; }
  .cat-tag { white-space: nowrap; color: var(--muted); font-size: 11.5px; }
  .chev-cell { text-align: right; }
  .chev-btn { background: transparent; border: none; color: var(--muted); cursor: pointer; font-size: 12px; padding: 2px 4px; }
  .chev-btn:hover { color: var(--accent); }

  /* ---------- badges & actions ---------- */
  .badge {
    padding: 2px 8px; border-radius: 20px; font-size: 10px; text-transform: uppercase;
    font-weight: 700; letter-spacing: .04em; display: inline-block;
  }
  .sev-critical { background: #e9314722; color: #ff6b7d; border: 1px solid #e9314755; }
  .sev-high { background: #f0883e22; color: #f0883e; border: 1px solid #f0883e55; }
  .sev-medium { background: #e3b34122; color: #e3b341; border: 1px solid #e3b34155; }
  .sev-low { background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff55; }
  .sev-info { background: #8b949e22; color: #8b949e; border: 1px solid #8b949e55; }
  .status-select {
    background: var(--card); color: var(--fg); border: 1px solid var(--border); border-radius: 6px;
    padding: 3px 6px; font: inherit; font-size: 11px; cursor: pointer;
  }
  .actions-cell { display: flex; align-items: center; gap: 4px; white-space: nowrap; }
  .icon-btn {
    background: transparent; border: 1px solid var(--border); border-radius: 6px; cursor: pointer;
    padding: 3px 7px; margin-right: 3px; color: var(--fg); font-size: 12px;
    transition: border-color .12s ease, transform .12s ease, background .12s ease;
  }
  .icon-btn:hover { border-color: var(--accent); background: color-mix(in srgb, var(--accent) 12%, transparent); transform: translateY(-1px); }

  /* ---------- tooltips ---------- */
  .tip { position: relative; }
  .tip::after {
    content: attr(data-tooltip);
    position: absolute; bottom: calc(100% + 7px); left: 50%; transform: translateX(-50%) translateY(2px);
    background: var(--vscode-editorWidget-background, #252526);
    color: var(--vscode-editorWidget-foreground, #cccccc);
    border: 1px solid var(--vscode-widget-border, #454545);
    padding: 5px 9px; border-radius: 6px; font-size: 11px; font-weight: 400; text-transform: none;
    letter-spacing: 0; white-space: normal; max-width: 320px; width: max-content; text-align: left;
    opacity: 0; pointer-events: none; z-index: 30; transition: opacity .12s ease, transform .12s ease;
    box-shadow: var(--shadow-sm);
  }
  .tip:hover::after, .tip:focus-visible::after { opacity: 1; transform: translateX(-50%) translateY(0); }
  /* ---------- expanded finding detail ---------- */
  .detail { padding: 4px 6px 10px; animation: slideIn .22s ease; }
  @keyframes slideIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: none; } }
  .detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
  .detail-block { background: var(--bg); border: 1px solid var(--border-soft); border-radius: var(--radius-sm); padding: 12px; }
  .detail-block.span2 { grid-column: 1 / -1; }
  .detail-block.muted { color: var(--muted); }
  .detail-block p { margin: 0 0 6px; font-size: 12.5px; line-height: 1.55; }
  .detail-block p:last-child { margin-bottom: 0; }
  .detail-block .exploit { color: var(--fg); }
  .tag-label {
    display: inline-block; font-size: 10px; text-transform: uppercase; letter-spacing: .05em;
    color: var(--warn); border: 1px solid color-mix(in srgb, var(--warn) 40%, transparent);
    border-radius: 5px; padding: 1px 6px; margin-right: 6px;
  }
  .pill {
    font-size: 10px; font-weight: 700; color: var(--accent); background: color-mix(in srgb, var(--accent) 16%, transparent);
    border-radius: 20px; padding: 1px 8px; margin-left: 6px; text-transform: none; letter-spacing: 0;
  }
  pre.code {
    margin: 0; background: color-mix(in srgb, var(--vscode-textCodeBlock-background, #000) 65%, transparent);
    border: 1px solid var(--border-soft); border-radius: 6px; padding: 10px;
    font-family: var(--mono); font-size: 11.5px; line-height: 1.5; overflow: auto; max-height: 340px; white-space: pre;
  }
  dl.facts { margin: 0; display: grid; grid-template-columns: 1fr; gap: 3px; }
  dl.facts > div { display: grid; grid-template-columns: 96px 1fr; gap: 8px; font-size: 12px; }
  dl.facts dt { color: var(--muted); }
  dl.facts dd { margin: 0; word-break: break-word; }
  .timeline { list-style: none; margin: 0; padding: 0 0 0 4px; }
  .timeline li { display: grid; grid-template-columns: 12px 1fr; gap: 10px; padding: 5px 0; position: relative; }
  .timeline li:not(:last-child)::before { content: ""; position: absolute; left: 5px; top: 18px; bottom: -2px; width: 1px; background: var(--border); }
  .tl-dot { width: 9px; height: 9px; border-radius: 50%; background: var(--accent); margin-top: 4px; }
  .tl-status { font-size: 12px; font-weight: 600; text-transform: capitalize; }
  .tl-meta { font-size: 11px; color: var(--muted); }
  .detail-foot { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 14px; }
  .copy-src { position: absolute; width: 1px; height: 1px; opacity: 0; pointer-events: none; }

  /* ---------- empty state ---------- */
  .empty-state {
    border: 1px dashed var(--border); border-radius: var(--radius); padding: 54px 24px; text-align: center;
    background: var(--card-2); display: flex; flex-direction: column; align-items: center; gap: 8px;
  }
  .empty-icon { font-size: 30px; }
  .empty-title { font-size: 15px; font-weight: 650; }
  .empty-hint { color: var(--muted); font-size: 12.5px; max-width: 480px; }
  .empty-state .btn { margin-top: 8px; }
  /* ---------- coverage / snapshot / reports ---------- */
  .coverage { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
  .coverage .ratio { font-size: 30px; font-weight: 800; color: var(--accent); font-variant-numeric: tabular-nums; }
  .coverage-line { font-size: 12.5px; }
  .snap-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 8px; }
  .snap-cell {
    display: flex; align-items: baseline; justify-content: space-between; gap: 10px;
    background: var(--card-2); border: 1px solid var(--border-soft); border-radius: var(--radius-sm); padding: 9px 12px;
  }
  .snap-lbl { color: var(--muted); font-size: 11.5px; }
  .snap-num { font-weight: 700; font-variant-numeric: tabular-nums; }
  .report-options { display: flex; flex-direction: column; gap: 10px; max-width: 620px; margin-top: 14px; }
  .report-options label {
    display: flex; gap: 10px; align-items: center; font-size: 12.5px; cursor: pointer;
    background: var(--card-2); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 10px 12px;
  }
  .report-options label:hover { border-color: color-mix(in srgb, var(--accent) 45%, var(--border)); }
  .report-options input { accent-color: var(--accent); }
  .export-options { max-width: 620px; }
  .export-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 8px; }
  .divider { border: none; border-top: 1px solid var(--border-soft); margin: 20px 0; }

  /* ---------- toasts ---------- */
  #toasts { position: fixed; right: 18px; bottom: 18px; display: flex; flex-direction: column; gap: 8px; z-index: 60; }
  .toast {
    background: var(--vscode-editorWidget-background, #252526); color: var(--vscode-editorWidget-foreground, #ddd);
    border: 1px solid var(--vscode-widget-border, #454545); border-left: 3px solid var(--accent);
    border-radius: var(--radius-sm); padding: 9px 14px; font-size: 12px; box-shadow: var(--shadow);
    animation: toastIn .2s cubic-bezier(.22,.7,.3,1);
  }
  .toast.ok { border-left-color: var(--ok); }
  .toast.warn { border-left-color: var(--warn); }
  .toast.bad { border-left-color: var(--bad); }
  .toast.out { opacity: 0; transform: translateY(6px); transition: opacity .4s ease, transform .4s ease; }
  @keyframes toastIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }

  /* ---------- help overlay ---------- */
  .overlay {
    position: fixed; inset: 0; z-index: 80; display: grid; place-items: center;
    background: rgba(0, 0, 0, .5); backdrop-filter: blur(2px);
  }
  .overlay[hidden] { display: none; }
  .overlay-card {
    background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 20px 22px; box-shadow: var(--shadow); min-width: 330px; max-width: 92vw;
  }
  .shortcuts { list-style: none; margin: 0 0 16px; padding: 0; display: flex; flex-direction: column; gap: 8px; }
  .shortcuts li { display: flex; align-items: center; gap: 10px; font-size: 12.5px; color: var(--muted); }
  kbd {
    font-family: var(--mono); font-size: 11px; background: var(--card-2); color: var(--fg);
    border: 1px solid var(--border); border-bottom-width: 2px; border-radius: 5px; padding: 1px 7px; min-width: 24px; text-align: center;
  }

  /* ---------- density ---------- */
  body.compact { --row-pad: 5px; }
  body.compact table.findings { font-size: 12px; }
  body.compact .finding-meta { display: none; }
  body.compact .stat .num { font-size: 20px; }

  @media (prefers-reduced-motion: reduce) {
    * { animation-duration: .001ms !important; animation-iteration-count: 1 !important; transition-duration: .001ms !important; }
    html { scroll-behavior: auto; }
  }
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-thumb { background: color-mix(in srgb, var(--border) 80%, transparent); border-radius: 6px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted); }
</style>
</head>
<body>
<div class="page">
  <header class="topbar">
    <div class="brand">
      <span class="shield" aria-hidden="true">🛡</span>
      <div>
        <h1>SecuGuard Dashboard</h1>
        <div class="meta" id="metaLine">Loading findings…</div>
      </div>
    </div>
    <div class="top-actions">
      <button class="ghost-btn tip" id="densityBtn" data-tooltip="Toggle compact / comfortable rows (d)">↕ Density</button>
      <button class="ghost-btn tip" id="helpBtn" data-tooltip="Keyboard shortcuts (?)">? Help</button>
      <button class="ghost-btn tip" id="settingsBtn" data-tooltip="Open SecuGuard settings">⚙️ Settings</button>
    </div>
  </header>

  <div class="stick">
    <nav class="tabs" role="tablist">
      <button class="tab" data-tab="overview" role="tab">Overview</button>
      <button class="tab" data-tab="security" role="tab">Security<span class="badge-tab" id="badge-security">0</span></button>
      <button class="tab" data-tab="quality" role="tab">Quality<span class="badge-tab" id="badge-quality">0</span></button>
      <button class="tab" data-tab="coverage" role="tab">Test coverage<span class="badge-tab" id="badge-coverage">0</span></button>
      <button class="tab" data-tab="docs" role="tab">Documentation<span class="badge-tab" id="badge-docs">0</span></button>
      <button class="tab" data-tab="reports" role="tab">Reports</button>
    </nav>

    <div class="filterbar" id="filterbar" hidden>
      <div class="filter-row">
        <label class="search-wrap">
          <span class="search-icon" aria-hidden="true">🔎</span>
          <input type="text" id="search" placeholder="Search title, file, CWE, rule…   (press /)" autocomplete="off" spellcheck="false" />
        </label>
        <select class="filter" id="categoryFilter" aria-label="Filter by category">
          <option value="">All categories</option>
          <option value="sast">sast</option>
          <option value="sca">sca</option>
          <option value="secret">secret</option>
          <option value="iac">iac</option>
          <option value="container">container</option>
          <option value="quality">quality</option>
          <option value="test-coverage">test-coverage</option>
          <option value="documentation">documentation</option>
        </select>
        <span class="result-count" id="resultCount"></span>
        <button class="ghost-btn" id="clearFilters" hidden>✕ Clear filters</button>
        <button class="ghost-btn tip" data-action="expandAll" data-tooltip="Expand every finding in this tab">⤢ Expand all</button>
        <button class="ghost-btn tip" data-action="collapseAll" data-tooltip="Collapse every finding in this tab">⤡ Collapse</button>
        <button class="ghost-btn tip" data-action="copyVisible" data-tooltip="Copy the filtered findings as Markdown">📋 Copy list</button>
      </div>
      <div class="chip-row" id="sevChips"></div>
      <div class="chip-row" id="qualityChipRow" hidden>
        <span class="chip-group-label">Quality debt</span>
        <span class="chip-inline" id="qualityChips"></span>
      </div>
    </div>
  </div>

  <main class="content">
    <section class="tab-section" id="tab-overview" hidden><div id="content-overview"></div></section>
    <section class="tab-section" id="tab-security" hidden><div id="content-security"></div></section>
    <section class="tab-section" id="tab-quality" hidden><div id="content-quality"></div></section>
    <section class="tab-section" id="tab-coverage" hidden><div id="content-coverage"></div></section>
    <section class="tab-section" id="tab-docs" hidden><div id="content-docs"></div></section>
    <section class="tab-section" id="tab-reports" hidden>
      <div id="content-reports"></div>
      <div class="card report-options">
        <h3>Final QA report <span class="hint">Markdown + self-contained HTML</span></h3>
        <label><input type="checkbox" id="optMd" checked /> Markdown (.md)</label>
        <label><input type="checkbox" id="optHtml" checked /> HTML (.html)</label>
        <label><input type="checkbox" id="optAi" /> Include AI executive summary <span class="finding-meta">(uses your <b>secuguard.ai</b> settings; skipped when AI is off)</span></label>
        <div><button class="btn primary" data-action="generateFinalReport">📄 Generate final QA report</button></div>
      </div>
      <hr class="divider" />
      <div class="card export-options">
        <h3>Raw exports <span class="hint">unchanged format</span></h3>
        <div class="export-grid">
          <button class="btn" data-action="exportRaw" data-format="markdown">Markdown summary (.md)</button>
          <button class="btn" data-action="exportRaw" data-format="csv">CSV spreadsheet (.csv)</button>
          <button class="btn" data-action="exportRaw" data-format="sarif">SARIF (.sarif)</button>
          <button class="btn" data-action="exportRaw" data-format="json">JSON (.json)</button>
        </div>
      </div>
    </section>
  </main>
</div>

<div id="toasts" aria-live="polite"></div>

<div id="helpOverlay" class="overlay" hidden>
  <div class="overlay-card" role="dialog" aria-label="Keyboard shortcuts">
    <h3>Keyboard shortcuts</h3>
    <ul class="shortcuts">
      <li><kbd>/</kbd><span>Focus the search box</span></li>
      <li><kbd>Esc</kbd><span>Clear the search / close this dialog</span></li>
      <li><kbd>1</kbd><kbd>2</kbd><kbd>3</kbd><kbd>4</kbd><kbd>5</kbd><kbd>6</kbd><span>Jump to a tab</span></li>
      <li><kbd>Enter</kbd><span>Expand / collapse the focused finding</span></li>
      <li><kbd>d</kbd><span>Toggle compact row density</span></li>
      <li><kbd>r</kbd><span>Rescan the workspace</span></li>
      <li><kbd>?</kbd><span>Toggle this dialog</span></li>
    </ul>
    <button class="btn primary" id="helpClose">Close</button>
  </div>
</div>
<script nonce="${nonce}">
(function () {
  var vscode = acquireVsCodeApi();
  var saved = vscode.getState() || {};
  var state = {
    tab: saved.tab || "overview",
    density: saved.density || "comfortable",
    sort: saved.sort || { key: "severity", dir: 1 },
    filters: saved.filters || { q: "", sevs: [], cat: "", qtype: "all" },
    expanded: {}
  };
  if (!state.filters.sevs) state.filters.sevs = [];
  (saved.expanded || []).forEach(function (id) { state.expanded[id] = true; });

  var TABS = ["overview", "security", "quality", "coverage", "docs", "reports"];
  var NEWLINE = String.fromCharCode(10);
  var lastNums = {};
  var reduceMotion = !!(window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches);

  function persist() {
    vscode.setState({
      tab: state.tab,
      density: state.density,
      sort: state.sort,
      filters: state.filters,
      expanded: Object.keys(state.expanded).filter(function (k) { return state.expanded[k]; })
    });
  }

  function setHtml(id, html) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  function setText(id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = String(text);
  }

  function toast(msg, kind) {
    var host = document.getElementById("toasts");
    if (!host) return;
    var el = document.createElement("div");
    el.className = "toast " + (kind || "info");
    el.textContent = msg;
    host.appendChild(el);
    setTimeout(function () { el.classList.add("out"); }, 2200);
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 2750);
  }

  function copyText(text) {
    var ok = function () { toast("Copied to clipboard", "ok"); };
    var fallback = function () {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "readonly");
        ta.style.position = "fixed";
        ta.style.top = "-1000px";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        ok();
      } catch (e) { toast("Copy failed — select the text manually", "bad"); }
    };
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(ok, fallback);
      } else { fallback(); }
    } catch (e) { fallback(); }
  }

  function renderPayload(p) {
    setHtml("content-overview", p.sections.overview);
    setHtml("content-security", p.sections.security);
    setHtml("content-quality", p.sections.quality);
    setHtml("content-coverage", p.sections.coverage);
    setHtml("content-docs", p.sections.docs);
    setHtml("content-reports", p.sections.reports);
    setHtml("sevChips", p.sevChipsHtml);
    setHtml("qualityChips", p.qualityChipsHtml);
    var meta = document.getElementById("metaLine");
    if (meta) meta.innerHTML = p.meta.summaryHtml;
    setText("badge-security", p.tabCounts.security);
    setText("badge-quality", p.tabCounts.quality);
    setText("badge-coverage", p.tabCounts.coverage);
    setText("badge-docs", p.tabCounts.docs);
    decorate();
  }
  function activeSection() {
    return document.querySelector(".tab-section:not([hidden])");
  }

  function decorate() {
    document.querySelectorAll("table.findings").forEach(function (table) {
      restoreExpansion(table);
      sortRows(table);
    });
    syncChips();
    applyFilters();
    animateNumbers();
  }

  /* ---------- sorting ---------- */
  function pad(n) {
    var s = String(n);
    while (s.length < 8) s = "0" + s;
    return s;
  }

  function rowValue(tr, key) {
    if (key === "severity") return String(99 - Number(tr.getAttribute("data-sev-rank") || 0));
    if (key === "location") return (tr.getAttribute("data-file") || "") + "#" + pad(Number(tr.getAttribute("data-line") || 0));
    if (key === "title") return (tr.getAttribute("data-title") || "").toLowerCase();
    if (key === "category") return (tr.getAttribute("data-category") || "").toLowerCase();
    if (key === "status") return (tr.getAttribute("data-status") || "").toLowerCase();
    return "";
  }

  function sortRows(table) {
    var tbody = table.querySelector("tbody");
    if (!tbody) return;
    var key = state.sort.key;
    var dir = state.sort.dir === -1 ? -1 : 1;
    var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr.finding-row"));
    rows.sort(function (a, b) {
      var av = rowValue(a, key);
      var bv = rowValue(b, key);
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return (a.getAttribute("data-title") || "").localeCompare(b.getAttribute("data-title") || "");
    });
    rows.forEach(function (tr) {
      var detail = tr.nextElementSibling;
      var hasDetail = detail && detail.classList && detail.classList.contains("detail-row");
      tbody.appendChild(tr);
      if (hasDetail) tbody.appendChild(detail);
    });
    table.querySelectorAll("th.sortable").forEach(function (th) {
      var isActive = th.getAttribute("data-key") === key;
      th.classList.toggle("sorted", isActive);
      var ind = th.querySelector(".sort-ind");
      if (ind) ind.textContent = isActive ? (dir === -1 ? "▲" : "▼") : "";
    });
  }

  /* ---------- expansion ---------- */
  function setChevron(tr) {
    var chev = tr.querySelector(".chev");
    if (chev) chev.textContent = tr.classList.contains("open") ? "▾" : "▸";
  }

  function syncDetails() {
    document.querySelectorAll("tr.finding-row").forEach(function (tr) {
      var d = tr.nextElementSibling;
      if (!d || !d.classList || !d.classList.contains("detail-row")) return;
      var open = !tr.classList.contains("hidden-row") && tr.classList.contains("open");
      d.classList.toggle("open", open);
    });
  }

  function restoreExpansion(table) {
    table.querySelectorAll("tr.finding-row").forEach(function (tr) {
      tr.classList.toggle("open", !!state.expanded[tr.getAttribute("data-id")]);
      setChevron(tr);
    });
  }

  function toggleRow(tr) {
    var id = tr.getAttribute("data-id");
    var open = !tr.classList.contains("open");
    tr.classList.toggle("open", open);
    state.expanded[id] = open;
    setChevron(tr);
    syncDetails();
    persist();
  }

  function setAllExpanded(open) {
    var section = activeSection();
    if (!section) return;
    var found = section.querySelectorAll("tr.finding-row");
    if (!found.length) { toast("Nothing to expand in this tab", "warn"); return; }
    found.forEach(function (tr) {
      tr.classList.toggle("open", open);
      state.expanded[tr.getAttribute("data-id")] = open;
      setChevron(tr);
    });
    syncDetails();
    persist();
    toast(open ? "Expanded every finding" : "Collapsed every finding");
  }

  /* ---------- filtering ---------- */
  function syncChips() {
    var f = state.filters;
    document.querySelectorAll("#sevChips .chip").forEach(function (c) {
      var id = c.getAttribute("data-sev-toggle");
      var active = id ? f.sevs.indexOf(id) !== -1 : f.sevs.length === 0;
      c.classList.toggle("active", active);
    });
    document.querySelectorAll("#qualityChips .chip").forEach(function (c) {
      c.classList.toggle("active", c.getAttribute("data-qtype") === f.qtype);
    });
    var sel = document.getElementById("categoryFilter");
    if (sel && sel.value !== f.cat) sel.value = f.cat || "";
    var search = document.getElementById("search");
    if (search && search.value !== f.q) search.value = f.q || "";
  }

  function applyFilters() {
    var f = state.filters;
    var q = f.q || "";
    var onQuality = state.tab === "quality";
    document.querySelectorAll("tr.finding-row").forEach(function (tr) {
      var ok = true;
      if (q && (tr.getAttribute("data-search") || "").indexOf(q) === -1) ok = false;
      if (ok && f.sevs.length && f.sevs.indexOf(tr.getAttribute("data-severity")) === -1) ok = false;
      if (ok && f.cat && tr.getAttribute("data-category") !== f.cat) ok = false;
      if (ok && onQuality && f.qtype !== "all" && tr.getAttribute("data-quality-type") !== f.qtype) ok = false;
      tr.classList.toggle("hidden-row", !ok);
    });
    syncDetails();

    var section = activeSection();
    var shown = 0;
    var total = 0;
    var sevTotals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (section) {
      section.querySelectorAll("tr.finding-row").forEach(function (tr) {
        total++;
        var sev = tr.getAttribute("data-severity");
        if (Object.prototype.hasOwnProperty.call(sevTotals, sev)) sevTotals[sev]++;
        if (!tr.classList.contains("hidden-row")) shown++;
      });
    }
    var count = document.getElementById("resultCount");
    if (count) count.innerHTML = total === 0 ? "" : "<b>" + shown + "</b> of " + total + " shown";
    var clear = document.getElementById("clearFilters");
    if (clear) clear.hidden = !(q || f.sevs.length || f.cat || (onQuality && f.qtype !== "all"));
    syncSevChips(sevTotals, total);
  }

  // The chips sit in a filter bar that only ever filters the visible tab, so
  // their counts must match that tab's rows. The payload ships project-wide
  // totals (e.g. "All 9" across every category) which would otherwise promise
  // nine findings while the Security tab only contains three rows.
  function syncSevChips(sevTotals, total) {
    document.querySelectorAll("#sevChips .chip[data-sev-toggle]").forEach(function (chip) {
      var sev = chip.getAttribute("data-sev-toggle") || "";
      var n = sevTotals[sev] || 0;
      var badge = chip.querySelector(".chip-count");
      if (badge) badge.textContent = String(n);
      chip.setAttribute("data-tooltip", sev + " · " + n + (n === 1 ? " finding" : " findings"));
      chip.classList.toggle("is-empty", n === 0);
    });
    var allChip = document.querySelector("#sevChips .chip[data-sev-clear]");
    if (allChip) {
      var allBadge = allChip.querySelector(".chip-count");
      if (allBadge) allBadge.textContent = String(total);
      allChip.classList.toggle("is-empty", total === 0);
    }
  }

  function clearFilters() {
    state.filters = { q: "", sevs: [], cat: "", qtype: "all" };
    syncChips();
    applyFilters();
    persist();
  }
  /* ---------- tabs & chrome ---------- */
  function switchTab(tab) {
    if (TABS.indexOf(tab) === -1) tab = "overview";
    state.tab = tab;
    // Category filters are scoped to one tab's rows. Carrying one across tabs
    // leaves the new tab with zero matches ("0 of 3 shown") even though it has
    // findings, so drop it here. Severity/search still carry over safely.
    state.filters.cat = "";
    document.querySelectorAll(".tab").forEach(function (b) {
      var on = b.getAttribute("data-tab") === tab;
      b.classList.toggle("active", on);
      b.setAttribute("aria-selected", on ? "true" : "false");
    });
    document.querySelectorAll(".tab-section").forEach(function (s) {
      s.hidden = s.id !== "tab-" + tab;
    });
    // Overview now lists every active finding too, so it needs the filter bar;
    // only Reports has nothing to filter.
    var showFilters = tab !== "reports";
    var fb = document.getElementById("filterbar");
    if (fb) fb.hidden = !showFilters;
    var qRow = document.getElementById("qualityChipRow");
    if (qRow) qRow.hidden = tab !== "quality";
    applyFilters();
    persist();
  }

  function applyDensity() {
    document.body.classList.toggle("compact", state.density === "compact");
    var btn = document.getElementById("densityBtn");
    if (btn) btn.textContent = state.density === "compact" ? "↕ Compact" : "↕ Comfortable";
  }

  function toggleDensity() {
    state.density = state.density === "compact" ? "comfortable" : "compact";
    applyDensity();
    persist();
  }

  function toggleHelp(force) {
    var overlay = document.getElementById("helpOverlay");
    if (!overlay) return;
    var next = typeof force === "boolean" ? force : overlay.hidden;
    overlay.hidden = !next;
  }

  function animateNumbers() {
    document.querySelectorAll("[data-num]").forEach(function (el) {
      var key = el.getAttribute("data-num") || "";
      var target = Number(el.getAttribute("data-value") || 0);
      var previous = lastNums[key];
      lastNums[key] = target;
      if (reduceMotion || previous === undefined || previous === target) {
        el.textContent = String(target);
        return;
      }
      var from = previous;
      var start = null;
      var duration = 420;
      function step(ts) {
        if (start === null) start = ts;
        var t = Math.min(1, (ts - start) / duration);
        var eased = 1 - Math.pow(1 - t, 3);
        el.textContent = String(Math.round(from + (target - from) * eased));
        if (t < 1) requestAnimationFrame(step);
        else el.textContent = String(target);
      }
      requestAnimationFrame(step);
    });
  }

  /* ---------- clipboard helpers ---------- */
  function copyFinding(el) {
    var row = el.closest("tr.finding-row");
    var detail = el.closest("tr.detail-row");
    if (!detail && row) detail = row.nextElementSibling;
    var src = detail && detail.querySelector ? detail.querySelector(".copy-src") : null;
    if (src && src.value) copyText(src.value);
    else toast("Nothing to copy for this finding", "warn");
  }

  function copyVisible() {
    var section = activeSection();
    if (!section) { toast("Open a findings tab first", "warn"); return; }
    var lines = [];
    section.querySelectorAll("tr.finding-row").forEach(function (tr) {
      if (tr.classList.contains("hidden-row")) return;
      var detail = tr.nextElementSibling;
      var src = detail && detail.querySelector ? detail.querySelector(".copy-src") : null;
      if (src && src.value) lines.push(src.value);
    });
    if (!lines.length) { toast("No visible findings to copy", "warn"); return; }
    copyText(lines.join(NEWLINE + NEWLINE));
  }

  function copySummary() {
    var src = document.getElementById("summarySrc");
    if (src && src.value) copyText(src.value);
    else toast("Nothing to copy yet", "warn");
  }
  /* ---------- interactions ---------- */
  function toggleSev(sev) {
    var f = state.filters;
    var i = f.sevs.indexOf(sev);
    if (i === -1) f.sevs.push(sev);
    else f.sevs.splice(i, 1);
    if (state.tab === "overview" || state.tab === "reports") switchTab("security");
    syncChips();
    applyFilters();
    persist();
  }

  function focusCategory(cat) {
    var tab = cat === "quality" ? "quality" : cat === "test-coverage" ? "coverage" : cat === "documentation" ? "docs" : "security";
    switchTab(tab);
    // Set after switchTab: switching tabs drops a category filter scoped to the
    // tab we just left, otherwise this would be immediately cleared.
    state.filters.cat = cat;
    syncChips();
    applyFilters();
    persist();
  }

  function jumpToTab(tab, sevs) {
    state.filters.sevs = sevs || [];
    switchTab(tab);
    syncChips();
    applyFilters();
    persist();
  }

  function handleAction(el) {
    var action = el.getAttribute("data-action");
    var id = el.getAttribute("data-id") || "";
    switch (action) {
      case "toggle": {
        var r = el.closest("tr.finding-row");
        if (r) toggleRow(r);
        break;
      }
      case "open": vscode.postMessage({ type: "open", id: id }); break;
      case "explain": vscode.postMessage({ type: "explain", id: id }); break;
      case "refreshAi":
        vscode.postMessage({ type: "refreshAi", id: id });
        toast("Re-running AI analysis…");
        break;
      case "generateTest":
        vscode.postMessage({ type: "generateTest", id: id });
        toast("Drafting a unit test for this symbol…");
        break;
      case "showHistory": vscode.postMessage({ type: "showHistory", id: id }); break;
      case "rescan":
        vscode.postMessage({ type: "rescan" });
        toast("Scanning the workspace…");
        break;
      case "generateAllTests":
        vscode.postMessage({ type: "generateAllTests" });
        toast("Generating tests for uncovered symbols…");
        break;
      case "exportRaw":
        vscode.postMessage({ type: "exportRaw", format: el.getAttribute("data-format") });
        toast("Building the export…");
        break;
      case "generateFinalReport": {
        var md = document.getElementById("optMd");
        var html = document.getElementById("optHtml");
        var ai = document.getElementById("optAi");
        var formats = [];
        if (md && md.checked) formats.push("markdown");
        if (html && html.checked) formats.push("html");
        if (!formats.length) { toast("Pick at least one report format", "warn"); break; }
        vscode.postMessage({ type: "generateFinalReport", formats: formats, includeAi: !!(ai && ai.checked) });
        toast("Generating the final QA report…");
        break;
      }
      case "copyFinding": copyFinding(el); break;
      case "copyVisible": copyVisible(); break;
      case "copySummary": copySummary(); break;
      case "expandAll": setAllExpanded(true); break;
      case "collapseAll": setAllExpanded(false); break;
      case "kpi": {
        var tab = el.getAttribute("data-tab") || "overview";
        var sevs = (el.getAttribute("data-sevs") || "").split(",").filter(function (s) { return !!s; });
        jumpToTab(tab, sevs);
        break;
      }
    }
  }
  document.addEventListener("click", function (e) {
    var t = e.target;
    if (!t || !t.closest) return;

    if (t.closest("#helpOverlay") && !t.closest(".overlay-card")) { toggleHelp(false); return; }
    if (t.closest("#helpBtn") || t.closest("#helpClose")) { toggleHelp(); return; }
    if (t.closest("#densityBtn")) { toggleDensity(); return; }
    if (t.closest("#settingsBtn")) { vscode.postMessage({ type: "openSettings" }); return; }

    var actionEl = t.closest("[data-action]");
    if (actionEl) { handleAction(actionEl); return; }

    var tabBtn = t.closest(".tab");
    if (tabBtn) { switchTab(tabBtn.getAttribute("data-tab")); return; }

    var sevChip = t.closest("[data-sev-toggle]");
    if (sevChip) { toggleSev(sevChip.getAttribute("data-sev-toggle")); return; }
    if (t.closest("[data-sev-clear]")) { state.filters.sevs = []; syncChips(); applyFilters(); persist(); return; }

    var qchip = t.closest("[data-qtype]");
    if (qchip) {
      state.filters.qtype = qchip.getAttribute("data-qtype");
      syncChips();
      applyFilters();
      persist();
      return;
    }
    var qjump = t.closest("[data-qtype-jump]");
    if (qjump) {
      state.filters.qtype = qjump.getAttribute("data-qtype-jump");
      switchTab("quality");
      syncChips();
      applyFilters();
      persist();
      return;
    }

    var legend = t.closest("[data-legend-sev]");
    if (legend && !legend.disabled) { toggleSev(legend.getAttribute("data-legend-sev")); return; }

    var bar = t.closest("[data-bar-cat]");
    if (bar) { focusCategory(bar.getAttribute("data-bar-cat")); return; }

    var th = t.closest("th.sortable");
    if (th) {
      var key = th.getAttribute("data-key");
      if (state.sort.key === key) state.sort.dir = state.sort.dir === -1 ? 1 : -1;
      else state.sort = { key: key, dir: 1 };
      document.querySelectorAll("table.findings").forEach(sortRows);
      persist();
      return;
    }

    if (t.closest("#clearFilters")) { clearFilters(); return; }

    var row = t.closest("tr.finding-row");
    if (row && !t.closest("button, select, a, input, textarea, label")) { toggleRow(row); }
  });

  document.addEventListener("change", function (e) {
    var t = e.target;
    if (!t || !t.closest) return;
    var sel = t.closest(".status-select");
    if (sel) {
      vscode.postMessage({ type: "setStatus", id: sel.getAttribute("data-id"), status: sel.value });
      toast("Status set to " + sel.value.replace("_", " ") + "…");
      return;
    }
    if (t.id === "categoryFilter") {
      state.filters.cat = t.value;
      applyFilters();
      persist();
    }
  });

  document.addEventListener("input", function (e) {
    var t = e.target;
    if (t && t.id === "search") {
      state.filters.q = (t.value || "").toLowerCase();
      applyFilters();
      persist();
    }
  });
  /* ---------- keyboard ---------- */
  document.addEventListener("keydown", function (e) {
    var target = e.target;
    var tag = target && target.tagName ? target.tagName.toLowerCase() : "";
    var typing = tag === "input" || tag === "textarea" || tag === "select";
    var overlay = document.getElementById("helpOverlay");

    if (e.key === "Escape") {
      if (overlay && !overlay.hidden) { toggleHelp(false); return; }
      if (typing) {
        state.filters.q = "";
        if (target && target.id === "search") target.value = "";
        applyFilters();
        persist();
      }
      return;
    }
    if (typing) return;

    if (e.key === "/") {
      e.preventDefault();
      var search = document.getElementById("search");
      if (search) search.focus();
      return;
    }
    if (e.key === "?") { e.preventDefault(); toggleHelp(); return; }
    if (e.key === "d" || e.key === "D") { toggleDensity(); return; }
    if (e.key === "r" || e.key === "R") {
      vscode.postMessage({ type: "rescan" });
      toast("Scanning the workspace…");
      return;
    }
    var row = target && target.closest ? target.closest("tr.finding-row") : null;
    if (row && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggleRow(row); return; }
    var n = parseInt(e.key, 10);
    if (n >= 1 && n <= TABS.length) switchTab(TABS[n - 1]);
  });

  /* ---------- trend chart tooltip ---------- */
  function showTrendTip(circle) {
    var tip = document.getElementById("trendTip");
    var svg = circle.ownerSVGElement;
    var wrap = svg && svg.parentNode;
    if (!tip || !svg || !wrap || !svg.viewBox || !svg.viewBox.baseVal) return;
    var vb = svg.viewBox.baseVal;
    if (!vb.width || !vb.height) return;
    var box = svg.getBoundingClientRect();
    var wrapBox = wrap.getBoundingClientRect();
    var x = (Number(circle.getAttribute("cx")) / vb.width) * box.width + (box.left - wrapBox.left);
    var y = (Number(circle.getAttribute("cy")) / vb.height) * box.height + (box.top - wrapBox.top);
    tip.innerHTML = "";
    var day = document.createElement("b");
    day.textContent = circle.getAttribute("data-day") || "";
    var val = document.createElement("span");
    val.textContent = (circle.getAttribute("data-count") || "0") + " new";
    tip.appendChild(day);
    tip.appendChild(val);
    tip.style.left = x + "px";
    tip.style.top = y + "px";
    tip.hidden = false;
  }

  function hideTrendTip() {
    var tip = document.getElementById("trendTip");
    if (tip) tip.hidden = true;
  }

  document.addEventListener("mouseover", function (e) {
    var t = e.target;
    if (t && t.classList && t.classList.contains("pt")) showTrendTip(t);
  });
  document.addEventListener("mouseout", function (e) {
    var t = e.target;
    if (t && t.classList && t.classList.contains("pt")) hideTrendTip();
  });

  /* ---------- wire up ---------- */
  window.addEventListener("message", function (event) {
    var msg = event.data;
    if (msg && msg.type === "data") renderPayload(msg);
  });

  applyDensity();
  switchTab(state.tab);
  vscode.postMessage({ type: "ready" });
})();
</script>
</body>
</html>`;
}
