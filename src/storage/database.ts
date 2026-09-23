import * as fs from "fs";
import * as path from "path";
import { Vulnerability } from "../types";

export interface AuditEntry {
  timestamp: string;
  action: string;
  detail: string;
  actor?: string;
}

export interface IgnoreRule {
  ruleId: string;
  reason: string;
  createdAt: string;
  file?: string;
}

interface MetaShape {
  version: number;
  hasScannedBefore: boolean;
  ignoreRules: IgnoreRule[];
}

const DB_VERSION = 1;

/**
 * Git-friendly storage layout (one file per finding, small stable-key meta file,
 * append-only NDJSON audit log):
 *   .secuguard/findings/<id>.json   — one Vulnerability per file, sorted keys
 *   .secuguard/meta.json            — scan flags + suppression rules
 *   .secuguard/audit-log.ndjson     — append-only, `merge=union` in .gitattributes
 *   .secuguard/ignore.yml           — human-readable suppress rules (derived)
 */
export class Database {
  private root: string;
  private findingsDir: string;
  private metaPath: string;
  private auditLogPath: string;
  private ignoreYmlPath: string;
  private meta!: MetaShape;
  private cache: Map<string, Vulnerability>;
  public baselineOnFirstRun: boolean;

  constructor(workspaceRoot: string, baselineOnFirstRun = true) {
    this.root = path.join(workspaceRoot, ".secuguard");
    this.findingsDir = path.join(this.root, "findings");
    this.metaPath = path.join(this.root, "meta.json");
    this.auditLogPath = path.join(this.root, "audit-log.ndjson");
    this.ignoreYmlPath = path.join(this.root, "ignore.yml");
    fs.mkdirSync(this.findingsDir, { recursive: true });
    this.baselineOnFirstRun = baselineOnFirstRun;
    this.cache = new Map();
    this.migrateLegacyDb();
    if (!this.meta) this.meta = this.loadMeta();
    this.loadFindingsFromDisk();
  }

  // ---- legacy .secuguard/db.json -> new layout -----------------------------

  private migrateLegacyDb(): void {
    const legacy = path.join(this.root, "db.json");
    if (!fs.existsSync(legacy)) return;
    try {
      const raw = JSON.parse(fs.readFileSync(legacy, "utf8"));
      for (const v of Object.values(raw.vulnerabilities ?? {}) as Vulnerability[]) {
        v.statusHistory = v.statusHistory ?? [];
        this.writeFindingFile(v);
        this.cache.set(v.id, v);
      }
      this.meta = {
        version: DB_VERSION,
        hasScannedBefore: !!raw.hasScannedBefore,
        ignoreRules: raw.ignoreRules ?? [],
      };
      this.persistMeta();
      for (const e of raw.auditLog ?? []) {
        fs.appendFileSync(
          this.auditLogPath,
          stringifyStableCompact({ timestamp: e.timestamp ?? new Date().toISOString(), action: e.action ?? "migrate", detail: e.detail ?? "" }),
          "utf8"
        );
      }
      this.syncIgnoreYml();
      fs.renameSync(legacy, legacy + ".migrated");
    } catch {
      // leave the legacy file untouched; fall back to a fresh DB
    }
  }

  // ---- meta (hasScannedBefore, ignoreRules) --------------------------------

  private loadMeta(): MetaShape {
    if (!fs.existsSync(this.metaPath)) return { version: DB_VERSION, hasScannedBefore: false, ignoreRules: [] };
    try {
      const raw = JSON.parse(fs.readFileSync(this.metaPath, "utf8"));
      return {
        version: raw.version ?? DB_VERSION,
        hasScannedBefore: !!raw.hasScannedBefore,
        ignoreRules: raw.ignoreRules ?? [],
      };
    } catch {
      return { version: DB_VERSION, hasScannedBefore: false, ignoreRules: [] };
    }
  }

  private persistMeta(): void {
    fs.writeFileSync(this.metaPath, stringifyStable(this.meta), "utf8");
  }

  hasScannedBefore(): boolean {
    return this.meta.hasScannedBefore;
  }

  markScannedOnce(): void {
    if (!this.meta.hasScannedBefore) {
      this.meta.hasScannedBefore = true;
      this.persistMeta();
    }
  }

  addIgnoreRule(rule: IgnoreRule): void {
    this.meta.ignoreRules.push(rule);
    this.persistMeta();
    this.syncIgnoreYml();
  }

  getIgnoreRules(): IgnoreRule[] {
    return this.meta.ignoreRules;
  }

  private syncIgnoreYml(): void {
    const lines = [
      "# SecuGuard suppression rules — generated & maintained automatically.",
      "# Add a reason so future scans and teammates understand why a rule is suppressed here.",
      "suppressions:",
      ...this.meta.ignoreRules.map(
        (r) => `  - rule: ${r.ruleId}\n    reason: "${r.reason.replace(/"/g, "'")}"\n    file: ${r.file ?? "*"}\n    created: ${r.createdAt}`
      ),
    ];
    fs.writeFileSync(this.ignoreYmlPath, lines.join("\n") + "\n", "utf8");
  }

  // ---- findings (one file per finding) -------------------------------------

  private safeId(id: string): string {
    return id.replace(/[^A-Za-z0-9._-]/g, "-");
  }

  private findingPath(id: string): string {
    return path.join(this.findingsDir, `${this.safeId(id)}.json`);
  }

  private writeFindingFile(v: Vulnerability): void {
    fs.writeFileSync(this.findingPath(v.id), stringifyStable(v), "utf8");
  }

  private loadFindingsFromDisk(): void {
    this.cache.clear();
    for (const f of fs.readdirSync(this.findingsDir)) {
      if (!f.endsWith(".json")) continue;
      try {
        const v = JSON.parse(fs.readFileSync(path.join(this.findingsDir, f), "utf8")) as Vulnerability;
        v.statusHistory = v.statusHistory ?? [];
        if (v.id) this.cache.set(v.id, v);
      } catch {
        // skip corrupt/half-written finding files
      }
    }
  }

  getAllAsMap(): Map<string, Vulnerability> {
    return new Map(this.cache);
  }

  getAll(): Vulnerability[] {
    return Array.from(this.cache.values()).sort((a, b) => a.file.localeCompare(b.file) || a.startLine - b.startLine);
  }

  get(id: string): Vulnerability | undefined {
    if (this.cache.has(id)) return this.cache.get(id);
    const p = this.findingPath(id);
    if (!fs.existsSync(p)) return undefined;
    try {
      const v = JSON.parse(fs.readFileSync(p, "utf8")) as Vulnerability;
      v.statusHistory = v.statusHistory ?? [];
      this.cache.set(id, v);
      return v;
    } catch {
      return undefined;
    }
  }

  upsertMany(vulns: Vulnerability[]): void {
    for (const v of vulns) {
      this.cache.set(v.id, v);
      const serialized = stringifyStable(v);
      const p = this.findingPath(v.id);
      if (!fs.existsSync(p) || fs.readFileSync(p, "utf8") !== serialized) {
        fs.writeFileSync(p, serialized, "utf8");
      }
    }
  }

  update(id: string, patch: Partial<Vulnerability>): Vulnerability | undefined {
    const existing = this.get(id);
    if (!existing) return undefined;
    const merged: Vulnerability = { ...existing, ...patch };
    this.cache.set(id, merged);
    this.writeFindingFile(merged);
    return merged;
  }

  // ---- audit log (append-only NDJSON) --------------------------------------

  addAuditEntry(action: string, detail: string, actor?: string): void {
    const entry = { timestamp: new Date().toISOString(), action, detail, ...(actor !== undefined ? { actor } : {}) };
    // audit-log.ndjson is one compact JSON object per line (stable keys) so
    // that `merge=union` merges concurrent appends cleanly.
    fs.appendFileSync(this.auditLogPath, stringifyStableCompact(entry), "utf8");
  }

  getAuditLog(): AuditEntry[] {
    if (!fs.existsSync(this.auditLogPath)) return [];
    const out: AuditEntry[] = [];
    for (const line of fs.readFileSync(this.auditLogPath, "utf8").split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        out.push(JSON.parse(t));
      } catch {
        // skip malformed lines
      }
    }
    return out;
  }

  // ---- lifecycle -----------------------------------------------------------

  /** Re-read everything from disk (e.g. after a `git pull` or teammate edit). */
  reload(): void {
    this.meta = this.loadMeta();
    this.loadFindingsFromDisk();
  }

  resetAll(): void {
    this.cache.clear();
    for (const f of fs.readdirSync(this.findingsDir)) {
      if (f.endsWith(".json")) {
        try {
          fs.unlinkSync(path.join(this.findingsDir, f));
        } catch {
          // ignore
        }
      }
    }
    this.meta = { version: DB_VERSION, hasScannedBefore: false, ignoreRules: [] };
    this.persistMeta();
    try {
      fs.writeFileSync(this.auditLogPath, "", "utf8");
    } catch {
      // ignore
    }
    this.syncIgnoreYml();
  }
}

// ---- stable serialization --------------------------------------------------

function sortKeysDeep<T>(value: T): T {
  if (Array.isArray(value)) return value.map((v) => sortKeysDeep(v)) as unknown as T;
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[k] = sortKeysDeep((value as Record<string, unknown>)[k]);
    }
    return sorted as T;
  }
  return value;
}

function stringifyStable(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value), null, 2) + "\n";
}

function stringifyStableCompact(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value)) + "\n";
}