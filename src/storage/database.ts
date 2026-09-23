import * as fs from "fs";
import * as path from "path";
import { Vulnerability } from "../types";

interface DbShape {
  version: number;
  hasScannedBefore: boolean;
  vulnerabilities: Record<string, Vulnerability>;
  auditLog: AuditEntry[];
  ignoreRules: IgnoreRule[];
}

export interface AuditEntry {
  timestamp: string;
  action: string;
  detail: string;
}

export interface IgnoreRule {
  ruleId: string;
  reason: string;
  createdAt: string;
  file?: string;
}

const DB_VERSION = 1;

export class Database {
  private dbPath: string;
  private ignoreYmlPath: string;
  private data: DbShape;
  public baselineOnFirstRun: boolean;

  constructor(workspaceRoot: string, baselineOnFirstRun = true) {
    const dir = path.join(workspaceRoot, ".secuguard");
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    this.dbPath = path.join(dir, "db.json");
    this.ignoreYmlPath = path.join(dir, "ignore.yml");
    this.baselineOnFirstRun = baselineOnFirstRun;
    this.data = this.load();
  }

  private load(): DbShape {
    if (fs.existsSync(this.dbPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(this.dbPath, "utf8"));
        return {
          version: raw.version ?? DB_VERSION,
          hasScannedBefore: !!raw.hasScannedBefore,
          vulnerabilities: raw.vulnerabilities ?? {},
          auditLog: raw.auditLog ?? [],
          ignoreRules: raw.ignoreRules ?? [],
        };
      } catch {
        // fall through to fresh DB on corrupt file
      }
    }
    return { version: DB_VERSION, hasScannedBefore: false, vulnerabilities: {}, auditLog: [], ignoreRules: [] };
  }

  private persist(): void {
    fs.writeFileSync(this.dbPath, JSON.stringify(this.data, null, 2), "utf8");
  }

  hasScannedBefore(): boolean {
    return this.data.hasScannedBefore;
  }

  markScannedOnce(): void {
    if (!this.data.hasScannedBefore) {
      this.data.hasScannedBefore = true;
      this.persist();
    }
  }

  getAllAsMap(): Map<string, Vulnerability> {
    return new Map(Object.entries(this.data.vulnerabilities));
  }

  getAll(): Vulnerability[] {
    return Object.values(this.data.vulnerabilities).sort((a, b) => a.file.localeCompare(b.file) || a.startLine - b.startLine);
  }

  get(id: string): Vulnerability | undefined {
    return this.data.vulnerabilities[id];
  }

  upsertMany(vulns: Vulnerability[]): void {
    for (const v of vulns) {
      this.data.vulnerabilities[v.id] = v;
    }
    this.persist();
  }

  update(id: string, patch: Partial<Vulnerability>): Vulnerability | undefined {
    const existing = this.data.vulnerabilities[id];
    if (!existing) return undefined;
    this.data.vulnerabilities[id] = { ...existing, ...patch };
    this.persist();
    return this.data.vulnerabilities[id];
  }

  addAuditEntry(action: string, detail: string): void {
    this.data.auditLog.push({ timestamp: new Date().toISOString(), action, detail });
    if (this.data.auditLog.length > 2000) this.data.auditLog.splice(0, this.data.auditLog.length - 2000);
    this.persist();
  }

  getAuditLog(): AuditEntry[] {
    return this.data.auditLog;
  }

  addIgnoreRule(rule: IgnoreRule): void {
    this.data.ignoreRules.push(rule);
    this.persist();
    this.syncIgnoreYml();
  }

  getIgnoreRules(): IgnoreRule[] {
    return this.data.ignoreRules;
  }

  private syncIgnoreYml(): void {
    const lines = [
      "# SecuGuard suppression rules — generated & maintained automatically.",
      "# Add a reason so future scans and teammates understand why a rule is suppressed here.",
      "suppressions:",
      ...this.data.ignoreRules.map(
        (r) => `  - rule: ${r.ruleId}\n    reason: "${r.reason.replace(/"/g, "'")}"\n    file: ${r.file ?? "*"}\n    created: ${r.createdAt}`
      ),
    ];
    fs.writeFileSync(this.ignoreYmlPath, lines.join("\n") + "\n", "utf8");
  }

  resetAll(): void {
    this.data = { version: DB_VERSION, hasScannedBefore: false, vulnerabilities: {}, auditLog: [], ignoreRules: [] };
    this.persist();
  }
}
