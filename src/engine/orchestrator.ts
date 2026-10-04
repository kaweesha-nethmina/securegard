import * as path from "path";
import { RawFinding, ScannerAdapter, Vulnerability, VulnStatus } from "../types";
import { normalize } from "./normalizer";
import { Database } from "../storage/database";

export interface OrchestratorOptions {
  useSemgrep: boolean;
}

export interface ScanStageEvent {
  phase: "start" | "stage-start" | "stage-done" | "done";
  /** Human label for the current phase (scan label or scanner name). */
  label: string;
  /** 1-based index of the scanner being started; 0 for the start/done events. */
  index: number;
  total: number;
  /** Scanner names that will actually run — only sent with the `start` event. */
  scanners?: string[];
  filesScanned: number;
  durationMs: number;
}

/** Return `false` to stop the scan before the next stage runs. */
export type ScanStageListener = (event: ScanStageEvent) => boolean | void;

export interface ScanOutcome {
  vulnerabilities: Vulnerability[];
  stats: { filesScanned: number; durationMs: number; scannersRun: string[] };
  /** True when the listener aborted the run — nothing was written to the database. */
  aborted: boolean;
  /**
   * Findings this scan could no longer reproduce and therefore closed as fixed.
   * Only ever populated for full-workspace scans (see reconcileMissingFindings).
   */
  autoFixed: Vulnerability[];
}

/** Statuses that a re-scan is allowed to close automatically. */
const AUTO_FIXABLE: VulnStatus[] = ["open", "triaged", "todo"];

export class Orchestrator {
  private scanners: ScannerAdapter[] = [];

  constructor(scanners: ScannerAdapter[], private db: Database, private workspaceRoot: string) {
    this.scanners = scanners;
  }

  /**
   * Runs every available scanner in order, reporting each stage so the sidebar and
   * dashboard can animate progress. Aborting via the listener stops before anything
   * is persisted, so a cancelled scan never mutates the findings database.
   */
  async runScan(targetPaths: string[], onStage?: ScanStageListener): Promise<ScanOutcome> {
    const start = Date.now();
    const allFindings: RawFinding[] = [];
    const scannersRun: string[] = [];
    let filesScanned = 0;

    // Resolve availability up-front so the progress checklist can show every row
    // that will actually run (skipped scanners are simply absent).
    const runnable: ScannerAdapter[] = [];
    for (const scanner of this.scanners) {
      const available = await scanner.isAvailable().catch(() => false);
      if (available) runnable.push(scanner);
    }

    const base = { filesScanned: 0, durationMs: 0 };
    if (onStage?.({ phase: "start", label: "", index: 0, total: runnable.length, scanners: runnable.map((s) => s.name), ...base }) === false) {
      return { vulnerabilities: [], stats: { filesScanned: 0, durationMs: Date.now() - start, scannersRun: [] }, aborted: true, autoFixed: [] };
    }

    for (let i = 0; i < runnable.length; i++) {
      const scanner = runnable[i];
      const resume =
        onStage?.({
          phase: "stage-start",
          label: scanner.name,
          index: i + 1,
          total: runnable.length,
          filesScanned,
          durationMs: Date.now() - start,
        }) !== false;
      if (!resume) {
        return { vulnerabilities: [], stats: { filesScanned, durationMs: Date.now() - start, scannersRun }, aborted: true, autoFixed: [] };
      }

      const result = await scanner.scan(targetPaths, this.workspaceRoot);
      allFindings.push(...result.findings);
      filesScanned = Math.max(filesScanned, result.filesScanned);
      scannersRun.push(scanner.name);

      if (
        onStage?.({
          phase: "stage-done",
          label: scanner.name,
          index: i + 1,
          total: runnable.length,
          filesScanned,
          durationMs: Date.now() - start,
        }) === false
      ) {
        return { vulnerabilities: [], stats: { filesScanned, durationMs: Date.now() - start, scannersRun }, aborted: true, autoFixed: [] };
      }
    }

    const isFirstEverScan = !this.db.hasScannedBefore();
    const existing = this.db.getAllAsMap();
    const now = new Date().toISOString();
    const normalized = normalize(allFindings, existing, now, isFirstEverScan && this.db.baselineOnFirstRun);

    this.db.upsertMany(normalized);
    this.db.markScannedOnce();

    const autoFixed = this.reconcileMissingFindings(
      normalized,
      existing,
      scannersRun,
      now,
      this.isFullWorkspaceScan(targetPaths)
    );

    const stats = { filesScanned, durationMs: Date.now() - start, scannersRun };
    onStage?.({ phase: "done", label: "", index: runnable.length, total: runnable.length, filesScanned, durationMs: stats.durationMs });
    return { vulnerabilities: normalized, stats, aborted: false, autoFixed };
  }

  /**
   * True when this run covered the entire workspace. Partial scans (scan-current-file,
   * rescan-one-file, scan-on-save) only observe a slice of the tree, so a finding they
   * fail to reproduce proves nothing about the rest of the codebase.
   */
  private isFullWorkspaceScan(targetPaths: string[]): boolean {
    return (
      targetPaths.length === 1 &&
      path.resolve(targetPaths[0]) === path.resolve(this.workspaceRoot)
    );
  }

  /**
   * Closes findings that a full-workspace scan could not reproduce.
   *
   * `normalize()` only ever returns findings the scanners still see, so without this
   * step a resolved issue keeps its old `open` status forever and the dashboard never
   * clears it. Anything absent from a complete scan is treated as fixed.
   *
   * Two guards keep that from over-closing:
   *  - only `open`/`triaged`/`todo` are closed; deliberate dispositions
   *    (`fixed`, `false_positive`, `wont_fix`) are left exactly as the user set them
   *  - a finding is only closed when at least one scanner that reported it actually
   *    ran this time. If Semgrep was unavailable, its silence means nothing.
   */
  private reconcileMissingFindings(
    detected: Vulnerability[],
    existing: Map<string, Vulnerability>,
    scannersRun: string[],
    now: string,
    fullWorkspaceScan: boolean
  ): Vulnerability[] {
    if (!fullWorkspaceScan) return [];

    const ranScanners = new Set(scannersRun.map((s) => s.trim().toLowerCase()));
    const detectedIds = new Set(detected.map((v) => v.id));
    const closed: Vulnerability[] = [];

    for (const prior of existing.values()) {
      if (detectedIds.has(prior.id)) continue;
      if (!AUTO_FIXABLE.includes(prior.status)) continue;

      // sourceScanner can list several scanners that merged into one finding.
      const producers = String(prior.sourceScanner || "")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const stillObservable = producers.length === 0 || producers.some((s) => ranScanners.has(s));
      if (!stillObservable) continue;

      const updated = this.db.update(prior.id, {
        status: "fixed",
        statusHistory: [
          ...(prior.statusHistory ?? []),
          {
            status: "fixed" as VulnStatus,
            changedBy: "secuguard (auto)",
            changedAt: now,
            note: "Closed automatically — a full workspace re-scan no longer reproduces this finding.",
          },
        ],
      });
      if (updated) closed.push(updated);
    }

    return closed;
  }
}

