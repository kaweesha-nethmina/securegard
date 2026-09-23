import { RawFinding, ScannerAdapter, Vulnerability } from "../types";
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
}

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
      return { vulnerabilities: [], stats: { filesScanned: 0, durationMs: Date.now() - start, scannersRun: [] }, aborted: true };
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
        return { vulnerabilities: [], stats: { filesScanned, durationMs: Date.now() - start, scannersRun }, aborted: true };
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
        return { vulnerabilities: [], stats: { filesScanned, durationMs: Date.now() - start, scannersRun }, aborted: true };
      }
    }

    const isFirstEverScan = !this.db.hasScannedBefore();
    const existing = this.db.getAllAsMap();
    const now = new Date().toISOString();
    const normalized = normalize(allFindings, existing, now, isFirstEverScan && this.db.baselineOnFirstRun);

    this.db.upsertMany(normalized);
    this.db.markScannedOnce();

    const stats = { filesScanned, durationMs: Date.now() - start, scannersRun };
    onStage?.({ phase: "done", label: "", index: runnable.length, total: runnable.length, filesScanned, durationMs: stats.durationMs });
    return { vulnerabilities: normalized, stats, aborted: false };
  }
}

