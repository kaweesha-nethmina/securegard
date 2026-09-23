import { RawFinding, ScannerAdapter, Vulnerability } from "../types";
import { normalize } from "./normalizer";
import { Database } from "../storage/database";

export interface OrchestratorOptions {
  useSemgrep: boolean;
}

export class Orchestrator {
  private scanners: ScannerAdapter[] = [];

  constructor(scanners: ScannerAdapter[], private db: Database, private workspaceRoot: string) {
    this.scanners = scanners;
  }

  async runScan(targetPaths: string[]): Promise<{ vulnerabilities: Vulnerability[]; stats: { filesScanned: number; durationMs: number; scannersRun: string[] } }> {
    const start = Date.now();
    const allFindings: RawFinding[] = [];
    const scannersRun: string[] = [];
    let filesScanned = 0;

    for (const scanner of this.scanners) {
      const available = await scanner.isAvailable().catch(() => false);
      if (!available) continue;
      const result = await scanner.scan(targetPaths, this.workspaceRoot);
      allFindings.push(...result.findings);
      filesScanned = Math.max(filesScanned, result.filesScanned);
      scannersRun.push(scanner.name);
    }

    const isFirstEverScan = !this.db.hasScannedBefore();
    const existing = this.db.getAllAsMap();
    const now = new Date().toISOString();
    const normalized = normalize(allFindings, existing, now, isFirstEverScan && this.db.baselineOnFirstRun);

    this.db.upsertMany(normalized);
    this.db.markScannedOnce();

    return {
      vulnerabilities: normalized,
      stats: { filesScanned, durationMs: Date.now() - start, scannersRun },
    };
  }
}
