import { todayString } from "./dates.js";
import { loadConfig } from "./config.js";
import { loadInventory } from "./inventory.js";
import { loadSnapshot, snapshotAgeDays } from "./snapshot.js";
import { verdictForAsset } from "./verdict.js";
import type { AuditReport, AuditSummary, Snapshot } from "./types.js";

export const TOOL_VERSION = "0.1.0";

export interface AuditOptions {
  today?: string;
  snapshotPath?: string;
}

export function runAudit(
  inventoryPath: string,
  opts: AuditOptions = {},
): AuditReport {
  const today = opts.today ?? todayString();
  const assets = loadInventory(inventoryPath);
  const config = loadConfig(inventoryPath);
  const snap: Snapshot = loadSnapshot(opts.snapshotPath);
  const age = snapshotAgeDays(snap, today);
  const results = assets.map((a) =>
    verdictForAsset(a, snap.vulnerabilities, config, today),
  );
  const summary: AuditSummary = {
    exposed: 0,
    atRisk: 0,
    safe: 0,
    unknown: 0,
    notListed: 0,
    total: results.length,
  };
  for (const r of results) {
    if (r.verdict === "EXPOSED") summary.exposed++;
    else if (r.verdict === "AT-RISK") summary.atRisk++;
    else if (r.verdict === "SAFE") summary.safe++;
    else if (r.verdict === "UNKNOWN") summary.unknown++;
    else summary.notListed++;
  }
  return {
    tool: "kevgap",
    version: TOOL_VERSION,
    today,
    snapshot: {
      catalogVersion: snap.catalogVersion,
      dateReleased: snap.dateReleased,
      fetchedAt: snap.fetchedAt,
      source: snap.source,
      entryCount: snap.entryCount,
    },
    snapshotAgeDays: age,
    snapshotStale: age > config.snapshotMaxAgeDays,
    assets: results,
    summary,
  };
}

/** Exit code for `audit`: 1 when anything is EXPOSED, else 0. */
export function auditExitCode(report: AuditReport): number {
  return report.summary.exposed > 0 ? 1 : 0;
}

/** Exit code for `check`: 1 when anything is EXPOSED (or AT-RISK with the flag). */
export function checkExitCode(
  report: AuditReport,
  failOnAtRisk: boolean,
): number {
  if (report.summary.exposed > 0) return 1;
  if (failOnAtRisk && report.summary.atRisk > 0) return 1;
  return 0;
}
