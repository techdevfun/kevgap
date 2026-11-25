import { readFileSync } from "node:fs";
import { InputError } from "./inventory.js";
import type { AuditReport } from "./types.js";

export interface DiffChange {
  assetId: string;
  kind:
    | "newly-overdue"
    | "newly-listed"
    | "closed-gap"
    | "window-growing"
    | "window-shrinking"
    | "new-asset"
    | "removed-asset";
  detail: string;
  regression: boolean;
}

export interface DiffReport {
  baselineToday: string;
  today: string;
  changes: DiffChange[];
  regressions: number;
}

/** Load a baseline file: the JSON output of a previous `audit --json`. */
export function loadBaseline(path: string): AuditReport {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new InputError(`cannot read baseline file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new InputError(`baseline file is not valid JSON: ${path}`);
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as AuditReport).tool !== "kevgap"
  ) {
    throw new InputError(`baseline is not a kevgap audit JSON file: ${path}`);
  }
  const report = parsed as AuditReport;
  if (!Array.isArray(report.assets)) {
    throw new InputError(`baseline has no assets array: ${path}`);
  }
  return report;
}

function worstDaysPastDue(asset: AuditReport["assets"][number]): number {
  let worst = 0;
  for (const m of asset.matched) {
    if (m.daysPastDue !== null && m.daysPastDue > worst) worst = m.daysPastDue;
  }
  return worst;
}

function worstDaysOpen(asset: AuditReport["assets"][number]): number {
  let worst = 0;
  for (const m of asset.matched) {
    if (m.daysSinceAdded > worst) worst = m.daysSinceAdded;
  }
  return worst;
}

export function diffReports(
  baseline: AuditReport,
  current: AuditReport,
): DiffReport {
  const changes: DiffChange[] = [];
  const baseById = new Map(baseline.assets.map((a) => [a.id, a]));
  const currentById = new Map(current.assets.map((a) => [a.id, a]));

  for (const asset of current.assets) {
    const base = baseById.get(asset.id);
    if (!base) {
      changes.push({
        assetId: asset.id,
        kind: "new-asset",
        detail: `new asset in inventory (verdict ${asset.verdict})`,
        regression: asset.verdict === "EXPOSED",
      });
      continue;
    }
    const baseCves = new Set(base.matched.map((m) => m.cveID));
    for (const m of asset.matched) {
      if (!baseCves.has(m.cveID)) {
        changes.push({
          assetId: asset.id,
          kind: "newly-listed",
          detail: `${m.cveID} is a new KEV entry for this asset (listed ${m.dateAdded}, due ${m.dueDate})`,
          regression:
            asset.verdict === "EXPOSED" || asset.verdict === "AT-RISK",
        });
      }
    }
    if (base.verdict !== "EXPOSED" && asset.verdict === "EXPOSED") {
      changes.push({
        assetId: asset.id,
        kind: "newly-overdue",
        detail: `now EXPOSED (was ${base.verdict}); past the KEV due date`,
        regression: true,
      });
    }
    if (
      (base.verdict === "EXPOSED" || base.verdict === "AT-RISK") &&
      asset.verdict === "SAFE"
    ) {
      changes.push({
        assetId: asset.id,
        kind: "closed-gap",
        detail: `gap closed (was ${base.verdict}, now SAFE)`,
        regression: false,
      });
    }
    // Window deltas only apply while the gap is still open. A SAFE
    // asset's closed window is historical fact (patchedDate minus
    // dateAdded); its "days past due" number grows with the calendar
    // even though nothing is getting worse, so it must not count as
    // a growing window.
    const windowApplies = asset.verdict !== "SAFE" && base.verdict !== "SAFE";
    const basePast = worstDaysPastDue(base);
    const curPast = worstDaysPastDue(asset);
    if (!windowApplies) {
      // Closed gaps are reported above; their windows do not move.
    } else if (curPast > basePast) {
      changes.push({
        assetId: asset.id,
        kind: "window-growing",
        detail: `worst exposure window grew from ${basePast}d to ${curPast}d past due`,
        regression: true,
      });
    } else if (curPast < basePast && curPast > 0) {
      changes.push({
        assetId: asset.id,
        kind: "window-shrinking",
        detail: `worst exposure window shrank from ${basePast}d to ${curPast}d past due`,
        regression: false,
      });
    } else if (basePast === 0 && curPast === 0) {
      const baseOpen = worstDaysOpen(base);
      const curOpen = worstDaysOpen(asset);
      if (curOpen > baseOpen) {
        changes.push({
          assetId: asset.id,
          kind: "window-growing",
          detail: `open window grew from ${baseOpen}d to ${curOpen}d since listing`,
          regression: false,
        });
      } else if (curOpen < baseOpen) {
        changes.push({
          assetId: asset.id,
          kind: "window-shrinking",
          detail: `open window shrank from ${baseOpen}d to ${curOpen}d since listing`,
          regression: false,
        });
      }
    }
  }

  for (const asset of baseline.assets) {
    if (!currentById.has(asset.id)) {
      changes.push({
        assetId: asset.id,
        kind: "removed-asset",
        detail: "asset no longer in the inventory",
        regression: false,
      });
    }
  }

  return {
    baselineToday: baseline.today,
    today: current.today,
    changes,
    regressions: changes.filter((c) => c.regression).length,
  };
}

export function renderDiff(diff: DiffReport): string {
  const lines: string[] = [];
  lines.push(`kevgap diff - baseline ${diff.baselineToday} vs ${diff.today}`);
  if (diff.changes.length === 0) {
    lines.push("no changes: exposure windows are unchanged.");
  } else {
    for (const c of diff.changes) {
      lines.push(`- [${c.kind}] ${c.assetId}: ${c.detail}`);
    }
  }
  lines.push(
    diff.regressions > 0
      ? `diff: ${diff.regressions} regression(s) - exposure is growing or newly overdue.`
      : "diff: no regressions.",
  );
  return lines.join("\n");
}
