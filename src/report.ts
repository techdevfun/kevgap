import type { AssetResult, AuditReport } from "./types.js";

function pad(value: string, width: number): string {
  return value.length >= width
    ? value
    : value + " ".repeat(width - value.length);
}

export function renderTable(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`kevgap ${report.version} - KEV exposure gap audit`);
  lines.push(
    `snapshot: catalog ${report.snapshot.catalogVersion} released ${report.snapshot.dateReleased.slice(0, 10)} ` +
      `fetched ${report.snapshot.fetchedAt} (${report.snapshot.entryCount} entries, ${report.snapshotAgeDays} days old)`,
  );
  if (report.snapshotStale) {
    lines.push(
      `warning: snapshot is older than the configured max age - run 'kevgap refresh'`,
    );
  }
  lines.push(`today: ${report.today}`);
  lines.push("");
  lines.push(
    `${pad("ASSET", 22)} ${pad("VERDICT", 10)} ${pad("CVE", 18)} ${pad("WINDOW", 46)} STATUS`,
  );
  for (const asset of report.assets) {
    lines.push(...renderAsset(asset));
  }
  lines.push("");
  const s = report.summary;
  lines.push(
    `summary: ${s.exposed} EXPOSED, ${s.atRisk} AT-RISK, ${s.safe} SAFE, ${s.unknown} UNKNOWN, ${s.notListed} NOT-LISTED (${s.total} assets)`,
  );
  return lines.join("\n");
}

function renderAsset(asset: AssetResult): string[] {
  const lines: string[] = [];
  if (asset.matched.length === 0) {
    lines.push(
      `${pad(asset.id, 22)} ${pad(asset.verdict, 10)} ${pad("-", 18)} ${pad("no KEV entry names this product", 46)} ${asset.status}`,
    );
    return lines;
  }
  asset.matched.forEach((m, i) => {
    const window = windowText(asset, m);
    const first = i === 0;
    lines.push(
      `${pad(first ? asset.id : "", 22)} ${pad(first ? asset.verdict : "", 10)} ` +
        `${pad(m.cveID, 18)} ${pad(window, 46)} ${first ? asset.status : ""}`,
    );
  });
  if (
    asset.verdict === "UNKNOWN" &&
    asset.candidates &&
    asset.candidates.length > 0
  ) {
    lines.push(
      `  ambiguous match - candidates: ${asset.candidates.join("; ")}`,
    );
  }
  lines.push(`  reason: ${asset.reason}`);
  return lines;
}

function windowText(
  asset: AssetResult,
  m: {
    daysSinceAdded: number;
    daysPastDue: number | null;
    daysUntilDue: number | null;
    closedWindowDays: number | null;
    patchedLateDays: number | null;
  },
): string {
  if (asset.verdict === "SAFE" && m.closedWindowDays !== null) {
    const late =
      m.patchedLateDays !== null && m.patchedLateDays > 0
        ? `, patched ${m.patchedLateDays}d past due`
        : ", patched on time";
    return `closed ${m.closedWindowDays}d after listing${late}`;
  }
  if (m.daysPastDue !== null) {
    return `open ${m.daysSinceAdded}d, ${m.daysPastDue}d past due`;
  }
  if (m.daysUntilDue !== null) {
    return `open ${m.daysSinceAdded}d, due in ${m.daysUntilDue}d`;
  }
  return `open ${m.daysSinceAdded}d`;
}

/** Compact gate output for `check`: findings only, no full table. */
export function renderCheck(report: AuditReport): string {
  const lines: string[] = [];
  const s = report.summary;
  lines.push(
    `kevgap check - ${s.exposed} EXPOSED, ${s.atRisk} AT-RISK, ${s.safe} SAFE, ${s.unknown} UNKNOWN, ${s.notListed} NOT-LISTED (${s.total} assets)`,
  );
  lines.push(
    `snapshot: catalog ${report.snapshot.catalogVersion}, ${report.snapshotAgeDays} days old`,
  );
  for (const asset of report.assets) {
    if (asset.verdict !== "EXPOSED" && asset.verdict !== "AT-RISK") continue;
    let worstCve = "";
    let worstPast = -1;
    let worstUntil: number | null = null;
    for (const m of asset.matched) {
      const past = m.daysPastDue ?? 0;
      if (past > worstPast) {
        worstPast = past;
        worstCve = m.cveID;
        worstUntil = m.daysUntilDue;
      }
    }
    const detail =
      asset.verdict === "EXPOSED"
        ? `${worstCve} (${worstPast}d past due)`
        : `${worstCve} (due in ${worstUntil ?? 0}d)`;
    lines.push(`- ${asset.id} ${asset.verdict} ${detail}`);
  }
  if (s.exposed > 0) {
    lines.push(`GATE FAILED: ${s.exposed} asset(s) past their KEV due date.`);
  } else if (s.atRisk > 0) {
    lines.push(
      `GATE PASSED on due dates, but ${s.atRisk} asset(s) AT-RISK (due soon, unpatched).`,
    );
  } else {
    lines.push("GATE PASSED: nothing past its KEV due date.");
  }
  return lines.join("\n");
}
