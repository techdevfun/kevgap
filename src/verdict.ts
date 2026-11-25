import { addDays, daysBetween } from "./dates.js";
import { matchAsset } from "./matcher.js";
import type {
  Asset,
  AssetResult,
  KevConfig,
  KevEntry,
  MatchedEntry,
  Verdict,
} from "./types.js";

const VERDICT_RANK: Record<Verdict, number> = {
  EXPOSED: 4,
  "AT-RISK": 3,
  UNKNOWN: 2,
  SAFE: 1,
  "NOT-LISTED": 0,
};

function entryVerdict(
  status: string,
  patchedDate: string | undefined,
  effectiveDue: string,
  today: string,
): { verdict: Verdict; reason: string } {
  if (status === "unknown") {
    return {
      verdict: "UNKNOWN",
      reason: "status is unknown; patch state not declared",
    };
  }
  if (status === "patched") {
    if (!patchedDate) {
      return {
        verdict: "UNKNOWN",
        reason: "status is patched but no patchedDate is given",
      };
    }
    return { verdict: "SAFE", reason: "patched" };
  }
  // unpatched
  if (daysBetween(today, effectiveDue) < 0) {
    return {
      verdict: "EXPOSED",
      reason: "unpatched and past the KEV due date",
    };
  }
  return {
    verdict: "AT-RISK",
    reason: "unpatched, KEV due date still in the future",
  };
}

function toMatched(
  entry: KevEntry,
  kind: "name" | "cve",
  status: string,
  patchedDate: string | undefined,
  today: string,
): MatchedEntry {
  const daysSinceAdded = daysBetween(entry.dateAdded, today);
  const rawPastDue = daysBetween(entry.dueDate, today);
  const daysPastDue = rawPastDue > 0 ? rawPastDue : null;
  const daysUntilDue = rawPastDue <= 0 ? Math.abs(rawPastDue) : null;
  let closedWindowDays: number | null = null;
  let patchedLateDays: number | null = null;
  if (status === "patched" && patchedDate) {
    closedWindowDays = daysBetween(entry.dateAdded, patchedDate);
    const late = daysBetween(entry.dueDate, patchedDate);
    patchedLateDays = late > 0 ? late : 0;
  }
  return {
    cveID: entry.cveID,
    vendorProject: entry.vendorProject,
    product: entry.product,
    vulnerabilityName: entry.vulnerabilityName,
    dateAdded: entry.dateAdded,
    dueDate: entry.dueDate,
    knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
    daysSinceAdded,
    daysPastDue,
    daysUntilDue,
    closedWindowDays,
    patchedLateDays,
    matchKind: kind,
  };
}

/**
 * Verdict for one asset. Worst KEV entry wins (EXPOSED > AT-RISK >
 * UNKNOWN > SAFE > NOT-LISTED). Patch status is operator-declared
 * only: kevgap never infers SAFE from a version number, and KEV
 * carries no fixed-version field, so `version` plays no part here.
 */
export function verdictForAsset(
  asset: Asset,
  catalog: KevEntry[],
  config: KevConfig,
  today: string,
): AssetResult {
  const status = asset.status ?? "unknown";
  const base: AssetResult = {
    id: asset.id,
    vendor: asset.vendor,
    product: asset.product,
    version: asset.version ?? null,
    status,
    patchedDate: asset.patchedDate ?? null,
    verdict: "NOT-LISTED",
    reason: "no KEV entry names this product",
    matched: [],
  };

  const match = matchAsset(asset, catalog);

  if (match.ambiguous) {
    base.verdict = "UNKNOWN";
    base.reason =
      "product name matches more than one KEV product; use cves to pin it down";
    base.candidates = match.candidates;
    base.matched = match.entries.map((e) =>
      toMatched(
        e,
        match.matchKinds.get(e.cveID) ?? "name",
        status,
        asset.patchedDate,
        today,
      ),
    );
    return base;
  }

  if (match.entries.length === 0) return base;

  let worst: Verdict = "NOT-LISTED";
  let worstReason = "";
  const matched: MatchedEntry[] = [];
  for (const entry of match.entries) {
    const effectiveDue = addDays(entry.dueDate, config.graceDays);
    const { verdict, reason } = entryVerdict(
      status,
      asset.patchedDate,
      effectiveDue,
      today,
    );
    matched.push(
      toMatched(
        entry,
        match.matchKinds.get(entry.cveID) ?? "name",
        status,
        asset.patchedDate,
        today,
      ),
    );
    if (VERDICT_RANK[verdict] > VERDICT_RANK[worst]) {
      worst = verdict;
      worstReason = reason;
    }
  }
  // daysPastDue/daysUntilDue in the matched rows are computed against
  // the real KEV due date; the grace-shifted date only gates the
  // verdict. State that in the reason when grace changes the outcome.
  if (config.graceDays > 0 && worst === "AT-RISK") {
    worstReason += ` (grace ${config.graceDays}d applied to the KEV due date)`;
  }
  base.verdict = worst;
  base.reason = worstReason;
  base.matched = matched;
  return base;
}
