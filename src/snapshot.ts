import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { daysBetween } from "./dates.js";
import type { KevEntry, Snapshot, SnapshotProvenance } from "./types.js";

export const SNAPSHOT_FIELDS = [
  "cveID",
  "vendorProject",
  "product",
  "vulnerabilityName",
  "dateAdded",
  "dueDate",
  "knownRansomwareCampaignUse",
  "shortDescription",
] as const;

export function snapshotPath(): string {
  const override = process.env.KEVGAP_SNAPSHOT;
  if (override) return override;
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "data", "kev-snapshot.json");
}

export function loadSnapshot(path?: string): Snapshot {
  const file = path ?? snapshotPath();
  let raw: string;
  try {
    raw = readFileSync(file, "utf8");
  } catch {
    throw new Error(
      `cannot read KEV snapshot: ${file} (run 'kevgap refresh' to fetch it)`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`KEV snapshot is not valid JSON: ${file}`);
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    !Array.isArray((parsed as Snapshot).vulnerabilities)
  ) {
    throw new Error(`KEV snapshot has no vulnerabilities array: ${file}`);
  }
  const snap = parsed as Snapshot;
  return snap;
}

export function snapshotAgeDays(snap: Snapshot, today: string): number {
  const released = snap.dateReleased.slice(0, 10);
  return daysBetween(released, today);
}

/** Trim a raw CISA KEV feed object to the 8 fields kevgap reads. */
export function trimFeed(feed: unknown, fetchedAt: string): Snapshot {
  if (!feed || typeof feed !== "object") {
    throw new Error("KEV feed is not a JSON object");
  }
  const f = feed as {
    catalogVersion?: unknown;
    dateReleased?: unknown;
    vulnerabilities?: unknown;
  };
  if (
    typeof f.catalogVersion !== "string" ||
    typeof f.dateReleased !== "string"
  ) {
    throw new Error("KEV feed is missing catalogVersion or dateReleased");
  }
  if (!Array.isArray(f.vulnerabilities)) {
    throw new Error("KEV feed is missing the vulnerabilities array");
  }
  const vulnerabilities: KevEntry[] = f.vulnerabilities.map((v) => {
    const e = v as Record<string, unknown>;
    const out: Record<string, string> = {};
    for (const field of SNAPSHOT_FIELDS) {
      const value = e[field];
      out[field] = typeof value === "string" ? value : "";
    }
    return out as unknown as KevEntry;
  });
  const provenance: SnapshotProvenance = {
    catalogVersion: f.catalogVersion,
    dateReleased: f.dateReleased,
    fetchedAt,
    source:
      "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    entryCount: vulnerabilities.length,
  };
  return { ...provenance, vulnerabilities };
}

export function writeSnapshot(snap: Snapshot, path?: string): void {
  const file = path ?? snapshotPath();
  writeFileSync(file, JSON.stringify(snap, null, 2) + "\n", "utf8");
}
