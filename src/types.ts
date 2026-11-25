export type AssetStatus = "patched" | "unpatched" | "unknown";

export interface Asset {
  id: string;
  vendor: string;
  product: string;
  version?: string;
  status?: AssetStatus;
  patchedDate?: string;
  fixedInVersion?: string;
  cves?: string[];
}

export interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  shortDescription: string;
}

export interface SnapshotProvenance {
  catalogVersion: string;
  dateReleased: string;
  fetchedAt: string;
  source: string;
  entryCount: number;
}

export interface Snapshot extends SnapshotProvenance {
  vulnerabilities: KevEntry[];
}

export interface KevConfig {
  graceDays: number;
  warnBeforeDueDays: number;
  snapshotMaxAgeDays: number;
}

export type Verdict = "EXPOSED" | "AT-RISK" | "SAFE" | "UNKNOWN" | "NOT-LISTED";

export interface MatchedEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  daysSinceAdded: number;
  daysPastDue: number | null;
  daysUntilDue: number | null;
  closedWindowDays: number | null;
  patchedLateDays: number | null;
  matchKind: "name" | "cve";
}

export interface AssetResult {
  id: string;
  vendor: string;
  product: string;
  version: string | null;
  status: AssetStatus;
  patchedDate: string | null;
  verdict: Verdict;
  reason: string;
  matched: MatchedEntry[];
  candidates?: string[];
}

export interface AuditSummary {
  exposed: number;
  atRisk: number;
  safe: number;
  unknown: number;
  notListed: number;
  total: number;
}

export interface AuditReport {
  tool: string;
  version: string;
  today: string;
  snapshot: SnapshotProvenance;
  snapshotAgeDays: number;
  snapshotStale: boolean;
  assets: AssetResult[];
  summary: AuditSummary;
}
