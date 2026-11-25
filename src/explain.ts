import { daysBetween } from "./dates.js";
import { findByCve, findByProduct } from "./matcher.js";
import { loadSnapshot } from "./snapshot.js";
import type { KevEntry, Snapshot } from "./types.js";

export interface ExplainResult {
  found: boolean;
  kind: "cve" | "product" | "none";
  entry?: KevEntry;
  entries?: KevEntry[];
  query: string;
  catalogVersion: string;
}

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

export function explainQuery(query: string, snap?: Snapshot): ExplainResult {
  const snapshot = snap ?? loadSnapshot();
  const q = query.trim();
  if (CVE_RE.test(q)) {
    const entry = findByCve(q, snapshot.vulnerabilities);
    if (!entry) {
      return {
        found: false,
        kind: "none",
        query: q,
        catalogVersion: snapshot.catalogVersion,
      };
    }
    return {
      found: true,
      kind: "cve",
      entry,
      query: q,
      catalogVersion: snapshot.catalogVersion,
    };
  }
  const entries = findByProduct(q, snapshot.vulnerabilities);
  if (entries.length === 0) {
    return {
      found: false,
      kind: "none",
      query: q,
      catalogVersion: snapshot.catalogVersion,
    };
  }
  return {
    found: true,
    kind: "product",
    entries,
    query: q,
    catalogVersion: snapshot.catalogVersion,
  };
}

export function renderExplain(result: ExplainResult, today: string): string {
  const lines: string[] = [];
  if (!result.found) {
    lines.push(
      `${result.query} is not in CISA KEV (catalog ${result.catalogVersion}).`,
    );
    lines.push(
      "That means no KEV-listed vulnerability names it - it does not mean the product is safe.",
    );
    lines.push(
      "KEV only lists vulnerabilities known to be exploited in the wild.",
    );
    return lines.join("\n");
  }
  if (result.kind === "cve" && result.entry) {
    const e = result.entry;
    lines.push(`${e.cveID} - ${e.vulnerabilityName}`);
    lines.push(`vendor: ${e.vendorProject}`);
    lines.push(`product: ${e.product}`);
    lines.push(`KEV listed: ${e.dateAdded} (due ${e.dueDate})`);
    lines.push(`days since listing: ${daysBetween(e.dateAdded, today)}`);
    const pastDue = daysBetween(e.dueDate, today);
    lines.push(
      pastDue > 0
        ? `days past KEV due date: ${pastDue}`
        : `days until KEV due date: ${-pastDue}`,
    );
    lines.push(`known ransomware use: ${e.knownRansomwareCampaignUse}`);
    lines.push(`required action: ${e.shortDescription}`);
    lines.push(
      "Note: KEV does not carry fixed versions, so kevgap cannot tell from KEV alone whether a version is patched. Patch status is operator-declared.",
    );
    lines.push(
      "Note: KEV due dates are the federal-agency deadlines from CISA BOD 19-02; your own SLA may differ (see grace-days in kevgap.config.json).",
    );
    return lines.join("\n");
  }
  const entries = result.entries ?? [];
  lines.push(
    `${entries.length} KEV ${entries.length === 1 ? "entry" : "entries"} name "${result.query}":`,
  );
  for (const e of entries) {
    lines.push(
      `- ${e.cveID} - ${e.vulnerabilityName} (listed ${e.dateAdded}, due ${e.dueDate})`,
    );
  }
  return lines.join("\n");
}
