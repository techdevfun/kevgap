import { formatDate } from "./dates.js";
import { trimFeed, writeSnapshot } from "./snapshot.js";

export const DEFAULT_FEED_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export class RefreshError extends Error {}

/**
 * Download the current CISA KEV feed and replace the bundled snapshot.
 * Only this command touches the network. Offline or a bad feed exits 2
 * with a clear message; the old snapshot is never silently overwritten
 * with stale or partial data.
 */
export async function refreshSnapshot(
  url: string,
  outPath?: string,
): Promise<{
  catalogVersion: string;
  entryCount: number;
  fetchedAt: string;
}> {
  let res: Response;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  } catch (err) {
    throw new RefreshError(
      `cannot reach the KEV feed at ${url}: ${(err as Error).message}. Check your network and try again; the bundled snapshot was not changed.`,
    );
  }
  if (!res.ok) {
    throw new RefreshError(
      `KEV feed returned HTTP ${res.status} for ${url}; the bundled snapshot was not changed.`,
    );
  }
  let feed: unknown;
  try {
    feed = await res.json();
  } catch {
    throw new RefreshError(
      "KEV feed did not return valid JSON; the bundled snapshot was not changed.",
    );
  }
  const fetchedAt = formatDate(new Date());
  const snap = trimFeed(feed, fetchedAt);
  writeSnapshot(snap, outPath);
  return {
    catalogVersion: snap.catalogVersion,
    entryCount: snap.entryCount,
    fetchedAt,
  };
}
