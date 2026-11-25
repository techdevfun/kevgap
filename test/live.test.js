import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(import.meta.url), "..", "..");
const CLI = join(ROOT, "dist", "cli.js");
const SNAPSHOT = join(ROOT, "data", "kev-snapshot.json");

const ENV = { ...process.env, KEVGAP_TODAY: "2026-11-25" };

function run(args, env = ENV) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", env });
}

/** Live network check. Returns true when the host is reachable. */
async function networkUp(url) {
  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(10_000),
    });
    return res.status < 500;
  } catch {
    return false;
  }
}

test("live: bundled snapshot provenance matches the live CISA KEV feed", async (t) => {
  const up = await networkUp(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  );
  if (!up) {
    t.skip("no network to cisa.gov from this sandbox");
    return;
  }
  const res = await fetch(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    { signal: AbortSignal.timeout(30_000) },
  );
  assert.equal(res.status, 200);
  const feed = await res.json();
  const snap = JSON.parse(readFileSync(SNAPSHOT, "utf8"));
  assert.equal(snap.catalogVersion, feed.catalogVersion);
  assert.equal(snap.entryCount, feed.vulnerabilities.length);
  const byId = Object.fromEntries(
    feed.vulnerabilities.map((v) => [v.cveID, v]),
  );
  const snapById = Object.fromEntries(
    snap.vulnerabilities.map((v) => [v.cveID, v]),
  );
  for (const cve of [
    "CVE-2026-16232",
    "CVE-2025-5777",
    "CVE-2024-21893",
    "CVE-2026-123158",
  ]) {
    assert.equal(snapById[cve].dateAdded, byId[cve].dateAdded, cve);
    assert.equal(snapById[cve].dueDate, byId[cve].dueDate, cve);
  }
});

test("live: explain CVE-2026-16232 returns the real KEV dates", () => {
  const r = run(["explain", "CVE-2026-16232"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /2026-07-22/);
  assert.match(r.stdout, /2026-07-25/);
  assert.match(r.stdout, /126/);
});

test("live: npm package name kevgap is still free (404)", async (t) => {
  const up = await networkUp("https://registry.npmjs.org/kevgap");
  if (!up) {
    t.skip("no network to registry.npmjs.org from this sandbox");
    return;
  }
  const res = await fetch("https://registry.npmjs.org/kevgap", {
    signal: AbortSignal.timeout(10_000),
  });
  assert.equal(res.status, 404);
});

test("live: org repo techdevfun/kevgap is still free (404, unauthenticated)", async (t) => {
  const up = await networkUp("https://api.github.com/repos/techdevfun/kevgap");
  if (!up) {
    t.skip("no network to api.github.com from this sandbox");
    return;
  }
  const res = await fetch("https://api.github.com/repos/techdevfun/kevgap", {
    headers: { "User-Agent": "kevgap-live-test" },
    signal: AbortSignal.timeout(10_000),
  });
  // 404 = free; 403 = unauthenticated rate limit, not evidence either way.
  if (res.status === 403) {
    t.skip("GitHub API rate-limited this unauthenticated probe (403)");
    return;
  }
  assert.equal(res.status, 404);
});

test("live: bundled snapshot has exactly the 8 fields per entry, no extras", () => {
  const snap = JSON.parse(readFileSync(SNAPSHOT, "utf8"));
  assert.equal(snap.entryCount, 1795);
  assert.equal(snap.vulnerabilities.length, 1795);
  const expected = [
    "cveID",
    "dateAdded",
    "dueDate",
    "knownRansomwareCampaignUse",
    "product",
    "shortDescription",
    "vendorProject",
    "vulnerabilityName",
  ];
  for (const v of snap.vulnerabilities) {
    assert.deepEqual(Object.keys(v).sort(), expected);
  }
});
