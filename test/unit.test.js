import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  addDays,
  daysBetween,
  formatDate,
  isValidDate,
  parseDate,
} from "../dist/dates.js";
import { normalize, productMatches } from "../dist/normalize.js";
import { findByCve, findByProduct, matchAsset } from "../dist/matcher.js";
import { verdictForAsset } from "../dist/verdict.js";
import { trimFeed } from "../dist/snapshot.js";
import { loadInventory, InputError } from "../dist/inventory.js";
import { loadConfig, DEFAULT_CONFIG } from "../dist/config.js";
import { diffReports } from "../dist/diff.js";

const CONFIG = { graceDays: 0, warnBeforeDueDays: 7, snapshotMaxAgeDays: 90 };

function entry(over = {}) {
  return {
    cveID: "CVE-2026-16232",
    vendorProject: "Check Point",
    product: "SmartConsole",
    vulnerabilityName: "Improper Authentication Vulnerability",
    dateAdded: "2026-07-22",
    dueDate: "2026-07-25",
    knownRansomwareCampaignUse: "Unknown",
    shortDescription: "Test fixture entry.",
    ...over,
  };
}

function asset(over = {}) {
  return {
    id: "a1",
    vendor: "Check Point",
    product: "SmartConsole",
    status: "unpatched",
    ...over,
  };
}

// ---------- date math ----------

test("daysBetween: same day is 0, forward and backward", () => {
  assert.equal(daysBetween("2026-07-22", "2026-07-22"), 0);
  assert.equal(daysBetween("2026-07-22", "2026-11-25"), 126);
  assert.equal(daysBetween("2026-11-25", "2026-07-22"), -126);
});

test("daysBetween: leap-year edge 2024-02-29 to 2024-03-01 is 1", () => {
  assert.equal(daysBetween("2024-02-29", "2024-03-01"), 1);
  assert.equal(daysBetween("2024-02-28", "2024-03-01"), 2);
});

test("daysBetween: year boundary and month boundary", () => {
  assert.equal(daysBetween("2025-12-31", "2026-01-01"), 1);
  assert.equal(daysBetween("2026-01-31", "2026-02-01"), 1);
  assert.equal(daysBetween("2026-07-25", "2026-11-25"), 123);
});

test("isValidDate rejects 2023-02-29, month 13, day 00, bad shape", () => {
  assert.equal(isValidDate("2023-02-29"), false);
  assert.equal(isValidDate("2024-02-29"), true);
  assert.equal(isValidDate("2026-13-01"), false);
  assert.equal(isValidDate("2026-01-00"), false);
  assert.equal(isValidDate("2026-1-1"), false);
  assert.equal(isValidDate("not-a-date"), false);
  assert.equal(isValidDate("2026-11-25"), true);
});

test("parseDate throws on invalid input; addDays crosses year", () => {
  assert.throws(() => parseDate("2026-02-30"), /invalid date/);
  assert.equal(addDays("2025-12-30", 3), "2026-01-02");
  assert.equal(addDays("2026-07-25", 0), "2026-07-25");
  assert.equal(formatDate(new Date(Date.UTC(2026, 10, 25))), "2026-11-25");
});

// ---------- normalizer / matcher ----------

test("normalize: case, punctuation, whitespace and 'and' are dropped", () => {
  assert.equal(normalize("NetScaler ADC and Gateway"), "netscaleradcgateway");
  assert.equal(normalize("netscaler-adc-and-gateway"), "netscaleradcgateway");
  assert.equal(normalize("  Check   Point  "), "checkpoint");
  assert.equal(
    normalize("Connect Secure, Policy Secure, and Neurons"),
    "connectsecurepolicysecureneurons",
  );
});

test("productMatches: short name matches the long KEV product name", () => {
  assert.equal(
    productMatches(
      "Citrix",
      "NetScaler",
      "Citrix",
      "NetScaler ADC and Gateway",
    ),
    true,
  );
  assert.equal(
    productMatches(
      "Ivanti",
      "Connect Secure",
      "Ivanti",
      "Connect Secure, Policy Secure, and Neurons",
    ),
    true,
  );
  assert.equal(
    productMatches(
      "Check Point",
      "SmartConsole",
      "Check Point",
      "SmartConsole",
    ),
    true,
  );
});

test("productMatches: different vendor or product does not match", () => {
  assert.equal(
    productMatches("Acme", "WidgetRouter", "Check Point", "SmartConsole"),
    false,
  );
  assert.equal(
    productMatches(
      "Check Point",
      "SmartConsole",
      "Citrix",
      "NetScaler ADC and Gateway",
    ),
    false,
  );
  assert.equal(
    productMatches("Check Point", "", "Check Point", "SmartConsole"),
    false,
  );
});

test("matchAsset: explicit cves match by id even when the name does not", () => {
  const catalog = [entry()];
  const a = asset({
    vendor: "Someone Else",
    product: "OtherThing",
    cves: ["CVE-2026-16232"],
  });
  const m = matchAsset(a, catalog);
  assert.equal(m.entries.length, 1);
  assert.equal(m.matchKinds.get("CVE-2026-16232"), "cve");
  assert.equal(m.ambiguous, false);
});

test("matchAsset: unknown CVE id in cves matches nothing", () => {
  const catalog = [entry()];
  const a = asset({ cves: ["CVE-2099-00001"] });
  const m = matchAsset(a, catalog);
  // Name matching still applies: same vendor+product as the entry.
  assert.equal(m.entries.length, 1);
  assert.equal(m.matchKinds.get("CVE-2026-16232"), "name");
});

test("matchAsset: ambiguous when the name is a substring of two KEV products", () => {
  const catalog = [
    entry({ cveID: "CVE-2026-00001", product: "SmartConsole" }),
    entry({ cveID: "CVE-2026-00002", product: "SmartConsole Cloud" }),
  ];
  // "Smart" matches both by contains, and neither exactly.
  const m = matchAsset(asset({ product: "Smart" }), catalog);
  assert.equal(m.ambiguous, true);
  assert.equal(m.candidates.length, 2);
  assert.equal(m.entries.length, 0);
});

test("matchAsset: an exact product name is not ambiguous even with longer siblings", () => {
  const catalog = [
    entry({ cveID: "CVE-2026-00001", product: "SmartConsole" }),
    entry({ cveID: "CVE-2026-00002", product: "SmartConsole Cloud" }),
  ];
  const m = matchAsset(asset(), catalog);
  assert.equal(m.ambiguous, false);
  assert.equal(m.entries.length, 1);
  assert.equal(m.entries[0].cveID, "CVE-2026-00001");
});

test("matchAsset: explicit cves clear ambiguity", () => {
  const catalog = [
    entry({ cveID: "CVE-2026-00001", product: "SmartConsole" }),
    entry({ cveID: "CVE-2026-00002", product: "SmartConsole Cloud" }),
  ];
  // "Smart" would be ambiguous by name alone; the explicit CVE pins it.
  const m = matchAsset(
    asset({ product: "Smart", cves: ["CVE-2026-00002"] }),
    catalog,
  );
  assert.equal(m.ambiguous, false);
  assert.ok(m.entries.some((e) => e.cveID === "CVE-2026-00002"));
  assert.equal(m.matchKinds.get("CVE-2026-00002"), "cve");
});

test("findByCve is case-insensitive; findByProduct finds by product text", () => {
  const catalog = [
    entry(),
    entry({
      cveID: "CVE-2025-5777",
      vendorProject: "Citrix",
      product: "NetScaler ADC and Gateway",
    }),
  ];
  assert.equal(findByCve("cve-2026-16232", catalog)?.product, "SmartConsole");
  assert.equal(findByCve("CVE-2099-00001", catalog), null);
  assert.equal(findByProduct("NetScaler", catalog).length, 1);
  assert.equal(findByProduct("NoSuchProduct", catalog).length, 0);
});

// ---------- verdict logic ----------

test("verdict: unpatched past due is EXPOSED with real window numbers", () => {
  const r = verdictForAsset(asset(), [entry()], CONFIG, "2026-11-25");
  assert.equal(r.verdict, "EXPOSED");
  assert.equal(r.matched[0].daysSinceAdded, 126);
  assert.equal(r.matched[0].daysPastDue, 123);
  assert.equal(r.matched[0].daysUntilDue, null);
});

test("verdict: unpatched before due is AT-RISK with days until due", () => {
  const r = verdictForAsset(asset(), [entry()], CONFIG, "2026-07-23");
  assert.equal(r.verdict, "AT-RISK");
  assert.equal(r.matched[0].daysUntilDue, 2);
  assert.equal(r.matched[0].daysPastDue, null);
});

test("verdict: on the due date itself is AT-RISK, not EXPOSED", () => {
  const r = verdictForAsset(asset(), [entry()], CONFIG, "2026-07-25");
  assert.equal(r.verdict, "AT-RISK");
  assert.equal(r.matched[0].daysUntilDue, 0);
});

test("verdict: patched with a date is SAFE and reports the closed window", () => {
  const r = verdictForAsset(
    asset({ status: "patched", patchedDate: "2026-11-13" }),
    [
      entry({
        cveID: "CVE-2026-123158",
        dateAdded: "2026-11-09",
        dueDate: "2026-11-12",
      }),
    ],
    CONFIG,
    "2026-11-25",
  );
  assert.equal(r.verdict, "SAFE");
  assert.equal(r.matched[0].closedWindowDays, 4);
  assert.equal(r.matched[0].patchedLateDays, 1);
});

test("verdict: patched on time reports patchedLateDays 0", () => {
  const r = verdictForAsset(
    asset({ status: "patched", patchedDate: "2026-07-24" }),
    [entry()],
    CONFIG,
    "2026-11-25",
  );
  assert.equal(r.verdict, "SAFE");
  assert.equal(r.matched[0].patchedLateDays, 0);
});

test("verdict: patched without a patchedDate is UNKNOWN, never SAFE", () => {
  const r = verdictForAsset(
    asset({ status: "patched" }),
    [entry()],
    CONFIG,
    "2026-11-25",
  );
  assert.equal(r.verdict, "UNKNOWN");
});

test("verdict: missing status defaults to UNKNOWN", () => {
  const a = { id: "a1", vendor: "Check Point", product: "SmartConsole" };
  const r = verdictForAsset(a, [entry()], CONFIG, "2026-11-25");
  assert.equal(r.verdict, "UNKNOWN");
  assert.equal(r.status, "unknown");
});

test("verdict: no KEV match is NOT-LISTED, not SAFE", () => {
  const r = verdictForAsset(
    asset({ vendor: "Acme", product: "WidgetRouter" }),
    [entry()],
    CONFIG,
    "2026-11-25",
  );
  assert.equal(r.verdict, "NOT-LISTED");
  assert.equal(r.matched.length, 0);
});

test("verdict: ambiguous match is UNKNOWN with candidates listed", () => {
  const catalog = [
    entry({ cveID: "CVE-2026-00001", product: "SmartConsole" }),
    entry({ cveID: "CVE-2026-00002", product: "SmartConsole Cloud" }),
  ];
  const r = verdictForAsset(
    asset({ product: "Smart" }),
    catalog,
    CONFIG,
    "2026-11-25",
  );
  assert.equal(r.verdict, "UNKNOWN");
  assert.equal(r.candidates?.length, 2);
});

test("verdict: worst entry wins - one EXPOSED beats one SAFE", () => {
  const catalog = [
    entry(),
    entry({
      cveID: "CVE-2025-5777",
      vendorProject: "Citrix",
      product: "NetScaler ADC and Gateway",
      dateAdded: "2025-07-10",
      dueDate: "2025-07-11",
    }),
  ];
  const a = asset({ cves: ["CVE-2026-16232", "CVE-2025-5777"] });
  const r = verdictForAsset(a, catalog, CONFIG, "2026-11-25");
  assert.equal(r.verdict, "EXPOSED");
  assert.equal(r.matched.length, 2);
});

test("verdict: grace-days shifts the gate but not the reported window", () => {
  const grace = { ...CONFIG, graceDays: 5 };
  const r = verdictForAsset(asset(), [entry()], grace, "2026-07-28");
  assert.equal(r.verdict, "AT-RISK");
  assert.equal(r.matched[0].daysPastDue, 3);
});

// ---------- snapshot trimming ----------

test("trimFeed keeps only the 8 fields and records provenance", () => {
  const feed = {
    catalogVersion: "2026.11.24",
    dateReleased: "2026-11-24T17:47:46.199Z",
    vulnerabilities: [
      {
        ...entry(),
        extraField: "dropped",
        cisaAction: "dropped too",
        notes: "x",
      },
    ],
  };
  const snap = trimFeed(feed, "2026-11-25");
  assert.equal(snap.catalogVersion, "2026.11.24");
  assert.equal(snap.entryCount, 1);
  assert.equal(snap.fetchedAt, "2026-11-25");
  assert.deepEqual(Object.keys(snap.vulnerabilities[0]).sort(), [
    "cveID",
    "dateAdded",
    "dueDate",
    "knownRansomwareCampaignUse",
    "product",
    "shortDescription",
    "vendorProject",
    "vulnerabilityName",
  ]);
});

test("trimFeed rejects a feed without a vulnerabilities array", () => {
  assert.throws(
    () => trimFeed({ catalogVersion: "x", dateReleased: "y" }, "2026-11-25"),
    /vulnerabilities/,
  );
});

// ---------- inventory + config validation ----------

function writeTmp(name, content) {
  const dir = mkdtempSync(join(tmpdir(), "kevgap-unit-"));
  const file = join(dir, name);
  writeFileSync(file, content);
  return file;
}

test("loadInventory accepts the init object form {assets: [...]}", () => {
  const file = writeTmp(
    "obj.json",
    JSON.stringify({ _note: "template comment", assets: [asset()] }),
  );
  const loaded = loadInventory(file);
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].id, "a1");
});

test("loadInventory rejects duplicate ids, bad status, bad date, bad CVE", () => {
  const dup = writeTmp("dup.json", JSON.stringify([asset(), asset()]));
  assert.throws(() => loadInventory(dup), /duplicate asset id/);
  const badStatus = writeTmp(
    "bad.json",
    JSON.stringify([asset({ status: "fixed" })]),
  );
  assert.throws(() => loadInventory(badStatus), /status/);
  const badDate = writeTmp(
    "badd.json",
    JSON.stringify([asset({ status: "patched", patchedDate: "2026-02-30" })]),
  );
  assert.throws(() => loadInventory(badDate), /patchedDate/);
  const badCve = writeTmp(
    "badc.json",
    JSON.stringify([asset({ cves: ["not-a-cve"] })]),
  );
  assert.throws(() => loadInventory(badCve), /cves/);
  const notArray = writeTmp("na.json", JSON.stringify({ id: "x" }));
  assert.throws(() => loadInventory(notArray), /array/);
  assert.throws(() => loadInventory("/nonexistent/kevgap.json"), InputError);
});

test("loadConfig defaults when no config file sits next to the inventory", () => {
  const inv = writeTmp("kevgap.json", JSON.stringify([asset()]));
  assert.deepEqual(loadConfig(inv), DEFAULT_CONFIG);
});

test("loadConfig reads grace-days and rejects a negative value", () => {
  const dir = mkdtempSync(join(tmpdir(), "kevgap-cfg-"));
  const inv = join(dir, "kevgap.json");
  writeFileSync(inv, JSON.stringify([asset()]));
  writeFileSync(
    join(dir, "kevgap.config.json"),
    JSON.stringify({ graceDays: 3 }),
  );
  assert.equal(loadConfig(inv).graceDays, 3);
  assert.equal(loadConfig(inv).warnBeforeDueDays, 7);
  writeFileSync(
    join(dir, "kevgap.config.json"),
    JSON.stringify({ graceDays: -1 }),
  );
  assert.throws(() => loadConfig(inv), /graceDays/);
});

// ---------- diff ----------

function reportFor(verdict, daysPastDue, today) {
  return {
    tool: "kevgap",
    version: "0.1.0",
    today,
    snapshot: {
      catalogVersion: "2026.11.24",
      dateReleased: "2026-11-24",
      fetchedAt: "2026-11-25",
      source: "x",
      entryCount: 1,
    },
    snapshotAgeDays: 1,
    snapshotStale: false,
    assets: [
      {
        id: "a1",
        vendor: "Check Point",
        product: "SmartConsole",
        version: null,
        status: "unpatched",
        patchedDate: null,
        verdict,
        reason: "test",
        matched: [
          {
            cveID: "CVE-2026-16232",
            vendorProject: "Check Point",
            product: "SmartConsole",
            vulnerabilityName: "x",
            dateAdded: "2026-07-22",
            dueDate: "2026-07-25",
            knownRansomwareCampaignUse: "Unknown",
            daysSinceAdded: 119,
            daysPastDue,
            daysUntilDue: daysPastDue === null ? 2 : null,
            closedWindowDays: null,
            patchedLateDays: null,
            matchKind: "name",
          },
        ],
      },
    ],
    summary: {
      exposed: 0,
      atRisk: 0,
      safe: 0,
      unknown: 0,
      notListed: 0,
      total: 1,
    },
  };
}

test("diff: newly overdue + growing window are regressions; closed gap is not", () => {
  const base = reportFor("AT-RISK", null, "2026-07-23");
  const cur = reportFor("EXPOSED", 123, "2026-11-25");
  const d = diffReports(base, cur);
  assert.ok(d.changes.some((c) => c.kind === "newly-overdue" && c.regression));
  assert.ok(d.changes.some((c) => c.kind === "window-growing" && c.regression));
  assert.equal(d.regressions, 2);
  const closed = reportFor("SAFE", null, "2026-11-25");
  const d2 = diffReports(cur, closed);
  assert.ok(d2.changes.some((c) => c.kind === "closed-gap" && !c.regression));
  assert.equal(d2.regressions, 0);
});

test("diff: identical reports produce no changes and no regressions", () => {
  const base = reportFor("EXPOSED", 116, "2026-11-18");
  const cur = reportFor("EXPOSED", 116, "2026-11-18");
  const d = diffReports(base, cur);
  assert.equal(d.changes.length, 0);
  assert.equal(d.regressions, 0);
});
