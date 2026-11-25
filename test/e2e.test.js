import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(import.meta.url), "..", "..");
const CLI = join(ROOT, "dist", "cli.js");
const EXAMPLES = join(ROOT, "examples", "gt13-inventory.json");
const BASELINE = join(ROOT, "examples", "gt13-baseline.json");

// Pin "today" so the e2e numbers are deterministic; the demo GIF
// runs unpinned and shows the real 123-day value for 25/11.
const ENV = { ...process.env, KEVGAP_TODAY: "2026-11-25" };

function run(args, env = ENV) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", env });
}

function runJson(args, env = ENV) {
  const r = run(args, env);
  return { ...r, json: JSON.parse(r.stdout) };
}

test("e2e: audit on the GT13 fixture returns the real verdicts", () => {
  const { json, status } = runJson(["audit", EXAMPLES, "--json"]);
  assert.equal(json.snapshot.catalogVersion, "2026.11.24");
  assert.equal(json.snapshot.entryCount, 1795);
  assert.equal(json.today, "2026-11-25");
  const byId = Object.fromEntries(json.assets.map((a) => [a.id, a]));
  assert.equal(byId["cp-smartconsole-01"].verdict, "EXPOSED");
  assert.equal(byId["cp-smartconsole-01"].matched[0].cveID, "CVE-2026-16232");
  assert.equal(byId["cp-smartconsole-01"].matched[0].daysPastDue, 123);
  assert.equal(byId["cp-smartconsole-01"].matched[0].daysSinceAdded, 126);
  assert.equal(byId["citrix-netscaler-01"].verdict, "EXPOSED");
  assert.equal(byId["ivanti-connect-01"].verdict, "EXPOSED");
  assert.equal(byId["openssh-01"].verdict, "SAFE");
  assert.equal(byId["openssh-01"].matched[0].closedWindowDays, 4);
  assert.equal(byId["openssh-01"].matched[0].patchedLateDays, 1);
  assert.equal(byId["acme-router-01"].verdict, "NOT-LISTED");
  assert.equal(byId["mystery-01"].verdict, "UNKNOWN");
  assert.deepEqual(json.summary, {
    exposed: 3,
    atRisk: 0,
    safe: 1,
    unknown: 1,
    notListed: 1,
    total: 6,
  });
  assert.equal(status, 1);
});

test("e2e: audit human table shows the 123-day window and the snapshot line", () => {
  const r = run(["audit", EXAMPLES]);
  assert.match(r.stdout, /catalog 2026\.11\.24/);
  assert.match(r.stdout, /123d past due/);
  assert.match(
    r.stdout,
    /3 EXPOSED, 0 AT-RISK, 1 SAFE, 1 UNKNOWN, 1 NOT-LISTED/,
  );
  assert.equal(r.status, 1);
});

test("e2e: check exits 1 on the GT13 fixture, 0 on a clean inventory", () => {
  assert.equal(run(["check", EXAMPLES]).status, 1);
  const dir = mkdtempSync(join(tmpdir(), "kevgap-e2e-"));
  const clean = join(dir, "clean.json");
  writeFileSync(
    clean,
    JSON.stringify([
      {
        id: "x1",
        vendor: "OpenBSD",
        product: "OpenSSH",
        status: "patched",
        patchedDate: "2026-11-10",
      },
      {
        id: "x2",
        vendor: "Acme",
        product: "WidgetRouter",
        status: "unpatched",
      },
    ]),
  );
  assert.equal(run(["check", clean]).status, 0);
  assert.equal(run(["audit", clean]).status, 0);
});

test("e2e: check --fail-on-at-risk fails on a future-due unpatched asset", () => {
  const dir = mkdtempSync(join(tmpdir(), "kevgap-e2e-"));
  const inv = join(dir, "risk.json");
  // Pinned to a single CVE by id so no other OpenSSH KEV entry matches:
  // sshole listed 2026-11-09, due 2026-11-12.
  writeFileSync(
    inv,
    JSON.stringify([
      {
        id: "r1",
        vendor: "Acme",
        product: "WidgetRouter",
        status: "unpatched",
        cves: ["CVE-2026-123158"],
      },
    ]),
  );
  const env = { ...process.env, KEVGAP_TODAY: "2026-11-10" };
  const plain = run(["check", inv], env);
  assert.equal(plain.status, 0);
  assert.match(plain.stdout, /AT-RISK/);
  assert.equal(run(["check", "--fail-on-at-risk", inv], env).status, 1);
});

test("e2e: diff vs the GT13 baseline reports a growing window (regression)", () => {
  const r = run(["diff", "--baseline", BASELINE, EXAMPLES]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /window-growing/);
  assert.match(r.stdout, /regression\(s\)/);
  // openssh-01 is SAFE (patched): its closed window is history, so it
  // must not appear as a growing window.
  assert.doesNotMatch(r.stdout, /openssh-01/);
});

test("e2e: diff of an audit against its own baseline has no regressions", () => {
  const dir = mkdtempSync(join(tmpdir(), "kevgap-e2e-"));
  const base = join(dir, "base.json");
  const saved = run(["audit", EXAMPLES, "--json", "--save-baseline", base]);
  assert.equal(saved.status, 1);
  assert.ok(existsSync(base));
  const d = run(["diff", "--baseline", base, EXAMPLES]);
  assert.equal(d.status, 0);
  assert.match(d.stdout, /no regressions/);
});

test("e2e: explain CVE-2026-16232 returns the real KEV dates", () => {
  const r = run(["explain", "CVE-2026-16232"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /CVE-2026-16232/);
  assert.match(r.stdout, /2026-07-22/);
  assert.match(r.stdout, /2026-07-25/);
  assert.match(r.stdout, /123/);
  assert.match(r.stdout, /KEV does not carry fixed versions/);
});

test("e2e: explain answers 'not in KEV' for the *2Shell CVEs", () => {
  for (const cve of [
    "CVE-2026-123007",
    "CVE-2026-114938",
    "CVE-2026-129975",
    "CVE-2026-132825",
    "CVE-2026-123633",
  ]) {
    const r = run(["explain", cve]);
    assert.equal(r.status, 0, cve);
    assert.match(r.stdout, /not in CISA KEV/, cve);
  }
});

test("e2e: explain by product lists every KEV entry naming it", () => {
  const r = run(["explain", "SmartConsole"]);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /CVE-2026-16232/);
  const unknown = run(["explain", "NoSuchProductXYZ"]);
  assert.match(unknown.stdout, /not in CISA KEV/);
});

test("e2e: init scaffolds inventory + config that audit cleanly", () => {
  const dir = mkdtempSync(join(tmpdir(), "kevgap-e2e-"));
  const target = join(dir, "estate");
  const r = run(["init", target]);
  assert.equal(r.status, 0);
  assert.ok(existsSync(join(target, "kevgap.json")));
  assert.ok(existsSync(join(target, "kevgap.config.json")));
  const audit = run(["audit", join(target, "kevgap.json")]);
  // The template asset is unpatched SmartConsole: EXPOSED, exit 1.
  assert.equal(audit.status, 1);
  assert.match(audit.stdout, /smartconsole-01/);
});

test("e2e: bad inventory exits 2 with the exact field named", () => {
  const dir = mkdtempSync(join(tmpdir(), "kevgap-e2e-"));
  const bad = join(dir, "bad.json");
  writeFileSync(
    bad,
    JSON.stringify([
      {
        id: "b1",
        vendor: "X",
        product: "Y",
        status: "patched",
        patchedDate: "2026-02-30",
      },
    ]),
  );
  const r = run(["audit", bad]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /patchedDate/);
  const missing = run(["audit", join(dir, "nope.json")]);
  assert.equal(missing.status, 2);
});

test("e2e: unknown command and missing args exit 2", () => {
  assert.equal(run(["frobnicate"]).status, 2);
  assert.equal(run(["audit"]).status, 2);
  assert.equal(run(["explain"]).status, 2);
  assert.equal(run(["diff", EXAMPLES]).status, 2);
});

test("e2e: refresh against a local feed server replaces the snapshot", async () => {
  const { createServer } = await import("node:http");
  const { spawn } = await import("node:child_process");
  const feed = {
    catalogVersion: "2026.11.24",
    dateReleased: "2026-11-24T17:47:46.199Z",
    vulnerabilities: [
      {
        cveID: "CVE-2026-16232",
        vendorProject: "Check Point",
        product: "SmartConsole",
        vulnerabilityName: "Improper Authentication Vulnerability",
        dateAdded: "2026-07-22",
        dueDate: "2026-07-25",
        knownRansomwareCampaignUse: "Unknown",
        shortDescription: "Test feed entry.",
      },
    ],
  };
  const server = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(feed));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const dir = mkdtempSync(join(tmpdir(), "kevgap-e2e-"));
  const out = join(dir, "snap.json");
  const env = { ...process.env, KEVGAP_SNAPSHOT: out };
  // Async spawn (not spawnSync): the feed server lives in this process,
  // so the event loop must stay free to answer the CLI's request.
  const code = await new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [CLI, "refresh", "--url", `http://127.0.0.1:${port}/kev.json`],
      { env },
    );
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("error", reject);
    child.on("close", (c) => resolve(c));
    void stderr;
  });
  server.close();
  assert.equal(code, 0);
  const snap = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(snap.catalogVersion, "2026.11.24");
  assert.equal(snap.entryCount, 1);
  assert.equal(snap.vulnerabilities[0].cveID, "CVE-2026-16232");
  // No network in audit/check/diff/explain: the CLI source only calls
  // fetch in refresh.ts. Asserted statically here and in live tests.
  const refreshSrc = readFileSync(join(ROOT, "src", "refresh.ts"), "utf8");
  assert.match(refreshSrc, /fetch\(/);
  for (const f of [
    "audit.ts",
    "verdict.ts",
    "matcher.ts",
    "explain.ts",
    "diff.ts",
  ]) {
    assert.doesNotMatch(readFileSync(join(ROOT, "src", f), "utf8"), /fetch\(/);
  }
});
