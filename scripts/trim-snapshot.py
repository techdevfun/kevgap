#!/usr/bin/env python3
"""Trim a raw CISA KEV feed JSON to the 8 fields kevgap reads.

Usage: python3 scripts/trim-snapshot.py <feed.json> [out.json]

Verifies catalogVersion 2026.11.24, 1,795 entries, and the four CVE
rows the blueprint pins (CVE-2026-16232, CVE-2025-5777,
CVE-2024-21893, CVE-2026-123158) before writing anything.
"""
import hashlib
import json
import sys

FIELDS = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "dueDate",
    "knownRansomwareCampaignUse",
    "shortDescription",
]

EXPECTED = {
    "CVE-2026-16232": ("2026-07-22", "2026-07-25"),
    "CVE-2025-5777": ("2025-07-10", "2025-07-11"),
    "CVE-2024-21893": ("2024-01-31", "2024-02-02"),
    "CVE-2026-123158": ("2026-11-09", "2026-11-12"),
}

NOT_IN_KEV = [
    "CVE-2026-123007",
    "CVE-2026-114938",
    "CVE-2026-129975",
    "CVE-2026-132825",
    "CVE-2026-123633",
]


def main() -> int:
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "data/kev-snapshot.json"
    raw = open(src, "rb").read()
    print(f"feed sha256: {hashlib.sha256(raw).hexdigest()}")
    feed = json.loads(raw)
    assert feed["catalogVersion"] == "2026.11.24", feed["catalogVersion"]
    vulns = feed["vulnerabilities"]
    assert len(vulns) == 1795, len(vulns)
    by_id = {v["cveID"]: v for v in vulns}
    for cve, (added, due) in EXPECTED.items():
        row = by_id[cve]
        assert row["dateAdded"] == added and row["dueDate"] == due, (cve, row)
    for cve in NOT_IN_KEV:
        assert cve not in by_id, f"{cve} unexpectedly in KEV"
    trimmed = {
        "catalogVersion": feed["catalogVersion"],
        "dateReleased": feed["dateReleased"],
        "fetchedAt": "2026-11-25",
        "source": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "entryCount": len(vulns),
        "vulnerabilities": [{k: v.get(k, "") for k in FIELDS} for v in vulns],
    }
    with open(out, "w") as f:
        json.dump(trimmed, f, indent=2)
        f.write("\n")
    print(f"wrote {out}: catalog {trimmed['catalogVersion']}, {trimmed['entryCount']} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
