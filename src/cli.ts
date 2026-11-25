#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import {
  auditExitCode,
  checkExitCode,
  runAudit,
  TOOL_VERSION,
} from "./audit.js";
import { diffReports, loadBaseline, renderDiff } from "./diff.js";
import { explainQuery, renderExplain } from "./explain.js";
import { initScaffold } from "./init.js";
import { InputError } from "./inventory.js";
import { DEFAULT_FEED_URL, RefreshError, refreshSnapshot } from "./refresh.js";
import { renderCheck, renderTable } from "./report.js";
import { todayString } from "./dates.js";

const USAGE = `kevgap ${TOOL_VERSION} - measure the KEV exposure gap

Usage:
  kevgap init [dir]              scaffold kevgap.json + kevgap.config.json
  kevgap audit <inventory>       audit an inventory against the KEV snapshot
  kevgap check <inventory>       CI gate: exit 1 while anything is overdue
  kevgap diff --baseline <file> <inventory>
                                 compare exposure windows vs a previous audit
  kevgap explain <CVE-or-product>
                                 KEV dates and required action for a CVE or product
  kevgap refresh [--url <feed-url>]
                                 download the current CISA KEV feed

Options:
  --json             machine-readable output (audit, check, diff, explain)
  --save-baseline <file>
                     write the audit JSON to a file for later diff
  --fail-on-at-risk  check also fails on AT-RISK assets (due date in future)
  --help             show this help

Exit codes: 0 ok, 1 findings / gate failed, 2 input or network error.
audit, check, diff and explain are 100% local - only refresh uses the network.
`;

function fail(message: string): never {
  console.error(`kevgap: ${message}`);
  process.exit(2);
}

function parseFlags(args: string[]): {
  flags: Map<string, string | true>;
  rest: string[];
} {
  const flags = new Map<string, string | true>();
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json" || a === "--fail-on-at-risk" || a === "--help") {
      flags.set(a, true);
    } else if (a === "--save-baseline" || a === "--baseline" || a === "--url") {
      const next = args[i + 1];
      if (!next) fail(`${a} needs a value`);
      flags.set(a, next);
      i++;
    } else if (a.startsWith("--")) {
      fail(`unknown option: ${a}`);
    } else {
      rest.push(a);
    }
  }
  return { flags, rest };
}

function emitJson(obj: unknown): void {
  console.log(JSON.stringify(obj, null, 2));
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "--help") {
    console.log(USAGE);
    return 0;
  }
  const command = argv[0];
  const { flags, rest } = parseFlags(argv.slice(1));
  const json = flags.has("--json");

  try {
    if (command === "init") {
      const dir = rest[0] ?? ".";
      const result = initScaffold(dir);
      console.log(`created ${result.inventoryPath}`);
      console.log(`created ${result.configPath}`);
      console.log(
        "Next: edit kevgap.json (declare each asset status), then run: kevgap audit kevgap.json",
      );
      return 0;
    }

    if (command === "audit" || command === "check") {
      const inventory = rest[0];
      if (!inventory) fail(`${command} needs an inventory file`);
      const report = runAudit(inventory);
      const save = flags.get("--save-baseline");
      if (typeof save === "string") {
        writeFileSync(save, JSON.stringify(report, null, 2) + "\n", "utf8");
      }
      if (json) {
        emitJson(report);
      } else if (command === "check") {
        console.log(renderCheck(report));
      } else {
        console.log(renderTable(report));
      }
      if (command === "audit") return auditExitCode(report);
      return checkExitCode(report, flags.has("--fail-on-at-risk"));
    }

    if (command === "diff") {
      const baselinePath = flags.get("--baseline");
      if (typeof baselinePath !== "string")
        fail("diff needs --baseline <file>");
      const inventory = rest[0];
      if (!inventory) fail("diff needs an inventory file");
      const baseline = loadBaseline(baselinePath);
      const current = runAudit(inventory);
      const diff = diffReports(baseline, current);
      if (json) {
        emitJson({ ...diff, baseline: baseline.today, current: current.today });
      } else {
        console.log(renderDiff(diff));
      }
      return diff.regressions > 0 ? 1 : 0;
    }

    if (command === "explain") {
      const query = rest[0];
      if (!query) fail("explain needs a CVE id or a product name");
      const result = explainQuery(query);
      if (json) {
        emitJson(result);
      } else {
        console.log(renderExplain(result, todayString()));
      }
      return 0;
    }

    if (command === "refresh") {
      const url =
        typeof flags.get("--url") === "string"
          ? (flags.get("--url") as string)
          : DEFAULT_FEED_URL;
      try {
        const out = await refreshSnapshot(url);
        console.log(
          `refreshed KEV snapshot: catalog ${out.catalogVersion}, ${out.entryCount} entries, fetched ${out.fetchedAt}`,
        );
        return 0;
      } catch (err) {
        if (err instanceof RefreshError) fail(err.message);
        throw err;
      }
    }

    // Unknown command: show usage, exit 2.
    console.error(`kevgap: unknown command: ${command}`);
    console.log(USAGE);
    return 2;
  } catch (err) {
    if (err instanceof InputError) fail(err.message);
    if (err instanceof Error) fail(err.message);
    fail(String(err));
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    console.error(`kevgap: ${(err as Error).message}`);
    process.exitCode = 2;
  });
