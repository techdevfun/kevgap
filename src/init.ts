import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { CONFIG_FILENAME, DEFAULT_CONFIG } from "./config.js";

export interface InitResult {
  inventoryPath: string;
  configPath: string;
  created: boolean;
}

const INVENTORY_TEMPLATE = `{
  "_note": "kevgap inventory. status is OPERATOR-DECLARED: patched, unpatched or unknown (default). kevgap never infers patch status from version numbers, and KEV carries no fixed-version field. Add one object per asset. Example asset below is the GT13 Check Point SmartConsole case.",
  "assets": [
    {
      "id": "smartconsole-01",
      "vendor": "Check Point",
      "product": "SmartConsole",
      "version": "R81.20",
      "status": "unpatched"
    }
  ]
}
`;

/** Scaffold kevgap.json + kevgap.config.json in a directory. */
export function initScaffold(dir: string): InitResult {
  const target = dir || ".";
  mkdirSync(target, { recursive: true });
  const inventoryPath = join(target, "kevgap.json");
  const configPath = join(target, CONFIG_FILENAME);
  const created = !existsSync(inventoryPath) && !existsSync(configPath);
  if (!existsSync(inventoryPath)) {
    writeFileSync(inventoryPath, INVENTORY_TEMPLATE, "utf8");
  }
  if (!existsSync(configPath)) {
    writeFileSync(
      configPath,
      JSON.stringify(DEFAULT_CONFIG, null, 2) + "\n",
      "utf8",
    );
  }
  return { inventoryPath, configPath, created };
}
