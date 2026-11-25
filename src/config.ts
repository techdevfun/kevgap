import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { KevConfig } from "./types.js";
import { InputError } from "./inventory.js";

export const DEFAULT_CONFIG: KevConfig = {
  graceDays: 0,
  warnBeforeDueDays: 7,
  snapshotMaxAgeDays: 90,
};

export const CONFIG_FILENAME = "kevgap.config.json";

/** Load kevgap.config.json next to the inventory, or the defaults. */
export function loadConfig(inventoryPath: string): KevConfig {
  const dir = inventoryPath.includes("/")
    ? inventoryPath.slice(0, inventoryPath.lastIndexOf("/")) || "."
    : ".";
  const file = join(dir, CONFIG_FILENAME);
  if (!existsSync(file)) return { ...DEFAULT_CONFIG };
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    throw new InputError(`config file is not valid JSON: ${file}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new InputError(`config file must be a JSON object: ${file}`);
  }
  const c = parsed as Record<string, unknown>;
  const config: KevConfig = { ...DEFAULT_CONFIG };
  for (const key of [
    "graceDays",
    "warnBeforeDueDays",
    "snapshotMaxAgeDays",
  ] as const) {
    if (c[key] !== undefined) {
      const v = c[key];
      if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
        throw new InputError(
          `config ${key} must be a non-negative integer: ${file}`,
        );
      }
      config[key] = v;
    }
  }
  return config;
}

/** Load a config from an explicit path (used by `init` output checks). */
export function loadConfigFile(path: string): KevConfig {
  if (!existsSync(path)) return { ...DEFAULT_CONFIG };
  return loadConfig(path.replace(/\/[^/]*$/, "/kevgap.json"));
}
