import { readFileSync } from "node:fs";
import { isValidDate } from "./dates.js";
import type { Asset, AssetStatus } from "./types.js";

const STATUSES: AssetStatus[] = ["patched", "unpatched", "unknown"];
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

export class InputError extends Error {}

/** Parse and strictly validate an inventory file. Throws InputError. */
export function loadInventory(path: string): Asset[] {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new InputError(`cannot read inventory file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new InputError(`inventory file is not valid JSON: ${path}`);
  }
  let items: unknown[];
  if (Array.isArray(parsed)) {
    items = parsed;
  } else if (
    parsed &&
    typeof parsed === "object" &&
    Array.isArray((parsed as { assets?: unknown }).assets)
  ) {
    // `kevgap init` writes an object with a "_note" and an "assets"
    // array so the template can carry a comment; accept that form too.
    items = (parsed as { assets: unknown[] }).assets;
  } else {
    throw new InputError(`inventory must be a JSON array of assets: ${path}`);
  }
  const seen = new Set<string>();
  return items.map((item, i) => validateAsset(item, i, seen));
}

function validateAsset(item: unknown, index: number, seen: Set<string>): Asset {
  const where = `asset[${index}]`;
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    throw new InputError(`${where}: each asset must be an object`);
  }
  const a = item as Record<string, unknown>;
  if (typeof a.id !== "string" || a.id.trim() === "") {
    throw new InputError(
      `${where}: "id" is required and must be a non-empty string`,
    );
  }
  if (seen.has(a.id)) {
    throw new InputError(`${where}: duplicate asset id "${a.id}"`);
  }
  seen.add(a.id);
  if (typeof a.vendor !== "string" || a.vendor.trim() === "") {
    throw new InputError(`${where} (${a.id}): "vendor" is required`);
  }
  if (typeof a.product !== "string" || a.product.trim() === "") {
    throw new InputError(`${where} (${a.id}): "product" is required`);
  }
  const status: AssetStatus =
    a.status === undefined ? "unknown" : (a.status as AssetStatus);
  if (
    typeof a.status !== "undefined" &&
    !STATUSES.includes(a.status as AssetStatus)
  ) {
    throw new InputError(
      `${where} (${a.id}): "status" must be patched, unpatched or unknown`,
    );
  }
  if (a.version !== undefined && typeof a.version !== "string") {
    throw new InputError(`${where} (${a.id}): "version" must be a string`);
  }
  if (a.patchedDate !== undefined) {
    if (typeof a.patchedDate !== "string" || !isValidDate(a.patchedDate)) {
      throw new InputError(
        `${where} (${a.id}): "patchedDate" must be a YYYY-MM-DD date`,
      );
    }
  }
  if (a.fixedInVersion !== undefined && typeof a.fixedInVersion !== "string") {
    throw new InputError(
      `${where} (${a.id}): "fixedInVersion" must be a string`,
    );
  }
  if (a.cves !== undefined) {
    if (
      !Array.isArray(a.cves) ||
      a.cves.some((c) => typeof c !== "string" || !CVE_RE.test(c))
    ) {
      throw new InputError(
        `${where} (${a.id}): "cves" must be an array of CVE ids like CVE-2026-16232`,
      );
    }
  }
  const asset: Asset = {
    id: a.id,
    vendor: a.vendor,
    product: a.product,
    status,
  };
  if (typeof a.version === "string") asset.version = a.version;
  if (typeof a.patchedDate === "string") asset.patchedDate = a.patchedDate;
  if (typeof a.fixedInVersion === "string")
    asset.fixedInVersion = a.fixedInVersion;
  if (Array.isArray(a.cves)) asset.cves = a.cves as string[];
  return asset;
}
