/**
 * Normalizer for vendor / product matching.
 * Case-insensitive, punctuation- and whitespace-insensitive, so
 * "NetScaler ADC and Gateway", "netscaler-adc-and-gateway" and
 * "NetScaler" all reduce to comparable keys. "and" / "&" are dropped
 * as stop words because KEV product names vary in how they join parts.
 */

const STOP_WORDS = new Set(["and"]);

export function normalize(value: string): string {
  return value
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, " ")
    .split(" ")
    .filter((w) => w.length > 0 && !STOP_WORDS.has(w))
    .join("");
}

export function normalizeVendorProduct(
  vendor: string,
  product: string,
): string {
  return normalize(vendor) + "|" + normalize(product);
}

/**
 * True when the asset product names the same product as the KEV entry.
 * Exact normalized equality, or one side contains the other (covers
 * "NetScaler" vs "NetScaler ADC and Gateway" and "Connect Secure" vs
 * "Connect Secure, Policy Secure, and Neurons"). The vendor must match
 * by the same rule, or the asset vendor must be empty.
 */
export function productMatches(
  assetVendor: string,
  assetProduct: string,
  kevVendor: string,
  kevProduct: string,
): boolean {
  const av = normalize(assetVendor);
  const ap = normalize(assetProduct);
  const kv = normalize(kevVendor);
  const kp = normalize(kevProduct);
  if (ap.length === 0 || kp.length === 0) return false;
  const productOk = ap === kp || kp.includes(ap) || ap.includes(kp);
  if (!productOk) return false;
  if (av.length === 0) return true;
  return kv === av || kv.includes(av) || av.includes(kv);
}
