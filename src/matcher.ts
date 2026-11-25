import { normalize } from "./normalize.js";
import type { Asset, KevEntry } from "./types.js";

export interface MatchResult {
  entries: KevEntry[];
  matchKinds: Map<string, "name" | "cve">;
  ambiguous: boolean;
  candidates: string[];
}

interface PreparedEntry {
  entry: KevEntry;
  vendor: string;
  product: string;
}

interface PreparedCatalog {
  byCve: Map<string, KevEntry>;
  byProduct: Map<string, PreparedEntry[]>;
  all: PreparedEntry[];
}

// One prepared index per catalog array, cached so a 500-asset audit
// normalizes the 1,795-entry catalog once instead of once per asset.
const preparedCache = new WeakMap<KevEntry[], PreparedCatalog>();

function prepareCatalog(catalog: KevEntry[]): PreparedCatalog {
  const cached = preparedCache.get(catalog);
  if (cached) return cached;
  const byCve = new Map<string, KevEntry>();
  const byProduct = new Map<string, PreparedEntry[]>();
  const all: PreparedEntry[] = [];
  for (const entry of catalog) {
    byCve.set(entry.cveID.toUpperCase(), entry);
    const prepared: PreparedEntry = {
      entry,
      vendor: normalize(entry.vendorProject),
      product: normalize(entry.product),
    };
    all.push(prepared);
    const list = byProduct.get(prepared.product);
    if (list) list.push(prepared);
    else byProduct.set(prepared.product, [prepared]);
  }
  const preparedCatalog = { byCve, byProduct, all };
  preparedCache.set(catalog, preparedCatalog);
  return preparedCatalog;
}

function vendorMatches(assetVendor: string, kevVendor: string): boolean {
  if (assetVendor.length === 0) return true;
  return (
    kevVendor === assetVendor ||
    kevVendor.includes(assetVendor) ||
    assetVendor.includes(kevVendor)
  );
}

/**
 * Match one asset against the KEV catalog.
 *
 * - By explicit CVE id in the asset's `cves` list (exact id match).
 * - By normalized vendor + product (see normalize.ts).
 * - Ambiguous when name matching spans two or more distinct KEV
 *   products and no explicit CVE list pins the match down. Explicit
 *   CVE ids always win over name matching and clear ambiguity.
 */
export function matchAsset(asset: Asset, catalog: KevEntry[]): MatchResult {
  const prepared = prepareCatalog(catalog);
  const matched = new Map<string, KevEntry>();
  const kinds = new Map<string, "name" | "cve">();

  const explicit = (asset.cves ?? []).map((c) => c.trim().toUpperCase());
  for (const cve of explicit) {
    const entry = prepared.byCve.get(cve);
    if (entry) {
      matched.set(entry.cveID, entry);
      kinds.set(entry.cveID, "cve");
    }
  }

  // Name matching, in two tiers. An exact normalized product match
  // wins outright: KEV lists the same product under several long
  // names ("Connect Secure" and "Connect Secure, Policy Secure, and
  // Neurons"), and a short asset name must not be called ambiguous
  // just because it is a substring of a longer sibling. Only when no
  // exact product exists do we fall back to contains-matching, and
  // only a single distinct product there counts as a match.
  const assetVendor = normalize(asset.vendor);
  const assetProduct = normalize(asset.product);
  const exactHits: KevEntry[] = [];
  const exactBucket = prepared.byProduct.get(assetProduct) ?? [];
  for (const p of exactBucket) {
    if (vendorMatches(assetVendor, p.vendor)) exactHits.push(p.entry);
  }
  let nameHits: KevEntry[];
  if (exactHits.length > 0) {
    nameHits = exactHits;
  } else {
    const containsHits: KevEntry[] = [];
    for (const p of prepared.all) {
      if (assetProduct.length === 0 || p.product.length === 0) continue;
      const productOk =
        p.product === assetProduct ||
        p.product.includes(assetProduct) ||
        assetProduct.includes(p.product);
      if (productOk && vendorMatches(assetVendor, p.vendor)) {
        containsHits.push(p.entry);
      }
    }
    nameHits = containsHits;
  }

  // Distinct normalized products among the name hits.
  const distinctProducts = new Set(nameHits.map((e) => normalize(e.product)));
  const ambiguous = explicit.length === 0 && distinctProducts.size > 1;

  if (!ambiguous) {
    for (const entry of nameHits) {
      if (!matched.has(entry.cveID)) {
        matched.set(entry.cveID, entry);
        kinds.set(entry.cveID, "name");
      }
    }
  }

  const candidates = [...distinctProducts].map((p) => {
    const hit = nameHits.find((e) => normalize(e.product) === p);
    return hit ? `${hit.vendorProject} ${hit.product}` : p;
  });

  return {
    entries: [...matched.values()],
    matchKinds: kinds,
    ambiguous,
    candidates: ambiguous ? candidates : [],
  };
}

/** Find a KEV entry by CVE id (case-insensitive), or null. */
export function findByCve(cveID: string, catalog: KevEntry[]): KevEntry | null {
  const want = cveID.trim().toUpperCase();
  for (const entry of catalog) {
    if (entry.cveID.toUpperCase() === want) return entry;
  }
  return null;
}

/** All KEV entries whose vendor/product names the given product text. */
export function findByProduct(
  product: string,
  catalog: KevEntry[],
): KevEntry[] {
  const needle = normalize(product);
  if (!needle) return [];
  return catalog.filter((entry) => {
    const hay = normalize(entry.vendorProject + " " + entry.product);
    return hay.includes(needle) || needle.includes(normalize(entry.product));
  });
}
