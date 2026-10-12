import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

/**
 * R5-API-05/06: the ONE bounded cache of compiled regex programs (used by `safeRegexFullMatch` and by the regex budget's
 * program-length lookup).
 *
 * The previous caches were two global 512-entry Maps that were CLEARED WHOLESALE when full: any request evaluating 512
 * distinct patterns flushed every other tenant's compiled programs (forcing recompiles on everyone's hot path), and 511
 * retained programs could hold ~134 MB. Now:
 *  - keys are the SHA-256 of the pattern source (the raw source is not retained as a key);
 *  - eviction is least-recently-used, one entry at a time; nothing on any request path clears the cache;
 *  - PER-SOURCE ADMISSION: each entry is owned by the source that inserted it (the server supplies the source, its trusted
 *    client address, through {@link setRegexCacheSourceProvider}); once a source owns {@link REGEX_CACHE_MAX_PER_SOURCE}
 *    entries, a new pattern from it evicts that source's OWN least-recently-used entry, so one source cannot flush the
 *    cache. (Many sources can still churn the global LRU, but a pattern in use stays most-recently-used.);
 *  - a total WEIGHT cap (instructions + character-class ranges) bounds memory, and a single program heavier than
 *    1/16 of it is compiled and used but never cached.
 * Library use outside any request is the anonymous source '' under the same rules.
 */
export const REGEX_CACHE_MAX_ENTRIES = 512;
export const REGEX_CACHE_MAX_PER_SOURCE = 64;
export const REGEX_CACHE_MAX_WEIGHT = 131_072;

interface Entry {
  value: unknown;
  source: string;
  weight: number;
}

const entries = new Map<string, Entry>(); // least-recently-used first
const bySource = new Map<string, Map<string, true>>(); // source -> its keys, least-recently-used first
let totalWeight = 0;
let sourceProvider: (() => string | null) | null = null;
const enc = new TextEncoder();

/** Install the provider of the CURRENT source (the server's per-request client key); `null` uninstalls. */
export function setRegexCacheSourceProvider(fn: (() => string | null) | null): void {
  sourceProvider = fn;
}

function currentSource(): string {
  try {
    return (sourceProvider === null ? null : sourceProvider()) ?? '';
  } catch {
    return '';
  }
}

function keyOf(src: string): string {
  return bytesToHex(sha256(enc.encode(src)));
}

function remove(key: string): void {
  const e = entries.get(key);
  if (e === undefined) return;
  entries.delete(key);
  totalWeight -= e.weight;
  const owned = bySource.get(e.source);
  if (owned !== undefined) {
    owned.delete(key);
    if (owned.size === 0) bySource.delete(e.source);
  }
}

/**
 * The cached value for pattern `src`, computing (and admitting) it on a miss. `weigh` gives the memory weight of a value
 * (>= 1). Never throws unless `compute` does.
 */
export function regexCacheGet<V>(src: string, compute: (src: string) => V, weigh: (v: V) => number): V {
  const key = keyOf(src);
  const hit = entries.get(key);
  if (hit !== undefined) {
    entries.delete(key);
    entries.set(key, hit);
    const owned = bySource.get(hit.source);
    if (owned !== undefined) {
      owned.delete(key);
      owned.set(key, true);
    }
    return hit.value as V;
  }
  const value = compute(src);
  const w = Math.max(1, Math.ceil(weigh(value)) || 1);
  if (w > REGEX_CACHE_MAX_WEIGHT / 16) return value; // too heavy to cache: never evict others for it
  const source = currentSource();
  // per-source admission: a source at its share replaces its OWN least-recently-used entry
  for (let owned = bySource.get(source); owned !== undefined && owned.size >= REGEX_CACHE_MAX_PER_SOURCE; owned = bySource.get(source)) {
    remove(owned.keys().next().value as string);
  }
  while (entries.size >= REGEX_CACHE_MAX_ENTRIES || totalWeight + w > REGEX_CACHE_MAX_WEIGHT) {
    const oldest = entries.keys().next();
    if (oldest.done) break;
    remove(oldest.value);
  }
  entries.set(key, { value, source, weight: w });
  totalWeight += w;
  const owned = bySource.get(source) ?? new Map<string, true>();
  owned.set(key, true);
  bySource.set(source, owned);
  return value;
}

/** Whether pattern `src` is currently cached (tests / diagnostics). */
export function regexCacheHas(src: string): boolean {
  return entries.has(keyOf(src));
}

/** Cache occupancy (tests / diagnostics). */
export function regexCacheStats(): { entries: number; weight: number; maxWeight: number; keys: string[]; bySource: Record<string, number> } {
  return {
    entries: entries.size,
    weight: totalWeight,
    maxWeight: REGEX_CACHE_MAX_WEIGHT,
    keys: [...entries.keys()],
    bySource: Object.fromEntries([...bySource].map(([s, m]) => [s, m.size])),
  };
}
