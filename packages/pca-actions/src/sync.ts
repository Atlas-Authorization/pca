// sync.ts - keep a platform's action definitions in step with the sources they were imported from (OpenAPI, MCP tools/list,
// GraphQL, gRPC, AsyncAPI, JSON Schema). Pure: the caller fetches the source and stores the lock.
//
// The lock records, per source, the digest of each operation AS IMPORTED (before any review). On the next sync:
//   added       an operation the source now has and the lock does not: it lands as imported (unreviewed, so strict)
//   changed     an operation whose imported form differs from the locked one: the NEW imported form replaces the reviewed def
//               and is unreviewed (strict) until a reviewer confirms it again; the semantic diff against the def it replaces
//               is reported
//   unchanged   the imported form equals the locked one: the current (possibly reviewed) def is kept as it is
//   removed     an operation the lock has and the source no longer does: deprecated (dropped from the defs, listed)
// A def the lock does not attribute to this source (hand-written, or another source's) is never touched.

import type { ActionDef } from './def';
import { CORE_REGISTRY } from './core-traits';
import { diffDefs, type DiffClass } from './diff';
import { defDigest } from './digest';
import type { ReviewOpts } from './effective';
import type { Registry } from './traits';

export interface SourceLock {
  /** Digest of the fetched source document (the importer's `spec_digest`). */
  spec_digest: string;
  /** verb -> defDigest of the operation as imported. */
  ops: Record<string, string>;
  /** Seconds since the epoch of the sync that wrote this lock. */
  synced_at: number;
}

export interface SyncEntry {
  verb: string;
  change: 'added' | 'changed' | 'unchanged' | 'removed';
  /** For `changed`: the semantic diff of the replacing (unreviewed) def against the def it replaces. */
  diff?: { class: DiffClass; reasons: string[] };
}

export interface SyncResult {
  /** The defs of this source after the sync (added and changed ones unreviewed; unchanged ones as they were). */
  defs: ActionDef[];
  entries: SyncEntry[];
  /** Verbs removed from the source (deprecate them). */
  deprecated: string[];
  lock: SourceLock;
  /** True when anything needs a reviewer (an added or changed operation). */
  needsReview: boolean;
}

/** Strip the review to the imported state: a changed operation is never carried over as confirmed. */
const asImported = (d: ActionDef): ActionDef => (d.review.state === 'confirmed' ? { ...d, review: { state: 'unreviewed' } } : d);

/**
 * Merge a fresh import of one source into the current defs. `current` may hold defs of other sources and hand-written ones;
 * only the verbs the lock attributes to this source (or, without a lock, the verbs the import names) are this source's.
 */
export function syncSource(args: {
  current: readonly ActionDef[];
  imported: readonly ActionDef[];
  specDigest: string;
  lock?: SourceLock;
  now: number;
  registry?: Registry;
  review?: ReviewOpts;
}): SyncResult {
  const reg = args.registry ?? CORE_REGISTRY;
  const cur = new Map(args.current.map((d) => [d.verb, d]));
  const imp = new Map(args.imported.map((d) => [d.verb, asImported(d)]));
  const ops: Record<string, string> = {};
  const entries: SyncEntry[] = [];
  const defs: ActionDef[] = [];
  for (const [verb, d] of [...imp].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const dg = defDigest(d);
    ops[verb] = dg;
    const old = cur.get(verb);
    const locked = args.lock?.ops[verb];
    if (old === undefined) {
      entries.push({ verb, change: 'added' });
      defs.push(d);
    } else if (locked === dg || (locked === undefined && defDigest(old) === dg)) {
      entries.push({ verb, change: 'unchanged' });
      defs.push(old);
    } else {
      let diff: SyncEntry['diff'];
      try { diff = diffDefs(old, d, reg, args.review ?? {}); } catch (e) { diff = { class: 'incomparable', reasons: [(e as Error).message] }; }
      entries.push({ verb, change: 'changed', diff });
      defs.push(d);
    }
  }
  const prevOps = Object.keys(args.lock?.ops ?? {});
  const deprecated = prevOps.filter((v) => !imp.has(v)).sort();
  for (const v of deprecated) entries.push({ verb: v, change: 'removed' });
  return { defs, entries, deprecated, lock: { spec_digest: args.specDigest, ops, synced_at: args.now }, needsReview: entries.some((e) => e.change === 'added' || e.change === 'changed') };
}

/** One line per entry, then a summary. */
export function syncText(r: SyncResult): string {
  const lines = r.entries.filter((e) => e.change !== 'unchanged').map((e) => `${e.change.padEnd(9)} ${e.verb}${e.diff ? `  (${e.diff.class}${e.diff.reasons.length ? `: ${e.diff.reasons.join(', ')}` : ''})` : ''}`);
  const n = (c: SyncEntry['change']) => r.entries.filter((e) => e.change === c).length;
  lines.push(`${n('added')} added, ${n('changed')} changed, ${n('removed')} removed (deprecated), ${n('unchanged')} unchanged${r.needsReview ? '; added and changed actions are unreviewed (strict) until a reviewer confirms them' : ''}`);
  return lines.join('\n');
}
