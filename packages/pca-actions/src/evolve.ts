// evolve.ts - the signed per-definition changes between two versions of a pack (spec section 7.1, EvolutionRecord).
// A grant that pinned a definition digest follows a record chain (`decidePin` in @atlasauth/pca) only through steps
// the registry signed as `equal` or `narrow`; everything else needs the principal. The records are TypeScript tooling output:
// natives verify the signatures, they do not recompute the diff (the shared vectors pin the verification).

import {
  evolutionDiffDigest, signEvolutionRecord, verifyEvolutionRecord, EVOLUTION_RECORD_KIND,
  type ActionSchemaKey, type EvolutionRecord, type UnsignedEvolutionRecord,
} from '@atlasauth/pca/ext/intent';
import type { SignerSuiteOpts } from '@atlasauth/pca';
import { ActionKitError, type ActionDef } from './def';
import { defDigest } from './digest';
import { diffDefs } from './diff';
import { CORE_REGISTRY } from './core-traits';
import type { ReviewOpts } from './effective';
import type { Registry } from './traits';

const byVerb = (defs: readonly ActionDef[]): Map<string, ActionDef> => {
  const m = new Map<string, ActionDef>();
  for (const d of defs) {
    if (m.has(d.verb)) throw new ActionKitError('duplicate_def', `verb '${d.verb}' appears twice`);
    m.set(d.verb, d);
  }
  return m;
};

/** The unsigned records that take `prev` to `next` (sorted by verb). A verb rename is `removed` + `added` (grants on the old verb do not follow). */
export function evolutionRecords(ns: string, prev: readonly ActionDef[], next: readonly ActionDef[], reg: Registry = CORE_REGISTRY, opts: ReviewOpts = {}): UnsignedEvolutionRecord[] {
  const a = byVerb(prev);
  const b = byVerb(next);
  const out: UnsignedEvolutionRecord[] = [];
  for (const verb of [...new Set([...a.keys(), ...b.keys()])].sort()) {
    const o = a.get(verb);
    const n = b.get(verb);
    const base = { v: 1 as const, kind: EVOLUTION_RECORD_KIND as typeof EVOLUTION_RECORD_KIND, ns, verb };
    if (o === undefined) out.push({ ...base, from: null, to: defDigest(n!), class: 'added', reasons: [] });
    else if (n === undefined) out.push({ ...base, from: defDigest(o), to: null, class: 'removed', reasons: [] });
    else {
      const from = defDigest(o);
      const to = defDigest(n);
      if (from === to) continue;
      const d = diffDefs(o, n, reg, opts);
      out.push({ ...base, from, to, class: d.class, reasons: d.reasons });
    }
  }
  return out;
}

/** Sign the records as the registry. */
export const signEvolution = (records: readonly UnsignedEvolutionRecord[], kid: string, secret: Uint8Array, suite?: SignerSuiteOpts): EvolutionRecord[] =>
  records.map((r) => signEvolutionRecord(r, kid, secret, suite));

const key = (r: UnsignedEvolutionRecord): string => `${r.verb}|${r.from}|${r.to}|${r.class}|${evolutionDiffDigest(r)}`;

/**
 * Does `records` EXACTLY describe the change from `prev` to `next`? Every record verifies under the pinned registry keys and names
 * `ns`; none is missing and none is extra; the class of each is the one the diff computes (a registry cannot sign `narrow` for a
 * widening). Null = consistent, else the reason.
 */
export function evolutionError(ns: string, prev: readonly ActionDef[], next: readonly ActionDef[], records: readonly unknown[], keys: readonly ActionSchemaKey[], reg: Registry = CORE_REGISTRY, opts: ReviewOpts = {}): string | null {
  try {
    for (const r of records) {
      const v = verifyEvolutionRecord(r, keys);
      if (!v.ok) return `evolution record: ${v.reason}`;
      if ((r as EvolutionRecord).ns !== ns) return `evolution record names namespace '${(r as EvolutionRecord).ns}', not '${ns}'`;
    }
    const want = evolutionRecords(ns, prev, next, reg, opts).map(key).sort();
    const have = (records as EvolutionRecord[]).map(({ sig: _s, ...u }) => key(u)).sort();
    if (want.length !== have.length) return `evolution has ${have.length} records, the change needs ${want.length}`;
    for (let i = 0; i < want.length; i++) if (want[i] !== have[i]) return 'evolution records do not match the computed change (a missing, extra or mis-classified record)';
    return null;
  } catch (e) {
    return `evolution error: ${(e as Error).message}`;
  }
}
