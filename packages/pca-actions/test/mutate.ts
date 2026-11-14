// mutate.ts - seeded random mutations of an ActionDef and random call samples, for the diff soundness oracle.
import { BLAST_RADII, CONTEXT_KEYS, CORE_TRAIT_IDS, EFFECTS, REVERSIBILITY, validateDef, type ActionDef, type ParamDef } from '../src';
import type { R } from './vectors-gen';

const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
type D = Record<string, any>;

const newParam = (r: R): ParamDef => {
  switch (r.int(0, 5)) {
    case 0: return { type: 'integer', min: 0, max: r.pick([10, 1000]) };
    case 1: return { type: 'string', max_len: r.pick([16, 256]) };
    case 2: return { type: 'boolean' };
    case 3: return { type: 'string', values: ['a', 'b', 'c'] };
    case 4: return { type: 'array', items: 'string', max_items: r.pick([4, 16]) };
    default: return { type: 'set', values: ['x', 'y', 'z'], max_items: 2 };
  }
};

/** One random edit; returns false when it did not apply. */
function edit(d: D, r: R): void {
  const names = Object.keys(d.params);
  const pick = () => (names.length ? r.pick(names) : undefined);
  switch (r.int(0, 27)) {
    case 0: d.title = `${d.title} v2`; break;
    case 1: d.description = 'changed text'; break;
    case 2: d.params[`n${r.int(0, 99)}`] = { ...newParam(r), required: false }; break;
    case 3: d.params[`n${r.int(0, 99)}`] = newParam(r); break;
    case 4: { const n = pick(); if (n) delete d.params[n]; break; }
    case 5: { const n = pick(); if (n) d.params[n].required = !(d.params[n].required ?? true); break; }
    case 6: { const n = pick(); if (n && d.params[n].max !== undefined) d.params[n].max += r.pick([-5, 5, 1000]); break; }
    case 7: { const n = pick(); if (n && d.params[n].min !== undefined) d.params[n].min += r.pick([-5, 5]); break; }
    case 8: { const n = pick(); if (n && d.params[n].max_len !== undefined) d.params[n].max_len = r.pick([8, 16, 256, 4096]); break; }
    case 9: { const n = pick(); if (n && d.params[n].values) d.params[n].values = r.pick([['a'], ['a', 'b'], ['a', 'b', 'c', 'd'], ['q']]); break; }
    case 10: { const n = pick(); if (n && d.params[n].max_items !== undefined) d.params[n].max_items = r.pick([1, 2, 4, 64]); break; }
    case 11: { const n = pick(); if (n) d.params[n].sensitivity = r.pick(['free', 'material', 'critical']); break; }
    case 12: { const n = pick(); if (n) d.params[n].provenance_min = r.pick(['first_party', 'tool', 'agent', undefined]); break; }
    case 13: { const n = pick(); if (n) d.params[n].tags = r.pick([[], ['pii'], ['secret'], ['pii', 'phi']]); break; }
    case 14: { const n = pick(); if (n) d.params[n].role = r.pick([undefined, 'contact.email', 'text.message', 'count.limit']); break; }
    case 15: { const n = pick(); if (n) d.params[n] = { ...newParam(r), required: d.params[n].required }; break; }
    case 16: d.effects = r.pick([['read'], ['update'], ['send', 'update'], ['delete'], [...EFFECTS].slice(0, 3)]); break;
    case 17: d.reversibility = r.pick([...REVERSIBILITY, undefined]); break;
    case 18: d.blast = r.pick([undefined, { radius: r.pick(BLAST_RADII) }, { radius: 'one', ppm: r.int(0, 1_000_000) }]); break;
    case 19: d.context = r.sub(CONTEXT_KEYS, 3); break;
    case 20: d.traits = r.sub(CORE_TRAIT_IDS, 3); break;
    case 21: d.resource.scope = r.pick(['one', 'set', 'tenant', 'global']); break;
    case 22: d.resource.id = r.pick<unknown>(['*', { exact: 'only' }, { prefix: 'g_', class: 'alnum', len: [4, 8] }, { prefix: 'g_', class: 'hex', len: [4, 8] }, { prefix: 'g_x', class: 'hex', len: [4, 6] }]); break;
    case 23: d.aliases = r.pick([undefined, ['alias_a'], ['alias_a', 'alias_b']]); break;
    case 24: d.idempotency = r.pick([undefined, { mode: 'natural' }, { mode: 'none' }]); break;
    case 25: d.side_effects = r.pick([undefined, [{ target: 'x.thing', kind: 'update' }]]); break;
    case 26: d.review = { state: r.pick(['authored', 'unreviewed', 'suggested', 'confirmed']) }; break;
    default: { const n = pick(); if (n) d.params[n].format = r.pick([undefined, 'email', 'url']); break; }
  }
}

/** A valid mutant of `d` (1..3 edits), or null when none of a few tries validated. */
export function mutate(d: ActionDef, r: R): ActionDef | null {
  for (let t = 0; t < 8; t++) {
    const m = clone(d) as D;
    for (let k = r.int(1, 3); k > 0; k--) edit(m, r);
    for (const key of Object.keys(m)) if (m[key] === undefined) delete m[key];
    if (validateDef(m) === null) return m as ActionDef;
  }
  return null;
}

const strings = (n: number) => 'x'.repeat(n);
function valuesFor(p: ParamDef, r: R): unknown[] {
  switch (p.type) {
    case 'integer': return [p.min ?? 0, (p.min ?? 0) - 1, p.max ?? 100, (p.max ?? 100) + 1, 0, 7, r.int(-20, 2000)];
    case 'duration': return [0, 1000, -1, p.max ?? 5000, (p.max ?? 5000) + 1];
    case 'boolean': return [true, false];
    case 'date': return ['2026-01-02', '2026-13-40'];
    case 'datetime': return ['2026-01-02T03:04:05Z', 'nope'];
    case 'object_ref': return ['obj_1', ''];
    case 'set': return [[], ['x'], ['x', 'y'], ['x', 'y', 'z'], ['a'], ['x', 'x'], ...(p.values ? [[...p.values], p.values.slice(0, 1)] : [])];
    case 'array': return [[], ['s'], p.items === 'integer' ? [1, 2] : ['a', 'b', 'c'], Array.from({ length: 5 }, () => 's'), Array.from({ length: 17 }, () => 's'), Array.from({ length: 65 }, () => 's')];
    default: return ['a', 'b', 'c', 'd', 'q', 'zzz', 'a@b.co', 'https://e.co/x', strings(8), strings(16), strings(17), strings(256), strings(257), strings(1025), ...(p.values ?? [])];
  }
}

/** Random call parameter maps over the declared names of both defs (plus an undeclared name). */
export function sampleCalls(defs: readonly ActionDef[], r: R, n: number): Record<string, unknown>[] {
  const decl = new Map<string, ParamDef[]>();
  for (const d of defs) for (const [k, p] of Object.entries(d.params)) decl.set(k, [...(decl.get(k) ?? []), p]);
  const out: Record<string, unknown>[] = [];
  for (let i = 0; i < n; i++) {
    const call: Record<string, unknown> = {};
    for (const [k, ps] of decl) {
      if (r.next() < 0.15) continue;
      const vals = valuesFor(r.pick(ps), r);
      call[k] = r.pick(vals);
    }
    if (r.next() < 0.05) call.undeclared_zz = 1;
    out.push(call);
  }
  return out;
}
