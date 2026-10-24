/* eslint-disable @typescript-eslint/no-explicit-any */
// Differential test: PROVED taint core (formal/dafny/Taint.dfy via src/ext-taint.ts) vs the hand-written taint.ts (frozen in test/support/legacy/taint.ts; production now runs the proved code).
// FUZZ_N scales the random sections (default 20k on the Mac; millions on a cloud box).
import { describe, expect, it } from 'vitest';
import {
  InMemoryTrustedInputRegistry,
  computeTaint,
  joinLabel,
  joinLabels,
  taintValue as prodTaintValue,
  type TaintLabel as PL,
  type TaintContext as PCtx,
} from './support/legacy/taint';
import {
  combineTaintRank,
  computeTaintVerified,
  joinLabelVerified,
  joinLabelsVerified,
  taintGateVerified,
  taintValue,
  type TaintLabel,
} from '../src/ext-taint';

const FUZZ_N = Number(process.env.FUZZ_N ?? 20000);
const SEED = Number(process.env.FUZZ_SEED ?? 12345);

function rng(seed: number) {
  let a = seed >>> 0;
  const f = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const next = (n: number) => Math.floor(f() * n);
  return { next, pick: <T>(xs: readonly T[]): T => xs[next(xs.length)]!, bool: () => f() < 0.5 };
}

const norm = (l: any): any => (l && l.id !== undefined ? { kind: l.kind, id: l.id } : { kind: l.kind });
const normRes = (r: any): any => ({
  taint: r.taint,
  label: norm(r.label),
  refs: r.refs.map((x: any) => ({ ref: x.ref, label: norm(x.label) })),
  valid: r.valid,
  reason: r.reason,
});

const KINDS = ['trusted', 'first_party', 'tool', 'web', 'agent'] as const;
const IDS: Array<string | undefined> = [undefined, 'x', 'y'];
const LABELS: TaintLabel[] = [];
for (const k of KINDS) for (const id of IDS) LABELS.push((id === undefined ? { kind: k } : { kind: k, id }) as TaintLabel);

describe('taint: joins (exhaustive + algebra)', () => {
  it('joinLabel == production on all 15x15 pairs; commutative/idempotent/associative (all triples)', () => {
    for (const a of LABELS) {
      for (const b of LABELS) {
        expect(norm(joinLabelVerified(a, b))).toEqual(norm(joinLabel(a as PL, b as PL)));
        expect(norm(joinLabelVerified(a, b))).toEqual(norm(joinLabelVerified(b, a)));
        for (const c of LABELS) {
          expect(norm(joinLabelVerified(joinLabelVerified(a, b), c))).toEqual(norm(joinLabelVerified(a, joinLabelVerified(b, c))));
          // the production TS is also associative on ids (no bug): checked on the same triples
          expect(norm(joinLabel(joinLabel(a as PL, b as PL), c as PL))).toEqual(norm(joinLabel(a as PL, joinLabel(b as PL, c as PL))));
        }
      }
      expect(norm(joinLabelVerified(a, a))).toEqual(norm(a));
      expect(norm(joinLabelVerified(a, { kind: 'agent' }))).toEqual({ kind: 'agent' });
    }
  });
  it('joinLabels == production on ALL sequences of length 0..4 over the 15 labels, and permutation-invariant', () => {
    let n = 0;
    const rec = (cur: TaintLabel[], depth: number) => {
      const v = norm(joinLabelsVerified(cur));
      expect(v).toEqual(norm(joinLabels(cur as PL[])));
      if (cur.length > 1) expect(norm(joinLabelsVerified([...cur].reverse()))).toEqual(v);
      n++;
      if (depth === 0) return;
      for (const l of LABELS) rec([...cur, l], depth - 1);
    };
    rec([], 4);
    expect(n).toBe(1 + 15 + 225 + 3375 + 50625);
  });
  it('joinLabels: random long lineages incl. all permutations of a shuffled copy', () => {
    const r = rng(SEED);
    for (let i = 0; i < Math.min(FUZZ_N, 20000); i++) {
      const ls = Array.from({ length: 1 + r.next(40) }, () => r.pick(LABELS));
      const sh = [...ls];
      for (let j = sh.length - 1; j > 0; j--) {
        const k = r.next(j + 1);
        [sh[j], sh[k]] = [sh[k]!, sh[j]!];
      }
      const v = norm(joinLabelsVerified(ls));
      expect(norm(joinLabelsVerified(sh))).toEqual(v);
      expect(v).toEqual(norm(joinLabels(ls as PL[])));
    }
  });
  it('a very long lineage (200k refs) is linear time and equals production', () => {
    const ls = Array.from({ length: 200_000 }, (_, i) => LABELS[i % LABELS.length]!);
    expect(norm(joinLabelsVerified(ls))).toEqual(norm(joinLabels(ls as PL[])));
  });
  it('taintValue scale', () => {
    for (const l of LABELS) expect(taintValue(l)).toBe(prodTaintValue(l as PL));
  });
});

// ---- computeTaint -------------------------------------------------------------------------------------------------
interface World {
  vouched: Map<string, TaintLabel | undefined>;
  graph: Set<string>;
}
function ctxOf(w: World, calls: string[]): PCtx {
  return {
    registry: {
      lookup(d: string) {
        calls.push('L:' + d);
        const v = w.vouched.get(d);
        return v ? { ...v } : undefined;
      },
    },
    resourceGraph: {
      node(id: string) {
        calls.push('N:' + id);
        return w.graph.has(id) ? {} : undefined;
      },
    } as any,
  };
}
function both(prov: unknown, w: World) {
  const c1: string[] = [];
  const c2: string[] = [];
  const a = computeTaint(prov, ctxOf(w, c1));
  const b = computeTaintVerified(prov, ctxOf(w, c2));
  expect(normRes(b)).toEqual(normRes(a));
  expect(c2).toEqual(c1); // identical registry / graph call sequence
  return b;
}

describe('taint: computeTaint vs production', () => {
  it('exhaustive: all lineages (len 0..3) over 17 server states, with duplicates', () => {
    const states: Array<{ v?: TaintLabel; g?: boolean }> = [{}, { g: true }, ...LABELS.map((v) => ({ v }))];
    const names = ['r0', 'r1', 'r2'];
    let n = 0;
    const rec = (cur: number[], depth: number) => {
      const w: World = { vouched: new Map(), graph: new Set() };
      // each position gets its own ref name (r0..), plus a repeated-ref case below
      cur.forEach((si, i) => {
        const s = states[si]!;
        if (s.v) w.vouched.set(names[i]!, s.v);
        if (s.g) w.graph.add(names[i]!);
      });
      both({ trusted_refs: cur.map((_, i) => names[i]!) }, w);
      n++;
      if (depth === 0) return;
      for (let s = 0; s < states.length; s++) rec([...cur, s], depth - 1);
    };
    rec([], 3);
    expect(n).toBe(1 + 17 + 289 + 4913);
  });
  it('malformed provenance / registry shapes (fail closed, same reasons)', () => {
    const w: World = { vouched: new Map([['a', { kind: 'trusted' }]]), graph: new Set() };
    const provs: unknown[] = [
      undefined, null, 0, 1, 'x', true, [], [{}], {}, { trusted_refs: undefined }, { trusted_refs: null }, { trusted_refs: 'a' }, { trusted_refs: 5 },
      { trusted_refs: {} }, { trusted_refs: [] }, { trusted_refs: [''] }, { trusted_refs: ['a', ''] }, { trusted_refs: ['a', 1] }, { trusted_refs: ['a', null] },
      { trusted_refs: [['a']] }, { trusted_refs: ['a'] }, { trusted_refs: ['a', 'a'] }, { trusted_refs: ['a', 'zzz'] }, { causal_hash: 1, taint_level: 0, trusted_refs: ['a'] },
      Object.create({ trusted_refs: ['a'] }), // inherited property
      { trusted_refs: Object.assign(['a'], { extra: 1 }) },
    ];
    for (const p of provs) both(p, w);
    for (const bad of [undefined, null, {}, { registry: null }, { registry: {} }, { registry: { lookup: 1 } }] as any[]) {
      const a = computeTaint({ trusted_refs: ['a'] }, bad);
      const b = computeTaintVerified({ trusted_refs: ['a'] }, bad);
      expect(normRes(b)).toEqual(normRes(a));
      expect(b.valid).toBe(false);
      expect(b.taint).toBe(1);
    }
  });
  it('long ids (>128) and exactly 128 drop/keep the id; huge lists', () => {
    for (const len of [127, 128, 129, 1000]) {
      const ref = 'q'.repeat(len);
      const r = both({ trusted_refs: [ref, ref] }, { vouched: new Map(), graph: new Set() });
      expect(r.label.kind).toBe('agent');
      expect((r.label as any).id === undefined).toBe(len > 128);
    }
    const w: World = { vouched: new Map(), graph: new Set() };
    const refs = Array.from({ length: 20000 }, (_, i) => 'k' + i);
    refs.forEach((k, i) => {
      if (i % 3) w.vouched.set(k, { kind: 'trusted' });
      else w.graph.add(k);
    });
    expect(both({ trusted_refs: refs }, w).taint).toBe(0.25);
  });
  it('registry / graph / getter that THROW: same exception propagates (callers fail closed), graph errors are the worst case', () => {
    const prov = { trusted_refs: ['a'] };
    const reg = { lookup: () => { throw new Error('boom'); } };
    // computeTaint never throws: a failing registry is an invalid, worst-case result (Taint.ComputeSafe / EvalErrorFailsClosed)
    expect(computeTaint(prov, { registry: reg })).toMatchObject({ valid: false, taint: 1, reason: 'taint: evaluation error (fail closed): boom' });
    expect(computeTaintVerified(prov, { registry: reg })).toEqual(computeTaint(prov, { registry: reg }));
    const g: any = { node: () => { throw new Error('g'); } };
    const ctx = { registry: { lookup: () => undefined }, resourceGraph: g };
    expect(normRes(computeTaintVerified(prov, ctx))).toEqual(normRes(computeTaint(prov, ctx)));
    const getter = { get trusted_refs(): string[] { throw new Error('getter'); } };
    expect(computeTaint(getter, ctx)).toMatchObject({ valid: false, taint: 1 });
    expect(computeTaintVerified(getter, ctx)).toEqual(computeTaint(getter, ctx));
    const px = new Proxy({}, { get() { throw new Error('proxy'); } });
    expect(computeTaint(px, ctx)).toMatchObject({ valid: false, taint: 1 });
    expect(computeTaintVerified(px, ctx)).toEqual(computeTaint(px, ctx));
    // a throwing ctx.registry getter
    const badCtx = { get registry(): never { throw new Error('ctx'); } } as never;
    expect(computeTaintVerified(prov, badCtx)).toEqual(computeTaint(prov, badCtx));
  });
  it('random worlds / lineages (FUZZ_N): results, labels, taint, call order identical', () => {
    const r = rng(SEED + 1);
    const pool = Array.from({ length: 12 }, (_, i) => 'ref' + i).concat(['q'.repeat(129), 'q'.repeat(128)]);
    let valid = 0;
    let low = 0;
    for (let i = 0; i < FUZZ_N; i++) {
      const w: World = { vouched: new Map(), graph: new Set() };
      for (const p of pool) {
        const m = r.next(5);
        if (m === 0) w.vouched.set(p, r.pick(LABELS));
        else if (m === 1) w.graph.add(p);
        else if (m === 2) {
          w.vouched.set(p, r.pick(LABELS));
          w.graph.add(p);
        }
      }
      const n = r.next(9);
      const refs: unknown[] = Array.from({ length: n }, () => (r.next(40) === 0 ? r.pick(['', 1, null, {}, undefined]) : r.pick(pool)));
      const shapes: unknown[] = [{ trusted_refs: refs }, { trusted_refs: refs }, { trusted_refs: refs }, {}, { trusted_refs: 'x' }, null, []];
      const res = both(r.pick(shapes), w);
      if (res.valid) valid++;
      if (res.valid && res.taint < 1) low++;
    }
    expect(valid).toBeGreaterThan(FUZZ_N / 3);
    expect(low).toBeGreaterThan(FUZZ_N / 50);
  });
});

// ---- the gate ---------------------------------------------------------------------------------------------------------
function prodGate(prov: unknown, ctx: PCtx, maxTaint: number): { ok: true } | { ok: false; reason: string } {
  // verbatim transcription of the `enforce.taint` branch of verifyPCActnCore (packages/pca/src/pcactn.ts)
  try {
    const t = computeTaint(prov, ctx);
    if (!t.valid) return { ok: false, reason: t.reason ?? 'provenance lineage is not server-verifiable (fail closed)' };
    if (!(maxTaint >= 0)) return { ok: false, reason: 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)' };
    if (!(t.taint <= maxTaint)) return { ok: false, reason: `information-flow taint ${t.taint} exceeds policy max ${maxTaint}` };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `taint gate error (fail closed): ${(e as Error).message}` };
  }
}
describe('taint: enforce.taint gate', () => {
  it('identical decision + reason over maxTaint in {valid, boundary, NaN, negative, coerced, Infinity}', () => {
    const r = rng(SEED + 2);
    const MAXES: any[] = [0, 0.25, 0.5, 0.75, 1, 0.24999999999999997, 0.2500000000000001, 2, Infinity, -0, -1, -Infinity, NaN, undefined, null, '0.5', '', 'x', true, false, 1e-300];
    let pass = 0;
    let fail = 0;
    for (let i = 0; i < FUZZ_N; i++) {
      const w: World = { vouched: new Map(), graph: new Set() };
      const refs = Array.from({ length: r.next(5) }, (_, j) => 'g' + j);
      refs.forEach((x) => {
        const m = r.next(3);
        if (m === 0) w.vouched.set(x, r.pick(LABELS));
        else if (m === 1) w.graph.add(x);
      });
      const prov = r.next(10) === 0 ? null : { trusted_refs: refs };
      const mx = r.pick(MAXES);
      const a = prodGate(prov, ctxOf(w, []), mx);
      const b = taintGateVerified(prov, ctxOf(w, []), mx);
      expect(b).toEqual(a);
      if (a.ok) pass++;
      else fail++;
    }
    expect(pass).toBeGreaterThan(FUZZ_N / 50);
    expect(fail).toBeGreaterThan(FUZZ_N / 10);
  });
  it('max-combination: the claim can only raise', () => {
    for (let c = 0; c <= 4; c++) for (let a = 0; a <= 4; a++) {
      expect(combineTaintRank(c, a)).toBe(Math.max(c, a));
      expect(combineTaintRank(c, a)).toBeGreaterThanOrEqual(c);
    }
  });
});

// ---- former DIVERGENCES (production bugs found by the proof effort; fixed in production, now identical) ----------------
describe('taint: production TS bugs (PoC)', () => {
  it('BUG-1 (FIXED): a registry label whose kind is an INHERITED key (e.g. "constructor") is worst-case taint, not NaN, and the gate FAILS', () => {
    const reg = new InMemoryTrustedInputRegistry();
    reg.record('d1', { kind: 'constructor' } as any); // record() now refuses a kind that is not an own level name
    expect(reg.size).toBe(0);
    const ctx: PCtx = { registry: { lookup: () => ({ kind: 'constructor' }) as any } }; // a custom registry can still return it
    const prod = computeTaint({ trusted_refs: ['d1'] }, ctx);
    expect(prod.valid).toBe(true);
    expect(prod.taint).toBe(1);
    expect(prod.label.kind).toBe('agent');
    expect(prodGate({ trusted_refs: ['d1'] }, ctx, 0).ok).toBe(false);
    const ver = computeTaintVerified({ trusted_refs: ['d1'] }, ctx);
    expect(ver.taint).toBe(1);
    expect(ver.label.kind).toBe('agent');
    expect(taintGateVerified({ trusted_refs: ['d1'] }, ctx, 0).ok).toBe(false);
  });
  it('BUG-2 (FIXED): computeTaint "never throws": a sparse trusted_refs array (hole) is rejected as malformed', () => {
    const holes: string[] = new Array(1);
    const ctx: PCtx = { registry: { lookup: () => undefined } };
    expect(computeTaint({ trusted_refs: holes }, ctx)).toMatchObject({ taint: 1, valid: false });
    const mixed = ['a', , 'b'] as string[]; // eslint-disable-line no-sparse-arrays
    const prodRes = computeTaint({ trusted_refs: mixed }, ctx);
    expect(prodRes.valid).toBe(false);
    const ver = computeTaintVerified({ trusted_refs: mixed }, ctx);
    expect(ver.valid).toBe(false);
    expect(ver.reason).toBe('taint: trusted_refs must be non-empty strings');
  });
  it('NOTE (FIXED): a throwing registry.lookup no longer propagates out of computeTaint; it is reported invalid (fail closed)', () => {
    const ctx: PCtx = { registry: { lookup: () => { throw new Error('x'); } } };
    expect(computeTaint({ trusted_refs: ['a'] }, ctx)).toMatchObject({ taint: 1, valid: false });
    expect(prodGate({ trusted_refs: ['a'] }, ctx, 1).ok).toBe(false);
  });
});
