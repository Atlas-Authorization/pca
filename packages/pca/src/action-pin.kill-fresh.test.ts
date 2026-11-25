/**
 * action-pin.ts builds its published constants, its grammar regexes and its small helpers (tier check, digest check, refusal
 * builder, diff digest) at module load. A test that imports the module statically evaluates them before any test runs, so these
 * tests re-evaluate the module (vi.resetModules + dynamic import) and check the observable behaviour of each.
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  const p = await import('./action-pin');
  const hash = await import('./hash');
  return { p, hash };
}

const dg = (c: string) => c.repeat(43);
const A = dg('A');
const B = dg('B');
const VERB = 'acme.thing.do';
const PIN = { pack: { ns: 'acme', root: dg('R') }, defs: { [VERB]: A }, on_new_action: 'deny' as const };
const pinWith = (over: Record<string, unknown>) => ({ ...PIN, ...over });

describe('published constants (fresh module)', () => {
  it('kinds and domains are the normative strings', async () => {
    const { p } = await fresh();
    expect(p.EVOLUTION_RECORD_KIND).toBe('pca-evolution-record');
    expect(p.REAPPROVAL_KIND).toBe('pca-reapproval');
    expect(p.EVOLUTION_DOMAIN).toBe('atlas-pca/action-evolution/v1\0');
    expect(p.EVOLUTION_DIFF_DOMAIN).toBe('atlas-pca/action-evolution-diff/v1');
    expect(p.REAPPROVAL_DOMAIN).toBe('atlas-pca/action-reapproval/v1\0');
  });

  it('the diff digest hashes the diff domain with the record fields', async () => {
    const { p, hash } = await fresh();
    const r = { v: 1 as const, kind: 'pca-evolution-record' as const, ns: 'acme', verb: VERB, from: A, to: B, class: 'widen' as const, reasons: ['x'] };
    expect(p.evolutionDiffDigest(r)).toBe(hash.hashCanonical({ d: 'atlas-pca/action-evolution-diff/v1', ns: 'acme', verb: VERB, from: A, to: B, class: 'widen', reasons: ['x'] }));
  });
});

describe('grammars (fresh module)', () => {
  it('root digest: exactly 43 base64url characters, anchored at both ends', async () => {
    const { p } = await fresh();
    const root = (r: unknown) => p.actionPinError(pinWith({ pack: { ns: 'acme', root: r } }));
    expect(root(dg('R'))).toBeNull();
    expect(root('a-_9'.repeat(10) + 'abc')).toBeNull();
    for (const bad of ['!' + dg('R'), dg('R') + '!', dg('R') + 'R', 'R', 'R'.repeat(42), '!'.repeat(43)]) {
      expect(root(bad), bad).toBe('actions.pack.root must be a base64url digest');
    }
  });

  it('namespace: one to six lowercase segments of one or more characters, anchored', async () => {
    const { p } = await fresh();
    const ns = (n: unknown) => p.actionPinError(pinWith({ pack: { ns: n, root: dg('R') } }));
    for (const ok of ['acme', 'ab', 'a.bc', 'ab.cd', 'a.b', 'a.b.c.d.e.f']) expect(ns(ok), ok).toBeNull();
    for (const bad of ['!acme', 'acme!', 'Acme', '!!', 'a.b.c.d.e.f.g', 'a.!', 'a..b', '.a', 'a.']) expect(ns(bad), bad).toBe('actions.pack.ns is not a namespace');
  });

  it('verb: two to six lowercase segments of one or more characters, anchored', async () => {
    const { p } = await fresh();
    const v = (n: string) => p.actionPinError(pinWith({ defs: { [n]: A } }));
    for (const ok of ['a.b', 'ab.cd', 'acme.thing.do', 'a.b.c.d.e.f']) expect(v(ok), ok).toBeNull();
    for (const bad of ['acme', '!acme.x', 'acme.x!', 'Acme.x', '!!.x', 'a.b.c.d.e.f.g', 'a.!', 'a..b']) expect(v(bad), bad).toBe(`actions.defs: '${bad}' is not a verb`);
  });

  it('a def digest is checked with the same 43-character grammar', async () => {
    const { p } = await fresh();
    expect(p.actionPinError(pinWith({ defs: { [VERB]: B } }))).toBeNull();
    expect(p.actionPinError(pinWith({ defs: { [VERB]: 'B' } }))).toBe(`actions.defs.${VERB} must be a base64url digest`);
  });
});

describe('helpers (fresh module)', () => {
  it('escalation tiers 0..3 are accepted and compared', async () => {
    const { p } = await fresh();
    expect(p.actionPinError(pinWith({ max_esc: 0 }))).toBeNull();
    expect(p.actionPinError(pinWith({ max_esc: 3, preauth_esc: 2 }))).toBeNull();
    expect(p.actionPinError(pinWith({ max_esc: 4 }))).toBe('actions.max_esc must be an integer tier 0..3');
    expect(p.actionPinError(pinWith({ max_esc: 1, preauth_esc: 2 }))).toBe('actions.preauth_esc exceeds actions.max_esc');
  });

  it('record endpoints are checked as digests', async () => {
    const { p } = await fresh();
    const bare = { v: 1, kind: 'pca-evolution-record', ns: 'acme', verb: VERB, from: A, to: B, class: 'widen', reasons: [] };
    expect(p.evolutionRecordError(bare, { signed: false })).toBeNull();
    expect(p.evolutionRecordError({ ...bare, from: 'x' }, { signed: false })).toBe('evolution record: bad from');
    expect(p.evolutionRecordError({ ...bare, to: 'x' }, { signed: false })).toBe('evolution record: bad to');
  });

  it('a refusal has the exact decision shape', async () => {
    const { p } = await fresh();
    const grant = { id: dg('G'), issuer: 'i' };
    expect(p.decidePin({ pin: 'x', doc: { pack: PIN.pack, verbs: [] }, verb: VERB, grant })).toStrictEqual({ ok: false, code: 'bad_pin', escalate: false, reason: 'actions must be an object' });
    expect(p.decidePin({ pin: PIN, doc: { pack: PIN.pack, verbs: [] }, verb: VERB, grant })).toStrictEqual({ ok: false, code: 'unknown_verb', escalate: false, reason: `the accepted schema does not declare '${VERB}'` });
  });
});
