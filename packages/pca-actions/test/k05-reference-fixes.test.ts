// PCA 0.5 reference fail-opens found by the Java port of the k05 oracles: one regression test per fix.
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { CORE_REGISTRY, RULE22_ENGINE, confirmDef, floorDecision, impliedFromFacts, verifyAttestation, type ActionDef, type ReviewerPins } from '../src';

const FL = { risk: 2, rev: 'irreversible', blast_ppm: 0, esc: 2, caveats: ['amount_cap'], context: ['idempotency'], prules: [] };
const doc = { verbs: [{ verb: 'a.pay.create', floors: FL }] };
const decide = (grant: Record<string, unknown>) => RULE22_ENGINE.decide({ doc, verb: 'a.pay.create', grant: { caveats: ['amount_cap'], ...grant } as never, context: ['idempotency'] });

describe('rule22 decide: the grant tiers must be non-negative integers (fail closed)', () => {
  it('a valid grant decides as before', () => {
    expect(decide({ max_esc: 3, preauth_esc: 2 })).toBe('allow');
    expect(decide({ max_esc: 3, preauth_esc: 1 })).toBe('escalate');
    expect(decide({ max_esc: 1, preauth_esc: 1 })).toBe('deny');
  });
  it.each([
    ['max_esc missing', { preauth_esc: 2 }], ['preauth_esc missing', { max_esc: 3 }], ['max_esc "3"', { max_esc: '3', preauth_esc: 2 }], ['preauth_esc "9"', { max_esc: 3, preauth_esc: '9' }],
    ['max_esc null', { max_esc: null, preauth_esc: 2 }], ['max_esc 2.5', { max_esc: 2.5, preauth_esc: 2 }], ['preauth_esc -1', { max_esc: 3, preauth_esc: -1 }], ['max_esc -0', { max_esc: -0, preauth_esc: 0 }],
    ['max_esc NaN', { max_esc: NaN, preauth_esc: 2 }], ['preauth_esc true', { max_esc: 3, preauth_esc: true }],
  ])('%s denies', (_l, g) => expect(decide(g)).toBe('deny'));
  it('floorDecision itself denies on a non-integer tier', () => {
    expect(floorDecision({ caveats: [], max_esc: undefined as never, preauth_esc: 0 }, { context: [] }, { ...FL, esc: 0, caveats: [], context: [] } as never)).toBe('deny');
  });
});

describe('verifyAttestation: final_traits must be an array (a read def is not confirmed by a missing one)', () => {
  const rev = generateKeyPair();
  const PINS: ReviewerPins = { keys: [{ kid: 'rev', pk: b64u(rev.publicKey), roles: ['reviewer'] }] };
  const read: ActionDef = { v: 1, kind: 'pca-action-def', verb: 'a.inv.read', title: 'Read', effects: ['read'], resource: { type: 'a.inv', id: '*', scope: 'one' }, params: { n: { type: 'string' } }, review: { state: 'unreviewed' } } as ActionDef;
  const c = confirmDef(read, { registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: [], ts: 1 });
  const a = c.review.attestation!;
  const v = (att: object) => verifyAttestation({ ...c, review: { state: 'confirmed', attestation: att as never } }, { pins: PINS, registry: CORE_REGISTRY });
  it('the control is confirmed', () => expect(v(a).ok).toBe(true));
  it.each([['missing', undefined], ['null', null], ['empty string', ''], ['object', {}]])('final_traits %s is refused', (_l, f) => {
    // the review message normalises final_traits (sortUniq(x ?? [])), so the original signature still covers this body
    const att: Record<string, unknown> = { ...a };
    if (f === undefined) delete att.final_traits; else att.final_traits = f;
    expect(v(att)).toMatchObject({ ok: false, reason: 'malformed' });
  });
  it('ts -0 is malformed (strict profile); ts 0 signs and verifies, and confirmDef refuses -0', () => {
    const z = confirmDef(read, { registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: [], ts: 0 });
    const za = z.review.attestation!;
    const vz = (att: object) => verifyAttestation({ ...z, review: { state: 'confirmed', attestation: att as never } }, { pins: PINS, registry: CORE_REGISTRY });
    expect(vz(za).ok).toBe(true);
    expect(vz({ ...za, ts: -0 })).toMatchObject({ ok: false, reason: 'malformed' });
    expect(() => confirmDef(read, { registry: CORE_REGISTRY, reviewer: { kid: 'rev', secret: rev.secretKey }, finalTraits: [], ts: -0 })).toThrow(/non-negative integer/);
  });
});

describe('implied traits: a null max_items is unbounded, so the array parameter is bulk', () => {
  it('null and absent both imply pca.bulk; a number does not', () => {
    const f = (max_items: unknown) => impliedFromFacts({ effects: ['create'], worstRev: 'reversible', params: [{ type: 'array', max_items: max_items as never }] } as never);
    expect(f(undefined)).toContain('pca.bulk');
    expect(f(null)).toContain('pca.bulk');
    expect(f(10)).not.toContain('pca.bulk');
  });
});
