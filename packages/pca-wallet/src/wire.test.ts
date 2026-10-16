import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, hashCanonical, intentActionDigest, paramsDigest } from '@atlasauth/pca';
import { rng } from '@atlasauth/pca-intent';
import {
  actionValuesOf,
  answerRef,
  answerShapeError,
  coordsError,
  frictionRank,
  maxFriction,
  pcaActionDigest,
  signIntentAnswer,
  verifyIntentAnswer,
  type SignedIntentAnswer,
} from './index';

const D = (s: string) => hashCanonical({ t: s });
const ana = generateKeyPair();
const site = generateKeyPair();
const AD = D('action');

const answer = (over: Partial<Parameters<typeof signIntentAnswer>[0]> = {}): SignedIntentAnswer =>
  signIntentAnswer(
    {
      map_digest: D('m'),
      session: D('s'),
      question_id: 'q_7Hk2',
      verb: 'air.book',
      cell: { 'action.params.total': [2, 3], 'action.params.add_ons': ['none'] },
      y: 1,
      source: 'elicitation',
      observed_at: 1_000,
      ux: { tier: 'typed', rendered_digest: D('card'), typed_digest: D('typed'), canary: false, action_digest: AD, consent_for_action: true },
      ...over,
    },
    ana.secretKey,
  );

describe('cell coordinates (shared with the core intent_required)', () => {
  it('are index ranges or value sets, never text blobs', () => {
    expect(coordsError({ a: [1, 2] })).toBeNull();
    expect(coordsError({ a: ['x', 'y'] })).toBeNull();
    expect(coordsError({ a: [2, 1] })).not.toBeNull();
    expect(coordsError({ a: [1, 'x'] })).not.toBeNull();
    expect(coordsError({ a: ['x', 'x'] })).not.toBeNull();
    expect(coordsError({})).not.toBeNull();
  });
  it('the action digest is the core one, over the PCActn action with the params digest', () => {
    const a = { verb: 'air.book', resource: 'skyair.example/bookings', params: { total: 77800 }, reversibility_class: 'irreversible' };
    expect(pcaActionDigest(a)).toBe(intentActionDigest({ verb: a.verb, resource: a.resource, params_digest: paramsDigest(a.params), reversibility_class: a.reversibility_class }));
    expect(pcaActionDigest({ ...a, params: { total: 77801 } })).not.toBe(pcaActionDigest(a));
    expect(actionValuesOf({ ...a, params: { total: 77800, add_ons: ['none'], note: null } })).toEqual({ verb: 'air.book', values: { 'action.resource': 'skyair.example/bookings', 'action.params.total': 77800 } });
  });
});

describe('M6 signed answer (observation v2)', () => {
  it('signs and verifies; the signer must be a session principal', () => {
    const a = answer();
    expect(verifyIntentAnswer(a, [a.signer])).toEqual({ ok: true });
    expect(verifyIntentAnswer(a, [b64u(site.publicKey)])).toEqual({ ok: false, reason: 'signer is not a principal of the session' });
    expect(answerRef(a)).toBe(answerRef(JSON.parse(JSON.stringify(a)) as SignedIntentAnswer));
  });
  it('every signed member is covered: flipping any of them breaks the signature', () => {
    const a = answer();
    const flips: Record<string, unknown>[] = [
      { y: 0 },
      { question_id: 'q_other' },
      { observed_at: 1_001 },
      { session: D('s2') },
      { map_digest: D('m2') },
      { cell: { 'action.params.total': [2, 2], 'action.params.add_ons': ['none'] } },
      { ux: { ...a.ux, tier: 'device' } },
      { ux: { ...a.ux, rendered_digest: D('card2') } },
      { ux: { ...a.ux, consent_for_action: false } },
    ];
    for (const f of flips) expect(verifyIntentAnswer({ ...a, ...f }).ok).toBe(false);
  });
  it('tier evidence must be present for a yes, and a canary never consents to an action', () => {
    expect(() => answer({ ux: { tier: 'typed', rendered_digest: D('c'), canary: false } })).toThrow(/typed tier needs typed_digest/);
    expect(() => answer({ ux: { tier: 'hold', rendered_digest: D('c'), canary: false, hold_ms: 1999 } })).toThrow(/hold tier/);
    expect(() => answer({ ux: { tier: 'device', rendered_digest: D('c'), canary: false } })).toThrow(/WebAuthn/);
    expect(() => answer({ ux: { tier: 'typed', rendered_digest: D('c'), typed_digest: D('t'), canary: true, action_digest: D('a'), consent_for_action: true } })).toThrow(/canary/);
    // A "no" needs no friction evidence.
    expect(answer({ y: 0, ux: { tier: 'device', rendered_digest: D('c'), canary: false } }).y).toBe(0);
    // A partial answer is a yes for the part, and never a JIT consent.
    expect(() => answer({ partial: { path: 'action.params.total', upTo: 70000 } })).toThrow(/consent_for_action/);
    expect(answer({ partial: { path: 'action.params.total', upTo: 70000 }, ux: { tier: 'typed', rendered_digest: D('c'), typed_digest: D('t'), canary: false } }).partial).toEqual({ path: 'action.params.total', upTo: 70000 });
  });
  it('unknown members (agent text) are refused at any level', () => {
    const a = answer();
    expect(answerShapeError({ ...a, note: 'hi' })).toBe('unknown member "note"');
    expect(answerShapeError({ ...a, ux: { ...a.ux, rationale: 'x' } })).toBe('ux: unknown member "rationale"');
  });
});

describe('friction order', () => {
  it('max is the join of the chain tap < hold < typed < device (property)', () => {
    const r = rng(7);
    const T = ['tap', 'hold', 'typed', 'device'] as const;
    for (let i = 0; i < 200; i++) {
      const a = T[Math.floor(r() * 4)]!;
      const b = T[Math.floor(r() * 4)]!;
      const m = maxFriction(a, b);
      expect(frictionRank(m)).toBe(Math.max(frictionRank(a), frictionRank(b)));
      expect(maxFriction(a, b)).toBe(maxFriction(b, a));
    }
  });
});
