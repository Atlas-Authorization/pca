import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytesStrict, generateKeyPair, hashCanonical, utf8, verifyB64u } from '@atlasauth/pca';
import {
  actionValuesOf,
  answerRef,
  answerShapeError,
  coordsError,
  deviceChallenge,
  INTENT_ANSWER_REF_DOMAIN,
  INTENT_ANSWER_SIG_DOMAIN,
  INTENT_DEVICE_CHALLENGE_DOMAIN,
  INTENT_TYPED_DOMAIN,
  isB64u32,
  isFrictionTier,
  isObj,
  maxFriction,
  signIntentAnswer,
  typedDigest,
  verifyIntentAnswer,
} from './index';

const D = (s: string) => hashCanonical({ t: s });
const key = generateKeyPair();
const UX = { tier: 'typed' as const, rendered_digest: D('card'), typed_digest: D('typed'), canary: false };
const A = signIntentAnswer(
  { map_digest: D('m'), session: D('s'), question_id: 'q_1', verb: 'air.book', cell: { 'action.params.total': [2, 3] }, y: 1, source: 'elicitation', observed_at: 1_000, ux: UX },
  key.secretKey,
);
const shape = (over: Record<string, unknown>) => answerShapeError({ ...A, ...over });
const ux = (over: Record<string, unknown>) => shape({ ux: { ...A.ux, ...over } });
const part = (partial: unknown) => shape({ partial });
const WA = { credential_id: 'c', authenticator_data: 'a', client_data_json: 'j', signature: 's' };

describe('small predicates', () => {
  it('isObj is true only for plain non-null non-array objects', () => {
    expect(isObj({})).toBe(true);
    for (const v of [null, [], 'x', 5, undefined, true]) expect(isObj(v)).toBe(false);
  });
  it('isB64u32 needs canonical 32-byte base64url', () => {
    expect(isB64u32(D('x'))).toBe(true);
    for (const v of ['bad', '', 5, null, b64u(new Uint8Array(31))]) expect(isB64u32(v)).toBe(false);
  });
  it('isFrictionTier accepts exactly the four tiers', () => {
    for (const t of ['tap', 'hold', 'typed', 'device']) expect(isFrictionTier(t)).toBe(true);
    for (const t of ['bogus', '', 5, null]) expect(isFrictionTier(t)).toBe(false);
  });
  it('maxFriction of nothing is tap', () => {
    expect(maxFriction()).toBe('tap');
    expect(maxFriction('hold', 'tap')).toBe('hold');
  });
  it('actionValuesOf keeps only finite numbers and strings', () => {
    const a = { verb: 'v', resource: 'r', params: { s: 'x', n: 1, nan: Number.NaN, inf: Infinity, b: true, nil: null, o: {} }, reversibility_class: 'reversible' };
    expect(actionValuesOf(a)).toEqual({ verb: 'v', values: { 'action.resource': 'r', 'action.params.s': 'x', 'action.params.n': 1 } });
  });
});

describe('answerShapeError messages', () => {
  it('accepts the signed base answer', () => {
    expect(answerShapeError(A)).toBeNull();
  });
  it('not an object', () => {
    for (const v of [null, 'x', 5, [], undefined]) expect(answerShapeError(v)).toBe('not an object');
  });
  it('version and kind', () => {
    expect(shape({ v: 1 })).toBe('not a pca-intent-observation v2');
    expect(shape({ kind: 'other' })).toBe('not a pca-intent-observation v2');
  });
  it('each digest member must be canonical 32-byte base64url', () => {
    for (const k of ['map_digest', 'session', 'signer']) expect(shape({ [k]: 'bad' })).toBe(`${k} is not canonical base64url (32 bytes)`);
  });
  it('question id', () => {
    const msg = 'question_id must match [A-Za-z0-9_-]{1,64}';
    for (const q of [5, '', 'a b', 'q'.repeat(65)]) expect(shape({ question_id: q })).toBe(msg);
    expect(shape({ question_id: 'q'.repeat(64) })).toBeNull();
  });
  it('verb', () => {
    for (const v of ['', 5, undefined]) expect(shape({ verb: v })).toBe('verb must be a non-empty string');
  });
  it('cell, y, source, observed_at, alg', () => {
    expect(shape({ cell: {} })).toBe(`cell: ${coordsError({})}`);
    expect(shape({ y: 2 })).toBe('y must be 0 or 1');
    expect(shape({ source: 'clarification' })).toBeNull();
    expect(shape({ source: 'x' })).toBe('source must be elicitation or clarification');
    expect(shape({ observed_at: 0 })).toBeNull();
    expect(shape({ observed_at: -1 })).toBe('observed_at must be a non-negative safe integer');
    expect(shape({ alg: 'rsa' })).toBe('alg must be ed25519');
  });
  it('ux members', () => {
    expect(shape({ ux: null })).toBe('ux must be an object');
    expect(shape({ ux: 'x' })).toBe('ux must be an object');
    expect(ux({ tier: 'bogus' })).toBe('ux.tier is not a friction tier');
    expect(ux({ tier: 5 })).toBe('ux.tier is not a friction tier');
    expect(ux({ rendered_digest: 'bad' })).toBe('ux.rendered_digest is not canonical base64url (32 bytes)');
    expect(ux({ canary: 'no' })).toBe('ux.canary must be a boolean');
    expect(ux({ typed_digest: 'bad' })).toBe('ux.typed_digest is not canonical base64url (32 bytes)');
    expect(ux({ action_digest: 'bad' })).toBe('ux.action_digest is not canonical base64url (32 bytes)');
    expect(ux({ consent_for_action: 'yes' })).toBe('ux.consent_for_action must be a boolean');
  });
  it('hold_ms is a non-negative safe integer', () => {
    for (const h of [-1, 1.5, '5', Number.NaN, 2 ** 60]) expect(ux({ hold_ms: h })).toBe('ux.hold_ms must be a non-negative integer');
    expect(ux({ hold_ms: 0 })).toBeNull();
  });
  it('consent for an action needs the digest, a plain yes and no canary', () => {
    const msg = 'consent_for_action needs action_digest and a plain yes';
    const withDigest = { consent_for_action: true, action_digest: D('act') };
    expect(ux({ consent_for_action: true })).toBe(msg);
    expect(shape({ y: 0, ux: { ...A.ux, ...withDigest } })).toBe(msg);
    expect(shape({ partial: { path: 'p', upTo: 1 }, ux: { ...A.ux, ...withDigest } })).toBe(msg);
    expect(ux(withDigest)).toBeNull();
    expect(ux({ ...withDigest, canary: true })).toBe('a canary never consents to an action');
  });
  it('webauthn evidence', () => {
    const msg = 'ux.webauthn is malformed';
    for (const w of [null, 'x', [], { ...WA, extra: 'e' }, { credential_id: 'c' }, { ...WA, signature: 5 }, { credential_id: 1, authenticator_data: 2, client_data_json: 3, signature: 4 }]) expect(ux({ webauthn: w })).toBe(msg);
    expect(ux({ webauthn: WA })).toBeNull();
  });
});

describe('partial answers', () => {
  it('shape of the partial member', () => {
    for (const p of [null, 'x', [], { path: 5, upTo: 1 }, { path: '', upTo: 1 }]) expect(part(p)).toBe('partial.path must be a non-empty string');
    const one = 'partial must carry exactly one of upTo / from / except / notFor';
    expect(part({ path: 'p' })).toBe(one);
    expect(part({ path: 'p', upTo: 1, from: 2 })).toBe(one);
    expect(part({ path: 'p', foo: 1 })).toBe('unknown partial member "foo"');
  });
  it('upTo and from are integers', () => {
    for (const k of ['upTo', 'from']) {
      for (const v of [1.5, '1', -0]) expect(part({ path: 'p', [k]: v })).toBe(`partial.${k} must be an integer`);
      expect(part({ path: 'p', [k]: 3 })).toBeNull();
    }
  });
  it('except is a non-empty integer array', () => {
    const msg = 'partial.except must be a non-empty integer array';
    for (const v of [[], [1.5], [1, 'x'], 5, 'abc', {}]) expect(part({ path: 'p', except: v })).toBe(msg);
    expect(part({ path: 'p', except: [1, 2] })).toBeNull();
  });
  it('notFor is a non-empty array of non-empty strings', () => {
    const msg = 'partial.notFor must be a non-empty string array';
    for (const v of [[], [''], [5], ['a', 5], [['a']], 'abc', 5, {}]) expect(part({ path: 'p', notFor: v })).toBe(msg);
    expect(part({ path: 'p', notFor: ['a', 'b'] })).toBeNull();
  });
  it('a partial answer is a yes', () => {
    expect(shape({ y: 0, partial: { path: 'p', upTo: 1 } })).toBe('a partial answer carries y = 1 (yes for the part)');
  });
});

describe('signing and verification', () => {
  it('signs utf8(domain) followed by the strict canonical body', () => {
    const { sig, ...body } = A;
    const d = utf8(INTENT_ANSWER_SIG_DOMAIN);
    const c = canonicalBytesStrict(body);
    const m = new Uint8Array(d.length + c.length);
    m.set(d, 0);
    m.set(c, d.length);
    expect(verifyB64u(A.signer, m, sig)).toBe(true);
    expect(INTENT_ANSWER_SIG_DOMAIN).toBe('atlas-pca/intent-obs/v2\0');
  });
  it('a partial member is signed', () => {
    const p = signIntentAnswer({ ...A, partial: { path: 'action.params.total', upTo: 5 } } as Parameters<typeof signIntentAnswer>[0], key.secretKey);
    expect(p.partial).toEqual({ path: 'action.params.total', upTo: 5 });
    expect(verifyIntentAnswer(p)).toEqual({ ok: true });
    expect(verifyIntentAnswer({ ...p, partial: { path: 'action.params.total', upTo: 6 } })).toEqual({ ok: false, reason: 'bad signature' });
    const { partial: _p, ...without } = p;
    expect(verifyIntentAnswer(without)).toEqual({ ok: false, reason: 'bad signature' });
  });
  it('reports the shape error for a malformed answer and a bad signature otherwise', () => {
    expect(verifyIntentAnswer(null)).toEqual({ ok: false, reason: 'not an object' });
    expect(verifyIntentAnswer({ ...A, y: 2 })).toEqual({ ok: false, reason: 'y must be 0 or 1' });
    expect(verifyIntentAnswer({ ...A, sig: b64u(new Uint8Array(64)) })).toEqual({ ok: false, reason: 'bad signature' });
    expect(verifyIntentAnswer(A)).toEqual({ ok: true });
  });
  it('never throws: an exception inside becomes a malformed-answer refusal', () => {
    const boom = { includes: () => { throw new Error('boom'); } } as unknown as string[];
    expect(verifyIntentAnswer(A, boom)).toEqual({ ok: false, reason: 'malformed answer: boom' });
  });
});

describe('content addresses', () => {
  it('answerRef, typedDigest and deviceChallenge hash their domain-separated members', () => {
    expect(answerRef(A)).toBe(hashCanonical({ d: INTENT_ANSWER_REF_DOMAIN, a: A }));
    expect(INTENT_ANSWER_REF_DOMAIN).toBe('atlas-pca/intent-answer-ref/v1');
    expect(typedDigest('q_1', '778')).toBe(hashCanonical({ d: INTENT_TYPED_DOMAIN, q: 'q_1', v: '778' }));
    expect(typedDigest('q_1', '778')).not.toBe(typedDigest('q_1', '779'));
    expect(INTENT_TYPED_DOMAIN).toBe('atlas-pca/intent-typed/v1');
    const r = D('card');
    expect(deviceChallenge({ questionId: 'q_1', renderedDigest: r, y: 1 })).toBe(hashCanonical({ d: INTENT_DEVICE_CHALLENGE_DOMAIN, q: 'q_1', r, y: 1, a: null }));
    expect(deviceChallenge({ questionId: 'q_1', renderedDigest: r, y: 0, actionDigest: D('act') })).toBe(hashCanonical({ d: INTENT_DEVICE_CHALLENGE_DOMAIN, q: 'q_1', r, y: 0, a: D('act') }));
    expect(INTENT_DEVICE_CHALLENGE_DOMAIN).toBe('atlas-pca/intent-device/v1');
  });
});
