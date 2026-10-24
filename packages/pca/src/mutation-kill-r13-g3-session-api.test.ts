/**
 * r13 (g3) mutation kills: the intent-session API surface no cross-language oracle reaches (the golden tables only feed
 * the validators and the verifier): the v2 goal string and its parser, mintSessionGrant's refusals and its pass-through
 * of holderPq / suite, the signature's coverage of the optional `flows` member, and the fail-closed catch of
 * verifySessionRoot.
 */
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { holderPqCommitment } from './capability';
import { b64u } from './hash';
import { INTENT_GOAL_V2C_PREFIX, INTENT_GOAL_V2_PREFIX } from './intent-binding';
import { intentGoalV2, mintSessionGrant, parseIntentGoalV2, sessionRootShapeError, validateIntentSessionWire, signSessionRoot, sessionRootDigest, verifySessionRoot, type SessionRootBody } from './intent-session';
import { publicKeyOf } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';

const seed = (l: string) => new Uint8Array(createHash('sha256').update(`r13-g3/${l}`).digest());
const dg = (l: string) => b64u(seed('dg/' + l));
const mk = (l: string) => { const sk = seed(l); return { sk, pk: b64u(publicKeyOf(sk)) }; };
const P = mk('principal');
const H = mk('holder');
const SESSION = dg('session');
const MAP = dg('map');

describe('intentGoalV2 / parseIntentGoalV2', () => {
  it('the goal strings are exact', () => {
    expect(INTENT_GOAL_V2_PREFIX).toBe('pca-intent:v2:');
    expect(INTENT_GOAL_V2C_PREFIX).toBe('pca-intent:v2c:');
    expect(intentGoalV2(SESSION, MAP)).toBe(`pca-intent:v2:${SESSION}:${MAP}`);
    expect(intentGoalV2(SESSION, MAP, 'commit')).toBe(`pca-intent:v2c:${SESSION}:${MAP}`);
  });
  it('a well-formed v2 goal parses to exactly its two digests', () => {
    expect(parseIntentGoalV2(intentGoalV2(SESSION, MAP))).toEqual({ session: SESSION, mapDigest: MAP });
    expect(parseIntentGoalV2(`pca-intent:v2:${MAP}:${SESSION}`)).toEqual({ session: MAP, mapDigest: SESSION });
  });
  it('anything else is null', () => {
    expect(parseIntentGoalV2(intentGoalV2(SESSION, MAP, 'commit'))).toBeNull(); // the committed-map prefix is not v2
    for (const g of [1, undefined, null, {}]) expect(() => parseIntentGoalV2(g as unknown as string)).not.toThrow();
    expect(parseIntentGoalV2(1 as unknown as string)).toBeNull();
    expect(parseIntentGoalV2(undefined as unknown as string)).toBeNull();
    expect(parseIntentGoalV2(`x${intentGoalV2(SESSION, MAP)}`)).toBeNull();
    expect(parseIntentGoalV2(`${SESSION}:${MAP}:pca-intent:v2:`)).toBeNull(); // ends with the prefix, does not start with it
    expect(parseIntentGoalV2('pca-intent:v2:')).toBeNull();
    expect(parseIntentGoalV2(`pca-intent:v2:${SESSION}`)).toBeNull();
    expect(parseIntentGoalV2(`pca-intent:v2:${SESSION}:${MAP}:${MAP}`)).toBeNull();
    expect(parseIntentGoalV2(`pca-intent:v2:${SESSION}:abc`)).toBeNull(); // second part not 32 bytes
    expect(parseIntentGoalV2(`pca-intent:v2:abc:${MAP}`)).toBeNull(); // first part not 32 bytes
    expect(parseIntentGoalV2(`pca-intent:v2:${SESSION}${MAP}`)).toBeNull();
  });
});

describe('mintSessionGrant', () => {
  const base = { principalSecret: P.sk, principalPublic: P.pk, holder: H.pk, session: SESSION, seq: 0, root: dg('root'), mapDigest: MAP, predicates: [], salt: 'salt' };
  it('refuses a malformed session caveat with the caveat reason', () => {
    expect(() => mintSessionGrant({ ...base, seq: 1 })).toThrow(new Error('mintSessionGrant: intent_session caveat: prev is present exactly when seq > 0'));
    expect(() => mintSessionGrant({ ...base, session: 'abc' })).toThrow(new Error('mintSessionGrant: intent_session caveat: session and root must be canonical base64url (32 bytes)'));
  });
  it('refuses a mapDigest that is not a 32-byte digest', () => {
    expect(() => mintSessionGrant({ ...base, mapDigest: 'abc' })).toThrow(new Error('mintSessionGrant: mapDigest must be canonical base64url (32 bytes)'));
  });
  it('the root carries the session caveat and commits the holder PQ key when given one', () => {
    const plain = mintSessionGrant(base).grant;
    expect(plain.holder_pq).toBeUndefined();
    expect(plain.caveats[1]).toEqual({ type: 'intent_session', session: SESSION, seq: 0, root: dg('root') });
    const pqHolder = encodeMlDsaPublicKey(mlDsa65Keygen(seed('holder-pq')).publicKey);
    const g = mintSessionGrant({ ...base, holderPq: pqHolder }).grant;
    expect(g.holder_pq).toBe(holderPqCommitment(pqHolder));
    expect(g.alg).toBeUndefined();
  });
  it('the root is signed under the requested suite', () => {
    const ml = mlDsa65Keygen(seed('principal-pq'));
    const g = mintSessionGrant({ ...base, suite: { alg: 'ml-dsa-65', mlDsa: ml } }).grant;
    expect(g.alg).toBe('ml-dsa-65');
    expect(g.pq_pk).toBe(encodeMlDsaPublicKey(ml.publicKey));
  });
});

describe('the session root signature', () => {
  const body = (over: Partial<SessionRootBody> = {}): SessionRootBody => ({
    v: 1, kind: 'pca-intent-session', session: SESSION, principals: [{ key: P.pk }], intent_ref: dg('ref'),
    schema: { aud: 'shop.example', digest: dg('schema') }, layers: { task: { map_digest: MAP } }, accumulators: [], monitors: [],
    question_uri: 'https://principal.example/q', expires_at: 1_800_000_000_000, ...over,
  });
  it('covers flows: a root signed with flows verifies, the same root with other flows does not', () => {
    const S = signSessionRoot(body({ flows: { read: ['a'] } }), P.sk);
    expect(S.flows).toEqual({ read: ['a'] });
    expect(verifySessionRoot(S)).toEqual({ ok: true });
    expect(verifySessionRoot({ ...S, flows: { read: ['b'] } })).toEqual({ ok: false, reason: 'session root signature invalid' });
    expect(verifySessionRoot({ ...S, flows: undefined })).toEqual({ ok: false, reason: 'session root signature invalid' });
    const noFlows = signSessionRoot(body(), P.sk);
    expect(Object.keys(noFlows)).not.toContain('flows');
    expect(verifySessionRoot({ ...noFlows, flows: {} })).toEqual({ ok: false, reason: 'session root signature invalid' });
    expect(sessionRootDigest(S)).not.toBe(sessionRootDigest(noFlows));
  });
  it('an internal error while verifying fails closed with the malformed-root reason', () => {
    const ml = mlDsa65Keygen(seed('principal-pq'));
    const S = signSessionRoot(body(), P.sk, { alg: 'ml-dsa-65', mlDsa: ml });
    const pins = { [P.pk]: encodeMlDsaPublicKey(ml.publicKey) };
    expect(verifySessionRoot(S, { pqPins: pins })).toEqual({ ok: true });
    const throwing = { get pqPins(): Record<string, string> { throw new Error('pin store offline'); } };
    expect(verifySessionRoot(S, throwing)).toEqual({ ok: false, reason: 'malformed session root: pin store offline' });
  });
  it('the signer may be any listed principal; an unlisted signer is refused', () => {
    const P2 = mk('principal-2');
    expect(() => signSessionRoot(body({ principals: [{ key: P2.pk }, { key: P.pk }] }), P.sk)).not.toThrow();
    const S = signSessionRoot(body({ principals: [{ key: P2.pk }, { key: P.pk }] }), P.sk);
    expect(S.signer).toBe(P.pk);
    expect(verifySessionRoot(S)).toEqual({ ok: true });
    expect(() => signSessionRoot(body({ principals: [{ key: P2.pk }] }), P.sk)).toThrow(new Error('signSessionRoot: the signer is not one of the session principals'));
  });
  it('PQ pins: a null options object or null pins mean "no pin" (refused with the pin reason, not an internal error)', () => {
    const ml = mlDsa65Keygen(seed('principal-pq'));
    const S = signSessionRoot(body(), P.sk, { alg: 'ml-dsa-65', mlDsa: ml });
    const reason = "session root suite 'ml-dsa-65' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it";
    expect(verifySessionRoot(S, null as never)).toEqual({ ok: false, reason });
    expect(verifySessionRoot(S, { pqPins: null as never })).toEqual({ ok: false, reason });
    expect(verifySessionRoot(S, {})).toEqual({ ok: false, reason });
  });
  it("the signer's principals entry: absent pq_pk is fine, another principal's pq_pk is not consulted", () => {
    const ml = mlDsa65Keygen(seed('principal-pq'));
    const ml2 = mlDsa65Keygen(seed('principal-pq-2'));
    const P2 = mk('principal-2');
    const pk1 = encodeMlDsaPublicKey(ml.publicKey);
    const pins = { [P.pk]: pk1 };
    // the signer (second) declares no pq_pk; the first principal declares a different one
    const S = signSessionRoot(body({ principals: [{ key: P2.pk, pq_pk: encodeMlDsaPublicKey(ml2.publicKey) }, { key: P.pk }] }), P.sk, { alg: 'ml-dsa-65', mlDsa: ml });
    expect(verifySessionRoot(S, { pqPins: pins })).toEqual({ ok: true });
    const S2 = signSessionRoot(body({ principals: [{ key: P2.pk }, { key: P.pk, pq_pk: encodeMlDsaPublicKey(ml2.publicKey) }] }), P.sk, { alg: 'ml-dsa-65', mlDsa: ml });
    expect(verifySessionRoot(S2, { pqPins: pins })).toEqual({ ok: false, reason: "session root pq_pk does not match the signer's principals entry" });
  });
  it('member order does not matter: a root whose schema is written {digest, aud} is well formed and verifies', () => {
    const b = body({ schema: { digest: dg('schema'), aud: 'shop.example' } as never });
    expect(sessionRootShapeError(b, { signed: false })).toBeNull();
    expect(() => signSessionRoot(b, P.sk)).not.toThrow();
    const S = signSessionRoot(b, P.sk);
    expect(Object.keys(S.schema)).toEqual(['digest', 'aud']);
    expect(sessionRootShapeError(S)).toBeNull();
    expect(verifySessionRoot(S)).toEqual({ ok: true });
  });
  it('wire prov refs must be strings: an array or object ref is refused with the prov reason (no throw)', () => {
    const w = (refs: unknown) => ({ session: SESSION, root: dg('root'), seq: 0, schema: dg('schema'), prov: { 'action.params.x': refs } });
    const reason = "'intent_session.prov.action.params.x' must be 1..8 non-empty strings of at most 256 UTF-8 bytes";
    for (const refs of [[['abc']], [{ length: 3 }], ['ok', ['abc']]]) {
      expect(() => validateIntentSessionWire(w(refs))).not.toThrow();
      expect(validateIntentSessionWire(w(refs))).toBe(reason);
    }
    expect(validateIntentSessionWire(w(['ok']))).toBeNull();
  });
});

