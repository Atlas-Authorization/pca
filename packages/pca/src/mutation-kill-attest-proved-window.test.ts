/**
 * 0.4.2 mutation kills for attest-proved.ts: the non-integer (double) arithmetic fallbacks of the nonce-age and validity-window
 * decisions at their exact boundaries, the refusal reasons for hostile contexts (an absent pcactn / attestation is a refusal with
 * its own reason, never an exception), and the self-declared-nonce hook on partial contexts.
 */
import { describe, expect, it } from 'vitest';
import { attestationBindingB64u, createAttestationVerifier, verifyAttestation, type AttestationDocument, type ExpectedAttestationBinding } from './attestation';
import type { AgentBinding } from './envelope';
import { mintGrant } from './envelope';
import { b64u, canonicalBytes, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';

const T = 5_000_000;
const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
const HOLDER = 'holder-key';
const GREF = 'grant-ref-1';
const att = generateKeyPair();
const ATT_PUB = encodeKey(att.publicKey);
const EXPECTED: ExpectedAttestationBinding = { holderPub: HOLDER, grantRef: GREF, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 };
const BOUND = attestationBindingB64u(EXPECTED);
const principal = generateKeyPair();
const grantWith = (binding: AgentBinding = {}) =>
  mintGrant({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: HOLDER, goal: 'g', envelope: { predicates: [{ verb: 'read', resource: '*' }], caveats: [], agent_binding: binding, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const mkCtx = (over: Record<string, unknown> = {}) => ({ pcactn: { grant_ref: GREF, attestation: { epoch: 1, quote_digest: NONCE }, cap_chain: [{ holder: HOLDER }], ...over }, grant: grantWith() }) as never;
const body = (o: Record<string, unknown> = {}) => ({
  model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 1000, attestor: ATT_PUB, mode: 'software', binding: BOUND, ...o,
});
const doc = (o: Record<string, unknown> = {}): AttestationDocument => {
  const b = body(o);
  const m = canonicalBytes(b);
  const p = utf8('atlas-pca/attest/v1\0');
  const msg = new Uint8Array(p.length + m.length);
  msg.set(p);
  msg.set(m, p.length);
  return { ...b, sig: b64u(sign(att.secretKey, msg)) } as never;
};
const run = (o: { document?: AttestationDocument; ctx?: unknown; expected?: Partial<ExpectedAttestationBinding>; nowMs?: number; maxNonceAgeMs?: number; clockSkewMs?: number } = {}) =>
  verifyAttestation({
    document: o.document ?? doc(),
    ctx: ('ctx' in o ? o.ctx : mkCtx()) as never,
    expected: { ...EXPECTED, ...(o.expected ?? {}) },
    nowMs: o.nowMs ?? T,
    trustedAttestorKeys: [ATT_PUB],
    ...(o.maxNonceAgeMs !== undefined ? { maxNonceAgeMs: o.maxNonceAgeMs } : {}),
    ...(o.clockSkewMs !== undefined ? { clockSkewMs: o.clockSkewMs } : {}),
  });
const why = async (o: Parameters<typeof run>[0]) => {
  const v = await run(o);
  expect(v.ok, 'expected a refusal').toBe(false);
  return v.reason;
};
const OK = undefined;
const verdict = async (o: Parameters<typeof run>[0]) => ((await run(o)).ok ? OK : await why(o));

describe('validity window, fractional clock (double arithmetic)', () => {
  const NOW = T + 0.5;
  const w = (iat: number, exp: number, extra: Parameters<typeof run>[0] = {}) => verdict({ document: doc({ issued_at: iat, expires_at: exp }), nowMs: NOW, ...extra });
  it('expires before it is issued is malformed; equal is a valid instant', async () => {
    expect(await w(NOW + 0.25, NOW)).toBe('malformed attestation validity window');
    expect(await w(NOW, NOW)).toBe(OK);
  });
  it('not yet valid exactly when now + skew < issued_at', async () => {
    expect(await w(NOW + 0.25, NOW + 1)).toBe('attestation not yet valid');
    expect(await w(NOW + 0.25, NOW + 1, { clockSkewMs: 0.25 })).toBe(OK);
    expect(await w(NOW + 0.25, NOW + 1, { clockSkewMs: 0.125 })).toBe('attestation not yet valid');
    expect(await w(NOW, NOW + 1)).toBe(OK);
  });
  it('expired exactly when now - skew > expires_at', async () => {
    expect(await w(NOW - 1, NOW - 0.25)).toBe('attestation expired');
    expect(await w(NOW - 1, NOW - 0.25, { clockSkewMs: 0.25 })).toBe(OK);
    expect(await w(NOW - 1, NOW - 0.25, { clockSkewMs: 0.125 })).toBe('attestation expired');
    expect(await w(NOW - 1, NOW)).toBe(OK);
  });
  it('a fractional issue / expiry time with an integer clock takes the same decisions', async () => {
    expect(await verdict({ document: doc({ issued_at: T + 0.5, expires_at: T + 1 }) })).toBe('attestation not yet valid');
    expect(await verdict({ document: doc({ issued_at: T - 1, expires_at: T - 0.5 }) })).toBe('attestation expired');
    expect(await verdict({ document: doc({ issued_at: T - 1.5, expires_at: T + 0.5 }) })).toBe(OK);
  });
});

describe('server nonce age, fractional values', () => {
  const NOW = T + 0.5;
  const n = (issuedAt: number, extra: Parameters<typeof run>[0] = {}) => verdict({ nowMs: NOW, expected: { nonceIssuedAt: issuedAt }, document: doc({ binding: attestationBindingB64u({ ...EXPECTED, nonceIssuedAt: issuedAt }) }), ...extra });
  it('issued in the future exactly when now + skew < issued', async () => {
    expect(await n(NOW + 0.25)).toBe('nonce issued in the future');
    expect(await n(NOW + 0.25, { clockSkewMs: 0.25 })).toBe(OK);
    expect(await n(NOW)).toBe(OK);
  });
  it('stale exactly when now - issued > maxAge + skew', async () => {
    expect(await n(NOW - 1000.25, { maxNonceAgeMs: 1000 })).toBe('attestation nonce expired (stale quote)');
    expect(await n(NOW - 1000.25, { maxNonceAgeMs: 1000, clockSkewMs: 0.25 })).toBe(OK);
    expect(await n(NOW - 1000, { maxNonceAgeMs: 1000 })).toBe(OK);
  });
  it('a fractional issue time with an integer clock and integer skew still decides on the doubles', async () => {
    expect(await verdict({ expected: { nonceIssuedAt: T + 0.5 }, document: doc({ binding: attestationBindingB64u({ ...EXPECTED, nonceIssuedAt: T + 0.5 }) }) })).toBe('nonce issued in the future');
    const stale = await verdict({ expected: { nonceIssuedAt: T - 1000.5 }, document: doc({ binding: attestationBindingB64u({ ...EXPECTED, nonceIssuedAt: T - 1000.5 }) }), maxNonceAgeMs: 1000 });
    expect(stale).toBe('attestation nonce expired (stale quote)');
    const fresh = await verdict({ expected: { nonceIssuedAt: T - 999.5 }, document: doc({ binding: attestationBindingB64u({ ...EXPECTED, nonceIssuedAt: T - 999.5 }) }), maxNonceAgeMs: 1000 });
    expect(fresh).toBe(OK);
  });
  it('a missing or non-finite issue time is not a freshness proof', async () => {
    for (const v of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const r = await run({ expected: { nonceIssuedAt: v }, document: doc({ binding: BOUND }) });
      expect(r.ok === false ? r.reason : 'accepted').not.toBe('accepted');
    }
  });
});

describe('hostile contexts are refusals with their own reasons', () => {
  it('no pcactn at all: the grant_ref differs', async () => {
    expect(await why({ ctx: { grant: grantWith() } })).toBe('attestation binding: PCActn grant_ref differs from expected grant');
  });
  it('a pcactn without an attestation: the epoch differs', async () => {
    expect(await why({ ctx: { pcactn: { grant_ref: GREF }, grant: grantWith() } })).toBe('attestation binding: PCActn attestation epoch differs from expected epoch');
  });
  it('an attestation without a quote digest: the nonce does not bind', async () => {
    expect(await why({ ctx: mkCtx({ attestation: { epoch: 1 } }) })).toBe('attestation nonce does not bind to this PCActn');
  });
  it('a wrong quote digest, wrong epoch, wrong grant ref, each with its own reason', async () => {
    expect(await why({ ctx: mkCtx({ attestation: { epoch: 1, quote_digest: 'zz' } }) })).toBe('attestation nonce does not bind to this PCActn');
    expect(await why({ ctx: mkCtx({ attestation: { epoch: 2, quote_digest: NONCE } }) })).toBe('attestation binding: PCActn attestation epoch differs from expected epoch');
    expect(await why({ ctx: mkCtx({ grant_ref: 'other' }) })).toBe('attestation binding: PCActn grant_ref differs from expected grant');
  });
});

describe('the self-declared-nonce hook on partial contexts', () => {
  const hook = createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => doc(), now: () => T, insecure_selfDeclaredNonce: true });
  it('a context without a pcactn is refused, not thrown', async () => {
    const r = await hook({ grant: grantWith() } as never);
    expect(r.ok).toBe(false);
    expect(r.enforced).toBe(true);
    expect(r.present).toBe(true);
    expect(r.bound).toBe(false);
    expect(r.reason).not.toMatch(/verification error/);
  });
  it('the holder is the last chain element; an empty chain falls back to the grant holder; a non-string holder is ""', async () => {
    const mk = (cap_chain: unknown) => ({ pcactn: { grant_ref: GREF, attestation: { epoch: 1, quote_digest: NONCE }, cap_chain }, grant: { holder: HOLDER } }) as never;
    const doc2 = (holder: string) => doc({ binding: attestationBindingB64u({ holderPub: holder, grantRef: GREF, epoch: 1, nonce: NONCE }), issued_at: T - 1000 });
    const refusal = 'attestation binding not constructible: binding: holderPub required';
    const v = (d: AttestationDocument, ctx: unknown) => createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => d, now: () => T, insecure_selfDeclaredNonce: true })(ctx as never);
    expect((await v(doc2('last'), mk([{ holder: 'first' }, { holder: 'last' }]))).ok).toBe(true);
    expect((await v(doc2('first'), mk([{ holder: 'first' }, { holder: 'last' }]))).ok).toBe(false);
    expect((await v(doc2(HOLDER), mk([]))).ok).toBe(true);
    const nonString = await v(doc2('x'), mk([{ holder: 5 }]));
    expect([nonString.ok, nonString.reason]).toEqual([false, refusal]);
  });
  it('the hook uses the wall clock by default', async () => {
    const d = doc({ issued_at: Date.now() - 1000, expires_at: Date.now() + 60_000 });
    const h = createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => d, insecure_selfDeclaredNonce: true });
    const ctx = { pcactn: { grant_ref: GREF, attestation: { epoch: 1, quote_digest: NONCE }, cap_chain: [{ holder: HOLDER }] }, grant: grantWith() } as never;
    const r = await h(ctx);
    expect(r.reason).not.toBe('attestation expired');
    expect(r.reason).not.toBe('attestation not yet valid');
  });
});
