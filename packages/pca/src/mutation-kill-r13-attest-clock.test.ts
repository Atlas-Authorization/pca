/**
 * 0.4.2 fix (r13 review): an unreadable verifier clock must refuse. With nowMs = NaN (or a hook clock returning NaN /
 * undefined / Infinity) every window and nonce-age comparison is false, which used to mean "valid": fail open.
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

describe('verifier clock', () => {
  it('a valid document passes at a finite clock (control)', async () => {
    expect((await run({})).ok).toBe(true);
    expect((await run({ nowMs: T + 0.5 })).ok).toBe(true);
  });
  it.each([Number.NaN, Infinity, -Infinity, '5000000'])('a %s clock is refused (fail closed)', async (bad) => {
    const v = await run({ nowMs: bad as unknown as number });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('verifier clock is not a finite time (fail closed)');
  });
  it('a hook whose clock returns NaN refuses', async () => {
    const hook = createAttestationVerifier({ trustedAttestorKeys: [ATT_PUB], resolveDocument: () => doc(), expectedBinding: () => EXPECTED, now: () => Number.NaN });
    const r = await hook(mkCtx());
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('verifier clock is not a finite time (fail closed)');
  });
});
