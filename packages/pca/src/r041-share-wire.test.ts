// 0.4.1: threshold share signatures are validated PER SUITE on the wire. Before, `wire` demanded a 64-byte share `sig`, so a
// pure post-quantum share (ML-DSA-65: 3309 bytes) verified through verifyThreshold but could never be carried in a PCActn.
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { thresholdMessage, verifyPCActnCore, type PCActn } from './pcactn';
import { encodeMlDsaPublicKey, mlDsa65Keygen, validateShareSignatureWire } from './pq';
import { AUD, NOW, setup } from './server/fixture.test-util';
import { createThresholdVerifier, signShare, type Signer } from './threshold';
import { validateWireV2 } from './wire';

const seed = (n: number) => new Uint8Array(32).fill(n);
const s = setup();
const base = s.mk(s.plan[0]!);
const guardian = generateKeyPair();
const gMl = mlDsa65Keygen(seed(7));
const set: Signer[] = [
  { role: 'agent', publicKey: s.aPub },
  { role: 'guardian', publicKey: encodeKey(guardian.publicKey), pq_pk: encodeMlDsaPublicKey(gMl.publicKey) },
];
const withShares = (shares: unknown[]): PCActn => ({ ...base, threshold: { shares } }) as PCActn;
const msg = thresholdMessage(base);
const pure = signShare('guardian', guardian.secretKey, msg, { signerSet: set, t: 2 }, { alg: 'ml-dsa-65', mlDsa: gMl });
const hybrid = signShare('guardian', guardian.secretKey, msg, { signerSet: set, t: 2 }, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: gMl });
const bytes = (n: number) => b64u(new Uint8Array(n).fill(3));

describe('0.4.1 per-suite threshold share wire', () => {
  it('a pure ML-DSA-65 share (3309-byte sig) rides in a PCActn and counts toward t', async () => {
    expect(pure.sig.length).toBe(4412);
    expect(validateWireV2(withShares([pure]))).toBeNull();
    const p = withShares([pure]);
    const core = await verifyPCActnCore(p, { grant: s.grant, nowEpoch: NOW, audience: AUD, hooks: { threshold: createThresholdVerifier({ signerSet: set, t: 2 }) } });
    expect(core.checks.wire).toBe('pass');
    expect(core.checks.threshold).toBe('pass');
  });

  it('a hybrid share (64-byte sig + 3309-byte pq_sig) is accepted on the wire', () => {
    expect(validateWireV2(withShares([hybrid]))).toBeNull();
  });

  it('wrong length for the declared suite is a wire failure', () => {
    expect(validateWireV2(withShares([{ ...pure, sig: bytes(3308) }]))).toMatch(/threshold\.shares\[0\]: 'sig'.*3309 bytes.*ml-dsa-65/);
    expect(validateWireV2(withShares([{ ...pure, sig: bytes(64) }]))).toMatch(/threshold\.shares\[0\]/);
    expect(validateWireV2(withShares([{ ...hybrid, pq_sig: bytes(3310) }]))).toMatch(/'pq_sig'/);
    // an ed25519 share keeps the 64-byte rule exactly
    expect(validateWireV2(withShares([{ role: 'agent', publicKey: s.aPub, sig: bytes(3309) }]))).toMatch(/64 bytes/);
    expect(validateWireV2(withShares([{ role: 'agent', publicKey: s.aPub, sig: bytes(64) }]))).toBeNull();
  });

  it('suite fields must match the suite: missing pq_sig on a hybrid, stray pq_sig, unknown or non-string alg', () => {
    const { pq_sig: _drop, ...noPq } = hybrid;
    expect(validateWireV2(withShares([noPq]))).toMatch(/'pq_sig'/);
    expect(validateWireV2(withShares([{ ...pure, pq_sig: bytes(3309) }]))).toMatch(/'pq_sig' must be absent/);
    expect(validateWireV2(withShares([{ role: 'agent', publicKey: s.aPub, sig: bytes(64), pq_sig: bytes(3309) }]))).toMatch(/'pq_sig' must be absent/);
    expect(validateWireV2(withShares([{ ...pure, alg: 'ml-dsa-66' }]))).toMatch(/unknown signature alg/);
    expect(validateWireV2(withShares([{ ...pure, alg: 65 }]))).toMatch(/'alg' must be a string/);
    expect(validateWireV2(withShares([{ ...pure, sig: pure.sig + '=' }]))).toMatch(/threshold\.shares\[0\]/);
  });

  it('every registered suite gets its own length (ML-DSA-87, SLH-DSA, LESS variable length)', () => {
    const v = (x: Record<string, unknown>) => validateShareSignatureWire(x);
    expect(v({ alg: 'ml-dsa-87', sig: bytes(4627) })).toBeNull();
    expect(v({ alg: 'slh-dsa-sha2-128f', sig: bytes(17088) })).toBeNull();
    expect(v({ alg: 'slh-dsa-sha2-256s', sig: bytes(29792) })).toBeNull();
    expect(v({ alg: 'hybrid-ed25519-slh-dsa-sha2-128f', sig: bytes(64), pq_sig: bytes(17088) })).toBeNull();
    expect(v({ alg: 'fn-dsa-512', sig: bytes(666) })).toBeNull();
    expect(v({ alg: 'less-cat1', sig: bytes(1329 - 16) })).toBeNull();
    expect(v({ alg: 'less-cat1', sig: bytes(1329 - 15) })).not.toBeNull();
    expect(v({ alg: 'slh-dsa-sha2-128f', sig: bytes(3309) })).not.toBeNull();
  });

  it('a share pq_pk echo is not judged by wire (verifyThreshold compares it with the signer set)', () => {
    expect(validateShareSignatureWire({ ...pure, pq_pk: 'x' })).toBeNull();
    expect(validateShareSignatureWire({ role: 'agent', publicKey: s.aPub, sig: bytes(64), pq_pk: 'x' })).toBeNull();
  });
});
