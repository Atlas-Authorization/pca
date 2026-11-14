// EAT evidence for blueprint admission: every verdict shape of the underlying verification maps to one exact admission result.
import { createHash } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateEatKeyPair, type AttestationTier, type FreshAttestedVerdict } from './index';
import { ed25519Jkt, eatAdmissionEvidence } from './admission';

// admission.ts and index.ts import each other, so vi.mock('./index') never reaches admission; swap the export on the one real module object instead
const actual = await vi.importActual<typeof import('./index')>('./index');
const verify = vi.fn<typeof actual.verifyFreshAttestedEAT>();
Object.defineProperty(actual, 'verifyFreshAttestedEAT', { configurable: true, enumerable: true, get: () => verify });

const KEY = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const opts = () => ({ verifyKey: generateEatKeyPair().publicKey, nonce: 'n', instanceKey: KEY, policy: {}, now: 1 });
const verdict = (v: Partial<FreshAttestedVerdict> & { ok: boolean }): FreshAttestedVerdict => ({ reasons: [], ...v });
const claims = { iss: 'i', iat: 0 };
const run = (v: FreshAttestedVerdict, o: Partial<ReturnType<typeof opts>> & { minTier?: 'affirming' | 'affirming-hw-rooted' } = {}) => {
  verify.mockResolvedValueOnce(v);
  return eatAdmissionEvidence('eat', { ...opts(), ...o });
};

beforeEach(() => verify.mockReset());

describe('eatAdmissionEvidence', () => {
  it('the instance key thumbprint is the RFC 7638 form of the Ed25519 JWK', () => {
    expect(ed25519Jkt('abc')).toBe(createHash('sha256').update('{"crv":"Ed25519","kty":"OKP","x":"abc"}').digest('base64url'));
    expect(ed25519Jkt('abc')).not.toBe(ed25519Jkt('abd'));
  });
  it('a failed verification is refused with its last reason, or a default one', async () => {
    expect(await run(verdict({ ok: false }))).toEqual({ ok: false, bound: false, reason: 'EAT rejected' });
    expect(await run(verdict({ ok: false, reasons: ['a', 'b', 'c'] }))).toEqual({ ok: false, bound: false, reason: 'c' });
    expect(await run(verdict({ ok: false, reasons: ['only'], tier: 'affirming' }))).toEqual({ ok: false, bound: false, reason: 'only' });
  });
  it('an accepted verification with no appraisal tier is refused the same way', async () => {
    expect(await run(verdict({ ok: true }))).toEqual({ ok: false, bound: false, reason: 'EAT rejected' });
    expect(await run(verdict({ ok: true, reasons: ['x', 'y', 'z'] }))).toEqual({ ok: false, bound: false, reason: 'z' });
  });
  it('the minimum tier defaults to affirming; degraded tiers are refused as bound evidence', async () => {
    for (const tier of ['warning', 'contraindicated', 'rejected'] as AttestationTier[]) {
      expect(await run(verdict({ ok: true, tier, claims })), tier).toEqual({ ok: false, bound: true, reason: `appraisal tier ${tier} is below the minimum` });
    }
    expect(await run(verdict({ ok: true, tier: 'affirming', claims }))).toEqual({ ok: true, bound: true });
    expect(await run(verdict({ ok: true, tier: 'affirming-hw-rooted', claims }))).toEqual({ ok: true, bound: true });
  });
  it('a hardware-rooted minimum refuses software-vouched evidence', async () => {
    expect(await run(verdict({ ok: true, tier: 'affirming', claims }), { minTier: 'affirming-hw-rooted' })).toEqual({ ok: false, bound: true, reason: 'appraisal tier affirming is below the minimum' });
    expect(await run(verdict({ ok: true, tier: 'affirming-hw-rooted', claims }), { minTier: 'affirming-hw-rooted' })).toEqual({ ok: true, bound: true });
  });
  it('the identity is the measured identity the verifier established, and absent when there is none', async () => {
    expect(await run(verdict({ ok: true, tier: 'affirming' }))).toEqual({ ok: true, bound: true });
    expect(await run(verdict({ ok: true, tier: 'affirming', claims }))).toEqual({ ok: true, bound: true });
    const measured = { runtime_measurement: 'r', model_id: 'm', weights_digest: 'w', operator: 'o', extra: 'ignored' };
    const r = await run(verdict({ ok: true, tier: 'affirming', claims: { ...claims, measured } }));
    expect(r).toStrictEqual({ ok: true, bound: true, identity: { runtime_measurement: 'r', model_id: 'm', weights_digest: 'w', operator: 'o' } });
  });
  it('the verification is asked for the instance key binding, with the instance-only options removed', async () => {
    await run(verdict({ ok: true, tier: 'affirming' }), { minTier: 'affirming' });
    const passed = verify.mock.calls.at(-1)![1] as unknown as Record<string, unknown>;
    expect(passed.channelBinding).toEqual({ jkt: ed25519Jkt(KEY) });
    expect(passed.nonce).toBe('n');
    expect('instanceKey' in passed).toBe(false);
    expect('minTier' in passed).toBe(false);
  });
  it('a verification that throws is refused unbound, named by the error type', async () => {
    verify.mockRejectedValueOnce(new TypeError('boom'));
    expect(await eatAdmissionEvidence('eat', opts())).toEqual({ ok: false, bound: false, reason: 'TypeError' });
    verify.mockImplementationOnce(() => {
      throw 'a string';
    });
    expect(await eatAdmissionEvidence('eat', opts())).toEqual({ ok: false, bound: false, reason: 'error' });
    verify.mockRejectedValueOnce({ name: 'NotAnError' });
    expect(await eatAdmissionEvidence('eat', opts())).toEqual({ ok: false, bound: false, reason: 'error' });
  });
});
