import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { admitWithEvidence, signBlueprint } from '@atlasauth/pca-grants';
import { buildEAT, ed25519Jkt, eatAdmissionEvidence, generateEatKeyPair, issueNonce } from './index';

const ISS = 'https://attester.atlasauth.net';
const NOW = 1_700_000_000_000;
const operator = generateKeyPair();
const inst = generateKeyPair();
const other = generateKeyPair();
const INST = encodeKey(inst.publicKey);
const measured = { model_id: 'm1', weights_digest: 'ab'.repeat(32), runtime_measurement: 'cd'.repeat(32), operator: 'acme' };
const policy = { endorsements: { issuers: [ISS] }, referenceValues: { measurements: [measured.runtime_measurement] } };
const bp = signBlueprint(operator.secretKey, { id: 'fleet', key: 'bpkey', ceiling: [], epoch: 1, status: 'active', issued_at: NOW, runtime_pins: [{ runtime_measurement: measured.runtime_measurement, operator: 'acme' }] });
const setup = (over: Partial<Parameters<typeof buildEAT>[0]> = {}, keyOf = INST) => {
  const { publicKey, privateKey } = generateEatKeyPair();
  const nonce = issueNonce({ now: NOW }).value;
  const eat = buildEAT({ issuer: ISS, nonce, channelBinding: { jkt: ed25519Jkt(keyOf) }, key: privateKey, now: NOW, measured, ...over });
  return { publicKey, nonce, eat };
};
const ev = (s: ReturnType<typeof setup>, o: object = {}) => eatAdmissionEvidence(s.eat, { verifyKey: s.publicKey, nonce: s.nonce, instanceKey: INST, policy, now: NOW, issuer: ISS, ...o });

describe('EAT evidence for blueprint admission - T-593', () => {
  it('a verified, fresh, instance-bound, appraised EAT admits under a matching pin', async () => {
    const s = setup();
    const e = await ev(s);
    expect(e).toMatchObject({ ok: true, bound: true, identity: { runtime_measurement: measured.runtime_measurement, operator: 'acme' } });
    expect(await admitWithEvidence(bp, () => e)).toMatchObject({ admitted: true });
  });
  it('the RFC 7638 thumbprint is stable and key-specific', () => {
    expect(ed25519Jkt(INST)).toBe(ed25519Jkt(INST));
    expect(ed25519Jkt(INST)).not.toBe(ed25519Jkt(encodeKey(other.publicKey)));
    expect(ed25519Jkt(INST)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it('everything unverifiable denies: wrong key, stale nonce, evidence for another instance, bad signature, policy miss, no measured identity', async () => {
    const s = setup();
    expect(await ev(s, { verifyKey: generateEatKeyPair().publicKey })).toMatchObject({ ok: false });
    expect(await ev(s, { nonce: 'a-different-nonce' })).toMatchObject({ ok: false });
    expect(await ev(s, { instanceKey: encodeKey(other.publicKey) })).toMatchObject({ ok: false, bound: false });
    expect(await ev(setup({}, encodeKey(other.publicKey)))).toMatchObject({ ok: false }); // evidence minted for another instance
    expect(await eatAdmissionEvidence(s.eat.slice(0, -4) + 'AAAA', { verifyKey: s.publicKey, nonce: s.nonce, instanceKey: INST, policy, now: NOW })).toMatchObject({ ok: false });
    expect(await ev(s, { policy: { endorsements: { issuers: ['https://someone-else'] } } })).toMatchObject({ ok: false });
    expect(await ev(s, { policy: {} })).toMatchObject({ ok: false });
    expect(await ev(s, { now: NOW + 3_600_000 })).toMatchObject({ ok: false }); // too old
    const bare = setup({ measured: undefined });
    const e = await ev(bare, { policy: { endorsements: { issuers: [ISS] } } });
    expect(e).toMatchObject({ ok: true, bound: true });
    expect(await admitWithEvidence(bp, () => e)).toMatchObject({ admitted: false, code: 'no_identity' });
  });
  it('a measured identity that matches no pin is not admitted', async () => {
    const s = setup({ measured: { ...measured, runtime_measurement: 'ee'.repeat(32) } });
    const e = await ev(s, { policy: { endorsements: { issuers: [ISS] }, referenceValues: { measurements: ['ee'.repeat(32)] } } });
    expect(e.ok).toBe(true);
    expect(await admitWithEvidence(bp, () => e)).toMatchObject({ admitted: false, code: 'no_matching_pin' });
  });
  it('a minimum tier of affirming-hw-rooted refuses software-vouched evidence', async () => {
    const s = setup();
    expect(await ev(s, { minTier: 'affirming-hw-rooted' })).toMatchObject({ ok: false, bound: true });
  });
});
