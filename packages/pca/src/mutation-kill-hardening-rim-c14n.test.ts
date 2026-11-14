/** An UNPREFIXED Signature/SignedInfo under a default-namespace root, signed per C14N 1.1 (xmlns emitted once), verifies; one altered byte does not. */
import { describe, expect, it } from 'vitest';
import { verifyNvidiaRim } from './attest-nvidia-rim';
import { forgeCorimPki, forgeRim, type RimMeasurementSpec } from './test-support/forge-spdm';

const PKI = forgeCorimPki({ seed: 'rim-c14n' });
const NOW = new Date('2026-10-20T00:00:00Z').getTime();
const spec: RimMeasurementSpec = { index: 0, active: true, hashes: ['a'.repeat(96)] };
const mk = (unprefixedSignature: boolean) => forgeRim({ version: '595.71.05', measurements: [spec], signerChain: PKI.certs, signerKey: PKI.signerKey, unprefixedSignature });
const verify = (xml: string) => verifyNvidiaRim(xml, { rimRootSpkiSha256: [PKI.rootSpkiSha256], nowMs: NOW });

describe('RIM signature element spelled without a prefix', () => {
  it('the forged document really is unprefixed under a default-namespace root', () => {
    const xml = mk(true);
    expect(xml).toMatch(/<Signature xmlns="http:\/\/www\.w3\.org\/2000\/09\/xmldsig#"><SignedInfo>/);
    expect(xml).not.toContain('<ds:');
    expect(mk(false)).toContain('<ds:SignedInfo>');
  });
  it('a genuinely signed unprefixed SignedInfo verifies', async () => {
    expect((await verify(mk(true))).ok).toBe(true);
  });
  it('the prefixed spelling still verifies', async () => {
    expect((await verify(mk(false))).ok).toBe(true);
  });
  it('one altered byte of SignedInfo fails', async () => {
    const xml = mk(true);
    const bad = xml.replace(/<DigestValue>(.)/, (_m, c: string) => `<DigestValue>${c === 'A' ? 'B' : 'A'}`);
    expect(bad).not.toBe(xml);
    const r = await verify(bad);
    expect(r).toMatchObject({ ok: false, reason: expect.stringContaining('SignedInfo signature does not verify under the signer certificate') });
  });
});
