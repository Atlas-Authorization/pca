/**
 * Negative paths for the AMD hardware-root wiring, driven by chains FORGED in AMD's real wire format (RSA-4096
 * RSASSA-PSS ARK/ASK, EC P-384 VCEK with the AMD hwID/SPL extensions) under a TEST ARK pin. Each failure is
 * produced by the hardened @atlasauth/pca verifier this package delegates to, and every test asserts the SPECIFIC
 * rejection reason. The positive control is a report signed by the forged VCEK.
 */
import { describe, it, expect } from 'vitest';
import { parseSevSnpReport } from '@atlasauth/pca';
import { ecdsaSign } from './test-support/forge-x509';
import { serializeSevSnpReport } from './test-support/sevsnp-report';
import { FORGE_CHIP, FORGE_NA, FORGE_NB, amdVcekExtensions, ext, forgeAmdChain, type AmdChainOptions } from './test-support/forge-amd';
import { verifyAmdAttestation, type AmdAttestationInput } from './index';

const NOW = Date.parse('2026-10-08T12:00:00Z');
const DAY = 86_400_000;
const MEASUREMENT = 'aa'.repeat(48);
const SPL = { chip: FORGE_CHIP, bl: 7, tee: 0, snp: 3, ucode: 0 };

const cache = new Map<string, ReturnType<typeof forgeAmdChain>>();
function chain(name: string, o: AmdChainOptions = {}): ReturnType<typeof forgeAmdChain> {
  let c = cache.get(name);
  if (!c) {
    c = forgeAmdChain({ label: 'eat-amd-test', ...o });
    cache.set(name, c);
  }
  return c;
}

function le72(b: Uint8Array): Uint8Array {
  const o = new Uint8Array(72);
  o.set(Uint8Array.from(b).reverse(), 0);
  return o;
}

/** A report signed by the forged chain's VCEK, bound to the forged CHIP_ID + the SPLs the VCEK carries. */
function signedReport(c: ReturnType<typeof forgeAmdChain>, over: { policy?: bigint } = {}): Uint8Array {
  const fields = {
    version: 2,
    vmpl: 0,
    policy: over.policy ?? 0n,
    reported_tcb: 0x0003_0000_0000_0007n,
    measurement: new Uint8Array(48).fill(0xaa),
    chip_id: FORGE_CHIP,
  };
  const parsed = parseSevSnpReport(serializeSevSnpReport(fields));
  const sig = ecdsaSign(c.vcekKey, 'sha384', parsed.signed).raw;
  return serializeSevSnpReport({ ...fields, signature: { r: le72(sig.subarray(0, 48)), s: le72(sig.subarray(48, 96)) } });
}

function input(c: ReturnType<typeof forgeAmdChain>, over: Partial<AmdAttestationInput> = {}): AmdAttestationInput {
  return { vcek: c.vcekDer, ask: c.askDer, ark: c.arkDer, trustAnchorArkSpkiSha384: c.arkPin, nowMs: NOW, ...over };
}

describe('forged AMD-format chain through verifyAmdAttestation (delegated to core)', () => {
  it('baseline: a report signed by the forged VCEK verifies and projects EAT evidence', async () => {
    const c = chain('ok');
    const r = await verifyAmdAttestation(signedReport(c), input(c, { expectedMeasurement: MEASUREMENT }));
    expect(r.reason).toBeUndefined();
    expect(r.ok).toBe(true);
    expect(r.evidence?.measurement).toBe(MEASUREMENT);
    expect(r.measured?.runtime_measurement).toBe(MEASUREMENT);
  }, 120_000);

  it('rejects a non-CA ASK (BasicConstraints CA:FALSE)', async () => {
    const c = chain('askNotCa', { ask: { extensions: [ext.basicConstraints(false), ext.keyUsage(['keyCertSign'])] } });
    const r = await verifyAmdAttestation(signedReport(c), input(c));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('cert chain invalid: AMD chain role check failed: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)');
  }, 120_000);

  it('rejects an ASK without BasicConstraints', async () => {
    const c = chain('askNoBc', { ask: { extensions: [ext.keyUsage(['keyCertSign'])] } });
    const r = await verifyAmdAttestation(signedReport(c), input(c));
    expect(r.reason).toBe('cert chain invalid: AMD chain role check failed: issuer certificate at depth 1 has no BasicConstraints (not a CA)');
  }, 120_000);

  it('rejects a VCEK that asserts CA:TRUE', async () => {
    const c = chain('vcekCa', { vcek: { extensions: [ext.basicConstraints(true), ...amdVcekExtensions(SPL)] } });
    const r = await verifyAmdAttestation(signedReport(c), input(c));
    expect(r.reason).toBe('cert chain invalid: AMD chain role check failed: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)');
  }, 120_000);

  it('rejects an ASK not issued by the ARK, and a VCEK not issued by the ASK', async () => {
    const foreignAsk = chain('askForeign', { askSignedBy: 'other-amd' });
    expect((await verifyAmdAttestation(signedReport(foreignAsk), input(foreignAsk))).reason).toBe('cert chain invalid: ASK is not signed by ARK');
    const foreignVcek = chain('vcekForeign', { vcekSignedBy: 'other-amd' });
    expect((await verifyAmdAttestation(signedReport(foreignVcek), input(foreignVcek))).reason).toBe('cert chain invalid: VCEK is not signed by ASK');
  }, 240_000);

  it('rejects a chain under a different ARK pin (wrong family) and under a real family pin', async () => {
    const c = chain('ok');
    const wrong = await verifyAmdAttestation(signedReport(c), { vcek: c.vcekDer, ask: c.askDer, ark: c.arkDer, family: 'genoa', nowMs: NOW });
    expect(wrong.reason).toBe('cert chain invalid: ARK does not match the pinned AMD trust anchor');
  }, 120_000);

  for (const [name, who] of [['VCEK', 'vcek'], ['ASK', 'ask'], ['ARK', 'ark']] as const) {
    it(`rejects a ${name} that is not yet valid, and one that has expired, at the verifier clock`, async () => {
      const early = chain(`${who}-early`, { [who]: { notBefore: new Date(NOW + DAY), notAfter: FORGE_NA } });
      expect((await verifyAmdAttestation(signedReport(early), input(early))).reason).toBe(`cert chain invalid: ${name} certificate is not yet valid`);
      const late = chain(`${who}-late`, { [who]: { notBefore: FORGE_NB, notAfter: new Date(NOW - DAY) } });
      expect((await verifyAmdAttestation(signedReport(late), input(late))).reason).toBe(`cert chain invalid: ${name} certificate has expired`);
    }, 240_000);
  }

  it('rejects a report signed by a key that is not the VCEK', async () => {
    const c = chain('ok');
    const other = chain('ok-other-vcek-sig', { label: 'eat-amd-other' });
    const r = await verifyAmdAttestation(signedReport(other), input(c));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('report signature does not verify under VCEK');
  }, 240_000);

  it('rejects a debug-enabled guest by default and accepts it only with the explicit allowDebug opt-in', async () => {
    const c = chain('ok');
    const report = signedReport(c, { policy: 1n << 19n });
    const denied = await verifyAmdAttestation(report, input(c));
    expect(denied.ok).toBe(false);
    expect(denied.reason).toBe('guest policy has the DEBUG bit set (host can inspect the guest)');
    const allowed = await verifyAmdAttestation(report, input(c, { allowDebug: true }));
    expect(allowed.reason).toBeUndefined();
    expect(allowed.evidence?.debug).toBe(true);
  }, 120_000);

  it('rejects a report whose chip id the VCEK does not certify', async () => {
    const c = chain('wrongChip', { vcek: { spl: { chip: new Uint8Array(64).fill(1) } } });
    const r = await verifyAmdAttestation(signedReport(c), input(c));
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('VCEK CHIP_ID does not match report chip_id');
  }, 120_000);

  it('rejects an ASK/ARK pair handed in the wrong order', async () => {
    const c = chain('ok');
    const r = await verifyAmdAttestation(signedReport(c), input(c, { ask: c.arkDer, ark: c.askDer }));
    expect(r.reason).toBe('cert chain invalid: second certificate of the chain is not a self-signed ARK (chain out of order?)');
  }, 120_000);
});
