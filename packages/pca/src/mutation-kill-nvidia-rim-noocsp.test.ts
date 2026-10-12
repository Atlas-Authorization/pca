/** The collateral hook refuses (instead of crashing) when the optional OCSP dependencies cannot be loaded. */
import { describe, expect, it, vi } from 'vitest';

vi.mock('./attest-nvidia-ocsp', () => {
  throw new Error('pkijs is not installed');
});

import { nvidiaCollateralHook } from './attest-nvidia-rim';
import { parseNvidiaSpdmEvidence, parsePemChain } from './attest-nvidia-spdm';
import { forgeNvidiaScenario } from './test-support/forge-spdm';

describe('nvidiaCollateralHook without pkijs/asn1js', () => {
  const sc = forgeNvidiaScenario({ seed: 'noocsp' });
  const chain = parsePemChain(sc.device.chainPem);
  const ctx = { report: parseNvidiaSpdmEvidence(sc.evidence.evidence), chain, leaf: chain[0]!, nowMs: sc.nowMs };
  const hook = (over: Record<string, unknown>) =>
    nvidiaCollateralHook({ rimRootSpkiSha256: [sc.rimRootSpkiSha256], resolve: () => ({ driverRimXml: sc.driverRimXml, vbiosRimXml: sc.vbiosRimXml, crls: sc.crls, ...(over['ocsp'] ? { ocsp: over['ocsp'] as Uint8Array[] } : {}) }), ...over } as never);
  const msg = 'revocation: OCSP verification needs the optional dependencies pkijs and asn1js (not installed)';
  it('required OCSP, and supplied OCSP evidence, both fail closed with the install hint', async () => {
    expect(await hook({ revocation: 'ocsp' })(ctx)).toBe(msg);
    expect(await hook({ revocation: 'both' })(ctx)).toBe(msg);
    expect(await hook({ ocsp: [new Uint8Array([1])] })(ctx)).toBe(msg);
  });
  it('CRL-only revocation never loads the OCSP module', async () => {
    expect(await hook({})(ctx)).toBeUndefined();
  });
});
