/** Without the optional pkijs/asn1js dependencies the OCSP module refuses with an install hint (and never throws from verify). */
import { X509Certificate } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

vi.mock('pkijs', () => {
  throw new Error('pkijs is not installed');
});

import { buildNvidiaOcspRequest, nvidiaCertOcspUrls, verifyNvidiaOcspResponse } from './attest-nvidia-ocsp';
import { parsePemChain } from './attest-nvidia-spdm';
import { forgeNvidiaScenario } from './test-support/forge-spdm';

const hint = 'NVIDIA OCSP requires the optional dependencies "pkijs" and "asn1js" (npm i pkijs asn1js)';
const sc = forgeNvidiaScenario({ seed: 'ocsp-nodeps' });
const chain: X509Certificate[] = parsePemChain(sc.device.chainPem);

describe('attest-nvidia-ocsp without pkijs', () => {
  it('request building and AIA parsing reject with the install hint', async () => {
    await expect(buildNvidiaOcspRequest(chain[0]!, chain[1]!)).rejects.toThrow(new Error(hint));
    await expect(nvidiaCertOcspUrls(chain[0]!)).rejects.toThrow(new Error(hint));
  });
  it('response verification fails closed (never throws) with the hint in the reason', async () => {
    const r = await verifyNvidiaOcspResponse(new Uint8Array([0x30, 0x00]), { cert: chain[0]!, issuer: chain[1]!, chain, nowMs: sc.nowMs });
    expect(r).toEqual({ ok: false, reason: `OCSP response rejected: ${hint}` });
  });
});
