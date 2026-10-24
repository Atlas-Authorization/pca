/** 0.4.2 mutation kills: verifyNvidiaOcspResponse rejection reasons and freshness boundaries, from the REAL captured NVIDIA responses. */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { X509Certificate } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parsePemChain } from './attest-nvidia-spdm';
import { NVIDIA_OCSP_DEFAULT_MAX_AGE_MS, verifyNvidiaOcspResponse } from './attest-nvidia-ocsp';

const FX = resolve(__dirname, '../fixtures/real-nvidia-cc');
const chain = parsePemChain(readFileSync(resolve(FX, 'h100-device-cert-chain.pem'), 'utf8')) as X509Certificate[];
const good = new Uint8Array(readFileSync(resolve(FX, 'ocsp', '2-provisioner-ica.nonce.resp.der')));
const NOW = Date.parse('2026-10-08T23:08:00Z');
const o = (over: Record<string, unknown> = {}) => ({ cert: chain[2]!, issuer: chain[3]!, chain, nowMs: NOW, ...over });
const reason = async (b: Uint8Array, over: Record<string, unknown> = {}) => {
  const r = await verifyNvidiaOcspResponse(b, o(over) as never);
  return r.ok ? 'ok' : r.reason;
};

describe('malformed responses: exact reasons', () => {
  it('not DER / truncated / empty', async () => {
    for (const bad of [new Uint8Array(0), new Uint8Array([1, 2, 3]), good.subarray(0, 300), good.subarray(0, good.length - 1), new Uint8Array(1000).fill(0x30)]) expect(await reason(bad)).toBe('response is not valid DER');
  });
  it('trailing bytes', async () => {
    expect(await reason(Uint8Array.from([...good, 0]))).toBe('trailing bytes after OCSPResponse');
  });
  it('a non-successful status', async () => {
    expect(await reason(Uint8Array.from([0x30, 0x03, 0x0a, 0x01, 0x01]))).toBe('OCSP responseStatus is 1 (not successful)');
  });
  it('a successful status with no responseBytes', async () => {
    expect(await reason(Uint8Array.from([0x30, 0x03, 0x0a, 0x01, 0x00]))).toBe('successful response carries no responseBytes');
  });
});

describe('freshness boundaries', () => {
  it('thisUpdate / producedAt may be in the future only within the skew; the age limit is inclusive', async () => {
    const r = await verifyNvidiaOcspResponse(good, o() as never);
    if (!r.ok) throw new Error('setup');
    const { thisUpdate, producedAt } = r;
    const later = Math.max(thisUpdate, producedAt);
    expect(await reason(good, { nowMs: later })).toBe('ok');
    if (thisUpdate >= producedAt) {
      expect(await reason(good, { nowMs: thisUpdate - 1 })).toBe('response thisUpdate is in the future');
      expect(await reason(good, { nowMs: thisUpdate - 1, clockSkewMs: 1 })).not.toBe('response thisUpdate is in the future');
    } else {
      expect(await reason(good, { nowMs: producedAt - 1 })).toMatch(/in the future/);
    }
    // the age limit: now - thisUpdate > maxAge refuses, equal is fine
    expect(await reason(good, { nowMs: thisUpdate + 1000, maxAgeMs: 1000 })).toBe('ok');
    expect(await reason(good, { nowMs: thisUpdate + 1001, maxAgeMs: 1000 })).toBe('response is older than the maximum accepted age');
    expect(NVIDIA_OCSP_DEFAULT_MAX_AGE_MS).toBe(7 * 24 * 3600 * 1000);
    expect(await reason(good, { nowMs: thisUpdate + NVIDIA_OCSP_DEFAULT_MAX_AGE_MS + 1, maxAgeMs: undefined })).not.toBe('ok');
  });
});
