import { describe, expect, it } from 'vitest';
import { verifyNvidiaOcspResponse } from './attest-nvidia-ocsp';

const verify = (o: Record<string, unknown>) => verifyNvidiaOcspResponse(new Uint8Array([0]), { nowMs: 1_000, ...o } as never);
const REASON = 'nowMs and clockSkewMs must be finite and maxAgeMs a number';

describe('a non-finite clock, skew or age never admits (NVIDIA OCSP)', () => {
  // old code reached the DER parse, so the reason differed; the guard now runs first for every non-finite value
  it('an infinite or NaN clock or skew is refused up front', async () => {
    for (const v of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, Number.NaN]) {
      expect(await verify({ nowMs: v })).toMatchObject({ ok: false, reason: expect.stringContaining(REASON) });
      expect(await verify({ clockSkewMs: v })).toMatchObject({ ok: false, reason: expect.stringContaining(REASON) });
    }
  });
  it('a NaN maximum age is refused', async () => {
    expect(await verify({ maxAgeMs: Number.NaN })).toMatchObject({ ok: false, reason: expect.stringContaining(REASON) });
  });
});
