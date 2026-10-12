/**
 * Round-2 SECURITY: createAmdSnpVerifier refuses an empty measurement allowlist at construction but forwarded the
 * caller's (mutable) policy object to the SEV-SNP check, whose measurement gate is skipped for an EMPTY list. A policy
 * emptied after construction therefore became accept-all. The verifier must keep the allowlist it was built with.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ r: vi.fn() }));
vi.mock('./hardware-sevsnp', async (orig) => ({ ...(await orig<typeof import('./hardware-sevsnp')>()), verifyGenuineSevSnpReport: h.r }));

import { createAmdSnpVerifier } from './attest-amd-snp';

beforeEach(() => { h.r.mockReset(); h.r.mockResolvedValue({ ok: false, reason: 'stop' }); });

describe('r2: SEV-SNP measurement allowlist snapshot', () => {
  it('the policy forwarded to the report check keeps the construction-time allowlist', async () => {
    const policy = { measurements: ['aa'] };
    const v = createAmdSnpVerifier({ family: 'genoa', binding: 'report-data', policy, resolveEvidence: () => ({ report: new Uint8Array(4), vcekDer: new Uint8Array(4), askArkPem: 'pem' }) } as never);
    policy.measurements.length = 0;
    await v.verify({ document: {} as never, ctx: {} as never, nowMs: 1, expected: { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' } } as never);
    expect(h.r).toHaveBeenCalledTimes(1);
    const forwarded = (h.r.mock.calls[0]![0] as { policy: { measurements: string[] } }).policy;
    expect(forwarded.measurements).toEqual(['aa']);
  });
});
