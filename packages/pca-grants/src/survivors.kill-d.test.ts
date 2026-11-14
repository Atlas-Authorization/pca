import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@atlasauth/pca';
import { LeaseRegistry, memoryLeaseKv, renewLease } from './lease';
import { WindowReadAccumulator, listAuthorized, type CandidateSource } from './list-authorized';
import { signerOf } from './sig';

describe('renewLease input checks come before the lease lookup', () => {
  const SK = new Uint8Array(32).fill(61);
  const reg = new LeaseRegistry({ authorities: [signerOf(SK)] }, memoryLeaseKv());
  const T0 = 1_800_000_000_000;
  it('refuses a bad clock or a bad increment even for an unknown lease', async () => {
    const bad = { ok: false, code: 'bad_input' };
    expect(await renewLease(SK, reg, 'nope', { now: 1.5, increment: 100, justification_digest: 'j' })).toEqual(bad);
    expect(await renewLease(SK, reg, 'nope', { now: T0, increment: 1.5, justification_digest: 'j' })).toEqual(bad);
    expect(await renewLease(SK, reg, 'nope', { now: -1, increment: 100, justification_digest: 'j' })).toEqual(bad);
    expect(await renewLease(SK, reg, 'nope', { now: T0, increment: 0, justification_digest: 'j' })).toEqual(bad);
    expect(await renewLease(SK, reg, 'nope', { now: T0, increment: 100, justification_digest: 'j' })).toEqual({ ok: false, code: 'unknown_lease' });
  });
});

describe('listAuthorized page size', () => {
  const kp = generateKeyPair();
  const ALL = Array.from({ length: 10 }, (_, i) => `doc:${i}`);
  it('ignores candidates beyond the page limit: charges, returns and resumes by the limit only', async () => {
    const wide: CandidateSource = { async page({ limit }) { return { objects: ALL.slice(0, limit + 2) }; } };
    const reads = new WindowReadAccumulator(3, 60_000);
    const r = await listAuthorized({
      subject: 'agent:a', resourceType: 'doc', permits: () => true, candidates: wide, filterId: 'f1', policyDigest: 'pd', freshAtDigest: 'fa',
      page: { limit: 3 }, reads, now: 1000, signingSecret: kp.secretKey,
    });
    expect(r.objects).toEqual(['doc:0', 'doc:1', 'doc:2']);
    expect('next_cursor' in r).toBe(false);
  });
});
