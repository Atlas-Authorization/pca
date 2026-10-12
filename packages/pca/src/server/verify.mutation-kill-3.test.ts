/** Round 3 for server/verify.ts: the exact check statuses an RS sees when a context element is absent, and the denied fallback. */
import { describe, expect, it } from 'vitest';
import { AUD, NOW, setup } from './fixture.test-util';
import { verifyPCActn } from './verify';
import { issueLivenessBeacon } from '../beacons';
import { generateKeyPair } from '../keys';

describe('verifyPCActn: absent context is reported as not-enforced, not pass', () => {
  it('no params / plan / revocation epoch / beacon / budget', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: {} });
    expect(v.checks.params_digest).toBe('not-enforced');
    expect(v.checks.plan_root_authorized).toBe('not-enforced');
    expect(v.checks.freshness).toBe('not-enforced');
    expect(v.checks.beacon).toBe('not-enforced');
    expect(v.checks.budget).toBe('not-enforced');
  });
  it('supplied elements flip the statuses to pass', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), {
      grant: s.grant, now: NOW, audience: AUD,
      context: { plan: s.plan, params: {}, budget: { B: 100, tau: NOW, asOf: NOW } },
    });
    expect(v.checks.params_digest).toBe('pass');
    expect(v.checks.budget).toBe('pass');
  });
  it('a bad beacon is rejected with the issuer reason (or the fixed fallback), never passed', async () => {
    const s = setup();
    const issuer = generateKeyPair();
    const bc = { beacon: { not: 'a beacon' } as never, issuers: [issuer.publicKey as never], instance: 'i' };
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: AUD, context: { beacon: bc as never } });
    expect(v.checks.beacon).toBe('fail');
    expect(v.reasons.some((r) => r.startsWith('beacon: '))).toBe(true);
    expect(v.allow).toBe(false);
  });
  it('a denial always carries at least one reason', async () => {
    const s = setup();
    const v = await verifyPCActn(s.mk(s.plan[0]!), { grant: s.grant, now: NOW, audience: 'wrong-aud', context: {} });
    expect(v.allow).toBe(false);
    expect(v.reasons.length).toBeGreaterThan(0);
    expect(v.reasons.every((r) => r !== '')).toBe(true);
  });
});
void issueLivenessBeacon;
