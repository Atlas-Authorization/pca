import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { signGnapRequest, verifyGnapRequest } from './index';

describe('verifyGnapRequest with a non-finite clock never admits', () => {
  // pre-fix: `created > nowSec + 60` and the staleness check were both false for a NaN clock, so a proof of any age passed
  it.each([Number.NaN, Number.NEGATIVE_INFINITY])('now of %s', async (now) => {
    const k = generateKeyPair();
    const c = { secretKey: k.secretKey, publicKey: k.publicKey, b64: b64u(k.publicKey) };
    const body = { x: 1 };
    const s = await signGnapRequest({ body, key: c, htm: 'POST', uri: 'https://as/tx', created: 1_700_000_000 });
    const ok = await verifyGnapRequest({ detachedJws: s.detachedJws, body, holder: c.b64, htm: 'POST', uri: 'https://as/tx', now: 1_700_000_000_000, replayCheck: 'unchecked' });
    expect(ok.ok).toBe(true);
    expect((await verifyGnapRequest({ detachedJws: s.detachedJws, body, holder: c.b64, htm: 'POST', uri: 'https://as/tx', now, replayCheck: 'unchecked' })).ok).toBe(false);
  });
  it('maxAgeSec of +Infinity (an unbounded window admits any age)', async () => {
    const k = generateKeyPair();
    const c = { secretKey: k.secretKey, publicKey: k.publicKey, b64: b64u(k.publicKey) };
    const body = { x: 1 };
    const s = await signGnapRequest({ body, key: c, htm: 'POST', uri: 'https://as/tx', created: 1_700_000_000 });
    const r = await verifyGnapRequest({ detachedJws: s.detachedJws, body, holder: c.b64, htm: 'POST', uri: 'https://as/tx', now: 1_700_000_000_000, maxAgeSec: Number.POSITIVE_INFINITY, replayCheck: 'unchecked' });
    expect(r.ok).toBe(false);
  });
});
