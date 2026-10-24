/** 0.4.2 mutation kills: createMaaKeyTrust freezes its POLICY but keeps the injected store and fetch as the caller's own objects. */
import { describe, expect, it } from 'vitest';
import { createMaaKeyTrust } from './attest-maa-keys';

const ISSUER = 'https://sharedwus.wus.attest.azure.net';
const NOW = Date.parse('2026-10-08T23:08:00Z');

describe('createMaaKeyTrust: store / fetch by reference', () => {
  it('the store is read live (state the caller puts there AFTER construction is seen, so a corrupt record fails closed)', async () => {
    const store = { state: undefined as unknown, async get() { return this.state; }, async put(_i: string, s: unknown) { this.state = s; } };
    let fetches = 0;
    const trust = createMaaKeyTrust({ policy: { trustedIssuers: [ISSUER], builtinPins: false } as never, store: store as never, fetch: (async () => { fetches++; throw new Error('no network'); }) as never });
    store.state = { v: 1, issuer: ISSUER, fetchedAtMs: 'bad', anchors: [] };
    const r = await trust.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r).toEqual({ ok: false, code: 'corrupt-state', reason: 'persisted MAA key state failed validation' });
    expect(fetches).toBe(0);
  });
  it('the policy is frozen at construction: a later edit by the caller changes nothing', async () => {
    const policy = { trustedIssuers: [ISSUER], builtinPins: false };
    const store = { async get() { return undefined; }, async put() {} };
    const trust = createMaaKeyTrust({ policy: policy as never, store: store as never, fetch: (async () => { throw new Error('x'); }) as never });
    policy.trustedIssuers.push('https://evil.example');
    (policy as { trustedIssuers: string[] }).trustedIssuers[0] = 'https://evil.example';
    const r = await trust.getTrustAnchors(ISSUER, { nowMs: NOW });
    expect(r.ok === false && r.code).not.toBe('untrusted-issuer');
    expect(await trust.getTrustAnchors('https://evil.example', { nowMs: NOW })).toMatchObject({ ok: false, code: 'untrusted-issuer' });
  });
  it('fetch must be injected, and the issuer list must be a non-empty list of https origins', () => {
    const store = { async get() { return undefined; }, async put() {} } as never;
    expect(() => createMaaKeyTrust({ policy: { trustedIssuers: [ISSUER] } as never, store, fetch: undefined as never })).toThrow('createMaaKeyTrust: fetch must be injected');
    for (const trustedIssuers of [[], 'x', ['http://a.example'], ['https://a.example/path']]) {
      expect(() => createMaaKeyTrust({ policy: { trustedIssuers } as never, store, fetch: (async () => ({})) as never })).toThrow('createMaaKeyTrust: policy.trustedIssuers must be a non-empty list of https origin URLs');
    }
  });
});
