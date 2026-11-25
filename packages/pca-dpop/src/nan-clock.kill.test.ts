import { describe, expect, it } from 'vitest';
import { createDpopNonceIssuer, createInMemoryDpopReplayStore } from './index';

// A clock that is not a finite number must never admit: NaN compares false, so "now < held" used to read as "not held".
describe('non-finite clock fails closed', () => {
  it('a replay store holding a live entry still refuses the key when now is NaN', async () => {
    const store = createInMemoryDpopReplayStore();
    expect(await store.addIfAbsent('k', 100, 10)).toBe(true);
    for (const bad of [NaN, Infinity, -Infinity]) expect(await store.addIfAbsent('k', 100, bad)).toBe(false);
  });
  it('a nonce is never valid under a non-finite clock', () => {
    const issuer = createDpopNonceIssuer({ secret: new Uint8Array(32).fill(1) });
    const nonce = issuer.issue(1000);
    expect(issuer.check(nonce, 1000)).toBe(true);
    for (const bad of [NaN, Infinity, -Infinity]) expect(issuer.check(nonce, bad)).toBe(false);
  });
});
