import { describe, expect, it } from 'vitest';
import { composeClear, composeSecureMalicious } from './index';
import { runDealer, runParty } from './net/protocol';

const V = [
  { allow: 1, t: 2, rQuant: 5 },
  { allow: 1, t: 1, rQuant: 3 },
];

describe('the dealer-free offline phase is the default; the trusted dealer is an explicit opt-in', () => {
  it('composeSecureMalicious with no offline option runs the dealer-free phase', () => {
    const r = composeSecureMalicious(V, { Q: 8, seed: 1n });
    expect(r.offlineMode).toBe('no-dealer');
    expect(r.composed).toEqual(composeClear(V, 8));
  });
  it('insecureTrustedDealer: true selects the dealer and labels the result', () => {
    const r = composeSecureMalicious(V, { Q: 8, seed: 1n, insecureTrustedDealer: true });
    expect(r.offlineMode).toBe('trusted-dealer');
    expect(r.composed).toEqual(composeClear(V, 8));
  });
  it('dealer options without the opt-in fail closed', () => {
    expect(() => composeSecureMalicious(V, { Q: 8, dealer: { verifyTriples: false } })).toThrow(/insecureTrustedDealer: true/);
  });
  it('an offline provider together with the dealer opt-in is refused', () => {
    expect(() => composeSecureMalicious(V, { Q: 8, insecureTrustedDealer: true, offline: { n: 2 } as never })).toThrow(/mutually exclusive/);
  });
  it('runDealer refuses without the opt-in', async () => {
    await expect(runDealer({ n: 2, mesh: {} as never })).rejects.toThrow(/insecureTrustedDealer: true/);
  });
  it('runParty with offline trusted-dealer and no opt-in aborts before any network use', async () => {
    await expect(
      runParty({ id: 0, n: 2, input: V[0]!, mesh: {} as never, sessionId: 's', offline: 'trusted-dealer' }),
    ).rejects.toMatchObject({ kind: 'local', blamed: null, reporter: 0 });
  });
});
