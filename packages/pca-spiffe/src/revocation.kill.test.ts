import { describe, expect, it } from 'vitest';
import { SpiffeError, createRevocationSource, type RevocationList } from './index';

const PLACEHOLDER = 'Stryker was here';
const x509 = (o: Partial<{ spiffeId: string; serialNumber: string; fingerprint256: string }> = {}) => ({
  spiffeId: 'spiffe://example.org/a', serialNumber: '01', fingerprint256: 'AA:BB', position: 0, isLeaf: true, ...o,
});
const jwt = (o: Partial<{ spiffeId: string; jti: string; tokenHash: string }> = {}) => ({
  spiffeId: 'spiffe://example.org/a', expiresAt: 1, tokenHash: 'h', ...o,
});
const src = (list: unknown) => createRevocationSource({ fetch: async () => list as RevocationList, refreshMs: 10, maxStaleMs: 30, now: () => 0 });

describe('revocation snapshot parsing', () => {
  it('absent list fields revoke nothing, whatever the subject looks like', async () => {
    const s = src({});
    await s.refresh();
    expect(s.x509(x509({ spiffeId: PLACEHOLDER, serialNumber: PLACEHOLDER, fingerprint256: PLACEHOLDER }))).toBe(false);
    expect(await s.jwt(jwt({ spiffeId: PLACEHOLDER, jti: PLACEHOLDER, tokenHash: PLACEHOLDER }))).toBe(false);
  });

  it('a list field that mixes strings with other values refuses the whole snapshot', async () => {
    const s = src({ jtis: ['ok', 5] });
    const err = await s.refresh().catch((e: unknown) => e as SpiffeError);
    expect(err).toBeInstanceOf(SpiffeError);
    expect((err as SpiffeError).code).toBe('revocation_unavailable');
    expect((err as SpiffeError).message).toBe('revocation list field "jtis" must be an array of strings');
  });

  it('matches fingerprints and serials regardless of case, colons and leading zeros', async () => {
    const s = src({ fingerprints: ['aa:bb'], serials: ['00ab'] });
    await s.refresh();
    expect(s.x509(x509({ fingerprint256: 'AA:BB', serialNumber: '99' }))).toBe(true);
    expect(s.x509(x509({ fingerprint256: 'CC:DD', serialNumber: 'AB' }))).toBe(true);
    expect(s.x509(x509({ fingerprint256: 'CC:DD', serialNumber: 'AC' }))).toBe(false);
  });

  it('a jwt without a jti is revoked only by spiffe id or token hash', async () => {
    const s = src({ jtis: ['j1'], tokenHashes: ['bad'] });
    await s.refresh();
    expect(await s.jwt(jwt())).toBe(false);
    expect(await s.jwt(jwt({ jti: 'j1' }))).toBe(true);
    expect(await s.jwt(jwt({ tokenHash: 'bad' }))).toBe(true);
  });

  it('checking before any snapshot exists is revocation_unavailable', () => {
    const s = createRevocationSource({ fetch: async () => ({}), refreshMs: 10, maxStaleMs: 30, now: () => 0 });
    let err: unknown;
    try {
      s.x509(x509());
    } catch (e) {
      err = e;
    }
    expect((err as SpiffeError).code).toBe('revocation_unavailable');
    expect((err as SpiffeError).message).toBe('no revocation snapshot available');
  });
});
