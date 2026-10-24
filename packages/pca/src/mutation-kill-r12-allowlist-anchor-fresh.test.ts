/**
 * 0.4.2 r12 mutation kills: attest-allowlist-anchor.ts builds DOMAIN, the B64U_DIGEST pattern and the `anchorEntryOf`
 * arrow at module load. Under Stryker's mutant switching that happens before any mutant is active, so the statically-
 * importing anchor tests never saw these mutants. Each test here re-evaluates the module (vi.resetModules + dynamic import).
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  const a = await import('./attest-allowlist-anchor');
  const hash = await import('./hash');
  const keys = await import('./keys');
  return { a, hash, keys };
}

describe('anchor commitment domain (fresh module)', () => {
  it('the leaf is hashCanonical over the pca-attest-allowlist-anchor/v1 domain and the entry', async () => {
    const { a, hash } = await fresh();
    const e = { issuer: 'ops', version: 3, digest: 'A'.repeat(43) };
    expect(a.allowlistAnchorCommit(e)).toBe(hash.hashCanonical({ domain: 'pca-attest-allowlist-anchor/v1', issuer: 'ops', version: 3, digest: 'A'.repeat(43) }));
    expect(a.allowlistAnchorCommit(e)).not.toBe(hash.hashCanonical({ domain: '', issuer: 'ops', version: 3, digest: 'A'.repeat(43) }));
  });
});

describe('anchor entry digest pattern (fresh module)', () => {
  it('accepts exactly 43 base64url chars and refuses 42 / 44 or a non-alphabet char', async () => {
    const { a, keys } = await fresh();
    const g = keys.generateKeyPair();
    const anchor = (digest: string) => {
      const log = a.createAllowlistAnchorLog({ instanceId: 'inst-1', principal: 'allowlist-log' });
      return a.anchorAllowlistHead(log, { issuer: 'ops', version: 1, digest }, { guardianSecret: g.secretKey, nowMs: 1_000 });
    };
    expect(anchor('Az09_-'.repeat(7) + 'x').entries).toStrictEqual([{ issuer: 'ops', version: 1, digest: 'Az09_-'.repeat(7) + 'x' }]);
    expect(() => anchor('A'.repeat(42))).toThrow('anchorAllowlistHead: malformed entry');
    expect(() => anchor('A'.repeat(44))).toThrow('anchorAllowlistHead: malformed entry');
    expect(() => anchor(`${'A'.repeat(42)}=`)).toThrow('anchorAllowlistHead: malformed entry');
    expect(() => anchor(`=${'A'.repeat(43)}`)).toThrow('anchorAllowlistHead: malformed entry');
    expect(() => anchor(`${'A'.repeat(43)}=`)).toThrow('anchorAllowlistHead: malformed entry');
  });
});

describe('anchorEntryOf (fresh module)', () => {
  it('projects exactly issuer / version / digest', async () => {
    const { a } = await fresh();
    const v = { ok: true, issuer: 'i', version: 4, digest: 'B'.repeat(43), body: {}, alg: 'ed25519' } as never;
    expect(a.anchorEntryOf(v)).toStrictEqual({ issuer: 'i', version: 4, digest: 'B'.repeat(43) });
  });
});
