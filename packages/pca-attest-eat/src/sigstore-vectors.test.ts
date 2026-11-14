// The shared Sigstore vectors (conformance fixtures, the npm bundle, Rekor v2 / RFC 3161 mutations) replayed through the
// reference; the natives replay the same file. The generator is checked for staleness in CI.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseTrustedRoot, verifySigstoreBundleCore } from './sigstore';

const V: { roots: Record<string, unknown>; cases: { name: string; roots: string; bundle: unknown; expect: { ok: boolean; core?: unknown; code?: string } }[] } = JSON.parse(
  readFileSync(join(__dirname, '..', '..', 'pca', 'conformance', 'sigstore-vectors.json'), 'utf8'),
);
const roots = Object.fromEntries(Object.entries(V.roots).map(([k, v]) => [k, parseTrustedRoot(v)]));

describe('sigstore-vectors.json', () => {
  it('covers Rekor v1 and v2, SET and RFC 3161 time, passes and refusals', () => {
    const ok = V.cases.filter((c) => c.expect.ok).map((c) => c.expect.core as { rekor: string; timestamps: { tsa: number; set: boolean } });
    expect(ok.some((c) => c.rekor === 'v2')).toBe(true);
    expect(ok.some((c) => c.rekor === 'v1' && c.timestamps.tsa > 0 && !c.timestamps.set)).toBe(true);
    expect(V.cases.filter((c) => !c.expect.ok).length).toBeGreaterThanOrEqual(15);
  });
  it.each(V.cases.map((c) => [c.name, c] as [string, (typeof V.cases)[number]]))('%s', (_n, c) => {
    const r = verifySigstoreBundleCore(c.bundle, { roots: roots[c.roots]! });
    expect(r.ok ? { ok: true, core: r.core } : { ok: false, code: r.code }).toEqual(c.expect);
  });
});
