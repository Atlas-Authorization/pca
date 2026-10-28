/**
 * The product-layer feature is production-tier (pending CI). It may rest on a lower-tier module only through the pinned
 * list below (the agent mesh reuses the Merkle log and consistency proof of the ledger, never its witness path). It
 * imports no hardware-bound module (entropy, the PUF verifier, hardware attestation), no FROST, no ZK and no KEM code.
 * The list may only shrink.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

const here = __dirname;
const map = JSON.parse(readFileSync(join(here, '..', 'maturity.json'), 'utf8')) as { features: Record<string, { tier: string; pending_ci?: boolean; modules: string[] }> };
const featureOf = new Map<string, string>();
for (const [f, v] of Object.entries(map.features)) for (const m of v.modules) featureOf.set(m, f);

function runtimeImports(m: string): string[] {
  const text = readFileSync(join(here, `${m}.ts`), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const out = new Set<string>();
  for (const x of text.matchAll(/(?:^|[\n;])\s*(?:import|export)\s+(?!type\s)([^;]*?)\bfrom\s+['"](\.[^'"]+)['"]/g)) {
    const clause = x[1]!.trim();
    if (/^\{[^}]*\}$/.test(clause) && clause.slice(1, -1).split(',').every((t) => !t.trim() || /^type\s/.test(t.trim()))) continue;
    const target = join(dirname(m), x[2]!.replace(/\.js$/, '')).split('\\').join('/');
    if (existsSync(join(here, `${target}.ts`))) out.add(target);
  }
  return [...out].sort();
}

const modules = (): string[] => map.features['product-layer']!.modules.filter((x) => !x.startsWith('ext/'));

describe('the product layer is production-tier (pending CI)', () => {
  it('is production with pending_ci set', () => {
    expect(map.features['product-layer']!.tier).toBe('production');
    expect(map.features['product-layer']!.pending_ci).toBe(true);
  });
  it('holds neither the QRNG entropy module nor the PUF verifier', () => {
    expect(modules()).not.toContain('entropy');
    expect(modules()).not.toContain('attest-puf');
    expect(map.features.entropy!.tier).toBe('hardened');
  });
  it('imports a lower-tier module only through the pinned list', () => {
    const edges: string[] = [];
    for (const m of modules()) for (const d of runtimeImports(m)) {
      const f = featureOf.get(d);
      if (f !== undefined && f !== 'product-layer' && ['experimental', 'hardened'].includes(map.features[f]!.tier)) edges.push(`${m} -> ${d}`);
    }
    expect(edges.sort()).toEqual(['mesh -> ledger']);
  });
  it('imports no hardware-bound, FROST, ZK or KEM module', () => {
    for (const m of modules()) for (const d of runtimeImports(m)) {
      expect([m, featureOf.get(d)]).not.toEqual([m, 'frost']);
      expect([m, featureOf.get(d)]).not.toEqual([m, 'attestation']);
      expect([m, featureOf.get(d)]).not.toEqual([m, 'zk-compliance']);
      expect([m, featureOf.get(d)]).not.toEqual([m, 'kem']);
      expect([m, featureOf.get(d)]).not.toEqual([m, 'entropy']);
    }
  });
});
