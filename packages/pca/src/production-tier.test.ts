/**
 * The two features promoted in 0.5 (software attestation, the intent frontier) are production-tier and may rest on a
 * lower-tier module only through the pinned list below. The list may only shrink: a new runtime import from one of their
 * modules into an experimental or hardened module fails this test. Their `pending_ci` flag stays set until the CI gates
 * (mutation set clean over the modules, the vector and conformance jobs) have passed once.
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

const lowerEdges = (feature: string): string[] => {
  const edges: string[] = [];
  for (const m of map.features[feature]!.modules.filter((x) => !x.startsWith('ext/'))) {
    for (const d of runtimeImports(m)) {
      const f = featureOf.get(d);
      if (f !== undefined && f !== feature && ['experimental', 'hardened'].includes(map.features[f]!.tier)) edges.push(`${m} -> ${d}`);
    }
  }
  return edges.sort();
};

describe('software attestation is production-tier (pending CI) and rests on the ledger only for optional anchoring', () => {
  it('has exactly the software modules; the hardware verifiers are hardened, awaiting independent audit and hardware evaluation', () => {
    const f = map.features['attestation-software']!;
    expect(f.tier).toBe('production');
    expect(f.pending_ci).toBe(true);
    expect([...f.modules].sort()).toEqual(['attest-allowlist', 'attest-allowlist-anchor', 'attest-pq-software', 'attest-proved', 'attestation', 'passport', 'x509-strict', 'x509-validity']);
    expect(map.features.attestation!.tier).toBe('hardened');
    for (const m of map.features.attestation!.modules) expect(m === 'ext/attestation' || m.startsWith('attest-') || m === 'hardware-sevsnp').toBe(true);
  });
  it('imports a lower-tier module only for transparency-log anchoring (the ledger feature)', () => {
    expect(lowerEdges('attestation-software')).toEqual(['attest-allowlist-anchor -> ledger', 'attest-proved -> ledger', 'attestation -> ledger']);
  });
  it('no software module imports a hardware verifier', () => {
    for (const m of map.features['attestation-software']!.modules) for (const d of runtimeImports(m)) expect(featureOf.get(d)).not.toBe('attestation');
  });
});

describe('the intent frontier is production-tier (pending CI) and imports nothing lower', () => {
  it('imports no experimental or hardened module at all', () => {
    expect(map.features['intent-frontier']!.pending_ci).toBe(true);
    expect(lowerEdges('intent-frontier')).toEqual([]);
  });
});
