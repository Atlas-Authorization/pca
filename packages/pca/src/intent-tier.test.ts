/**
 * The intent layer's tier (binding and enforcement) may rest on a lower-tier module only through one optional
 * seam, documented: `verifyIntentAnchor` (transparency-log anchoring, the ledger feature). The attested classifier gate
 * (`verifyClassifierAttestation`) rests on the semantic-threshold module, which is production since the frontier became
 * tighten-or-escalate only. This test pins that list. It may only shrink: a new runtime import from an intent module
 * into an experimental or hardened module fails it.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

const here = __dirname;
const map = JSON.parse(readFileSync(join(here, '..', 'maturity.json'), 'utf8')) as { features: Record<string, { tier: string; modules: string[] }> };
const featureOf = new Map<string, string>();
for (const [f, v] of Object.entries(map.features)) for (const m of v.modules) featureOf.set(m, f);

/** The runtime (non type-only) relative imports and re-exports of a module. */
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

describe('the hardened intent feature', () => {
  it('is production (pending CI; B16 made the durable session store, the clock and attested progress state the defaults), and its frontier members are production', () => {
    expect(map.features.intent!.tier).toBe('production');
    expect(map.features['intent-frontier']!.tier).toBe('production');
    expect(map.features['intent-frontier']!.modules.sort()).toEqual(['frontier-signals', 'objective-binding', 'objective-risk', 'progress', 'semantic-threshold']);
  });
  it('imports an experimental or hardened module only through the one documented optional seam', () => {
    const lower = (m: string) => {
      const f = featureOf.get(m);
      return f !== undefined && f !== 'intent' && ['experimental', 'hardened'].includes(map.features[f]!.tier);
    };
    const edges: string[] = [];
    for (const m of map.features.intent!.modules.filter((x) => !x.startsWith('ext/'))) for (const d of runtimeImports(m)) if (lower(d)) edges.push(`${m} -> ${d}`);
    expect(edges.sort()).toEqual(['intent -> ledger']);
  });
});
