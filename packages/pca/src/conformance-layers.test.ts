// The TypeScript conformance runner for the layered corpus (conformance/LAYERS.md): re-runs the policy layer
// (policy-vectors.json) and the stateful layer (stateful-vectors.json) against the reference read from SOURCE, and checks
// the layer manifest (layers.json) tags every committed vector. The generators computed the expectations from dist with the
// same evaluation (scripts/policy-decision.mjs, scripts/stateful-sequence.mjs), so a change to decide() / requirePCA that
// moves any decision fails here.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import * as pca from './index';

const CONF = join(__dirname, '..', 'conformance');
const SCRIPTS = join(__dirname, '..', 'scripts');
const read = (f: string) => JSON.parse(readFileSync(join(CONF, f), 'utf8'));
const policy = read('policy-vectors.json');
const stateful = read('stateful-vectors.json');
const layers = read('layers.json');
const core = read('vectors.json');

type PolicyVector = { name: string; layer: string; features: string[]; grant: unknown; chain: unknown[]; context: unknown; expect: { decision: { allow: boolean; reasons: string[] }; caveats: { allow: boolean; failed: string[] } } };
type Step = { op: 'present' | 'revoke'; expect?: { allow: boolean; failed: string[] } };
type Sequence = { name: string; layer: string; steps: Step[] };

/* eslint-disable @typescript-eslint/no-explicit-any */
let P: any, S: any, L: any;
beforeAll(async () => {
  P = await import(pathToFileURL(join(SCRIPTS, 'policy-decision.mjs')).href);
  S = await import(pathToFileURL(join(SCRIPTS, 'stateful-sequence.mjs')).href);
  L = await import(pathToFileURL(join(SCRIPTS, 'conformance-layers.mjs')).href);
});

describe('policy layer: policy_decision', () => {
  const cases: PolicyVector[] = policy.policy_decision;
  it('covers every caveat type at every placement, every reason code, allow and deny', () => {
    expect(cases.length).toBeGreaterThanOrEqual(400);
    const names = new Set(cases.map((c) => c.name));
    for (const type of ['max_spend', 'expires', 'not_before', 'rate', 'max_blast_radius', 'reversibility_max', 'delegation_depth', 'budget_alloc', 'predicates', 'tool_schema', 'unknown']) {
      for (const pl of ['root-only', 'root', 'delegated', 'envelope']) {
        expect([...names].some((n) => n.startsWith(`pd-${pl}-${type}-`)), `${pl} ${type}`).toBe(true);
      }
    }
    const codes = new Set(cases.flatMap((c) => c.expect.decision.reasons));
    expect([...codes].sort()).toEqual([...P.REASON_CODES].sort());
    expect(cases.some((c) => c.expect.decision.allow)).toBe(true);
    expect(cases.some((c) => !c.expect.decision.allow)).toBe(true);
    expect(cases.every((c) => c.layer === 'policy')).toBe(true);
    expect(policy.reason_codes).toEqual(P.REASON_CODES);
  });
  it.each(cases.map((c) => [c.name, c] as const))('%s', (_n, c) => {
    expect(P.evaluatePolicyVector(pca, c)).toEqual(c.expect);
  });
});

describe('stateful layer: sequences against one store', () => {
  const seqs: Sequence[] = stateful.stateful;
  const expected = (s: Sequence) => s.steps.map((x) => (x.op === 'present' ? x.expect : null));
  it('covers replay, counter ordering, revocation mid-sequence and budget depletion', () => {
    for (const fam of ['st-replay-', 'st-counter-', 'st-revoke-', 'st-budget-']) expect(seqs.some((s) => s.name.startsWith(fam)), fam).toBe(true);
    const failed = new Set(seqs.flatMap((s) => s.steps.flatMap((x) => x.expect?.failed ?? [])));
    for (const c of ['replay', 'revocation', 'threshold', 'validity']) expect(failed.has(c), c).toBe(true);
  });
  it.each(seqs.map((s) => [s.name, s] as const))('%s (atomic store)', async (_n, s) => {
    expect(await S.runSequence(pca, s, { store: pca.atomicMemoryPcaStore() })).toEqual(expected(s));
  });
  it.each(seqs.map((s) => [s.name, s] as const))('%s (locked get / put store)', async (_n, s) => {
    expect(await S.runSequence(pca, s, { store: pca.memoryPcaStore() })).toEqual(expected(s));
  });
});

describe('layer manifest', () => {
  it('tags every vectors.json vector with exactly one layer, by the shared rule', () => {
    const tagged = layers.vectors['vectors.json'] as Record<string, string[]>;
    const seen = new Map<string, string>();
    for (const [layer, names] of Object.entries(tagged)) for (const n of names) {
      expect(seen.has(n), n).toBe(false);
      seen.set(n, layer);
    }
    expect(seen.size).toBe(core.vectors.length);
    for (const v of core.vectors) expect(seen.get(v.name), v.name).toBe(L.layerOfVerdict(v.expect));
  });
  it('maps every primitives table and counts the new layers', () => {
    for (const t of Object.keys(core.primitives)) expect(L.TABLE_LAYER[t], t).toBeDefined();
    expect(layers.layers.map((l: { id: string }) => l.id)).toEqual(['wire', 'proof', 'capability', 'policy', 'stateful', 'extension', 'integration']);
    expect(layers.files['policy-vectors.json']).toEqual({ layer: 'policy', n: policy.policy_decision.length });
    expect(layers.counts.stateful).toBe(stateful.counts.present_steps);
  });
  it('tags gate items: first failing check decides, accepted is proof', () => {
    expect(L.layerOfVerdict({ allow: true, checks: { wire: true } })).toBe('proof');
    expect(L.layerOfVerdict({ allow: false, checks: { wire: false } })).toBe('wire');
    expect(L.layerOfVerdict({ allow: false, checks: { wire: true, version: true, audience: true, validity: true, chain: false, leaf_signature: false } })).toBe('capability');
    expect(L.layerOfVerdict({ allow: false, checks: { wire: true, chain: true, leaf_signature: false } })).toBe('proof');
    expect(L.layerOfVerdict({ allow: false, checks: { wire: true, intent: false } })).toBe('policy');
    expect(L.layerOfGateItem('canon', undefined)).toBe('wire');
    expect(L.layerOfGateItem('chain', undefined)).toBe('capability');
    expect(L.layerOfGateItem('policy', undefined)).toBe('policy');
  });
});
