import { describe, expect, it } from 'vitest';
import { ResourceGraph } from './objective-risk';
import { riskScore, DEFAULT_RISK_POLICY, type RiskInputs } from './risk';
import {
  BOTTOM,
  EMPTY_REGISTRY,
  InMemoryTrustedInputRegistry,
  TAINT_LEVELS,
  TOP,
  type TaintContext,
  type TaintLabel,
  classifyRef,
  computeTaint,
  joinLabel,
  joinLabels,
  labelRank,
  taintValue,
} from './taint';

const prov = (trusted_refs: unknown, extra: Record<string, unknown> = {}) => ({
  causal_hash: '',
  taint_level: 0,
  trusted_refs,
  ...extra,
});

/** A context whose first-party source is a committed resource graph holding `nodeIds`. */
const ctxWith = (opts: { registry?: InMemoryTrustedInputRegistry; nodeIds?: string[] } = {}): TaintContext => {
  const graph = new ResourceGraph();
  for (const id of opts.nodeIds ?? []) graph.addNode({ id });
  return { registry: opts.registry ?? new InMemoryTrustedInputRegistry(), resourceGraph: opts.nodeIds ? graph : undefined };
};

const ALL: TaintLabel[] = [
  { kind: 'trusted' },
  { kind: 'first_party' },
  { kind: 'tool', id: 'a' },
  { kind: 'web' },
  { kind: 'agent', id: 'x' },
];

describe('taint label lattice', () => {
  it('values are ordered trusted(0) ⊏ first_party ⊏ tool ⊏ web ⊏ agent(1)', () => {
    expect(TAINT_LEVELS).toEqual(['trusted', 'first_party', 'tool', 'web', 'agent']);
    expect(ALL.map(taintValue)).toEqual([0, 0.25, 0.5, 0.75, 1]);
    expect(taintValue(BOTTOM)).toBe(0);
    expect(taintValue(TOP)).toBe(1);
  });

  it('join = least-upper-bound (the worse lineage wins)', () => {
    expect(joinLabel({ kind: 'trusted' }, { kind: 'web' })).toEqual({ kind: 'web' });
    expect(joinLabel({ kind: 'agent' }, { kind: 'trusted' })).toEqual({ kind: 'agent' });
    expect(joinLabel({ kind: 'first_party' }, { kind: 'tool', id: 'a' })).toEqual({ kind: 'tool', id: 'a' });
  });

  it('join is idempotent, commutative and associative (semilattice laws)', () => {
    for (const a of ALL)
      for (const b of ALL) {
        // commutative (by value)
        expect(taintValue(joinLabel(a, b))).toBe(taintValue(joinLabel(b, a)));
        // idempotent
        expect(joinLabel(a, a)).toEqual(a);
        for (const c of ALL) {
          const left = joinLabel(joinLabel(a, b), c);
          const right = joinLabel(a, joinLabel(b, c));
          expect(taintValue(left)).toBe(taintValue(right));
        }
      }
  });

  it('BOTTOM is the identity; same-rank distinct ids collapse to the generic representative', () => {
    for (const a of ALL) expect(joinLabel(a, BOTTOM)).toEqual(a);
    expect(joinLabel({ kind: 'tool', id: 'a' }, { kind: 'tool', id: 'b' })).toEqual({ kind: 'tool' });
    expect(joinLabel({ kind: 'agent', id: 'p' }, { kind: 'agent', id: 'q' })).toEqual({ kind: 'agent' });
    expect(joinLabel({ kind: 'tool', id: 'a' }, { kind: 'tool', id: 'a' })).toEqual({ kind: 'tool', id: 'a' });
  });

  it('joinLabels over an EMPTY lineage is TOP (no trusted evidence ≠ trusted)', () => {
    expect(joinLabels([])).toEqual({ kind: 'agent' });
    expect(taintValue(joinLabels([]))).toBe(1);
  });

  it('labelRank matches the declared order', () => {
    expect(ALL.map(labelRank)).toEqual([0, 1, 2, 3, 4]);
  });
});

describe('classifyRef (server-independent, never reads the agent label)', () => {
  it('registry hit returns the REGISTERED label', () => {
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('d-trusted').recordWeb('d-web').recordTool('d-tool', 'search');
    const ctx = ctxWith({ registry });
    expect(classifyRef('d-trusted', ctx)).toEqual({ kind: 'trusted' });
    expect(classifyRef('d-web', ctx)).toEqual({ kind: 'web' });
    expect(classifyRef('d-tool', ctx)).toEqual({ kind: 'tool', id: 'search' });
  });

  it('a resource-graph node is first_party; anything else is agent (worst)', () => {
    const ctx = ctxWith({ nodeIds: ['doc:policy-1'] });
    expect(classifyRef('doc:policy-1', ctx)).toEqual({ kind: 'first_party' });
    expect(classifyRef('doc:unknown', ctx)).toMatchObject({ kind: 'agent' });
  });

  it('registry wins over the graph, and non-string/empty refs are agent', () => {
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('doc:policy-1');
    const ctx = ctxWith({ registry, nodeIds: ['doc:policy-1'] });
    expect(classifyRef('doc:policy-1', ctx)).toEqual({ kind: 'trusted' });
    expect(classifyRef('', ctx)).toEqual({ kind: 'agent' });
    expect(classifyRef(42 as unknown, ctx)).toEqual({ kind: 'agent' });
  });
});

describe('computeTaint', () => {
  it('all-trusted verified lineage → taint ≈ 0, and r is lower than the constant-1 case', () => {
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('u1').recordTrusted('u2');
    const ctx = ctxWith({ registry });
    const res = computeTaint(prov(['u1', 'u2']), ctx);
    expect(res.valid).toBe(true);
    expect(res.taint).toBe(0);
    expect(res.label).toEqual({ kind: 'trusted' });

    // r drops versus the old inert constant (taint pinned to 1).
    const base: RiskInputs = { semanticDistance: 0.5, reversibility: 1, blastRadius: 0.5, taint: 0, confidence: 1, age: 0 };
    const rLow = riskScore({ ...base, taint: res.taint }, DEFAULT_RISK_POLICY.weights);
    const rPinned = riskScore({ ...base, taint: 1 }, DEFAULT_RISK_POLICY.weights);
    expect(rLow).toBeLessThan(rPinned);
    expect(rPinned - rLow).toBeCloseTo(DEFAULT_RISK_POLICY.weights.delta, 10); // exactly the taint term
  });

  it('a single untrusted / web ref makes taint high', () => {
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('u1').recordWeb('w1');
    const ctx = ctxWith({ registry });
    // mostly trusted, ONE web ref → join is web → 0.75
    expect(computeTaint(prov(['u1', 'w1']), ctx).taint).toBe(0.75);
    // mostly trusted, ONE unverifiable ref → join is agent → 1
    expect(computeTaint(prov(['u1', 'unknown-ref']), ctx).taint).toBe(1);
  });

  it('an agent CLAIMING trusted refs NOT in the registry cannot forge low taint', () => {
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('real-trusted');
    const ctx = ctxWith({ registry, nodeIds: ['doc:policy-1'] });
    // The wire carries a self-asserted "trusted" taint_level 0 and refs the agent calls trusted — all fabricated.
    const forged = prov(['i-swear-this-is-trusted', 'and-this-one-too'], { taint_level: 0 });
    const res = computeTaint(forged, ctx);
    expect(res.taint).toBe(1); // stays worst-case
    expect(res.refs.every((r) => r.label.kind === 'agent')).toBe(true);
    // Only refs the SERVER vouches for lower it:
    expect(computeTaint(prov(['real-trusted']), ctx).taint).toBe(0);
    expect(computeTaint(prov(['doc:policy-1']), ctx).taint).toBe(0.25);
  });

  it('malformed / absent provenance fails closed to 1 (valid:false)', () => {
    const ctx = ctxWith();
    for (const bad of [undefined, null, 42, 'x', [], prov('not-an-array'), prov([1, 2]), prov([''])]) {
      const res = computeTaint(bad, ctx);
      expect(res.taint).toBe(1);
      expect(res.valid).toBe(false);
    }
    // an empty-but-well-formed lineage is VALID but still worst-case (no trusted evidence).
    const empty = computeTaint(prov([]), ctx);
    expect(empty.valid).toBe(true);
    expect(empty.taint).toBe(1);
  });

  it('a missing registry in the context fails closed', () => {
    expect(computeTaint(prov(['u1']), {} as unknown as TaintContext).taint).toBe(1);
    expect(computeTaint(prov(['u1']), { registry: EMPTY_REGISTRY }).taint).toBe(1); // vouches for nothing
  });

  it('is MONOTONE: adding a ref can only raise taint, never lower it', () => {
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('t1').recordFirstParty('f1').recordWeb('w1');
    const ctx = ctxWith({ registry });
    const chain = [['t1'], ['t1', 'f1'], ['t1', 'f1', 'w1'], ['t1', 'f1', 'w1', 'agent-ref']];
    const taints = chain.map((refs) => computeTaint(prov(refs), ctx).taint);
    expect(taints).toEqual([0, 0.25, 0.75, 1]);
    for (let i = 1; i < taints.length; i++) expect(taints[i]!).toBeGreaterThanOrEqual(taints[i - 1]!);
  });

  it('is DETERMINISTIC and order-independent', () => {
    const registry = new InMemoryTrustedInputRegistry().recordTrusted('t1').recordWeb('w1').recordFirstParty('f1');
    const ctx = ctxWith({ registry });
    const a = computeTaint(prov(['t1', 'w1', 'f1']), ctx);
    const b = computeTaint(prov(['t1', 'w1', 'f1']), ctx);
    const c = computeTaint(prov(['f1', 't1', 'w1']), ctx); // permuted
    expect(a).toEqual(b);
    expect(a.taint).toBe(c.taint);
    expect(a.label).toEqual(c.label);
  });

  it('the registry copies labels (no aliasing of internal state)', () => {
    const registry = new InMemoryTrustedInputRegistry().recordTool('d', 'search');
    const first = registry.lookup('d')!;
    (first as { id?: string }).id = 'tampered';
    expect(registry.lookup('d')).toEqual({ kind: 'tool', id: 'search' });
  });
});
