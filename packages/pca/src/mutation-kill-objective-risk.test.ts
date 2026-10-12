/**
 * Mutation-kill tests for objective-risk.ts: exact error/reason strings, every boundary, ordering/sort stability of the
 * committed digests, an independent reference implementation of the native hash embedder, and the full evidence digest.
 */
import { describe, expect, it } from 'vitest';
import { canonicalize, hashCanonicalLenient as hashCanonical, sha256, utf8 } from './hash';
import { DEFAULT_RISK_POLICY as P, riskScore } from './risk';
import {
  DEFAULT_EPSILON,
  DEFAULT_MAX_PARAM_LEAVES,
  DEFAULT_NATIVE_CONFIG,
  EmbeddingError,
  InMemoryInverseRegistry,
  METRIC,
  NATIVE_SCHEME,
  ResourceGraph,
  blastRadius,
  byoEmbedder,
  byoModelId,
  calibrate,
  calibrationDigest,
  canonicalAction,
  canonicalActionDigest,
  canonicalActionJson,
  commitGoal,
  committedDistance,
  committedDistanceChecked,
  conformalThreshold,
  conformanceCheck,
  harmReport,
  nativeHashEmbedder,
  objectiveRisk,
  objectiveRiskOracle,
  reversibility,
  validateVector,
  vectorDistance,
  verifyGoalCommitment,
  type ByoDescriptor,
  type Embedder,
  type GoalCommitment,
  type NativeEmbedderConfig,
  type ObjAction,
  type ObjectiveRiskContext,
  type ResourceNode,
} from './objective-risk';

const perms = <T>(a: T[]): T[][] => (a.length <= 1 ? [a.slice()] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map((p) => [x, ...p])));
const cmpStr = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

// ---------------------------------------------------------------------------------------------
describe('canonicalAction', () => {
  it('rejects non-string verb/resource with the exact message, including a null/undefined action', () => {
    const m = 'canonicalAction: verb/resource must be strings';
    expect(() => canonicalAction({ verb: 1, resource: 'r' } as never)).toThrow(new TypeError(m));
    expect(() => canonicalAction({ verb: 'v', resource: 2 } as never)).toThrow(new TypeError(m));
    expect(() => canonicalAction(null as never)).toThrow(new TypeError(m));
    expect(() => canonicalAction(undefined as never)).toThrow(new TypeError(m));
    expect(() => canonicalAction({ resource: 'r' } as never)).toThrow(new TypeError(m));
  });
  it('rejects empty verb/resource (after trim) with the exact message', () => {
    const m = 'canonicalAction: empty verb/resource';
    expect(() => canonicalAction({ verb: '  ', resource: 'r' })).toThrow(new TypeError(m));
    expect(() => canonicalAction({ verb: 'v', resource: '' })).toThrow(new TypeError(m));
    expect(() => canonicalAction({ verb: 'v', resource: '   ' })).toThrow(new TypeError(m));
  });
  it('trims the resource but keeps its case; lowercases + trims the verb', () => {
    const c = canonicalAction({ verb: '  DB.Delete\t', resource: '  Orders/X \n' });
    expect(c).toEqual({ verb: 'db.delete', resource: 'Orders/X', params: {} });
  });
  it('NFC-normalizes verb, resource, string values, nested keys and array elements', () => {
    const nfd = 'é';
    const nfc = 'é';
    const c = canonicalAction({ verb: nfd, resource: nfd, params: { [nfd]: nfd, n: { [nfd]: [nfd, { [nfd]: nfd }] } } });
    expect(c.verb).toBe(nfc);
    expect(c.resource).toBe(nfc);
    expect(c.params).toEqual({ [nfc]: nfc, n: { [nfc]: [nfc, { [nfc]: nfc }] } });
    expect(Object.keys(c.params)[0]).toBe(nfc);
  });
  it('keeps arrays as arrays, null as null, and primitives untouched', () => {
    const c = canonicalAction({ verb: 'v', resource: 'r', params: { a: [1, 'x', null, true], z: null, n: 0.5 } });
    expect(Array.isArray(c.params.a)).toBe(true);
    expect(c.params).toEqual({ a: [1, 'x', null, true], z: null, n: 0.5 });
    expect(c.params.z).toBeNull();
  });
  it('rejects two keys that collide after NFC normalization', () => {
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: { 'é': 1, 'é': 2 } })).toThrow(
      new TypeError('canonicalAction: duplicate key after NFC normalization'),
    );
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: { n: { 'é': 1, 'é': 2 } } })).toThrow(/duplicate key/);
  });
  it('requires params to be a plain object (not array / string / number)', () => {
    const m = 'canonicalAction: params must be an object';
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: [] as never })).toThrow(new TypeError(m));
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: [1] as never })).toThrow(new TypeError(m));
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: 'x' as never })).toThrow(new TypeError(m));
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: 5 as never })).toThrow(new TypeError(m));
    expect(() => canonicalAction({ verb: 'v', resource: 'r', params: true as never })).toThrow(new TypeError(m));
    // null params falls back to {}
    expect(canonicalAction({ verb: 'v', resource: 'r', params: null as never }).params).toEqual({});
    expect(canonicalAction({ verb: 'v', resource: 'r' }).params).toEqual({});
  });
  it('json / digest helpers are canonicalize / hashCanonical of the canonical form', () => {
    const c = canonicalAction({ verb: 'v', resource: 'r', params: { b: 1, a: 2 } });
    expect(canonicalActionJson(c)).toBe(canonicalize(c));
    expect(canonicalActionJson(c)).toBe('{"params":{"a":2,"b":1},"resource":"r","verb":"v"}');
    expect(canonicalActionDigest(c)).toBe(hashCanonical(c));
  });
});

// ---------------------------------------------------------------------------------------------
describe('InMemoryInverseRegistry', () => {
  const ev = { verifierId: 'v1', evidenceDigest: 'd1' };
  it('has no trusted verifiers by default', () => {
    expect(new InMemoryInverseRegistry().trustedVerifiers()).toEqual([]);
  });
  it('de-duplicates and sorts trusted verifiers', () => {
    expect(new InMemoryInverseRegistry(['c', 'a', 'b', 'a', 'c']).trustedVerifiers()).toEqual(['a', 'b', 'c']);
    expect(new InMemoryInverseRegistry(['b', 'a']).trustedVerifiers()).toEqual(['a', 'b']);
    expect(new InMemoryInverseRegistry(['zz', 'Za', 'a', 'B']).trustedVerifiers()).toEqual(['B', 'Za', 'a', 'zz']);
  });
  it('digest is independent of insertion order (all permutations) and of trusted-verifier order', () => {
    const entries: [string, 'exact' | 'partial'][] = [['d', 'exact'], ['b', 'partial'], ['c', 'exact'], ['a', 'partial']];
    const mk = (order: typeof entries) => {
      const r = new InMemoryInverseRegistry(['t2', 't1']);
      for (const [v, f] of order) r.register(v, { inverseKind: `inv.${v}`, fidelity: f, verification: ev });
      return r.digest();
    };
    const ref = mk(entries);
    for (const p of perms(entries)) expect(mk(p)).toBe(ref);
    const r2 = new InMemoryInverseRegistry(['t1', 't2']);
    for (const [v, f] of entries) r2.register(v, { inverseKind: `inv.${v}`, fidelity: f, verification: ev });
    expect(r2.digest()).toBe(ref);
  });
  it('digest commits verb, inverseKind, fidelity, verification and the trusted set', () => {
    const base = () => new InMemoryInverseRegistry(['t']).register('v', { inverseKind: 'k', fidelity: 'exact', verification: ev });
    const d0 = base().digest();
    expect(base().digest()).toBe(d0);
    expect(new InMemoryInverseRegistry(['t']).register('w', { inverseKind: 'k', fidelity: 'exact', verification: ev }).digest()).not.toBe(d0);
    expect(new InMemoryInverseRegistry(['t']).register('v', { inverseKind: 'k2', fidelity: 'exact', verification: ev }).digest()).not.toBe(d0);
    expect(new InMemoryInverseRegistry(['t']).register('v', { inverseKind: 'k', fidelity: 'partial', verification: ev }).digest()).not.toBe(d0);
    expect(new InMemoryInverseRegistry(['t']).register('v', { inverseKind: 'k', fidelity: 'exact' }).digest()).not.toBe(d0);
    expect(new InMemoryInverseRegistry(['t']).register('v', { inverseKind: 'k', fidelity: 'exact', verification: { ...ev, evidenceDigest: 'd2' } }).digest()).not.toBe(d0);
    expect(new InMemoryInverseRegistry(['u']).register('v', { inverseKind: 'k', fidelity: 'exact', verification: ev }).digest()).not.toBe(d0);
    // the exact committed shape
    expect(d0).toBe(
      hashCanonical({ v: 1, trusted: ['t'], entries: [{ verb: 'v', inverseKind: 'k', fidelity: 'exact', verification: ev }] }),
    );
    expect(new InMemoryInverseRegistry().register('v', { inverseKind: 'k', fidelity: 'partial' }).digest()).toBe(
      hashCanonical({ v: 1, trusted: [], entries: [{ verb: 'v', inverseKind: 'k', fidelity: 'partial', verification: null }] }),
    );
  });
  it('register stores a defensive copy (verification and entry); lookup returns a copy', () => {
    const verification = { verifierId: 'v1', evidenceDigest: 'd1' };
    const entry = { inverseKind: 'k', fidelity: 'exact' as const, verification };
    const r = new InMemoryInverseRegistry(['v1']).register('x', entry);
    verification.verifierId = 'evil';
    verification.evidenceDigest = 'evil';
    entry.inverseKind = 'evil';
    expect(r.lookup('x')).toEqual({ inverseKind: 'k', fidelity: 'exact', verification: { verifierId: 'v1', evidenceDigest: 'd1' } });
    const got = r.lookup('x')!;
    got.inverseKind = 'tamper';
    expect(r.lookup('x')!.inverseKind).toBe('k');
    expect(r.lookup('nope')).toBeUndefined();
  });
  it('an entry without verification has no verification key', () => {
    const r = new InMemoryInverseRegistry().register('x', { inverseKind: 'k', fidelity: 'partial' });
    expect(r.lookup('x')).toEqual({ inverseKind: 'k', fidelity: 'partial' });
    expect('verification' in r.lookup('x')!).toBe(false);
  });
});

describe('reversibility', () => {
  const ev = { verifierId: 'ok', evidenceDigest: 'd' };
  const reg = () =>
    new InMemoryInverseRegistry(['ok'])
      .register('exact', { inverseKind: 'undo', fidelity: 'exact', verification: ev })
      .register('part', { inverseKind: 'comp', fidelity: 'partial', verification: ev })
      .register('noev', { inverseKind: 'undo', fidelity: 'exact' })
      .register('rogue', { inverseKind: 'undo', fidelity: 'exact', verification: { verifierId: 'rogue', evidenceDigest: 'd' } });
  const auth = new Set(['undo', 'comp']);
  it('classifies exactly', () => {
    expect(reversibility({ verb: 'exact' }, reg(), auth)).toEqual({ class: 'reversible', value: 1, inverseKind: 'undo' });
    expect(reversibility({ verb: 'part' }, reg(), auth)).toEqual({ class: 'compensable', value: 0.5, inverseKind: 'comp' });
  });
  it('everything else is irreversible with no inverseKind', () => {
    const irr = { class: 'irreversible', value: 0 };
    expect(reversibility({ verb: 'noev' }, reg(), auth)).toEqual(irr); // no verification evidence (even though authorized)
    expect(reversibility({ verb: 'rogue' }, reg(), auth)).toEqual(irr); // untrusted verifier
    expect(reversibility({ verb: 'unknown' }, reg(), auth)).toEqual(irr);
    expect(reversibility({ verb: 'exact' }, reg(), new Set(['comp']))).toEqual(irr); // inverse not authorized
    expect(reversibility({ verb: 'part' }, reg(), new Set())).toEqual(irr);
  });
});

// ---------------------------------------------------------------------------------------------
describe('ResourceGraph', () => {
  const chain = () =>
    new ResourceGraph()
      .addNode({ id: 'd' })
      .addNode({ id: 'a' })
      .addNode({ id: 'c' })
      .addNode({ id: 'b' })
      .addNode({ id: 'e' })
      .addNode({ id: 'z' })
      .addEdge({ from: 'a', to: 'b', kind: 'x' })
      .addEdge({ from: 'b', to: 'c', kind: 'x' })
      .addEdge({ from: 'c', to: 'd', kind: 'x' })
      .addEdge({ from: 'a', to: 'e', kind: 'y' })
      .addEdge({ from: 'e', to: 'z', kind: 'x' });

  it('addEdge requires both endpoints, each independently', () => {
    const g = new ResourceGraph().addNode({ id: 'a' }).addNode({ id: 'b' });
    expect(() => g.addEdge({ from: 'a', to: 'nope', kind: 'k' })).toThrow(new Error('edge endpoints must exist'));
    expect(() => g.addEdge({ from: 'nope', to: 'b', kind: 'k' })).toThrow(new Error('edge endpoints must exist'));
    expect(() => g.addEdge({ from: 'nope', to: 'nope2', kind: 'k' })).toThrow(new Error('edge endpoints must exist'));
    expect(() => g.addEdge({ from: 'a', to: 'b', kind: 'k' })).not.toThrow();
  });
  it('size and node()', () => {
    const g = chain();
    expect(g.size).toBe(6);
    expect(g.node('a')).toEqual({ id: 'a' });
    expect(g.node('q')).toBeUndefined();
  });
  it('re-adding a node keeps its existing out-edges', () => {
    const g = new ResourceGraph().addNode({ id: 'a' }).addNode({ id: 'b' }).addEdge({ from: 'a', to: 'b', kind: 'k' });
    g.addNode({ id: 'a', harm: { rows: 1 } });
    expect(g.reachable('a')).toEqual(['a', 'b']);
    expect(g.node('a')).toEqual({ id: 'a', harm: { rows: 1 } });
  });
  it('reachable: unknown start is empty; result is sorted and includes start', () => {
    const g = chain();
    expect(g.reachable('nope')).toEqual([]);
    expect(g.reachable('a')).toEqual(['a', 'b', 'c', 'd', 'e', 'z']);
    expect(g.reachable('c')).toEqual(['c', 'd']);
    expect(g.reachable('d')).toEqual(['d']);
    expect(g.reachable('z', {})).toEqual(['z']);
  });
  it('reachable: maxDepth is a hop count (0 = only start)', () => {
    const g = chain();
    expect(g.reachable('a', { maxDepth: 0 })).toEqual(['a']);
    expect(g.reachable('a', { maxDepth: 1 })).toEqual(['a', 'b', 'e']);
    expect(g.reachable('a', { maxDepth: 2 })).toEqual(['a', 'b', 'c', 'e', 'z']);
    expect(g.reachable('a', { maxDepth: 3 })).toEqual(['a', 'b', 'c', 'd', 'e', 'z']);
  });
  it('reachable: edgeKinds filter (empty list = nothing is followed)', () => {
    const g = chain();
    expect(g.reachable('a', { edgeKinds: ['x'] })).toEqual(['a', 'b', 'c', 'd']);
    expect(g.reachable('a', { edgeKinds: ['y'] })).toEqual(['a', 'e']);
    expect(g.reachable('a', { edgeKinds: ['y', 'x'] })).toEqual(['a', 'b', 'c', 'd', 'e', 'z']);
    expect(g.reachable('a', { edgeKinds: [] })).toEqual(['a']);
    expect(g.reachable('a', { edgeKinds: ['x'], maxDepth: 2 })).toEqual(['a', 'b', 'c']);
  });
  it('reachable handles cycles and a revisited node exactly once', () => {
    const g = new ResourceGraph().addNode({ id: 'b' }).addNode({ id: 'a' }).addEdge({ from: 'a', to: 'b', kind: 'k' }).addEdge({ from: 'b', to: 'a', kind: 'k' }).addEdge({ from: 'a', to: 'b', kind: 'k' });
    expect(g.reachable('a')).toEqual(['a', 'b']);
    expect(g.reachable('b')).toEqual(['a', 'b']);
  });
  it('digest is invariant under any insertion order of nodes and edges', () => {
    const nodes: ResourceNode[] = [{ id: 'n3' }, { id: 'n1', harm: { rows: 5 } }, { id: 'n2' }, { id: 'n4', harm: { usd: 1 } }];
    const edges = [
      { from: 'n1', to: 'n2', kind: 'a' },
      { from: 'n1', to: 'n2', kind: 'b' },
      { from: 'n2', to: 'n3', kind: 'a' },
      { from: 'n1', to: 'n3', kind: 'a' },
    ];
    const mk = (ns: typeof nodes, es: typeof edges) => {
      const g = new ResourceGraph();
      for (const n of ns) g.addNode(n);
      for (const e of es) g.addEdge(e);
      return g.digest();
    };
    const ref = mk(nodes, edges);
    for (const pn of perms(nodes)) expect(mk(pn, edges)).toBe(ref);
    for (const pe of perms(edges)) expect(mk(nodes, pe)).toBe(ref);
    // edge sort key: compares from, then to, then kind (separator-delimited)
    expect(mk(nodes, [...edges].reverse())).toBe(ref);
  });
  it('digest commits node ids, harm, and every edge field', () => {
    const mk = (f: (g: ResourceGraph) => void) => {
      const g = new ResourceGraph().addNode({ id: 'a', harm: { rows: 1 } }).addNode({ id: 'b' }).addNode({ id: 'c' }).addEdge({ from: 'a', to: 'b', kind: 'k' });
      f(g);
      return g.digest();
    };
    const d0 = mk(() => {});
    expect(mk(() => {})).toBe(d0);
    expect(mk((g) => g.addNode({ id: 'extra' }))).not.toBe(d0);
    expect(mk((g) => g.addNode({ id: 'a', harm: { rows: 2 } }))).not.toBe(d0);
    expect(mk((g) => g.addNode({ id: 'a', harm: { usd: 1 } }))).not.toBe(d0);
    expect(mk((g) => g.addEdge({ from: 'a', to: 'c', kind: 'k' }))).not.toBe(d0);
    expect(mk((g) => g.addEdge({ from: 'b', to: 'a', kind: 'k' }))).not.toBe(d0);
    expect(mk((g) => g.addEdge({ from: 'a', to: 'b', kind: 'k2' }))).not.toBe(d0);
    // the committed shape (harm absent == {}; edges and nodes sorted)
    const g = new ResourceGraph().addNode({ id: 'b' }).addNode({ id: 'a', harm: { rows: 1 } }).addEdge({ from: 'b', to: 'a', kind: 'k' });
    expect(g.digest()).toBe(hashCanonical({ v: 1, n: [{ id: 'a', harm: { rows: 1 } }, { id: 'b', harm: {} }], e: [{ from: 'b', to: 'a', kind: 'k' }] }));
    expect(new ResourceGraph().addNode({ id: 'a' }).digest()).toBe(new ResourceGraph().addNode({ id: 'a', harm: {} }).digest());
  });
});

describe('blastRadius', () => {
  it('unknown resource / empty graph fail closed with the exact record', () => {
    const g = new ResourceGraph().addNode({ id: 'a' });
    expect(blastRadius({ resource: 'nope' }, g)).toEqual({ count: 0, reachable: [], normalized: 1, harm: {} });
    expect(blastRadius({ resource: 'x' }, new ResourceGraph())).toEqual({ count: 0, reachable: [], normalized: 1, harm: {} });
  });
  it('count, reachable, normalized = count/size and summed harm per denomination', () => {
    const g = new ResourceGraph()
      .addNode({ id: 'a', harm: { rows: 10, usd: 1 } })
      .addNode({ id: 'b', harm: { rows: 5 } })
      .addNode({ id: 'c' })
      .addNode({ id: 'd', harm: { rows: 1000 } })
      .addEdge({ from: 'a', to: 'b', kind: 'k' })
      .addEdge({ from: 'b', to: 'c', kind: 'k' });
    const b = blastRadius({ resource: 'a' }, g);
    expect(b).toEqual({ count: 3, reachable: ['a', 'b', 'c'], normalized: 3 / 4, harm: { rows: 15, usd: 1 } });
    expect(blastRadius({ resource: 'a' }, g, { maxDepth: 1 })).toEqual({ count: 2, reachable: ['a', 'b'], normalized: 2 / 4, harm: { rows: 15, usd: 1 } });
    expect(blastRadius({ resource: 'd' }, g)).toEqual({ count: 1, reachable: ['d'], normalized: 1 / 4, harm: { rows: 1000 } });
    expect(blastRadius({ resource: 'c' }, g).harm).toEqual({});
  });
  it('ignores non-finite, zero and negative harm amounts', () => {
    const g = new ResourceGraph()
      .addNode({ id: 'a', harm: { zero: 0, neg: -5, nan: NaN, inf: Infinity, ninf: -Infinity, ok: 2 } })
      .addNode({ id: 'b', harm: { ok: 3, neg: -1 } })
      .addEdge({ from: 'a', to: 'b', kind: 'k' });
    expect(blastRadius({ resource: 'a' }, g).harm).toEqual({ ok: 5 });
    expect(Object.keys(blastRadius({ resource: 'a' }, g).harm)).toEqual(['ok']);
  });
});

// ---------------------------------------------------------------------------------------------
describe('validateVector', () => {
  const lim = (dims: number) => Math.floor(Math.sqrt(Number.MAX_SAFE_INTEGER / (2 * Math.max(1, dims))));
  it('length / type errors carry the exact messages', () => {
    expect(() => validateVector([1, 2], 3)).toThrow(new EmbeddingError('vector must have exactly 3 components'));
    expect(() => validateVector([1, 2, 3, 4], 3)).toThrow('vector must have exactly 3 components');
    expect(() => validateVector('abc', 3)).toThrow('vector must have exactly 3 components');
    expect(() => validateVector({ length: 3, 0: 1, 1: 2, 2: 3 }, 3)).toThrow('vector must have exactly 3 components');
    expect(() => validateVector(undefined, 0)).toThrow('vector must have exactly 0 components');
    expect(validateVector([], 0)).toEqual([]);
  });
  it('throws an EmbeddingError', () => {
    expect(() => validateVector([1], 2)).toThrow(EmbeddingError);
  });
  it('components must be safe integers', () => {
    const m = 'vector components must be safe integers';
    for (const bad of [1.5, NaN, Infinity, 2 ** 53, '1', null, undefined]) expect(() => validateVector([0, bad], 2)).toThrow(new EmbeddingError(m));
  });
  it('component magnitude bound is exact (inclusive) for several dims, both signs', () => {
    for (const dims of [1, 2, 4, 8, 256]) {
      const L = lim(dims);
      const ok = Array.from({ length: dims }, (_, i) => (i % 2 ? -L : L));
      expect(validateVector(ok, dims)).toEqual(ok);
      const over = Array.from({ length: dims }, () => 0);
      over[dims - 1] = L + 1;
      expect(() => validateVector(over, dims)).toThrow(new EmbeddingError('vector component out of range'));
      over[dims - 1] = -(L + 1);
      expect(() => validateVector(over, dims)).toThrow('vector component out of range');
    }
  });
  it('normalizes -0 to +0 and returns a fresh array', () => {
    const input = [-0, 0, 5, -0];
    const out = validateVector(input, 4);
    expect(out).not.toBe(input);
    expect(Object.is(out[0], 0)).toBe(true);
    expect(Object.is(out[1], 0)).toBe(true);
    expect(Object.is(out[3], 0)).toBe(true);
    expect(out[2]).toBe(5);
  });
});

// ---------------------------------------------------------------------------------------------
describe('nativeHashEmbedder: config validation', () => {
  const cfg = (o: Partial<NativeEmbedderConfig> = {}, fw: Partial<NativeEmbedderConfig['fieldWeights']> = {}): NativeEmbedderConfig => ({
    ...DEFAULT_NATIVE_CONFIG,
    ...o,
    fieldWeights: { ...DEFAULT_NATIVE_CONFIG.fieldWeights, ...fw },
  });
  const dimsMsg = 'native config: dims must be an integer in [8, 65536]';
  const ngMsg = 'native config: need 1 <= ngramMin <= ngramMax <= 8';
  it('dims bounds are inclusive [8, 65536] and must be integers', () => {
    expect(() => nativeHashEmbedder(cfg({ dims: 7 }))).toThrow(new RangeError(dimsMsg));
    expect(() => nativeHashEmbedder(cfg({ dims: 65537 }))).toThrow(new RangeError(dimsMsg));
    expect(() => nativeHashEmbedder(cfg({ dims: 8.5 }))).toThrow(dimsMsg);
    expect(() => nativeHashEmbedder(cfg({ dims: NaN }))).toThrow(dimsMsg);
    expect(nativeHashEmbedder(cfg({ dims: 8 })).dims).toBe(8);
    expect(nativeHashEmbedder(cfg({ dims: 65536 })).dims).toBe(65536);
  });
  it('ngram range: 1 <= min <= max <= 8', () => {
    expect(() => nativeHashEmbedder(cfg({ ngramMin: 0 }))).toThrow(new RangeError(ngMsg));
    expect(() => nativeHashEmbedder(cfg({ ngramMin: 9, ngramMax: 9 }))).toThrow(ngMsg);
    expect(() => nativeHashEmbedder(cfg({ ngramMin: 3, ngramMax: 2 }))).toThrow(ngMsg);
    expect(() => nativeHashEmbedder(cfg({ ngramMin: 2, ngramMax: 9 }))).toThrow(ngMsg);
    expect(() => nativeHashEmbedder(cfg({ ngramMin: 1.5, ngramMax: 3 }))).toThrow(ngMsg);
    expect(() => nativeHashEmbedder(cfg({ ngramMin: 1, ngramMax: 8 }))).not.toThrow();
    expect(() => nativeHashEmbedder(cfg({ ngramMin: 8, ngramMax: 8 }))).not.toThrow();
    expect(() => nativeHashEmbedder(cfg({ ngramMin: 3, ngramMax: 3 }))).not.toThrow();
  });
  it('seed must be a non-empty string', () => {
    expect(() => nativeHashEmbedder(cfg({ seed: '' }))).toThrow(new RangeError('native config: seed required'));
    expect(() => nativeHashEmbedder(cfg({ seed: 5 as never }))).toThrow('native config: seed required');
    expect(() => nativeHashEmbedder(cfg({ seed: undefined as never }))).toThrow('native config: seed required');
    expect(() => nativeHashEmbedder(cfg({ seed: 'x' }))).not.toThrow();
  });
  it('each field weight must be an integer in [0, 1000] with its own message', () => {
    for (const k of ['verb', 'resource', 'param'] as const) {
      const m = `native config: fieldWeights.${k} must be an integer in [0, 1000]`;
      expect(() => nativeHashEmbedder(cfg({}, { [k]: -1 }))).toThrow(new RangeError(m));
      expect(() => nativeHashEmbedder(cfg({}, { [k]: 1001 }))).toThrow(m);
      expect(() => nativeHashEmbedder(cfg({}, { [k]: 1.5 }))).toThrow(m);
      expect(() => nativeHashEmbedder(cfg({}, { [k]: 0 }))).not.toThrow();
      expect(() => nativeHashEmbedder(cfg({}, { [k]: 1000 }))).not.toThrow();
    }
  });
  it('maxParamLeaves must be an integer in [1, 1000000] when present', () => {
    const m = 'native config: maxParamLeaves must be an integer in [1, 1000000]';
    expect(() => nativeHashEmbedder(cfg({ maxParamLeaves: 0 }))).toThrow(new RangeError(m));
    expect(() => nativeHashEmbedder(cfg({ maxParamLeaves: 1_000_001 }))).toThrow(m);
    expect(() => nativeHashEmbedder(cfg({ maxParamLeaves: 2.5 }))).toThrow(m);
    expect(() => nativeHashEmbedder(cfg({ maxParamLeaves: 1 }))).not.toThrow();
    expect(() => nativeHashEmbedder(cfg({ maxParamLeaves: 1_000_000 }))).not.toThrow();
  });
  it("paramMode must be 'leaves' or 'digest' when present", () => {
    const m = "native config: paramMode must be 'leaves' or 'digest'";
    expect(() => nativeHashEmbedder(cfg({ paramMode: 'other' as never }))).toThrow(new RangeError(m));
    expect(() => nativeHashEmbedder(cfg({ paramMode: '' as never }))).toThrow(m);
    expect(() => nativeHashEmbedder(cfg({ paramMode: 'leaves' }))).not.toThrow();
    expect(() => nativeHashEmbedder(cfg({ paramMode: 'digest' }))).not.toThrow();
  });
  it('modelId / config commit the scheme + a copy of the config', () => {
    const c = cfg();
    const e = nativeHashEmbedder(c);
    expect(e.config).toEqual({ scheme: NATIVE_SCHEME, ...c });
    expect(e.modelId).toBe(`native:${hashCanonical({ scheme: NATIVE_SCHEME, ...c })}`);
    expect(e.dims).toBe(256);
    c.fieldWeights.verb = 99; // caller mutation must not leak into the committed config
    expect(nativeHashEmbedder(DEFAULT_NATIVE_CONFIG).modelId).toBe(e.modelId);
    expect((e.config as { fieldWeights: { verb: number } }).fieldWeights.verb).toBe(4);
  });
});

// ---------------------------------------------------------------------------------------------
/** Independent reference implementation of the documented native scheme. */
function refEmbed(cfg: NativeEmbedderConfig, a: { verb: string; resource: string; params: Record<string, unknown> }): number[] {
  const v = new Array<number>(cfg.dims).fill(0);
  const add = (feat: string, w: number) => {
    const bytes = utf8(`${cfg.seed}\u001f${feat}`);
    const h = sha256(bytes);
    const u32 = ((h[0]! << 24) | (h[1]! << 16) | (h[2]! << 8) | h[3]!) >>> 0;
    v[u32 % cfg.dims]! += h[4]! & 1 ? -w : w;
  };
  const feats = (prefix: string, t: string): string[] => {
    const out: string[] = [];
    const cps = [...`\u0002${t}\u0003`];
    for (let n = cfg.ngramMin; n <= cfg.ngramMax; n++) for (let i = 0; i + n <= cps.length; i++) out.push(`${prefix}c${n}:${cps.slice(i, i + n).join('')}`);
    for (const w of t.split(/[^\p{L}\p{N}]+/u)) if (w !== '') out.push(`${prefix}w:${w.toLowerCase()}`);
    return out;
  };
  const leaves: string[] = [];
  const walk = (x: unknown, path: string) => {
    if (Array.isArray(x)) x.forEach((y, i) => walk(y, `${path}[${i}]`));
    else if (x !== null && typeof x === 'object') for (const k of Object.keys(x)) walk((x as Record<string, unknown>)[k], path === '' ? k : `${path}.${k}`);
    else leaves.push(`${path}=${canonicalize(x)}`);
  };
  walk(a.params, '');
  for (const f of feats('v:', a.verb)) add(f, cfg.fieldWeights.verb);
  for (const f of feats('r:', a.resource)) add(f, cfg.fieldWeights.resource);
  if (cfg.paramMode === 'digest') add(`p#:${hashCanonical({ t: 'pca-objrisk-params-v1', params: a.params })}`, cfg.fieldWeights.param);
  else for (const l of leaves) for (const f of feats('p:', l)) add(f, cfg.fieldWeights.param);
  return v.map((x) => (Object.is(x, -0) ? 0 : x));
}

describe('nativeHashEmbedder: matches an independent reference implementation', () => {
  const actions: ObjAction[] = [
    { verb: 'db.delete', resource: 'orders', params: { table: 'orders', where: 'id<10' } },
    { verb: 'x', resource: 'y' },
    { verb: 'mail.send', resource: 'user@example.com/Inbox', params: { to: ['a@b.c', 'd@e.f'], nested: { deep: { er: [1, 2, { z: null }] }, b: true }, n: 3.5 } },
    { verb: 'écrêter', resource: 'Café/\u{1F600}/x', params: { 'über': 'straße  ---  wörd1 wörd2', k: [[], {}], emoji: '\u{1F600}\u{1F601}a' } },
    { verb: 'a', resource: 'b', params: { a: 1, b: 2, c: 3, d: 4, e: 5, f: 6 } },
  ];
  const configs: NativeEmbedderConfig[] = [
    DEFAULT_NATIVE_CONFIG,
    { ...DEFAULT_NATIVE_CONFIG, dims: 8, ngramMin: 1, ngramMax: 3, seed: 's2', fieldWeights: { verb: 7, resource: 0, param: 3 } },
    { ...DEFAULT_NATIVE_CONFIG, dims: 64, ngramMin: 3, ngramMax: 3, fieldWeights: { verb: 1, resource: 5, param: 0 } },
    { ...DEFAULT_NATIVE_CONFIG, dims: 100, paramMode: 'digest' },
    { ...DEFAULT_NATIVE_CONFIG, dims: 17, ngramMin: 2, ngramMax: 6, paramMode: 'digest', fieldWeights: { verb: 2, resource: 3, param: 11 } },
    { ...DEFAULT_NATIVE_CONFIG, paramMode: 'leaves', maxParamLeaves: 1000 },
  ];
  for (let ci = 0; ci < configs.length; ci++) {
    it(`config #${ci}`, () => {
      const cfg = configs[ci]!;
      const e = nativeHashEmbedder(cfg);
      for (const a of actions) {
        const c = canonicalAction(a);
        expect(e.embed(c)).toEqual(refEmbed(cfg, c));
      }
    });
  }
  it('leaf paths distinguish array indices and nested keys', () => {
    // param-only embedder so only the path text matters
    const e = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, fieldWeights: { verb: 0, resource: 0, param: 1 } });
    const em = (params: Record<string, unknown>) => e.embed(canonicalAction({ verb: 'v', resource: 'r', params }));
    expect(em({ a: [1] })).not.toEqual(em({ b: [1] }));
    expect(em({ a: [1] })).not.toEqual(em({ a: [[1]] }));
    expect(em({ a: { x: 1 } })).not.toEqual(em({ a: { y: 1 } }));
    expect(em({ a: { x: 1 } })).not.toEqual(em({ b: { x: 1 } }));
    expect(em({ a: [1, 2] })).not.toEqual(em({ a: [2, 1] }));
    expect(em({ a: [1] })).not.toEqual(em({ a: [2] }));
    // key order is irrelevant
    expect(em({ a: 1, b: 2 })).toEqual(em({ b: 2, a: 1 }));
  });
  it('digest mode: one params token; adding params changes the vector by at most that bucket', () => {
    const e = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, paramMode: 'digest' });
    const a = e.embed(canonicalAction({ verb: 'v', resource: 'r', params: { x: 1 } }));
    const b = e.embed(canonicalAction({ verb: 'v', resource: 'r', params: { x: 1, y: 2, z: 3 } }));
    const diff = a.map((x, i) => (x === b[i] ? 0 : 1)).reduce<number>((s, x) => s + x, 0);
    expect(diff).toBeLessThanOrEqual(2);
    expect(diff).toBeGreaterThan(0);
  });
});

describe('nativeHashEmbedder: param-leaf cap', () => {
  const leavesAct = (n: number): ObjAction => ({ verb: 'v', resource: 'r', params: Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i])) });
  it('default cap is DEFAULT_MAX_PARAM_LEAVES (inclusive), message names count and cap', () => {
    expect(DEFAULT_MAX_PARAM_LEAVES).toBe(256);
    const e = nativeHashEmbedder();
    expect(() => e.embed(canonicalAction(leavesAct(256)))).not.toThrow();
    expect(() => e.embed(canonicalAction(leavesAct(257)))).toThrow(new EmbeddingError('param leaf count 257 exceeds cap 256'));
  });
  it('explicit cap is honoured and applies to digest mode too', () => {
    const e = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, maxParamLeaves: 3 });
    expect(() => e.embed(canonicalAction(leavesAct(3)))).not.toThrow();
    expect(() => e.embed(canonicalAction(leavesAct(4)))).toThrow(new EmbeddingError('param leaf count 4 exceeds cap 3'));
    const d = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, maxParamLeaves: 2, paramMode: 'digest' });
    expect(() => d.embed(canonicalAction(leavesAct(3)))).toThrow('param leaf count 3 exceeds cap 2');
  });
  it('nested/array leaves are counted', () => {
    const e = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, maxParamLeaves: 2 });
    expect(() => e.embed(canonicalAction({ verb: 'v', resource: 'r', params: { a: [1, 2], b: { c: 3 } } }))).toThrow('param leaf count 3 exceeds cap 2');
    expect(() => e.embed(canonicalAction({ verb: 'v', resource: 'r', params: { a: [1, 2] } }))).not.toThrow();
  });
});

// ---------------------------------------------------------------------------------------------
describe('byoEmbedder', () => {
  const desc = (o: Partial<ByoDescriptor> = {}, q: Partial<ByoDescriptor['quantization']> = {}): ByoDescriptor => ({
    name: 'm',
    version: '1',
    weightsDigest: 'w',
    runtime: 'rt',
    dims: 3,
    quantization: { bits: 8, scale: 1, ...q },
    inputEncoding: 'pca-canonical-action-json-v1',
    ...o,
  });
  const ident = () => [1, 2, 3];
  it('dims must be a positive safe integer', () => {
    const m = 'byo: dims must be a positive integer';
    expect(() => byoEmbedder(desc({ dims: 0 }), ident)).toThrow(new RangeError(m));
    expect(() => byoEmbedder(desc({ dims: -1 }), ident)).toThrow(m);
    expect(() => byoEmbedder(desc({ dims: 1.5 }), ident)).toThrow(m);
    expect(() => byoEmbedder(desc({ dims: 2 ** 60 }), ident)).toThrow(m);
    expect(() => byoEmbedder(desc({ dims: NaN }), ident)).toThrow(m);
    expect(byoEmbedder(desc({ dims: 1 }), () => [1]).dims).toBe(1);
  });
  it('quantization: bits integer in [2,31], scale > 0', () => {
    const m = 'byo: invalid quantization';
    for (const bits of [1, 0, 32, 2.5, NaN, Infinity]) expect(() => byoEmbedder(desc({}, { bits }), ident)).toThrow(new RangeError(m));
    for (const scale of [0, -1, NaN]) expect(() => byoEmbedder(desc({}, { scale }), ident)).toThrow(m);
    expect(() => byoEmbedder(desc({}, { bits: 2 }), ident)).not.toThrow();
    expect(() => byoEmbedder(desc({}, { bits: 31 }), ident)).not.toThrow();
    expect(() => byoEmbedder(desc({}, { scale: 1e-9 }), ident)).not.toThrow();
  });
  it('inputEncoding must be the canonical-action-json encoding', () => {
    expect(() => byoEmbedder(desc({ inputEncoding: 'other' as never }), ident)).toThrow(new RangeError('byo: unsupported inputEncoding'));
  });
  it('claimed modelId must equal the descriptor hash', () => {
    const d = desc();
    expect(byoModelId(d)).toBe(`byo:${hashCanonical(d)}`);
    expect(byoEmbedder(d, ident).modelId).toBe(byoModelId(d));
    expect(byoEmbedder(d, ident, byoModelId(d)).modelId).toBe(byoModelId(d));
    expect(() => byoEmbedder(d, ident, 'byo:other')).toThrow(new Error('byo: modelId does not match the committed descriptor'));
    expect(byoEmbedder(d, ident).config).toBe(d);
  });
  it('embed feeds canonical JSON to infer and enforces dims / range / quantization', () => {
    let seen = '';
    const e = byoEmbedder(desc({}, { bits: 4 }), (j) => {
      seen = j;
      return [7, -7, 0];
    });
    const c = canonicalAction({ verb: 'v', resource: 'r', params: { b: 1, a: 2 } });
    expect(e.embed(c)).toEqual([7, -7, 0]);
    expect(seen).toBe(canonicalActionJson(c));
    // qmax = 2^(bits-1) - 1 = 7 inclusive
    expect(() => byoEmbedder(desc({}, { bits: 4 }), () => [8, 0, 0]).embed(c)).toThrow(new EmbeddingError('byo: component exceeds declared quantization range'));
    expect(() => byoEmbedder(desc({}, { bits: 4 }), () => [0, -8, 0]).embed(c)).toThrow('byo: component exceeds declared quantization range');
    expect(byoEmbedder(desc({}, { bits: 2 }), () => [1, -1, 0]).embed(c)).toEqual([1, -1, 0]);
    expect(() => byoEmbedder(desc({}, { bits: 2 }), () => [2, 0, 0]).embed(c)).toThrow('byo: component exceeds declared quantization range');
    expect(() => byoEmbedder(desc({}, { bits: 20 }), () => [2 ** 19, 0, 0]).embed(c)).toThrow('byo: component exceeds');
    expect(byoEmbedder(desc({}, { bits: 20 }), () => [2 ** 19 - 1, 0, 0]).embed(c)[0]).toBe(2 ** 19 - 1);
    expect(() => byoEmbedder(desc(), () => [1, 2]).embed(c)).toThrow('vector must have exactly 3 components');
    expect(() => byoEmbedder(desc(), () => [1, 1.5, 3]).embed(c)).toThrow('vector components must be safe integers');
  });
});

describe('conformanceCheck', () => {
  const e = nativeHashEmbedder();
  const a1: ObjAction = { verb: 'a.b', resource: 'r1', params: { p: 1 } };
  const a2: ObjAction = { verb: 'c.d', resource: 'r2' };
  const v1 = e.embed(canonicalAction(a1));
  const v2 = e.embed(canonicalAction(a2));
  it('true iff every case reproduces exactly', () => {
    expect(conformanceCheck(e, [])).toBe(true);
    expect(conformanceCheck(e, [{ action: a1, vector: v1 }])).toBe(true);
    expect(conformanceCheck(e, [{ action: a1, vector: v1 }, { action: a2, vector: v2 }])).toBe(true);
    expect(conformanceCheck(e, [{ action: a1, vector: v1 }, { action: a2, vector: v1 }])).toBe(false); // 2nd wrong
    expect(conformanceCheck(e, [{ action: a1, vector: v2 }, { action: a2, vector: v2 }])).toBe(false); // 1st wrong
  });
  it('a single differing component fails; length mismatch (prefix equal) fails both ways', () => {
    const off = v1.slice();
    off[off.length - 1] = off[off.length - 1]! + 1;
    expect(conformanceCheck(e, [{ action: a1, vector: off }])).toBe(false);
    const off0 = v1.slice();
    off0[0] = off0[0]! + 1;
    expect(conformanceCheck(e, [{ action: a1, vector: off0 }])).toBe(false);
    expect(conformanceCheck(e, [{ action: a1, vector: [...v1, 0] }])).toBe(false); // expected longer than produced
    expect(conformanceCheck(e, [{ action: a1, vector: v1.slice(0, 10) }])).toBe(false); // expected shorter than produced
    // partial agreement (some equal, some not) must fail
    const half = v1.map((x, i) => (i % 2 ? x + 1 : x));
    expect(conformanceCheck(e, [{ action: a1, vector: half }])).toBe(false);
  });
  it('a throwing case (bad action or throwing embedder) yields false, never throws', () => {
    expect(conformanceCheck(e, [{ action: { verb: '', resource: 'r' }, vector: [] }])).toBe(false);
    const boom: Embedder = { modelId: 'x', config: {}, dims: 1, embed: () => { throw new Error('boom'); } };
    expect(conformanceCheck(boom, [{ action: a1, vector: [1] }])).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('goal commitment', () => {
  const native = nativeHashEmbedder();
  const goalAction: ObjAction = { verb: 'report.read', resource: 'sales/q3', params: { format: 'pdf' } };
  const recommit = (g: Omit<GoalCommitment, 'commit'>): GoalCommitment => ({
    ...g,
    commit: hashCanonical({ embedderModelId: g.embedderModelId, config: g.config, goalVector: g.goalVector, metric: g.metric, epsilon: g.epsilon }),
  });
  const good = () => commitGoal(native, goalAction);

  it('constants', () => {
    expect(METRIC).toBe('half-chord-v1');
    expect(DEFAULT_EPSILON).toBe(1 / 4096);
  });
  it('commitGoal binds embedder id/config, vector, metric and epsilon with the documented hash', () => {
    const g = good();
    expect(g.embedderModelId).toBe(native.modelId);
    expect(g.config).toBe(native.config);
    expect(g.goalVector).toEqual(native.embed(canonicalAction(goalAction)));
    expect(g.metric).toBe('half-chord-v1');
    expect(g.epsilon).toBe(1 / 4096);
    expect(g.commit).toBe(hashCanonical({ embedderModelId: g.embedderModelId, config: g.config, goalVector: g.goalVector, metric: g.metric, epsilon: g.epsilon }));
    expect(commitGoal(native, goalAction, 0.5).epsilon).toBe(0.5);
    expect(commitGoal(native, goalAction, 0.5).commit).not.toBe(g.commit);
  });
  it('commitGoal epsilon must be in (0, 1]', () => {
    const m = 'epsilon must be in (0, 1]';
    for (const eps of [0, -0.1, 1.0001, 2, NaN, Infinity]) expect(() => commitGoal(native, goalAction, eps)).toThrow(new RangeError(m));
    expect(commitGoal(native, goalAction, 1).epsilon).toBe(1);
    expect(commitGoal(native, goalAction, 1e-9).epsilon).toBe(1e-9);
  });
  it('commitGoal validates the embedder output', () => {
    const bad: Embedder = { modelId: 'x', config: {}, dims: 3, embed: () => [1, 2] };
    expect(() => commitGoal(bad, goalAction)).toThrow('vector must have exactly 3 components');
  });
  it('verifyGoalCommitment accepts a good commitment', () => {
    expect(verifyGoalCommitment(good(), native)).toBeNull();
  });
  it('unknown metric', () => {
    expect(verifyGoalCommitment({ ...good(), metric: 'other' as never }, native)).toBe('unknown metric');
  });
  it('bad epsilon is reported before the hash check, at both ends and exactly', () => {
    const g = good();
    for (const eps of [0, -1, 1.5, NaN]) expect(verifyGoalCommitment({ ...g, epsilon: eps }, native)).toBe('bad epsilon');
    // recommitted so only the bound matters
    expect(verifyGoalCommitment(recommit({ ...g, epsilon: 0 }), native)).toBe('bad epsilon');
    expect(verifyGoalCommitment(recommit({ ...g, epsilon: 1.0000001 }), native)).toBe('bad epsilon');
    expect(verifyGoalCommitment(recommit({ ...g, epsilon: 1 }), native)).toBeNull();
    expect(verifyGoalCommitment(recommit({ ...g, epsilon: 1e-12 }), native)).toBeNull();
    expect(verifyGoalCommitment(recommit({ ...g, epsilon: 0.5 }), native)).toBeNull();
  });
  it('hash mismatch', () => {
    const g = good();
    const v = g.goalVector.slice();
    v[0] = v[0]! + 1;
    expect(verifyGoalCommitment({ ...g, goalVector: v }, native)).toBe('goal commitment hash mismatch');
    expect(verifyGoalCommitment({ ...g, epsilon: 0.5 }, native)).toBe('goal commitment hash mismatch');
    expect(verifyGoalCommitment({ ...g, commit: 'x' }, native)).toBe('goal commitment hash mismatch');
  });
  it('embedder modelId mismatch', () => {
    const g = recommit({ ...good(), embedderModelId: 'native:other' });
    expect(verifyGoalCommitment(g, native)).toBe('embedder modelId mismatch');
  });
  it('embedder config mismatch (same id, different config)', () => {
    const g = recommit({ ...good(), config: { different: true } });
    expect(verifyGoalCommitment(g, native)).toBe('embedder config mismatch');
    // an embedder that claims the same id but carries another config
    const liar: Embedder = { ...native, config: { scheme: 'other' } };
    expect(verifyGoalCommitment(good(), liar)).toBe('embedder config mismatch');
    // equal config content in a different object is accepted
    const clone: Embedder = { ...native, config: JSON.parse(JSON.stringify(native.config)) };
    expect(verifyGoalCommitment(good(), clone)).toBeNull();
  });
  it('goal vector is validated against the embedder dims (message surfaced)', () => {
    const g = recommit({ ...good(), goalVector: [1, 2, 3] });
    expect(verifyGoalCommitment(g, native)).toBe('vector must have exactly 256 components');
    const g2 = recommit({ ...good(), goalVector: Array.from({ length: 256 }, (_, i) => (i === 3 ? 0.5 : 0)) });
    expect(verifyGoalCommitment(g2, native)).toBe('vector components must be safe integers');
  });
  it('never throws: an Error message is surfaced, a non-Error becomes a fixed string', () => {
    const errG = Object.defineProperty({ ...good() }, 'metric', { get() { throw new Error('getter boom'); } }) as GoalCommitment;
    expect(verifyGoalCommitment(errG, native)).toBe('getter boom');
    const strG = Object.defineProperty({ ...good() }, 'metric', { get() { throw 'not an error'; } }) as GoalCommitment; // eslint-disable-line no-throw-literal
    expect(verifyGoalCommitment(strG, native)).toBe('invalid goal commitment');
  });
});

describe('vectorDistance', () => {
  it('length mismatch is maximal distance even when the common prefix is identical', () => {
    expect(vectorDistance([1], [1, 2])).toBe(1);
    expect(vectorDistance([1, 2], [1])).toBe(1);
    expect(vectorDistance([], [1])).toBe(1);
  });
  it('a zero vector is maximal distance (even against itself)', () => {
    expect(vectorDistance([0, 0], [0, 0])).toBe(1);
    expect(vectorDistance([0, 0], [1, 2])).toBe(1);
    expect(vectorDistance([1, 2], [0, 0])).toBe(1);
    expect(vectorDistance([], [])).toBe(1);
  });
  it('identical vectors are at distance 0; parallel vectors too', () => {
    expect(vectorDistance([3, 4], [3, 4])).toBe(0);
    expect(vectorDistance([1, 1], [2, 2])).toBe(0);
    expect(vectorDistance([123456789, -987654321, 5], [123456789, -987654321, 5])).toBe(0);
  });
  it('orthogonal = sqrt(1/2) rounded UP to the epsilon grid; opposite = 1', () => {
    expect(vectorDistance([1, 0], [0, 1])).toBe(2897 / 4096);
    expect(vectorDistance([1, 0], [0, 1], 0.25)).toBe(0.75);
    expect(vectorDistance([1, 0], [-1, 0])).toBe(1);
    expect(vectorDistance([1, 0], [-3, 0], 0.25)).toBe(1);
  });
  it('is symmetric and lies on the epsilon grid in (0,1]', () => {
    const a = [3, -1, 4, 1, -5];
    const b = [2, 7, -1, 8, 2];
    const d = vectorDistance(a, b);
    expect(vectorDistance(b, a)).toBe(d);
    expect(d).toBeGreaterThan(0);
    expect(d).toBeLessThanOrEqual(1);
    expect(Math.abs(d * 4096 - Math.round(d * 4096))).toBeLessThan(1e-9);
    // custom epsilon grid
    const d2 = vectorDistance(a, b, 0.1);
    expect(Math.abs(d2 * 10 - Math.round(d2 * 10))).toBeLessThan(1e-9);
    expect(d2).toBeGreaterThanOrEqual(d - 1e-12);
  });
  it('a tiny but non-zero angle still rounds up to one epsilon (never to 0)', () => {
    const big = 1e7;
    expect(vectorDistance([big, 1], [big, 2])).toBe(1 / 4096);
  });
});

describe('committedDistanceChecked / committedDistance', () => {
  const native = nativeHashEmbedder();
  const goalAction: ObjAction = { verb: 'report.read', resource: 'sales/q3', params: { format: 'pdf' } };
  const goal = commitGoal(native, goalAction);
  it('ok path returns the grid distance', () => {
    const c = canonicalAction(goalAction);
    expect(committedDistanceChecked(c, goal, native)).toEqual({ ok: true, value: 0 });
    const other = canonicalAction({ verb: 'db.drop', resource: 'prod', params: { force: true } });
    const r = committedDistanceChecked(other, goal, native);
    expect(r).toEqual({ ok: true, value: vectorDistance(native.embed(other), goal.goalVector, goal.epsilon) });
    expect((r as { value: number }).value).toBeGreaterThan(0);
  });
  it('commitment failure is reported with its reason', () => {
    const c = canonicalAction(goalAction);
    expect(committedDistanceChecked(c, { ...goal, epsilon: 0 }, native)).toEqual({ ok: false, reason: 'bad epsilon' });
    expect(committedDistanceChecked(c, { ...goal, metric: 'z' as never }, native)).toEqual({ ok: false, reason: 'unknown metric' });
  });
  it('embedding failure: Error message surfaced, non-Error gets the fixed text', () => {
    const c = canonicalAction(goalAction);
    const mk = (embed: Embedder['embed']): Embedder => ({ ...native, embed });
    expect(committedDistanceChecked(c, goal, mk(() => { throw new Error('embed boom'); }))).toEqual({ ok: false, reason: 'embed boom' });
    expect(committedDistanceChecked(c, goal, mk(() => { throw 'str'; }))).toEqual({ ok: false, reason: 'embedding failed' }); // eslint-disable-line no-throw-literal
    expect(committedDistanceChecked(c, goal, mk(() => [1, 2]))).toEqual({ ok: false, reason: 'vector must have exactly 256 components' });
    const cap = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, maxParamLeaves: 1 });
    const cg = commitGoal(cap, goalAction);
    expect(committedDistanceChecked(canonicalAction({ verb: 'v', resource: 'r', params: { a: 1, b: 2 } }), cg, cap)).toEqual({ ok: false, reason: 'param leaf count 2 exceeds cap 1' });
  });
  it('committedDistance canonicalizes and returns 1 on any failure (never throws)', () => {
    expect(committedDistance(goalAction, goal, native)).toBe(0);
    expect(committedDistance({ ...goalAction, verb: '  REPORT.READ ' }, goal, native)).toBe(0);
    expect(committedDistance({ verb: '', resource: 'r' }, goal, native)).toBe(1);
    expect(committedDistance(goalAction, { ...goal, epsilon: 5 }, native)).toBe(1);
    expect(committedDistance({ verb: 'x', resource: 'y', params: { u: undefined } } as never, goal, native)).toBe(1);
    const d = committedDistance({ verb: 'db.drop', resource: 'prod' }, goal, native);
    expect(d).toBeGreaterThan(0);
    expect(d).toBeLessThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------------------------
describe('calibration', () => {
  it('calibrate: 1 - (1 + #{s >= raw}) / (n + 1); ties count; empty / non-finite fail closed', () => {
    expect(calibrate(0.5, [])).toBe(1);
    expect(calibrate(NaN, [0.1])).toBe(1);
    expect(calibrate(Infinity, [0.1])).toBe(1);
    expect(calibrate(-Infinity, [0.1])).toBe(1);
    expect(calibrate(0.5, [0.5, 0.5, 0.2])).toBe(1 - 3 / 4); // two ties
    expect(calibrate(0.5, [0.6, 0.5, 0.2])).toBe(1 - 3 / 4);
    expect(calibrate(0.5, [0.4, 0.3, 0.2])).toBe(1 - 1 / 4); // nothing >= raw
    expect(calibrate(0.1, [0.4, 0.3, 0.2])).toBe(1 - 4 / 4); // all >=
    expect(calibrate(0.1, [0.4])).toBe(1 - 2 / 2);
    expect(calibrate(0.5, [0.1])).toBe(1 - 1 / 2);
    expect(calibrate(0, [1, 1, 1, 1, 1, 1, 1, 1, 1])).toBe(1 - 10 / 10);
  });
  it('calibrate is non-decreasing in raw', () => {
    const s = [0.1, 0.5, 0.5, 0.9];
    let prev = -1;
    for (const raw of [0, 0.1, 0.3, 0.5, 0.7, 0.9, 1]) {
      const r = calibrate(raw, s);
      expect(r).toBeGreaterThanOrEqual(prev);
      prev = r;
    }
  });
  it('conformalThreshold picks the ceil((n+1)(1-alpha))-th smallest score', () => {
    const sc = [0.9, 0.1, 0.5, 0.3, 0.7, 0.2, 0.8, 0.4, 0.6]; // n = 9, unsorted
    const orig = sc.slice();
    expect(conformalThreshold(sc, 0.1)).toBe(0.9); // k = ceil(10*.9) = 9 = n  -> allowed (k > n is Infinity)
    expect(conformalThreshold(sc, 0.5)).toBe(0.5); // k = 5
    expect(conformalThreshold(sc, 0.8)).toBe(0.2); // k = ceil(10*.2)= 2
    expect(conformalThreshold(sc, 0.9)).toBe(0.1); // k = 1
    expect(sc).toEqual(orig); // input untouched
    expect(conformalThreshold([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8], 0.1)).toBe(Infinity); // n = 8: k = 9 > n
    expect(conformalThreshold([3, 1, 2], 0.5)).toBe(2); // k = ceil(4*.5) = 2
    expect(conformalThreshold([10, 9, 1], 0.5)).toBe(9); // numeric (not lexicographic) sort
    expect(conformalThreshold([5], 0.5)).toBe(5); // k = ceil(2 * .5) = 1
    expect(conformalThreshold([5], 0.4)).toBe(Infinity); // k = ceil(2*.6)= 2 > 1
    expect(conformalThreshold([1, 2, 3, 4], 0.25)).toBe(4); // k = ceil(5 * .75) = 4 = n -> allowed
  });
  it('conformalThreshold: exact (n+1)(1-alpha) arithmetic', () => {
    // multiplication vs division, (1 - alpha) vs (1 + alpha)
    expect(conformalThreshold([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.3)).toBe(8); // k = ceil(11 * .7) = ceil(7.7) = 8
    expect(conformalThreshold([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.5)).toBe(6); // ceil(5.5)
    expect(conformalThreshold([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.9)).toBe(2); // ceil(1.1)
    expect(conformalThreshold([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 0.05)).toBe(Infinity); // ceil(10.45) = 11 > 10
  });
  it('conformalThreshold on an empty set is Infinity for every alpha (including alpha = 1)', () => {
    expect(conformalThreshold([], 0.5)).toBe(Infinity);
    expect(conformalThreshold([], 1)).toBe(Infinity);
    expect(conformalThreshold([], 0)).toBe(Infinity);
  });
  it('calibrationDigest is order-independent and numerically sorted', () => {
    const ref = hashCanonical({ v: 1, scores: [1, 2, 10] });
    for (const p of perms([10, 1, 2])) expect(calibrationDigest(p)).toBe(ref);
    const s = [0.5, 0.25, 0.75, 0.1];
    for (const p of perms(s)) expect(calibrationDigest(p)).toBe(hashCanonical({ v: 1, scores: [0.1, 0.25, 0.5, 0.75] }));
    expect(calibrationDigest([1, 2])).not.toBe(calibrationDigest([1, 3]));
    const arr = [3, 1, 2];
    calibrationDigest(arr);
    expect(arr).toEqual([3, 1, 2]);
  });
});

describe('harmReport', () => {
  const dn = (id: string, ceiling: number, weight: number) => ({ id, ceiling, weight });
  it('weighted saturating normalization', () => {
    const units = { a: 5, b: 50 };
    expect(harmReport(units, [dn('a', 10, 1), dn('b', 100, 3)])).toEqual({ units, normalized: (1 * 0.5 + 3 * 0.5) / 4 });
    expect(harmReport({ a: 10, b: 0 }, [dn('a', 10, 1), dn('b', 100, 3)]).normalized).toBe(0.25);
    expect(harmReport({ a: 0, b: 100 }, [dn('a', 10, 1), dn('b', 100, 3)]).normalized).toBe(0.75);
    expect(harmReport({ a: 1e9 }, [dn('a', 10, 1)]).normalized).toBe(1); // saturates
    expect(harmReport({ a: 3 }, [dn('a', 10, 2), dn('b', 10, 2)]).normalized).toBe((2 * 0.3 + 0) / 4);
  });
  it('echoes the same units object', () => {
    const units = { a: 1 };
    expect(harmReport(units, [dn('a', 10, 1)]).units).toBe(units);
  });
  it('negative units count as 0; missing units count as 0', () => {
    expect(harmReport({ a: -5 }, [dn('a', 10, 1)]).normalized).toBe(0);
    expect(harmReport({ a: -5, b: 10 }, [dn('a', 10, 1), dn('b', 10, 1)]).normalized).toBe(0.5);
    expect(harmReport({}, [dn('a', 10, 1)]).normalized).toBe(0);
  });
  it('denominations with non-positive weight OR non-positive ceiling are skipped', () => {
    const ok = dn('ok', 10, 1);
    const half = { ok: 5 };
    expect(harmReport({ ...half, w: 1 }, [dn('w', 10, -1), ok]).normalized).toBe(0.5); // negative weight
    expect(harmReport({ ...half, w: 5 }, [dn('w', 10, 0), ok]).normalized).toBe(0.5); // zero weight
    expect(harmReport({ ...half, c: 5 }, [dn('c', 0, 1), ok]).normalized).toBe(0.5); // zero ceiling (would be NaN/Infinity)
    expect(harmReport({ ...half, c: 0 }, [dn('c', 0, 1), ok]).normalized).toBe(0.5);
    expect(harmReport({ ...half, c: 5 }, [dn('c', -10, 1), ok]).normalized).toBe(0.5); // negative ceiling
    expect(harmReport({ ...half, w: 5 }, [dn('w', 10, NaN), ok]).normalized).toBe(0.5);
    expect(harmReport({ ...half, w: 5 }, [dn('w', NaN, 1), ok]).normalized).toBe(0.5);
    expect(harmReport({ ...half, w: 100 }, [dn('w', 10, -1), dn('w2', 10, 1), ok]).normalized).toBe(0.25);
    // weight > 0 but ceiling <= 0 and vice versa are each skipped
    expect(harmReport({ a: 10, b: 10 }, [dn('a', 10, 1), dn('b', 0, 5)]).normalized).toBe(1);
    expect(harmReport({ a: 0, b: 10 }, [dn('a', 10, 1), dn('b', 10, -5)]).normalized).toBe(0);
  });
  it('no usable denomination => 1 (fail closed)', () => {
    expect(harmReport({ a: 1 }, []).normalized).toBe(1);
    expect(harmReport({ a: 1 }, [dn('a', 0, 1), dn('b', 5, 0)]).normalized).toBe(1);
  });
});

// ---------------------------------------------------------------------------------------------
describe('objectiveRisk', () => {
  const native = nativeHashEmbedder();
  const goalAction: ObjAction = { verb: 'report.read', resource: 'api', params: { format: 'pdf' } };
  const goal = commitGoal(native, goalAction);
  const ev = { verifierId: 'acme', evidenceDigest: 'sha256:abc' };
  const mkRegistry = () =>
    new InMemoryInverseRegistry(['acme'])
      .register('db.delete', { inverseKind: 'db.restore', fidelity: 'exact', verification: ev })
      .register('mail.send', { inverseKind: 'mail.apologize', fidelity: 'partial', verification: ev });
  const mkGraph = (harmScale = 1) =>
    new ResourceGraph()
      .addNode({ id: 'api', harm: { rows: 0 } })
      .addNode({ id: 'orders', harm: { rows: 1000 * harmScale, usd: 5000 * harmScale } })
      .addNode({ id: 'items', harm: { rows: 5000 * harmScale } })
      .addNode({ id: 'island', harm: { rows: 1 } })
      .addNode({ id: 'lonely' })
      .addEdge({ from: 'api', to: 'orders', kind: 'rw' })
      .addEdge({ from: 'orders', to: 'items', kind: 'rw' });
  const denoms = [
    { id: 'rows', ceiling: 10000, weight: 1 },
    { id: 'usd', ceiling: 10000, weight: 1 },
  ];
  const ctx = (o: Partial<ObjectiveRiskContext> = {}): ObjectiveRiskContext => ({
    registry: mkRegistry(),
    authorizedKinds: new Set(['db.restore', 'mail.apologize']),
    graph: mkGraph(),
    embedder: native,
    goal,
    commitments: { registryDigest: mkRegistry().digest(), graphDigest: mkGraph().digest() },
    denominations: denoms,
    weights: P.weights,
    taint: 0.1,
    age: 0.2,
    ...o,
  });
  const act = (o: Partial<ObjAction> = {}): ObjAction => ({ verb: 'db.delete', resource: 'orders', params: { table: 'orders' }, ...o });

  const WORST = { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 };
  const rejected = (reasons: string[]) => ({
    r: 1,
    valid: false,
    reasons,
    raw: 1,
    inputs: WORST,
    reversibility: { class: 'irreversible', value: 0 },
    blast: { count: 0, reachable: [], normalized: 1, harm: {} },
    harm: { units: {}, normalized: 1 },
    evidenceDigest: '',
  });

  it('fail-closed record is exact and fresh on every call', () => {
    const a = objectiveRisk({ verb: '', resource: 'r' }, ctx());
    expect(a).toEqual(rejected(['action: canonicalAction: empty verb/resource']));
    a.inputs.age = 0;
    a.reversibility.value = 1;
    a.blast.reachable.push('x');
    const b = objectiveRisk({ verb: '', resource: 'r' }, ctx());
    expect(b.inputs).toEqual(WORST);
    expect(b.reversibility).toEqual({ class: 'irreversible', value: 0 });
    expect(b.blast.reachable).toEqual([]);
  });
  it('un-canonicalizable action: Error message vs non-Error', () => {
    const bad = { verb: 'v', resource: 'r', params: { x: undefined } } as unknown as ObjAction;
    const r = objectiveRisk(bad, ctx());
    expect(r.valid).toBe(false);
    expect(r.reasons).toHaveLength(1);
    expect(r.reasons[0]!.startsWith('action: ')).toBe(true);
    expect(r.reasons[0]!.length).toBeGreaterThan('action: '.length);
    const thrower = Object.defineProperty({ resource: 'r' }, 'verb', { get() { throw 'weird'; } }) as unknown as ObjAction; // eslint-disable-line no-throw-literal
    expect(objectiveRisk(thrower, ctx())).toEqual(rejected(['action: not canonicalizable']));
  });
  it('registry / graph digest mismatches have exact reasons and accumulate in order', () => {
    const rg = 'registry digest does not match the committed digest';
    const gg = 'graph digest does not match the committed digest';
    expect(objectiveRisk(act(), ctx({ commitments: { registryDigest: 'x', graphDigest: mkGraph().digest() } }))).toEqual(rejected([rg]));
    expect(objectiveRisk(act(), ctx({ commitments: { registryDigest: mkRegistry().digest(), graphDigest: 'y' } }))).toEqual(rejected([gg]));
    expect(objectiveRisk(act(), ctx({ commitments: { registryDigest: 'x', graphDigest: 'y' } }))).toEqual(rejected([rg, gg]));
  });
  it('calibration: reasons for missing / mismatching committed digest; matching digest is accepted', () => {
    const cal = [0.1, 0.5, 0.9];
    const missing = 'calibration set used without a committed digest';
    const mismatch = 'calibration digest does not match the committed digest';
    const base = ctx().commitments;
    expect(objectiveRisk(act(), ctx({ calibration: cal }))).toEqual(rejected([missing]));
    expect(objectiveRisk(act(), ctx({ calibration: cal, commitments: { ...base, calibrationDigest: 'nope' } }))).toEqual(rejected([mismatch]));
    const ok = objectiveRisk(act(), ctx({ calibration: cal, commitments: { ...base, calibrationDigest: calibrationDigest(cal) } }));
    expect(ok.valid).toBe(true);
    expect(ok.reasons).toEqual([]);
    expect(ok.r).toBe(calibrate(ok.raw, cal));
    // a committed digest with no calibration set in use is simply ignored
    expect(objectiveRisk(act(), ctx({ commitments: { ...base, calibrationDigest: 'whatever' } })).valid).toBe(true);
  });
  it('goal/embedder failures are prefixed; all failures accumulate in a fixed order', () => {
    expect(objectiveRisk(act(), ctx({ goal: { ...goal, metric: 'z' as never } }))).toEqual(rejected(['goal/embedder: unknown metric']));
    expect(objectiveRisk(act(), ctx({ goal: { ...goal, epsilon: 9 } }))).toEqual(rejected(['goal/embedder: bad epsilon']));
    const cal = [0.5];
    const all = objectiveRisk(
      act(),
      ctx({ commitments: { registryDigest: 'x', graphDigest: 'y', calibrationDigest: 'z' }, calibration: cal, goal: { ...goal, epsilon: 9 } }),
    );
    expect(all.reasons).toEqual([
      'registry digest does not match the committed digest',
      'graph digest does not match the committed digest',
      'calibration digest does not match the committed digest',
      'goal/embedder: bad epsilon',
    ]);
    // embedding failure surfaces its message
    const cap = nativeHashEmbedder({ ...DEFAULT_NATIVE_CONFIG, maxParamLeaves: 1 });
    const r = objectiveRisk(act({ params: { a: 1, b: 2 } }), ctx({ embedder: cap, goal: commitGoal(cap, goalAction) }));
    expect(r.reasons).toEqual(['goal/embedder: param leaf count 2 exceeds cap 1']);
  });

  it('valid result: every field', () => {
    const c = ctx();
    const res = objectiveRisk(act(), c);
    expect(res.valid).toBe(true);
    expect(res.reasons).toEqual([]);
    const canon = canonicalAction(act());
    const dist = committedDistance(act(), goal, native);
    expect(res.reversibility).toEqual({ class: 'reversible', value: 1, inverseKind: 'db.restore' });
    expect(res.blast).toEqual({ count: 2, reachable: ['items', 'orders'], normalized: 2 / 5, harm: { rows: 6000, usd: 5000 } });
    expect(res.harm).toEqual({ units: { rows: 6000, usd: 5000 }, normalized: (0.6 + 0.5) / 2 });
    expect(res.inputs).toEqual({
      semanticDistance: dist,
      reversibility: 1,
      blastRadius: Math.max(2 / 5, (0.6 + 0.5) / 2),
      taint: 0.1,
      confidence: 1,
      age: 0.2,
    });
    expect(res.raw).toBe(riskScore(res.inputs, P.weights));
    expect(res.r).toBe(res.raw);
    expect(res.evidenceDigest).toBe(
      hashCanonical({
        action: canonicalActionDigest(canon),
        scope: { edgeKinds: null, maxDepth: null },
        authorized: ['db.restore', 'mail.apologize'],
        registry: c.commitments.registryDigest,
        graph: c.commitments.graphDigest,
        goal: goal.commit,
        calibration: null,
        inputs: res.inputs,
      }),
    );
  });
  it('blast input = max(count-normalized, harm-normalized) only when denominations AND harm exist', () => {
    // harm dominates (harm.normalized ~ .55 > count 2/5 = .4)
    const dom = objectiveRisk(act(), ctx());
    expect(dom.inputs.blastRadius).toBe(dom.harm.normalized);
    expect(dom.inputs.blastRadius).toBeGreaterThan(dom.blast.normalized);
    // count dominates: huge graph relative to harm
    const small = (s: number) => mkGraph(s);
    const g = small(0.001);
    const cnt = objectiveRisk(act(), ctx({ graph: g, commitments: { registryDigest: mkRegistry().digest(), graphDigest: g.digest() } }));
    expect(cnt.harm.normalized).toBeLessThan(cnt.blast.normalized);
    expect(cnt.inputs.blastRadius).toBe(cnt.blast.normalized);
    // no denominations: harm is ignored (an empty denomination list would otherwise report 1)
    const noDen = objectiveRisk(act(), ctx({ denominations: [] }));
    expect(noDen.harm.normalized).toBe(1);
    expect(noDen.inputs.blastRadius).toBe(2 / 5);
    // denominations but the reachable set carries no harm: count only (harm.normalized would be 0)
    const lonelyG = mkGraph();
    const noHarm = objectiveRisk(act({ resource: 'lonely' }), ctx());
    expect(noHarm.blast.harm).toEqual({});
    expect(noHarm.inputs.blastRadius).toBe(noHarm.blast.normalized);
    expect(noHarm.blast.normalized).toBe(1 / 5);
    void lonelyG;
    // unknown resource: normalized 1 (fail closed) regardless of harm
    const unk = objectiveRisk(act({ resource: 'nope' }), ctx());
    expect(unk.valid).toBe(true);
    expect(unk.inputs.blastRadius).toBe(1);
    // denominations present but all skipped => harm.normalized is 1 => blast 1 when harm exists
    const skipped = objectiveRisk(act(), ctx({ denominations: [{ id: 'rows', ceiling: 0, weight: 1 }] }));
    expect(skipped.inputs.blastRadius).toBe(1);
  });
  it('attestedUncertainty only lowers confidence, clamped to [0,1]; absent = 0', () => {
    const conf = (u?: number) => objectiveRisk(act(), ctx({ attestedUncertainty: u })).inputs.confidence;
    expect(conf(undefined)).toBe(1);
    expect(conf(0)).toBe(1);
    expect(conf(0.25)).toBe(0.75);
    expect(conf(1)).toBe(0);
    expect(conf(2)).toBe(0); // clamped
    expect(conf(-0.5)).toBe(1); // clamped (cannot RAISE confidence above 1 / lower r)
    expect(conf(NaN)).toBe(0); // non-finite fails closed
    expect(conf(Infinity)).toBe(0);
  });
  it('reversibility drives the input and class (partial = compensable, unregistered = irreversible)', () => {
    expect(objectiveRisk(act({ verb: 'mail.send' }), ctx()).inputs.reversibility).toBe(0.5);
    expect(objectiveRisk(act({ verb: 'mail.send' }), ctx()).reversibility.class).toBe('compensable');
    expect(objectiveRisk(act({ verb: 'unknown.verb' }), ctx()).inputs.reversibility).toBe(0);
    expect(objectiveRisk(act({ verb: ' DB.Delete ' }), ctx()).reversibility.class).toBe('reversible'); // canonical verb
  });
  it('scope restricts reachability and is committed (sorted) in the evidence digest', () => {
    const g = new ResourceGraph()
      .addNode({ id: 'a' })
      .addNode({ id: 'b' })
      .addNode({ id: 'c' })
      .addEdge({ from: 'a', to: 'b', kind: 'k1' })
      .addEdge({ from: 'b', to: 'c', kind: 'k2' });
    const reg = mkRegistry();
    const mk = (scope: ObjectiveRiskContext['scope'], authorized: string[]) =>
      ctx({ graph: g, scope, authorizedKinds: new Set(authorized), commitments: { registryDigest: reg.digest(), graphDigest: g.digest() } });
    const expected = (c: ObjectiveRiskContext, inputs: object, edgeKinds: string[] | null, maxDepth: number | null, authorized: string[]) =>
      hashCanonical({
        action: canonicalActionDigest(canonicalAction(act({ resource: 'a' }))),
        scope: { edgeKinds, maxDepth },
        authorized,
        registry: c.commitments.registryDigest,
        graph: c.commitments.graphDigest,
        goal: goal.commit,
        calibration: c.commitments.calibrationDigest ?? null,
        inputs,
      });
    const c1 = mk({ edgeKinds: ['k2', 'k1'], maxDepth: 1 }, ['mail.apologize', 'db.restore', 'zz']);
    const r1 = objectiveRisk(act({ resource: 'a' }), c1);
    expect(r1.blast.reachable).toEqual(['a', 'b']);
    expect(r1.evidenceDigest).toBe(expected(c1, r1.inputs, ['k1', 'k2'], 1, ['db.restore', 'mail.apologize', 'zz']));
    const c2 = mk({ edgeKinds: ['k1', 'k2'] }, ['db.restore', 'mail.apologize']);
    const r2 = objectiveRisk(act({ resource: 'a' }), c2);
    expect(r2.blast.reachable).toEqual(['a', 'b', 'c']);
    expect(r2.evidenceDigest).toBe(expected(c2, r2.inputs, ['k1', 'k2'], null, ['db.restore', 'mail.apologize']));
    const c3 = mk({ maxDepth: 0 }, []);
    const r3 = objectiveRisk(act({ resource: 'a' }), c3);
    expect(r3.blast.reachable).toEqual(['a']);
    expect(r3.evidenceDigest).toBe(expected(c3, r3.inputs, null, 0, []));
    // scope order does not change the digest; different scopes do
    const c1b = mk({ edgeKinds: ['k1', 'k2'], maxDepth: 1 }, ['zz', 'db.restore', 'mail.apologize']);
    expect(objectiveRisk(act({ resource: 'a' }), c1b).evidenceDigest).toBe(r1.evidenceDigest);
    expect(r1.evidenceDigest).not.toBe(r2.evidenceDigest);
    // unrestricted scope vs no scope
    expect(objectiveRisk(act({ resource: 'a' }), mk(undefined, ['db.restore', 'mail.apologize'])).evidenceDigest).toBe(
      objectiveRisk(act({ resource: 'a' }), mk({}, ['db.restore', 'mail.apologize'])).evidenceDigest,
    );
    expect(objectiveRisk(act({ resource: 'a' }), mk(undefined, ['db.restore', 'mail.apologize'])).evidenceDigest).not.toBe(r2.evidenceDigest);
  });
  it('evidence digest commits the calibration digest and the calibrated r', () => {
    const cal = [0.9, 0.1, 0.5];
    const base = ctx().commitments;
    const c = ctx({ calibration: cal, commitments: { ...base, calibrationDigest: calibrationDigest(cal) } });
    const res = objectiveRisk(act(), c);
    expect(res.valid).toBe(true);
    expect(res.evidenceDigest).toBe(
      hashCanonical({
        action: canonicalActionDigest(canonicalAction(act())),
        scope: { edgeKinds: null, maxDepth: null },
        authorized: ['db.restore', 'mail.apologize'],
        registry: base.registryDigest,
        graph: base.graphDigest,
        goal: goal.commit,
        calibration: calibrationDigest(cal),
        inputs: res.inputs,
      }),
    );
    expect(res.r).toBe(calibrate(res.raw, cal));
    expect(res.raw).toBe(riskScore(res.inputs, P.weights));
    expect(res.evidenceDigest).not.toBe(objectiveRisk(act(), ctx()).evidenceDigest);
  });
  it('permuting the authorized kinds (all orders) does not change the evidence digest', () => {
    const kinds = ['db.restore', 'mail.apologize', 'a.b', 'z.y'];
    const ref = objectiveRisk(act(), ctx({ authorizedKinds: new Set(kinds) })).evidenceDigest;
    for (const p of perms(kinds)) expect(objectiveRisk(act(), ctx({ authorizedKinds: new Set(p) })).evidenceDigest).toBe(ref);
  });
  it('is a pure function of the canonical action: encodings collapse', () => {
    const a = objectiveRisk({ verb: ' DB.delete', resource: 'orders ', params: { b: 1, a: { y: 2, x: 1 } } }, ctx());
    const b = objectiveRisk({ verb: 'db.delete', resource: 'orders', params: { a: { x: 1, y: 2 }, b: 1 } }, ctx());
    expect(a.valid).toBe(true);
    expect(a.evidenceDigest).toBe(b.evidenceDigest);
    expect(a.r).toBe(b.r);
  });
});

// ---------------------------------------------------------------------------------------------
describe('objectiveRiskOracle', () => {
  const native = nativeHashEmbedder();
  const goalAction: ObjAction = { verb: 'report.read', resource: 'api', params: { format: 'pdf' } };
  const goal = commitGoal(native, goalAction);
  const ev = { verifierId: 'acme', evidenceDigest: 'sha256:abc' };
  const mkRegistry = () => new InMemoryInverseRegistry(['acme']).register('db.delete', { inverseKind: 'db.restore', fidelity: 'partial', verification: ev });
  const mkGraph = () =>
    new ResourceGraph().addNode({ id: 'orders', harm: { rows: 1000 } }).addNode({ id: 'items', harm: { rows: 500 } }).addNode({ id: 'other' }).addEdge({ from: 'orders', to: 'items', kind: 'rw' });
  const ctx = (o: Partial<ObjectiveRiskContext> = {}): ObjectiveRiskContext => ({
    registry: mkRegistry(),
    authorizedKinds: new Set(['db.restore']),
    graph: mkGraph(),
    embedder: native,
    goal,
    commitments: { registryDigest: mkRegistry().digest(), graphDigest: mkGraph().digest() },
    denominations: [{ id: 'rows', ceiling: 10000, weight: 1 }],
    weights: P.weights,
    taint: 0.1,
    age: 0.2,
    ...o,
  });
  const snap = (action: unknown) => ({ action: { action } }) as never;
  const okAction = { verb: 'db.delete', resource: 'orders', params: { table: 'orders' } };
  const oracle = (o: Partial<ObjectiveRiskContext> = {}) => objectiveRiskOracle(ctx(o));
  const MISSING = 'snapshot action is missing a canonical verb/resource';

  it('resolves each disputable input from the committed facts, with exactly the documented fields', () => {
    const ref = objectiveRisk(okAction, ctx());
    expect(ref.valid).toBe(true);
    const o = oracle();
    expect(o.resolve('reversibility_class', snap(okAction))).toEqual({ input: 'reversibility_class', class: 'compensable', valid: true });
    expect(o.resolve('reversibility', snap(okAction))).toEqual({ input: 'reversibility', value: 0.5, valid: true });
    expect(o.resolve('blastRadius', snap(okAction))).toEqual({ input: 'blastRadius', value: ref.inputs.blastRadius, valid: true });
    expect(o.resolve('semanticDistance', snap(okAction))).toEqual({ input: 'semanticDistance', value: ref.inputs.semanticDistance, valid: true });
    expect(ref.inputs.blastRadius).toBeGreaterThan(0);
    expect(ref.inputs.semanticDistance).toBeGreaterThan(0);
    expect(ref.inputs.semanticDistance).not.toBe(ref.inputs.blastRadius);
  });
  it('unknown disputed input fails closed with its name', () => {
    expect(oracle().resolve('bogus' as never, snap(okAction))).toEqual({ input: 'bogus', valid: false, reason: 'unknown disputed input: bogus' });
  });
  it('a missing / malformed snapshot action is reported with the canonical-verb/resource message', () => {
    const o = oracle();
    const bad = (s: unknown) => o.resolve('reversibility', s as never);
    const exp = { input: 'reversibility', valid: false, reason: MISSING };
    expect(bad(undefined)).toEqual(exp);
    expect(bad(null)).toEqual(exp);
    expect(bad({})).toEqual(exp);
    expect(bad({ action: undefined })).toEqual(exp);
    expect(bad({ action: {} })).toEqual(exp);
    expect(bad({ action: { action: null } })).toEqual(exp);
    expect(bad(snap({ resource: 'orders' }))).toEqual(exp);
    expect(bad(snap({ verb: 5, resource: 'orders' }))).toEqual(exp);
    expect(bad(snap({ verb: 'db.delete' }))).toEqual(exp);
    expect(bad(snap({ verb: 'db.delete', resource: 7 }))).toEqual(exp);
  });
  it('non-object params are treated as {} (and a real object is honoured)', () => {
    const o = oracle();
    const dist = (params: unknown) => (o.resolve('semanticDistance', snap({ verb: 'db.delete', resource: 'orders', params })) as { value: number; valid: boolean });
    const empty = dist({});
    expect(empty.valid).toBe(true);
    for (const p of [[1, 2], [], 'str', 5, true, null, undefined]) expect(dist(p)).toEqual(empty);
    const withParams = dist({ table: 'orders', where: 'id < 10' });
    expect(withParams.valid).toBe(true);
    expect(withParams.value).not.toBe(empty.value);
    expect(withParams.value).toBe(committedDistance({ verb: 'db.delete', resource: 'orders', params: { table: 'orders', where: 'id < 10' } }, goal, native));
  });
  it('an invalid objective risk (commitment mismatch) is indeterminate, with reasons joined by "; "', () => {
    const o = oracle({ commitments: { registryDigest: 'x', graphDigest: 'y' } });
    expect(o.resolve('blastRadius', snap(okAction))).toEqual({
      input: 'blastRadius',
      valid: false,
      reason: 'registry digest does not match the committed digest; graph digest does not match the committed digest',
    });
    const one = oracle({ goal: { ...goal, epsilon: 7 } });
    expect(one.resolve('reversibility_class', snap(okAction))).toEqual({ input: 'reversibility_class', valid: false, reason: 'goal/embedder: bad epsilon' });
    // an un-encodable action
    const o2 = oracle();
    expect(o2.resolve('reversibility', snap({ verb: '   ', resource: 'orders' }))).toEqual({
      input: 'reversibility',
      valid: false,
      reason: 'action: canonicalAction: empty verb/resource',
    });
  });
  it('never throws: unexpected errors become a fail-closed resolution (Error message vs "unknown")', () => {
    const boomErr = oracle({ registry: { ...mkRegistry(), lookup: () => undefined, trustedVerifiers: () => [], digest: () => { throw new Error('registry down'); } } });
    expect(boomErr.resolve('reversibility', snap(okAction))).toEqual({
      input: 'reversibility',
      valid: false,
      reason: 'objective oracle error (fail closed): registry down',
    });
    const boomStr = oracle({ registry: { lookup: () => undefined, trustedVerifiers: () => [], digest: () => { throw 'str'; } } }); // eslint-disable-line no-throw-literal
    expect(boomStr.resolve('semanticDistance', snap(okAction))).toEqual({
      input: 'semanticDistance',
      valid: false,
      reason: 'objective oracle error (fail closed): unknown',
    });
  });
});

// ---------------------------------------------------------------------------------------------
describe('sorting is a genuine total order on large inputs', () => {
  const prng = (seed: number) => () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) | 0;
    return (seed >>> 0) / 4294967296;
  };
  const shuffled = <T>(a: T[], seed: number): T[] => {
    const r = prng(seed);
    const o = a.slice();
    for (let i = o.length - 1; i > 0; i--) {
      const j = Math.floor(r() * (i + 1));
      [o[i], o[j]] = [o[j]!, o[i]!];
    }
    return o;
  };
  const ids = Array.from({ length: 400 }, (_, i) => `id${(i * 7919) % 400}`).sort(cmpStr);
  it('registry digest is independent of insertion order for hundreds of verbs', () => {
    const mk = (order: string[]) => {
      const r = new InMemoryInverseRegistry(['b', 'a']);
      for (const v of order) r.register(v, { inverseKind: 'k', fidelity: 'exact' });
      return r.digest();
    };
    const ref = mk(ids);
    expect(mk([...ids].reverse())).toBe(ref);
    for (const s of [1, 2, 3, 4, 5]) expect(mk(shuffled(ids, s))).toBe(ref);
  });
  it('graph reachability and digest are independent of insertion order for hundreds of nodes', () => {
    const mk = (order: string[]) => {
      const g = new ResourceGraph();
      for (const v of order) g.addNode({ id: v });
      for (const v of ids.slice(1)) g.addEdge({ from: ids[0]!, to: v, kind: 'k' });
      return g;
    };
    const ref = mk(ids);
    expect(ref.reachable(ids[0]!)).toEqual(ids);
    for (const s of [11, 12, 13]) {
      const g = mk(shuffled(ids, s));
      expect(g.reachable(ids[0]!)).toEqual(ids);
      expect(g.digest()).toBe(ref.digest());
    }
  });
});

describe('sorting handles interleaved sorted runs (merge / gallop paths)', () => {
  const ids = Array.from({ length: 400 }, (_, i) => `id${String(i).padStart(4, '0')}`);
  const blk = (a: number, b: number) => ids.slice(a, b);
  it('registry digest is order independent for interleaved runs', () => {
    const mk = (order: string[]) => {
      const r = new InMemoryInverseRegistry();
      for (const v of order) r.register(v, { inverseKind: 'k', fidelity: 'exact' });
      return r.digest();
    };
    const ref = mk(ids);
    expect(mk([...blk(0, 100), ...blk(200, 300), ...blk(100, 200), ...blk(300, 400)])).toBe(ref);
    expect(mk([...blk(100, 200), ...blk(300, 400), ...blk(0, 100), ...blk(200, 300)])).toBe(ref);
    expect(mk([...blk(0, 10), ...blk(20, 30), ...blk(10, 20), ...blk(30, 400)])).toBe(ref);
  });
  it('graph reachable / digest are order independent for interleaved runs', () => {
    const mk = (order: string[]) => {
      const g = new ResourceGraph();
      for (const v of order) g.addNode({ id: v });
      for (const v of ids.slice(1)) g.addEdge({ from: ids[0]!, to: v, kind: 'k' });
      return g;
    };
    const ref = mk(ids);
    const g2 = mk([...blk(0, 100), ...blk(200, 300), ...blk(100, 200), ...blk(300, 400)]);
    expect(g2.reachable(ids[0]!)).toEqual(ids);
    expect(g2.digest()).toBe(ref.digest());
  });
});
