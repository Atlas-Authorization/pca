/**
 * Mutation-kill tests for agent-native.ts (part 2): capability introspection (describeEnvelope / envelopePermits /
 * envelopePermitsToolCall) and the authority lease. Real signed chains; every caveat type, every hint, every guard.
 */
import { describe, expect, it } from 'vitest';
import { b64u, canonicalBytes, hashCanonical } from './hash';
import { generateKeyPair, sign, verifyB64u } from './keys';
import { attenuate, mintRoot, verifyChain, type Capability, type CapabilityChain, type Caveat } from './capability';
import { mintGrant } from './envelope';
import { DEFAULT_RISK_POLICY as P } from './risk';
import {
  HEARTBEAT_SKEW_MS,
  MAX_LEASE_TTL_MS,
  describeEnvelope,
  envelopePermits,
  envelopePermitsToolCall,
  grantLease,
  leaseState,
  renewLease,
  signHeartbeat,
  toolSchemaCaveat,
  type AuthorityEnvelope,
  type CapabilityLease,
  type Heartbeat,
} from './agent-native';

const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pk: b64u(k.publicKey) };
};
const PR = kp();
const A = kp();

const grant = (predicates: unknown[], caveats: unknown[] = []): Capability =>
  mintGrant({
    principalSecret: PR.sk,
    principalPublic: PR.pk,
    holder: A.pk,
    goal: 'g',
    envelope: { predicates, caveats, agent_binding: {}, risk_policy: P } as never,
  }).grant;
const plainRoot = (caveats: Caveat[] = []): Capability => mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: A.pk, caveats });
/** root + one attenuation hop per caveat list */
const chainOf = (root: Capability, ...hops: Caveat[][]): CapabilityChain => {
  const out: Capability[] = [root];
  for (const h of hops) out.push(attenuate(out[out.length - 1]!, h, A.sk));
  return out as CapabilityChain;
};
const desc = (preds: unknown[], ...hops: Caveat[][]) => describeEnvelope(chainOf(grant(preds), ...hops));
const allow = (...p: unknown[]): Caveat => ({ type: 'predicates', allow: p });
const E = (o: Partial<AuthorityEnvelope> = {}): AuthorityEnvelope => ({
  ok: true,
  hasEnvelope: true,
  scopes: null,
  verbs: null,
  resources: null,
  opaqueResourceConstraints: [],
  tools: null,
  toolSchemas: [],
  unsatisfiable: [],
  caveats: [],
  remainingBudgetHints: {},
  ...o,
});

// =============================================================================================
describe('describeEnvelope: failure shapes', () => {
  const EMPTY = {
    ok: false,
    hasEnvelope: false,
    scopes: [],
    verbs: [],
    resources: [],
    opaqueResourceConstraints: [],
    tools: [],
    toolSchemas: [],
    unsatisfiable: [],
    caveats: [],
    remainingBudgetHints: {},
  };
  it('an unverifiable chain yields the empty envelope plus the verifier reason', () => {
    const e = describeEnvelope([]);
    const r = verifyChain([]);
    expect(r.ok).toBe(false);
    expect(e).toEqual({ ...EMPTY, reason: (r as { reason: string }).reason });
    const root = grant([{ verb: '*' }]);
    const tampered = { ...attenuate(root, [{ type: 'rate', max: 1, per_secs: 1 }], A.sk), caveats: [] } as Capability;
    const e2 = describeEnvelope([root, tampered]);
    expect(e2.ok).toBe(false);
    expect(e2.reason).toBe((verifyChain([root, tampered]) as { reason: string }).reason);
    expect(e2.scopes).toEqual([]);
  });
  it('each failure shape is a fresh object (no shared mutable arrays)', () => {
    const a = describeEnvelope([]);
    a.scopes!.push({ verbs: ['x'], resources: [], where: [] });
    a.unsatisfiable.push('x');
    a.caveats.push({ type: 'x' });
    expect(describeEnvelope([])).toMatchObject({ scopes: [], unsatisfiable: [], caveats: [] });
  });
  it('an unexpected exception is fail-closed with a fixed reason', () => {
    const base = chainOf(grant([{ verb: '*' }]), [{ type: 'rate', max: 1, per_secs: 1 }]);
    let found = false;
    for (let k = 1; k <= 60 && !found; k++) {
      let reads = 0;
      const leaf = new Proxy(base[1]!, {
        get(t, key, rcv) {
          if (key === 'caveats' && ++reads === k) throw new Error('boom');
          return Reflect.get(t, key, rcv);
        },
      });
      const r = describeEnvelope([base[0]!, leaf as Capability]);
      if (r.reason === 'introspection error (fail closed)') {
        found = true;
        expect(r).toEqual({ ...EMPTY, reason: 'introspection error (fail closed)' });
      }
    }
    expect(found).toBe(true);
  });
});

describe('describeEnvelope: envelope / no-envelope roots', () => {
  it('a root WITHOUT an envelope caveat: unrestricted by predicates (null projections)', () => {
    const e = describeEnvelope([plainRoot()]);
    expect(e).toMatchObject({ ok: true, hasEnvelope: false, scopes: null, verbs: null, resources: null, tools: null, unsatisfiable: [], opaqueResourceConstraints: [], toolSchemas: [] });
    expect(e.caveats).toEqual([]);
    expect(envelopePermits(e, 'anything', '/anywhere')).toBe(true);
    expect('reason' in e).toBe(false);
  });
  it('predicates / tool_schema caveats appended to a no-envelope chain start from "everything"', () => {
    const root = plainRoot();
    const e = describeEnvelope(chainOf(root, [allow({ verb: ['b', 'a'], resource: '/x/*' }), toolSchemaCaveat('t', { props: {} })]));
    expect(e.hasEnvelope).toBe(false);
    expect(e.scopes).toEqual([{ verbs: ['a', 'b'], resources: ['/x/*'], where: [] }]);
    expect(e.verbs).toEqual(['a', 'b']);
    expect(e.resources).toEqual(['/x/*']);
    expect(e.tools).toEqual(['t']);
    const e2 = describeEnvelope(chainOf(root, [allow({ verb: '*' })]));
    expect(e2.scopes).toEqual([{ verbs: ['*'], resources: ['*'], where: [] }]);
  });
  it('hasEnvelope true for an envelope root; caveats echoes the leaf caveats as signed', () => {
    const root = grant([{ verb: 'read' }]);
    const c = chainOf(root, [{ type: 'rate', max: 1, per_secs: 1 }]);
    const e = describeEnvelope(c);
    expect(e.hasEnvelope).toBe(true);
    expect(e.ok).toBe(true);
    expect(e.caveats).toEqual(c[1]!.caveats);
    expect(e.caveats).toHaveLength(2);
  });
  it('envelope-root scopes: sorted/deduped verbs, default resource "*", where carried', () => {
    const w = [{ field: 'action.params.n', op: 'lte', value: 1 }];
    const e = describeEnvelope([grant([{ verb: ['write', 'read', 'read'] }, { verb: 'x', resource: '/r', where: w }])]);
    expect(e.scopes).toHaveLength(2);
    expect(e.scopes).toEqual(expect.arrayContaining([{ verbs: ['read', 'write'], resources: ['*'], where: [] }, { verbs: ['x'], resources: ['/r'], where: w }]));
    expect(e.verbs).toEqual(['read', 'write', 'x']);
    expect(e.resources).toEqual(['*', '/r']);
  });
  it('empty predicate list => no scopes, nothing permitted', () => {
    const e = describeEnvelope([grant([])]);
    expect(e.scopes).toEqual([]);
    expect(e.verbs).toEqual([]);
    expect(e.resources).toEqual([]);
    expect(envelopePermits(e, 'a', 'b')).toBe(false);
  });
  it('scope ordering is a true total order even for interleaved sorted runs (exercises merge/gallop)', () => {
    const mkp = (i: number) => ({ verb: `v${i}`, resource: '/r' });
    const hashOf = (i: number) => hashCanonical({ verbs: [`v${i}`], resources: ['/r'], where: [] });
    const order = Array.from({ length: 300 }, (_, i) => i).sort((a, b) => (hashOf(a) < hashOf(b) ? -1 : hashOf(a) > hashOf(b) ? 1 : 0));
    const blk = (a: number, b: number) => order.slice(a, b);
    const input = [...blk(0, 75), ...blk(150, 225), ...blk(75, 150), ...blk(225, 300)];
    const e = describeEnvelope([grant(input.map(mkp))]);
    expect(e.scopes!.map((s) => s.verbs[0])).toEqual(order.map((i) => `v${i}`));
    const e2 = describeEnvelope([grant([...blk(0, 150), ...blk(150, 300)].map(mkp))]);
    expect(e2.scopes).toEqual(e.scopes);
    const e3 = describeEnvelope([grant([...blk(150, 300), ...blk(0, 150)].map(mkp))]);
    expect(e3.scopes).toEqual(e.scopes);
  });
  it('scopes are deduplicated and ordered by content hash regardless of predicate order', () => {
    const preds = Array.from({ length: 40 }, (_, i) => ({ verb: [`v${i}`, 'z'], resource: `/p${i % 7}/*` }));
    const e1 = describeEnvelope([grant(preds)]);
    const e2 = describeEnvelope([grant([...preds].reverse())]);
    const e3 = describeEnvelope([grant([...preds, ...preds.slice(0, 10)])]);
    expect(e1.scopes).toHaveLength(40);
    expect(e2.scopes).toEqual(e1.scopes);
    expect(e3.scopes).toEqual(e1.scopes);
    const hs = e1.scopes!.map((s) => hashCanonical(s));
    expect(hs).toEqual([...hs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)));
  });
});

describe('describeEnvelope: unsatisfiable envelope.predicates', () => {
  const bad = (preds: unknown[]) => describeEnvelope([grant(preds)]);
  const expectBad = (e: AuthorityEnvelope, names: string[]) => {
    expect(e.ok).toBe(true);
    expect(e.unsatisfiable).toEqual(names);
    expect(e.reason).toBe(`unsatisfiable caveat(s): ${names.join(', ')}`);
    expect(e.scopes).toEqual([]);
    expect(e.verbs).toEqual([]);
    expect(e.resources).toEqual([]);
    expect(e.tools).toEqual([]);
    expect(envelopePermits(e, 'read', '/x')).toBe(false);
  };
  it('every malformed predicate shape marks the envelope unsatisfiable', () => {
    for (const p of [null, 5, 'x', { verb: 5 }, { verb: ['a', 5] }, { verb: { x: 1 } }, {}, { verb: 'a', resource: 5 }, { verb: 'a', where: 'x' }, { verb: 'a', where: {} }]) {
      expectBad(bad([p]), ['envelope.predicates']);
    }
  });
  it('one bad predicate poisons valid siblings (some, not every)', () => {
    expectBad(bad([{ verb: 'a' }, 5]), ['envelope.predicates']);
    expectBad(bad([5, { verb: 'a' }]), ['envelope.predicates']);
    expectBad(bad([null, { verb: 'a' }]), ['envelope.predicates']);
  });
  it('a valid predicate with only optional fields is fine', () => {
    expect(bad([{ verb: 'a', resource: '/x', where: [] }]).unsatisfiable).toEqual([]);
  });
});

describe('describeEnvelope: verb / resource / where intersection across hops', () => {
  const sc = (rootVerb: unknown, childVerb: unknown, rootRes = '*', childRes = '*') =>
    desc([{ verb: rootVerb, resource: rootRes }], [allow({ verb: childVerb, resource: childRes })]).scopes;
  it('verbs', () => {
    expect(sc('*', ['b', 'a', 'b'])).toEqual([{ verbs: ['a', 'b'], resources: ['*'], where: [] }]);
    expect(sc(['b', 'a'], '*')).toEqual([{ verbs: ['a', 'b'], resources: ['*'], where: [] }]);
    expect(sc(['read', 'write', 'read'], ['write', 'read', 'delete'])).toEqual([{ verbs: ['read', 'write'], resources: ['*'], where: [] }]);
    expect(sc(['b', 'a', 'c'], ['c', 'a'])).toEqual([{ verbs: ['a', 'c'], resources: ['*'], where: [] }]);
    expect(sc('read', 'write')).toEqual([]);
    expect(sc('*', '*')).toEqual([{ verbs: ['*'], resources: ['*'], where: [] }]);
    expect(sc('*', 'x')).toEqual([{ verbs: ['x'], resources: ['*'], where: [] }]);
    expect(sc('x', '*')).toEqual([{ verbs: ['x'], resources: ['*'], where: [] }]);
  });
  const res = (r: string, c: string) => sc('*', '*', r, c);
  const one = (resources: string[]) => [{ verbs: ['*'], resources, where: [] }];
  it('literal / prefix / wildcard resource intersection', () => {
    expect(res('/a/*', '/a/b/*')).toEqual(one(['/a/b/*']));
    expect(res('/a/b/*', '/a/*')).toEqual(one(['/a/b/*']));
    expect(res('ab*', 'a*')).toEqual(one(['ab*']));
    expect(res('a*', 'ab*')).toEqual(one(['ab*']));
    expect(res('/a/*', '/b/*')).toEqual([]);
    expect(res('/a/*', '/a/x')).toEqual(one(['/a/x']));
    expect(res('/a/x', '/a/*')).toEqual(one(['/a/x']));
    expect(res('/a/*', '/b/x')).toEqual([]);
    expect(res('/b/x', '/a/*')).toEqual([]);
    expect(res('/a/x', '/a/y')).toEqual([]);
    expect(res('/a/x', '/a/x')).toEqual(one(['/a/x']));
    expect(res('/a/*', '/a/*')).toEqual(one(['/a/*']));
    expect(res('*', '/a/*')).toEqual(one(['/a/*']));
    expect(res('/a/*', '*')).toEqual(one(['/a/*']));
    expect(res('*', '/a/x')).toEqual(one(['/a/x']));
    expect(res('/a/x', '*')).toEqual(one(['/a/x']));
    expect(res('*', '*')).toEqual(one(['*']));
  });
  it('regex resource patterns are carried (sorted) next to the literal, never intersected', () => {
    expect(res('re:/a/[0-9]+', '/a/*')).toEqual(one(['/a/*', 're:/a/[0-9]+']));
    expect(res('/a/x', 're:/a/.*')).toEqual(one(['/a/x', 're:/a/.*']));
    expect(res('*', 're:/a/.*')).toEqual(one(['re:/a/.*']));
    expect(res('re:b', 're:a')).toEqual(one(['re:a', 're:b']));
    expect(res('re:a', 're:a')).toEqual(one(['re:a']));
    const e = desc([{ verb: '*', resource: 're:/a/.*' }], [allow({ verb: '*', resource: '/a/x' })]);
    expect(e.opaqueResourceConstraints).toEqual(['re:/a/.*']);
    expect(e.resources).toEqual(['/a/x', 're:/a/.*']);
  });
  it('literals across three hops keep narrowing', () => {
    const e = describeEnvelope(chainOf(grant([{ verb: '*', resource: '/a/*' }]), [allow({ verb: '*', resource: '/a/b/*' })], [allow({ verb: '*', resource: '/a/b/c' })]));
    expect(e.scopes).toEqual([{ verbs: ['*'], resources: ['/a/b/c'], where: [] }]);
    const gone = describeEnvelope(chainOf(grant([{ verb: '*', resource: '/a/*' }]), [allow({ verb: '*', resource: '/a/b/*' })], [allow({ verb: '*', resource: '/z' })]));
    expect(gone.scopes).toEqual([]);
  });
  it('where conditions concatenate (root first), and cross-product scopes are produced', () => {
    const c1 = { field: 'action.params.a', op: 'lte', value: 1 };
    const c2 = { field: 'action.params.b', op: 'lte', value: 2 };
    const e = desc([{ verb: 'pay', resource: '/x/*', where: [c1] }], [allow({ verb: 'pay', resource: '/x/1', where: [c2] })]);
    expect(e.scopes).toEqual([{ verbs: ['pay'], resources: ['/x/1'], where: [c1, c2] }]);
    const multi = desc([{ verb: 'a' }, { verb: 'b' }], [allow({ verb: 'a' }, { verb: 'b' }, { verb: 'c' })]);
    expect(multi.scopes).toHaveLength(2);
    expect(multi.verbs).toEqual(['a', 'b']);
  });
  it('an empty `allow` list permits nothing', () => {
    const e = desc([{ verb: '*' }], [allow()]);
    expect(e.ok).toBe(true);
    expect(e.unsatisfiable).toEqual([]);
    expect(e.scopes).toEqual([]);
  });
});

describe('describeEnvelope: caveat well-formedness => unsatisfiable', () => {
  const run = (...caveats: Caveat[]) => desc([{ verb: '*' }], caveats);
  const unsat = (...caveats: Caveat[]) => run(...caveats).unsatisfiable;
  it('time caveats need a finite `at`', () => {
    for (const type of ['expires', 'not_before']) {
      expect(unsat({ type, at: 'soon' })).toEqual([type]);
      expect(unsat({ type })).toEqual([type]);
      expect(unsat({ type, at: null })).toEqual([type]);
      expect(unsat({ type, at: 100 })).toEqual([]);
      expect(unsat({ type, at: 0 })).toEqual([]);
    }
  });
  it('rate needs finite max and finite per_secs > 0', () => {
    expect(unsat({ type: 'rate', max: 5, per_secs: 60 })).toEqual([]);
    expect(unsat({ type: 'rate', max: 'x', per_secs: 60 })).toEqual(['rate']);
    expect(unsat({ type: 'rate', max: 5, per_secs: 'x' })).toEqual(['rate']);
    expect(unsat({ type: 'rate', max: 5, per_secs: 0 })).toEqual(['rate']);
    expect(unsat({ type: 'rate', max: 5, per_secs: -1 })).toEqual(['rate']);
    expect(unsat({ type: 'rate', per_secs: 60 })).toEqual(['rate']);
    expect(unsat({ type: 'rate', max: 5 })).toEqual(['rate']);
    expect(unsat({ type: 'rate', max: 0, per_secs: 1 })).toEqual([]);
  });
  it('max_blast_radius / delegation_depth need a finite max', () => {
    for (const type of ['max_blast_radius', 'delegation_depth']) {
      expect(unsat({ type, max: 'x' })).toEqual([type]);
      expect(unsat({ type })).toEqual([type]);
      expect(unsat({ type, max: 0 })).toEqual([]);
    }
  });
  it('reversibility_max needs a known class', () => {
    for (const c of ['reversible', 'rate_limited', 'irreversible']) expect(unsat({ type: 'reversibility_max', class: c })).toEqual([]);
    expect(unsat({ type: 'reversibility_max', class: 'bogus' })).toEqual(['reversibility_max']);
    expect(unsat({ type: 'reversibility_max' })).toEqual(['reversibility_max']);
  });
  it('predicates needs an allow array of well-formed predicates (all of them)', () => {
    expect(unsat({ type: 'predicates', allow: [{ verb: 'a' }] })).toEqual([]);
    expect(unsat({ type: 'predicates', allow: [] })).toEqual([]);
    expect(unsat({ type: 'predicates' })).toEqual(['predicates']);
    expect(unsat({ type: 'predicates', allow: 'x' })).toEqual(['predicates']);
    expect(unsat({ type: 'predicates', allow: { length: 0 } })).toEqual(['predicates']);
    expect(unsat({ type: 'predicates', allow: [5] })).toEqual(['predicates']);
    expect(unsat({ type: 'predicates', allow: [{ verb: 'a' }, 5] })).toEqual(['predicates']);
    expect(unsat({ type: 'predicates', allow: [5, { verb: 'a' }] })).toEqual(['predicates']);
  });
  it('tool_schema needs a non-empty tool', () => {
    expect(unsat({ type: 'tool_schema', tool: '' })).toEqual(['tool_schema']);
    expect(unsat({ type: 'tool_schema' })).toEqual(['tool_schema']);
    expect(unsat({ type: 'tool_schema', tool: 5 })).toEqual(['tool_schema']);
  });
  it('unknown types, duplicate envelope caveats; several are sorted and joined', () => {
    expect(unsat({ type: 'verbs', allow: ['read'] })).toEqual(['verbs']);
    expect(unsat({ type: 'envelope', predicates: [], caveats: [] })).toEqual(['envelope']);
    const e = run({ type: 'zeta' }, { type: 'alpha' }, { type: 'zeta' }, { type: 'expires', at: 'x' });
    expect(e.unsatisfiable).toEqual(['alpha', 'expires', 'zeta']);
    expect(e.reason).toBe('unsatisfiable caveat(s): alpha, expires, zeta');
    expect(e.scopes).toEqual([]);
    expect(e.tools).toEqual([]);
  });
  it('budget_alloc: well-formed when finite and >= 0 (0 included); not unsatisfiable', () => {
    expect(unsat({ type: 'budget_alloc', limit: 0 })).toEqual([]);
    expect(unsat({ type: 'budget_alloc', limit: 5 })).toEqual([]);
  });
  it('malformed entries inside the signed envelope are reported (type absent / non-string / non-object)', () => {
    const e = (cav: unknown) => describeEnvelope([grant([{ verb: '*' }], [cav])]);
    for (const c of [5, null, {}, { type: 5 }, 'x', []]) {
      expect(e(c).unsatisfiable).toEqual(['<malformed>']);
      expect(e(c).scopes).toEqual([]);
    }
    expect(e({ type: 'rate', max: 1, per_secs: 1 }).unsatisfiable).toEqual([]);
  });
  it('budget_alloc inside the envelope: negative / non-numeric limits are unsatisfiable', () => {
    const e = (limit: unknown) => describeEnvelope([grant([{ verb: '*' }], [{ type: 'budget_alloc', limit }])]);
    expect(e(-1).unsatisfiable).toEqual(['budget_alloc']);
    expect(e('x').unsatisfiable).toEqual(['budget_alloc']);
    expect(e(null).unsatisfiable).toEqual(['budget_alloc']);
    expect(e(0).unsatisfiable).toEqual([]);
    expect(e(0).remainingBudgetHints.budgetAlloc).toBe(0);
    expect(e(7).remainingBudgetHints.budgetAlloc).toBe(7);
  });
  it('an `envelope` caveat nested inside the envelope, or a second one at the leaf, is unsatisfiable', () => {
    expect(describeEnvelope([grant([{ verb: '*' }], [{ type: 'envelope', predicates: [], caveats: [] }])]).unsatisfiable).toEqual(['envelope']);
    expect(describeEnvelope([grant([{ verb: '*' }], [{ type: 'rate', max: 1, per_secs: 1 }])]).unsatisfiable).toEqual([]);
  });
});

describe('describeEnvelope: remaining-budget hints', () => {
  const run = (envCaveats: Caveat[], hops: Caveat[][], now?: number) => describeEnvelope(chainOf(mintGrantWith(envCaveats), ...hops), now);
  const mintGrantWith = (envCaveats: Caveat[]) => grant([{ verb: '*' }], envCaveats);
  it('expires: minimum wins in either order, expiresIn only with a finite now', () => {
    expect(run([], [[{ type: 'expires', at: 200 }, { type: 'expires', at: 100 }]]).remainingBudgetHints).toEqual({ expiresAt: 100 });
    expect(run([], [[{ type: 'expires', at: 100 }, { type: 'expires', at: 200 }]]).remainingBudgetHints).toEqual({ expiresAt: 100 });
    expect(run([], [[{ type: 'expires', at: 100 }]], 40).remainingBudgetHints).toEqual({ expiresAt: 100, expiresIn: 60 });
    expect(run([], [[{ type: 'expires', at: 100 }]], 140).remainingBudgetHints.expiresIn).toBe(-40);
    expect('expiresIn' in run([], [[{ type: 'expires', at: 100 }]]).remainingBudgetHints).toBe(false);
    expect('expiresIn' in run([], [[{ type: 'expires', at: 100 }]], NaN).remainingBudgetHints).toBe(false);
    expect('expiresIn' in run([], [[{ type: 'expires', at: 100 }]], Infinity).remainingBudgetHints).toBe(false);
    expect(run([], [[{ type: 'rate', max: 1, per_secs: 1 }]], 40).remainingBudgetHints).not.toHaveProperty('expiresIn');
    expect(run([], [[{ type: 'rate', max: 1, per_secs: 1 }]], 40).remainingBudgetHints).not.toHaveProperty('expiresAt');
    expect(run([{ type: 'expires', at: 90 }], [[{ type: 'expires', at: 100 }]], 40).remainingBudgetHints).toEqual({ expiresAt: 90, expiresIn: 50 });
  });
  it('not_before: maximum wins in either order', () => {
    expect(run([], [[{ type: 'not_before', at: 100 }, { type: 'not_before', at: 50 }]]).remainingBudgetHints).toEqual({ notBefore: 100 });
    expect(run([], [[{ type: 'not_before', at: 50 }, { type: 'not_before', at: 100 }]]).remainingBudgetHints).toEqual({ notBefore: 100 });
    expect(run([], [[{ type: 'not_before', at: 50 }]]).remainingBudgetHints).toEqual({ notBefore: 50 });
  });
  it('max_blast_radius: minimum wins in either order', () => {
    expect(run([], [[{ type: 'max_blast_radius', max: 0.5 }, { type: 'max_blast_radius', max: 0.2 }]]).remainingBudgetHints).toEqual({ maxBlastRadius: 0.2 });
    expect(run([], [[{ type: 'max_blast_radius', max: 0.2 }, { type: 'max_blast_radius', max: 0.5 }]]).remainingBudgetHints).toEqual({ maxBlastRadius: 0.2 });
    expect(run([], [[{ type: 'max_blast_radius', max: 0 }]]).remainingBudgetHints).toEqual({ maxBlastRadius: 0 });
  });
  it('rate: the lowest sustained rate binds; ties go to the smaller max; stable otherwise', () => {
    const r = (...rs: [number, number][]) => run([], [rs.map(([max, per_secs]) => ({ type: 'rate', max, per_secs }))]).remainingBudgetHints.maxRate;
    expect(r([10, 5])).toEqual({ max: 10, per_secs: 5 });
    expect(r([10, 5], [1, 1])).toEqual({ max: 1, per_secs: 1 }); // 2/s then 1/s
    expect(r([1, 1], [10, 5])).toEqual({ max: 1, per_secs: 1 }); // 1/s then 2/s: stays
    expect(r([10, 10], [5, 5])).toEqual({ max: 5, per_secs: 5 }); // tie, smaller max
    expect(r([5, 5], [10, 10])).toEqual({ max: 5, per_secs: 5 }); // tie, larger max: stays
    expect(r([5, 5], [5, 5])).toEqual({ max: 5, per_secs: 5 });
    expect(r([10, 1], [2, 0.1])).toEqual({ max: 10, per_secs: 1 }); // 10/s then 20/s with a smaller max: stays
    expect(r([2, 0.1], [10, 1])).toEqual({ max: 10, per_secs: 1 }); // 20/s then 10/s: lower sustained rate wins
    expect(r([6, 3], [1, 4])).toEqual({ max: 1, per_secs: 4 }); // 2/s vs 0.25/s
    expect(r([1, 4], [6, 3])).toEqual({ max: 1, per_secs: 4 });
    expect(r([2, 4], [3, 6])).toEqual({ max: 2, per_secs: 4 }); // 0.5 tie: smaller max wins, also first
    expect(r([3, 6], [2, 4])).toEqual({ max: 2, per_secs: 4 });
    expect(r([100, 10], [30, 3])).toEqual({ max: 30, per_secs: 3 }); // 10/s tie, smaller max
    expect(r([100, 10], [30, 3], [2, 1])).toEqual({ max: 2, per_secs: 1 });
  });
  it('reversibility_max: the most restrictive (lowest) class wins in either order', () => {
    const r = (...cs: string[]) => run([], [cs.map((c) => ({ type: 'reversibility_max', class: c }))]).remainingBudgetHints.reversibilityMax;
    expect(r('irreversible')).toBe('irreversible');
    expect(r('irreversible', 'rate_limited')).toBe('rate_limited');
    expect(r('rate_limited', 'irreversible')).toBe('rate_limited');
    expect(r('rate_limited', 'reversible')).toBe('reversible');
    expect(r('reversible', 'rate_limited')).toBe('reversible');
    expect(r('reversible', 'reversible')).toBe('reversible');
    expect(r('rate_limited', 'rate_limited')).toBe('rate_limited');
    expect(r('irreversible', 'irreversible')).toBe('irreversible');
  });
  it('delegation_depth: remaining = max - (hops); minimum wins in either order', () => {
    const d = (hops: Caveat[][]) => run([], hops).remainingBudgetHints.delegationDepthRemaining;
    expect(d([[{ type: 'delegation_depth', max: 3 }]])).toBe(2); // chain length 2
    expect(d([[{ type: 'delegation_depth', max: 3 }], []])).toBe(1); // chain length 3
    expect(d([[{ type: 'delegation_depth', max: 5 }, { type: 'delegation_depth', max: 2 }]])).toBe(1);
    expect(d([[{ type: 'delegation_depth', max: 2 }, { type: 'delegation_depth', max: 5 }]])).toBe(1);
    expect(d([[{ type: 'delegation_depth', max: 0 }]])).toBe(-1);
    expect(run([{ type: 'delegation_depth', max: 3 }], []).remainingBudgetHints.delegationDepthRemaining).toBe(3); // root only
  });
  it('budget_alloc: the tightest (minimum) carried allocation', () => {
    const b = (...limits: number[]) => run([], limits.map((limit) => [{ type: 'budget_alloc', limit }])).remainingBudgetHints.budgetAlloc;
    expect(b(10)).toBe(10);
    expect(b(10, 4)).toBe(4);
    expect(b(10, 4, 4, 1)).toBe(1);
    expect(b()).toBeUndefined();
    // inside the signed envelope nothing enforces monotonicity, so the fold itself must take the minimum
    expect(run([{ type: 'budget_alloc', limit: 3 }, { type: 'budget_alloc', limit: 5 }], []).remainingBudgetHints.budgetAlloc).toBe(3);
    expect(run([{ type: 'budget_alloc', limit: 5 }, { type: 'budget_alloc', limit: 3 }], [[{ type: 'budget_alloc', limit: 3 }]]).remainingBudgetHints.budgetAlloc).toBe(3);
  });
  it('envelope-internal caveats are folded too', () => {
    const e = run([{ type: 'expires', at: 500 }, { type: 'max_blast_radius', max: 0.9 }], [[{ type: 'max_blast_radius', max: 0.3 }]], 100);
    expect(e.remainingBudgetHints).toEqual({ expiresAt: 500, expiresIn: 400, maxBlastRadius: 0.3 });
  });
});

describe('describeEnvelope: tool_schema caveats', () => {
  const tc = (name: string) => toolSchemaCaveat(name, { props: { a: { type: 'boolean' } } });
  const inconsistent = (patch: Record<string, unknown>): Caveat => ({ ...tc('t'), ...patch });
  const run = (...cavs: Caveat[]) => desc([{ verb: '*' }], cavs);
  it('tools are the intersection over all consistent tool_schema caveats; every caveat is listed', () => {
    const one = run(tc('t'));
    expect(one.tools).toEqual(['t']);
    expect(one.toolSchemas).toHaveLength(1);
    expect(one.toolSchemas[0]).toEqual(tc('t'));
    expect(one.unsatisfiable).toEqual([]);
    expect(run(tc('t'), tc('t')).tools).toEqual(['t']);
    expect(run(tc('t'), tc('t')).toolSchemas).toHaveLength(2);
    expect(run(tc('t'), tc('u')).tools).toEqual([]);
    expect(run(tc('u'), tc('t')).tools).toEqual([]);
    expect(run(tc('t'), tc('u'), tc('t')).tools).toEqual([]);
    expect(run().tools).toBeNull();
  });
  it('each kind of self-inconsistency empties the tools and is unsatisfiable (and is still listed)', () => {
    const sig = hashCanonical('t');
    const badSchema = { props: { a: { type: 'bogus' } } };
    const variants: Caveat[] = [
      inconsistent({ schema_digest: 'x' }), // digest mismatch alone
      inconsistent({ binding_digest: 'x' }), // binding mismatch alone
      inconsistent({ signature_digest: 'x' }), // binding no longer matches
      {
        ...tc('t'),
        schema: badSchema,
        schema_digest: hashCanonical(badSchema),
        binding_digest: hashCanonical({ tool: 't', signature_digest: sig, schema: badSchema }),
      } as Caveat, // only the schema is invalid; both digests agree with it
    ];
    for (const v of variants) {
      const e = run(v);
      expect(e.tools).toEqual([]);
      expect(e.unsatisfiable).toEqual(['tool_schema']);
      expect(e.toolSchemas).toHaveLength(1);
      expect(e.reason).toBe('unsatisfiable caveat(s): tool_schema');
      expect(e.scopes).toEqual([]);
    }
    expect(run(inconsistent({ schema_digest: 'x' }), tc('t')).tools).toEqual([]);
    expect(run(tc('t'), inconsistent({ binding_digest: 'x' })).tools).toEqual([]);
  });
});

describe('describeEnvelope: output ordering', () => {
  it('verbs / resources / tools / opaque are sorted unions', () => {
    const e = desc([{ verb: ['zz', 'aa'], resource: '/z' }, { verb: 'mm', resource: 're:/b' }, { verb: 'aa', resource: 're:/a' }, { verb: 'bb', resource: '/a' }], [
      toolSchemaCaveat('t', { props: {} }),
    ]);
    expect(e.verbs).toEqual(['aa', 'bb', 'mm', 'zz']);
    expect(e.resources).toEqual(['/a', '/z', 're:/a', 're:/b']);
    expect(e.opaqueResourceConstraints).toEqual(['re:/a', 're:/b']);
    expect(e.tools).toEqual(['t']);
  });
});

// =============================================================================================
describe('envelopePermits', () => {
  const scope = (o: Record<string, unknown> = {}) => ({ verbs: ['read'], resources: ['/a/*'], where: [], ...o });
  it('requires a usable envelope', () => {
    const sc = [scope()];
    expect(envelopePermits(E({ scopes: sc }), 'read', '/a/x')).toBe(true);
    expect(envelopePermits(E({ scopes: sc, ok: false }), 'read', '/a/x')).toBe(false);
    expect(envelopePermits(E({ scopes: sc, unsatisfiable: ['x'] }), 'read', '/a/x')).toBe(false);
    expect(envelopePermits(E({ scopes: sc, ok: false, unsatisfiable: ['x'] }), 'read', '/a/x')).toBe(false);
    expect(envelopePermits(E({ scopes: sc, ok: false, unsatisfiable: [] }), 'read', '/a/x')).toBe(false);
  });
  it('null scopes = unrestricted; empty = nothing', () => {
    expect(envelopePermits(E({ scopes: null }), 'x', 'y')).toBe(true);
    expect(envelopePermits(E({ scopes: [] }), 'x', 'y')).toBe(false);
  });
  it('verb and resource matching (exact, wildcard verb, prefix, conjunction, regex)', () => {
    const e = (s: unknown) => E({ scopes: [s as never] });
    expect(envelopePermits(e(scope()), 'write', '/a/x')).toBe(false);
    expect(envelopePermits(e(scope()), 'read', '/b/x')).toBe(false);
    expect(envelopePermits(e(scope({ verbs: ['*'] })), 'anything', '/a/x')).toBe(true);
    expect(envelopePermits(e(scope({ verbs: ['read', 'write'] })), 'write', '/a/x')).toBe(true);
    expect(envelopePermits(e(scope({ resources: ['/a/*', '/a/b/*'] })), 'read', '/a/b/x')).toBe(true);
    expect(envelopePermits(e(scope({ resources: ['/a/*', '/a/b/*'] })), 'read', '/a/c')).toBe(false);
    expect(envelopePermits(e(scope({ resources: ['*'] })), 'read', '/anything')).toBe(true);
    expect(envelopePermits(e(scope({ resources: ['/a/*', 're:/a/[0-9]+'] })), 'read', '/a/12')).toBe(true);
    expect(envelopePermits(e(scope({ resources: ['/a/*', 're:/a/[0-9]+'] })), 'read', '/a/xx')).toBe(false);
    expect(envelopePermits(E({ scopes: [scope({ verbs: ['other'] }), scope()] }), 'read', '/a/x')).toBe(true); // any scope suffices
    expect(envelopePermits(E({ scopes: [scope({ verbs: ['other'] }), scope({ resources: ['/z'] })] }), 'read', '/a/x')).toBe(false);
  });
  it('where conditions are evaluated only when params are supplied (fail closed)', () => {
    const w = [{ field: 'action.params.amt', op: 'lte', value: 100 }];
    const e = E({ scopes: [scope({ where: w })] });
    expect(envelopePermits(e, 'read', '/a/x')).toBe(true);
    expect(envelopePermits(e, 'read', '/a/x', undefined, { amt: 50 })).toBe(true);
    expect(envelopePermits(e, 'read', '/a/x', undefined, { amt: 100 })).toBe(true);
    expect(envelopePermits(e, 'read', '/a/x', undefined, { amt: 101 })).toBe(false);
    expect(envelopePermits(e, 'read', '/a/x', undefined, {})).toBe(false);
    expect(envelopePermits(E({ scopes: [scope()] }), 'read', '/a/x', undefined, { anything: 1 })).toBe(true);
  });
  it('delegation depth: negative remaining refuses, zero allows', () => {
    const e = (n: number | undefined) => E({ scopes: null, remainingBudgetHints: n === undefined ? {} : { delegationDepthRemaining: n } });
    expect(envelopePermits(e(-1), 'a', 'b')).toBe(false);
    expect(envelopePermits(e(0), 'a', 'b')).toBe(true);
    expect(envelopePermits(e(3), 'a', 'b')).toBe(true);
    expect(envelopePermits(e(undefined), 'a', 'b')).toBe(true);
  });
  it('time window: expiry is exclusive, not_before inclusive, non-finite now refuses, absent now skips', () => {
    const e = E({ scopes: null, remainingBudgetHints: { expiresAt: 100, notBefore: 50 } });
    expect(envelopePermits(e, 'a', 'b', 49)).toBe(false);
    expect(envelopePermits(e, 'a', 'b', 50)).toBe(true);
    expect(envelopePermits(e, 'a', 'b', 99)).toBe(true);
    expect(envelopePermits(e, 'a', 'b', 100)).toBe(false);
    expect(envelopePermits(e, 'a', 'b', 101)).toBe(false);
    expect(envelopePermits(e, 'a', 'b')).toBe(true);
    expect(envelopePermits(e, 'a', 'b', NaN)).toBe(false);
    expect(envelopePermits(e, 'a', 'b', Infinity)).toBe(false);
    const onlyNb = E({ scopes: null, remainingBudgetHints: { notBefore: 50 } });
    expect(envelopePermits(onlyNb, 'a', 'b', 49)).toBe(false);
    expect(envelopePermits(onlyNb, 'a', 'b', 50)).toBe(true);
    expect(envelopePermits(onlyNb, 'a', 'b', 10_000)).toBe(true);
    const onlyExp = E({ scopes: null, remainingBudgetHints: { expiresAt: 100 } });
    expect(envelopePermits(onlyExp, 'a', 'b', 0)).toBe(true);
    expect(envelopePermits(onlyExp, 'a', 'b', 100)).toBe(false);
    expect(envelopePermits(E({ scopes: null }), 'a', 'b', 12345)).toBe(true);
  });
  it('is total: a throwing envelope yields false', () => {
    expect(envelopePermits(E({ scopes: { some() { throw new Error('x'); } } as never }), 'a', 'b')).toBe(false);
    expect(envelopePermits(null as never, 'a', 'b')).toBe(false);
  });
  it('end to end: matches the hints from a real chain', () => {
    const e = describeEnvelope(
      chainOf(grant([{ verb: ['read', 'write'], resource: '/a/*' }]), [allow({ verb: 'read', resource: '/a/*' }), { type: 'expires', at: 1000 }, { type: 'not_before', at: 100 }]),
      500,
    );
    expect(envelopePermits(e, 'read', '/a/x', 500)).toBe(true);
    expect(envelopePermits(e, 'write', '/a/x', 500)).toBe(false);
    expect(envelopePermits(e, 'read', '/a/x', 99)).toBe(false);
    expect(envelopePermits(e, 'read', '/a/x', 100)).toBe(true);
    expect(envelopePermits(e, 'read', '/a/x', 1000)).toBe(false);
  });
});

describe('envelopePermitsToolCall', () => {
  const sig = { name: 't', params: { a: 'boolean' } };
  const tcA = toolSchemaCaveat(sig, { props: { a: { type: 'boolean' } } });
  const tcB = toolSchemaCaveat(sig, { props: { a: { type: 'boolean', const: true } } });
  const call = (o: Record<string, unknown> = {}) => ({ tool: 't', args: { a: true }, ...o }) as never;
  it('unusable envelopes are refused with the envelope reason, or a fixed one', () => {
    expect(envelopePermitsToolCall(E({ ok: false, reason: 'chain broke' }), call())).toEqual({ ok: false, reason: 'chain broke' });
    expect(envelopePermitsToolCall(E({ ok: false }), call())).toEqual({ ok: false, reason: 'envelope not usable' });
    expect(envelopePermitsToolCall(E({ unsatisfiable: ['x'], reason: 'unsatisfiable caveat(s): x' }), call())).toEqual({ ok: false, reason: 'unsatisfiable caveat(s): x' });
    expect(envelopePermitsToolCall(E({ unsatisfiable: ['x'] }), call())).toEqual({ ok: false, reason: 'envelope not usable' });
    expect(envelopePermitsToolCall(E({ ok: false, unsatisfiable: [] }), call())).toEqual({ ok: false, reason: 'envelope not usable' });
    expect(envelopePermitsToolCall(E({ ok: true, unsatisfiable: ['x'], reason: undefined }), call())).toEqual({ ok: false, reason: 'envelope not usable' });
  });
  it('a tool outside env.tools is refused with the quoted (truncated) name; null tools = unconstrained', () => {
    expect(envelopePermitsToolCall(E({ tools: ['t'] }), call({ tool: 'drop' }))).toEqual({ ok: false, reason: 'tool "drop" not authorized' });
    expect(envelopePermitsToolCall(E({ tools: [] }), call())).toEqual({ ok: false, reason: 'tool "t" not authorized' });
    expect(envelopePermitsToolCall(E({ tools: ['t'] }), call({ tool: 'q'.repeat(60) }))).toEqual({ ok: false, reason: `tool "${'q'.repeat(48)}…" not authorized` });
    expect(envelopePermitsToolCall(E({ tools: ['t'] }), call({ tool: 5 }))).toEqual({ ok: false, reason: 'tool "5" not authorized' });
    expect(envelopePermitsToolCall(E({ tools: ['t'] }), call())).toEqual({ ok: true });
    expect(envelopePermitsToolCall(E({ tools: null }), call({ tool: 'anything' }))).toEqual({ ok: true });
  });
  it('every tool_schema caveat must hold; the first failure is returned as-is', () => {
    const env = E({ tools: ['t'], toolSchemas: [tcA, tcB] });
    expect(envelopePermitsToolCall(env, call())).toEqual({ ok: true });
    expect(envelopePermitsToolCall(env, call({ args: { a: false } }))).toEqual({ ok: false, reason: 'args.a: violates const' });
    expect(envelopePermitsToolCall(env, call({ args: { a: 1 } }))).toEqual({ ok: false, reason: 'args.a: wrong type (expected boolean)' });
    expect(envelopePermitsToolCall(E({ toolSchemas: [tcB, tcA] }), call({ args: { a: false } }))).toEqual({ ok: false, reason: 'args.a: violates const' });
    expect(envelopePermitsToolCall(E({ toolSchemas: [] }), call({ args: { whatever: 1 } }))).toEqual({ ok: true });
  });
  it('is total', () => {
    expect(envelopePermitsToolCall(E({ tools: { includes() { throw new Error('x'); } } as never }), call())).toEqual({ ok: false, reason: 'evaluation error (fail closed)' });
    expect(envelopePermitsToolCall(E({ tools: ['t'] }), null as never)).toEqual({ ok: false, reason: 'evaluation error (fail closed)' });
  });
  it('end to end through describeEnvelope', () => {
    const e = describeEnvelope(chainOf(grant([{ verb: '*' }]), [tcA], [tcB]));
    expect(e.tools).toEqual(['t']);
    expect(envelopePermitsToolCall(e, call())).toEqual({ ok: true });
    expect(envelopePermitsToolCall(e, call({ args: { a: false } })).ok).toBe(false);
    expect(envelopePermitsToolCall(e, call({ tool: 'u' })).ok).toBe(false);
  });
});

// =============================================================================================
describe('grantLease', () => {
  const ok = (o: Record<string, unknown> = {}) => grantLease({ cap_id: 'c', holder: A.pk, now: 1000, ttl_ms: 5000, ...o } as never);
  it('shape: minimal and with optional bounds (absent optionals are absent keys)', () => {
    const l = ok();
    expect(l).toEqual({ cap_id: 'c', holder: A.pk, issued_at: 1000, renewed_at: 1000, ttl_ms: 5000, renewals: 0, last_seq: 0, expires_at: 6000 });
    expect(Object.keys(l).sort()).toEqual(['cap_id', 'expires_at', 'holder', 'issued_at', 'last_seq', 'renewals', 'renewed_at', 'ttl_ms']);
    const h = ok({ hard_expires_at: 4000, max_renewals: 3 });
    expect(h).toEqual({ ...l, hard_expires_at: 4000, max_renewals: 3, expires_at: 4000 });
    expect(ok({ hard_expires_at: 9000 }).expires_at).toBe(6000);
    expect(ok({ max_renewals: 0 }).max_renewals).toBe(0);
    expect('hard_expires_at' in ok({ max_renewals: 1 })).toBe(false);
    expect('max_renewals' in ok({ hard_expires_at: 9000 })).toBe(false);
  });
  it('identifiers must be non-empty strings', () => {
    const m = new TypeError('grantLease: cap_id and holder required');
    for (const bad of ['', undefined, 5, null]) {
      expect(() => ok({ cap_id: bad })).toThrow(m);
      expect(() => ok({ holder: bad })).toThrow(m);
    }
  });
  it('now / ttl_ms: finite, ttl in (0, MAX_LEASE_TTL_MS]', () => {
    const m = new RangeError('grantLease: invalid now/ttl_ms');
    expect(MAX_LEASE_TTL_MS).toBe(7 * 24 * 3_600_000);
    for (const bad of [NaN, Infinity, '1', undefined]) expect(() => ok({ now: bad })).toThrow(m);
    for (const bad of [0, -1, NaN, Infinity, MAX_LEASE_TTL_MS + 1, '5', undefined]) expect(() => ok({ ttl_ms: bad })).toThrow(m);
    expect(ok({ ttl_ms: MAX_LEASE_TTL_MS }).expires_at).toBe(1000 + MAX_LEASE_TTL_MS);
    expect(ok({ ttl_ms: 1 }).expires_at).toBe(1001);
  });
  it('hard_expires_at: finite and strictly in the future', () => {
    const m = new RangeError('grantLease: hard_expires_at must be finite and in the future');
    for (const bad of [NaN, Infinity, 1000, 999, '5000']) expect(() => ok({ hard_expires_at: bad })).toThrow(m);
    expect(ok({ hard_expires_at: 1001 }).expires_at).toBe(1001);
  });
  it('max_renewals: a non-negative integer', () => {
    const m = new RangeError('grantLease: invalid max_renewals');
    for (const bad of [-1, 1.5, NaN, '2', Infinity]) expect(() => ok({ max_renewals: bad })).toThrow(m);
    expect(ok({ max_renewals: 0 }).max_renewals).toBe(0);
  });
});

describe('leaseState', () => {
  const lease = (o: Record<string, unknown> = {}): CapabilityLease => ({ ...grantLease({ cap_id: 'c', holder: A.pk, now: 10_000, ttl_ms: 5000, hard_expires_at: 20_000, max_renewals: 2 }), ...o }) as CapabilityLease;
  const dead = (reason: string) => ({ live: false, expiresIn: 0, reason });
  it('live: exact expiresIn; the lapse boundary is exclusive', () => {
    expect(leaseState(lease(), 10_000)).toEqual({ live: true, expiresIn: 5000 });
    expect(leaseState(lease(), 14_999)).toEqual({ live: true, expiresIn: 1 });
    expect(leaseState(lease(), 15_000)).toEqual(dead('lease lapsed'));
    expect(leaseState(lease(), 99_999)).toEqual(dead('lease lapsed'));
  });
  it('a clock more than the skew before the last renewal is refused', () => {
    expect(leaseState(lease(), 10_000 - HEARTBEAT_SKEW_MS)).toEqual({ live: true, expiresIn: 5000 + HEARTBEAT_SKEW_MS });
    expect(leaseState(lease(), 10_000 - HEARTBEAT_SKEW_MS - 1)).toEqual(dead('clock before last renewal'));
  });
  it('invalid clock', () => {
    for (const bad of [NaN, Infinity, -Infinity, '1', undefined]) expect(leaseState(lease(), bad as never)).toEqual(dead('invalid clock'));
  });
  it('structural malformations, each alone', () => {
    const m = dead('malformed lease');
    expect(leaseState(null as never, 10_000)).toEqual(m);
    expect(leaseState([] as never, 10_000)).toEqual(m);
    class C {}
    expect(leaseState(Object.assign(new C(), lease()) as never, 10_000)).toEqual(m);
    for (const k of ['cap_id', 'holder']) for (const bad of ['', undefined, 5]) expect(leaseState(lease({ [k]: bad }), 10_000)).toEqual(m);
    for (const k of ['issued_at', 'renewed_at', 'ttl_ms', 'expires_at']) for (const bad of [NaN, Infinity, '1', undefined]) expect(leaseState(lease({ [k]: bad }), 10_000)).toEqual(m);
    expect(leaseState(lease({ ttl_ms: 0 }), 10_000)).toEqual(m);
    expect(leaseState(lease({ ttl_ms: -5 }), 10_000)).toEqual(m);
    // ttl rules apply even when the expiry arithmetic alone would not catch them
    expect(leaseState(lease({ ttl_ms: 0, expires_at: 10_000, hard_expires_at: undefined }), 10_000)).toEqual(m);
    expect(leaseState(lease({ ttl_ms: -5, expires_at: 5_000, hard_expires_at: undefined }), 10_000)).toEqual(m);
    expect(leaseState(lease({ ttl_ms: MAX_LEASE_TTL_MS + 1 }), 10_000)).toEqual(m);
    for (const bad of [-1, 1.5, NaN, '1', undefined]) {
      expect(leaseState(lease({ renewals: bad }), 10_000)).toEqual(m);
      expect(leaseState(lease({ last_seq: bad }), 10_000)).toEqual(m);
    }
    for (const bad of [-1, 1.5, NaN, '1']) expect(leaseState(lease({ max_renewals: bad }), 10_000)).toEqual(m);
    for (const bad of [NaN, Infinity, '5']) expect(leaseState(lease({ hard_expires_at: bad }), 10_000)).toEqual(m);
  });
  it('valid edge values', () => {
    expect(leaseState(lease({ renewals: 0, last_seq: 0 }), 10_000).live).toBe(true);
    expect(leaseState(lease({ max_renewals: 0 }), 10_000).live).toBe(true);
    const long = lease({ ttl_ms: MAX_LEASE_TTL_MS, expires_at: 10_000 + MAX_LEASE_TTL_MS, hard_expires_at: undefined });
    expect(leaseState(long, 10_000).live).toBe(true);
    const noHard = { ...lease(), hard_expires_at: undefined };
    expect(leaseState(noHard as never, 10_000)).toEqual({ live: true, expiresIn: 5000 });
  });
  it('hard-expiry invariant: expires_at may equal but not exceed it', () => {
    expect(leaseState(lease({ hard_expires_at: 15_000 }), 10_000).live).toBe(true);
    expect(leaseState(lease({ hard_expires_at: 14_999 }), 10_000)).toEqual(dead('lease exceeds hard expiry'));
  });
  it('a lease can never outlive one ttl past its last renewal', () => {
    expect(leaseState(lease({ expires_at: 15_000, hard_expires_at: undefined }), 10_000).live).toBe(true);
    expect(leaseState(lease({ expires_at: 15_001, hard_expires_at: undefined }), 10_000)).toEqual(dead('malformed lease'));
    expect(leaseState(lease({ expires_at: 15_001 }), 10_000)).toEqual(dead('malformed lease'));
  });
});

describe('signHeartbeat / renewLease', () => {
  const mk = (o: Record<string, unknown> = {}) => grantLease({ cap_id: 'c', holder: A.pk, now: 10_000, ttl_ms: 5000, hard_expires_at: 100_000, max_renewals: 2, ...o } as never);
  const hb = (l: CapabilityLease, seq: number, at: number, sk = A.sk, over: Record<string, unknown> = {}): Heartbeat =>
    ({ ...signHeartbeat({ cap_id: l.cap_id, seq, at, holder: l.holder, lease_issued_at: l.issued_at }, sk), ...over }) as Heartbeat;
  const bad = (reason: string) => ({ ok: false, reason });

  it('signHeartbeat: the documented body, domain-separated, extras dropped', () => {
    const l = mk();
    const h = signHeartbeat({ cap_id: 'c', seq: 3, at: 11_000, holder: A.pk, lease_issued_at: 10_000, extra: 1 } as never, A.sk);
    expect(Object.keys(h).sort()).toEqual(['at', 'cap_id', 'holder', 'lease_issued_at', 'seq', 'sig']);
    const body = { cap_id: 'c', seq: 3, at: 11_000, holder: A.pk, lease_issued_at: 10_000 };
    expect(verifyB64u(A.pk, canonicalBytes({ d: 'atlas-pca/lease-hb/v2', b: body }), h.sig)).toBe(true);
    expect(verifyB64u(A.pk, canonicalBytes({ d: 'other', b: body }), h.sig)).toBe(false);
    expect(l.cap_id).toBe('c');
  });
  it('renews: exact next record', () => {
    const l = mk();
    const r = renewLease(l, hb(l, 1, 12_000), 12_000);
    expect(r).toEqual({
      ok: true,
      lease: { ...l, renewals: 1, last_seq: 1, renewed_at: 12_000, expires_at: 17_000 },
    });
    const r2 = renewLease((r as { lease: CapabilityLease }).lease, hb((r as { lease: CapabilityLease }).lease, 5, 13_000), 13_000);
    expect((r2 as { lease: CapabilityLease }).lease).toMatchObject({ renewals: 2, last_seq: 5, renewed_at: 13_000, expires_at: 18_000 });
    expect(l.renewals).toBe(0); // pure
  });
  it('renews a lease WITHOUT a hard expiry or renewal cap', () => {
    const l = mk({ hard_expires_at: undefined, max_renewals: undefined });
    expect('hard_expires_at' in l).toBe(false);
    const r = renewLease(l, hb(l, 1, 12_000), 12_000);
    expect(r.ok).toBe(true);
    expect((r as { lease: CapabilityLease }).lease.expires_at).toBe(17_000);
    expect('hard_expires_at' in (r as { lease: CapabilityLease }).lease).toBe(false);
  });
  it('never extends past the hard expiry, never shortens, renewed_at never moves backwards', () => {
    const l = mk({ hard_expires_at: 14_000 });
    expect(l.expires_at).toBe(14_000);
    const r = renewLease(l, hb(l, 1, 12_000), 12_000);
    expect((r as { lease: CapabilityLease }).lease.expires_at).toBe(14_000);
    const l2 = mk();
    const early = renewLease(l2, hb(l2, 1, 10_000 - 10_000), 10_000 - 10_000); // clock 10s before renewal (inside skew)
    expect((early as { lease: CapabilityLease }).lease.expires_at).toBe(15_000); // max(exp=10_000-10_000+5000, 15_000)
    expect((early as { lease: CapabilityLease }).lease.renewed_at).toBe(10_000); // max(now, renewed_at)
  });
  it('a lapsed lease is dead for good; other non-live states are prefixed', () => {
    const l = mk();
    expect(renewLease(l, hb(l, 1, 15_000), 15_000)).toEqual(bad('lease lapsed'));
    expect(renewLease({ ...l, cap_id: '' }, hb(l, 1, 12_000), 12_000)).toEqual(bad('lease not live: malformed lease'));
    expect(renewLease(l, hb(l, 1, 12_000), NaN)).toEqual(bad('lease not live: invalid clock'));
    expect(renewLease(l, hb(l, 1, 12_000), 10_000 - HEARTBEAT_SKEW_MS - 1)).toEqual(bad('lease not live: clock before last renewal'));
    expect(renewLease({ ...l, expires_at: 100_000, hard_expires_at: 50_000 }, hb(l, 1, 12_000), 12_000)).toEqual(bad('lease not live: lease exceeds hard expiry'));
  });
  it('heartbeat shape', () => {
    const l = mk();
    const m = bad('malformed heartbeat');
    expect(renewLease(l, null as never, 12_000)).toEqual(m);
    expect(renewLease(l, [] as never, 12_000)).toEqual(m);
    expect(renewLease(l, hb(l, 1, 12_000, A.sk, { extra: 1 }), 12_000)).toEqual(m);
    expect(renewLease(l, hb(l, 1, 12_000, A.sk, { sig: 5 }), 12_000)).toEqual(m);
    const { sig: _s, ...nosig } = hb(l, 1, 12_000);
    void _s;
    expect(renewLease(l, nosig as never, 12_000)).toEqual(m);
    class C {}
    expect(renewLease(l, Object.assign(new C(), hb(l, 1, 12_000)) as never, 12_000)).toEqual(m);
  });
  it('heartbeat must be for this lease (cap_id, holder, grant time — each alone)', () => {
    const l = mk();
    const m = bad('heartbeat not for this lease');
    expect(renewLease(l, hb(l, 1, 12_000, A.sk, { cap_id: 'other' }), 12_000)).toEqual(m);
    expect(renewLease(l, hb(l, 1, 12_000, A.sk, { holder: kp().pk }), 12_000)).toEqual(m);
    expect(renewLease(l, hb(l, 1, 12_000, A.sk, { lease_issued_at: 9_999 }), 12_000)).toEqual(m);
    expect(renewLease(l, hb(l, 1, 12_000), 12_000).ok).toBe(true);
  });
  it('sequence numbers: safe integers strictly above last_seq', () => {
    const l = mk({});
    const stale = bad('stale or replayed heartbeat');
    const l5 = { ...l, last_seq: 5 };
    expect(renewLease(l5, hb(l5, 5, 12_000), 12_000)).toEqual(stale);
    expect(renewLease(l5, hb(l5, 4, 12_000), 12_000)).toEqual(stale);
    expect(renewLease(l5, hb(l5, 6, 12_000), 12_000).ok).toBe(true);
    expect(renewLease(l, hb(l, 0, 12_000), 12_000)).toEqual(stale);
    expect(renewLease(l, hb(l, 1.5, 12_000), 12_000)).toEqual(stale);
    expect(renewLease(l, hb(l, 1, 12_000, A.sk, { seq: 2 ** 53 }), 12_000)).toEqual(stale);
    expect(renewLease(l, hb(l, Number.MAX_SAFE_INTEGER, 12_000), 12_000).ok).toBe(true);
    expect(renewLease(l, hb(l, '2' as never, 12_000, A.sk), 12_000)).toEqual(stale);
  });
  it('freshness: |at - now| <= skew, finite', () => {
    const l = mk();
    const m = bad('heartbeat outside skew window');
    expect(renewLease(l, hb(l, 1, 12_000 + HEARTBEAT_SKEW_MS), 12_000).ok).toBe(true);
    expect(renewLease(l, hb(l, 1, 12_000 - HEARTBEAT_SKEW_MS), 12_000).ok).toBe(true);
    expect(renewLease(l, hb(l, 1, 12_000 + HEARTBEAT_SKEW_MS + 1), 12_000)).toEqual(m);
    expect(renewLease(l, hb(l, 1, 12_000 - HEARTBEAT_SKEW_MS - 1), 12_000)).toEqual(m);
    expect(renewLease(l, hb(l, 1, 12_000, A.sk, { at: 'x' }), 12_000)).toEqual(m);
  });
  it('signature: must be the lease holder over exactly this body', () => {
    const l = mk();
    const m = bad('bad heartbeat signature');
    expect(renewLease(l, hb(l, 1, 12_000, kp().sk), 12_000)).toEqual(m);
    expect(renewLease(l, hb(l, 1, 12_000, A.sk, { at: 12_001 }), 12_000)).toEqual(m);
    const old = hb(l, 1, 12_000);
    expect(renewLease(l, { ...old, seq: 2 }, 12_000)).toEqual(m);
    const wrongDomain = { ...old, sig: b64u(sign(A.sk, canonicalBytes({ d: 'x', b: { cap_id: l.cap_id, seq: 1, at: 12_000, holder: l.holder, lease_issued_at: l.issued_at } }))) };
    expect(renewLease(l, wrongDomain, 12_000)).toEqual(m);
  });
  it('renewal budget: renewals >= max_renewals is exhausted', () => {
    const l = mk({ max_renewals: 2 });
    expect(renewLease({ ...l, renewals: 1 }, hb(l, 1, 12_000), 12_000).ok).toBe(true);
    expect(renewLease({ ...l, renewals: 2 }, hb(l, 1, 12_000), 12_000)).toEqual(bad('renewal budget exhausted'));
    expect(renewLease({ ...l, renewals: 3 }, hb(l, 1, 12_000), 12_000)).toEqual(bad('renewal budget exhausted'));
    const zero = mk({ max_renewals: 0 });
    expect(renewLease(zero, hb(zero, 1, 12_000), 12_000)).toEqual(bad('renewal budget exhausted'));
  });
  it('is total: a throwing accessor yields the malformed-heartbeat reason', () => {
    const l = mk();
    const h = throwingProp(hb(l, 1, 12_000), 'sig');
    expect(renewLease(l, h, 12_000)).toEqual(bad('malformed heartbeat'));
    expect(renewLease(l, throwingProp(hb(l, 1, 12_000), 'seq', 'str'), 12_000)).toEqual(bad('malformed heartbeat'));
  });
});

function throwingProp<T extends object>(o: T, key: string, thrown: unknown = new Error('getter')): T {
  return Object.defineProperty({ ...o }, key, { enumerable: true, get() { throw thrown; } });
}
