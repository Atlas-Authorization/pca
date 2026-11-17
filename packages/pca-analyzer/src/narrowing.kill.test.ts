import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, hashCanonical, sha256, sign, utf8 } from '@atlasauth/pca';
import { DEFAULT_CATALOG, extendCatalog } from '@atlasauth/pca/ext/research';
import { ACCESS_REQUEST_SIG_DOMAIN, signAccessRequest, suggestNarrowing, verifyAccessRequest, type AccessRequest, type ObservedAction, type PolicyInput } from './index';
import { toModel } from './enumerate';
import { policyDigestOf } from './residual';

type Spec = Parameters<typeof extendCatalog>[1][number];
const spec = (action: string, reversibility: Spec['reversibility'], blastRadius: number, connector = 'kt'): Spec => ({ connector, action, verb: `${connector}.${action}`, reversibility, blastRadius, description: 'd' });
// ranks: blastRadius x (1 reversible, 2 rate_limited, 3 irreversible)
const catalog = extendCatalog(DEFAULT_CATALOG, [spec('read', 'reversible', 2), spec('limited', 'rate_limited', 2), spec('final', 'irreversible', 2), spec('any', 'rate_limited', 5, 'unknown')]);

const led = (verb: string, resource: string, params?: Record<string, unknown>, extra: Partial<ObservedAction> = {}): ObservedAction => ({ verb, resource, ...(params ? { params } : {}), source: 'ledger', ...extra });
const predicatesOf = (r: ReturnType<typeof suggestNarrowing>): Array<Record<string, unknown>> => (r.proposal as { predicates: Array<Record<string, unknown>> }).predicates;
const field = (name: string, op: string, value: unknown) => ({ field: `action.params.${name}`, op, value }) as never;
const amounts = (xs: unknown[], verb = 'v', extra: (i: number) => Record<string, unknown> = () => ({})): ObservedAction[] => xs.map((a, i) => led(verb, `/r/${i}`, { amount: a, ...extra(i) }));

describe('suggestNarrowing findings (exact)', () => {
  it('reports unused predicates and verbs with exact details, ranks and order', () => {
    const policy: PolicyInput = {
      predicates: [
        { verb: 'kt.final', resource: '/r/*' },
        { verb: ['kt.read', 'kt.limited'], resource: '/r/*' },
        { verb: '*', resource: '/never/*' },
        { verb: ['kt.read', '*'], resource: '/r/*' },
        { verb: ['kt.final', 'kt.limited'], resource: '/never/*' },
      ],
    };
    const r = suggestNarrowing(policy, [led('kt.read', '/r/1'), led('kt.read', '/r/2'), led('kt.read', '/other/1')], { catalog });
    expect(r.findings).toEqual([
      { kind: 'unused-predicate', predicate: 2, verb: '*', detail: 'no observed action used predicate 2 (*)', blastRadius: 5, reversibility: 'rate_limited', rank: 10 },
      { kind: 'unused-predicate', predicate: 0, verb: 'kt.final', detail: 'no observed action used predicate 0 (kt.final)', blastRadius: 2, reversibility: 'irreversible', rank: 6 },
      { kind: 'unused-predicate', predicate: 4, verb: 'kt.final', detail: 'no observed action used predicate 4 (kt.final, kt.limited)', blastRadius: 2, reversibility: 'irreversible', rank: 6 },
      { kind: 'unused-verb', predicate: 1, verb: 'kt.limited', detail: 'verb kt.limited is granted by predicate 1 but never used', blastRadius: 2, reversibility: 'rate_limited', rank: 4 },
    ]);
  });

  it('a verb used only by an observation that the predicate does not admit is still unused; verbs used by different observations are all used', () => {
    const policy: PolicyInput = { predicates: [{ verb: ['kt.read', 'kt.limited'], resource: '/r/*' }] };
    const used = suggestNarrowing(policy, [led('kt.read', '/r/1'), led('kt.limited', '/r/2'), led('kt.limited', '/elsewhere')], { catalog });
    expect(used.findings).toEqual([]);
    const outside = suggestNarrowing(policy, [led('kt.read', '/r/1'), led('kt.limited', '/elsewhere')], { catalog });
    expect(outside.findings.map((f) => [f.kind, f.verb])).toEqual([['unused-verb', 'kt.limited']]);
  });

  it('a predicate without a usable verb reads as the wildcard in its finding', () => {
    const policy = { predicates: [{ verb: [], resource: '/never/*' }, { resource: '/never/*' }] } as unknown as PolicyInput;
    const r = suggestNarrowing(policy, [led('kt.read', '/r/1')], { catalog });
    expect(r.proposal).toBeUndefined();
    expect(r.reason).toBe('no ledger observation matches any predicate');
    expect(r.findings).toEqual([
      { kind: 'unused-predicate', predicate: 0, verb: '*', detail: 'no observed action used predicate 0 (*)', blastRadius: 5, reversibility: 'rate_limited', rank: 10 },
      { kind: 'unused-predicate', predicate: 1, verb: '*', detail: 'no observed action used predicate 1 (*)', blastRadius: 5, reversibility: 'rate_limited', rank: 10 },
    ]);
  });

  it('ranks scale with the reversibility class', () => {
    const policy: PolicyInput = { predicates: [{ verb: 'kt.read', resource: '/never/*' }, { verb: 'kt.limited', resource: '/never/*' }, { verb: 'kt.final', resource: '/never/*' }] };
    const r = suggestNarrowing(policy, [led('x', '/y')], { catalog });
    expect(r.findings.map((f) => [f.verb, f.rank])).toEqual([['kt.final', 6], ['kt.limited', 4], ['kt.read', 2]]);
  });

  it('a value that is not a policy yields no findings', () => {
    const r = suggestNarrowing({} as unknown as PolicyInput, [led('kt.read', '/r/1')], { catalog });
    expect(r.findings).toEqual([]);
    expect(r.reason).toBe('no ledger observation matches any predicate');
  });
});

describe('suggestNarrowing unreached caps (exact)', () => {
  const cap = (op: string, value: number): PolicyInput => ({ predicates: [{ verb: 'kt.limited', resource: '/r/*', where: [field('amount', op, value)] }] });
  const finding = (c: number, largest: number) => ({ kind: 'unreached-cap', predicate: 0, verb: 'kt.limited', detail: `amount <= ${c} but the largest observed value is ${largest}`, blastRadius: 2, reversibility: 'rate_limited', rank: 4 });
  const run = (p: PolicyInput, xs: number[]) => suggestNarrowing(p, amounts(xs, 'kt.limited'), { catalog }).findings;

  it('flags a cap whose largest observed value is under half of it, for both lte and lt', () => {
    expect(run(cap('lte', 1000), [10, 20, 30, 40, 100])).toEqual([finding(1000, 100)]);
    expect(run(cap('lt', 1000), [10, 20, 30, 40, 100])).toEqual([finding(1000, 100)]);
  });

  it('needs minSamples observations (5 is enough, 4 is not)', () => {
    expect(run(cap('lte', 1000), [10, 20, 30, 40])).toEqual([]);
    expect(run(cap('lte', 1000), [10, 20, 30, 40, 50])).toHaveLength(1);
    expect(suggestNarrowing(cap('lte', 1000), amounts([10, 20, 30], 'kt.limited'), { catalog, minSamples: 3 }).findings).toHaveLength(1);
  });

  it('compares the largest value against half the cap: strictly under', () => {
    expect(run(cap('lte', 200), [10, 20, 30, 40, 99])).toEqual([finding(200, 99)]);
    expect(run(cap('lte', 200), [10, 20, 30, 40, 100])).toEqual([]);
    expect(run(cap('lte', 200), [10, 20, 30, 40, 150])).toEqual([]);
  });

  it('only the observations the predicate admits count, and only caps flag', () => {
    const policy: PolicyInput = { predicates: [{ verb: 'kt.limited', resource: '/r/*', where: [field('amount', 'lte', 1000)] }, { verb: 'kt.read' }] };
    const obs = [...amounts([10, 20, 30, 40, 100], 'kt.limited'), ...amounts([5000, 5000, 5000, 5000, 5000], 'kt.read')];
    expect(suggestNarrowing(policy, obs, { catalog }).findings).toEqual([finding(1000, 100)]);
  });

  it('a lower bound, a string comparison and a grouping are not caps', () => {
    const policy: PolicyInput = { predicates: [{ verb: 'kt.limited', resource: '/r/*', where: [field('amount', 'gte', -10), field('kind', 'eq', 'a'), { not: field('flag', 'eq', true) }] }] };
    const obs = amounts([-8, -9, -8, -7, -9], 'kt.limited', () => ({ kind: 'a', flag: false }));
    expect(suggestNarrowing(policy, obs, { catalog }).findings).toEqual([]);
  });
});

describe('suggestNarrowing counts and access requests', () => {
  const policy: PolicyInput = { predicates: [{ verb: 'v', resource: '/r/*' }] };

  it('counts used, rejected and refused observations separately', () => {
    const obs = [
      ...amounts([10, 20, 30, 40, 50]),
      led('v', '/r/d', { amount: 5 }, { outcome: 'denied' }),
      led('v', '/r/d', { amount: 5 }, { outcome: 'denied' }),
      led('v', '/r/d', { amount: 5 }, { source: 'agent', outcome: 'denied' }),
    ];
    const r = suggestNarrowing(policy, obs);
    expect([r.used, r.rejected, r.denied]).toEqual([5, 1, 2]);
    expect(r.accessRequests.map((a) => [a.resource, a.denied_count])).toEqual([['/r/d', 2]]);
    expect(r).not.toHaveProperty('taskBinding');
  });

  it('keeps refused groups apart by verb and resource and orders them by count, then verb, then arrival', () => {
    const d = (verb: string, resource: string, n: number): ObservedAction[] => Array.from({ length: n }, () => led(verb, resource, undefined, { outcome: 'denied' }));
    const obs = [...d('b.x', '/r1', 1), ...d('c.x', '/r1', 3), ...d('a.x', '/r1', 3), ...d('d.x', '/r1', 3), ...d('e.x', '/r1', 1), ...d('e.x', '/r2', 1)];
    const r = suggestNarrowing(policy, obs);
    const digest = policyDigestOf(toModel(policy));
    expect(r.accessRequests.map((a) => [a.verb, a.resource, a.denied_count])).toEqual([
      ['a.x', '/r1', 3],
      ['c.x', '/r1', 3],
      ['d.x', '/r1', 3],
      ['b.x', '/r1', 1],
      ['e.x', '/r1', 1],
      ['e.x', '/r2', 1],
    ]);
    expect(r.accessRequests[0]).toStrictEqual({ v: 1, kind: 'pca-access-request', verb: 'a.x', resource: '/r1', example_params: {}, denied_count: 3, policy_digest: digest });
  });
});

describe('suggestNarrowing proposals (exact)', () => {
  it('narrows the resource to the single observed one, the common prefix, or keeps the original', () => {
    const one = suggestNarrowing({ predicates: [{ verb: 'v', resource: '/r/*' }] }, [led('v', '/r/one'), led('v', '/r/one'), led('v', '/r/one')]);
    expect(predicatesOf(one)).toStrictEqual([{ verb: 'v', resource: '/r/one' }]);
    const many = suggestNarrowing({ predicates: [{ verb: 'v', resource: '/r/*' }] }, [led('v', '/r/a/1'), led('v', '/r/a/2')]);
    expect(predicatesOf(many)).toStrictEqual([{ verb: 'v', resource: '/r/a/*' }]);
    const forked = suggestNarrowing({ predicates: [{ verb: 'v', resource: '/r/*' }] }, [led('v', '/r/a/1'), led('v', '/r/b/1'), led('v', '/r/a/2')]);
    expect(predicatesOf(forked)).toStrictEqual([{ verb: 'v', resource: '/r/*' }]);
    const shorter = suggestNarrowing({ predicates: [{ verb: 'v', resource: '/r/*' }] }, [led('v', '/r/a/b/1'), led('v', '/r/a/b')]);
    expect(predicatesOf(shorter)).toStrictEqual([{ verb: 'v', resource: '/r/a/*' }]);
    const keep = suggestNarrowing({ predicates: [{ verb: 'v', resource: '*' }] }, [led('v', '/a/1'), led('v', '/b/1')]);
    expect(predicatesOf(keep)).toStrictEqual([{ verb: 'v', resource: '*' }]);
  });

  it('adds no resource when the predicate has none and the observations share no directory', () => {
    const slash = suggestNarrowing({ predicates: [{ verb: 'v' }] }, [led('v', '/a/1'), led('v', '/b/1')]);
    expect(predicatesOf(slash)).toStrictEqual([{ verb: 'v' }]);
    const bare = suggestNarrowing({ predicates: [{ verb: 'v' }] }, [led('v', 'x1'), led('v', 'y1')]);
    expect(predicatesOf(bare)).toStrictEqual([{ verb: 'v' }]);
  });

  it('lists the observed verbs sorted, as one verb when there is one', () => {
    const r = suggestNarrowing({ predicates: [{ verb: '*', resource: '/r/*' }] }, [led('zeta', '/r/a/1'), led('alpha', '/r/a/2'), led('zeta', '/r/a/3')]);
    expect(predicatesOf(r)).toStrictEqual([{ verb: ['alpha', 'zeta'], resource: '/r/a/*' }]);
  });

  it('falls back to the original resource when the observed prefix would be wider than it', () => {
    const r = suggestNarrowing({ predicates: [{ verb: 'v', resource: '/acct/a*' }, { verb: 'w' }] }, [led('v', '/acct/ab/1'), led('v', '/acct/ac/2'), led('w', '/x/1')]);
    expect(predicatesOf(r)).toStrictEqual([{ verb: 'v', resource: '/acct/a*' }, { verb: 'w' }]);
    expect(r).not.toHaveProperty('reason');
    expect(r.coversObserved).toBe(true);
    expect(r.diff?.widens).toBe(false);
  });

  it('withholds the proposal, with the analyzer reason, when narrowing cannot be proven', () => {
    const r = suggestNarrowing({ predicates: [{ verb: 'v', resource: 're:/r/a+' }] }, [led('v', '/r/a'), led('v', '/r/aa')]);
    expect(r.proposal).toBeUndefined();
    expect(r.coversObserved).toBe(false);
    expect(r.reason).toContain('regex resource matcher');
    expect(r.reason).toContain('cannot prove the relation');
  });

  it('carries the caveats and the prohibitions of the original', () => {
    const veto = { id: 'x', kind: 'deny' as const, when: { verb: 'zzz' } };
    const policy: PolicyInput = { predicates: [{ verb: 'v', resource: '/r/*' }], caveats: [{ type: 'expires', at: 9_999_999_999 }], vetoes: [veto] };
    const r = suggestNarrowing(policy, [led('v', '/r/1')]);
    const proposal = r.proposal as { caveats: unknown[]; vetoes: unknown[] };
    expect(proposal.caveats).toEqual([{ type: 'expires', at: 9_999_999_999 }]);
    expect(proposal.vetoes).toEqual([veto]);
  });
});

describe('suggestNarrowing parameter constraints (exact)', () => {
  const whereOf = (policy: PolicyInput, obs: ObservedAction[], o: Parameters<typeof suggestNarrowing>[2] = {}) => predicatesOf(suggestNarrowing(policy, obs, o))[0]!.where;
  const open: PolicyInput = { predicates: [{ verb: 'v', resource: '/r/*' }] };
  const withWhere = (...where: never[]): PolicyInput => ({ predicates: [{ verb: 'v', resource: '/r/*', where }] });

  it('caps an integer parameter at the largest value plus margin, rounded up, from the fifth sample', () => {
    expect(whereOf(open, amounts([10, 20, 30, 40, 50]))).toEqual([field('amount', 'lte', Math.ceil(50 * (1 + 0.1)))]);
    expect(whereOf(open, amounts([10, 20, 30, 40]))).toBeUndefined();
  });

  it('does not round a cap when any observed value is fractional', () => {
    expect(whereOf(open, amounts([1.5, 2, 3, 4, 5.5]))).toEqual([field('amount', 'lte', 5.5 * (1 + 0.1))]);
  });

  it('adds a cap only when it is strictly tighter than an existing upper bound', () => {
    const xs = [10, 20, 30, 40, 80];
    expect(whereOf(withWhere(field('amount', 'lte', 89)), amounts(xs))).toEqual([field('amount', 'lte', 89), field('amount', 'lte', 88)]);
    expect(whereOf(withWhere(field('amount', 'lte', 88)), amounts(xs))).toEqual([field('amount', 'lte', 88)]);
    const high = [10, 20, 30, 40, 190];
    expect(whereOf(withWhere(field('amount', 'lt', 200)), amounts(high))).toEqual([field('amount', 'lt', 200)]);
    expect(whereOf(withWhere(field('amount', 'lte', 200)), amounts(high))).toEqual([field('amount', 'lte', 200)]);
    expect(whereOf(withWhere(field('amount', 'lte', 500), field('amount', 'lte', 200)), amounts(high))).toEqual([field('amount', 'lte', 500), field('amount', 'lte', 200)]);
  });

  it('reads only the upper bounds of the same parameter', () => {
    const where = [field('amount', 'lte', 500), field('limit', 'lte', 5), field('amount', 'gte', 1)] as never[];
    const obs = amounts([10, 20, 30, 40, 50], 'v', () => ({ limit: 1 }));
    expect(whereOf(withWhere(...where), obs)).toEqual([...where, field('amount', 'lte', 56), field('limit', 'lte', 2)]);
  });

  it('constrains parameters in name order', () => {
    const obs = [1, 2, 3, 4, 5].map((n, i) => led('v', `/r/${i}`, { zz: n, aa: 1 }));
    expect(whereOf(open, obs)).toEqual([field('aa', 'lte', 2), field('zz', 'lte', 6)]);
  });

  it('constrains a string parameter to its observed set up to the enum limit', () => {
    const kinds = ['a', 'b', 'c', 'd', 'a', 'b'];
    const obs = kinds.map((k, i) => led('v', `/r/${i}`, { kind: k }));
    expect(whereOf(open, obs, { enumLimit: 4 })).toEqual([field('kind', 'in', ['a', 'b', 'c', 'd'])]);
    expect(whereOf(open, obs, { enumLimit: 3 })).toBeUndefined();
  });

  it('constrains nothing when the values are of mixed or other types', () => {
    const strict = (obs: ObservedAction[]) => predicatesOf(suggestNarrowing(open, obs))[0];
    expect(strict(amounts([10, '20', 30, 40, 50]))).toStrictEqual({ verb: 'v', resource: '/r/*' });
    expect(strict(amounts([true, false, true, false, true, false]))).toStrictEqual({ verb: 'v', resource: '/r/*' });
    expect(strict(amounts([-Infinity, -Infinity, -Infinity, -Infinity, -Infinity]))).toStrictEqual({ verb: 'v', resource: '/r/*' });
    expect(strict(amounts([10, 20, 30, 40, 50]).map((o, i) => (i === 2 ? { ...o, params: {} } : o)))).toStrictEqual({ verb: 'v', resource: '/r/*' });
  });
});

describe('access request signatures (exact)', () => {
  const request: AccessRequest = { v: 1, kind: 'pca-access-request', verb: 'v', resource: '/r', example_params: { amount: 1 }, denied_count: 2, policy_digest: 'd' };

  it('verifies without a pinned signer, and signs the domain-separated digest of the request', () => {
    const k = generateKeyPair();
    const pub = b64u(k.publicKey);
    const signed = signAccessRequest(request, k.secretKey, pub);
    expect(verifyAccessRequest(signed)).toBe(true);
    const domain = utf8(ACCESS_REQUEST_SIG_DOMAIN);
    const digest = sha256(utf8(hashCanonical(request)));
    const message = new Uint8Array(domain.length + digest.length);
    message.set(domain);
    message.set(digest, domain.length);
    expect(signed.sig).toBe(b64u(sign(k.secretKey, message)));
    expect(verifyAccessRequest({ request, signer: pub, sig: b64u(sign(k.secretKey, message)) }, pub)).toBe(true);
  });

  it('rejects a correctly signed request of another kind or version', () => {
    const k = generateKeyPair();
    const pub = b64u(k.publicKey);
    expect(verifyAccessRequest(signAccessRequest({ ...request, kind: 'other' } as unknown as AccessRequest, k.secretKey, pub), pub)).toBe(false);
    expect(verifyAccessRequest(signAccessRequest({ ...request, v: 2 } as unknown as AccessRequest, k.secretKey, pub), pub)).toBe(false);
    expect(verifyAccessRequest(signAccessRequest(request, k.secretKey, pub), pub)).toBe(true);
  });

  it('rejects values that are not signed requests', () => {
    expect(verifyAccessRequest(null as never)).toBe(false);
    expect(verifyAccessRequest({ request: null } as never)).toBe(false);
    expect(verifyAccessRequest({ request: [], signer: 'x', sig: 'y' } as never)).toBe(false);
  });

  it('rejects a request that cannot be hashed instead of throwing', () => {
    const k = generateKeyPair();
    const pub = b64u(k.publicKey);
    const signed = signAccessRequest(request, k.secretKey, pub);
    expect(verifyAccessRequest({ ...signed, request: { ...request, example_params: { n: Number.NaN } } }, pub)).toBe(false);
  });
});

describe('suggestNarrowing unreached caps on a grouping that also carries leaf members', () => {
  // the evaluator reads such a condition as its all_of group; the cap check reads its leaf members
  const finding = (c: number, largest: number) => ({ kind: 'unreached-cap', predicate: 0, verb: 'kt.limited', detail: `amount <= ${c} but the largest observed value is ${largest}`, blastRadius: 2, reversibility: 'rate_limited', rank: 4 });
  const hybrid = (fieldName: unknown): PolicyInput => ({
    predicates: [{ verb: 'kt.limited', resource: '/r/*', where: [{ all_of: [{ field: 'action.verb', op: 'eq', value: 'kt.limited' }], field: fieldName, op: 'lte', value: 1000 } as never] }],
  });

  it('only numeric observed values count toward the largest value and the sample count', () => {
    const obs = [...amounts([10, 20, 30, 40, 100], 'kt.limited'), led('kt.limited', '/r/9', {})];
    expect(suggestNarrowing(hybrid('action.params.amount'), obs, { catalog }).findings).toEqual([finding(1000, 100)]);
  });

  it('a member that is not a string field is not a cap', () => {
    expect(suggestNarrowing(hybrid(5), amounts([10, 20, 30, 40, 100], 'kt.limited'), { catalog }).findings).toEqual([]);
  });
});
