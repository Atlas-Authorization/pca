import { describe, expect, it } from 'vitest';
import type { Condition, Predicate } from '@atlasauth/pca';
import { b64u, generateKeyPair, hashCanonical, sha256, utf8, verifyB64u } from '@atlasauth/pca';
import { POLICY_TESTS_KIND, POLICY_TESTS_SIG_DOMAIN, decideAll, generateBoundaryTests, policyTestsDoc, runPolicyTests, signPolicyTests, verifyPolicyTests, type PolicyTestDoc } from './testrunner';
import type { PolicyInput } from './index';
import { refund } from './k2-fixtures';

const leaf = (field: string, op: string, value?: unknown): Condition => ({ field, op, value }) as unknown as Condition;
const P = (verb: string, where?: unknown[]): Predicate => ({ verb, ...(where ? { where } : {}) }) as unknown as Predicate;
const at = (amount: number, resource = '/acct/1') => ({ verb: 'stripe.refund', resource, params: { amount } });
const names = (d: PolicyTestDoc): string[] => d.cases.map((c) => c.name);

describe('runPolicyTests result shape', () => {
  const policy: PolicyInput = { predicates: [refund(500)] };
  it('counts passed cases and omits expectedDecidedBy when no clause was asserted', () => {
    const doc = policyTestsDoc(policy, [
      { name: 'ok', action: at(100), expect: 'allow' },
      { name: 'wrong', action: at(100), expect: 'deny' },
    ]);
    const r = runPolicyTests(policy, doc);
    expect(r.total).toBe(2);
    expect(r.passed).toBe(1);
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0]).not.toHaveProperty('expectedDecidedBy');
    expect(r.failures[0]).toEqual({ name: 'wrong', expected: 'deny', got: 'allow', decidedBy: 'permit[0]' });
  });
});

describe('signed policy tests', () => {
  const doc = policyTestsDoc({ predicates: [refund(500)] }, [{ name: 'ok', action: at(100), expect: 'allow' }]);

  it('the signature covers the domain prefix and the digest of the document', () => {
    const k = generateKeyPair();
    const pub = b64u(k.publicKey);
    const s = signPolicyTests(doc, k.secretKey, pub);
    const pre = utf8(POLICY_TESTS_SIG_DOMAIN);
    const d = sha256(utf8(hashCanonical(doc)));
    const msg = new Uint8Array(pre.length + d.length);
    msg.set(pre);
    msg.set(d, pre.length);
    expect(verifyB64u(pub, msg, s.sig)).toBe(true);
  });

  it('a document of another kind is refused even when its signature is valid', () => {
    const k = generateKeyPair();
    const pub = b64u(k.publicKey);
    const other = { ...doc, kind: 'something-else' } as unknown as PolicyTestDoc;
    expect(verifyPolicyTests(signPolicyTests(other, k.secretKey, pub), pub)).toBe(false);
    expect(verifyPolicyTests(signPolicyTests({ ...doc, kind: POLICY_TESTS_KIND }, k.secretKey, pub), pub)).toBe(true);
  });

  it('a document that cannot be canonicalized fails closed', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const bad = { ...doc, cases: [cyclic] } as unknown as PolicyTestDoc;
    const pub = b64u(generateKeyPair().publicKey);
    expect(verifyPolicyTests({ doc: bad, signer: pub, sig: 'AAAA' }, pub)).toBe(false);
  });
});

describe('decideAll', () => {
  it('returns the decision of every case in order', () => {
    const policy: PolicyInput = { predicates: [refund(500)] };
    const doc = policyTestsDoc(policy, [
      { name: 'a', action: at(100), expect: 'allow' },
      { name: 'b', action: at(900), expect: 'deny' },
      { name: 'c', action: at(500), expect: 'allow' },
    ]);
    expect(decideAll(policy, doc)).toEqual(['allow', 'deny', 'allow']);
  });
});

describe('generateBoundaryTests: base action and triggers', () => {
  it('the base action is one the prohibitions let through', () => {
    const vetoes = [
      { id: 'low', kind: 'deny' as const, when: P('stripe.refund', [leaf('action.params.amount', 'lte', 100)]) },
      { id: 'high', kind: 'deny' as const, when: P('stripe.refund', [leaf('action.params.amount', 'gte', 400)]) },
    ];
    const d = generateBoundaryTests({ predicates: [refund(500)], vetoes });
    const base = d.cases.find((c) => c.name === 'permit[0]: minimal admitted action');
    expect(base?.expect).toBe('allow');
    expect(base?.decidedBy).toBe('permit[0]');
  });

  it('a permit every prohibition stops still gets a base action, decided by the prohibition', () => {
    const d = generateBoundaryTests({ predicates: [refund(500)], vetoes: [{ id: 'all', kind: 'deny', when: P('stripe.refund') }] });
    const base = d.cases.find((c) => c.name === 'permit[0]: minimal admitted action');
    expect(base).toMatchObject({ expect: 'deny', decidedBy: 'all' });
  });

  it('an unsatisfiable permit has no examples', () => {
    const dead: PolicyInput = { predicates: [P('v', [leaf('action.params.n', 'gte', 10), leaf('action.params.n', 'lte', 1)])] };
    expect(generateBoundaryTests(dead).cases).toEqual([]);
  });

  it('boundary examples keep the other parameters of the base action', () => {
    const p: PolicyInput = { predicates: [P('v', [leaf('action.params.x', 'lte', 5), leaf('action.params.y', 'eq', 'k')])] };
    const c = generateBoundaryTests(p).cases.find((x) => x.name === 'permit[0]: x at 5');
    expect(c?.action.params).toEqual({ x: 5, y: 'k' });
  });

  it('a prohibition is triggered under a reversibility cap', () => {
    const p: PolicyInput = { predicates: [P('v')], caveats: [{ type: 'reversibility_max', class: 'reversible' }] as never, vetoes: [{ id: 'blk', kind: 'deny', when: P('v') }] };
    // the trigger action coincides with the permit's base action, so it appears under that name
    const c = generateBoundaryTests(p).cases.find((x) => x.decidedBy === 'blk');
    expect(c).toMatchObject({ expect: 'deny', decidedBy: 'blk' });
    expect(c?.action.reversibilityClass).toBe('reversible');
  });

  it('a prohibition that no permitted action can trigger gets no example', () => {
    const p: PolicyInput = { predicates: [refund(500)], vetoes: [{ id: 'cut', kind: 'deny', when: P('other.verb') }] };
    expect(names(generateBoundaryTests(p)).some((n) => n === 'cut: trigger')).toBe(false);
  });
});

describe('generateBoundaryTests: which conditions contribute thresholds', () => {
  it('finds parameters inside all_of, any_of and not, and ignores other fields and permits without conditions', () => {
    const p: PolicyInput = {
      predicates: [
        P('v', [
          { all_of: [leaf('action.params.n', 'lte', 5)] },
          { any_of: [leaf('action.params.m', 'gte', 3)] },
          { not: leaf('action.params.k', 'gt', 9) },
          leaf('subject.level', 'gte', 77),
        ]),
        P('w'),
      ],
    };
    const n = names(generateBoundaryTests(p));
    expect(n).toEqual(expect.arrayContaining(['permit[0]: n at 5', 'permit[0]: m below 3', 'permit[0]: k at 9', 'permit[1]: minimal admitted action']));
    expect(n.some((x) => x.includes(' 77'))).toBe(false);
  });

  it('malformed members of a group are skipped', () => {
    const p: PolicyInput = { predicates: [P('v', [{ any_of: [null, { weird: 1 }, leaf('action.params.m', 'gte', 3)] }])] };
    expect(names(generateBoundaryTests(p))).toEqual(expect.arrayContaining(['permit[0]: m below 3']));
  });
});

describe('generateBoundaryTests: edge inputs', () => {
  it('a prohibition is triggered under a reversibility cap by an action other than the base one', () => {
    const p: PolicyInput = {
      predicates: [P('v')],
      caveats: [{ type: 'reversibility_max', class: 'reversible' }] as never,
      vetoes: [{ id: 'blk', kind: 'deny', when: P('v', [leaf('action.params.x', 'eq', 1)]) }],
    };
    const c = generateBoundaryTests(p).cases.find((x) => x.name === 'blk: trigger');
    expect(c).toMatchObject({ expect: 'deny', decidedBy: 'blk', action: { verb: 'v', params: { x: 1 }, reversibilityClass: 'reversible' } });
  });

  it('an undefined member of a group is skipped when collecting parameters, and the policy is then refused at its digest', () => {
    const p: PolicyInput = { predicates: [P('v', [{ any_of: [undefined, leaf('action.params.m', 'gte', 3)] }])] };
    expect(() => generateBoundaryTests(p)).toThrow(/canonicalize/);
  });
});
