/**
 * authorizeExecution: the configuration check, the amount-priced risk, the operation binding, exactly what it hands to
 * `authorize` (input and options), the plan gate and seed it installs, and how it reads a refusal (the decisive reason).
 * `authorize` is replaced by a recorder so every forwarded option is checked as it is passed.
 */
import { describe, expect, it, vi } from 'vitest';
import type { Capability } from '../capability';
import { ENVELOPE_CAVEAT } from '../envelope';
import { merkleRoot, planNodeLeaf, type PlanNode } from '../merkle';
import type { PCActn } from '../pcactn';

type Call = { input: Record<string, unknown>; opts: Record<string, unknown> };
const state: { calls: Call[]; result: () => unknown } = { calls: [], result: () => undefined };
vi.mock('./authorize', async (orig) => ({
  ...(await orig<typeof import('./authorize')>()),
  authorize: async (input: Record<string, unknown>, opts: Record<string, unknown>) => {
    state.calls.push({ input, opts });
    return state.result();
  },
}));

import { amountRisk, authorizeExecution, EXECUTION_REQUIRED_CHECKS, missingExecutionComponents, type AuthorizeExecutionOptions } from './authorize-execution';

const GRANT = { id: 'g1', caveats: [] } as unknown as Capability;
const STORE = { get: async () => undefined, put: async () => undefined };
const base = (over: Partial<AuthorizeExecutionOptions> = {}): AuthorizeExecutionOptions => ({ audience: 'rs', grant: GRANT, state: STORE, isRevoked: () => false, ...over });
const P = { grant_ref: 'g1', plan: { node_id: 'n1', root: 'r0' }, action: { verb: 'do', resource: 'res', params_digest: 'd', reversibility_class: 'reversible' } } as unknown as PCActn;
const deny = (checks: Record<string, string>, reasons: string[]) => () => ({
  allow: false,
  decision: 'deny',
  status: 403,
  reason: 'ignored',
  assurance: {},
  verdict: { allow: false, r: 1, requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false }, checks, reasons },
});
const reasonOf = async (checks: Record<string, string>, reasons: string[]) => {
  state.result = deny(checks, reasons);
  const d = await authorizeExecution(P, { verb: 'do', params: {} }, base());
  return d.allow ? 'ALLOW' : d.reason;
};

describe('missingExecutionComponents', () => {
  it('a null state, or a state without get, is missing', () => {
    expect(missingExecutionComponents({ audience: 'rs', grant: GRANT, state: null as never, isRevoked: () => false })).toEqual(['state']);
    expect(missingExecutionComponents({ audience: 'rs', grant: GRANT, state: { put: async () => undefined } as never, isRevoked: () => false })).toEqual(['state']);
  });
  it('the refusal lists every missing component, comma separated', async () => {
    const d = await authorizeExecution(P, { verb: 'do', params: {} }, { grant: GRANT, state: STORE } as never);
    expect(d).toStrictEqual({ allow: false, kind: 'config', status: 403, reason: 'full policy mode is missing audience, isRevoked (fail closed)' });
  });
});

describe('amountRisk', () => {
  it('a grant without a readable envelope prices nothing', () => {
    expect(amountRisk({ caveats: [] } as unknown as Capability, { amount: 5 })).toBeUndefined();
  });

  // The envelope's policy is validated when it is read (two reads of kappa); the third read is the one amountRisk divides by.
  const withKappa = (third: unknown) => {
    let reads = 0;
    const risk_policy = {
      weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 },
      theta1: 0.25,
      theta2: 0.6,
      lambda: 0,
      rho: 0.5,
      bMax: 1,
      get kappa() {
        reads++;
        return reads <= 2 ? 4 : third;
      },
    };
    const grant = { caveats: [{ type: ENVELOPE_CAVEAT, goal_commit: 'g', predicates: [], caveats: [], agent_binding: {}, risk_policy }] } as unknown as Capability;
    return { grant, reads: () => reads };
  };
  it('divides by a positive numeric kappa only', () => {
    const ok = withKappa(4);
    expect([amountRisk(ok.grant, { amount: 2 }), ok.reads()]).toEqual([{ blastRadius: 0.5 }, 3]);
    const str = withKappa('4');
    expect([amountRisk(str.grant, { amount: 2 }), str.reads()]).toEqual([undefined, 3]);
    const zero = withKappa(0);
    expect([amountRisk(zero.grant, { amount: 2 }), zero.reads()]).toEqual([undefined, 3]);
  });
});

describe('authorizeExecution: binding before anything else', () => {
  it('a null or action-less proof is a binding refusal naming undefined', async () => {
    state.calls = [];
    for (const p of [null, {}]) {
      expect(await authorizeExecution(p as never, { verb: 'do', params: {} }, base())).toStrictEqual({
        allow: false,
        kind: 'binding',
        status: 403,
        reason: 'the proof is for undefined on undefined, but this call is do',
      });
    }
    expect(state.calls).toEqual([]);
  });

  it('an unknown grant_ref is an authn refusal and authorize is never called', async () => {
    state.calls = [];
    const d = await authorizeExecution(P, { verb: 'do', params: {} }, base({ grant: undefined, resolveGrant: () => null }));
    expect(d).toStrictEqual({ allow: false, kind: 'authn', status: 401, reason: 'unknown grant_ref' });
    expect(state.calls).toEqual([]);
  });
});

describe('authorizeExecution: what reaches authorize', () => {
  const allow = () => ({ allow: true, decision: 'allow', status: 200, pcactn: P, verdict: { allow: true }, assurance: {} });

  it('with only the required options: no optional member is passed, the defaults are filled', async () => {
    state.calls = [];
    state.result = allow;
    await authorizeExecution(P, { verb: 'do', params: { a: 1 } }, base());
    const [{ input, opts }] = state.calls as [Call];
    expect(input).toStrictEqual({ operation: { verb: 'do', resource: 'res', params: { a: 1 } }, pcactn: P });
    expect(Object.keys(opts).sort()).toEqual(['allowedSuites', 'audience', 'budgetStore', 'context', 'hooks', 'now', 'require', 'resolveGrant', 'risk', 'seedBudget']);
    expect(opts.allowedSuites).toEqual(['ed25519']);
    expect(opts.require).toEqual([...EXECUTION_REQUIRED_CHECKS]);
    expect(opts.budgetStore).toBe(STORE);
  });

  it('every optional member that is set is passed through as given', async () => {
    state.calls = [];
    state.result = allow;
    const o = {
      allowedSuites: ['ml-dsa-65'] as const,
      pqPins: { iss: 'pk' },
      requireAssurance: { attestation: 'software' as const },
      enforce: {},
      multiInstance: false,
      replayScope: 'audience-grant-holder' as const,
      claimRetries: 0,
      k1: {},
      usesStore: {} as never,
      provenance: {},
      require: ['extra'],
    };
    await authorizeExecution(P, { verb: 'do', params: {}, provenance: 'bundle' }, base(o));
    const [{ input, opts }] = state.calls as [Call];
    expect(input.provenance).toBe('bundle');
    expect(opts.allowedSuites).toBe(o.allowedSuites);
    for (const k of ['pqPins', 'requireAssurance', 'enforce', 'multiInstance', 'replayScope', 'claimRetries', 'k1', 'usesStore', 'provenance'] as const) expect([k, opts[k]]).toEqual([k, o[k]]);
    expect(Object.prototype.hasOwnProperty.call(opts, 'multiInstance') && Object.prototype.hasOwnProperty.call(opts, 'claimRetries')).toBe(true);
    expect(opts.require).toEqual([...EXECUTION_REQUIRED_CHECKS, 'extra']);
  });

  it('the seed budget of a grant without an envelope is 0; the plan gate compares the rebuilt one-step root', async () => {
    state.calls = [];
    state.result = allow;
    await authorizeExecution(P, { verb: 'do', params: { a: 1 } }, base());
    const { opts } = state.calls[0]!;
    const seed = opts.seedBudget as (g: Capability, t: number) => unknown;
    expect(seed({ caveats: [] } as unknown as Capability, 5)).toStrictEqual({ B: 0, tau: 5, asOf: 5 });
    const context = opts.context as (req: unknown, pc: PCActn) => Promise<unknown>;
    const node: PlanNode = { id: 'n1', verb: 'do', resource: 'res', params_digest: 'd', reversibility_class: 'reversible' };
    expect(await context({}, P)).toStrictEqual({ params: { a: 1 }, plan: [node], planAuthorized: false });
    const consistent = { ...P, plan: { node_id: 'n1', root: merkleRoot([planNodeLeaf(node)]) } } as unknown as PCActn;
    expect(await context({}, consistent)).toStrictEqual({ params: { a: 1 }, plan: [node], planAuthorized: true });
  });

  it('a non-Error thrown by authorize is an "unknown" authorization error', async () => {
    state.result = () => {
      throw 'nope';
    };
    expect(await authorizeExecution(P, { verb: 'do', params: {} }, base())).toStrictEqual({ allow: false, kind: 'policy', status: 403, reason: 'authorization error (fail closed): unknown' });
  });
});

describe('authorizeExecution: the decisive reason of a refusal', () => {
  it('the first FAILING check with a reason wins', async () => {
    expect(await reasonOf({ a: 'pass', b: 'fail' }, ['a: x', 'b: y'])).toBe('b: y');
    expect(await reasonOf({ a: 'fail', b: 'fail' }, ['b: y'])).toBe('b: y');
  });

  it('without a matching check: the first reason that is not risk noise, then the first reason, then "denied"', async () => {
    expect(await reasonOf({}, ['risk input(s) missing: taint', 'z'])).toBe('z');
    expect(await reasonOf({}, ['risk input(s) missing: taint'])).toBe('risk input(s) missing: taint');
    expect(await reasonOf({}, [])).toBe('denied');
  });

  it('a failing operation check is ranked after the others', async () => {
    expect(await reasonOf({ operation: 'fail', policy: 'fail' }, ['operation: o', 'policy: p'])).toBe('policy: p');
  });

  it('the ranking comparator: operation last, every other pair tied', async () => {
    type Cmp = (a: unknown, b: unknown) => number;
    const orig = Array.prototype.sort;
    let got: Cmp | undefined;
    Array.prototype.sort = function (this: unknown[], fn?: Cmp) {
      const first = this[0];
      if (fn && !got && Array.isArray(first) && first[0] === 'policy' && first[1] === 'fail') got = fn;
      return orig.call(this, fn);
    } as typeof orig;
    try {
      await reasonOf({ policy: 'fail', operation: 'fail' }, ['policy: p']);
    } finally {
      Array.prototype.sort = orig;
    }
    const cmp = got!;
    expect([cmp(['operation', 'fail'], ['policy', 'fail']), cmp(['policy', 'fail'], ['operation', 'fail']), cmp(['operation', 'fail'], ['operation', 'fail']), cmp(['a', 'fail'], ['b', 'fail'])]).toEqual([1, -1, 0, 0]);
  });
});
