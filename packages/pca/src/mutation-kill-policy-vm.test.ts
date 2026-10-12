/**
 * Mutation-kill tests for policy-vm.ts (decide / toolCallOf / deriveDecideInput). Every denial is asserted by its exact
 * reason, every derived value (r, threshold, budget) exactly, and every optional chain on a caller-supplied value is
 * exercised with the value absent, so a dropped guard, a flipped comparison or a blanked message is observable.
 */
import { describe, expect, it } from 'vitest';
import { mintRoot, verifyChain, type Capability } from './capability';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import type { PlanNode } from './merkle';
import type { PCActn } from './pcactn';
import { mlDsa65Keygen } from './pq';
import { DecideInputGrantRequired, decide, deriveDecideInput, toolCallOf, type DecideInput } from './policy-vm';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const pPub = encodeKey(P.publicKey);
const aPub = encodeKey(A.publicKey);
const NOW = 1_000_000;

function grant(caveats: Record<string, unknown>[] = [{ type: 'expires', at: 9e12 }]): Capability {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: pPub,
    holder: aPub,
    goal: 'secure my account',
    envelope: {
      predicates: [{ verb: 'revoke_session', resource: '/acct/*' }, { verb: 'other', resource: '/*' }],
      caveats: caveats as never,
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  }).grant;
}
const G = grant();
const lowRisk = { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 };
const { semanticDistance: _sd, ...noDist } = lowRisk;
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };
const act = (over: object = {}) => ({ action: { verb: 'revoke_session', resource: '/acct/1/s', params: {} }, ...over });
const input = (over: Partial<DecideInput> = {}): DecideInput => ({ grant: G, action: act(), risk: lowRisk, budget: fresh, now: NOW, ...over });
const node = (id: string | undefined, verb: string, resource: string, extra: object = {}): PlanNode => ({ ...(id === undefined ? {} : { id }), verb, resource, ...extra }) as PlanNode;
const STRONG = { t: 3, proof: 'strong', optimisticAllowed: false };
const noPolicyError = (reasons: string[]) => expect(reasons.filter((r) => r.startsWith('policy evaluation error'))).toEqual([]);

describe('toolCallOf', () => {
  it('absent action / absent inner action / absent params: empty tool, empty args, no digest', () => {
    expect(toolCallOf(undefined as never)).toEqual({ tool: '', args: {} });
    expect(toolCallOf({} as never)).toEqual({ tool: '', args: {} });
    expect(toolCallOf({ action: {} } as never)).toEqual({ tool: '', args: {} });
  });
  it('a non-string verb is not a tool name; null / array params are not args; a non-string toolBinding is dropped', () => {
    expect(toolCallOf({ action: { verb: 5, params: null }, toolBinding: 7 } as never)).toEqual({ tool: '', args: {} });
    expect(toolCallOf({ action: { verb: 'v', params: [1] } } as never)).toEqual({ tool: 'v', args: {} });
    expect(toolCallOf({ action: { verb: 'v', params: { a: 1 } }, toolBinding: 'd' } as never)).toEqual({ tool: 'v', args: { a: 1 }, toolSignatureDigest: 'd' });
  });
});

describe('decide: fail-closed denials are exact', () => {
  it('invalid decision time: the full denied shape', () => {
    expect(decide(input({ now: Number.NaN }))).toEqual({ releaseGuardianShare: false, requiredThreshold: STRONG, r: 1, admit: false, needStepUp: true, reasons: ['invalid decision time'], budget: fresh });
  });
  it('a grant without an envelope is denied by that reason (also with chainVerified)', () => {
    const bare = mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, caveats: [] });
    for (const chainVerified of [true, false]) {
      expect(decide(input({ grant: bare, chainVerified }))).toEqual({ releaseGuardianShare: false, requiredThreshold: STRONG, r: 1, admit: false, needStepUp: true, reasons: ['grant carries no valid envelope'], budget: fresh });
    }
  });
  it('an unverified chain names verifyChain\'s own reason', () => {
    const bad = { ...G, sig: (G.sig[0] === 'A' ? 'B' : 'A') + G.sig.slice(1) };
    const why = verifyChain([bad], bad.issuer).reason;
    expect(why).toBeTypeOf('string');
    expect(decide(input({ grant: bad })).reasons).toEqual([`capability chain unverified: ${why}`]);
  });
  it('an Error thrown while evaluating is a denial with its message and the input budget', () => {
    const d = decide(undefined as never);
    expect(d).toMatchObject({ releaseGuardianShare: false, requiredThreshold: STRONG, r: 1, admit: false, needStepUp: true, budget: { B: 0, tau: 0 } });
    expect(d.budget).toEqual({ B: 0, tau: 0 });
    expect(d.reasons).toHaveLength(1);
    expect(d.reasons[0]).toMatch(/^policy evaluation error \(fail closed\): .+/);
  });
  it('a non-Error throw is reported as unknown, with the caller budget', () => {
    const hostile = { ...input() } as Record<string, unknown>;
    Object.defineProperty(hostile, 'action', {
      enumerable: true,
      get() {
        throw 'nope';
      },
    });
    const d = decide(hostile as never);
    expect(d.reasons).toEqual(['policy evaluation error (fail closed): unknown']);
    expect(d.budget).toEqual(fresh);
  });
  it('a refused (not released) decision always needs step-up', () => {
    const d = decide(input({ action: act({ action: { verb: 'nope', resource: '/x' } }) }));
    expect(d.releaseGuardianShare).toBe(false);
    expect(d.admit).toBe(false);
    expect(d.needStepUp).toBe(true);
    expect(d.reasons).toEqual(['no predicate permits nope on /x']);
  });
});

describe('decide: PQ root needs the verifier pin', () => {
  it('a hybrid root verifies with pqPins for its issuer and is denied without', () => {
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(5));
    const pq = mintRoot({ principalSecret: P.secretKey, principalPublic: pPub, holder: aPub, caveats: G.caveats, suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml } });
    const ok = decide(input({ grant: pq, pqPins: { [pPub]: pq.pq_pk! } }));
    expect(ok.reasons).toEqual([]);
    expect(ok.releaseGuardianShare).toBe(true);
    const no = decide(input({ grant: pq }));
    expect(no.releaseGuardianShare).toBe(false);
    expect(no.reasons[0]!.startsWith('capability chain unverified: ')).toBe(true);
  });
});

describe('decide: caveat and risk reasons join with ", "', () => {
  it('two failing envelope caveats', () => {
    const g = grant([{ type: 'expires', at: NOW - 1 }, { type: 'not_before', at: NOW + 1e9 }]);
    expect(decide(input({ grant: g })).reasons).toEqual(['caveat(s) not satisfied: expires, not_before']);
  });
  it('two failing delegated caveats', () => {
    const leaf = { ...G, caveats: [...G.caveats, { type: 'expires', at: NOW - 1 }, { type: 'not_before', at: NOW + 1e9 }] };
    expect(decide(input({ chain: [G, leaf] as never, chainVerified: true })).reasons).toEqual(['delegated caveat(s) not satisfied: expires, not_before']);
  });
  it('missing risk inputs are listed in order; a non-finite input counts as missing', () => {
    const d = decide(input({ risk: {} }));
    expect(d.reasons[0]).toBe('risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence');
    expect(decide(input({ risk: { ...lowRisk, taint: Number.NaN } })).reasons[0]).toBe('risk input(s) missing, assumed worst case: taint');
  });
  it('an absent risk object is all-worst, never an evaluation error (with and without a plan)', () => {
    for (const plan of [undefined, [node('n', 'revoke_session', '/acct/1/s')]]) {
      const d = decide(input({ risk: undefined as never, plan }));
      noPolicyError(d.reasons);
      expect(d.reasons[0]).toBe(
        plan ? 'risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence' : 'risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence',
      );
    }
  });
});

describe('decide: absent action shapes are never an evaluation error', () => {
  it('action undefined / {} with and without a plan, and a plan with no matching node', () => {
    for (const action of [undefined, {}]) {
      for (const plan of [undefined, [node('z', 'q', '/q')]]) {
        const d = decide(input({ action: action as never, plan }));
        noPolicyError(d.reasons);
        expect(d.releaseGuardianShare).toBe(false);
      }
    }
    // a plan node without a verb matches an absent action verb, so the resource comparison runs on the absent action too
    for (const action of [undefined, {}]) {
      const d = decide(input({ action: action as never, plan: [{ id: 'z', resource: '/q' } as never] }));
      noPolicyError(d.reasons);
    }
    const d = decide(input({ plan: [node('z', 'q', '/q')] }));
    expect(d.reasons).toEqual([]);
    expect(d.releaseGuardianShare).toBe(true);
  });
});

describe('decide: plan node and plan geodesic (the node is the one named by nodeId, never guessed)', () => {
  it('without nodeId no node is guessed, even one matching verb and resource: worst-case distance', () => {
    const plan = [node('n1', 'revoke_session', '/other'), node('n3', 'revoke_session', '/acct/1/s')];
    expect(decide(input({ plan, risk: noDist })).r).toBe(0.25);
    expect(decide(input({ plan, risk: noDist, nodeId: 'n3' })).r).toBe(0);
  });
  it('the default goal is the LAST plan node; an explicit goal wins', () => {
    const plan = [node('a', 'q', '/q'), node('n', 'revoke_session', '/acct/1/s')];
    expect(decide(input({ plan, risk: noDist, nodeId: 'n' })).r).toBe(0);
    const plan2 = [node('n', 'revoke_session', '/acct/1/s'), node('g', 'q', '/q')];
    expect(decide(input({ plan: plan2, risk: noDist, nodeId: 'n', goalNodeId: 'n' })).r).toBe(0);
    expect(decide(input({ plan: plan2, risk: noDist, nodeId: 'n' })).r).toBe(0.25);
  });
  it('an empty plan gives distance 1 (no throw)', () => {
    const d = decide(input({ plan: [], risk: noDist, nodeId: 'n' }));
    noPolicyError(d.reasons);
    expect(d.r).toBe(0.25);
  });
  it('no node id: distance 1 even if some plan node lacks an id', () => {
    const plan = [node(undefined, 'a', '/a'), node('g', 'b', '/b'), node('h', 'c', '/c')];
    expect(decide(input({ plan, risk: noDist, goalNodeId: 'g' })).r).toBe(0.25);
  });
  it('no goal id (last node has none): distance 1', () => {
    const plan = [node('x', 'q', '/q'), node('n', 'revoke_session', '/acct/1/s'), node(undefined, 'z', '/z')];
    expect(decide(input({ plan, risk: noDist, nodeId: 'n' })).r).toBe(0.25);
  });
  it('the reversibility class comes from the named node itself, not another node', () => {
    const plan = [node('n0', 'q', '/q', { reversibility_class: 'reversible' }), node('n1', 'revoke_session', '/acct/1/s', { reversibility_class: 'irreversible' })];
    expect(decide(input({ plan, nodeId: 'n1' })).requiredThreshold).toEqual({ t: 1, proof: 'claim', optimisticAllowed: false });
    const plan2 = [node('n0', 'q', '/q', { reversibility_class: 'irreversible' }), node('n1', 'revoke_session', '/acct/1/s', { reversibility_class: 'reversible' })];
    expect(decide(input({ plan: plan2, nodeId: 'n1' })).requiredThreshold).toEqual({ t: 1, proof: 'claim', optimisticAllowed: true });
  });
  it('without nodeId a reversibility_max caveat cannot use a verb/resource-matching node: unknown class, denied', () => {
    const plan = [node('n1', 'revoke_session', '/acct/1/s', { reversibility_class: 'reversible' })];
    const g = grant([{ type: 'reversibility_max', class: 'irreversible' }]);
    expect(decide(input({ grant: g, plan })).reasons).toContain('caveat(s) not satisfied: reversibility_max');
    expect(decide(input({ grant: g, plan, nodeId: 'n1' })).reasons).toEqual([]);
  });
});

describe('decide: rFloor and step-up reasons', () => {
  it('a NaN rFloor is ignored', () => {
    expect(decide(input({ rFloor: Number.NaN })).r).toBe(0);
  });
  it('depleted budget at t<3: human recharge', () => {
    const d = decide(input({ risk: { ...lowRisk, blastRadius: 1 }, budget: { B: 0.1, tau: NOW, asOf: NOW } }));
    expect(d.reasons).toEqual(['trust budget depleted: human recharge required']);
  });
  it('t=2 with budget: step-up to t=2 with the exact risk', () => {
    const d = decide(input({ risk: { ...lowRisk, semanticDistance: 1, blastRadius: 1 } }));
    expect(d.reasons).toEqual(['risk 0.450 exceeds auto threshold: step-up to t=2']);
  });
  it('t=3: step-up to t=3, not "depleted"', () => {
    const d = decide(input({ risk: { semanticDistance: 1, reversibility: 0, blastRadius: 1, taint: 1, confidence: 0, age: 1 } }));
    expect(d.reasons).toEqual(['risk 1.000 exceeds auto threshold: step-up to t=3']);
  });
});

describe('deriveDecideInput', () => {
  const ctx = { risk: lowRisk, budget: fresh, now: NOW, grant: G };
  it('requires the verifier\'s own grant (undefined, null, non-object)', () => {
    for (const g of [undefined, null, 'g', 5]) {
      expect(() => deriveDecideInput({} as PCActn, { ...ctx, grant: g as never })).toThrow(DecideInputGrantRequired);
    }
    try {
      deriveDecideInput({} as PCActn, { ...ctx, grant: undefined as never });
    } catch (e) {
      expect((e as Error).name).toBe('DecideInputGrantRequired');
      expect((e as Error).message).toBe('deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant');
      expect((e as DecideInputGrantRequired).code).toBe('grant_required');
    }
  });
  it('a PCActn without action / plan derives undefined fields (no throw)', () => {
    const d = deriveDecideInput({} as PCActn, ctx);
    expect(d.action).toEqual({ action: { verb: undefined, resource: undefined, params: {}, reversibility_class: undefined } });
    expect(d.nodeId).toBeUndefined();
  });
  it('subject and env pass through', () => {
    const p = { action: { verb: 'v', resource: '/r', reversibility_class: 'reversible' }, plan: { node_id: 'n' }, cap_chain: [] } as unknown as PCActn;
    const d = deriveDecideInput(p, { ...ctx, subject: { id: 's' }, env: { e: 1 }, params: { a: 1 } });
    expect(d.action).toEqual({ action: { verb: 'v', resource: '/r', params: { a: 1 }, reversibility_class: 'reversible' }, subject: { id: 's' }, env: { e: 1 } });
    expect(d.nodeId).toBe('n');
  });
});
