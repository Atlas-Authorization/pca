/**
 * r13 mutation kills for the small g7 files: session.ts (goal sharing with and without envelopes), budget-forecast.ts
 * (start time, a step-up at index 0, the rationale), beacons.ts / envelope.ts module constants (fresh module, pinned
 * against independent values), revocation.ts (the opt-in proved inclusion check's catch is final), console.ts
 * (an unknown outcome is not counted as executed), merkle.ts (a nullish proof), threshold.ts (an own pq_pk member
 * that is undefined is not "absent").
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Agent } from './facade';
import { compilePolicy } from './facade';
import { hashCanonical, utf8 } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { mintGrant } from './envelope';
import { DEFAULT_RISK_POLICY } from './risk';
import { sharesGoal, startSession } from './session';
import { forecast, recommendPolicy } from './budget-forecast';
import { simulate } from './policy-sim';
import { buildConsole } from './console';
import { verifyInclusion } from './merkle';
import { signShare, verifyThreshold, assembleThreshold } from './threshold';
import type { ActivityEvent } from './console';
import { trustedPq } from './pq-test-support';

/** Run f, capturing its value or its error (name + message), so a throwing mutant fails an assertion. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
const P = generateKeyPair();
const A = generateKeyPair();
const grantFor = (goal: string) =>
  mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), goal, envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const agentOf = (grant: unknown) => ({ grant }) as unknown as Agent;

describe('session', () => {
  it('a root without an envelope has an empty goal commit', () => {
    expect(settle(() => startSession(agentOf({ caveats: [] })).goalCommit)).toEqual({ ok: true, value: '' });
  });
  it('sharesGoal requires every member to carry the root goal commit', () => {
    const g1 = grantFor('a');
    const root = agentOf(g1);
    const s = startSession(root);
    expect(sharesGoal({ ...s, members: [root, agentOf(g1)] })).toBe(true);
    expect(sharesGoal({ ...s, members: [root, agentOf(grantFor('b'))] })).toBe(false);
    expect(settle(() => sharesGoal({ ...s, members: [root, agentOf({ caveats: [] })] }))).toEqual({ ok: true, value: false });
    const bare = startSession(agentOf({ caveats: [] }));
    expect(settle(() => sharesGoal({ ...bare, members: [agentOf({ caveats: [] }), agentOf({ caveats: [] })] }))).toEqual({ ok: true, value: true });
  });
});

describe('budget-forecast', () => {
  const policy = compilePolicy({ permissions: { stripe: ['payout', 'create_customer'] } });
  it('passes the start time through to the simulation', () => {
    const plan = [{ verb: 'stripe.create_customer', resource: 'c', at: 1_000_000 }];
    const f = forecast(policy, plan, { start: 1_000_000 });
    expect(f.steps[0]!.budgetAfter).toBe(simulate(policy, plan, { start: 1_000_000 }).results[0]!.budgetAfter);
    expect(f.steps[0]!.budgetAfter).not.toBe(forecast(policy, plan).steps[0]!.budgetAfter);
  });
  it('reports a step-up at index 0', () => {
    const plan = [{ verb: 'stripe.payout', resource: 'acct', params: { amount: 1e9 } }];
    const sim = simulate(policy, plan);
    expect(sim.results[0]!.outcome).toBe('step_up');
    expect(forecast(policy, plan).firstStepUpAt).toBe(0);
  });
  it('rationale', () => {
    expect(recommendPolicy(10, 0.5, { kappa: 2 }).rationale).toBe('Σr ≤ bMax/κ = 5.000 ≥ 10×0.500 actions before a human co-sign');
  });
});

describe('module constants (fresh module)', () => {
  it('beacons', async () => {
    vi.resetModules();
    const b = await import('./beacons');
    expect(b.GLOBAL_SCOPE).toBe('*');
    expect(b.BEACON_MAX_VALIDITY_MS).toBe(3_600_000);
    const m = b.livenessBeaconMessage({ v: 2, instance: 'i', scope: '*', epoch: 1, seq: 1, issued_at: 60_000, not_after: 120_000, issuer: 'x' } as never);
    const d = utf8('atlas-pca/beacon/v2\0');
    expect(Array.from(m.subarray(0, d.length))).toEqual(Array.from(d));
    expect(m[d.length]).toBe('{'.charCodeAt(0));
  });
  it('envelope', async () => {
    vi.resetModules();
    const e = await import('./envelope');
    expect(e.ENVELOPE_CAVEAT).toBe('envelope');
    expect(e.goalCommitOf('g', 's')).toBe(hashCanonical({ d: 'atlas-pca/goal/v1\0', goal: 'g', salt: 's' }));
  });
});

describe('revocation (merkle-strict opt-in)', () => {
  afterEach(async () => (await import('./verified-core-mode')).__setVerifiedCoreModeForTests(undefined));
  it('the proved inclusion check accepts a good proof and refuses a mismatched one', async () => {
    vi.resetModules();
    const r = await import('./revocation');
    const mode = await import('./verified-core-mode');
    const set = new r.RevocationSet(['a', 'b', 'c']);
    const good = set.membershipProof('b');
    expect(r.verifyMembership(set.root, good, 'b')).toBe(true);
    mode.__setVerifiedCoreModeForTests('merkle-strict');
    expect(r.verifyMembership(set.root, good, 'b')).toBe(true);
    expect(r.verifyMembership(set.root, set.membershipProof('a'), 'b')).toBe(false);
  });
});

describe('console', () => {
  it('an unknown outcome is not counted as executed', () => {
    const v = buildConsole([{ agent: 'a', at: 1, outcome: 'weird', r: 0 } as unknown as ActivityEvent, { agent: 'a', at: 2, outcome: 'executed', r: 0 } as unknown as ActivityEvent]);
    expect(v.agents[0]!.executed).toBe(1);
  });
});

describe('merkle', () => {
  it('a nullish proof never verifies', () => {
    expect(verifyInclusion('r', null as never, 'a')).toBe(false);
    expect(verifyInclusion('r', undefined as never, 'a')).toBe(false);
  });
});

describe('threshold', () => {
  it('a share with an own pq_pk member set to undefined is a pq_pk mismatch', () => {
    const G = generateKeyPair();
    const set = [{ role: 'guardian' as const, publicKey: encodeKey(G.publicKey) }];
    const msg = utf8('m');
    const share = signShare('guardian', G.secretKey, msg, { signerSet: set, t: 1 });
    expect(verifyThreshold(assembleThreshold([share]), msg, set, 1).ok).toBe(true);
    const v = verifyThreshold(assembleThreshold([{ ...share, pq_pk: undefined }]), msg, set, 1);
    expect(v.ok).toBe(false);
  });
});

describe('pq-test-support', () => {
  it('trustedPq of a missing or non-string key is undefined (no throw)', () => {
    expect(settle(() => trustedPq(undefined))).toEqual({ ok: true, value: undefined });
    expect(settle(() => trustedPq(5))).toEqual({ ok: true, value: undefined });
    expect(settle(() => trustedPq(''))).toEqual({ ok: true, value: undefined });
  });
});
