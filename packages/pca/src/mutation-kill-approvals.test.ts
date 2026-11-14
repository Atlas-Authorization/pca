/**
 * Mutation-kill tests for approvals.ts. A real agent supplies a real grant (goal_commit, goalSalt); its policy and dryRun
 * are overridden so each branch (limit formatting, param summaries, risk recompute, class-approval windows) is pinned exactly.
 */
import { describe, expect, it } from 'vitest';
import { batchReview, buildGoalLineage, classApprovalCovers, coveredByAny, describeGoalLineage, approveClass, pendingRequests, reviewAction } from './approvals';
import { agent, type Agent } from './facade';
import { hashCanonical } from './hash';
import { generateKeyPair } from './keys';
import { goalCommitOf, readEnvelope } from './envelope';

const real = agent({ principal: generateKeyPair(), goal: 'process October payouts', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'ins_x', now: 0 });
const commit = readEnvelope(real.grant)!.goal_commit as string;
type Over = { actions?: unknown[]; limits?: Record<string, unknown>; budgetModel?: string; kappa?: number; dryRun?: unknown; goalSalt?: string };
const mk = (o: Over = {}): Agent =>
  ({
    ...real,
    goalSalt: o.goalSalt ?? real.goalSalt,
    policy: { ...real.policy, actions: o.actions ?? [{ verb: 'v', blastRadius: 0.3, description: 'does v', amountField: 'amt' }], limits: o.limits ?? {}, budgetModel: o.budgetModel ?? 'risk', riskPolicy: { ...real.policy.riskPolicy, kappa: o.kappa ?? 100 } },
    dryRun: o.dryRun ?? (() => ({ allowed: true, t: 2, reason: undefined })),
  }) as unknown as Agent;

describe('formatLimit via authority label', () => {
  const label = (limits: Record<string, unknown>) => buildGoalLineage(mk({ limits }), 'v', 'r').chain[1]!.label;
  it('unit and amount', () => {
    expect(label({ v: { unit: 'usd', amount: 5 } })).toBe('Delegated authority to v (up to $5)');
    expect(label({ v: { unit: 'count', amount: 5 } })).toBe('Delegated authority to v (up to 5)');
    expect(label({})).toBe('Delegated authority to v');
  });
  it('period rendering: days, hours, minutes, boundaries', () => {
    const p = (ms: number) => label({ v: { unit: 'count', amount: 3, periodMs: ms } });
    expect(p(86_400_000)).toBe('Delegated authority to v (up to 3/1d)');
    expect(p(172_800_000)).toBe('Delegated authority to v (up to 3/2d)');
    expect(p(36 * 3_600_000)).toBe('Delegated authority to v (up to 3/36h)'); // >=24 but not a multiple of 24
    expect(p(23 * 3_600_000)).toBe('Delegated authority to v (up to 3/23h)'); // %24 != 0
    expect(p(3_600_000)).toBe('Delegated authority to v (up to 3/1h)');
    expect(p(2 * 3_600_000)).toBe('Delegated authority to v (up to 3/2h)');
    expect(p(1_800_000)).toBe('Delegated authority to v (up to 3/30m)');
    expect(p(60_000)).toBe('Delegated authority to v (up to 3/1m)');
    expect(label({ v: { unit: 'usd', amount: 7, periodMs: 7_200_000 } })).toBe('Delegated authority to v (up to $7/2h)');
  });
});

describe('summarizeParams via action detail', () => {
  const det = (params: Record<string, unknown> | undefined, spec: Record<string, unknown> = { verb: 'v', blastRadius: 0.3, description: 'd', amountField: 'amt' }) =>
    buildGoalLineage(mk({ actions: [spec] }), 'v', 'res', params).chain[2]!;
  it('no params -> no detail key', () => {
    expect('detail' in det(undefined)).toBe(false);
    expect('detail' in det({})).toBe(false);
  });
  it('amountField present wins; absent falls back to key summary', () => {
    expect(det({ amt: 5, other: 1 }).detail).toBe('amt=5');
    expect(det({ other: 1 }).detail).toBe('other=1');
    expect(det({ amt: undefined, other: 1 }).detail).toBe('amt=undefined, other=1');
    expect(det({ amt: 0 }, { verb: 'v', blastRadius: 0.3, description: 'd' }).detail).toBe('amt=0'); // no amountField
  });
  it('joins up to 4 keys with ", " and JSON-encodes objects', () => {
    expect(det({ a: 1, b: { x: 2 }, c: 'z', d: [1], e: 5 }, { verb: 'v', blastRadius: 0.3 }).detail).toBe('a=1, b={"x":2}, c=z, d=[1]');
    expect(det({ a: null }, { verb: 'v', blastRadius: 0.3 }).detail).toBe('a=null');
  });
  it('the action node label is "verb resource"', () => {
    expect(det({}).label).toBe('v res');
    expect(det({}).kind).toBe('action');
  });
});

describe('buildGoalLineage', () => {
  it('verified goal', () => {
    const l = buildGoalLineage(real, 'stripe.payout', 'acct:1', undefined, { goal: 'process October payouts' });
    expect(l.goalVerified).toBe(true);
    expect(l.goalCommit).toBe(commit);
    expect(l.goal).toBe('process October payouts');
    expect(l.chain[0]).toEqual({ kind: 'goal', label: 'Pursue the goal: “process October payouts”', detail: 'verified: this goal opens the signed grant commitment' });
    expect(l.because).toBe('Approving stripe.payout on acct:1 because you asked to “process October payouts”.');
  });
  it('wrong goal is unverified, and so is a good goal under an empty / non-string salt', () => {
    const w = buildGoalLineage(real, 'stripe.payout', 'a', undefined, { goal: 'something else' });
    expect(w.goalVerified).toBe(false);
    expect(w.chain[0]!.detail).toBe('unverified: the revealed goal does not open the grant commitment');
    expect(buildGoalLineage(mk({ goalSalt: '' }), 'v', 'r', undefined, { goal: 'process October payouts' }).goalVerified).toBe(false);
    expect(buildGoalLineage({ ...real, goalSalt: 5 as unknown as string }, 'v', 'r', undefined, { goal: 'process October payouts' }).goalVerified).toBe(false);
  });
  it('an empty goal string is still a revealed goal', () => {
    const l = buildGoalLineage(real, 'v', 'r', undefined, { goal: '' });
    expect(l.goal).toBe('');
    expect(l.chain[0]!.label).toBe('Pursue the goal: “”');
    expect(l.because).toBe('Approving v on r because you asked to “”.');
  });
  it('no goal: committed-goal wording, detail carries the commitment, goal key absent', () => {
    const l = buildGoalLineage(real, 'v', 'r');
    expect('goal' in l).toBe(false);
    expect(l.goalVerified).toBe(false);
    expect(l.chain[0]).toEqual({ kind: 'goal', label: 'Pursue the grant’s committed goal', detail: `committed as ${commit}` });
    expect(l.because).toBe('Approving v on r, authorized under the grant’s committed goal.');
  });
  it('a grant without an envelope commitment: empty goalCommit, no goal detail, never verified', () => {
    const bare = { ...real, grant: { ...real.grant, caveats: [] } } as unknown as Agent;
    const l = buildGoalLineage(bare, 'v', 'r', undefined, { goal: 'process October payouts' });
    expect(l.goalCommit).toBe('');
    expect(l.goalVerified).toBe(false);
    const l2 = buildGoalLineage(bare, 'v', 'r');
    expect(l2.goalCommit).toBe('');
    expect('detail' in l2.chain[0]!).toBe(false);
  });
  it('authority node: description detail only when the spec has one; unknown verb has no detail', () => {
    expect(buildGoalLineage(mk(), 'v', 'r').chain[1]).toEqual({ kind: 'authority', label: 'Delegated authority to v', detail: 'does v' });
    expect('detail' in buildGoalLineage(mk({ actions: [{ verb: 'v', blastRadius: 0.1, description: '' }] }), 'v', 'r').chain[1]!).toBe(false);
    expect('detail' in buildGoalLineage(mk(), 'other', 'r').chain[1]!).toBe(false);
  });
  it('picks the spec whose verb matches, not the first', () => {
    const a = mk({ actions: [{ verb: 'x', blastRadius: 0.1, description: 'dx' }, { verb: 'v', blastRadius: 0.2, description: 'dv' }] });
    expect(buildGoalLineage(a, 'v', 'r').chain[1]!.detail).toBe('dv');
    expect(buildGoalLineage(a, 'x', 'r').chain[1]!.detail).toBe('dx');
  });
  it('describeGoalLineage joins label and detail with an em dash', () => {
    const l = { chain: [{ kind: 'goal', label: 'A', detail: 'd' }, { kind: 'action', label: 'B' }] } as never;
    expect(describeGoalLineage(l)).toEqual(['A — d', 'B']);
    expect(describeGoalLineage(buildGoalLineage(real, 'v', 'r'))[0]).toBe(`Pursue the grant’s committed goal — committed as ${commit}`);
  });
});

describe('reviewAction', () => {
  const NOW = 5000;
  it('deny: reason passes through, default text when absent', () => {
    expect(reviewAction(mk({ dryRun: () => ({ allowed: false, reason: 'nope' }) }), 'v', 'r')).toEqual({ kind: 'deny', reason: 'nope' });
    expect(reviewAction(mk({ dryRun: () => ({ allowed: false }) }), 'v', 'r')).toEqual({ kind: 'deny', reason: 'denied by policy' });
  });
  it('dryRun receives verb, resource, params and the same now', () => {
    const seen: unknown[] = [];
    const a = mk({ dryRun: (...args: unknown[]) => (seen.push(args), { allowed: true, t: 1 }) });
    reviewAction(a, 'v', 'res', { p: 1 }, { insecureUnboundApproval: true, now: NOW });
    expect(seen).toEqual([['v', 'res', { p: 1 }, { now: NOW }]]);
  });
  it('t=1 and t=undefined auto-admit', () => {
    expect(reviewAction(mk({ dryRun: () => ({ allowed: true, t: 1 }) }), 'v', 'r').kind).toBe('auto');
    expect(reviewAction(mk({ dryRun: () => ({ allowed: true }) }), 'v', 'r').kind).toBe('auto');
  });
  it('step-up request fields, id derivation and optional keys', () => {
    const a = mk({ dryRun: () => ({ allowed: true, t: 3, reason: 'big' }) });
    const r = reviewAction(a, 'v', 'res', { amt: 10 }, { insecureUnboundApproval: true, now: NOW, goal: 'process October payouts' });
    expect(r.kind).toBe('step_up');
    if (r.kind !== 'step_up') return;
    const q = r.request;
    expect(q.id).toBe(hashCanonical({ d: 'atlas-pca/stepup/v1', verb: 'v', resource: 'res', params: { amt: 10 }, at: NOW }));
    expect(q).toMatchObject({ verb: 'v', resource: 'res', params: { amt: 10 }, tier: 3, reason: 'big', goalCommit: commit, goal: 'process October payouts', requestedAt: NOW });
    expect(q.lineage.goalVerified).toBe(true);
    expect(q.lineage.goal).toBe('process October payouts');
    const bare = reviewAction(mk({ dryRun: () => ({ allowed: true, t: 2 }) }), 'v', 'res', undefined, { insecureUnboundApproval: true, now: NOW });
    if (bare.kind !== 'step_up') throw new Error('x');
    expect(bare.request.reason).toBe('requires tier 2 co-sign');
    expect('params' in bare.request).toBe(false);
    expect('goal' in bare.request).toBe(false);
    expect('goal' in bare.request.lineage).toBe(false);
    expect(bare.request.id).toBe(hashCanonical({ d: 'atlas-pca/stepup/v1', verb: 'v', resource: 'res', params: null, at: NOW }));
    expect(bare.request.id).not.toBe(q.id);
  });
  it('id depends on every input', () => {
    const a = mk({ dryRun: () => ({ allowed: true, t: 2 }) });
    const id = (v: string, r: string, p: Record<string, unknown> | undefined, now: number) => (reviewAction(a, v, r, p, { now, insecureUnboundApproval: true }) as { request: { id: string } }).request.id;
    const base = id('v', 'r', { a: 1 }, 1);
    expect(new Set([base, id('w', 'r', { a: 1 }, 1), id('v', 's', { a: 1 }, 1), id('v', 'r', { a: 2 }, 1), id('v', 'r', { a: 1 }, 2), id('v', 'r', undefined, 1)]).size).toBe(6);
  });
  it('risk r: dollars model scales amount by kappa and clamps to [0,1]', () => {
    const rOf = (o: Over, params?: Record<string, unknown>) => {
      const r = reviewAction(mk({ dryRun: () => ({ allowed: true, t: 2 }), ...o }), 'v', 'x', params, { insecureUnboundApproval: true, now: 1 });
      return (r as { request: { r: number } }).request.r;
    };
    expect(rOf({ budgetModel: 'dollars', kappa: 200 }, { amt: 50 })).toBe(0.25);
    expect(rOf({ budgetModel: 'dollars', kappa: 100 }, { amt: 500 })).toBe(1);
    expect(rOf({ budgetModel: 'dollars', kappa: 100 }, { amt: -5 })).toBe(0);
    expect(rOf({ budgetModel: 'dollars', kappa: 0 }, { amt: 50 })).toBe(0.3); // kappa 0 -> blast radius
    expect(rOf({ budgetModel: 'dollars', kappa: -10 }, { amt: 5 })).toBe(0.3);
    expect(rOf({ budgetModel: 'dollars', kappa: 100 }, { amt: 'abc' })).toBe(0.3); // not finite
    expect(rOf({ budgetModel: 'dollars', kappa: 100 }, undefined)).toBe(0.3); // missing -> NaN... Number(undefined)
    expect(rOf({ budgetModel: 'dollars', kappa: 100, actions: [{ verb: 'v', blastRadius: 0.4 }] }, { amt: 50 })).toBe(0.4); // no amountField
    expect(rOf({ budgetModel: 'risk', kappa: 100 }, { amt: 50 })).toBe(0.3); // risk model ignores amount
    expect(rOf({ budgetModel: 'dollars', kappa: 1 }, { amt: 1 })).toBe(1);
    expect(rOf({ actions: [{ verb: 'v', blastRadius: 7 }] })).toBe(1);
    expect(rOf({ actions: [{ verb: 'v', blastRadius: -2 }] })).toBe(0);
    expect(rOf({ actions: [{ verb: 'other', blastRadius: 0.1 }] })).toBe(0.8); // unknown verb
    expect(rOf({ actions: [{ verb: 'x', blastRadius: 0.1 }, { verb: 'v', blastRadius: 0.6 }] })).toBe(0.6);
  });
  it('standing approvals downgrade a step-up to auto only when they cover it', () => {
    const a = mk({ dryRun: () => ({ allowed: true, t: 2 }) });
    const ap = approveClass(['v'], { ttlMs: 1000, by: 'me', now: 100 });
    expect(reviewAction(a, 'v', 'r', undefined, { insecureUnboundApproval: true, now: 500, standing: [ap] }).kind).toBe('auto');
    expect(reviewAction(a, 'v', 'r', undefined, { insecureUnboundApproval: true, now: 2000, standing: [ap] }).kind).toBe('step_up');
    expect(reviewAction(a, 'v', 'r', undefined, { insecureUnboundApproval: true, now: 500, standing: [] }).kind).toBe('step_up');
    expect(reviewAction(a, 'v', 'r', undefined, { insecureUnboundApproval: true, now: 500 }).kind).toBe('step_up');
    const denied = mk({ dryRun: () => ({ allowed: false, reason: 'x' }) });
    expect(reviewAction(denied, 'v', 'r', undefined, { insecureUnboundApproval: true, now: 500, standing: [ap] }).kind).toBe('deny'); // a standing approval never overrides a deny
  });
  it('batchReview / pendingRequests keep only step-ups, in order', () => {
    let n = 0;
    const a = mk({ dryRun: () => ({ allowed: true, t: [1, 2, 3][n++ % 3] }) });
    const reviews = batchReview(a, [{ verb: 'v', resource: 'a' }, { verb: 'v', resource: 'b' }, { verb: 'v', resource: 'c', params: { amt: 1 } }], { now: 9, insecureUnboundApproval: true });
    expect(reviews.map((r) => r.kind)).toEqual(['auto', 'step_up', 'step_up']);
    expect(pendingRequests(reviews).map((r) => r.resource)).toEqual(['b', 'c']);
    expect(pendingRequests([{ kind: 'auto' }, { kind: 'deny', reason: 'x' }])).toEqual([]);
  });
});

describe('class approvals', () => {
  const ap = approveClass(['a', 'b'], { ttlMs: 100, by: 'me', now: 1000 });
  it('validity window is [grantedAt, grantedAt+ttl)', () => {
    expect(classApprovalCovers(ap, 'a', 'r', 999)).toBe(false);
    expect(classApprovalCovers(ap, 'a', 'r', 1000)).toBe(true);
    expect(classApprovalCovers(ap, 'a', 'r', 1099)).toBe(true);
    expect(classApprovalCovers(ap, 'a', 'r', 1100)).toBe(false);
  });
  it('verb must be listed', () => {
    expect(classApprovalCovers(ap, 'c', 'r', 1000)).toBe(false);
    expect(classApprovalCovers(ap, 'b', 'r', 1000)).toBe(true);
  });
  it('resource matching: omitted, *, prefix*, exact', () => {
    const m = (resource: string | undefined, r: string) => classApprovalCovers(approveClass(['a'], { ttlMs: 10, by: 'x', now: 0, ...(resource !== undefined ? { resource } : {}) }), 'a', r, 1);
    expect(m(undefined, 'anything')).toBe(true);
    expect(m('*', 'anything')).toBe(true);
    expect(m('acct:*', 'acct:7')).toBe(true);
    expect(m('acct:*', 'acct:')).toBe(true);
    expect(m('acct:*', 'acc')).toBe(false);
    expect(m('acct:*', 'xacct:7')).toBe(false);
    expect(m('acct:1', 'acct:1')).toBe(true);
    expect(m('acct:1', 'acct:12')).toBe(false);
    expect(m('acct:1', 'acct:')).toBe(false);
    expect(m('a*b', 'a*b')).toBe(true); // only a TRAILING * is a wildcard; 'a*b' is exact
    expect(m('a*b', 'axb')).toBe(false);
  });
  it('approveClass: fields, id is order-insensitive in verbs but binds resource / time / by', () => {
    const x = approveClass(['b', 'a'], { ttlMs: 5, by: 'me', now: 7, resource: 'r*' });
    expect(x).toMatchObject({ verbs: ['b', 'a'], resource: 'r*', grantedAt: 7, ttlMs: 5, by: 'me' });
    expect(x.id).toBe(hashCanonical({ d: 'atlas-pca/class-approval/v1', verbs: ['a', 'b'], resource: 'r*', grantedAt: 7, by: 'me' }));
    expect(approveClass(['a', 'b'], { ttlMs: 5, by: 'me', now: 7, resource: 'r*' }).id).toBe(x.id);
    expect('resource' in approveClass(['a'], { ttlMs: 5, by: 'me', now: 7 })).toBe(false);
    expect(approveClass(['a'], { ttlMs: 5, by: 'me', now: 7 }).id).toBe(hashCanonical({ d: 'atlas-pca/class-approval/v1', verbs: ['a'], resource: null, grantedAt: 7, by: 'me' }));
    const v = ['z', 'a'];
    approveClass(v, { ttlMs: 1, by: 'x', now: 0 });
    expect(v).toEqual(['z', 'a']);
    const out = approveClass(v, { ttlMs: 1, by: 'x', now: 0 });
    out.verbs.push('q');
    expect(v).toEqual(['z', 'a']);
  });
  it('coveredByAny is "some", not "every"', () => {
    const live = approveClass(['a'], { ttlMs: 100, by: 'x', now: 0 });
    const dead = approveClass(['a'], { ttlMs: 1, by: 'x', now: 0 });
    expect(coveredByAny([dead, live], 'a', 'r', 50)).toBe(true);
    expect(coveredByAny([live, dead], 'a', 'r', 50)).toBe(true);
    expect(coveredByAny([dead], 'a', 'r', 50)).toBe(false);
    expect(coveredByAny([], 'a', 'r', 50)).toBe(false);
  });
});

describe('residual boundaries', () => {
  const withCommit = (c: string, salt: unknown): Agent => {
    const caveats = real.grant.caveats.map((cv) => ('goal_commit' in cv ? { ...cv, goal_commit: c } : cv));
    return { ...real, goalSalt: salt as string, grant: { ...real.grant, caveats } } as unknown as Agent;
  };
  it('a goal is verified only under a non-empty STRING salt, even if the commitment was made with an empty / non-string one', () => {
    expect(buildGoalLineage(withCommit(goalCommitOf('g', 'S'), 'S'), 'v', 'r', undefined, { goal: 'g' }).goalVerified).toBe(true); // control
    expect(buildGoalLineage(withCommit(goalCommitOf('g', ''), ''), 'v', 'r', undefined, { goal: 'g' }).goalVerified).toBe(false);
    const arr = ['x'] as unknown as string;
    expect(buildGoalLineage(withCommit(goalCommitOf('g', arr), arr), 'v', 'r', undefined, { goal: 'g' }).goalVerified).toBe(false);
  });
  it('period of zero renders as minutes, not days', () => {
    expect(buildGoalLineage(mk({ limits: { v: { unit: 'count', amount: 1, periodMs: 0 } } }), 'v', 'r').chain[1]!.label).toBe('Delegated authority to v (up to 1/0m)');
  });
  it('reviewAction on a grant with no readable envelope yields an empty goalCommit instead of throwing', () => {
    const bare = { ...mk({ dryRun: () => ({ allowed: true, t: 2 }) }), grant: { ...real.grant, caveats: [] } } as unknown as Agent;
    const r = reviewAction(bare, 'v', 'r', undefined, { insecureUnboundApproval: true, now: 1 });
    expect(r.kind === 'step_up' && r.request.goalCommit).toBe('');
  });
  it('dollars model with an uncatalogued verb falls back to the default blast radius', () => {
    const r = reviewAction(mk({ budgetModel: 'dollars', dryRun: () => ({ allowed: true, t: 2 }) }), 'unknown', 'r', { amt: 5 }, { insecureUnboundApproval: true, now: 1 });
    expect(r.kind === 'step_up' && r.request.r).toBe(0.8);
  });
});
