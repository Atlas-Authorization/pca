/**
 * authorize(): every pre-guard gate (linked template, forbid, workflow, contract, adaptive policy), the callbacks it hands the
 * guard (operation, plan registry context, principal commitments, escalation answer, provenance bundle, undo admission), the
 * per-request state it resets, and the post-guard checks (plan state, linked template, adaptive policy, contract, undo window).
 * The guard is replaced by a recorder (as in the guard-stub test) so each callback and each post-guard branch is driven directly.
 */
import { describe, expect, it, vi } from 'vitest';

type Guard = (req: object) => unknown;
type GuardOpts = Record<string, any>;
const state: {
  opts: GuardOpts;
  guard: Guard;
  guardCalls: number;
  admit?: (inp: Record<string, any>) => unknown;
  checkCert?: () => unknown;
  verifyLink?: () => unknown;
} = { opts: {}, guard: () => ({}), guardCalls: 0 };

vi.mock('./require-pca', async (orig) => ({
  ...(await orig<typeof import('./require-pca')>()),
  requirePCA: (o: GuardOpts) => {
    state.opts = o;
    return async (req: object) => {
      state.guardCalls++;
      return state.guard(req);
    };
  },
}));
vi.mock('../workflow', async (orig) => {
  const m = await orig<typeof import('../workflow')>();
  return { ...m, admitStep: (inp: Parameters<typeof m.admitStep>[0]) => (state.admit ? state.admit(inp as never) : m.admitStep(inp)) };
});
vi.mock('../forbid-certificate', async (orig) => {
  const m = await orig<typeof import('../forbid-certificate')>();
  return { ...m, checkForbidCertificate: (...a: Parameters<typeof m.checkForbidCertificate>) => (state.checkCert ? state.checkCert() : m.checkForbidCertificate(...a)) };
});
vi.mock('../policy-link', async (orig) => {
  const m = await orig<typeof import('../policy-link')>();
  return { ...m, verifyLinkedPolicy: (...a: Parameters<typeof m.verifyLinkedPolicy>) => (state.verifyLink ? state.verifyLink() : m.verifyLinkedPolicy(...a)) };
});

import type { Capability } from '../capability';
import { certify, type PolicyClause } from '../forbid-certificate';
import type { PCActn } from '../pcactn';
import { DEFAULT_RISK_POLICY, type RiskPolicy } from '../risk';
import { createAuthorizer, requireAuthorized, type AuthorizeOptions, type AuthorizeResult } from './authorize';

const OP = { verb: 'do', resource: 'r', params: {} };
const PC = { grant_ref: 'g', plan: { root: 'root1', node_id: 'n1' }, cap_chain: [] } as unknown as PCActn;
const BOUND = { verb: 'do', resource: 'r', params_digest: 'd', id: 'i' };
const SPEND: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const TIGHT: RiskPolicy = { ...SPEND, theta1: 0.1, theta2: 0.2 };
/** A grant whose envelope `readEnvelope` accepts. */
const envGrant = (extra: Record<string, unknown> = {}, risk_policy: RiskPolicy = DEFAULT_RISK_POLICY) =>
  ({ id: 'g', caveats: [{ type: 'envelope', goal_commit: 'c', predicates: [], caveats: [], agent_binding: {}, risk_policy, ...extra }] }) as unknown as Capability;

const verdictOk = (r = 0, t: 1 | 2 | 3 = 1) => ({ allow: true, r, requiredThreshold: { t, proof: 'claim', optimisticAllowed: true }, checks: {} as Record<string, string>, reasons: [] as string[] });
const allowResult = (extra: Record<string, unknown> = {}, v = verdictOk()) => ({ ok: true, verdict: v, pcactn: PC, operation: BOUND, ...extra });
const denyResult = (checks: Record<string, string> = { x: 'fail' }, reasons: string[] = ['x: 1'], extra: Record<string, unknown> = {}) => ({
  ok: false,
  status: 403,
  verdict: { allow: false, r: 1, requiredThreshold: { t: 3, proof: 'strong', optimisticAllowed: false }, checks: { ...checks }, reasons: [...reasons] },
  ...extra,
});

const base = (over: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
  audience: 'rs',
  resolveGrant: async () => null,
  budgetStore: { get: async () => undefined, put: async () => undefined } as never,
  hooks: { revocation: () => ({ enforced: true, ok: true }) },
  ...over,
});
const reset = (guard: Guard = () => denyResult()) => {
  state.guard = guard;
  state.guardCalls = 0;
  delete state.admit;
  delete state.checkCert;
  delete state.verifyLink;
};
/** The refusal's decisive reason and checks, or ALLOW. */
const out = (r: AuthorizeResult) => (r.allow ? 'ALLOW' : { reason: r.reason, checks: r.verdict.checks });

describe('linked template', () => {
  const registry = { templates: {}, trusted: [] };

  it('before the guard: a grant without a readable envelope is refused and the guard never runs', async () => {
    reset(() => allowResult());
    const r = await createAuthorizer(base({ requireLinkedTemplate: { registry } }))({ operation: OP, pcactn: PC });
    expect(out(r)).toStrictEqual({ reason: 'template: the grant has no readable envelope', checks: { template: 'fail' } });
    expect(state.guardCalls).toBe(0);
  });

  it('a verification without a reason is "refused"; with one it is quoted', async () => {
    reset(() => allowResult());
    const opts = base({ requireLinkedTemplate: { registry }, resolveGrant: async () => envGrant({ template_ref: 'ref' }) });
    state.verifyLink = () => ({ ok: false });
    expect(out(await createAuthorizer(opts)({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'template: refused', checks: { template: 'fail' } });
    state.verifyLink = () => ({ ok: false, reason: 'edited' });
    expect(out(await createAuthorizer(opts)({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'template: edited', checks: { template: 'fail' } });
  });

  it('after the guard: an unreadable proof up front is left to the guard, then the verified grant is checked', async () => {
    reset(() => allowResult());
    const r = await createAuthorizer(base({ requireLinkedTemplate: { registry } }))({ operation: OP });
    expect(out(r)).toStrictEqual({ reason: 'template: the grant has no readable envelope', checks: { template: 'fail' } });
    expect(state.guardCalls).toBe(1);
  });
});

describe('the callbacks handed to the guard', () => {
  it('operation: the frozen copy of the operation of this call', async () => {
    let seen: unknown;
    reset((req) => ((seen = state.opts.operation(req)), denyResult()));
    await createAuthorizer(base())({ operation: { verb: 'do', resource: 'r', params: { a: 1 } }, pcactn: PC });
    expect(seen).toEqual({ verb: 'do', resource: 'r', params: { a: 1 } });
  });

  it('undo admission: no operation is never admitted; a refused admission is undefined; an admission is converted', async () => {
    const calls: unknown[] = [];
    let ret: unknown = { refused: 'not reversible' };
    const undo = { admit: async (a: unknown) => (calls.push(a), ret), open: async () => ({}) } as never;
    reset();
    createAuthorizer(base({ undo }));
    const admit = state.opts.undo.admit as (a: unknown) => Promise<unknown>;
    expect(await admit({ pcactn: PC, grant: {}, operation: undefined })).toBeUndefined();
    expect(calls).toEqual([]);
    expect(await admit({ pcactn: PC, grant: {}, operation: OP })).toBeUndefined();
    ret = { window: 1 };
    expect(await admit({ pcactn: PC, grant: {}, operation: OP })).toEqual({ window: 1 });
    expect(calls[1]).toEqual({ pcactn: PC, grant: {}, operation: OP, converted: true });
  });
});

describe('plan registry context', () => {
  const registry = (ret: unknown) => {
    const calls: unknown[][] = [];
    return { calls, plans: { context: async (...a: unknown[]) => (calls.push(a), ret) } as never };
  };
  const drive = async (plans: never, p: unknown, over: Partial<AuthorizeOptions> = {}) => {
    let principal: unknown = 'unset';
    let ctx: unknown;
    reset(async (req) => {
      ctx = await state.opts.context(req, p);
      principal = state.opts.provenance.principal(req);
      return denyResult();
    });
    const r = await createAuthorizer(base({ plans, ...over }))({ operation: OP, pcactn: PC });
    return { r, principal, ctx };
  };

  it('a non-string or missing plan root is looked up as the empty root; the clock defaults to Date.now', async () => {
    const a = registry(undefined);
    await drive(a.plans, { ...PC, plan: { root: 5, node_id: 'n1' } });
    await drive(a.plans, { grant_ref: 'g' });
    await drive(a.plans, PC, { now: () => 42 });
    expect(a.calls.map(([g, root]) => [g, root])).toEqual([['g', ''], ['g', ''], ['g', 'root1']]);
    expect([typeof a.calls[0]![2], a.calls[2]![2]]).toEqual(['number', 42]);
  });

  it('only an authorized AND executable plan is the principal plan commitment', async () => {
    const run = async (planAuthorized: boolean, executable: boolean) => (await drive(registry({ plan: [], planAuthorized, status: { state: 's', executable } }).plans, PC)).principal;
    expect(await run(true, true)).toStrictEqual({ plan: true });
    expect(await run(false, true)).toBeUndefined();
    expect(await run(true, false)).toBeUndefined();
    expect(await run(false, false)).toBeUndefined();
  });

  it('a plan that is not executable: the state names the refusal when there is no reason', async () => {
    const { r } = await drive(registry({ plan: [], planAuthorized: false, status: { state: 'committed', executable: false } }).plans, PC);
    expect(out(r)).toStrictEqual({ reason: 'plan_state: plan is committed', checks: { x: 'fail', plan_state: 'fail' } });
  });

  it('a guard that allows a non-executable plan is still refused (with the reason, or "not executable")', async () => {
    for (const [status, reason] of [
      [{ state: 'committed', executable: false }, 'plan_state: not executable'],
      [{ state: 'committed', executable: false, reason: 'approval expired' }, 'plan_state: approval expired'],
    ] as const) {
      reset(async (req) => (await state.opts.context(req, PC), allowResult()));
      const r = await createAuthorizer(base({ plans: { context: async () => ({ plan: [], planAuthorized: false, status }) } as never }))({ operation: OP, pcactn: PC });
      expect(out(r)).toStrictEqual({ reason, checks: { plan_state: 'fail' } });
    }
  });
});

describe('per-request state is reset on every call with the same request object', () => {
  it('plan state, escalation answer, provenance bundle and principal commitments never leak into the next call', async () => {
    let known = false;
    const plans = { context: async () => (known ? { plan: [], planAuthorized: true, status: { state: 'authorized', executable: true } } : undefined) } as never;
    const escalation = { principals: ['k'], answer: () => 'USER' };
    const provenance = { bundle: () => 'USER-BUNDLE' };
    const az = createAuthorizer(base({ plans, escalation, provenance }));
    const req = { headers: {} };
    const seen: unknown[] = [];
    // first call: an unknown plan root (plan_state recorded), an answer and a bundle carried by the call
    reset(async (rq) => {
      await state.opts.context(rq, PC);
      seen.push(await state.opts.escalation.answer(rq, PC), await state.opts.provenance.bundle(rq, PC, OP));
      return denyResult();
    });
    const first = await az({ operation: OP, pcactn: PC, request: req, escalationAnswer: 'ANSWER', provenance: 'CALL-BUNDLE' });
    expect(first.verdict.checks).toStrictEqual({ x: 'fail', plan_state: 'fail' });
    // second call: nothing carried, the guard does not consult the registry
    reset(async (rq) => {
      seen.push(await state.opts.escalation.answer(rq, PC), await state.opts.provenance.bundle(rq, PC, OP));
      return denyResult();
    });
    const second = await az({ operation: OP, pcactn: PC, request: req });
    expect(second.verdict.checks).toStrictEqual({ x: 'fail' });
    expect(seen).toEqual(['ANSWER', 'CALL-BUNDLE', 'USER', 'USER-BUNDLE']);
    // a plan commitment of one call is gone in the next
    known = true;
    const principals: unknown[] = [];
    reset(async (rq) => (await state.opts.context(rq, PC), principals.push(state.opts.provenance.principal(rq)), denyResult()));
    await az({ operation: OP, pcactn: PC, request: req });
    reset(async (rq) => (principals.push(state.opts.provenance.principal(rq)), denyResult()));
    await az({ operation: OP, pcactn: PC, request: req });
    expect(principals).toStrictEqual([{ plan: true }, undefined]);
  });
});

describe('forbid', () => {
  const permit = (o: Partial<PolicyClause> = {}): PolicyClause => ({ id: 'p', kind: 'permit', when: { verb: 'do' }, ...o });

  it('the clause source gets the grant resolved from the presented proof', async () => {
    let grant: unknown = 'unset';
    const G = envGrant();
    reset();
    await createAuthorizer(base({ resolveGrant: async (ref) => (ref === 'g' ? G : null), forbid: { clauses: (_o, g) => ((grant = g), [permit()]) } }))({ operation: OP, pcactn: PC });
    expect(grant).toBe(G);
  });

  it('the subject from context() is what the clauses see', async () => {
    reset(() => allowResult());
    const clauses = [permit({ when: { verb: 'do', where: [{ field: 'subject.role', op: 'eq', value: 'admin' }] } })];
    const r = await createAuthorizer(base({ forbid: { clauses: () => clauses, context: () => ({ subject: { role: 'admin' } }) } }))({ operation: OP, pcactn: PC });
    expect(r.allow).toBe(true);
  });

  it('permitSigners drops a permit from another signer: default deny, no winner id', async () => {
    reset(() => allowResult());
    const r = await createAuthorizer(base({ forbid: { clauses: () => [permit({ signer: 'user' })], permitSigners: ['org'] } }))({ operation: OP, pcactn: PC });
    expect(out(r)).toStrictEqual({ reason: 'forbid: deny by none', checks: { forbid: 'fail' } });
  });

  it('precedence names the most authoritative matching forbid', async () => {
    reset(() => allowResult());
    const clauses: PolicyClause[] = [
      { id: 'f-a', kind: 'forbid', signer: 'user', when: { verb: 'do' } },
      { id: 'f-b', kind: 'forbid', signer: 'org', when: { verb: 'do' } },
      permit(),
    ];
    const r = await createAuthorizer(base({ forbid: { clauses: () => clauses, precedence: ['org', 'user'] } }))({ operation: OP, pcactn: PC });
    expect(out(r)).toStrictEqual({ reason: 'forbid: deny by forbid f-b', checks: { forbid: 'fail' } });
  });

  it('requireCertificate: missing, refused with the reason, refused without one', async () => {
    reset(() => allowResult());
    const f = { clauses: () => [permit()], requireCertificate: true };
    const az = createAuthorizer(base({ forbid: f }));
    expect(out(await az({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'forbid: the call carries no certificate (fail closed)', checks: { forbid: 'fail' } });
    const forged = { ...certify([permit()], { action: { verb: 'do', resource: 'r', params: {} } }), decision: 'deny' as const };
    expect(out(await az({ operation: OP, pcactn: PC, forbidCertificate: forged }))).toStrictEqual({ reason: 'forbid: certificate refused (certificate table does not entail its decision)', checks: { forbid: 'fail' } });
    state.checkCert = () => ({ ok: false });
    expect(out(await az({ operation: OP, pcactn: PC, forbidCertificate: forged }))).toStrictEqual({ reason: 'forbid: certificate refused (mismatch)', checks: { forbid: 'fail' } });
  });
});

describe('workflow', () => {
  const wf = { principal: 'pk', rsSigner: 'rk' };
  const step = { commitment: {}, receipts: [], step: 's1' };
  const drive = async (pcactn: unknown, decision: { decision: string; code: string | null; step: string | null }) => {
    const admitted: Record<string, any>[] = [];
    let principal: unknown = 'unset';
    reset((req) => ((principal = state.opts.provenance.principal(req)), denyResult()));
    state.admit = (inp) => (admitted.push(inp), decision);
    const r = await createAuthorizer(base({ workflow: wf }))({ operation: OP, pcactn: pcactn as never, workflow: step });
    return { r, admitted, principal };
  };
  const ALLOW = { decision: 'allow', code: null, step: null };

  it('the plan root handed to admitStep: the string root, else null (also without a plan)', async () => {
    expect((await drive(PC, ALLOW)).admitted.map((i) => i.request.plan_root)).toEqual(['root1']);
    expect((await drive({ ...PC, plan: { root: 7 } }, ALLOW)).admitted.map((i) => i.request.plan_root)).toEqual([null]);
    expect((await drive({ grant_ref: 'g' }, ALLOW)).admitted.map((i) => i.request.plan_root)).toEqual([null]);
  });

  it('a proof that is not an object is not judged by the workflow and commits nothing', async () => {
    const d = await drive(5, { decision: 'deny', code: 'x', step: null });
    expect([d.admitted.length, d.principal, out(d.r)]).toStrictEqual([0, undefined, { reason: 'x: 1', checks: { x: 'fail' } }]);
  });

  it('an admitted step of a readable proof is the principal control commitment', async () => {
    expect((await drive(PC, ALLOW)).principal).toStrictEqual({ control: true });
  });

  it('a refusal without a code or step is "refused"', async () => {
    expect(out((await drive(PC, { decision: 'deny', code: null, step: null })).r)).toStrictEqual({ reason: 'workflow: refused', checks: { workflow: 'fail' } });
  });
});

describe('contracts', () => {
  const enforcer = (peek: unknown, check: unknown = { allow: true, violated: [] }) => ({ peek: async () => peek, check: async () => check }) as never;

  it('before the guard: the violated clause ids are joined with commas; none = no suffix', async () => {
    reset(() => allowResult());
    expect(out(await createAuthorizer(base({ contracts: enforcer({ allow: false, reason: 'violated', violated: ['a', 'b'] }) }))({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'contract: violated (a,b)', checks: { contract: 'fail' } });
    expect(out(await createAuthorizer(base({ contracts: enforcer({ allow: false, reason: 'latched', violated: [] }) }))({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'contract: latched', checks: { contract: 'fail' } });
    expect(state.guardCalls).toBe(0);
  });

  it('after the guard: the commit refusal is reported the same way', async () => {
    reset(() => allowResult());
    const ok = { allow: true, violated: [] };
    expect(out(await createAuthorizer(base({ contracts: enforcer(ok, { allow: false, reason: 'violated', violated: ['a', 'b'] }) }))({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'contract: violated (a,b)', checks: { contract: 'fail' } });
    expect(out(await createAuthorizer(base({ contracts: enforcer(ok, { allow: false, reason: 'race', violated: [] }) }))({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'contract: race', checks: { contract: 'fail' } });
    expect((await createAuthorizer(base({ contracts: enforcer(ok, ok) }))({ operation: OP, pcactn: PC })).allow).toBe(true);
  });

  // `contracts` read as an accessor: read 1 when the authorizer is built, then once per use in the call.
  const flipping = (until: number) => {
    let reads = 0;
    const e = enforcer({ allow: true, violated: [] }, { allow: false, reason: 'violated', violated: [] });
    const opts = base();
    Object.defineProperty(opts, 'contracts', { enumerable: true, get: () => (++reads <= until ? e : undefined) });
    return opts;
  };
  it('the pre-guard check needs the enforcer at the moment it is checked', async () => {
    reset();
    expect(out(await createAuthorizer(flipping(2))({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'x: 1', checks: { x: 'fail' } });
  });
  it('the commit after the guard needs the enforcer at the moment it is committed', async () => {
    reset(() => allowResult());
    expect((await createAuthorizer(flipping(4))({ operation: OP, pcactn: PC })).allow).toBe(true);
  });
});

describe('adaptive policy', () => {
  it('is asked with the configured clock', async () => {
    let at: unknown;
    reset();
    await createAuthorizer(base({ now: () => 777, adaptivePolicy: (n) => ((at = n), undefined) }))({ operation: OP, pcactn: PC });
    expect(at).toBe(777);
  });

  it('an invalid policy is refused under the adaptive check', async () => {
    reset();
    const r = await createAuthorizer(base({ adaptivePolicy: () => ({}) as RiskPolicy }))({ operation: OP, pcactn: PC });
    expect(out(r)).toStrictEqual({ reason: 'adaptive: invalid policy (risk_policy.weights missing)', checks: { adaptive: 'fail' } });
  });

  it('server risk is priced up front only when the presented grant has an envelope', async () => {
    let priced = 0;
    reset();
    await createAuthorizer(base({ adaptivePolicy: () => TIGHT, risk: () => ((priced++), { blastRadius: 1 }) }))({ operation: OP, pcactn: PC });
    expect(priced).toBe(0);
  });

  it('a tightened threshold is refused before the guard, under the adaptive check', async () => {
    reset(() => allowResult());
    const opts = base({ resolveGrant: async () => envGrant({}, SPEND), adaptivePolicy: () => TIGHT, risk: () => ({ blastRadius: 1, semanticDistance: 0, reversibility: 1, taint: 0, confidence: 1 }) });
    expect(out(await createAuthorizer(opts)({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'adaptive: tightened policy requires threshold t=3 (grant policy: t=1)', checks: { adaptive: 'fail' } });
    expect(state.guardCalls).toBe(0);
  });

  it('and after the guard against the verified risk, under the adaptive check', async () => {
    reset(() => allowResult({}, verdictOk(1, 1)));
    expect(out(await createAuthorizer(base({ adaptivePolicy: () => TIGHT }))({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'adaptive: tightened policy requires threshold t=3 (grant policy: t=1)', checks: { adaptive: 'fail' } });
  });
});

describe('undo windows after the guard', () => {
  const coordinator = (admitted: unknown, fail?: unknown) => {
    const opened: unknown[] = [];
    const undo = {
      admit: async () => admitted,
      open: async (a: unknown) => {
        opened.push(a);
        if (fail !== undefined) throw fail;
        return { window: 'w' };
      },
    } as never;
    return { undo, opened };
  };

  it('a refused admission opens no window', async () => {
    reset(() => allowResult());
    const c = coordinator({ refused: 'irreversible' });
    const r = await createAuthorizer(base({ undo: c.undo }))({ operation: OP, pcactn: PC });
    expect([r.allow, r.allow && 'undo' in r, c.opened]).toEqual([true, false, []]);
  });

  it('a converted escalation whose window cannot be opened is refused (non-Error = "error")', async () => {
    reset(() => allowResult({ undo: { adm: 1 } }));
    const c = coordinator({ refused: 'x' }, 'disk full');
    expect(out(await createAuthorizer(base({ undo: c.undo }))({ operation: OP, pcactn: PC }))).toStrictEqual({ reason: 'undo: the veto window could not be opened (error) (fail closed)', checks: { undo_window: 'fail' } });
    expect(c.opened).toEqual([{ adm: 1 }]);
  });
});

describe('the result shapes', () => {
  it('authorize: an allow says decision allow and carries the escalation answer', async () => {
    reset(() => allowResult({ escalation: { answered_by: 'k' } }));
    const r = await createAuthorizer(base())({ operation: OP, pcactn: PC });
    expect(r.allow && [r.decision, r.escalation]).toEqual(['allow', { answered_by: 'k' }]);
  });

  it('requireAuthorized: allow and refusal both carry decision and escalation', async () => {
    const guard = requireAuthorized({ ...base(), operation: () => OP });
    reset(() => allowResult({ escalation: { answered_by: 'k' } }));
    const a = await guard({ headers: {} });
    expect(a.ok && [a.decision, a.escalation, a.operation]).toEqual(['allow', { answered_by: 'k' }, BOUND]);
    const esc = { id: 'e1' };
    reset(() => denyResult({ x: 'fail' }, ['x: 1'], { decision: 'escalate', escalation: esc }));
    const d = await guard({ headers: {} });
    expect(!d.ok && [d.decision, d.status, d.escalation]).toEqual(['escalate', 403, esc]);
  });
});
