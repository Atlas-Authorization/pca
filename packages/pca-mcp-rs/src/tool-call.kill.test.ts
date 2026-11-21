/** Kill tests for authorizeToolCall / toolCallRisk with the full verifier and the envelope reader controlled, so each branch is reached in isolation. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { agent, generateKeyPair, merkleRoot, pcaHeaders, planNodeLeaf, type Capability } from '@atlasauth/pca';
import { WELL_KNOWN_OAUTH_PRM, authorizeToolCall, toolCallRisk, type AuthorizeToolCallOptions, type ToolActionMap } from './index';

const st = vi.hoisted(() => ({
  result: undefined as unknown,
  calls: [] as unknown[][],
  env: { on: false, value: undefined as unknown },
}));

vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return {
    ...actual,
    authorize: async (...a: unknown[]) => {
      st.calls.push(a);
      return st.result !== undefined ? st.result : (actual.authorize as (...x: unknown[]) => unknown)(...a);
    },
    readEnvelope: (g: unknown) => (st.env.on ? st.env.value : (actual.readEnvelope as (x: unknown) => unknown)(g)),
  };
});

const RESOURCE = 'https://mcp.example.com/mcp';
const PRM_URL = `https://mcp.example.com${WELL_KNOWN_OAUTH_PRM}`;
const toolAction: ToolActionMap = (tool, args) => (tool === 'refund' ? { verb: 'stripe.refund', resource: `charge:${String(args['chargeId'])}` } : null);

function setup() {
  const a = agent({ principal: generateKeyPair(), goal: 'refund customers', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: RESOURCE });
  a.provenance?.principal('refund the broken orders');
  const grants = new Map<string, Capability>([[a.grant.id, a.grant]]);
  const state = { get: async () => undefined, put: async () => undefined } as never;
  const args = { chargeId: 'ch_1', amount: 42 };
  const act = a.act('stripe.refund', 'charge:ch_1', args, { aud: RESOURCE });
  const req = { headers: pcaHeaders(act.encoded, act.provenance) };
  const base: AuthorizeToolCallOptions = {
    resource: RESOURCE,
    prmUrl: PRM_URL,
    tool: 'refund',
    args,
    toolAction,
    resolveGrant: (ref) => grants.get(ref) ?? null,
    state,
    isRevoked: () => false,
  };
  const call = (extra: Partial<AuthorizeToolCallOptions> = {}, r: { headers: Record<string, string> } = req) => authorizeToolCall(r, { ...base, ...extra });
  return { a, base, call, req, args, grants };
}

const denied = (verdict: Record<string, unknown>, status = 403) => {
  st.result = { allow: false, status, verdict: { checks: {}, reasons: [], ...verdict } };
};
const reasonOf = (r: Awaited<ReturnType<typeof authorizeToolCall>>) => (r.ok ? undefined : r.reason);
const hintOf = (r: Awaited<ReturnType<typeof authorizeToolCall>>) => (r.ok ? undefined : r.hint);

beforeEach(() => {
  st.result = undefined;
  st.calls = [];
  st.env = { on: false, value: undefined };
});

describe('the decisive reason of a verifier denial', () => {
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ['the params_digest reason outranks a failing operation check', { checks: { operation: 'fail', params_digest: 'fail' }, reasons: ['operation: OP', 'params_digest: PD'] }, 'params_digest: PD'],
    ['a failing operation check alone is reported', { checks: { operation: 'fail' }, reasons: ['operation: OP'] }, 'operation: OP'],
    ['passing checks are skipped and the policy prefix is stripped', { checks: { wire: 'pass', policy: 'fail' }, reasons: ['wire: fine', 'policy: P'] }, 'P'],
    ['a failing check with no reason of its own falls back to the first reason', { checks: { x: 'fail' }, reasons: ['other: Z'] }, 'other: Z'],
    ['risk-input noise is not the decisive reason', { checks: { policy: 'fail' }, reasons: ['policy: risk input(s) missing q', 'policy: real'] }, 'real'],
    ['the first non-noise reason wins when no check names it', { checks: {}, reasons: ['risk input(s) missing a', 'zzz'] }, 'zzz'],
    ['noise only: the first reason', { checks: {}, reasons: ['risk input(s) missing a'] }, 'risk input(s) missing a'],
    ['no reasons at all', { checks: {}, reasons: [] }, 'denied'],
    ['only a leading "policy: " is stripped', { checks: {}, reasons: ['zz policy: q'] }, 'zz policy: q'],
  ];
  it.each(cases)('%s', async (_n, verdict, reason) => {
    const { call } = setup();
    denied(verdict);
    const r = await call();
    expect(r).toMatchObject({ ok: false, status: 403, error: 'forbidden', reason });
  });
});

describe('plain-language explanation of "no predicate permits"', () => {
  const noPermit = { checks: { policy: 'fail' }, reasons: ['policy: no predicate permits stripe.refund on charge:ch_1'] };
  const cond = (field: string, op: string, value: unknown) => ({ field, op, value });
  it('a grant with no envelope permits nothing', async () => {
    const { call } = setup();
    st.env = { on: true, value: null };
    denied(noPermit);
    expect(reasonOf(await call())).toBe('the grant does not permit stripe.refund (it permits: nothing)');
    st.env = { on: true, value: { predicates: [] } };
    expect(reasonOf(await call())).toBe('the grant does not permit stripe.refund (it permits: nothing)');
  });
  it('lists every verb the grant does permit', async () => {
    const { call } = setup();
    st.env = { on: true, value: { predicates: [{ verb: ['a.b', 'c.d'] }, { verb: 'e.f' }] } };
    denied(noPermit);
    expect(reasonOf(await call())).toBe('the grant does not permit stripe.refund (it permits: a.b, c.d, e.f)');
  });
  it('a wildcard, an exact verb and a verb list each count as a predicate for the verb', async () => {
    const { call } = setup();
    denied(noPermit);
    const want = (verb: unknown) => {
      st.env = { on: true, value: { predicates: [{ verb: 'zzz.other' }, { verb, where: [cond('action.params.amount', 'lte', 500)] }] } };
      return call();
    };
    for (const verb of ['*', 'stripe.refund', ['x.y', 'stripe.refund']]) {
      expect(reasonOf(await want(verb))).toBe("stripe.refund on charge:ch_1 is outside the grant's limits (amount <= 500)");
    }
    expect(reasonOf(await want(['x.y']))).toMatch(/^the grant does not permit stripe\.refund \(it permits: zzz\.other, x\.y\)$/);
    expect(reasonOf(await want('stripe.refund2'))).toMatch(/^the grant does not permit/);
  });
  it('spells every operator and joins the limits with ", "', async () => {
    const { call } = setup();
    st.env = {
      on: true,
      value: {
        predicates: [
          {
            verb: 'stripe.refund',
            where: [cond('action.params.p1', 'lte', 1), cond('action.params.p2', 'lt', 2), cond('action.params.p3', 'gte', 3), cond('action.params.p4', 'gt', 4), cond('action.params.p5', 'eq', 'five'), cond('p6.action.params.x', 'neq', 6), cond('p7', 'in', ['a']), cond('p8', 'weird', 8)],
          },
        ],
      },
    };
    denied(noPermit);
    expect(reasonOf(await call())).toBe(
      `stripe.refund on charge:ch_1 is outside the grant's limits (p1 <= 1, p2 < 2, p3 >= 3, p4 > 4, p5 == "five", p6.action.params.x != 6, p7 in ["a"], p8 weird 8)`,
    );
  });
  it('conditions without a field and an operator are not limits; no limits means the plain reason', async () => {
    const { call } = setup();
    denied(noPermit);
    st.env = { on: true, value: { predicates: [{ verb: 'stripe.refund' }] } };
    expect(reasonOf(await call())).toBe('no predicate permits stripe.refund on charge:ch_1');
    st.env = { on: true, value: { predicates: [{ verb: 'stripe.refund', where: [{ type: 't' }, { field: 'f', value: 1 }, { op: 'lte', value: 1 }] }] } };
    expect(reasonOf(await call())).toBe('no predicate permits stripe.refund on charge:ch_1');
    st.env = { on: true, value: { predicates: [{ verb: 'stripe.refund', where: [{ type: 't' }, cond('action.params.q', 'eq', 's')] }] } };
    expect(reasonOf(await call())).toBe(`stripe.refund on charge:ch_1 is outside the grant's limits (q == "s")`);
  });
});

describe('developer hints', () => {
  const HINTS: Array<[string, string, string]> = [
    ['trust budget depleted: B=0', 'trust budget', 'the agent spent its trust budget; for money-moving calls make sure the server prices them (toolCallRisk / the `risk` option), or recharge the budget'],
    ['counter: 1 is not greater than 1', 'counter', 'each PCActn is single-use: the agent must build a fresh one per call (pcaFetch / bridgeToolCall do)'],
    ['replay: seen', 'replay', 'each PCActn is single-use: the agent must build a fresh one per call (pcaFetch / bridgeToolCall do)'],
    ['x replay y', 'replay', 'each PCActn is single-use: the agent must build a fresh one per call (pcaFetch / bridgeToolCall do)'],
    ['plan_root_authorized: no', 'plan', '`isPlanAuthorized` did not approve this plan root'],
    ['revocation: revoked', 'revocation', '`isRevoked` reported the grant as revoked'],
    ['audience: wrong', 'audience', 'mint the PCActn for this server: its aud must equal the `resource` option'],
  ];
  it.each(HINTS)('%s', async (reason, _k, hint) => {
    const { call } = setup();
    denied({ checks: {}, reasons: [reason] });
    const r = await call();
    expect(hintOf(r)).toBe(hint);
  });
  it.each(['xxcounter: a', 'x plan_root_authorized', 'x revocation', 'x audience', 'zzz', 'trust: nope'])('%s has no hint', async (reason) => {
    const { call } = setup();
    denied({ checks: {}, reasons: [reason] });
    const r = await call();
    expect('hint' in r).toBe(false);
  });
});

describe('the co-sign explanation', () => {
  const coSign = { checks: { threshold: 'fail', policy: 'pass' }, reasons: ['threshold: needs more'], requiredThreshold: { t: 2 }, r: 0.456 };
  it('names the threshold and the risk, with the hint to supply risk inputs', async () => {
    const { call } = setup();
    denied(coSign);
    const r = await call();
    expect(reasonOf(r)).toBe("stripe.refund on charge:ch_1 needs a co-sign at threshold t=2 (risk 0.46 under the grant's risk policy)");
    expect(hintOf(r)).toBe('supply the risk inputs your server can vouch for in the `risk` option (a grant with money limits is priced by toolCallRisk), or collect the co-sign with the PCA step-up flow');
  });
  it('mentions worst-case pricing only when risk inputs were missing', async () => {
    const { call } = setup();
    denied({ ...coSign, reasons: ['risk input(s) missing semanticDistance', 'threshold: needs more'] });
    expect(reasonOf(await call())).toBe("stripe.refund on charge:ch_1 needs a co-sign at threshold t=2 (risk 0.46 under the grant's risk policy); risk inputs the server did not supply were priced at the worst case");
    denied({ ...coSign, reasons: ['threshold: a', 'risk input(s) missing q'] });
    expect(reasonOf(await call())).toMatch(/worst case$/);
  });
  it('a failing policy check alongside the threshold is a policy denial, not a co-sign request', async () => {
    const { call } = setup();
    denied({ ...coSign, checks: { threshold: 'fail', policy: 'fail' }, reasons: ['policy: P'] });
    const r = await call();
    expect(reasonOf(r)).toBe('P');
    expect('hint' in r).toBe(false);
  });
  it('the status picks the error code: 401 invalid_token, anything else forbidden', async () => {
    const { call } = setup();
    denied({ checks: {}, reasons: ['x'] }, 401);
    const r401 = await call();
    expect(r401).toMatchObject({ ok: false, status: 401, error: 'invalid_token', checks: {} });
    expect(r401.ok === false && r401.wwwAuthenticate).toBe(`Bearer realm="pca", resource_metadata="${PRM_URL}", error="invalid_token"`);
    denied({ checks: { a: 'pass' }, reasons: ['x'] }, 403);
    expect(await call()).toMatchObject({ ok: false, status: 403, error: 'forbidden', checks: { a: 'pass' } });
  });
});

describe('an allowed call', () => {
  it('returns the verified proof, the grant, the scopes and the operation', async () => {
    const { call, grants, a } = setup();
    const pcactn = { grant_ref: 'g' };
    const verdict = { allow: true, checks: {} };
    const operation = { verb: 'stripe.refund', resource: 'charge:ch_1', params: {} };
    st.result = { allow: true, pcactn, verdict, operation };
    const r = await call();
    expect(r).toMatchObject({ ok: true, status: 200, pcactn, verdict, operation });
    expect(r.ok && r.grant).toBe(grants.get(a.grant.id));
    expect(r.ok && Array.isArray(r.grantedScopes)).toBe(true);
  });
});

describe('what is handed to the full verifier', () => {
  const allow = () => {
    st.result = { allow: true, pcactn: {}, verdict: {}, operation: {} };
  };
  const optsOf = (): Record<string, any> => st.calls[0]![1] as Record<string, any>;
  it('binds the operation to the mapped call and forwards the request', async () => {
    const { call, req, args } = setup();
    allow();
    await call();
    expect(st.calls[0]![0]).toStrictEqual({ operation: { verb: 'stripe.refund', resource: 'charge:ch_1', params: args }, request: req });
    expect(optsOf().audience).toBe(RESOURCE);
  });
  it('defaults: ed25519 only and no optional gates', async () => {
    const { call, base } = setup();
    allow();
    await call();
    const o = optsOf();
    expect(o.allowedSuites).toEqual(['ed25519']);
    for (const k of ['pqPins', 'enforce', 'multiInstance', 'replayScope', 'claimRetries', 'provenance']) expect(k in o).toBe(false);
    expect(o.budgetStore).toBe(base.state);
    expect(o.now).toBe(Date.now);
  });
  it('forwards every optional gate that is set', async () => {
    const { call } = setup();
    allow();
    const now = () => Date.now();
    const extra = { allowedSuites: ['ed25519', 'ml-dsa-65'], pqPins: { k: 'v' }, enforce: { a: 1 }, multiInstance: true, replayScope: 'tenant', claimRetries: 3, provenance: { p: 1 }, now };
    await call(extra as never);
    const o = optsOf();
    expect(o.allowedSuites).toEqual(['ed25519', 'ml-dsa-65']);
    expect(o.pqPins).toEqual({ k: 'v' });
    expect(o.enforce).toEqual({ a: 1 });
    expect(o.multiInstance).toBe(true);
    expect(o.replayScope).toBe('tenant');
    expect(o.claimRetries).toBe(3);
    expect(o.provenance).toEqual({ p: 1 });
    expect(o.now).toBe(now);
  });
  it('falsy-but-set gates are still forwarded', async () => {
    const { call } = setup();
    allow();
    await call({ multiInstance: false, claimRetries: 0, replayScope: '' } as never);
    const o = optsOf();
    expect(o.multiInstance).toBe(false);
    expect(o.claimRetries).toBe(0);
    expect(o.replayScope).toBe('');
  });
  it('the grant lookup turns undefined into null; revocation is enforced and ok only when not revoked', async () => {
    const { call, grants } = setup();
    allow();
    let revoked: unknown = false;
    let lookups = 0;
    await call({ resolveGrant: (ref) => (lookups++ === 0 ? grants.get(ref) : (undefined as never)), isRevoked: () => revoked as never });
    const o = optsOf();
    expect(await o.resolveGrant('x', {})).toBeNull();
    const g = {} as Capability;
    expect(await o.hooks.revocation({ grant: g })).toEqual({ enforced: true, ok: true });
    revoked = true;
    expect(await o.hooks.revocation({ grant: g })).toEqual({ enforced: true, ok: false });
    revoked = 1;
    expect(await o.hooks.revocation({ grant: g })).toEqual({ enforced: true, ok: true });
  });
  it('a store-less agent starts at the grant signed bMax, or 0 without an envelope', async () => {
    const { call } = setup();
    allow();
    await call();
    const o = optsOf();
    st.env = { on: true, value: { risk_policy: { bMax: 7 } } };
    expect(o.seedBudget({}, 5)).toEqual({ B: 7, tau: 5, asOf: 5 });
    st.env = { on: true, value: null };
    expect(o.seedBudget({}, 5)).toEqual({ B: 0, tau: 5, asOf: 5 });
    st.env = { on: true, value: { risk_policy: {} } };
    expect(o.seedBudget({}, 6)).toEqual({ B: 0, tau: 6, asOf: 6 });
  });
  describe('the per-call context', () => {
    const pcOf = (root?: string) => {
      const node = { id: 'n1', verb: 'stripe.refund', resource: 'charge:ch_1', params_digest: 'pd', reversibility_class: 'reversible' };
      return { pc: { grant_ref: 'g', plan: { node_id: 'n1', root: root ?? merkleRoot([node as never].map(planNodeLeaf)) }, action: { verb: node.verb, resource: node.resource, params_digest: 'pd', reversibility_class: 'reversible' } } as never, node };
    };
    it('prices the call from the verified amount and approves a consistent plan', async () => {
      const { call, args } = setup();
      allow();
      st.env = { on: true, value: { risk_policy: { kappa: 500 } } };
      await call();
      const { pc, node } = pcOf();
      expect(await optsOf().context({}, pc)).toStrictEqual({ params: args, plan: [node], planAuthorized: true, risk: { blastRadius: 42 / 500 } });
    });
    it('omits the risk when there is nothing to price, and takes the option when given', async () => {
      const { call } = setup();
      allow();
      st.env = { on: true, value: null };
      await call();
      const { pc } = pcOf();
      const ctx = await optsOf().context({}, pc);
      expect('risk' in ctx).toBe(false);
      st.calls = [];
      allow();
      const seen: unknown[] = [];
      await call({ risk: (g, a, p) => (seen.push(g, a, p), { blastRadius: 0.25 }) });
      const ctx2 = await optsOf().context({}, pc);
      expect(ctx2.risk).toEqual({ blastRadius: 0.25 });
      expect(seen[2]).toBe(pc);
      expect(seen[1]).toEqual({ chargeId: 'ch_1', amount: 42 });
    });
    it('the plan is authorized only when it matches the signed root and the server approves it', async () => {
      const { call } = setup();
      allow();
      await call();
      const good = pcOf();
      expect((await optsOf().context({}, pcOf('A'.repeat(43)).pc)).planAuthorized).toBe(false);
      for (const [approve, expected] of [[true, true], [false, false], ['yes', false], [undefined, false]] as const) {
        st.calls = [];
        allow();
        await call({ isPlanAuthorized: async () => approve as never });
        expect((await optsOf().context({}, good.pc)).planAuthorized, String(approve)).toBe(expected);
        expect((await optsOf().context({}, pcOf('A'.repeat(43)).pc)).planAuthorized).toBe(false);
      }
    });
    it('passes the grant reference and plan root to isPlanAuthorized', async () => {
      const { call } = setup();
      allow();
      const seen: unknown[][] = [];
      await call({ isPlanAuthorized: (...a: unknown[]) => (seen.push(a), true) as never });
      const { pc } = pcOf();
      await optsOf().context({}, pc);
      expect(seen).toEqual([['g', (pc as { plan: { root: string } }).plan.root]]);
    });
  });
});

describe('refusals before the verifier', () => {
  const missingHint = 'authorizeRequest and authorizeToolCall authorize the whole call; pass these, or call authorizeRequest with admissionOnly: true to check admission alone';
  const noop = () => undefined;
  const cases: Array<[string, Partial<Record<string, unknown>>, string]> = [
    ['an empty tool', { tool: '' }, 'tool'],
    ['a non-string tool with a length', { tool: ['x'] }, 'tool'],
    ['no toolAction', { toolAction: undefined }, 'toolAction'],
    ['no resolveGrant', { resolveGrant: undefined }, 'resolveGrant'],
    ['no state', { state: undefined }, 'state'],
    ['a state without get', { state: { put: noop } }, 'state'],
    ['a state without put', { state: { get: noop } }, 'state'],
    ['no isRevoked', { isRevoked: undefined }, 'isRevoked'],
    ['everything', { tool: '', toolAction: undefined, resolveGrant: undefined, state: {}, isRevoked: undefined }, 'tool, toolAction, resolveGrant, state, isRevoked'],
  ];
  it.each(cases)('%s is refused naming what is missing', async (_n, patch, missing) => {
    const { call } = setup();
    const r = await call(patch as never);
    expect(r).toStrictEqual({
      ok: false,
      status: 403,
      error: 'forbidden',
      reason: `authorization is not configured: missing ${missing} (fail closed)`,
      wwwAuthenticate: `Bearer realm="pca", resource_metadata="${PRM_URL}", error="forbidden"`,
      hint: missingHint,
    });
    expect(st.calls).toEqual([]);
  });
  it('a custom realm is used in every challenge', async () => {
    const { call } = setup();
    const r = await call({ tool: '', realm: 'acme' } as never);
    expect(r.ok === false && r.wwwAuthenticate).toBe(`Bearer realm="acme", resource_metadata="${PRM_URL}", error="forbidden"`);
  });
  it('arguments that are not an object reach the tool mapping as an empty object', async () => {
    const { call, args } = setup();
    const seen: unknown[] = [];
    const spy: ToolActionMap = (t, a) => (seen.push(a), null);
    for (const bad of [null, 'x', 5, undefined]) await call({ args: bad as never, toolAction: spy });
    expect(seen).toEqual([{}, {}, {}, {}]);
    await call({ toolAction: spy });
    expect(seen[4]).toBe(args);
  });
  it('an unmapped tool is refused with a hint', async () => {
    const { call } = setup();
    const r = await call({ tool: 'nope' });
    expect(r).toStrictEqual({
      ok: false,
      status: 403,
      error: 'forbidden',
      reason: "tool 'nope' has no PCA mapping on this server",
      wwwAuthenticate: `Bearer realm="pca", resource_metadata="${PRM_URL}", error="forbidden"`,
      hint: 'add the tool to your `toolAction` mapping',
    });
    expect(st.calls).toEqual([]);
  });
  it('a proof for another verb or another resource is refused, each on its own', async () => {
    const { call } = setup();
    const hint = 'the agent must sign the action this tool call maps to, with the same `toolAction` mapping (pcaFetch does this per call)';
    const other = await call({ toolAction: () => ({ verb: 'other.verb', resource: 'charge:ch_1' }) });
    expect(other).toMatchObject({ ok: false, status: 403, error: 'forbidden', reason: 'the proof is for stripe.refund on charge:ch_1, but this call is other.verb on charge:ch_1', hint });
    const res = await call({ toolAction: () => ({ verb: 'stripe.refund', resource: 'charge:other' }) });
    expect(res).toMatchObject({ ok: false, status: 403, error: 'forbidden', reason: 'the proof is for stripe.refund on charge:ch_1, but this call is stripe.refund on charge:other', hint });
    expect(st.calls).toEqual([]);
  });
  it('a thrown error is a fail-closed refusal', async () => {
    const { call } = setup();
    const r = await call({ toolAction: () => { throw new Error('boom'); } });
    expect(r).toStrictEqual({ ok: false, status: 403, error: 'forbidden', reason: 'authorization error (fail closed): boom', wwwAuthenticate: `Bearer realm="pca", resource_metadata="${PRM_URL}", error="forbidden"` });
    const r2 = await call({ toolAction: () => { throw 'str'; } });
    expect(r2.ok === false && r2.reason).toBe('authorization error (fail closed): unknown');
  });
});

describe('admission refusals are passed through', () => {
  it('a missing proof is explained for the tool; an unreadable one keeps its own description', async () => {
    const { call } = setup();
    const none = await call({}, { headers: {} });
    expect(none).toMatchObject({ ok: false, status: 401, error: 'invalid_request', reason: "tool 'refund' requires a proof-carrying action: send it in the PCA-Action header" });
    const bad = await call({}, { headers: { 'pca-action': '!!not base64url!!' } });
    expect(bad).toMatchObject({ ok: false, status: 401, error: 'invalid_request' });
    expect(reasonOf(bad)).toMatch(/^unreadable PCActn: /);
  });
  it('an unregistered grant has a hint and none of the optional members', async () => {
    const { call, grants } = setup();
    grants.clear();
    const r = await call();
    expect(r).toMatchObject({ ok: false, status: 401, error: 'invalid_token', reason: 'unknown grant_ref' });
    expect(hintOf(r)).toMatch(/resolveGrant found no grant/);
    expect('stepUp' in r).toBe(false);
    expect('checks' in r).toBe(false);
  });
  it('a failed core check passes the checks along without a hint or step-up', async () => {
    const { call } = setup();
    const r = await call({ resource: 'https://other.example.com' } as never);
    expect(r).toMatchObject({ ok: false, status: 401, error: 'invalid_token' });
    expect(hintOf(r)).toBe('mint the PCActn for this server: its aud must equal the `resource` option (agent({ aud }) or act(..., { aud }))');
    expect('stepUp' in r).toBe(false);
    expect('checks' in r).toBe(false);
  });
  it('a pending step-up is passed along with its checks and no hint', async () => {
    const { call } = setup();
    const r = await call({ requiredTier: 2, stepUpSatisfied: async () => false } as never);
    expect(r).toMatchObject({ ok: false, status: 401, error: 'insufficient_user_authentication' });
    if (r.ok) throw new Error('unexpected');
    expect(r.stepUp).toMatchObject({ tier: 2, acr: 'pca:tier2' });
    expect(r.checks).toBeDefined();
    expect(Object.keys(r.checks ?? {})).toContain('wire');
    expect('hint' in r).toBe(false);
  });
  it('an explicit authorization-server allowlist is honoured, the default trusts the grant store', async () => {
    const { call, a } = setup();
    allowAll();
    expect((await call({ authorizationServers: [a.grant.issuer] })).ok).toBe(true);
    const wrong = await call({ authorizationServers: ['https://as.example.com'] });
    expect(wrong).toMatchObject({ ok: false, status: 401, error: 'invalid_token' });
    expect((await call()).ok).toBe(true);
  });
});
function allowAll() {
  st.result = { allow: true, pcactn: {}, verdict: {}, operation: {} };
}

describe('toolCallRisk', () => {
  const grant = {} as Capability;
  const withKappa = (kappa: unknown) => {
    st.env = { on: true, value: { risk_policy: { kappa } } };
  };
  it('prices an amount against the grant kappa and clamps to [0, 1]', () => {
    withKappa(500);
    expect(toolCallRisk(grant, { amount: 50 })).toEqual({ blastRadius: 0.1 });
    expect(toolCallRisk(grant, { amount: 5000 })).toEqual({ blastRadius: 1 });
    expect(toolCallRisk(grant, { amount: -5 })).toEqual({ blastRadius: 0 });
  });
  it('refuses to price with a missing or unusable kappa', () => {
    for (const kappa of [0, -5, '500', undefined, null, Number.NaN]) {
      withKappa(kappa);
      expect(toolCallRisk(grant, { amount: 5 }), String(kappa)).toBeUndefined();
    }
    st.env = { on: true, value: null };
    expect(toolCallRisk(grant, { amount: 5 })).toBeUndefined();
  });
  it('refuses to price a non-finite or non-numeric amount', () => {
    withKappa(500);
    for (const amount of [Number.NaN, Number.POSITIVE_INFINITY, '50', null, undefined, {}]) expect(toolCallRisk(grant, { amount }), String(amount)).toBeUndefined();
  });
  it('reads a dotted field through own properties of objects and arrays only', () => {
    withKappa(500);
    expect(toolCallRisk(grant, { pay: { amount: 50 } }, { amountField: 'pay.amount' })).toEqual({ blastRadius: 0.1 });
    expect(toolCallRisk(grant, { p: [50] }, { amountField: 'p.0' })).toEqual({ blastRadius: 0.1 });
    expect(toolCallRisk(grant, { 'pay.amount': 25, pay: { amount: 50 } }, { amountField: 'pay.amount' })).toEqual({ blastRadius: 0.05 });
    expect(toolCallRisk(grant, { p: 'abc' }, { amountField: 'p.length' })).toBeUndefined();
    expect(toolCallRisk(grant, { p: 5 }, { amountField: 'p.toFixed' })).toBeUndefined();
    expect(toolCallRisk(grant, { p: null }, { amountField: 'p.amount' })).toBeUndefined();
    expect(toolCallRisk(grant, { p: { q: 1 } }, { amountField: 'p.amount' })).toBeUndefined();
    expect(toolCallRisk(grant, {}, { amountField: 'p.amount' })).toBeUndefined();
  });
});
