import { describe, expect, it } from 'vitest';
import { agent, decodePCActn, decodePcaHeader, durablePcaStateStore, generateKeyPair, hashCanonical, memoryAtomicKv, memoryPcaStore, paramsDigest, pcaHeaders, pcaStateKey, type Capability } from '@atlasauth/pca';
import { BUILTIN_ACTIONS, buildCatalog, defineAction, type Catalog } from '@atlasauth/pca/ext/research';
import { WELL_KNOWN_OAUTH_PRM, authorizeRequest, authorizeToolCall, toolCallRisk, type AuthorizeToolCallOptions, type ToolActionMap } from './index';

const RESOURCE = 'https://mcp.example.com/mcp';
const PRM_URL = `https://mcp.example.com${WELL_KNOWN_OAUTH_PRM}`;

const toolAction: ToolActionMap = (tool, args) => {
  if (tool === 'refund') return { verb: 'stripe.refund', resource: `charge:${String(args['chargeId'])}` };
  if (tool === 'delete_customer') return { verb: 'stripe.delete_customer', resource: `customer:${String(args['customerId'])}` };
  return null;
};

function setup(o: { catalog?: Catalog; revoked?: boolean; permissions?: Record<string, string[]>; limits?: Record<string, string> } = {}) {
  const a = agent({
    principal: generateKeyPair(),
    goal: 'refund customers for broken orders',
    permissions: o.permissions ?? { stripe: ['refund'] },
    ...(o.limits === undefined && o.permissions !== undefined ? {} : { limits: o.limits ?? { refund: '$500/day' } }),
    aud: RESOURCE,
    ...(o.catalog ? { catalog: o.catalog } : {}),
  });
  const grants = new Map<string, Capability>([[a.grant.id, a.grant]]);
  const state = memoryPcaStore();
  const base = (tool: string, args: Record<string, unknown>): AuthorizeToolCallOptions => ({
    resource: RESOURCE,
    prmUrl: PRM_URL,
    tool,
    args,
    toolAction,
    resolveGrant: (ref) => grants.get(ref) ?? null,
    state,
    isRevoked: () => o.revoked === true,
  });
  /** A signed PCActn header for (verb, resource, params), the way the agent's fetch builds it. */
  const proof = (verb: string, resource: string, params: Record<string, unknown>, aud = RESOURCE) => ({ headers: pcaHeaders(a.act(verb, resource, params, { aud }).encoded) });
  const call = (tool: string, args: Record<string, unknown>, req: { headers: Record<string, string> }, extra: Partial<AuthorizeToolCallOptions> = {}) =>
    authorizeToolCall(req, { ...base(tool, args), ...extra });
  return { a, grants, proof, call, base };
}

describe('authorizeToolCall: the allowed path', () => {
  it('allows an in-scope refund, and server-side pricing leaves budget for more calls', async () => {
    const { proof, call } = setup();
    for (const id of ['ch_1', 'ch_2', 'ch_3', 'ch_4']) {
      const args = { chargeId: id, amount: 42 };
      const r = await call('refund', args, proof('stripe.refund', `charge:${id}`, args));
      expect(r.ok, JSON.stringify(r)).toBe(true);
      if (r.ok) {
        expect(r.status).toBe(200);
        expect(r.pcactn.action.verb).toBe('stripe.refund');
      }
    }
  });

  it('accepts an explicit issuer allowlist that names the principal', async () => {
    const { a, proof, call } = setup();
    const args = { chargeId: 'ch_1', amount: 1 };
    expect((await call('refund', args, proof('stripe.refund', 'charge:ch_1', args), { authorizationServers: [a.grant.issuer] })).ok).toBe(true);
    const r = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args), { authorizationServers: ['https://as.example.com'] });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.hint).toMatch(/principal's public key/);
  });
});

describe('authorizeToolCall refuses every hole the admission-only check leaves open', () => {
  it('a verb the grant does not permit (stripe.delete_customer on a refund-only grant)', async () => {
    const { proof, call, base } = setup();
    const args = { customerId: 'cus_42' };
    const req = proof('stripe.delete_customer', 'customer:cus_42', args);
    const b = base('delete_customer', args);
    const hole = await authorizeRequest(req, { resource: b.resource, prmUrl: b.prmUrl, resolveGrant: b.resolveGrant, authorizationServers: [setupIssuer(req)], tool: 'delete_customer', admissionOnly: true });
    expect(hole.ok).toBe(true); // the admission-only check admits it (explicit opt-in since 0.5)
    const r = await call('delete_customer', args, req);
    expect(r).toMatchObject({ ok: false, status: 403, error: 'forbidden', reason: 'the grant does not permit stripe.delete_customer (it permits: stripe.refund)' });
  });

  it('an over-limit amount ($5000 under a $500 limit)', async () => {
    const { proof, call } = setup();
    const args = { chargeId: 'ch_1', amount: 5000 };
    const r = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args));
    expect(r).toMatchObject({ ok: false, status: 403 });
    expect(!r.ok && r.reason).toBe('amount <= 500 not satisfied for stripe.refund on charge:ch_1');
  });

  it('a replayed proof', async () => {
    const { proof, call } = setup();
    const args = { chargeId: 'ch_1', amount: 42 };
    const req = proof('stripe.refund', 'charge:ch_1', args);
    expect((await call('refund', args, req)).ok).toBe(true);
    const again = await call('refund', args, req);
    expect(again.ok).toBe(false);
    expect(!again.ok && again.reason, JSON.stringify(again)).toMatch(/^replay: 1 is not greater than last seen 1/);
    expect(!again.ok && again.hint).toMatch(/fresh one per call/);
  });

  it('a valid proof presented for another tool, another resource or other arguments', async () => {
    const { proof, call } = setup();
    const signed = { chargeId: 'ch_1', amount: 42 };
    const req = proof('stripe.refund', 'charge:ch_1', signed);
    const otherTool = await call('delete_customer', { customerId: 'cus_1' }, req);
    expect(otherTool).toMatchObject({ ok: false, status: 403, reason: 'the proof is for stripe.refund on charge:ch_1, but this call is stripe.delete_customer on customer:cus_1' });
    expect((await call('refund', { chargeId: 'ch_2', amount: 42 }, req)).ok).toBe(false);
    expect((await call('refund', { chargeId: 'ch_1', amount: 420 }, req)).ok).toBe(false);
    expect((await call('nope', {}, req))).toMatchObject({ ok: false, reason: "tool 'nope' has no PCA mapping on this server" });
    // none of the refusals above spent the proof: it still authorizes the call it was made for
    expect((await call('refund', signed, req)).ok).toBe(true);
  });
});

describe('authorizeToolCall: other refusals', () => {
  it('no proof, an unregistered grant, a revoked grant, another audience', async () => {
    const s = setup();
    const args = { chargeId: 'ch_1', amount: 1 };
    const none = await s.call('refund', args, { headers: {} });
    expect(none).toMatchObject({ ok: false, status: 401, error: 'invalid_request', reason: "tool 'refund' requires a proof-carrying action: send it in the PCA-Action header" });
    expect(!none.ok && none.hint).toMatch(/pcaHeaders/);

    const other = setup();
    expect((await s.call('refund', args, other.proof('stripe.refund', 'charge:ch_1', args))).ok).toBe(false);

    const rv = setup({ revoked: true });
    const revoked = await rv.call('refund', args, rv.proof('stripe.refund', 'charge:ch_1', args));
    expect(revoked.ok).toBe(false);
    expect(!revoked.ok && revoked.reason).toMatch(/^revocation/);

    expect((await s.call('refund', args, s.proof('stripe.refund', 'charge:ch_1', args, 'https://other.example.com'))).ok).toBe(false);
  });

  it('isPlanAuthorized can require pre-approved plans', async () => {
    const { proof, call } = setup();
    const args = { chargeId: 'ch_1', amount: 1 };
    const r = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args), { isPlanAuthorized: () => false });
    expect(r.ok).toBe(false);
  });

  it('the challenge never carries request-derived text', async () => {
    const { proof, call } = setup();
    const args = { customerId: 'cus_"\r\nX' };
    const r = await call('delete_customer', args, proof('stripe.delete_customer', `customer:${args.customerId}`, args));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.wwwAuthenticate).toBe(`Bearer realm="pca", resource_metadata="${PRM_URL}", error="forbidden"`);
      expect(r.reason).toContain('stripe.delete_customer');
    }
  });

  it('a grant without money limits: the default risk policy asks for a co-sign unless the server vouches for the risk inputs', async () => {
    const { proof, call } = setup({ permissions: { stripe: ['refund'] } });
    const args = { chargeId: 'ch_1' };
    const r = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args));
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/needs a co-sign/);
    expect(!r.ok && r.hint).toMatch(/`risk` option/);
    const vouched = { semanticDistance: 0, reversibility: 1, blastRadius: 0.1, taint: 0, confidence: 1, age: 0 };
    const ok = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args), { risk: () => vouched });
    expect(ok.ok, JSON.stringify(ok)).toBe(true);
  });

  it('fails closed when a callback throws', async () => {
    const { proof, call } = setup();
    const args = { chargeId: 'ch_1', amount: 1 };
    const r = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args), { isRevoked: () => { throw new Error('db down'); } });
    expect(r.ok).toBe(false);
  });
});

describe('toolCallRisk', () => {
  it('prices the verified amount against the grant cap, and returns undefined without a numeric amount', () => {
    const { a } = setup();
    expect(toolCallRisk(a.grant, { amount: 50 })).toEqual({ blastRadius: 0.1 });
    expect(toolCallRisk(a.grant, { amount: 5000 })).toEqual({ blastRadius: 1 });
    expect(toolCallRisk(a.grant, { amount: -3 })).toEqual({ blastRadius: 0 });
    expect(toolCallRisk(a.grant, { total: 50 }, { amountField: 'total' })).toEqual({ blastRadius: 0.1 });
    // derived from an action definition's money.amount role (flat, dotted, ambiguous and absent)
    const def = (params: Record<string, { role?: string }>) => ({ params });
    expect(toolCallRisk(a.grant, { total: 50 }, { action: def({ total: { role: 'money.amount' }, to: {} }) })).toEqual({ blastRadius: 0.1 });
    expect(toolCallRisk(a.grant, { pay: { amount: 50 } }, { action: def({ 'pay.amount': { role: 'money.amount' } }) })).toEqual({ blastRadius: 0.1 });
    expect(toolCallRisk(a.grant, { a: 1, b: 2 }, { action: def({ a: { role: 'money.amount' }, b: { role: 'money.amount' } }) })).toBeUndefined();
    expect(toolCallRisk(a.grant, { a: 1 }, { action: def({ a: {} }) })).toBeUndefined();
    expect(toolCallRisk(a.grant, { amount: '50' })).toBeUndefined();
    expect(toolCallRisk(a.grant, {})).toBeUndefined();
  });
});

/** The grant issuer of the PCActn in a request (for the admission-only comparison). */
function setupIssuer(req: { headers: Record<string, string> }): string {
  return decodePCActn(decodePcaHeader(req.headers['PCA-Action']!)).cap_chain[0]!.issuer;
}

describe('authorizeToolCall runs the one pipeline, authorize (0.5)', () => {
  it('the allowed result is bound to the tool call: verb, resource, params digest and the operation id', async () => {
    const { proof, call } = setup();
    const args = { chargeId: 'ch_1', amount: 42 };
    const r = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args));
    expect(r.ok && r.operation).toEqual({ verb: 'stripe.refund', resource: 'charge:ch_1', params_digest: paramsDigest(args), id: r.ok ? hashCanonical(r.pcactn) : '' });
  });

  it("replayScope 'audience-grant-holder': the counter and the seeded budget live under the audience-scoped key (no re-seed)", async () => {
    const { a, proof, call } = setup();
    const state = memoryPcaStore();
    const holder = a.grant.holder;
    const first = await call('refund', { chargeId: 'ch_1', amount: 42 }, proof('stripe.refund', 'charge:ch_1', { chargeId: 'ch_1', amount: 42 }), { state, replayScope: 'audience-grant-holder' });
    const second = await call('refund', { chargeId: 'ch_2', amount: 42 }, proof('stripe.refund', 'charge:ch_2', { chargeId: 'ch_2', amount: 42 }), { state, replayScope: 'audience-grant-holder' });
    expect([first.ok, second.ok]).toEqual([true, true]);
    const leaf = first.ok ? first.pcactn.cap_chain[first.pcactn.cap_chain.length - 1]!.holder : holder;
    const scoped = await state.get(pcaStateKey(a.grant.id, leaf, 'audience-grant-holder', RESOURCE));
    expect([scoped?.lastCounter, await state.get(pcaStateKey(a.grant.id, leaf))]).toEqual([second.ok ? second.pcactn.counter : -1, undefined]);
    // the second call spent from the stored budget, not from a fresh seed
    expect(first.ok && second.ok && second.verdict.budget!.B < first.verdict.budget!.B).toBe(true);
  });

  it('multiInstance: a process-local store is refused (fail closed); a shared atomic store is accepted', async () => {
    const { proof, call } = setup();
    const args = { chargeId: 'ch_1', amount: 1 };
    const r = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args), { multiInstance: true });
    expect(!r.ok && r.reason).toBe(
      'authorization error (fail closed): requirePCA: multiInstance needs a budgetStore with `claim` (AtomicPcaStateStore) or `withKeyLock`; the in-process lock is correct for one process only (multiInstance is on unless the store declares `scope: \'process\'`; pass multiInstance: false to run this store in one process on purpose)',
    );
    const ok = await call('refund', args, proof('stripe.refund', 'charge:ch_1', args), { multiInstance: true, state: durablePcaStateStore(memoryAtomicKv()) });
    expect(ok.ok).toBe(true);
  });

  it('a params mismatch keeps the established params_digest reason (the operation check is ranked last)', async () => {
    // a refund is irreversible now (it would fail the policy check first); a rate-limited money action isolates the params check
    const catalog = buildCatalog([...BUILTIN_ACTIONS, defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.5, amountField: 'amount', description: 'Refund' })]);
    const { proof, call } = setup({ catalog });
    const r = await call('refund', { chargeId: 'ch_1', amount: 400 }, proof('stripe.refund', 'charge:ch_1', { chargeId: 'ch_1', amount: 4 }));
    expect(!r.ok && { reason: r.reason, operation: r.checks?.['operation'], params: r.checks?.['params_digest'] }).toEqual({
      reason: 'params_digest: supplied params do not hash to action.params_digest',
      operation: 'fail',
      params: 'fail',
    });
  });
});

describe('authorizeRequest is the complete check by default (0.5)', () => {
  it('refuses what only admission admits: a verb the grant does not permit, an over-limit amount, a replay', async () => {
    const { proof, base } = setup();
    const call = (tool: string, args: Record<string, unknown>, req: { headers: Record<string, string> }) => authorizeRequest(req, base(tool, args));
    const del = { customerId: 'cus_42' };
    expect(await call('delete_customer', del, proof('stripe.delete_customer', 'customer:cus_42', del))).toMatchObject({ ok: false, status: 403, reason: 'the grant does not permit stripe.delete_customer (it permits: stripe.refund)' });
    const big = { chargeId: 'ch_1', amount: 5000 };
    expect(await call('refund', big, proof('stripe.refund', 'charge:ch_1', big))).toMatchObject({ ok: false, status: 403 });
    const ok = { chargeId: 'ch_2', amount: 10 };
    const req = proof('stripe.refund', 'charge:ch_2', ok);
    expect((await call('refund', ok, req)).ok).toBe(true);
    expect(await call('refund', ok, req)).toMatchObject({ ok: false });
  });
  it('is exactly authorizeToolCall', async () => {
    const { proof, base } = setup();
    const args = { chargeId: 'ch_3', amount: 10 };
    const r = await authorizeRequest(proof('stripe.refund', 'charge:ch_3', args), base('refund', args));
    expect(r.ok && 'verdict' in r).toBe(true);
  });
  it('a call that omits what the full check needs is refused, not downgraded to admission', async () => {
    const { proof, base } = setup();
    const b = base('refund', { chargeId: 'ch_4', amount: 10 });
    const req = proof('stripe.refund', 'charge:ch_4', { chargeId: 'ch_4', amount: 10 });
    const { state: _s, isRevoked: _r, toolAction: _t, args: _a, ...admission } = b;
    const r = await authorizeRequest(req, admission as never);
    expect(r).toMatchObject({ ok: false, status: 403, error: 'forbidden', reason: 'authorization is not configured: missing toolAction, state, isRevoked (fail closed)' });
  });
  it('admissionOnly: true is the explicit admission check', async () => {
    const { proof, base } = setup();
    const del = { customerId: 'cus_42' };
    const b = base('delete_customer', del);
    const req = proof('stripe.delete_customer', 'customer:cus_42', del);
    const r = await authorizeRequest(req, { resource: b.resource, prmUrl: b.prmUrl, resolveGrant: b.resolveGrant, authorizationServers: [setupIssuer(req)], tool: 'delete_customer', admissionOnly: true });
    expect(r.ok).toBe(true);
    expect(r.ok && 'verdict' in r).toBe(false);
  });
});
