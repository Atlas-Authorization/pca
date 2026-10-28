import { describe, expect, it } from 'vitest';
import {
  type PCActn,
  type PlanNode,
  generateKeyPair,
  encodeKey,
  mintRoot,
  verifyPCActnCore,
  verifyChain,
  commitPlan as commitPlanLocal,
  createProvenanceRecorder,
  decideArgProvenance,
} from '@atlasauth/pca';
import { verifyLedgerInclusion, TransparencyLedger } from '@atlasauth/pca/ext/ledger';
import { createAgent, type FetchLike } from './agent';

const principal = generateKeyPair();
const agentKp = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const grant = mintRoot({
  principalSecret: principal.secretKey,
  principalPublic: pub(principal),
  holder: pub(agentKp),
  caveats: [],
});
const plan: PlanNode[] = [
  { id: 'n1', verb: 'read', resource: 'doc:1' },
  { id: 'n2', verb: 'write', resource: 'doc:2' },
];

interface Call { url: string; method?: string; body?: any }
function mock(handler: (c: Call) => { status: number; json: unknown }) {
  const calls: Call[] = [];
  const fetch: FetchLike = async (url, init) => {
    const c = { url, method: init?.method, body: init?.body ? JSON.parse(init.body) : undefined };
    calls.push(c);
    const r = handler(c);
    return { status: r.status, json: async () => r.json };
  };
  return { fetch, calls };
}
const mk = (m: ReturnType<typeof mock>) =>
  createAgent({ grant, agentSecret: agentKp.secretKey, agentPublic: pub(agentKp), rsBaseUrl: 'https://rs.test/', audience: 'ins_test', fetch: m.fetch });


/** A stateful fake resource server: echoes the plan root, enforces a strictly increasing counter, appends allowed actions to a real ledger. */
function server(opts: { allow?: boolean; stepUp?: boolean } = {}) {
  const ledger = new TransparencyLedger();
  const seen: number[] = [];
  const m = mock((c) => {
    if (c.url.endsWith('/plans')) return { status: 201, json: { plan_root: commitPlanLocal(c.body.nodes).root } };
    if (c.url.endsWith('/actions')) {
      const p = c.body.pcactn as PCActn;
      if (seen.length && p.counter <= seen[seen.length - 1]!) return { status: 409, json: { allow: false, verdict: { allow: false, reason: 'counter' } } };
      seen.push(p.counter);
      if (opts.stepUp) return { status: 202, json: { status: 'step_up_required', stepup_id: 'su1', required_t: 2 } };
      if (opts.allow === false) return { status: 403, json: { allow: false, verdict: { allow: false, reason: 'x' } } };
      const salt = `salt-${p.counter}`;
      const { index, commit } = ledger.append(p, { salt });
      const head = ledger.head();
      return { status: 200, json: { allow: true, verdict: { allow: true, budget: { B: 7, tau: 1, asOf: 1 } }, receipt: { index, commit, root: head.root, size: head.size, salt, inclusion_proof: ledger.inclusionProof(index) } } };
    }
    return { status: 404, json: {} };
  });
  return { ...m, ledger, seen };
}

const okReceipt = { index: 0, commit: 'c', root: 'r', inclusion_proof: { index: 0, size: 1, path: [] } };

describe('pca-agent', () => {
  it('provenance by default: act sends the session bundle as pca_provenance', async () => {
    const m = server();
    const recorder = createProvenanceRecorder({ mediator: 'harness', kid: 'k1' });
    const a = createAgent({ grant, agentSecret: agentKp.secretKey, agentPublic: pub(agentKp), rsBaseUrl: 'https://rs.test/', audience: 'ins_test', fetch: m.fetch, provenance: recorder });
    await a.commitPlan(plan);
    recorder.principal('Write x=1 to doc:2');
    await a.act('n2', { x: 1 });
    const sent = m.calls.find((c) => c.url.endsWith('/actions'))!.body.pca_provenance;
    expect(sent.receipts.map((r: { origin: string }) => r.origin)).toEqual(['principal', 'action']);
    expect(decideArgProvenance({ bundle: sent, operation: { verb: 'write', resource: 'doc:2', params: { x: 1 } }, mediators: [recorder.pin] }).outcome).toBe('pass');
  });

  it('commitPlan posts grant_ref + nodes and stores the root', async () => {
    const m = server();
    const a = mk(m);
    const { planRoot } = await a.commitPlan(plan);
    expect(m.calls[0]).toMatchObject({ url: 'https://rs.test/v1/pca/plans', method: 'POST', body: { grant_ref: grant.id, nodes: plan } });
    expect(a.planRoot).toBe(planRoot);
    expect(planRoot).toBe(commitPlanLocal(plan).root);
  });

  it('act builds a verifying PCActn, posts it, bumps the counter, updates budget, and the receipt verifies', async () => {
    const m = server();
    const a = mk(m);
    await a.commitPlan(plan);
    const r1 = await a.act('n1');
    const r2 = await a.act('n2', { x: 1 });
    expect(r1.status).toBe('allowed');
    expect(a.counter).toBe(2);
    expect(a.budget).toEqual({ B: 7, tau: 1, asOf: 1 });
    const posts = m.calls.filter((c) => c.url === 'https://rs.test/v1/pca/actions');
    expect(posts).toHaveLength(2);
    const p1 = posts[0]!.body.pcactn as PCActn;
    expect(p1.counter).toBe(1);
    expect((posts[1]!.body.pcactn as PCActn).counter).toBe(2);
    expect(p1.threshold).toBeUndefined(); // the leaf sig IS the agent share
    expect(r2.status).toBe('allowed');
    if (r1.status === 'allowed') expect(a.verifyReceipt(r1.receipt)).toBe(true);
    // wire v2 freshness binding, stamped by the agent
    expect([p1.ver, p1.aud]).toEqual([2, 'ins_test']);
    expect(p1.exp - p1.iat).toBe(20 * 60_000);
    expect(p1.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect((posts[1]!.body.pcactn as PCActn).nonce).not.toBe(p1.nonce);
    const v = await verifyPCActnCore(p1, { insecureSkipPlanRootCheck: true, grant, audience: 'ins_test' });
    expect(v.allow).toBe(true);
    expect((await verifyPCActnCore(p1, { insecureSkipPlanRootCheck: true, grant, audience: 'ins_other' })).checks.audience).toBe('fail');
  });

  it('requires an audience and can sign the optional v2 slots', async () => {
    const m = server();
    expect(() => createAgent({ grant, agentSecret: agentKp.secretKey, rsBaseUrl: 'https://rs.test/', fetch: m.fetch } as never)).toThrow(/audience/);
    const a = mk(m);
    await a.commitPlan(plan);
    await a.act('n1', undefined, { caution: 0.5, nonce: 'fixed-nonce' });
    const posts = m.calls.filter((c) => c.url === 'https://rs.test/v1/pca/actions');
    const p = posts[0]!.body.pcactn as PCActn;
    expect([p.caution, p.nonce]).toEqual([0.5, 'fixed-nonce']);
    expect((await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant })).checks.leaf_signature).toBe('pass');
  });

  it('returns denied without throwing', async () => {
    const a = mk(server({ allow: false }));
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r).toMatchObject({ status: 'denied', httpStatus: 403 });
  });

  it('typed errors for unknown node / no plan', async () => {
    const a = mk(server());
    const none = await a.act('n1');
    expect(none.status === 'error' && none.error.code).toBe('no_plan');
    await a.commitPlan(plan);
    const r = await a.act('zzz');
    expect(r.status === 'error' && r.error.code).toBe('unknown_node');
  });

  it('handles 202 step-up and awaitStepUp polls to approval', async () => {
    let polls = 0;
    const m = mock((c) => {
      if (c.url.endsWith('/plans')) return { status: 201, json: { plan_root: commitPlanLocal(c.body.nodes).root } };
      if (c.url.endsWith('/actions')) return { status: 202, json: { status: 'step_up_required', stepup_id: 'su1', required_t: 2 } };
      polls++;
      return { status: 200, json: { status: polls < 3 ? 'pending' : 'approved' } };
    });
    const a = mk(m);
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r).toMatchObject({ status: 'step_up', stepupId: 'su1', requiredT: 2 });
    const out = await a.awaitStepUp('su1', { pollMs: 1, timeoutMs: 1000 });
    expect(out.status).toBe('approved');
    expect(polls).toBe(3);
    expect(m.calls.at(-1)!.url).toBe('https://rs.test/v1/pca/stepups/su1');
  });

  it('awaitStepUp times out', async () => {
    const a = mk(mock(() => ({ status: 200, json: { status: 'pending' } })));
    expect((await a.awaitStepUp('x', { pollMs: 1, timeoutMs: 5 })).status).toBe('timeout');
  });

  it('delegate yields a verifying, strictly-attenuated sub-chain', async () => {
    const sub = generateKeyPair();
    const m = server();
    const a = mk(m);
    const child = a.delegate({ toPublic: pub(sub), addedCaveats: [{ type: 'max_calls', n: 1 }], agentSecret: sub.secretKey });
    expect(child.chain).toHaveLength(2);
    expect(verifyChain(child.chain, grant.issuer).ok).toBe(true);
    expect(child.chain[1]!.caveats.length).toBe(grant.caveats.length + 1);
    await child.commitPlan(plan);
    await child.act('n1');
    const p = m.calls.find((c) => c.url.endsWith('/actions'))!.body.pcactn as PCActn;
    expect((await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant, audience: 'ins_test' })).allow).toBe(true);
    // a secret-less sub client cannot act
    const mute = a.delegate({ toPublic: pub(sub), addedCaveats: [] });
    await mute.commitPlan(plan);
    const r = await mute.act('n1');
    expect(r.status === 'error' && r.error.code).toBe('no_secret');
  });

  it('verifyReceipt checks a real ledger inclusion proof', async () => {
    const m = server();
    const a = mk(m);
    await a.commitPlan(plan);
    const r = await a.act('n1');
    if (r.status !== 'allowed') throw new Error('expected allowed');
    expect(a.verifyReceipt(r.receipt)).toBe(true);
    expect(a.verifyReceipt({ ...r.receipt, commit: 'bad' })).toBe(false);
    expect(a.verifyReceipt({ ...r.receipt, root: 'bad' })).toBe(false);
    expect(a.verifyReceipt({ index: 0, commit: 'bad', root: 'bad', inclusion_proof: { index: 0, size: 1, path: [] } as never })).toBe(false);
    expect(typeof verifyLedgerInclusion).toBe('function');
    // a receipt without a proof is a false, not a throw
    expect(a.verifyReceipt({ ...r.receipt, inclusion_proof: undefined as never })).toBe(false);
  });
});

/**
 * Fail-closed table (README "Failure modes"). Each row: what is missing or wrong, and the exact outcome.
 * The fake server is stateful (plan root echo, counter order, a real ledger), so each row is one cause.
 */
describe('pca-agent fail-closed table', () => {
  const planOk = (c: Call) => ({ status: 201, json: { plan_root: commitPlanLocal(c.body.nodes).root } });
  const withAct = (act: (c: Call) => { status: number; json: unknown }) =>
    mk(mock((c) => (c.url.endsWith('/plans') ? planOk(c) : act(c))));

  it('missing plan_root in the commit response: commitPlan throws bad_response and no plan is kept', async () => {
    const a = mk(mock(() => ({ status: 201, json: {} })));
    await expect(a.commitPlan(plan)).rejects.toMatchObject({ code: 'bad_response' });
    expect(a.planRoot).toBeUndefined();
    const r = await a.act('n1');
    expect(r.status === 'error' && r.error.code).toBe('no_plan');
  });

  it('a different plan_root in the commit response: commitPlan throws bad_response', async () => {
    const a = mk(mock(() => ({ status: 201, json: { plan_root: 'AAAA' } })));
    await expect(a.commitPlan(plan)).rejects.toMatchObject({ code: 'bad_response' });
    expect(a.planRoot).toBeUndefined();
  });

  it('a non-2xx commit response: commitPlan throws bad_response with the status', async () => {
    const a = mk(mock(() => ({ status: 500, json: {} })));
    await expect(a.commitPlan(plan)).rejects.toMatchObject({ code: 'bad_response', httpStatus: 500 });
  });

  it('mutating the node array after commit does not change the plan the agent acts on', async () => {
    const nodes: PlanNode[] = [{ id: 'n1', verb: 'read', resource: 'doc:1' }];
    const a = mk(server());
    await a.commitPlan(nodes);
    nodes[0]!.id = 'evil';
    expect((await a.act('evil')).status).toBe('error');
    expect((await a.act('n1')).status).toBe('allowed');
  });

  it('a network failure on act: error network, and the counter is still consumed (never reused)', async () => {
    const m = mock((c) => {
      if (c.url.endsWith('/plans')) return planOk(c);
      throw new Error('ECONNRESET');
    });
    const a = mk(m);
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r.status === 'error' && r.error.code).toBe('network');
    expect(a.counter).toBe(1);
  });

  it('a non-JSON body on a 200: denied, never allowed', async () => {
    const fetch: FetchLike = async (url) => ({ status: 200, json: async () => { if (url.endsWith('/plans')) return { plan_root: commitPlanLocal(plan).root }; throw new SyntaxError('x'); } });
    const a = createAgent({ grant, agentSecret: agentKp.secretKey, rsBaseUrl: 'https://rs.test', audience: 'ins_test', fetch });
    await a.commitPlan(plan);
    expect((await a.act('n1')).status).toBe('denied');
  });

  it('200 with allow:true but no receipt: error bad_response', async () => {
    const a = withAct(() => ({ status: 200, json: { allow: true, verdict: { allow: true } } }));
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r.status === 'error' && r.error.code).toBe('bad_response');
  });

  it('200 with a receipt whose inclusion proof does not verify: error bad_response, not allowed', async () => {
    const a = withAct(() => ({ status: 200, json: { allow: true, verdict: { allow: true }, receipt: okReceipt } }));
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r.status === 'error' && r.error.code).toBe('bad_response');
  });

  it('a receipt for a different action (salt does not reproduce the commit): error bad_response', async () => {
    const m = server();
    const other = new TransparencyLedger();
    const decoy = mk(m);
    await decoy.commitPlan(plan);
    const first = await decoy.act('n1');
    if (first.status !== 'allowed') throw new Error('setup');
    // replay the first receipt as the answer to the next action
    const a = withAct(() => ({ status: 200, json: { allow: true, verdict: { allow: true }, receipt: first.receipt } }));
    void other;
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r.status === 'error' && r.error.code).toBe('bad_response');
  });

  it('verifyReceipts:false accepts an unverifiable receipt (test double only)', async () => {
    const a = createAgent({
      grant, agentSecret: agentKp.secretKey, rsBaseUrl: 'https://rs.test', audience: 'ins_test', verifyReceipts: false,
      fetch: mock((c) => (c.url.endsWith('/plans') ? planOk(c) : { status: 200, json: { allow: true, verdict: { allow: true }, receipt: okReceipt } })).fetch,
    });
    await a.commitPlan(plan);
    expect((await a.act('n1')).status).toBe('allowed');
  });

  it('allow:true at top level but verdict.allow false: denied', async () => {
    const a = withAct(() => ({ status: 200, json: { allow: true, verdict: { allow: false }, receipt: okReceipt } }));
    await a.commitPlan(plan);
    expect((await a.act('n1')).status).toBe('denied');
  });

  it('verdict.allow true but top-level allow false: denied', async () => {
    const a = withAct(() => ({ status: 200, json: { allow: false, verdict: { allow: true }, receipt: okReceipt } }));
    await a.commitPlan(plan);
    expect((await a.act('n1')).status).toBe('denied');
  });

  it('a truthy non-boolean allow ("true", 1): denied', async () => {
    for (const allow of ['true', 1, {}]) {
      const a = withAct(() => ({ status: 200, json: { verdict: { allow }, receipt: okReceipt } }));
      await a.commitPlan(plan);
      expect((await a.act('n1')).status).toBe('denied');
    }
  });

  it('an allow body on a non-2xx status: denied', async () => {
    const a = withAct(() => ({ status: 500, json: { allow: true, verdict: { allow: true }, receipt: okReceipt } }));
    await a.commitPlan(plan);
    expect((await a.act('n1')).status).toBe('denied');
  });

  it('a well-formed budget on a denied verdict is recorded (the server is the budget authority)', async () => {
    const a = withAct(() => ({ status: 403, json: { verdict: { allow: false, budget: { B: 3, tau: 0, asOf: 5 } } } }));
    await a.commitPlan(plan);
    await a.act('n1');
    expect(a.budget).toEqual({ B: 3, tau: 0, asOf: 5 });
  });

  it('a budget with non-numeric or non-finite fields never replaces the budget', async () => {
    const m = server();
    const a = mk(m);
    await a.commitPlan(plan);
    await a.act('n1');
    expect(a.budget).toEqual({ B: 7, tau: 1, asOf: 1 });
    const bad = withAct(() => ({ status: 403, json: { verdict: { allow: false, budget: { B: 'x', tau: 1, asOf: 1 } } } }));
    await bad.commitPlan(plan);
    await bad.act('n1');
    expect(bad.budget).toBeUndefined();
    const inf = withAct(() => ({ status: 403, json: { verdict: { allow: false, budget: { B: Infinity, tau: 1, asOf: 1 } } } }));
    await inf.commitPlan(plan);
    await inf.act('n1');
    expect(inf.budget).toBeUndefined();
  });

  it('a step-up response with no id: error bad_response', async () => {
    const a = withAct(() => ({ status: 202, json: { status: 'step_up_required' } }));
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r.status === 'error' && r.error.code).toBe('bad_response');
  });

  it('the server rejecting a replayed counter surfaces as denied (409), and counters only grow', async () => {
    const m = server();
    const a = mk(m);
    await a.commitPlan(plan);
    await a.act('n1');
    const again = createAgent({ grant, agentSecret: agentKp.secretKey, rsBaseUrl: 'https://rs.test', audience: 'ins_test', fetch: m.fetch });
    await again.commitPlan(plan);
    const r = await again.act('n1'); // counter restarts at 1 <= server high-water
    expect(r).toMatchObject({ status: 'denied', httpStatus: 409 });
    expect(m.seen).toEqual([1]);
  });

  it('awaitStepUp: a non-2xx "approved" is not an approval', async () => {
    const a = mk(mock(() => ({ status: 500, json: { status: 'approved' } })));
    expect((await a.awaitStepUp('x', { pollMs: 1, timeoutMs: 5 })).status).toBe('timeout');
  });

  it('awaitStepUp: 404 stops polling and is denied with the status', async () => {
    let polls = 0;
    const a = mk(mock(() => { polls++; return { status: 404, json: {} }; }));
    expect(await a.awaitStepUp('x', { pollMs: 1, timeoutMs: 1000 })).toEqual({ status: 'denied', httpStatus: 404 });
    expect(polls).toBe(1);
  });

  it('awaitStepUp: denied and expired are passed through; a network failure throws network', async () => {
    for (const st of ['denied', 'expired'] as const) {
      const a = mk(mock(() => ({ status: 200, json: { status: st } })));
      expect((await a.awaitStepUp('x', { pollMs: 1, timeoutMs: 50 })).status).toBe(st);
    }
    const a = mk(mock(() => { throw new Error('down'); }));
    await expect(a.awaitStepUp('x', { pollMs: 1, timeoutMs: 50 })).rejects.toMatchObject({ code: 'network' });
  });

  it('awaitStepUp URL-encodes the step-up id', async () => {
    const m = mock(() => ({ status: 200, json: { status: 'approved' } }));
    await mk(m).awaitStepUp('a/b?c', { pollMs: 1, timeoutMs: 50 });
    expect(m.calls[0]!.url).toBe('https://rs.test/v1/pca/stepups/a%2Fb%3Fc');
  });

  it('a non-http(s) or relative rsBaseUrl is refused at construction', () => {
    for (const rsBaseUrl of ['', '/relative', 'ftp://rs.test', 'javascript:alert(1)']) {
      expect(() => createAgent({ grant, agentSecret: agentKp.secretKey, rsBaseUrl, audience: 'ins_test' })).toThrow(/rsBaseUrl/);
    }
  });

  it('delegate without agentSecret throws no_secret', () => {
    const a = createAgent({ grant, rsBaseUrl: 'https://rs.test', audience: 'ins_test' });
    expect(() => a.delegate({ toPublic: pub(agentKp) })).toThrow(/agentSecret/);
  });

  it('a sub-agent inherits verifyReceipts and the audience', async () => {
    const sub = generateKeyPair();
    const a = createAgent({
      grant, agentSecret: agentKp.secretKey, rsBaseUrl: 'https://rs.test', audience: 'ins_test', verifyReceipts: false,
      fetch: mock((c) => (c.url.endsWith('/plans') ? planOk(c) : { status: 200, json: { allow: true, verdict: { allow: true }, receipt: okReceipt } })).fetch,
    });
    const child = a.delegate({ toPublic: pub(sub), agentSecret: sub.secretKey });
    await child.commitPlan(plan);
    expect((await child.act('n1')).status).toBe('allowed');
  });
});
