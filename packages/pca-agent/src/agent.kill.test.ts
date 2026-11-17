import { afterEach, describe, expect, it, vi } from 'vitest';
import { type PCActn, type PlanNode, generateKeyPair, encodeKey, mintRoot, commitPlan as commitPlanLocal } from '@atlasauth/pca';
import { TransparencyLedger } from '@atlasauth/pca/ext/ledger';
import { PcaAgentError, createAgent, type CreateAgentOptions, type FetchLike } from './agent';

const principal = generateKeyPair();
const agentKp = generateKeyPair();
const subKp = generateKeyPair();
const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);
const grant = mintRoot({ principalSecret: principal.secretKey, principalPublic: pub(principal), holder: pub(agentKp), caveats: [] });
const plan: PlanNode[] = [{ id: 'n1', verb: 'read', resource: 'doc:1' }, { id: 'n2', verb: 'write', resource: 'doc:2' }];

interface Seen { url: string; init: { method?: string; headers?: Record<string, string>; body?: string } | undefined }
type Reply = { status: number; json: unknown };

function rig(handler: (url: string, body: any, n: number) => Reply, extra: Partial<CreateAgentOptions> = {}) {
  const seen: Seen[] = [];
  const fetch: FetchLike = async (url, init) => {
    seen.push({ url, init: init as Seen['init'] });
    const r = handler(url, init?.body ? JSON.parse(init.body) : undefined, seen.length);
    return { status: r.status, json: async () => r.json };
  };
  const a = createAgent({ grant, agentSecret: agentKp.secretKey, agentPublic: pub(agentKp), rsBaseUrl: 'https://rs.test/', audience: 'ins_test', fetch, ...extra });
  return { a, seen };
}
const planOk = (url: string, body: any): Reply | undefined => (url.endsWith('/plans') ? { status: 201, json: { plan_root: commitPlanLocal(body.nodes).root } } : undefined);
const denyAll = (url: string, body: any): Reply => planOk(url, body) ?? { status: 403, json: { allow: false, verdict: { allow: false } } };

async function denied(extra: Partial<CreateAgentOptions>, slots?: Parameters<ReturnType<typeof createAgent>['act']>[2], params?: Record<string, unknown>) {
  const { a, seen } = rig(denyAll, extra);
  await a.commitPlan(plan);
  const r = await a.act('n1', params, slots);
  if (r.status !== 'denied') throw new Error('expected denied, got ' + r.status);
  return { a, seen, p: r.pcactn as PCActn & Record<string, unknown> };
}

/** An allowed reply backed by a real ledger; `mutate` adjusts the receipt / body. */
function allowing(opts: { status?: number; verdict?: Record<string, unknown>; body?: Record<string, unknown>; receipt?: (r: Record<string, unknown>) => unknown; salt?: unknown } = {}) {
  const ledger = new TransparencyLedger();
  return (url: string, body: any): Reply => {
    const pl = planOk(url, body);
    if (pl) return pl;
    const p = body.pcactn as PCActn;
    const salt = 'salt' in opts ? opts.salt : 's1';
    const { index, commit } = ledger.append(p, salt === undefined ? {} : { salt: salt as string });
    const head = ledger.head();
    const receipt: Record<string, unknown> = { index, commit, root: head.root, size: head.size, ...(salt === undefined ? {} : { salt }), inclusion_proof: ledger.inclusionProof(index) };
    return { status: opts.status ?? 200, json: { allow: true, verdict: { allow: true, ...opts.verdict }, receipt: opts.receipt ? opts.receipt(receipt) : receipt, ...opts.body } };
  };
}
async function actWith(handler: (url: string, body: any, n: number) => Reply, extra: Partial<CreateAgentOptions> = {}) {
  const { a, seen } = rig(handler, extra);
  await a.commitPlan(plan);
  return { a, seen, r: await a.act('n1') };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('PcaAgentError', () => {
  it('carries name, code and http status', () => {
    const e = new PcaAgentError('network', 'm', 502);
    expect(e.name).toBe('PcaAgentError');
    expect(e.code).toBe('network');
    expect(e.httpStatus).toBe(502);
    expect(e.message).toBe('m');
  });
});

describe('createAgent construction', () => {
  const base = { grant, agentSecret: agentKp.secretKey, audience: 'ins_test' };
  it('requires a non-empty audience', () => {
    for (const audience of ['', undefined as unknown as string]) {
      try {
        createAgent({ ...base, audience, rsBaseUrl: 'https://rs.test' });
        throw new Error('did not throw');
      } catch (e) {
        expect(e).toBeInstanceOf(PcaAgentError);
        expect((e as PcaAgentError).code).toBe('build_failed');
        expect((e as PcaAgentError).message).toBe('createAgent: `audience` is required (the resource-server / Atlas instance id PCActns are for)');
      }
    }
  });
  it('accepts http and https and refuses other schemes and non-URLs', () => {
    expect(() => createAgent({ ...base, rsBaseUrl: 'http://rs.test' })).not.toThrow();
    expect(() => createAgent({ ...base, rsBaseUrl: 'https://rs.test' })).not.toThrow();
    for (const rsBaseUrl of ['ftp://rs.test', 'not a url']) {
      try {
        createAgent({ ...base, rsBaseUrl });
        throw new Error('did not throw');
      } catch (e) {
        expect((e as PcaAgentError).code).toBe('build_failed');
        expect((e as PcaAgentError).message).toBe('createAgent: `rsBaseUrl` must be an absolute http(s) URL');
      }
    }
  });
  it('strips every trailing slash, sends JSON headers, and no body on GET', async () => {
    const { a, seen } = rig((url, body) => planOk(url, body) ?? { status: 200, json: { status: 'approved' } }, { rsBaseUrl: 'https://rs.test///' });
    await a.commitPlan(plan);
    await a.awaitStepUp('s', { pollMs: 1, timeoutMs: 1000 });
    expect(seen[0]!.url).toBe('https://rs.test/v1/pca/plans');
    expect(seen[0]!.init!.method).toBe('POST');
    expect(seen[0]!.init!.headers).toEqual({ 'content-type': 'application/json', accept: 'application/json' });
    expect(seen[1]!.init!.method).toBe('GET');
    expect(seen[1]!.init!.body).toBeUndefined();
  });
  it('falls back to the global fetch', async () => {
    const calls: Array<[string, unknown]> = [];
    vi.stubGlobal('fetch', async (u: string, i: unknown) => (calls.push([u, i]), { status: 201, json: async () => ({ plan_root: commitPlanLocal(plan).root }) }));
    const a = createAgent({ ...base, rsBaseUrl: 'https://rs.test' });
    await a.commitPlan(plan);
    expect(calls).toHaveLength(1);
    expect(calls[0]![0]).toBe('https://rs.test/v1/pca/plans');
  });
});

describe('commitPlan', () => {
  const commitWith = (status: number, root?: string | null) => {
    const { a } = rig((url, body) => ({ status, json: { plan_root: root === null ? undefined : root ?? commitPlanLocal(body.nodes).root } }));
    return a.commitPlan(plan);
  };
  it('accepts 200 and 299 only up to the 2xx range', async () => {
    expect((await commitWith(200)).planRoot).toBe(commitPlanLocal(plan).root);
    expect((await commitWith(299)).planRoot).toBe(commitPlanLocal(plan).root);
  });
  it.each([199, 300, 500])('refuses status %i with the status in the message', async (status) => {
    const e = await commitWith(status).catch((x) => x as PcaAgentError);
    expect(e).toBeInstanceOf(PcaAgentError);
    expect(e.code).toBe('bad_response');
    expect(e.message).toBe(`plan commit failed (${status})`);
    expect(e.httpStatus).toBe(status);
  });
  it('refuses a missing or different plan_root', async () => {
    for (const root of [null, 'other']) {
      const e = await commitWith(201, root).catch((x) => x as PcaAgentError);
      expect(e.code).toBe('bad_response');
      expect(e.message).toBe('server plan_root is missing or differs from the locally computed root');
    }
  });
});

describe('act preconditions and build', () => {
  it('reports no_plan, no_secret and unknown_node with exact messages', async () => {
    const { a } = rig(denyAll);
    const r1 = await a.act('n1');
    expect(r1.status === 'error' && r1.error.code === 'no_plan' && r1.error.message).toBe('commitPlan() first');
    const ns = rig(denyAll, { agentSecret: undefined });
    await ns.a.commitPlan(plan);
    const r2 = await ns.a.act('n1');
    expect(r2.status === 'error' && r2.error.code === 'no_secret' && r2.error.message).toBe('no agentSecret for this client');
    await a.commitPlan(plan);
    const r3 = await a.act('zzz');
    expect(r3.status === 'error' && r3.error.code === 'unknown_node' && r3.error.message).toBe('unknown plan node zzz');
  });
  it('maps a build failure to build_failed with the builder message', async () => {
    const guarded: PlanNode[] = [{ id: 'g', verb: 'write', resource: 'doc:9', params_digest: 'not-the-digest' }];
    const { a } = rig(denyAll);
    await a.commitPlan(guarded);
    const r = await a.act('g', { x: 1 });
    expect(r.status).toBe('error');
    if (r.status === 'error') {
      expect(r.error).toBeInstanceOf(PcaAgentError);
      expect(r.error.code).toBe('build_failed');
      expect(r.error.message).toContain("do not match plan node g's params_digest");
    }
  });
  it('maps a throwing provenance recorder to build_failed and sends nothing', async () => {
    const { a, seen } = rig(denyAll, { provenance: { forAction: () => { throw new Error('prov down'); } } as never });
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r.status === 'error' && r.error.code).toBe('build_failed');
    expect(r.status === 'error' && r.error.message).toBe('prov down');
    expect(seen).toHaveLength(1);
  });
  it('stamps ttl, clock and every signed slot, and sends the provenance bundle', async () => {
    const forAction = vi.fn((_a: unknown) => ({ bundle: 1 }));
    const { p, seen } = await denied({ ttlMs: 1000, now: () => 5000, provenance: { forAction } as never }, { caution: 0.5, rationaleCommitment: 'rc', progressStep: { s: 1 }, prohibitionEvidence: [1], toolBinding: 'tb' });
    expect(p.iat).toBe(5000);
    expect(p.exp).toBe(6000);
    expect(p.caution).toBe(0.5);
    expect(p.rationale_commitment).toBe('rc');
    expect(p.progress_step).toEqual({ s: 1 });
    expect(p.prohibition_evidence).toEqual([1]);
    expect(p.tool_binding).toBe('tb');
    expect(forAction).toHaveBeenCalledWith({ verb: 'read', resource: 'doc:1', params: {} });
    expect(JSON.parse(seen[1]!.init!.body!).pca_provenance).toEqual({ bundle: 1 });
  });
  it('omits unset slots, ttl and provenance from the wire', async () => {
    const { p, seen } = await denied({ now: () => 5000 });
    for (const k of ['caution', 'rationale_commitment', 'progress_step', 'prohibition_evidence', 'tool_binding']) expect(k in p).toBe(false);
    expect(JSON.parse(seen[1]!.init!.body!)).not.toHaveProperty('pca_provenance');
    expect(seen[1]!.init!.method).toBe('POST');
  });
  it('nonce: random hex by default, caller override, none when disabled', async () => {
    expect((await denied({})).p.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect((await denied({}, { nonce: 'n-1' })).p.nonce).toBe('n-1');
    expect('nonce' in (await denied({ nonce: false })).p).toBe(false);
    expect((await denied({ nonce: true })).p.nonce).toMatch(/^[0-9a-f]{32}$/);
  });
  it('nonce bytes are zero-padded to two hex digits', async () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((b: Uint8Array) => (b.fill(1), b)) as never);
    expect((await denied({})).p.nonce).toBe('01'.repeat(16));
  });
});

describe('act step-up detection', () => {
  const stepup = async (reply: Reply) => {
    const { a } = rig((url, body) => planOk(url, body) ?? reply);
    await a.commitPlan(plan);
    return a.act('n1');
  };
  it.each([
    ['202 alone', { status: 202, json: { stepup_id: 'su' } }],
    ['status field alone', { status: 200, json: { status: 'step_up_required', stepup_id: 'su' } }],
    ['flag alone', { status: 200, json: { step_up_required: true, stepup_id: 'su' } }],
  ])('%s', async (_n, reply) => {
    const r = await stepup(reply);
    expect(r.status).toBe('step_up');
    if (r.status === 'step_up') {
      expect(r.stepupId).toBe('su');
      expect(r.requiredT).toBe(2);
    }
  });
  it('does not treat a truthy non-true flag or other status as step-up', async () => {
    expect((await stepup({ status: 200, json: { step_up_required: 'yes', status: 'other', stepup_id: 'su', allow: false } })).status).toBe('denied');
  });
  it('requiredT: a number is used, anything else defaults to 2', async () => {
    const r = await stepup({ status: 202, json: { stepup_id: 'su', required_t: 3 } });
    expect(r.status === 'step_up' && r.requiredT).toBe(3);
    const s = await stepup({ status: 202, json: { stepup_id: 'su', required_t: '3' } });
    expect(s.status === 'step_up' && s.requiredT).toBe(2);
  });
  it('a step-up without an id is a bad_response', async () => {
    const r = await stepup({ status: 202, json: {} });
    expect(r.status === 'error' && r.error.code).toBe('bad_response');
    expect(r.status === 'error' && r.error.message).toBe('step-up response missing stepup_id');
    expect(r.status === 'error' && r.error.httpStatus).toBe(202);
  });
});

describe('act allow decision', () => {
  it('allows 200 and 299, denies 199 and 300 even with allow=true', async () => {
    for (const status of [200, 299]) expect((await actWith(allowing({ status })) .then((x) => x.r)).status).toBe('allowed');
    for (const status of [199, 300]) {
      const { r } = await actWith((url, body) => planOk(url, body) ?? { status, json: { allow: true, verdict: { allow: true } } });
      expect(r.status).toBe('denied');
    }
  });
  it('a verdict-only allow (no top-level allow) is allowed; a contradicting top-level allow is denied', async () => {
    expect((await actWith(allowing())).r.status).toBe('allowed');
    expect((await actWith(allowing({ body: { allow: false } }))).r.status).toBe('denied');
    expect((await actWith(allowing({ body: { allow: undefined } }))).r.status).toBe('allowed');
  });
  it('requires a receipt object', async () => {
    for (const receipt of [undefined, 'x']) {
      const { r } = await actWith(allowing({ receipt: () => receipt }));
      expect(r.status === 'error' && r.error.message).toBe('allow without receipt');
      expect(r.status === 'error' && r.error.httpStatus).toBe(200);
    }
  });
  it('refuses an inclusion proof that does not verify', async () => {
    const { r } = await actWith(allowing({ receipt: (x) => ({ ...x, root: 'AAAA' }) }));
    expect(r.status === 'error' && r.error.message).toBe('allow receipt inclusion proof does not verify');
  });
  it('refuses a salted receipt that does not commit to this action; skips the check without a salt', async () => {
    const { r } = await actWith(allowing({ salt: 's1', receipt: (x) => ({ ...x, salt: 'other' }) }));
    expect(r.status === 'error' && r.error.message).toBe('allow receipt does not commit to this action');
    expect((await actWith(allowing({ salt: undefined }))).r.status).toBe('allowed');
  });
  it('refuses a non-string salt even when the commit matches it', async () => {
    const { r } = await actWith(allowing({ salt: 5 }));
    expect(r.status === 'error' && r.error.message).toBe('allow receipt does not commit to this action');
  });
  it('refuses a salt that cannot be hashed', async () => {
    const { a } = rig((url, body) => {
      const pl = planOk(url, body);
      if (pl) return pl;
      const ledger = new TransparencyLedger();
      const { index, commit } = ledger.appendCommitment('c1');
      const head = ledger.head();
      return { status: 200, json: { allow: true, verdict: { allow: true }, receipt: { index, commit, root: head.root, size: head.size, salt: '\ud800', inclusion_proof: ledger.inclusionProof(index) } } };
    });
    await a.commitPlan(plan);
    const r = await a.act('n1');
    expect(r.status === 'error' && r.error.message).toBe('allow receipt does not commit to this action');
  });
  it('verifyReceipts=false accepts an unverifiable receipt', async () => {
    const { r } = await actWith(allowing({ receipt: (x) => ({ ...x, root: 'AAAA' }) }), { verifyReceipts: false });
    expect(r.status).toBe('allowed');
  });
  it('ignores a malformed budget and applies a well-formed one', async () => {
    for (const budget of [null, { B: 1, tau: 2, asOf: 'x' }, { B: 1, tau: 2 }]) {
      const { a, r } = await actWith(allowing({ verdict: { budget } }));
      expect(r.status).toBe('allowed');
      expect(a.budget).toBeUndefined();
    }
    const { a } = await actWith(allowing({ verdict: { budget: { B: 7, tau: 1, asOf: 3 } } }));
    expect(a.budget).toEqual({ B: 7, tau: 1, asOf: 3 });
  });
});

describe('awaitStepUp', () => {
  const sequence = (replies: Reply[]) => rig((url, body, n) => planOk(url, body) ?? replies[Math.min(n - 1, replies.length - 1)]!);
  it('default timeout is minutes, not milliseconds', async () => {
    const { a } = rig((() => { let n = 0; return () => (++n < 3 ? { status: 200, json: { status: 'pending' } } : { status: 200, json: { status: 'approved' } }); })());
    expect((await a.awaitStepUp('s', { pollMs: 1 })).status).toBe('approved');
  });
  it('GET on the encoded step-up path', async () => {
    const { a, seen } = rig(() => ({ status: 200, json: { status: 'approved' } }));
    await a.awaitStepUp('a/b', { timeoutMs: 60_000 });
    expect(seen[0]!.init!.method).toBe('GET');
    expect(seen[0]!.url).toBe('https://rs.test/v1/pca/stepups/a%2Fb?wait=25');
  });
  it('only a 2xx answer approves', async () => {
    for (const status of [199, 300]) {
      const { a } = rig(() => ({ status, json: { status: 'approved' } }));
      expect((await a.awaitStepUp('s', { pollMs: 1, timeoutMs: 1 })).status).toBe('timeout');
    }
    for (const status of [200, 299]) {
      const { a } = rig(() => ({ status, json: { status: 'denied', why: 'x' } }));
      expect(await a.awaitStepUp('s', { pollMs: 1, timeoutMs: 1000 })).toEqual({ status: 'denied', why: 'x' });
    }
  });
  it('4xx other than 429 is final, including 400 and 499; 429 keeps polling', async () => {
    for (const status of [400, 404, 499]) {
      const { a } = rig(() => ({ status, json: { status: 'approved' } }));
      expect(await a.awaitStepUp('s', { pollMs: 1, timeoutMs: 1000 })).toEqual({ status: 'denied', httpStatus: status });
    }
    const { a } = sequence([{ status: 429, json: {} }, { status: 200, json: { status: 'approved' } }]);
    expect((await a.awaitStepUp('s', { pollMs: 1, timeoutMs: 1000 })).status).toBe('approved');
  });
  it('a 5xx keeps polling until the deadline', async () => {
    const { a } = rig(() => ({ status: 500, json: {} }));
    expect((await a.awaitStepUp('s', { pollMs: 1, timeoutMs: 20 })).status).toBe('timeout');
  });
  it('polls again when the next poll lands exactly on the deadline', async () => {
    vi.useFakeTimers();
    const { a } = sequence([{ status: 200, json: { status: 'pending' } }, { status: 200, json: { status: 'approved' } }]);
    const p = a.awaitStepUp('s', { pollMs: 1000, timeoutMs: 1000 });
    await vi.advanceTimersByTimeAsync(1000);
    expect((await p).status).toBe('approved');
  });
  it('times out without sleeping when the next poll would pass the deadline', async () => {
    vi.useFakeTimers();
    const { a } = rig(() => ({ status: 200, json: { status: 'pending' } }));
    expect(await a.awaitStepUp('s', { pollMs: 1000, timeoutMs: 500 })).toEqual({ status: 'timeout' });
  });
  it('a thrown fetch becomes a network error', async () => {
    const a = createAgent({ grant, audience: 'ins_test', rsBaseUrl: 'https://rs.test', fetch: async () => { throw new Error('down'); } });
    const e = await a.awaitStepUp('s').catch((x) => x as PcaAgentError);
    expect(e.code).toBe('network');
    expect(e.message).toBe('down');
  });
});

describe('delegate', () => {
  it('needs an agentSecret', () => {
    const a = createAgent({ grant, audience: 'ins_test', rsBaseUrl: 'https://rs.test' });
    try {
      a.delegate({ toPublic: pub(subKp) });
      throw new Error('did not throw');
    } catch (e) {
      expect((e as PcaAgentError).code).toBe('no_secret');
      expect((e as PcaAgentError).message).toBe('cannot delegate without agentSecret');
    }
  });
  it('adds no caveats by default and extends the chain', () => {
    const { a } = rig(denyAll);
    const sub = a.delegate({ toPublic: pub(subKp), agentSecret: subKp.secretKey });
    expect(sub.chain).toHaveLength(2);
    expect(sub.chain[1]!.caveats).toEqual([]);
    expect(sub.agentPublic).toBe(pub(subKp));
    expect(sub.counter).toBe(0);
  });
  it('the sub-agent inherits ttl, clock, nonce setting and provenance', async () => {
    const forAction = vi.fn(() => ({ b: 1 }));
    const { a, seen } = rig(denyAll, { ttlMs: 1000, now: () => 5000, nonce: false, provenance: { forAction } as never });
    const sub = a.delegate({ toPublic: pub(subKp), agentSecret: subKp.secretKey });
    await sub.commitPlan(plan);
    const r = await sub.act('n1');
    expect(r.status).toBe('denied');
    const p = (r as { pcactn: PCActn }).pcactn;
    expect(p.iat).toBe(5000);
    expect(p.exp).toBe(6000);
    expect('nonce' in p).toBe(false);
    expect(forAction).toHaveBeenCalledTimes(1);
    expect(JSON.parse(seen[seen.length - 1]!.init!.body!).pca_provenance).toEqual({ b: 1 });
  });
  it('the sub-agent inherits verifyReceipts=false', async () => {
    const { a } = rig(allowing({ receipt: (x) => ({ ...x, root: 'AAAA' }) }), { verifyReceipts: false });
    const sub = a.delegate({ toPublic: pub(subKp), agentSecret: subKp.secretKey });
    await sub.commitPlan(plan);
    expect((await sub.act('n1')).status).toBe('allowed');
  });
});
