import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, reviewAction, type StepUpRequest } from '@atlasauth/pca';
import { CibaProviderError, createCibaClient, verifyPingCallback, toCibaAuthRequest } from './index';

function stepUp(): StepUpRequest {
  const a = agent({
    principal: generateKeyPair(),
    goal: 'reconcile October refunds',
    permissions: { stripe: ['payout'] },
    limits: { payout: '$100' },
    aud: 'ins_test',
    riskPolicy: { theta1: 0.3, theta2: 0.6 },
    now: 0,
  });
  const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { insecureUnboundApproval: true, now: 1, goal: 'reconcile October refunds' });
  if (r.kind !== 'step_up') throw new Error('expected step_up');
  return r.request;
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

/** A scripted token endpoint: each call pops the next reply; the clock advances only through `sleep`. */
function harness(replies: Response[]) {
  const t = { now: 1_000_000 };
  const sleeps: number[] = [];
  const calls: { url: string; body: string }[] = [];
  const fetchFn = (async (url: string, init: RequestInit) => {
    calls.push({ url, body: String(init.body) });
    if (url.endsWith('/auth')) return json(200, { auth_req_id: 'abc', expires_in: 120, interval: 2 });
    const next = replies.shift();
    if (!next) throw new Error('no scripted reply left');
    return next;
  }) as unknown as typeof fetch;
  const client = createCibaClient({
    backchannelAuthenticationEndpoint: 'http://op/auth',
    tokenEndpoint: 'http://op/token',
    clientId: 'c',
    clientSecret: 's',
    fetch: fetchFn,
    allowInsecureHttp: true,
    sleep: async (ms) => {
      sleeps.push(ms);
      t.now += ms;
    },
    now: () => t.now,
  });
  return { client, sleeps, calls, t };
}

describe('createCibaClient (offline, scripted provider)', () => {
  it('never polls faster than the interval and adds 5s on each slow_down (CIBA Core 11)', async () => {
    const h = harness([
      json(400, { error: 'authorization_pending' }),
      json(400, { error: 'slow_down' }),
      json(400, { error: 'slow_down' }),
      json(200, { access_token: 'at', token_type: 'Bearer' }),
    ]);
    const flow = await h.client.initiate(stepUp(), { loginHint: 'alice' });
    const poller = h.client.poller(flow);
    const r = await poller.wait();
    expect(r.status).toBe('approved');
    // 2s before the first poll, 2s after pending, then 7s after the first slow_down, 12s after the second
    expect(h.sleeps).toEqual([2000, 2000, 7000, 12000]);
    expect(poller.intervalSec()).toBe(12);
  });

  it('caches a terminal answer instead of re-sending an auth_req_id to the token endpoint', async () => {
    const h = harness([json(400, { error: 'access_denied' })]);
    const poller = h.client.poller(await h.client.initiate(stepUp(), { loginHint: 'alice' }));
    expect((await poller.poll()).status).toBe('denied');
    expect((await poller.poll()).status).toBe('denied');
    expect(h.calls.filter((c) => c.url.endsWith('/token'))).toHaveLength(1);
  });

  it('maps expired_token, stops locally at expires_in, and surfaces other errors', async () => {
    const h = harness([json(400, { error: 'expired_token' })]);
    expect((await h.client.poller(await h.client.initiate(stepUp(), { loginHint: 'a' })).poll()).status).toBe('expired');

    const h2 = harness([]);
    const flow = await h2.client.initiate(stepUp(), { loginHint: 'a' });
    h2.t.now += 121_000;
    expect((await h2.client.poller(flow).poll()).status).toBe('expired');
    expect(h2.calls.filter((c) => c.url.endsWith('/token'))).toHaveLength(0);

    const h3 = harness([json(401, { error: 'invalid_client', error_description: 'bad secret' })]);
    const p3 = h3.client.poller(await h3.client.initiate(stepUp(), { loginHint: 'a' }));
    await expect(p3.poll()).rejects.toBeInstanceOf(CibaProviderError);
  });

  it('requires exactly one hint and rejects a malformed provider reply', async () => {
    const h = harness([]);
    await expect(h.client.initiate(stepUp(), {})).rejects.toThrow(RangeError);
    await expect(h.client.initiate(stepUp(), { loginHint: 'a', idTokenHint: 'x.y.z' })).rejects.toThrow(RangeError);
    const bad = createCibaClient({
      backchannelAuthenticationEndpoint: 'http://op/auth',
      tokenEndpoint: 'http://op/token',
      clientId: 'c',
      clientSecret: 's',
      fetch: (async () => json(200, { auth_req_id: 'x', expires_in: -1 })) as unknown as typeof fetch,
      allowInsecureHttp: true,
    });
    await expect(bad.initiate(stepUp(), { loginHint: 'a' })).rejects.toBeInstanceOf(CibaProviderError);
  });

  it('sends client_notification_token only in ping mode and verifies the callback in constant time', async () => {
    const h = harness([]);
    const flow = await h.client.initiate(stepUp(), { loginHint: 'a', delivery: 'ping' });
    expect(new URLSearchParams(h.calls[0]?.body).get('client_notification_token')).toBe(flow.clientNotificationToken);
    expect(verifyPingCallback({ authorization: `Bearer ${flow.clientNotificationToken}`, body: { auth_req_id: 'abc' } }, flow)).toBe('abc');
    expect(() => verifyPingCallback({ authorization: 'Bearer nope', body: { auth_req_id: 'abc' } }, flow)).toThrow();
    expect(() => verifyPingCallback({ authorization: `Bearer ${flow.clientNotificationToken}`, body: { auth_req_id: 'other' } }, flow)).toThrow();
    const pollFlow = await h.client.initiate(stepUp(), { loginHint: 'a' });
    expect(new URLSearchParams(h.calls[1]?.body).has('client_notification_token')).toBe(false);
    expect(() => verifyPingCallback({ authorization: 'Bearer x', body: { auth_req_id: 'abc' } }, pollFlow)).toThrow();
  });
});

describe('bindingMessage profile', () => {
  it('token-only mode stays within A-Za-z0-9._- and maxChars, cut on a token boundary', () => {
    const su = stepUp();
    const r = toCibaAuthRequest(su, { bindingMessage: { tokenOnly: true } });
    expect(r.binding_message).toMatch(/^[A-Za-z0-9._-]{1,50}$/);
    expect(r.binding_message.startsWith('Approve-stripe.payout-80-USD-to-bob')).toBe(true);
    // A limit that cannot hold the whole decision is refused, never silently truncated.
    expect(() => toCibaAuthRequest(su, { bindingMessage: { tokenOnly: true, maxChars: 21 } })).toThrow(RangeError);
    expect(toCibaAuthRequest(su, { bindingMessage: { tokenOnly: true, maxChars: 50 } }).binding_message).toBe('Approve-stripe.payout-80-USD-to-bob-acct-1');
    expect(() => toCibaAuthRequest(su, { bindingMessage: { maxChars: 0 } })).toThrow(RangeError);
  });
});

function stepUpWith(params: Record<string, unknown>, resource = 'acct:1'): StepUpRequest {
  return { ...stepUp(), params, resource } as StepUpRequest;
}

describe('tokenOnly binding message never misstates the decision', () => {
  const t = { bindingMessage: { tokenOnly: true, maxChars: 80 } } as const;
  it('rejects negative, exponent and non-plain amounts', () => {
    for (const amount of [-500, 1e21, 1e-7, Number.NaN, Infinity, '5e2', ' 5', '5 ']) {
      expect(() => toCibaAuthRequest(stepUpWith({ amount, currency: 'USD', payee: 'bob' }), t), String(amount)).toThrow(RangeError);
    }
    expect(toCibaAuthRequest(stepUpWith({ amount: 12.5, currency: 'eur', payee: 'bob' }), t).binding_message).toBe('Approve-stripe.payout-12.5-EUR-to-bob-acct-1');
  });
  it('rejects a currency or resource that would be dropped or altered', () => {
    expect(() => toCibaAuthRequest(stepUpWith({ amount: 5, currency: 'US D', payee: 'bob' }), t)).toThrow(RangeError);
    expect(() => toCibaAuthRequest(stepUpWith({ amount: 5, currency: 7, payee: 'bob' }), t)).toThrow(RangeError);
    expect(() => toCibaAuthRequest(stepUpWith({ amount: 5, currency: 'USD', payee: 'bob' }, ':::'), t)).toThrow(RangeError);
  });
  it('refuses when the limit would truncate amount, currency or resource', () => {
    expect(() => toCibaAuthRequest(stepUpWith({ amount: 480, currency: 'EUR', payee: 'bob' }, 'acct:9'), { bindingMessage: { tokenOnly: true, maxChars: 30 } })).toThrow(RangeError);
  });
});

describe('client robustness', () => {
  const cfg = (fetchFn: typeof fetch, extra: Record<string, unknown> = {}) => ({
    backchannelAuthenticationEndpoint: 'https://op/auth',
    tokenEndpoint: 'https://op/token',
    clientId: 'c',
    clientSecret: 's',
    fetch: fetchFn,
    ...extra,
  });
  const flowOf = () => ({
    authReqId: 'abc', expiresInSec: 600, intervalSec: 2, startedAt: 0, delivery: 'poll' as const, request: toCibaAuthRequest(stepUp()),
  });

  it('rejects http:// endpoints unless allowInsecureHttp is set', () => {
    const f = (async () => json(200, {})) as unknown as typeof fetch;
    expect(() => createCibaClient({ ...cfg(f), tokenEndpoint: 'http://op/token' })).toThrow(RangeError);
    expect(() => createCibaClient({ ...cfg(f), backchannelAuthenticationEndpoint: 'http://op/auth' })).toThrow(RangeError);
    expect(() => createCibaClient({ ...cfg(f), tokenEndpoint: 'http://op/token', allowInsecureHttp: true })).not.toThrow();
  });

  it('requires a caller-supplied clientNotificationToken of at least 128 bits', async () => {
    const f = (async () => json(200, { auth_req_id: 'a', expires_in: 60 })) as unknown as typeof fetch;
    const c = createCibaClient(cfg(f));
    await expect(c.initiate(stepUp(), { loginHint: 'a', delivery: 'ping', clientNotificationToken: 'short' })).rejects.toThrow(RangeError);
    await expect(c.initiate(stepUp(), { loginHint: 'a', delivery: 'ping', clientNotificationToken: 'x'.repeat(22) })).resolves.toBeTruthy();
  });

  it('verifyPingCallback accepts a case-insensitive Bearer scheme', () => {
    const flow = { authReqId: 'abc', clientNotificationToken: 'T'.repeat(30) };
    for (const scheme of ['bearer', 'BEARER', 'Bearer']) {
      expect(verifyPingCallback({ authorization: `${scheme} ${flow.clientNotificationToken}`, body: { auth_req_id: 'abc' } }, flow)).toBe('abc');
    }
  });

  it('dedupes concurrent poll() calls into one token request', async () => {
    let n = 0;
    const f = (async () => { n += 1; await new Promise((r) => setTimeout(r, 5)); return json(400, { error: 'authorization_pending' }); }) as unknown as typeof fetch;
    const p = createCibaClient(cfg(f, { sleep: async () => {}, now: () => 10_000 })).poller(flowOf());
    const [a, b, c] = await Promise.all([p.poll(), p.poll(), p.poll()]);
    expect(n).toBe(1);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('notify() wakes a sleeping wait()', async () => {
    let calls = 0;
    const f = (async () => { calls += 1; return json(200, { access_token: 't', token_type: 'Bearer' }); }) as unknown as typeof fetch;
    const p = createCibaClient(cfg(f, { sleep: () => new Promise<void>(() => {}), now: () => 0 })).poller(flowOf());
    const w = p.wait();
    await new Promise((r) => setTimeout(r, 10));
    expect(calls).toBe(0);
    p.notify();
    await expect(w).resolves.toMatchObject({ status: 'approved' });
  });

  it('backs off after a thrown fetch, a 5xx and a non-JSON reply', async () => {
    const replies: (() => Response | Promise<Response>)[] = [
      () => { throw new Error('ECONNRESET'); },
      () => new Response('boom', { status: 503 }),
      () => new Response('<html>', { status: 200 }),
    ];
    const t = { now: 0 };
    const sleeps: number[] = [];
    const f = (async () => replies.shift()!()) as unknown as typeof fetch;
    const p = createCibaClient(cfg(f, { now: () => t.now, sleep: async (ms: number) => { sleeps.push(ms); t.now += ms; } })).poller({ ...flowOf(), startedAt: 0 });
    for (let i = 0; i < 3; i++) {
      await expect(p.poll()).rejects.toMatchObject({ retryable: true });
    }
    expect(sleeps.length).toBe(3);
    expect(sleeps[1]!).toBeGreaterThan(sleeps[0]!);
    expect(sleeps[2]!).toBeGreaterThan(sleeps[1]!);
  });

  it('aborts a hung fetch on timeout and on the caller signal', async () => {
    const hang = ((_u: string, init: RequestInit) => new Promise((_r, rej) => {
      init.signal?.addEventListener('abort', () => rej(new Error('aborted by signal')));
    })) as unknown as typeof fetch;
    const c = createCibaClient(cfg(hang, { timeoutMs: 20 }));
    await expect(c.initiate(stepUp(), { loginHint: 'a' })).rejects.toMatchObject({ error: 'network_error', retryable: true });
    const p = createCibaClient(cfg(hang, { sleep: async () => {}, now: () => 10_000 })).poller(flowOf());
    const ac = new AbortController();
    const w = p.wait({ signal: ac.signal });
    setTimeout(() => ac.abort(), 10);
    await expect(w).rejects.toThrow(/aborted/);
  });
});
