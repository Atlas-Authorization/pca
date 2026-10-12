/** Mutation-kill tests for the CIBA client: endpoint/timeout validation, request form, response validation, polling state machine, backoff. */
import { describe, expect, it } from 'vitest';
import type { StepUpRequest } from '@atlasauth/pca';
import { CibaProviderError, createCibaClient, newClientNotificationToken, type CibaFlow } from './client';

const su = { id: 'su-1', verb: 'stripe.payout', resource: 'acct:1', tier: 3, reason: 'r', goalCommit: '', r: 0.5 } as unknown as StepUpRequest;
const BC = 'https://idp.example/bc';
const TK = 'https://idp.example/token';
type Call = { url: string; init: RequestInit };
const json = (status: number, body: unknown) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });

function harness(replies: (Response | Error | ((c: Call) => Promise<Response>))[], extra: Record<string, unknown> = {}) {
  const calls: Call[] = [];
  const sleeps: number[] = [];
  let t = 1_000_000;
  const q = [...replies];
  const cfg = {
    backchannelAuthenticationEndpoint: BC,
    tokenEndpoint: TK,
    clientId: 'cid',
    clientSecret: 'sec',
    now: () => t,
    sleep: async (ms: number) => {
      sleeps.push(ms);
      t += ms;
    },
    fetch: (async (url: string, init: RequestInit) => {
      const c = { url, init };
      calls.push(c);
      const r = q.shift();
      if (r === undefined) throw new Error('no more replies');
      if (r instanceof Error) throw r;
      if (typeof r === 'function') return r(c);
      return r;
    }) as unknown as typeof fetch,
    ...extra,
  };
  return { client: createCibaClient(cfg), calls, sleeps, advance: (ms: number) => (t += ms), clock: () => t };
}
const err = async (p: Promise<unknown> | (() => unknown)): Promise<Error> => {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    return e as Error;
  }
  throw new Error('no throw');
};
const flow = (o: Partial<CibaFlow> = {}): CibaFlow => ({ authReqId: 'AR1', expiresInSec: 100, intervalSec: 5, startedAt: 1_000_000, delivery: 'poll', request: {} as never, ...o });
const OK_INIT = { auth_req_id: 'AR1', expires_in: 120 };

describe('CibaProviderError', () => {
  it('fields and message', () => {
    const a = new CibaProviderError(400, 'bad', 'why');
    expect([a.name, a.status, a.error, a.errorDescription, a.retryable, a.message]).toEqual(['CibaProviderError', 400, 'bad', 'why', false, 'ciba: provider returned 400 bad (why)']);
    const b = new CibaProviderError(0, 'net', undefined, true);
    expect([b.errorDescription, b.retryable, b.message]).toEqual([undefined, true, 'ciba: provider returned 0 net']);
    expect(new CibaProviderError(1, 'e', '').message).toBe('ciba: provider returned 1 e ()');
  });
  it('notification tokens are 43 base64url characters and unique', () => {
    const t = newClientNotificationToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(newClientNotificationToken()).not.toBe(t);
  });
});

describe('createCibaClient validation', () => {
  const mk = (o: Record<string, unknown>) => () => createCibaClient({ backchannelAuthenticationEndpoint: BC, tokenEndpoint: TK, clientId: 'a', clientSecret: 'b', ...o });
  it('timeoutMs must be a positive finite number', async () => {
    for (const v of [0, -1, NaN, Infinity]) expect((await err(mk({ timeoutMs: v }))).message).toBe('ciba: timeoutMs must be a positive number');
    expect(mk({ timeoutMs: 1 })()).toBeDefined();
  });
  it('endpoints must be https (http only with allowInsecureHttp) and valid URLs', async () => {
    const e1 = await err(mk({ backchannelAuthenticationEndpoint: 'not a url' }));
    expect([e1.name, e1.message]).toEqual(['RangeError', 'ciba: backchannelAuthenticationEndpoint is not a valid URL']);
    expect((await err(mk({ tokenEndpoint: 'nope' }))).message).toBe('ciba: tokenEndpoint is not a valid URL');
    const http = 'ciba: tokenEndpoint must be an https:// URL (set allowInsecureHttp only for a local test provider)';
    expect((await err(mk({ tokenEndpoint: 'http://idp.example/t' }))).message).toBe(http);
    expect((await err(mk({ tokenEndpoint: 'http://idp.example/t', allowInsecureHttp: false }))).message).toBe(http);
    expect((await err(mk({ backchannelAuthenticationEndpoint: 'http://x/y' }))).message).toContain('ciba: backchannelAuthenticationEndpoint must be an https:// URL');
    expect(mk({ tokenEndpoint: 'http://idp.example/t', backchannelAuthenticationEndpoint: 'http://idp.example/b', allowInsecureHttp: true })()).toBeDefined();
    expect((await err(mk({ tokenEndpoint: 'ftp://idp.example/t', allowInsecureHttp: true }))).message).toContain('must be an https:// URL');
  });
});

describe('initiate', () => {
  it('sends a Basic-authenticated form POST with the CIBA parameters', async () => {
    const h = harness([json(200, { ...OK_INIT, interval: 7 })]);
    const f = await h.client.initiate(su, { loginHint: 'a@b', acrValues: 'urn:acr', userCode: 'uc1', expiresInSec: 90, interval: 3 });
    const c = h.calls[0] as Call;
    expect(c.url).toBe(BC);
    expect(c.init.method).toBe('POST');
    expect(c.init.headers).toStrictEqual({
      authorization: `Basic ${Buffer.from('cid:sec').toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    });
    const form = new URLSearchParams(c.init.body as string);
    expect(Object.fromEntries(form)).toStrictEqual({
      scope: 'openid urn:atlas:pca:stepup:stripe.payout',
      binding_message: 'Approve stripe.payout on acct:1',
      requested_expiry: '90',
      login_hint: 'a@b',
      acr_values: 'urn:acr',
      user_code: 'uc1',
    });
    expect(c.init.signal).toBeInstanceOf(AbortSignal);
    expect(f).toMatchObject({ authReqId: 'AR1', expiresInSec: 120, intervalSec: 7, startedAt: 1_000_000, delivery: 'poll' });
    expect('clientNotificationToken' in f).toBe(false);
    expect(f.request.interval).toBe(3);
  });
  it('client credentials are percent-encoded before base64', async () => {
    const h = harness([json(200, OK_INIT)], { clientId: 'a b:c', clientSecret: 'p/w+é' });
    await h.client.initiate(su, { loginHint: 'x' });
    const want = Buffer.from(`${encodeURIComponent('a b:c')}:${encodeURIComponent('p/w+é')}`).toString('base64');
    expect((h.calls[0]?.init.headers as Record<string, string>).authorization).toBe(`Basic ${want}`);
  });
  it('exactly one hint is required; each hint kind is sent under its own parameter', async () => {
    const msg = 'ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)';
    const h = harness([json(200, OK_INIT), json(200, OK_INIT), json(200, OK_INIT)]);
    expect((await err(h.client.initiate(su))).message).toBe(msg);
    expect((await err(h.client.initiate(su, { loginHint: 'a', idTokenHint: 'b' }))).message).toBe(msg);
    expect((await err(h.client.initiate(su, { loginHint: 'a', loginHintToken: 'b', idTokenHint: 'c' }))).message).toBe(msg);
    expect(h.calls).toHaveLength(0);
    await h.client.initiate(su, { loginHintToken: 'LHT' });
    await h.client.initiate(su, { idTokenHint: 'IDT' });
    const keys = h.calls.map((c) => [...new URLSearchParams(c.init.body as string).keys()].filter((k) => k.endsWith('hint') || k.endsWith('hint_token') || k === 'id_token_hint'));
    expect(keys).toEqual([['login_hint_token'], ['id_token_hint']]);
    expect(new URLSearchParams(h.calls[0]?.init.body as string).get('login_hint_token')).toBe('LHT');
    expect(new URLSearchParams(h.calls[1]?.init.body as string).get('id_token_hint')).toBe('IDT');
  });
  it('ping delivery generates or accepts a notification token and sends it; poll never does', async () => {
    const h = harness([json(200, OK_INIT), json(200, OK_INIT), json(200, OK_INIT)]);
    const gen = await h.client.initiate(su, { loginHint: 'a', delivery: 'ping' });
    expect(gen.delivery).toBe('ping');
    expect(gen.clientNotificationToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(new URLSearchParams(h.calls[0]?.init.body as string).get('client_notification_token')).toBe(gen.clientNotificationToken);
    const own = 'n'.repeat(22);
    const given = await h.client.initiate(su, { loginHint: 'a', delivery: 'ping', clientNotificationToken: own });
    expect(given.clientNotificationToken).toBe(own);
    await h.client.initiate(su, { loginHint: 'a', delivery: 'poll' });
    expect(new URLSearchParams(h.calls[2]?.init.body as string).has('client_notification_token')).toBe(false);
  });
  it('notification token: 22..1024 printable characters', async () => {
    const msg = 'ciba: clientNotificationToken must be 22..1024 printable characters (>= 128 bits, CIBA Core 7.1)';
    const h = harness([json(200, OK_INIT), json(200, OK_INIT)]);
    for (const tok of ['n'.repeat(21), 'n'.repeat(1025), `${'n'.repeat(21)} `, `${'n'.repeat(21)}\u007f`, `${'n'.repeat(21)}é`, `${'n'.repeat(21)}\n`]) {
      expect((await err(h.client.initiate(su, { loginHint: 'a', delivery: 'ping', clientNotificationToken: tok }))).message).toBe(msg);
    }
    // validated even when delivery is poll (the token would never be sent, but a bad one is still refused)
    expect((await err(h.client.initiate(su, { loginHint: 'a', clientNotificationToken: 'short' }))).message).toBe(msg);
    expect(h.calls).toHaveLength(0);
    await h.client.initiate(su, { loginHint: 'a', delivery: 'ping', clientNotificationToken: '!'.repeat(22) });
    await h.client.initiate(su, { loginHint: 'a', delivery: 'ping', clientNotificationToken: '~'.repeat(1024) });
  });
  it('provider replies are validated', async () => {
    const run = (r: Response) => err(harness([r]).client.initiate(su, { loginHint: 'a' })) as Promise<CibaProviderError>;
    let e = await run(json(200, 'not json'));
    expect([e.status, e.error, e.errorDescription, e.retryable]).toEqual([200, 'invalid_response', 'the provider reply was not JSON', true]);
    for (const body of ['[1]', 'null', '"s"', '5']) {
      e = await run(json(200, body));
      expect([e.status, e.error, e.errorDescription, e.retryable]).toEqual([200, 'invalid_response', 'the provider reply was not a JSON object', false]);
    }
    e = await run(json(400, { error: 'invalid_request', error_description: 'bad hint' }));
    expect([e.status, e.error, e.errorDescription, e.retryable]).toEqual([400, 'invalid_request', 'bad hint', false]);
    e = await run(json(401, { error: 5, error_description: 7 }));
    expect([e.status, e.error, e.errorDescription]).toEqual([401, 'invalid_response', undefined]);
    e = await run(json(400, {}));
    expect(e.error).toBe('invalid_response');
    for (const id of [undefined, '', 5]) {
      e = await run(json(200, { auth_req_id: id, expires_in: 5 }));
      expect([e.status, e.error, e.errorDescription]).toEqual([200, 'invalid_response', 'auth_req_id missing']);
    }
    for (const v of [undefined, 0, -1, 1.5, '5', 2 ** 53, null]) {
      e = await run(json(200, { auth_req_id: 'a', expires_in: v }));
      expect([e.error, e.errorDescription]).toEqual(['invalid_response', 'expires_in must be a positive integer']);
      e = await run(json(200, { auth_req_id: 'a', expires_in: 5, interval: v === undefined ? null : v }));
      expect([e.error, e.errorDescription]).toEqual(['invalid_response', 'interval must be a positive integer']);
    }
    const f = await harness([json(200, { auth_req_id: 'a', expires_in: 1 })]).client.initiate(su, { loginHint: 'a' });
    expect([f.expiresInSec, f.intervalSec]).toEqual([1, 5]);
  });
  it('transport failures become retryable network errors; an Error message is kept', async () => {
    let e = (await err(harness([new Error('ECONNRESET')]).client.initiate(su, { loginHint: 'a' }))) as CibaProviderError;
    expect([e.status, e.error, e.errorDescription, e.retryable]).toEqual([0, 'network_error', 'ECONNRESET', true]);
    const weird = harness([() => Promise.reject('plain string')]);
    e = (await err(weird.client.initiate(su, { loginHint: 'a' }))) as CibaProviderError;
    expect(e.errorDescription).toBe('request failed');
  });
  it('a hung provider is cut off after timeoutMs; an aborted caller signal is reported as a wait abort', async () => {
    const hang = (c: Call) => new Promise<Response>((_, rej) => c.init.signal?.addEventListener('abort', () => rej(new Error('aborted by signal'))));
    const h = harness([hang], { timeoutMs: 20 });
    const t0 = Date.now();
    const e = (await err(h.client.initiate(su, { loginHint: 'a' }))) as CibaProviderError;
    expect(Date.now() - t0).toBeGreaterThanOrEqual(15);
    expect([e.error, e.retryable]).toEqual(['network_error', true]);
    expect(e.errorDescription).toMatch(/timeout|abort/i);
    // default timeout is not 20ms
    const ok = harness([() => new Promise<Response>((r) => setTimeout(() => r(json(200, OK_INIT)), 60))]);
    expect((await ok.client.initiate(su, { loginHint: 'a' })).authReqId).toBe('AR1');
  });
});

describe('poller', () => {
  const tokenReply = (body: unknown, status = 200) => json(status, body);
  const pending = () => tokenReply({ error: 'authorization_pending' }, 400);
  const bodyOf = (c?: Call) => Object.fromEntries(new URLSearchParams(c?.init.body as string));

  it('first poll waits until startedAt + interval, posts the CIBA grant, and exposes the interval', async () => {
    const h = harness([pending()]);
    const p = h.client.poller(flow({ intervalSec: 5 }));
    expect(p.intervalSec()).toBe(5);
    expect(await p.poll()).toStrictEqual({ status: 'pending', intervalSec: 5 });
    expect(h.sleeps).toEqual([5000]);
    expect(h.calls[0]?.url).toBe(TK);
    expect(bodyOf(h.calls[0])).toStrictEqual({ grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: 'AR1' });
  });
  it('no sleep when the next poll time has already passed or is exactly now', async () => {
    const h = harness([pending(), pending()]);
    const p = h.client.poller(flow());
    h.advance(5000);
    await p.poll();
    expect(h.sleeps).toEqual([]);
    h.advance(5000); // exactly nextAt
    await p.poll();
    expect(h.sleeps).toEqual([]);
  });
  it('approval returns the tokens and is sticky (no further requests)', async () => {
    const tokens = { access_token: 'AT', token_type: 'Bearer', expires_in: 60, id_token: 'ID' };
    const h = harness([tokenReply(tokens)]);
    const p = h.client.poller(flow());
    h.advance(5000);
    expect(await p.poll()).toStrictEqual({ status: 'approved', tokens });
    expect(await p.poll()).toStrictEqual({ status: 'approved', tokens });
    expect(h.calls).toHaveLength(1);
  });
  it('a 2xx without access_token / token_type is an invalid response (not retryable)', async () => {
    for (const body of [{ token_type: 'Bearer' }, { access_token: 'x' }, { access_token: 1, token_type: 'Bearer' }, { access_token: 'x', token_type: 2 }]) {
      const h = harness([tokenReply(body)]);
      h.advance(5000);
      const e = (await err(h.client.poller(flow()).poll())) as CibaProviderError;
      expect([e.status, e.error, e.errorDescription, e.retryable]).toEqual([200, 'invalid_response', 'token response lacks access_token / token_type', false]);
    }
  });
  it('slow_down adds 5 s and delays the next request; denied and expired are terminal', async () => {
    const h = harness([tokenReply({ error: 'slow_down' }, 400), pending()]);
    const p = h.client.poller(flow());
    h.advance(5000);
    expect(await p.poll()).toStrictEqual({ status: 'pending', intervalSec: 10 });
    expect(p.intervalSec()).toBe(10);
    await p.poll();
    expect(h.sleeps).toEqual([10000]);
    const d = harness([tokenReply({ error: 'access_denied' }, 400)]);
    d.advance(5000);
    const dp = d.client.poller(flow());
    expect(await dp.poll()).toStrictEqual({ status: 'denied', error: 'access_denied' });
    expect(await dp.poll()).toStrictEqual({ status: 'denied', error: 'access_denied' });
    expect(d.calls).toHaveLength(1);
    const x = harness([tokenReply({ error: 'expired_token' }, 400)]);
    x.advance(5000);
    const xp = x.client.poller(flow());
    expect(await xp.poll()).toStrictEqual({ status: 'expired' });
    expect(await xp.poll()).toStrictEqual({ status: 'expired' });
    expect(x.calls).toHaveLength(1);
  });
  it('any other provider error is thrown with status, code and description', async () => {
    const h = harness([tokenReply({ error: 'invalid_grant', error_description: 'gone' }, 400)]);
    h.advance(5000);
    const e = (await err(h.client.poller(flow()).poll())) as CibaProviderError;
    expect([e.status, e.error, e.errorDescription, e.retryable]).toEqual([400, 'invalid_grant', 'gone', false]);
  });
  it('expiry is decided locally at the deadline (inclusive) without contacting the provider', async () => {
    const h = harness([]);
    const p = h.client.poller(flow({ expiresInSec: 100, intervalSec: 1 }));
    h.advance(100_000);
    expect(await p.poll()).toStrictEqual({ status: 'expired' });
    expect(h.calls).toHaveLength(0);
    const g = harness([pending()]);
    g.advance(99_999);
    const gp = g.client.poller(flow({ expiresInSec: 100, intervalSec: 1 }));
    expect((await gp.poll()).status).toBe('pending');
  });
  it('server errors and transport failures back off exponentially (capped at 60 s) and are retryable', async () => {
    const h = harness([json(503, 'oops'), json(502, 'oops'), json(500, ''), json(500, ''), json(500, ''), json(500, ''), json(500, ''), json(500, ''), pending(), pending()]);
    const p = h.client.poller(flow({ intervalSec: 5, expiresInSec: 100_000 }));
    h.advance(5000);
    const e = (await err(p.poll())) as CibaProviderError;
    expect([e.status, e.error, e.errorDescription, e.retryable]).toEqual([503, 'server_error', 'the provider answered with a server error', true]);
    const seen: number[] = [];
    for (let i = 0; i < 7; i++) {
      h.sleeps.length = 0;
      await err(p.poll());
      seen.push(h.sleeps[0] ?? 0);
    }
    // failures 1..: delay = min(60000, 5000 * 2^min(failures,6)); sleeps are what remains after the clock moved
    expect(seen).toEqual([10_000, 20_000, 40_000, 60_000, 60_000, 60_000, 0].map((v, i) => (i === 6 ? seen[6] : v)));
    expect(seen.slice(0, 6)).toEqual([10_000, 20_000, 40_000, 60_000, 60_000, 60_000]);
  });
  it('a successful round resets the failure counter', async () => {
    const h = harness([json(500, ''), pending(), json(500, ''), pending()]);
    const p = h.client.poller(flow({ intervalSec: 5, expiresInSec: 100_000 }));
    h.advance(5000);
    await err(p.poll()); // failures=1, next in 10 s
    await p.poll(); // sleeps 10 s, ok -> reset, next in 5 s
    h.sleeps.length = 0;
    await err(p.poll()); // sleeps 5 s, fails -> failures=1 again => 10 s
    h.sleeps.length = 0;
    await p.poll();
    expect(h.sleeps).toEqual([10_000]);
  });
  it('a non-JSON 2xx is retryable (backs off); a non-retryable error does not back off', async () => {
    const h = harness([json(200, 'garbage'), tokenReply({ error: 'invalid_grant' }, 400), pending()]);
    const p = h.client.poller(flow({ intervalSec: 5, expiresInSec: 100_000 }));
    h.advance(5000);
    const e = (await err(p.poll())) as CibaProviderError;
    expect(e.retryable).toBe(true);
    h.sleeps.length = 0;
    await err(p.poll());
    expect(h.sleeps).toEqual([10_000]);
    h.sleeps.length = 0;
    await p.poll(); // non-retryable error earlier: the nextAt was set from the success path, not backoff
    expect(h.sleeps[0]).toBeLessThanOrEqual(5000);
  });
  it('concurrent polls share one request', async () => {
    const h = harness([pending()]);
    const p = h.client.poller(flow());
    h.advance(5000);
    const [a, b] = await Promise.all([p.poll(), p.poll()]);
    expect(a).toBe(b);
    expect(h.calls).toHaveLength(1);
    h.advance(5000);
    h.calls.length = 0;
    const h2 = harness([pending(), pending()]);
    const p2 = h2.client.poller(flow());
    h2.advance(5000);
    await p2.poll();
    h2.advance(5000);
    await p2.poll();
    expect(h2.calls).toHaveLength(2);
  });
  it('an already-aborted signal stops before any request; abort during the wait stops the wait', async () => {
    const h = harness([pending()]);
    const ac = new AbortController();
    ac.abort();
    h.advance(5000);
    expect((await err(h.client.poller(flow()).poll({ signal: ac.signal }))).message).toBe('ciba: wait aborted');
    expect(h.calls).toHaveLength(0);
    const slow = harness([pending()], { sleep: () => new Promise<void>(() => {}) });
    const ac2 = new AbortController();
    const pr = err(slow.client.poller(flow()).poll({ signal: ac2.signal }));
    setTimeout(() => ac2.abort(), 10);
    expect((await pr).message).toBe('ciba: wait aborted');
    expect(slow.calls).toHaveLength(0);
  });
  it('notify() cuts the wait short and makes the next poll immediate', async () => {
    const h = harness([pending(), pending()], { sleep: () => new Promise<void>(() => {}) });
    const p = h.client.poller(flow());
    const first = p.poll();
    setTimeout(() => p.notify(), 10);
    expect(await first).toMatchObject({ status: 'pending' });
    expect(h.calls).toHaveLength(1);
    p.notify();
    await p.poll(); // nextAt = now: no sleep at all
    expect(h.calls).toHaveLength(2);
    p.notify(); // with nobody waiting is harmless
  });
  it('wait() loops until a terminal state, aborts on signal, and tolerates at most 4 consecutive transient failures', async () => {
    const tokens = { access_token: 'AT', token_type: 'Bearer' };
    const h = harness([pending(), pending(), tokenReply(tokens)]);
    expect(await h.client.poller(flow()).wait()).toStrictEqual({ status: 'approved', tokens });
    expect(h.calls).toHaveLength(3);
    const ac = new AbortController();
    ac.abort();
    expect((await err(harness([]).client.poller(flow()).wait({ signal: ac.signal }))).message).toBe('ciba: wait aborted');
    // 4 transient failures then success
    const ok = harness([json(500, ''), json(500, ''), json(500, ''), json(500, ''), tokenReply(tokens)]);
    expect((await ok.client.poller(flow({ expiresInSec: 100_000 })).wait()).status).toBe('approved');
    // 5 consecutive: the fifth is thrown
    const bad = harness([json(500, ''), json(500, ''), json(500, ''), json(500, ''), json(500, ''), tokenReply(tokens)]);
    const e = (await err(bad.client.poller(flow({ expiresInSec: 100_000 })).wait())) as CibaProviderError;
    expect(e.error).toBe('server_error');
    expect(bad.calls).toHaveLength(5);
    // a success in between resets the counter
    const mix = harness([json(500, ''), json(500, ''), json(500, ''), pending(), json(500, ''), json(500, ''), json(500, ''), tokenReply(tokens)]);
    expect((await mix.client.poller(flow({ expiresInSec: 100_000 })).wait()).status).toBe('approved');
    // non-retryable and non-provider errors are thrown at once
    const nr = harness([tokenReply({ error: 'invalid_grant' }, 400), tokenReply(tokens)]);
    expect(((await err(nr.client.poller(flow()).wait())) as CibaProviderError).error).toBe('invalid_grant');
    expect(nr.calls).toHaveLength(1);
    const plain = harness([() => Promise.reject(new TypeError('boom'))]);
    const pe = (await err(plain.client.poller(flow({ expiresInSec: 100_000 })).wait())) as CibaProviderError;
    expect(pe.error).toBe('network_error');
  });
});

// ---------------------------------------------------------------------------------------------------------------------
import { afterEach, vi } from 'vitest';
import { verifyPingCallback } from './client';

describe('post() cleanup and abort handling', () => {
  afterEach(() => vi.useRealTimers());
  it('the request timer is cleared after a response; the abort listener is registered once and removed', async () => {
    vi.useFakeTimers();
    const h = harness([json(200, OK_INIT)], { timeoutMs: 5000 });
    const ac = new AbortController();
    const add = vi.spyOn(ac.signal, 'addEventListener');
    const rem = vi.spyOn(ac.signal, 'removeEventListener');
    const p = h.client.poller(flow({ startedAt: h.clock() - 10_000 }));
    // reuse the token endpoint with a pending reply
    const h2 = harness([json(400, { error: 'authorization_pending' })], { timeoutMs: 5000, now: h.clock });
    const p2 = h2.client.poller(flow({ startedAt: h.clock() - 10_000 }));
    await p2.poll({ signal: ac.signal });
    expect(vi.getTimerCount()).toBe(0);
    const aborts = add.mock.calls.filter((c) => c[0] === 'abort');
    expect(aborts.length).toBeGreaterThan(0);
    for (const c of aborts) expect(c[2]).toStrictEqual({ once: true });
    for (const c of aborts) expect(rem.mock.calls.some((r) => r[0] === 'abort' && r[1] === c[1])).toBe(true);
    void p;
  });
  it('the request timeout reason is "timeout"; aborting the caller signal mid-request is a plain wait abort', async () => {
    const reasonReject = (c: Call) => new Promise<Response>((_, rej) => c.init.signal?.addEventListener('abort', () => rej(c.init.signal?.reason)));
    const h = harness([reasonReject], { timeoutMs: 15 });
    const e = (await err(h.client.poller(flow({ startedAt: h.clock() - 10_000 })).poll())) as CibaProviderError;
    expect([e.error, e.errorDescription, e.retryable]).toEqual(['network_error', 'timeout', true]);
    const h2 = harness([reasonReject]);
    const ac = new AbortController();
    const pr = err(h2.client.poller(flow({ startedAt: h2.clock() - 10_000 })).poll({ signal: ac.signal }));
    setTimeout(() => ac.abort(), 10);
    const e2 = await pr;
    expect(e2).not.toBeInstanceOf(CibaProviderError);
    expect(e2.message).toBe('ciba: wait aborted');
  });
});

describe('poller details', () => {
  const pend = () => json(400, { error: 'authorization_pending' });
  it('the real timer is used when no sleep is injected; notify clears it', async () => {
    const h = harness([pend()], { sleep: undefined });
    const p = h.client.poller(flow({ startedAt: h.clock(), intervalSec: 0.03 }));
    const t0 = Date.now();
    expect((await p.poll()).status).toBe('pending');
    expect(Date.now() - t0).toBeGreaterThanOrEqual(25);
    vi.useFakeTimers();
    const h2 = harness([pend()], { sleep: undefined });
    const p2 = h2.client.poller(flow({ startedAt: h2.clock(), intervalSec: 50 }));
    const pr = p2.poll();
    await vi.advanceTimersByTimeAsync(10);
    p2.notify();
    await vi.advanceTimersByTimeAsync(0);
    await pr;
    expect(vi.getTimerCount()).toBe(0);
    vi.useRealTimers();
  });
  it('pause registers a one-shot abort listener and removes it afterwards', async () => {
    const h = harness([pend()]);
    const ac = new AbortController();
    const add = vi.spyOn(ac.signal, 'addEventListener');
    const rem = vi.spyOn(ac.signal, 'removeEventListener');
    await h.client.poller(flow()).poll({ signal: ac.signal });
    const aborts = add.mock.calls.filter((c) => c[0] === 'abort');
    expect(aborts.length).toBe(2); // pause + post
    for (const c of aborts) {
      expect(c[2]).toStrictEqual({ once: true });
      expect(rem.mock.calls.filter((r) => r[0] === 'abort' && r[1] === c[1]).length).toBe(1);
    }
  });
  it('a live (never aborted) signal does not disturb polling', async () => {
    const h = harness([pend()]);
    const ac = new AbortController();
    expect((await h.client.poller(flow()).poll({ signal: ac.signal })).status).toBe('pending');
    const h2 = harness([json(200, { access_token: 'a', token_type: 'b' })]);
    expect((await h2.client.poller(flow()).wait({ signal: new AbortController().signal })).status).toBe('approved');
  });
  it('abort after the wait that also passes the deadline is reported as an abort, not as expiry', async () => {
    const ac = new AbortController();
    let t = 1_000_000;
    const h = harness([pend()], { now: () => t, sleep: async () => { t += 10_000_000; ac.abort(); } });
    const e = await err(h.client.poller(flow({ startedAt: 1_000_000 })).poll({ signal: ac.signal }));
    expect(e.message).toBe('ciba: wait aborted');
    expect(h.calls).toHaveLength(0);
  });
  it('a settled poller answers immediately without sleeping or contacting the provider', async () => {
    const h = harness([json(200, { access_token: 'a', token_type: 'b' })]);
    const p = h.client.poller(flow());
    await p.poll();
    const sleeps = h.sleeps.length;
    await p.poll();
    expect(h.sleeps.length).toBe(sleeps);
    expect(h.calls).toHaveLength(1);
    const ac = new AbortController();
    ac.abort();
    expect((await p.wait({ signal: ac.signal }).catch((e) => e as Error)) instanceof Error).toBe(true);
  });
  it('only retryable provider errors trigger backoff', async () => {
    for (const bad of [json(200, '[1]'), json(200, 'null')]) {
      const h = harness([bad, json(400, { error: 'authorization_pending' })]);
      const p = h.client.poller(flow({ intervalSec: 5, expiresInSec: 100_000 }));
      h.advance(5000);
      const e = (await err(p.poll())) as CibaProviderError;
      expect(e.retryable).toBe(false);
      h.sleeps.length = 0;
      await p.poll();
      expect(h.sleeps.length === 0 || (h.sleeps[0] ?? 0) <= 0).toBe(true);
    }
    // an abort (plain Error) must not count as a failure either
    const ac = new AbortController();
    ac.abort();
    const h = harness([json(400, { error: 'authorization_pending' })]);
    const p = h.client.poller(flow({ intervalSec: 5 }));
    h.advance(5000);
    await err(p.poll({ signal: ac.signal }));
    await p.poll();
    expect(h.sleeps).toEqual([]);
  });
  it('an aborted signal stops a wait() on a poller that has already settled', async () => {
    const h = harness([json(400, { error: 'access_denied' })]);
    const p = h.client.poller(flow());
    await p.poll();
    const ac = new AbortController();
    ac.abort();
    expect((await err(p.wait({ signal: ac.signal }))).message).toBe('ciba: wait aborted');
    expect((await p.wait()).status).toBe('denied');
  });
});

describe('initiate details', () => {
  it('optional parameters are absent from the form unless given; a leading control character invalidates a notification token', async () => {
    const h = harness([json(200, OK_INIT)]);
    await h.client.initiate(su, { loginHint: 'a' });
    expect([...new URLSearchParams(h.calls[0]?.init.body as string).keys()].sort()).toEqual(['binding_message', 'login_hint', 'requested_expiry', 'scope']);
    const msg = 'ciba: clientNotificationToken must be 22..1024 printable characters (>= 128 bits, CIBA Core 7.1)';
    expect((await err(h.client.initiate(su, { loginHint: 'a', delivery: 'ping', clientNotificationToken: `\u0001${'n'.repeat(22)}` }))).message).toBe(msg);
    expect((await err(h.client.initiate(su, { loginHint: 'a', delivery: 'ping', clientNotificationToken: ` ${'n'.repeat(22)}` }))).message).toBe(msg);
  });
});

describe('verifyPingCallback', () => {
  const f = { authReqId: 'AR1', clientNotificationToken: 'tok-123' };
  const body = { auth_req_id: 'AR1' };
  const fails = (input: { authorization: string | undefined; body: unknown }, flow = f) => {
    try {
      verifyPingCallback(input, flow);
    } catch (e) {
      return (e as Error).message;
    }
    return 'NO THROW';
  };
  it('accepts the matching bearer and auth_req_id (case-insensitive scheme, several spaces)', () => {
    expect(verifyPingCallback({ authorization: 'Bearer tok-123', body }, f)).toBe('AR1');
    expect(verifyPingCallback({ authorization: 'bEaReR   tok-123', body }, f)).toBe('AR1');
  });
  it('rejects every malformed or mismatching callback with its own message', () => {
    expect(fails({ authorization: 'Bearer tok-123', body }, { authReqId: 'AR1' } as unknown as typeof f)).toBe('ciba: flow was not started in ping mode');
    for (const a of [undefined, '', 'Basic tok-123', 'Bearer', 'Bearer ', 'Bearer tok-123 extra', 'x Bearer tok-123', 'Bearer\ttok-123', 'Bearerx tok-123']) {
      expect(fails({ authorization: a, body })).toBe('ciba: ping callback lacks a bearer token');
    }
    expect(fails({ authorization: 'Bearer tok-124', body })).toBe('ciba: ping callback bearer does not match the client_notification_token');
    expect(fails({ authorization: 'Bearer tok-12', body })).toBe('ciba: ping callback bearer does not match the client_notification_token');
    const idMsg = 'ciba: ping callback auth_req_id does not match this flow';
    for (const b of [null, undefined, 'AR1', 5, {}, { auth_req_id: 5 }, { auth_req_id: 'AR2' }, { auth_req_id: ['AR1'] }, ['AR1']]) {
      expect(fails({ authorization: 'Bearer tok-123', body: b })).toBe(idMsg);
    }
  });
});
