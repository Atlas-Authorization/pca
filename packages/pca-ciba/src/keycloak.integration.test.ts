/**
 * Integration test against a REAL OpenID Provider (Keycloak, CIBA enabled). Skipped unless
 * PCA_CIBA_KEYCLOAK_URL is set, so the default suite stays offline. Reproduce with
 * `scripts/run-keycloak-ciba.sh` (downloads Keycloak + a JDK, runs this file, tears everything down).
 *
 * Keycloak delegates "reaching the human" to an Authentication Channel provider: it POSTs the request to
 * a configured URL and waits for that device to call back with SUCCEED / CANCELLED / UNAUTHORIZED. This
 * file plays that device (`channel`), so approve / deny are real round-trips through Keycloak.
 *
 * With PCA_CIBA_RECORD=1 every HTTP exchange is written to fixtures/keycloak-ciba-transcripts.json
 * (secrets and tokens redacted); `keycloak.replay.test.ts` replays that file offline.
 */

import { createServer, type IncomingMessage, type Server } from 'node:http';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { agent, generateKeyPair, reviewAction, type StepUpRequest } from '@atlasauth/pca';
import {
  createCibaClient,
  toCibaAuthRequest,
  verifyPingCallback,
  type CibaClient,
  type CibaFlow,
} from './index';

const env = (k: string): string => process.env[k] ?? '';
const BASE = env('PCA_CIBA_KEYCLOAK_URL');
const REALM = env('PCA_CIBA_REALM') || 'pca';
const CLIENT_ID = env('PCA_CIBA_CLIENT_ID') || 'pca-ciba';
const CLIENT_SECRET = env('PCA_CIBA_CLIENT_SECRET');
const ADMIN_PASS = env('PCA_CIBA_ADMIN_PASSWORD');
const USER = env('PCA_CIBA_USER') || 'alice';
const CHAN_PORT = Number(env('PCA_CIBA_CHANNEL_PORT') || '18481');
const PING_PORT = Number(env('PCA_CIBA_PING_PORT') || '18482');
const RECORD = env('PCA_CIBA_RECORD') === '1';
const OIDC = `${BASE}/realms/${REALM}/protocol/openid-connect`;
const AUTH_URL = `${OIDC}/ext/ciba/auth`;
const TOKEN_URL = `${OIDC}/token`;
const CALLBACK_URL = `${OIDC}/ext/ciba/auth/callback`;

// ---- transcript recorder ------------------------------------------------------------------------------

interface Exchange {
  label: string;
  request: { method: string; url: string; headers: Record<string, string>; body: string };
  response: { status: number; body: string };
}
const transcript: Exchange[] = [];
let currentLabel = 'unlabelled';

function redactText(text: string): string {
  return text
    .replace(/"(access_token|id_token|refresh_token)":"[^"]*"/g, '"$1":"<redacted>"')
    .replace(/"auth_req_id":"[^"]*"/g, (m) => `"auth_req_id":"<redacted:${String(m.length - 17)} chars>"`)
    .replace(/auth_req_id=[^&\s]*/g, 'auth_req_id=<redacted>')
    .replace(/client_notification_token=[^&\s]*/g, 'client_notification_token=<redacted>')
    .replace(/(id_token_hint|login_hint_token)=[^&\s]*/g, '$1=<redacted>');
}

function recordingFetch(): typeof fetch {
  return (async (input: string | URL, init?: RequestInit) => {
    const res = await fetch(input, init);
    const text = await res.clone().text();
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((v, k) => {
      headers[k] = k === 'authorization' ? `${v.split(' ')[0] ?? ''} <redacted>` : v;
    });
    transcript.push({
      label: currentLabel,
      request: { method: init?.method ?? 'GET', url: String(input), headers, body: redactText(String(init?.body ?? '')) },
      response: { status: res.status, body: redactText(text) },
    });
    return res;
  }) as typeof fetch;
}

// ---- admin helpers -------------------------------------------------------------------------------------

async function adminToken(): Promise<string> {
  const res = await fetch(`${BASE}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    body: new URLSearchParams({ client_id: 'admin-cli', grant_type: 'password', username: 'admin', password: ADMIN_PASS }),
  });
  return ((await res.json()) as { access_token: string }).access_token;
}

async function admin(method: string, path: string, body?: unknown): Promise<unknown> {
  const res = await fetch(`${BASE}/admin/realms${path}`, {
    method,
    headers: { authorization: `Bearer ${await adminToken()}`, 'content-type': 'application/json' },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  if (!res.ok && res.status !== 409) throw new Error(`admin ${method} ${path} -> ${String(res.status)}`);
  const text = await res.text();
  return text === '' ? undefined : JSON.parse(text);
}

async function setRealmAttrs(attrs: Record<string, string>): Promise<void> {
  const realm = (await admin('GET', `/${REALM}`)) as { attributes: Record<string, string> };
  await admin('PUT', `/${REALM}`, { ...realm, attributes: { ...realm.attributes, ...attrs } });
}

// ---- the mock Authentication Channel (the human's device) ----------------------------------------------

interface ChannelHit {
  bearer: string;
  body: Record<string, unknown>;
}
const channelHits: ChannelHit[] = [];
let channelServer: Server;
let pingServer: Server;
const pings: { authorization: string | undefined; body: unknown }[] = [];

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function listen(handler: (req: IncomingMessage, body: string) => void, port: number, status = 201): Promise<Server> {
  const server = createServer((req, res) => {
    void readBody(req).then((body) => {
      handler(req, body);
      res.writeHead(status).end();
    });
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server)));
}

async function until<T>(f: () => T | undefined, ms = 15000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = f();
    if (v !== undefined) return v;
    if (Date.now() > end) throw new Error('timed out waiting');
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** Wait for Keycloak to hand the request to the "device", identified by its (unique) binding message. */
const channelFor = (bindingMessage: string): Promise<ChannelHit> => until(() => channelHits.find((h) => h.body['binding_message'] === bindingMessage));

async function deviceDecides(hit: ChannelHit, status: 'SUCCEED' | 'CANCELLED' | 'UNAUTHORIZED', expected = 200): Promise<void> {
  const res = await fetch(CALLBACK_URL, {
    method: 'POST',
    headers: { authorization: `Bearer ${hit.bearer}`, 'content-type': 'application/json' },
    body: JSON.stringify({ status }),
  });
  expect(res.status).toBe(expected);
  transcript.push({
    label: currentLabel,
    request: { method: 'POST', url: CALLBACK_URL, headers: { authorization: 'Bearer <redacted>', 'content-type': 'application/json' }, body: JSON.stringify({ status }) },
    response: { status: res.status, body: '' },
  });
}

// ---- fixtures ------------------------------------------------------------------------------------------

function stepUp(resource: string): StepUpRequest {
  const a = agent({
    principal: generateKeyPair(),
    goal: 'reconcile October refunds',
    permissions: { stripe: ['payout'] },
    limits: { payout: '$100' },
    aud: 'ins_test',
    riskPolicy: { theta1: 0.3, theta2: 0.6 },
    now: 0,
  });
  const r = reviewAction(a, 'stripe.payout', resource, { amount: 80, currency: 'USD', payee: 'bob' }, { now: 1, goal: 'reconcile October refunds' });
  if (r.kind !== 'step_up') throw new Error('expected a step_up');
  return r.request;
}

const TOKEN_ONLY = { tokenOnly: true } as const;
/** Keycloak only accepts scopes registered for the client, so no per-verb step-up scope. */
const OP = { bindingMessage: TOKEN_ONLY, stepUpScope: false } as const;
/** The unique binding message the broker will send for `resource`. */
const bmFor = (resource: string): string => toCibaAuthRequest(stepUp(resource), OP).binding_message;

function decodeJwtPayload(jwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
}

async function rawPost(url: string, form: Record<string, string>, creds = `${CLIENT_ID}:${CLIENT_SECRET}`): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await recordingFetch()(url, {
    method: 'POST',
    headers: { authorization: `Basic ${Buffer.from(creds).toString('base64')}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

describe.skipIf(BASE === '')('pca-ciba against a real Keycloak', () => {
  let client: CibaClient;
  let sleeps: number[] = [];

  beforeAll(async () => {
    channelServer = await listen((req, body) => {
      const bearer = /^Bearer (\S+)$/.exec(String(req.headers['authorization'] ?? ''))?.[1] ?? '';
      channelHits.push({ bearer, body: JSON.parse(body) as Record<string, unknown> });
      transcript.push({
        label: `${currentLabel} (provider -> device)`,
        request: { method: 'POST', url: `http://127.0.0.1:${String(CHAN_PORT)}${req.url ?? ''}`, headers: { authorization: 'Bearer <redacted>', 'content-type': String(req.headers['content-type'] ?? '') }, body },
        response: { status: 201, body: '' },
      });
    }, CHAN_PORT);
    pingServer = await listen((req, body) => {
      pings.push({ authorization: req.headers['authorization'], body: JSON.parse(body) as unknown });
      transcript.push({
        label: `${currentLabel} (provider -> client ping)`,
        request: { method: 'POST', url: `http://127.0.0.1:${String(PING_PORT)}${req.url ?? ''}`, headers: { authorization: 'Bearer <redacted>', 'content-type': String(req.headers['content-type'] ?? '') }, body: redactText(body) },
        response: { status: 204, body: '' },
      });
    }, PING_PORT, 204); // CIBA Core 10.2: the client acknowledges a ping with 204; Keycloak treats anything else as a failure
    client = createCibaClient({ allowInsecureHttp: true,
      backchannelAuthenticationEndpoint: AUTH_URL,
      tokenEndpoint: TOKEN_URL,
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      fetch: recordingFetch(),
      // Real sleeping (so Keycloak's own interval enforcement is exercised), but remembered for assertions.
      sleep: (ms) => {
        sleeps.push(ms);
        return new Promise((r) => setTimeout(r, ms));
      },
    });
  });

  afterAll(async () => {
    await new Promise((r) => channelServer.close(r));
    await new Promise((r) => pingServer.close(r));
    await setRealmAttrs({ cibaExpiresIn: '120', cibaInterval: '2', cibaAuthRequestedUserHint: 'login_hint' });
    if (RECORD) {
      writeFileSync(
        join(__dirname, '..', 'fixtures', 'keycloak-ciba-transcripts.json'),
        `${JSON.stringify({ provider: 'keycloak', version: env('PCA_CIBA_KC_VERSION'), recordedAt: new Date().toISOString(), note: 'tokens, auth_req_id and credentials redacted; a throwaway local realm', exchanges: transcript }, null, 2)}\n`,
      );
    }
  });

  it('discovery advertises the CIBA endpoint and the poll and ping modes', async () => {
    currentLabel = 'discovery';
    const res = await recordingFetch()(`${BASE}/realms/${REALM}/.well-known/openid-configuration`);
    const doc = (await res.json()) as Record<string, unknown>;
    expect(doc['backchannel_authentication_endpoint']).toBe(AUTH_URL);
    expect(doc['backchannel_token_delivery_modes_supported']).toEqual(expect.arrayContaining(['poll', 'ping']));
  });

  it('POLL approve: binding_message and scope reach the device; slow_down is enforced and obeyed; the token is single-use', async () => {
    currentLabel = 'poll-approve';
    sleeps = [];
    const resource = 'acct:poll-approve';
    const flow = await client.initiate(stepUp(resource), { loginHint: USER, ...OP });
    expect(flow.expiresInSec).toBeGreaterThan(0);
    expect(flow.intervalSec).toBeGreaterThan(0);

    const hit = await channelFor(bmFor(resource));
    expect(hit.body['login_hint']).toBe(USER);
    expect(String(hit.body['scope'])).toContain('openid');
    expect(hit.body['binding_message']).toBe(flow.request.binding_message);

    // Polling before the human acts: authorization_pending, then slow_down when we ignore the interval.
    const first = await rawPost(TOKEN_URL, { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: flow.authReqId });
    const early = await rawPost(TOKEN_URL, { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: flow.authReqId });
    expect(first.body['error']).toBe('authorization_pending');
    expect(early.body['error']).toBe('slow_down');
    expect(early.status).toBe(400);

    await deviceDecides(hit, 'SUCCEED');
    const poller = client.poller(flow);
    const result = await poller.wait();
    expect(result.status).toBe('approved');
    if (result.status !== 'approved') throw new Error('unreachable');
    expect(result.tokens.token_type).toBe('Bearer');
    expect(sleeps.length).toBeGreaterThan(0);
    const claims = decodeJwtPayload(result.tokens.access_token);
    expect(claims['preferred_username']).toBe(USER);
    expect(claims['iss']).toBe(`${BASE}/realms/${REALM}`);
    if (result.tokens.id_token !== undefined) expect(decodeJwtPayload(result.tokens.id_token)['sub']).toBe(claims['sub']);

    // An approved auth_req_id is consumed.
    const replay = await rawPost(TOKEN_URL, { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: flow.authReqId });
    expect(replay.body['error']).toBe('invalid_grant');
  }, 60_000);

  it('POLL deny: CANCELLED and UNAUTHORIZED both surface as access_denied', async () => {
    for (const [status, label] of [['CANCELLED', 'deny-cancelled'], ['UNAUTHORIZED', 'deny-unauthorized']] as const) {
      currentLabel = label;
      const resource = `acct:${label}`;
      const flow = await client.initiate(stepUp(resource), { loginHint: USER, ...OP });
      await deviceDecides(await channelFor(bmFor(resource)), status);
      const r = await client.poller(flow).wait();
      expect(r).toEqual({ status: 'denied', error: 'access_denied' });
    }
  }, 60_000);

  it('expiry: an unanswered request ends as expired_token at the provider', async () => {
    currentLabel = 'expiry';
    await setRealmAttrs({ cibaExpiresIn: '6', cibaInterval: '2' });
    try {
      const resource = 'acct:expiry';
      const flow = await client.initiate(stepUp(resource), { loginHint: USER, ...OP, expiresInSec: 5 });
      expect(flow.expiresInSec).toBeLessThanOrEqual(6);
      const r = await client.poller(flow).wait();
      expect(r.status).toBe('expired');
      // After the deadline the provider itself says expired_token (not just our local clock).
      await new Promise((resolve) => setTimeout(resolve, 2500));
      const server = await rawPost(TOKEN_URL, { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: flow.authReqId });
      expect(server.body['error']).toBe('expired_token');
      // A decision that arrives after expiry cannot revive it.
      // Keycloak refuses the device's late answer (403) rather than reviving the request.
      await deviceDecides(await channelFor(bmFor(resource)), 'SUCCEED', 403);
      const after = await rawPost(TOKEN_URL, { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: flow.authReqId });
      expect(after.body['error']).toMatch(/expired_token|invalid_grant/);
    } finally {
      await setRealmAttrs({ cibaExpiresIn: '120', cibaInterval: '2' });
    }
  }, 60_000);

  it('binding_message: the rich default is refused by Keycloak; the token-only profile is accepted', async () => {
    currentLabel = 'binding-message';
    const su = stepUp('acct:bm');
    const rich = toCibaAuthRequest(su, { actsFor: 'support-bot' });
    expect(rich.binding_message.length).toBeGreaterThan(50);
    const refused = await rawPost(AUTH_URL, { scope: 'openid', login_hint: USER, binding_message: rich.binding_message });
    expect(refused.status).toBe(400);
    expect(refused.body['error']).toBe('invalid_binding_message');
    await expect(client.initiate(su, { loginHint: USER, stepUpScope: false })).rejects.toMatchObject({ error: 'invalid_binding_message' });
    // ...and the per-verb scope the default adds is refused too, as invalid_scope.
    await expect(client.initiate(su, { loginHint: USER, bindingMessage: TOKEN_ONLY })).rejects.toMatchObject({ error: 'invalid_scope' });
    const ok = await client.initiate(su, { loginHint: USER, ...OP });
    expect(ok.request.binding_message).toMatch(/^[A-Za-z0-9._-]{1,50}$/);
  }, 30_000);

  it('login_hint variants: username, e-mail and different case resolve; unknown user and missing hint are refused', async () => {
    currentLabel = 'login-hint';
    for (const hint of [USER, 'alice@example.test', USER.toUpperCase()]) {
      const f = await client.initiate(stepUp(`acct:hint-${hint}`), { loginHint: hint, ...OP });
      expect(f.authReqId.length).toBeGreaterThan(0);
    }
    await expect(client.initiate(stepUp('acct:nobody'), { loginHint: 'nobody-here', ...OP })).rejects.toMatchObject({ status: 400, errorDescription: 'invalid_user' });
    const noHint = await rawPost(AUTH_URL, { scope: 'openid', binding_message: 'x' });
    expect(noHint.status).toBe(400);
    expect(String(noHint.body['error_description'])).toContain('login_hint');
    // Our own client refuses a request without exactly one hint before it reaches the wire.
    await expect(client.initiate(stepUp('acct:nohint'), {})).rejects.toThrow(RangeError);
  }, 30_000);

  it('id_token_hint and login_hint_token: sent correctly, but the stock Keycloak resolver only understands login_hint', async () => {
    currentLabel = 'other-hints';
    // The default CIBALoginUserResolver resolves login_hint only; the other two hint types need a custom
    // resolver SPI. We send a genuine ID token (direct grant on a helper client) so the refusal is the
    // provider's capability, not a malformed request.
    await admin('POST', `/${REALM}/clients`, { clientId: 'pca-hint-src', enabled: true, publicClient: true, directAccessGrantsEnabled: true });
    const login = await fetch(TOKEN_URL, { method: 'POST', body: new URLSearchParams({ client_id: 'pca-hint-src', grant_type: 'password', username: USER, password: 'alice-pass', scope: 'openid' }) });
    const idToken = ((await login.json()) as { id_token?: string }).id_token;
    if (idToken === undefined) throw new Error('no id_token from the direct grant');
    const jwt = (claims: object): string => `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
    for (const [mode, opts] of [
      ['id_token_hint', { idTokenHint: idToken }],
      ['login_hint_token', { loginHintToken: jwt({ sub: USER }) }],
    ] as const) {
      await setRealmAttrs({ cibaAuthRequestedUserHint: mode });
      try {
        await expect(client.initiate(stepUp(`acct:${mode}`), { ...opts, ...OP })).rejects.toMatchObject({ status: 400, errorDescription: 'invalid_user' });
      } finally {
        await setRealmAttrs({ cibaAuthRequestedUserHint: 'login_hint' });
      }
    }
  }, 60_000);

  it('error responses: bad client secret, missing openid scope, unsupported user_code, malformed requested_expiry, unknown auth_req_id', async () => {
    currentLabel = 'errors';
    const badSecret = await rawPost(AUTH_URL, { scope: 'openid', login_hint: USER }, `${CLIENT_ID}:wrong`);
    expect(badSecret.status).toBe(401);
    expect(typeof badSecret.body['error']).toBe('string');
    // CIBA Core 7.1 requires `openid`; Keycloak 26.8 does not enforce it (recorded, not asserted).
    await rawPost(AUTH_URL, { scope: 'profile', login_hint: USER });
    const badScope = await rawPost(AUTH_URL, { scope: 'openid urn:unregistered:scope', login_hint: USER });
    expect(badScope.body['error']).toBe('invalid_scope');
    const userCode = await rawPost(AUTH_URL, { scope: 'openid', login_hint: USER, user_code: '1234' });
    expect(userCode.body['error_description']).toBe('User code not supported');
    const badExpiry = await rawPost(AUTH_URL, { scope: 'openid', login_hint: USER, requested_expiry: 'abc' });
    expect(badExpiry.status).toBe(400);
    const bogus = await rawPost(TOKEN_URL, { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: 'bogus' });
    expect(bogus.status).toBe(400);
    expect(bogus.body['error']).toBe('invalid_grant');
    const wrongGrant = await rawPost(TOKEN_URL, { grant_type: 'client_credentials' });
    expect(wrongGrant.status).toBeGreaterThanOrEqual(400);
    // The client class maps a provider error to CibaProviderError with the provider's code intact.
    const bad = createCibaClient({ allowInsecureHttp: true, backchannelAuthenticationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, clientId: CLIENT_ID, clientSecret: 'wrong', fetch: recordingFetch() });
    await expect(bad.initiate(stepUp('acct:badsecret'), { loginHint: USER, ...OP })).rejects.toMatchObject({ status: 401 });
  }, 30_000);

  it('requested_expiry is a hint: the provider answers with its own expires_in', async () => {
    currentLabel = 'requested-expiry';
    const f = await client.initiate(stepUp('acct:req-exp'), { loginHint: USER, ...OP, expiresInSec: 30 });
    expect(f.expiresInSec).toBeGreaterThan(0);
    expect(f.request.requested_expiry).toBe(30);
  });

  it('PING: Keycloak calls our notification endpoint with the client_notification_token; the decision is then fetched immediately', async () => {
    currentLabel = 'ping';
    // A second client registered for ping delivery.
    const clientId = 'pca-ciba-ping';
    await admin('POST', `/${REALM}/clients`, {
      clientId,
      enabled: true,
      publicClient: false,
      secret: CLIENT_SECRET,
      standardFlowEnabled: false,
      attributes: {
        'oidc.ciba.grant.enabled': 'true',
        'ciba.backchannel.token.delivery.mode': 'ping',
        'ciba.backchannel.client.notification.endpoint': `http://127.0.0.1:${String(PING_PORT)}/ciba-ping`,
      },
    });
    const pingClient = createCibaClient({ allowInsecureHttp: true, backchannelAuthenticationEndpoint: AUTH_URL, tokenEndpoint: TOKEN_URL, clientId, clientSecret: CLIENT_SECRET, fetch: recordingFetch() });
    const resource = 'acct:ping';
    const flow: CibaFlow = await pingClient.initiate(stepUp(resource), { loginHint: USER, ...OP, delivery: 'ping' });
    // Ping mode: no polling interval is advertised or required before the callback.
    expect(flow.delivery).toBe('ping');
    await deviceDecides(await channelFor(bmFor(resource)), 'SUCCEED');
    const ping = await until(() => pings[pings.length - 1]);
    expect(verifyPingCallback(ping, flow)).toBe(flow.authReqId);
    const poller = pingClient.poller(flow);
    poller.notify();
    const t0 = Date.now();
    const r = await poller.poll();
    expect(Date.now() - t0).toBeLessThan(1500);
    expect(r.status).toBe('approved');
    // A forged callback does not verify.
    expect(() => verifyPingCallback({ authorization: 'Bearer forged', body: ping.body }, flow)).toThrow();
  }, 60_000);
});
