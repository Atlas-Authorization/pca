/**
 * Conformance tests against OpenID Connect CIBA Core 1.0 (Final):
 *
 *  1. The non-normative examples copied from the specification (fixtures/ciba-core-1_0-examples.json,
 *     provenance + sha256 in fixtures/PROVENANCE.json) are replayed through an independent, widely
 *     used CIBA client (`openid-client`, version recorded in package.json).
 *  2. A small HTTP OpenID Provider is put in front of this package's broker and driven end to end by
 *     the same client library: initiate, poll while pending, approve / deny / expire.
 *  3. The normative MUST / SHOULD constraints the specification places on the values this package
 *     emits (`auth_req_id`, `requested_expiry`, `scope`, `binding_message`) are asserted directly.
 *
 * The provider in (2) is written for these tests (it is NOT a certified OP). What is independently
 * verified is the client side of the wire protocol: that a vetted library accepts this package's
 * values and its pending / approved / denied / expired outcomes end to end.
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import * as client from 'openid-client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { agent, generateKeyPair, reviewAction, type StepUpRequest } from '@atlasauth/pca';
import { createCibaBroker, toCibaAuthRequest, type CibaAuthRequest } from './index';

const PKG = join(__dirname, '..');
const SPEC = JSON.parse(readFileSync(join(PKG, 'fixtures', 'ciba-core-1_0-examples.json'), 'utf8')) as {
  specExamples: Record<'authRequestForm' | 'authResponse' | 'tokenRequestForm' | 'tokenResponse' | 'pingCallback' | 'pushCallback' | 'errorResponse', string>;
  section7_1_requestParameters: string[];
  errorCodesMentioned: string[];
};

/** Body of an HTTP message copied from the spec: everything after the first blank line. */
function specBody(message: string): string {
  const i = message.indexOf('\n\n');
  return i < 0 ? message : message.slice(i + 2).trim();
}

/** Unfold a spec form body (examples wrap lines for display) into its decoded parameters. */
function specForm(message: string): URLSearchParams {
  return new URLSearchParams(specBody(message).replace(/\s*\n\s*/g, ''));
}

function mkStepUp(over?: { goal?: string; verb?: string; resource?: string }): StepUpRequest {
  const a = agent({
    principal: generateKeyPair(),
    goal: over?.goal ?? 'reconcile October refunds',
    permissions: { stripe: ['payout'] },
    limits: { payout: '$100' },
    aud: 'ins_test',
    riskPolicy: { theta1: 0.3, theta2: 0.6 },
    now: 0,
  });
  const r = reviewAction(a, 'stripe.payout', over?.resource ?? 'acct:1', { amount: 80 }, { now: 1, goal: over?.goal ?? 'reconcile October refunds' });
  if (r.kind !== 'step_up') throw new Error('expected a step_up');
  return over?.verb === undefined ? r.request : { ...r.request, verb: over.verb };
}

describe('fixtures', () => {
  it('match the sha256 recorded in PROVENANCE.json', () => {
    const prov = JSON.parse(readFileSync(join(PKG, 'fixtures', 'PROVENANCE.json'), 'utf8')) as { files: { file: string; sha256: string; kind: string }[] };
    for (const f of prov.files) {
      expect(createHash('sha256').update(readFileSync(join(PKG, 'fixtures', f.file))).digest('hex'), f.file).toBe(f.sha256);
      expect(f.kind).toBe('official-specification-examples');
    }
  });

  it('carry the specification examples that the other tests rely on', () => {
    expect(SPEC.section7_1_requestParameters).toEqual([
      'scope', 'client_notification_token', 'acr_values', 'login_hint_token', 'id_token_hint', 'login_hint', 'binding_message', 'user_code', 'requested_expiry',
    ]);
    expect(JSON.parse(specBody(SPEC.specExamples.authResponse))).toEqual({ auth_req_id: '1c266114-a1be-4252-8ad1-04986c5b9ac1', expires_in: 120, interval: 2 });
    expect(specForm(SPEC.specExamples.tokenRequestForm).get('grant_type')).toBe('urn:openid:params:grant-type:ciba');
    expect(JSON.parse(specBody(SPEC.specExamples.pingCallback))).toEqual({ auth_req_id: '1c266114-a1be-4252-8ad1-04986c5b9ac1' });
  });
});

// ---------------------------------------------------------------------------
// A tiny HTTP OpenID Provider on top of the broker
// ---------------------------------------------------------------------------

interface Received {
  authorize: URLSearchParams[];
  token: URLSearchParams[];
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

interface Op {
  server: Server;
  issuer: string;
  broker: ReturnType<typeof createCibaBroker>;
  received: Received;
  clock: { now: number };
  /** Mode switch: when set, /bc-authorize and /token replay the specification's verbatim messages. */
  replaySpec: boolean;
  stepUp: StepUpRequest;
}

async function startOp(stepUp: StepUpRequest): Promise<Op> {
  const clock = { now: 1_000_000 };
  const broker = createCibaBroker({ now: () => clock.now });
  const received: Received = { authorize: [], token: [] };
  const op: Op = { server: createServer(), issuer: '', broker, received, clock, replaySpec: false, stepUp };
  op.server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const form = new URLSearchParams(await readBody(req));
      if (req.url === '/bc-authorize') {
        received.authorize.push(form);
        if (op.replaySpec) {
          // The error case from the specification, byte for byte.
          sendJson(res, 400, JSON.parse(specBody(SPEC.specExamples.errorResponse)));
          return;
        }
        const scope = (form.get('scope') ?? '').split(' ');
        const expiry = Number(form.get('requested_expiry'));
        if (!scope.includes('openid')) return sendJson(res, 400, { error: 'invalid_scope' });
        if (!Number.isSafeInteger(expiry) || expiry <= 0) return sendJson(res, 400, { error: 'invalid_request', error_description: 'requested_expiry' });
        const login = form.get('login_hint') ?? undefined;
        const started = broker.start(op.stepUp, login === undefined ? { expiresInSec: expiry } : { expiresInSec: expiry, loginHint: login });
        // The client library polls at max(interval, its own floor); one second keeps the suite fast.
        return sendJson(res, 200, { auth_req_id: started.auth_req_id, expires_in: started.requested_expiry, interval: 1 });
      }
      if (req.url === '/token') {
        received.token.push(form);
        if (form.get('grant_type') !== 'urn:openid:params:grant-type:ciba') return sendJson(res, 400, { error: 'unsupported_grant_type' });
        let status: string;
        try {
          status = broker.poll(form.get('auth_req_id') ?? '').status;
        } catch {
          return sendJson(res, 400, { error: 'invalid_grant' });
        }
        if (status === 'pending') return sendJson(res, 400, { error: 'authorization_pending' });
        if (status === 'denied') return sendJson(res, 400, { error: 'access_denied' });
        if (status === 'expired') return sendJson(res, 400, { error: 'expired_token' });
        return sendJson(res, 200, { access_token: 'test-access-token', token_type: 'Bearer', expires_in: 120 });
      }
      res.writeHead(404).end();
    })();
  });
  await new Promise<void>((resolve) => op.server.listen(0, '127.0.0.1', resolve));
  op.issuer = `http://127.0.0.1:${(op.server.address() as AddressInfo).port}`;
  return op;
}

function configFor(op: Op): client.Configuration {
  const config = new client.Configuration(
    {
      issuer: op.issuer,
      token_endpoint: `${op.issuer}/token`,
      backchannel_authentication_endpoint: `${op.issuer}/bc-authorize`,
    },
    'pca-test-client',
    'pca-test-secret',
  );
  client.allowInsecureRequests(config);
  return config;
}

describe('openid-client (independent CIBA client) against the broker', () => {
  let op: Op;
  beforeAll(async () => {
    op = await startOp(mkStepUp());
  });
  afterAll(async () => {
    await new Promise<void>((resolve) => op.server.close(() => resolve()));
  });

  function paramsFor(req: CibaAuthRequest): Record<string, string> {
    return {
      scope: req.scope,
      binding_message: req.binding_message,
      requested_expiry: String(req.requested_expiry),
      ...(req.login_hint !== undefined ? { login_hint: req.login_hint } : {}),
    };
  }

  it('accepts the specification\'s own authentication response (parsed by the library)', async () => {
    // Replay the spec's response body through the library's response validation, via a throwaway server.
    const body = specBody(SPEC.specExamples.authResponse);
    const srv = createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(body);
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    const issuer = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    try {
      const config = new client.Configuration({ issuer, token_endpoint: `${issuer}/token`, backchannel_authentication_endpoint: `${issuer}/bc` }, 'c', 's');
      client.allowInsecureRequests(config);
      const r = await client.initiateBackchannelAuthentication(config, { scope: 'openid', login_hint: 'x' });
      expect(r.auth_req_id).toBe('1c266114-a1be-4252-8ad1-04986c5b9ac1');
      expect(r.expires_in).toBe(120);
      expect(r.interval).toBe(2);
    } finally {
      await new Promise<void>((r) => srv.close(() => r()));
    }
  });

  it('surfaces the specification\'s error response verbatim as a ResponseBodyError', async () => {
    op.replaySpec = true;
    try {
      const err = await client.initiateBackchannelAuthentication(configFor(op), { scope: 'openid', login_hint: 'x' }).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(err).toBeInstanceOf(client.ResponseBodyError);
      const e = err as client.ResponseBodyError;
      expect(e.error).toBe('unauthorized_client');
      expect(e.error_description).toBe("The client 'client.example.org' is not allowed to use CIBA.");
      expect(e.status).toBe(400);
    } finally {
      op.replaySpec = false;
    }
  });

  it('initiates with this package\'s request values; the OP receives them intact (including non-ASCII punctuation)', async () => {
    const req = toCibaAuthRequest(op.stepUp, { actsFor: 'support-bot', loginHint: 'owner@acme.example', expiresInSec: 90 });
    const r = await client.initiateBackchannelAuthentication(configFor(op), paramsFor(req));
    const got = op.received.authorize.at(-1);
    expect(got?.get('binding_message')).toBe(req.binding_message);
    expect(got?.get('scope')).toBe(req.scope);
    expect(got?.get('login_hint')).toBe('owner@acme.example');
    expect(got?.get('requested_expiry')).toBe('90');
    // Only parameters defined in the specification are sent by this package's request.
    // (client_id / client_secret are the client-authentication parameters the library adds itself.)
    for (const k of got?.keys() ?? []) expect([...SPEC.section7_1_requestParameters, 'client_id', 'client_secret']).toContain(k);
    // The library validated the broker's response: auth_req_id is a string, expires_in/interval numbers.
    expect(r.auth_req_id).toMatch(/^[A-Za-z0-9._-]{22,}$/);
    expect(r.expires_in).toBe(90);
    expect(r.interval).toBe(1);
  });

  it('polls through authorization_pending to success once the human approves', async () => {
    const stepUp = mkStepUp({ resource: 'acct:approve' });
    const local = await startOp(stepUp);
    try {
      const req = toCibaAuthRequest(stepUp, { loginHint: 'owner@acme.example' });
      const init = await client.initiateBackchannelAuthentication(configFor(local), paramsFor(req));
      // Human approves out of band while the client is polling.
      setTimeout(() => local.broker.resolve(init.auth_req_id, 'approve', 'owner@acme.example'), 1500);
      const tokens = await client.pollBackchannelAuthenticationGrant(configFor(local), init);
      expect(tokens.access_token).toBe('test-access-token');
      expect(local.received.token.length).toBeGreaterThanOrEqual(2); // at least one authorization_pending first
      const last = local.received.token.at(-1);
      expect(last?.get('grant_type')).toBe('urn:openid:params:grant-type:ciba');
      expect(last?.get('auth_req_id')).toBe(init.auth_req_id);
    } finally {
      await new Promise<void>((resolve) => local.server.close(() => resolve()));
    }
  }, 30_000);

  it('a denied flow ends the client\'s poll with access_denied', async () => {
    const stepUp = mkStepUp({ resource: 'acct:deny' });
    const local = await startOp(stepUp);
    try {
      const init = await client.initiateBackchannelAuthentication(configFor(local), paramsFor(toCibaAuthRequest(stepUp, { loginHint: 'o@x.example' })));
      setTimeout(() => local.broker.resolve(init.auth_req_id, 'deny', 'owner@acme.example'), 1200);
      const err = await client.pollBackchannelAuthenticationGrant(configFor(local), init).then(() => undefined, (e: unknown) => e);
      expect(err).toBeInstanceOf(client.ResponseBodyError);
      expect((err as client.ResponseBodyError).error).toBe('access_denied');
    } finally {
      await new Promise<void>((resolve) => local.server.close(() => resolve()));
    }
  }, 30_000);

  it('an expired flow ends the client\'s poll with expired_token', async () => {
    const stepUp = mkStepUp({ resource: 'acct:expire' });
    const local = await startOp(stepUp);
    try {
      const init = await client.initiateBackchannelAuthentication(
        configFor(local),
        paramsFor(toCibaAuthRequest(stepUp, { loginHint: 'o@x.example', expiresInSec: 60 })),
      );
      local.clock.now += 61_000; // the broker's clock passes requested_expiry
      const err = await client.pollBackchannelAuthenticationGrant(configFor(local), init).then(() => undefined, (e: unknown) => e);
      expect(err).toBeInstanceOf(client.ResponseBodyError);
      expect((err as client.ResponseBodyError).error).toBe('expired_token');
    } finally {
      await new Promise<void>((resolve) => local.server.close(() => resolve()));
    }
  }, 30_000);
});

// ---------------------------------------------------------------------------
// Normative constraints on emitted values (CIBA Core 1.0, section 7)
// ---------------------------------------------------------------------------

describe('values emitted against the CIBA Core 1.0 requirements', () => {
  const AUTH_REQ_ID_CHARS = /^[A-Za-z0-9._-]+$/;

  it('the specification\'s example auth_req_id satisfies the same character rule the package enforces', () => {
    const id = (JSON.parse(specBody(SPEC.specExamples.authResponse)) as { auth_req_id: string }).auth_req_id;
    expect(id).toMatch(AUTH_REQ_ID_CHARS);
    // ...and the package accepts it when supplied, unmodified.
    expect(toCibaAuthRequest(mkStepUp(), { authReqId: id }).auth_req_id).toBe(id);
  });

  it('auth_req_id is not derivable from public step-up fields: it is fresh per broker flow (7.3: >=128 bits of entropy)', () => {
    const stepUp = mkStepUp();
    const derived = toCibaAuthRequest(stepUp).auth_req_id;
    const a = createCibaBroker().start(stepUp);
    const b = createCibaBroker().start(stepUp);
    expect(a.auth_req_id).not.toBe(derived);
    expect(a.auth_req_id).not.toBe(b.auth_req_id);
    for (const id of [a.auth_req_id, b.auth_req_id]) {
      expect(id).toMatch(AUTH_REQ_ID_CHARS);
      // 160 random bits base64url-encoded = 27 characters (>= the 128-bit floor).
      expect(Buffer.from(id, 'base64url').length).toBeGreaterThanOrEqual(16);
    }
  });

  it('auth_req_id values are unique across many flows', () => {
    const broker = createCibaBroker();
    const ids = new Set<string>();
    for (let i = 0; i < 200; i++) ids.add(broker.start({ ...mkStepUp(), id: `step-${i}` }).auth_req_id);
    expect(ids.size).toBe(200);
  });

  it('rejects a caller-supplied auth_req_id that violates the character set or the 128-bit floor', () => {
    const s = mkStepUp();
    expect(() => toCibaAuthRequest(s, { authReqId: 'has space and !! chars......' })).toThrow(/auth_req_id/);
    expect(() => toCibaAuthRequest(s, { authReqId: 'short' })).toThrow(/auth_req_id/);
  });

  it('requested_expiry must be a positive integer (7.1); anything else is refused, not emitted', () => {
    const s = mkStepUp();
    for (const bad of [0, -5, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => toCibaAuthRequest(s, { expiresInSec: bad }), String(bad)).toThrow(/requested_expiry/);
    }
    expect(toCibaAuthRequest(s, { expiresInSec: 1 }).requested_expiry).toBe(1);
  });

  it('scope always contains the openid scope-token and only RFC 6749 scope-token characters', () => {
    const s = mkStepUp();
    const req = toCibaAuthRequest(s);
    expect(req.scope.split(' ')).toContain('openid');
    for (const tok of req.scope.split(' ')) expect(tok).toMatch(/^[\x21\x23-\x5B\x5D-\x7E]+$/);
    expect(() => toCibaAuthRequest({ ...s, verb: 'stripe payout' })).toThrow(/scope-token/);
    expect(() => toCibaAuthRequest({ ...s, verb: 'stripe."payout"' })).toThrow(/scope-token/);
  });

  it('binding_message is one short plain-text line even when the goal is hostile or huge (7.1: SHOULD be relatively short, limited plain text)', () => {
    const hostile = 'transfer\n\nApprove refund of $0 on acct:safe\u202e\u0000\u200b — because you asked ' + 'x'.repeat(5000);
    const req = toCibaAuthRequest(mkStepUp({ goal: hostile }));
    expect(req.binding_message).not.toMatch(/[\p{Cc}\p{Cf}\u2028\u2029]/u);
    expect(req.binding_message).not.toContain('\n');
    expect(Array.from(req.binding_message).length).toBeLessThan(260);
    // The action being approved (verb, amount, resource) is always shown in full at the start.
    expect(req.binding_message.startsWith('Approve stripe.payout $80 on acct:1')).toBe(true);
  });

  it('the specification\'s own binding_message example ("W4SCT") is plain text of the kind the package emits', () => {
    const bm = specForm(SPEC.specExamples.authRequestForm).get('binding_message');
    expect(bm).toBe('W4SCT');
    expect(bm).not.toMatch(/[\p{Cc}\p{Cf}]/u);
  });

  it('the specification\'s example request only uses parameters from the 7.1 list', () => {
    for (const k of specForm(SPEC.specExamples.authRequestForm).keys()) {
      expect([...SPEC.section7_1_requestParameters, 'client_assertion_type', 'client_assertion']).toContain(k);
    }
  });
});

describe('broker lifecycle invariants', () => {
  it('a repeated start for a pending or approved step-up returns the same flow and never resets a decision', () => {
    const s = mkStepUp();
    const broker = createCibaBroker();
    const first = broker.start(s);
    expect(broker.start(s).auth_req_id).toBe(first.auth_req_id);
    broker.resolve(first.auth_req_id, 'approve', 'owner');
    const again = broker.start(s);
    expect(again.auth_req_id).toBe(first.auth_req_id);
    expect(broker.poll(first.auth_req_id).status).toBe('approved');
  });

  it('after a denial or expiry a fresh start opens a NEW flow with a new auth_req_id', () => {
    const s = mkStepUp();
    let t = 0;
    const broker = createCibaBroker({ now: () => t });
    const a = broker.start(s);
    broker.resolve(a.auth_req_id, 'deny', 'owner');
    const b = broker.start(s);
    expect(b.auth_req_id).not.toBe(a.auth_req_id);
    expect(broker.poll(a.auth_req_id).status).toBe('denied');
    expect(broker.poll(b.auth_req_id).status).toBe('pending');
    t += 400_000;
    const c = broker.start(s);
    expect(c.auth_req_id).not.toBe(b.auth_req_id);
  });

  it('every state is single-resolution: a second resolve is refused with the settled status', () => {
    const s = mkStepUp();
    const broker = createCibaBroker();
    const a = broker.start(s);
    broker.resolve(a.auth_req_id, 'deny', 'owner');
    expect(() => broker.resolve(a.auth_req_id, 'approve', 'owner')).toThrow(/already denied/);
  });
});
