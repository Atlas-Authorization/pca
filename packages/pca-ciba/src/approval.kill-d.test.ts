import { mkdtempSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, reviewAction } from '@atlasauth/pca';
import { createDurableCibaBroker, createFileApprovalStore, type ApprovalStore } from './index';
import { createMemoryApprovalStore } from './testing';

function stepUp() {
  const a = agent({ principal: generateKeyPair(), goal: 'reconcile October refunds', permissions: { stripe: ['payout'] }, limits: { payout: '$100' }, aud: 'ins_test', riskPolicy: { theta1: 0.3, theta2: 0.6 }, now: 0 });
  const r = reviewAction(a, 'stripe.payout', 'acct:1', { amount: 80, currency: 'USD', payee: 'bob' }, { insecureUnboundApproval: true, now: 1, goal: 'reconcile October refunds' });
  if (r.kind !== 'step_up') throw new Error('expected step_up');
  return r.request;
}
const clockAt = () => {
  const c = { t: 1_000_000 };
  return { c, now: () => c.t };
};
const reasonOf = async (p: Promise<unknown>): Promise<string> => p.then(() => 'resolved', (e: Error) => e.message);

describe('file approval store', () => {
  it('refuses a file whose JSON is not an object', () => {
    for (const body of ['null', '5', '"text"', '[]', 'true']) {
      const path = join(mkdtempSync(join(tmpdir(), 'ciba-fs-')), 'a.json');
      writeFileSync(path, body);
      expect(() => createFileApprovalStore(path).get('k'), body).toThrow(new Error('ciba: approval store file is corrupt'));
    }
  });
  it('writes the file readable by its owner only', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ciba-fs-')), 'a.json');
    const s = createFileApprovalStore(path);
    expect(s.cas('k', 0, { v: 1 })).toBe(true);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(s.get('k')).toEqual({ version: 1, value: { v: 1 } });
  });
});

describe('durable broker construction', () => {
  const msg = 'createDurableCibaBroker: `store` is required';
  it('a missing options object or store is refused with the typed message', () => {
    expect(() => createDurableCibaBroker(undefined as never)).toThrow(new TypeError(msg));
    expect(() => createDurableCibaBroker(null as never)).toThrow(new TypeError(msg));
    expect(() => createDurableCibaBroker({ store: undefined as never })).toThrow(new TypeError(msg));
    expect(() => createDurableCibaBroker({ store: 5 as never })).toThrow(new TypeError(msg));
  });
  it('a store needs both get and cas', () => {
    const inner = createMemoryApprovalStore();
    expect(() => createDurableCibaBroker({ store: { cas: inner.cas } as never })).toThrow(new TypeError(msg));
    expect(() => createDurableCibaBroker({ store: { get: inner.get } as never })).toThrow(new TypeError(msg));
    expect(() => createDurableCibaBroker({ store: inner })).not.toThrow();
  });
  it('a non-positive or non-finite ttl is refused with the typed message', () => {
    for (const decisionTtlSec of [0, -1, NaN, Infinity]) {
      expect(() => createDurableCibaBroker({ store: createMemoryApprovalStore(), decisionTtlSec })).toThrow(
        new TypeError('createDurableCibaBroker: decisionTtlSec must be a positive number'),
      );
    }
  });
});

describe('stored record validation', () => {
  const valid = () => ({ request: { auth_req_id: 'a'.repeat(22) }, createdAt: 1, expiresAt: 2, interval: 5 });
  const brokerOver = (value: unknown) => {
    const store: ApprovalStore = { get: () => ({ version: 1, value }), cas: () => true };
    return createDurableCibaBroker({ store, now: () => 1_000_000 });
  };
  it('a well-formed record is read', async () => {
    expect(await brokerOver(valid()).poll('x')).toEqual({ status: 'expired' });
  });
  it.each([
    ['null', () => null],
    ['a function carrying valid fields', () => Object.assign(() => 0, valid())],
    ['no request', () => ({ createdAt: 1, expiresAt: 2, interval: 5 })],
    ['a numeric auth_req_id', () => ({ ...valid(), request: { auth_req_id: 5 } })],
    ['a string createdAt', () => ({ ...valid(), createdAt: '1' })],
    ['a missing createdAt', () => ({ request: valid().request, expiresAt: 2, interval: 5 })],
    ['a NaN expiresAt', () => ({ ...valid(), expiresAt: NaN })],
    ['an infinite interval', () => ({ ...valid(), interval: Infinity })],
  ])('%s is malformed', async (_n, make) => {
    expect(await reasonOf(brokerOver(make()).poll('x'))).toBe('ciba: stored approval record is malformed');
  });
});

describe('durable broker behaviour', () => {
  it('a pending session carries no decision fields and a decided one carries both', async () => {
    const { c, now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const req = await b.start(stepUp());
    const pending = await b.get(req.auth_req_id);
    expect(Object.keys(pending!).sort()).toEqual(['auth_req_id', 'createdAt', 'expiresAt', 'request', 'status']);
    c.t += 7;
    const done = await b.resolve(req.auth_req_id, 'approve', 'owner');
    expect(done.decidedBy).toBe('owner');
    expect(done.decidedAt).toBe(1_000_007);
    expect(await b.get(req.auth_req_id)).toMatchObject({ decidedBy: 'owner', decidedAt: 1_000_007, status: 'approved' });
  });

  it('gives up after exactly eight compare-and-set attempts', async () => {
    const inner = createMemoryApprovalStore();
    let attempts = 0;
    const failing: ApprovalStore = {
      get: (k) => inner.get(k),
      cas: () => {
        attempts += 1;
        return false;
      },
    };
    const b = createDurableCibaBroker({ store: failing });
    expect(await reasonOf(b.start(stepUp()))).toBe('ciba: approval store contention, gave up');
    expect(attempts).toBe(8);

    const seeded = createDurableCibaBroker({ store: inner });
    const req = await seeded.start(stepUp());
    attempts = 0;
    expect(await reasonOf(b.token(req.auth_req_id))).toBe('ciba: approval store contention, gave up');
    expect(attempts).toBe(8);
  });

  it('start restarts when the live index points at a record that is gone', async () => {
    const inner = createMemoryApprovalStore();
    const su = stepUp();
    expect(inner.cas(`s:${su.id}`, 0, 'ghost')).toBe(true);
    const b = createDurableCibaBroker({ store: inner });
    const req = await b.start(su);
    expect(req.auth_req_id).not.toBe('ghost');
    expect(inner.get(`s:${su.id}`)).toEqual({ version: 2, value: req.auth_req_id });
  });

  it('start is idempotent while pending, and begins a new flow after a denial', async () => {
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now: clockAt().now });
    const su = stepUp();
    const first = await b.start(su);
    expect((await b.start(su)).auth_req_id).toBe(first.auth_req_id);
    await b.resolve(first.auth_req_id, 'deny', 'owner');
    expect((await b.start(su)).auth_req_id).not.toBe(first.auth_req_id);
  });

  it('polling exactly at the interval is allowed, a second earlier is slowed down, spacing is in seconds', async () => {
    const { c, now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const req = await b.start(stepUp());
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'authorization_pending', interval: 5 });
    c.t += 5000;
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'authorization_pending', interval: 5 });
    c.t += 1000;
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'slow_down', interval: 10 });
  });

  it('a denied request answers access_denied with the current interval', async () => {
    const { c, now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const req = await b.start(stepUp());
    await b.resolve(req.auth_req_id, 'deny', 'owner');
    c.t += 6000;
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'access_denied', interval: 5 });
  });

  it('resolve refuses a decider that is not a non-empty string', async () => {
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore() });
    const req = await b.start(stepUp());
    const msg = 'ciba: `by` (the authenticated decider) is required';
    for (const by of [5, '', undefined, null]) expect(await reasonOf(b.resolve(req.auth_req_id, 'approve', by as never))).toBe(msg);
    expect((await b.poll(req.auth_req_id)).status).toBe('pending');
  });
});
