import { mkdtempSync, writeFileSync } from 'node:fs';
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
const clockAt = () => { const c = { t: 1_000_000 }; return { c, now: () => c.t }; };
const settle = async <T>(p: Promise<T>) => p.then((v) => ({ ok: true as const, v }), (e: Error) => ({ ok: false as const, msg: e.message }));

describe('durable broker', () => {
  it('requires a store and a positive ttl', () => {
    expect(() => createDurableCibaBroker({} as never)).toThrow(TypeError);
    expect(() => createDurableCibaBroker({ store: createMemoryApprovalStore(), decisionTtlSec: 0 })).toThrow(TypeError);
    expect(() => createDurableCibaBroker({ store: createMemoryApprovalStore(), decisionTtlSec: NaN })).toThrow(TypeError);
  });

  it('pending, then approved after resolve', async () => {
    const { now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const req = await b.start(stepUp());
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'authorization_pending', interval: 5 });
    const s = await b.resolve(req.auth_req_id, 'approve', 'owner@acme');
    expect(s.status).toBe('approved');
  });

  it('single use and slow_down against the poll interval', async () => {
    const { c, now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const req = await b.start(stepUp());
    await b.token(req.auth_req_id);
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'slow_down', interval: 10 });
    await b.resolve(req.auth_req_id, 'approve', 'owner');
    c.t += 11_000;
    const first = await b.token(req.auth_req_id);
    expect(first.ok).toBe(true);
    c.t += 11_000;
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'invalid_grant', interval: 10 });
  });

  it('a decision cannot be replayed: second resolve (same or opposite) is refused and the first stands', async () => {
    const { now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const req = await b.start(stepUp());
    await b.resolve(req.auth_req_id, 'deny', 'owner');
    expect(await settle(b.resolve(req.auth_req_id, 'approve', 'owner'))).toEqual({ ok: false, msg: `ciba: cannot resolve ${req.auth_req_id} — already denied` });
    expect(await settle(b.resolve(req.auth_req_id, 'deny', 'owner'))).toEqual({ ok: false, msg: `ciba: cannot resolve ${req.auth_req_id} — already denied` });
    expect((await b.poll(req.auth_req_id)).status).toBe('denied');
  });

  it('an approval expires decisionTtlSec after the decision and is no longer redeemable', async () => {
    const { c, now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now, decisionTtlSec: 60 });
    const req = await b.start(stepUp());
    await b.resolve(req.auth_req_id, 'approve', 'owner');
    c.t += 60_000;
    expect((await b.poll(req.auth_req_id)).status).toBe('expired');
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'expired_token', interval: 5 });
  });

  it('an approval one ms before the ttl is still redeemable', async () => {
    const { c, now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now, decisionTtlSec: 60 });
    const req = await b.start(stepUp());
    await b.resolve(req.auth_req_id, 'approve', 'owner');
    c.t += 59_999;
    expect((await b.token(req.auth_req_id)).ok).toBe(true);
  });

  it('a pending request expires at requested_expiry and a late resolve is refused', async () => {
    const { c, now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const req = await b.start(stepUp());
    c.t += req.requested_expiry * 1000;
    expect((await b.poll(req.auth_req_id)).status).toBe('expired');
    expect(await settle(b.resolve(req.auth_req_id, 'approve', 'owner'))).toEqual({ ok: false, msg: `ciba: cannot resolve ${req.auth_req_id} — already expired` });
    expect(await b.token(req.auth_req_id)).toEqual({ ok: false, error: 'expired_token', interval: 5 });
  });

  it('unknown id: token is invalid_grant, poll/resolve throw, get is undefined', async () => {
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore() });
    expect(await b.token('nope')).toEqual({ ok: false, error: 'invalid_grant', interval: 5 });
    expect(await settle(b.poll('nope'))).toEqual({ ok: false, msg: 'ciba: unknown auth_req_id nope' });
    expect(await settle(b.resolve('nope', 'approve', 'o'))).toEqual({ ok: false, msg: 'ciba: unknown auth_req_id nope' });
    expect(await b.get('nope')).toBeUndefined();
  });

  it('refuses a missing decider and a bad decision', async () => {
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore() });
    const req = await b.start(stepUp());
    expect(await settle(b.resolve(req.auth_req_id, 'approve', ''))).toEqual({ ok: false, msg: 'ciba: `by` (the authenticated decider) is required' });
    expect(await settle(b.resolve(req.auth_req_id, 'yes' as never, 'o'))).toEqual({ ok: false, msg: 'ciba: decision must be "approve" or "deny"' });
    expect((await b.poll(req.auth_req_id)).status).toBe('pending');
  });

  it('start is idempotent while pending, and issues a fresh flow once the old one is consumed', async () => {
    const { c, now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const su = stepUp();
    const r1 = await b.start(su);
    expect((await b.start(su)).auth_req_id).toBe(r1.auth_req_id);
    await b.resolve(r1.auth_req_id, 'approve', 'o');
    expect((await b.start(su)).auth_req_id).toBe(r1.auth_req_id);
    c.t += 6000;
    await b.token(r1.auth_req_id);
    expect((await b.start(su)).auth_req_id).not.toBe(r1.auth_req_id);
  });

  it('a decision made in one broker instance is seen (and cannot be replayed) by another on the same store', async () => {
    const { now } = clockAt();
    const store = createMemoryApprovalStore();
    const a = createDurableCibaBroker({ store, now });
    const b = createDurableCibaBroker({ store, now });
    const req = await a.start(stepUp());
    await a.resolve(req.auth_req_id, 'approve', 'o');
    expect((await b.get(req.auth_req_id))?.status).toBe('approved');
    expect((await settle(b.resolve(req.auth_req_id, 'approve', 'o'))).ok).toBe(false);
  });

  it('concurrent resolves: exactly one wins', async () => {
    const { now } = clockAt();
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), now });
    const req = await b.start(stepUp());
    const rs = await Promise.all([settle(b.resolve(req.auth_req_id, 'approve', 'a')), settle(b.resolve(req.auth_req_id, 'deny', 'b'))]);
    expect(rs.filter((r) => r.ok).length).toBe(1);
  });

  it('gives up with an error under permanent CAS contention', async () => {
    const real = createMemoryApprovalStore();
    const hostile: ApprovalStore = { get: real.get, cas: (k, e, v) => (k.startsWith('a:') && e > 0 ? false : real.cas(k, e, v)) };
    const b = createDurableCibaBroker({ store: hostile });
    const req = await b.start(stepUp());
    expect(await settle(b.resolve(req.auth_req_id, 'approve', 'o'))).toEqual({ ok: false, msg: 'ciba: approval store contention, gave up' });
    expect((await b.poll(req.auth_req_id)).status).toBe('pending');
  });

  it('a malformed stored record fails closed', async () => {
    const store = createMemoryApprovalStore();
    store.cas('a:x', 0, { garbage: true });
    const b = createDurableCibaBroker({ store });
    expect(await settle(b.token('x'))).toEqual({ ok: false, msg: 'ciba: stored approval record is malformed' });
  });

  it('onComplete fires after the decision is recorded; a throwing notifier does not undo it', async () => {
    const seen: string[] = [];
    const b = createDurableCibaBroker({ store: createMemoryApprovalStore(), onComplete: (s) => { seen.push(s.status); throw new Error('boom'); } });
    const req = await b.start(stepUp());
    expect((await b.resolve(req.auth_req_id, 'approve', 'o')).status).toBe('approved');
    expect(seen).toEqual(['approved']);
    expect((await b.poll(req.auth_req_id)).status).toBe('approved');
  });
});

describe('file store (durable)', () => {
  it('survives a restart: a new broker over the same file sees the decision, and the replay is refused', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ciba-')), 'approvals.json');
    const { now } = clockAt();
    const a = createDurableCibaBroker({ store: createFileApprovalStore(path), now });
    const req = await a.start(stepUp());
    await a.resolve(req.auth_req_id, 'approve', 'o');
    const b = createDurableCibaBroker({ store: createFileApprovalStore(path), now });
    expect((await b.get(req.auth_req_id))?.status).toBe('approved');
    expect((await b.token(req.auth_req_id)).ok).toBe(true);
    const c = createDurableCibaBroker({ store: createFileApprovalStore(path), now });
    expect(await c.token(req.auth_req_id)).toEqual({ ok: false, error: 'invalid_grant', interval: 5 });
  });

  it('a corrupt file fails closed', async () => {
    const path = join(mkdtempSync(join(tmpdir(), 'ciba-')), 'approvals.json');
    writeFileSync(path, '{not json');
    const b = createDurableCibaBroker({ store: createFileApprovalStore(path) });
    expect((await settle(b.token('x'))).ok).toBe(false);
    writeFileSync(path, '[]');
    expect(await settle(b.token('x'))).toEqual({ ok: false, msg: 'ciba: approval store file is corrupt' });
  });
});
