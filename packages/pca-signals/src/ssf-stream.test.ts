import { generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  DELIVERY_POLL, DELIVERY_PUSH, EVENT_TYPES, PollQueue, StreamHealth, assuranceLevelChangeSET, createInMemorySetReplayStore, createRevocationState, handleVerificationRequest,
  pushResponse, receiveSET, riskLevelChangeSET, validateStreamConfig, verifySET, type StreamConfig,
} from './index';

const cfg = (over: Partial<StreamConfig> = {}): StreamConfig => ({
  stream_id: 's1', iss: 'https://tx.example', aud: 'https://rs.example', events_supported: [EVENT_TYPES.grantRevoked, EVENT_TYPES.verification],
  events_delivered: [EVENT_TYPES.grantRevoked], delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://rs.example/events' }, min_verification_interval: 30, ...over,
});

describe('validateStreamConfig', () => {
  it('accepts a well formed push and poll stream', () => {
    expect(validateStreamConfig(cfg())).toEqual([]);
    expect(validateStreamConfig(cfg({ delivery: { method: DELIVERY_POLL, endpoint_url: 'https://tx.example/poll' } }))).toEqual([]);
  });
  it('names each problem', () => {
    expect(validateStreamConfig(null)).toEqual(['not an object']);
    expect(validateStreamConfig(cfg({ stream_id: '' }))).toEqual(['stream_id is required']);
    expect(validateStreamConfig(cfg({ aud: [] }))).toEqual(['aud must be a non-empty string or array']);
    expect(validateStreamConfig(cfg({ events_delivered: [] }))).toEqual(['events_delivered must be a non-empty array of event type URIs']);
    expect(validateStreamConfig(cfg({ events_delivered: ['https://x/unsupported'] }))).toEqual(['events_delivered must be a subset of events_supported']);
    expect(validateStreamConfig(cfg({ events_requested: [] }))).toEqual(['events_requested must be a non-empty array of URIs']);
    expect(validateStreamConfig(cfg({ delivery: { method: 'urn:x' as never, endpoint_url: 'https://a' } }))).toEqual(['delivery.method must be the RFC 8935 or RFC 8936 URI']);
    expect(validateStreamConfig(cfg({ delivery: { method: DELIVERY_PUSH, endpoint_url: 'http://a' } }))).toEqual(['delivery.endpoint_url must be an https URL']);
    expect(validateStreamConfig(cfg({ min_verification_interval: -1 }))).toEqual(['min_verification_interval must be a non-negative integer (seconds)']);
  });
});

describe('StreamHealth', () => {
  it('unverified -> healthy on a matching single-use state -> degraded after the window', () => {
    const h = new StreamHealth(cfg({ min_verification_interval: 0 }), { verifiedWithinSec: 100 });
    expect(h.report(0).state).toBe('unverified');
    expect(h.revocationFreshWithin(100, 0)).toBe(false);
    const st = h.requestVerification(10)!;
    expect(h.ackVerification(st, 12)).toBe(true);
    expect(h.report(12)).toMatchObject({ state: 'healthy', last_verified_at: 12, pending_verifications: 0 });
    expect(h.revocationFreshWithin(100, 112)).toBe(true);
    expect(h.revocationFreshWithin(100, 113)).toBe(false);
    expect(h.report(113)).toMatchObject({ state: 'degraded' });
    expect(h.ackVerification(st, 13)).toBe(false); // single use
    expect(h.report(113).rejected_verifications).toBe(1);
  });
  it('refuses unknown, expired and non-string states; expiry counts toward failing', () => {
    const h = new StreamHealth(cfg({ min_verification_interval: 0 }), { verifyTimeoutSec: 10, failAfter: 2 });
    expect(h.ackVerification('forged', 1)).toBe(false);
    expect(h.ackVerification(undefined, 1)).toBe(false);
    const s1 = h.requestVerification(0)!;
    expect(h.ackVerification(s1, 11)).toBe(false); // expired
    h.requestVerification(20);
    expect(h.report(31)).toMatchObject({ state: 'failing', consecutive_verification_failures: 2 });
    const s3 = h.requestVerification(40)!;
    expect(h.ackVerification(s3, 41)).toBe(true);
    expect(h.report(41)).toMatchObject({ state: 'healthy', consecutive_verification_failures: 0 });
  });
  it('honours min_verification_interval, the pending cap and the status; paused and disabled never claim revocation freshness', () => {
    const h = new StreamHealth(cfg({ min_verification_interval: 30 }), { maxPending: 2 });
    expect(h.requestVerification(100)).not.toBeNull();
    expect(h.requestVerification(129)).toBeNull();
    expect(h.requestVerification(130)).not.toBeNull();
    expect(h.requestVerification(160)).toBeNull(); // cap of 2 outstanding
    const h2 = new StreamHealth(cfg({ min_verification_interval: 0 }));
    h2.ackVerification(h2.requestVerification(1)!, 2);
    h2.setStatus('paused');
    expect(h2.report(3)).toMatchObject({ state: 'paused', status: 'paused' });
    expect(h2.revocationFreshWithin(1000, 3)).toBe(false);
    expect(h2.requestVerification(4)).toBeNull();
    h2.setStatus('disabled');
    expect(h2.report(3).state).toBe('disabled');
    expect(() => h2.setStatus('bogus' as never)).toThrow(RangeError);
  });
});

describe('verification round trip over real SETs', () => {
  it('transmitter answers 204 + a SET that echoes state; the receiver verifies it and the stream turns healthy', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const c = cfg({ min_verification_interval: 30 });
    const streams = new Map([[c.stream_id, { config: c }]]);
    const h = new StreamHealth(c);
    const now = Math.floor(Date.now() / 1000);
    const state = h.requestVerification(now)!;
    const out = await handleVerificationRequest(streams, { stream_id: 's1', state }, now, privateKey);
    expect(out.status).toBe(204);
    if (out.status !== 204) throw new Error();
    const rec = await receiveSET(out.set, publicKey, { issuer: c.iss, audience: c.aud, replayStore: createInMemorySetReplayStore(), state: createRevocationState(), maxAgeSec: 300 });
    expect(rec.ok).toBe(true);
    if (!rec.ok) throw new Error();
    const ev = rec.parsed.events[EVENT_TYPES.verification] as { state?: string };
    expect(rec.parsed.payload.sub_id).toEqual({ format: 'opaque', id: 's1' });
    expect(h.ackVerification(ev.state, now + 1)).toBe(true);
    expect(h.report(now + 1).state).toBe('healthy');
    // rate limit, unknown stream, malformed
    expect(await handleVerificationRequest(streams, { stream_id: 's1' }, now + 5, privateKey)).toEqual({ status: 429, error: 'verification requested too soon' });
    expect((await handleVerificationRequest(streams, { stream_id: 's1' }, now + 31, privateKey)).status).toBe(204);
    expect((await handleVerificationRequest(streams, { stream_id: 'nope' }, now, privateKey)).status).toBe(404);
    expect((await handleVerificationRequest(streams, { stream_id: 7 }, now, privateKey)).status).toBe(400);
    expect((await handleVerificationRequest(streams, null, now, privateKey)).status).toBe(400);
  });
});

describe('RFC 8936 poll queue and RFC 8935 push mapping', () => {
  it('retains until acked, caps maxEvents with moreAvailable, drops errored SETs and records them', () => {
    const q = new PollQueue();
    for (const j of ['a', 'b', 'c']) q.enqueue(j, `set-${j}`);
    expect(q.poll({ maxEvents: 2 })).toEqual({ sets: { a: 'set-a', b: 'set-b' }, moreAvailable: true });
    expect(q.poll({ maxEvents: 2 }).sets).toEqual({ a: 'set-a', b: 'set-b' }); // unacked: retransmitted
    expect(q.poll({ ack: ['a'], setErrs: { b: { err: 'invalid_key', description: 'bad' } } })).toEqual({ sets: { c: 'set-c' } });
    expect(q.errors).toEqual([{ jti: 'b', err: 'invalid_key', description: 'bad' }]);
    expect(q.poll({ maxEvents: 0, ack: ['c'] })).toEqual({ sets: {} });
    expect(q.depth).toBe(0);
    expect(() => q.poll({ maxEvents: -1 })).toThrow(RangeError);
  });
  it('push: 202 on success; refusals map to the registered error codes', () => {
    expect(pushResponse({ ok: true })).toEqual({ status: 202 });
    expect(pushResponse({ ok: false, code: 'verify_failed', reason: 'r' })).toEqual({ status: 400, body: { err: 'invalid_key', description: 'r' } });
    expect(pushResponse({ ok: false, code: 'malformed', reason: 'r' }).status).toBe(400);
    expect(pushResponse({ ok: false, code: 'replay', reason: 'r' })).toEqual({ status: 400, body: { err: 'invalid_request', description: 'r' } });
    expect(pushResponse({ ok: false, code: 'misconfigured', reason: 'r' })).toEqual({ status: 400, body: { err: 'access_denied', description: 'r' } });
  });
});

describe('CAEP events from the decision log', () => {
  it('risk-level-change and assurance-level-change round trip, deriving change_direction from an order', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const common = { issuer: 'https://tx.example', audience: 'https://rs.example', key: privateKey };
    const r = await verifySET(await riskLevelChangeSET({ ...common, event: { principal: 'SESSION', current_level: 'HIGH', previous_level: 'LOW', risk_reason: 'IMMUNE_ANOMALY', event_timestamp: 5 } }), publicKey);
    expect(r.events[EVENT_TYPES.riskLevelChange]).toEqual({ principal: 'SESSION', current_level: 'HIGH', previous_level: 'LOW', risk_reason: 'IMMUNE_ANOMALY', event_timestamp: 5 });
    const order = ['aal1', 'aal2', 'aal3'];
    const a = await verifySET(await assuranceLevelChangeSET({ ...common, order, event: { namespace: 'NIST-AAL', current_level: 'aal1', previous_level: 'aal3', event_timestamp: 6 } }), publicKey);
    expect(a.events[EVENT_TYPES.assuranceLevelChange]).toMatchObject({ change_direction: 'decrease' });
    const b = await verifySET(await assuranceLevelChangeSET({ ...common, event: { namespace: 'NIST-AAL', current_level: 'aal1', previous_level: 'aal3', event_timestamp: 6 } }), publicKey);
    expect(b.events[EVENT_TYPES.assuranceLevelChange]).not.toHaveProperty('change_direction');
  });
});
