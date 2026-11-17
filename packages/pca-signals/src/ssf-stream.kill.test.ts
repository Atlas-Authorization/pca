import { decodeJwt, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  DELIVERY_POLL, DELIVERY_PUSH, EVENT_TYPES, PollQueue, StreamHealth, assuranceLevelChangeSET, handleVerificationRequest, pushResponse, validateStreamConfig,
  type StreamConfig,
} from './index';

const A = EVENT_TYPES.grantRevoked;
const V = EVENT_TYPES.verification;
const cfg = (over: Partial<StreamConfig> = {}): StreamConfig => ({
  stream_id: 's1', iss: 'https://tx.example', aud: 'https://rs.example', events_supported: [A, V], events_delivered: [A],
  delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://rs.example/events' }, min_verification_interval: 30, ...over,
});

describe('validateStreamConfig: exact problems', () => {
  it('a non-object is the only problem', () => {
    for (const c of [5, 'str', true, [], null, undefined]) expect(validateStreamConfig(c)).toEqual(['not an object']);
  });
  it('identifiers must be non-empty strings, not arrays', () => {
    expect(validateStreamConfig(cfg({ iss: '' }))).toEqual(['iss is required']);
    expect(validateStreamConfig(cfg({ iss: ['x'] as never }))).toEqual(['iss is required']);
    expect(validateStreamConfig(cfg({ stream_id: ['x'] as never }))).toEqual(['stream_id is required']);
    expect(validateStreamConfig(cfg({ aud: [['x']] as never }))).toEqual(['aud must be a non-empty string or array']);
  });
  it('an audience array is valid only when every entry is non-empty', () => {
    expect(validateStreamConfig(cfg({ aud: ['https://a.example', 'https://b.example'] }))).toEqual([]);
    expect(validateStreamConfig(cfg({ aud: ['https://a.example', ''] }))).toEqual(['aud must be a non-empty string or array']);
  });
  it('event lists must be arrays of non-empty strings', () => {
    const D = 'events_delivered must be a non-empty array of event type URIs';
    expect(validateStreamConfig(cfg({ events_delivered: 'abc' as never }))).toEqual([D]);
    expect(validateStreamConfig(cfg({ events_delivered: [A, ''] }))).toEqual([D]);
    expect(validateStreamConfig(cfg({ events_delivered: [A, 5 as never] }))).toEqual([D]);
    const S = 'events_supported must be an array of URIs';
    expect(validateStreamConfig(cfg({ events_supported: 'x' as never }))).toEqual([S]);
    expect(validateStreamConfig(cfg({ events_supported: [A, ''] }))).toEqual([S]);
    expect(validateStreamConfig(cfg({ events_supported: undefined }))).toEqual([]);
    const R = 'events_requested must be a non-empty array of URIs';
    expect(validateStreamConfig(cfg({ events_requested: [A] }))).toEqual([]);
    expect(validateStreamConfig(cfg({ events_requested: 'x' as never }))).toEqual([R]);
    expect(validateStreamConfig(cfg({ events_requested: [A, ''] }))).toEqual([R]);
    expect(validateStreamConfig(cfg({ events_requested: [] }))).toEqual([R]);
  });
  it('the endpoint must be a string https URL without whitespace', () => {
    const E = 'delivery.endpoint_url must be an https URL';
    for (const u of [['https://a.example'], 5, 'http://a.example', 'xhttps://a.example', 'https://a b', 'https://']) {
      expect(validateStreamConfig(cfg({ delivery: { method: DELIVERY_POLL, endpoint_url: u as never } }))).toEqual([E]);
    }
    expect(validateStreamConfig(cfg({ delivery: { method: DELIVERY_POLL, endpoint_url: 'https://a.example/p' } }))).toEqual([]);
  });
  it('a zero interval is valid', () => {
    expect(validateStreamConfig(cfg({ min_verification_interval: 0 }))).toEqual([]);
    expect(validateStreamConfig(cfg({ min_verification_interval: 1 }))).toEqual([]);
  });
});

describe('StreamHealth: exact behaviour', () => {
  it('rejects an unknown status', () => {
    expect(() => new StreamHealth(cfg()).setStatus('bogus' as never)).toThrow('unknown stream status');
  });
  it('last_event_at is the maximum seen and absent until an event arrives', () => {
    const h = new StreamHealth(cfg());
    expect('last_event_at' in h.report(0)).toBe(false);
    h.recordEvent(5);
    expect(h.report(5).last_event_at).toBe(5);
    h.recordEvent(3);
    expect(h.report(5).last_event_at).toBe(5);
    h.recordEvent(9);
    expect(h.report(9).last_event_at).toBe(9);
  });
  it('a verification ack records the event time as a maximum', () => {
    const fresh = new StreamHealth(cfg({ min_verification_interval: 0 }));
    expect(fresh.ackVerification(fresh.requestVerification(1)!, 12)).toBe(true);
    expect(fresh.report(12).last_event_at).toBe(12);
    const later = new StreamHealth(cfg({ min_verification_interval: 0 }));
    later.recordEvent(20);
    expect(later.ackVerification(later.requestVerification(1)!, 12)).toBe(true);
    expect(later.report(12).last_event_at).toBe(20);
  });
  it('an unknown or non-string state is rejected and counted', () => {
    const h = new StreamHealth(cfg({ min_verification_interval: 0 }));
    expect(h.ackVerification('nope', 1)).toBe(false);
    expect(h.ackVerification(5, 1)).toBe(false);
    expect(h.report(1).rejected_verifications).toBe(2);
  });
  it('expired pending verifications free their slot on request', () => {
    const h = new StreamHealth(cfg({ min_verification_interval: 0 }), { maxPending: 1, verifyTimeoutSec: 10 });
    expect(h.requestVerification(0)).not.toBeNull();
    expect(h.requestVerification(5)).toBeNull();
    expect(h.requestVerification(10)).toBeNull();
    expect(h.requestVerification(11)).not.toBeNull();
  });
  it('reports every state with its exact reason', () => {
    const fresh = new StreamHealth(cfg());
    expect(fresh.report(0)).toStrictEqual({
      state: 'unverified', status: 'enabled', reasons: ['no verification round trip has completed'], pending_verifications: 0, consecutive_verification_failures: 0, rejected_verifications: 0,
    });
    const paused = new StreamHealth(cfg());
    paused.setStatus('paused');
    expect(paused.report(0)).toMatchObject({ state: 'paused', status: 'paused', reasons: ['stream is paused: events may be delayed'] });
    const disabled = new StreamHealth(cfg());
    disabled.setStatus('disabled');
    expect(disabled.report(0)).toMatchObject({ state: 'disabled', status: 'disabled', reasons: ['stream is disabled: no events are transmitted or held'] });
    const failing = new StreamHealth(cfg({ min_verification_interval: 0 }), { verifyTimeoutSec: 1 });
    failing.requestVerification(0);
    failing.requestVerification(2);
    failing.requestVerification(4);
    expect(failing.report(6)).toStrictEqual({
      state: 'failing', status: 'enabled', reasons: ['3 consecutive verification requests timed out'], pending_verifications: 0, consecutive_verification_failures: 3, rejected_verifications: 0,
    });
  });
  it('healthy at exactly the window, degraded one second later, with the exact age in the reason', () => {
    const h = new StreamHealth(cfg({ min_verification_interval: 0 }), { verifiedWithinSec: 100 });
    expect(h.ackVerification(h.requestVerification(10)!, 12)).toBe(true);
    expect(h.report(112)).toStrictEqual({
      state: 'healthy', status: 'enabled', reasons: [], pending_verifications: 0, consecutive_verification_failures: 0, rejected_verifications: 0, last_event_at: 12, last_verified_at: 12,
    });
    expect(h.report(113)).toMatchObject({ state: 'degraded', reasons: ['last verified 101s ago, over 100s'], last_verified_at: 12 });
    expect(h.revocationFreshWithin(100, 112)).toBe(true);
    expect(h.revocationFreshWithin(100, 113)).toBe(false);
    h.setStatus('paused');
    expect(h.revocationFreshWithin(100, 112)).toBe(false);
  });
});

describe('handleVerificationRequest: exact outcomes', () => {
  const MSG = 'stream_id (string) is required; state must be a string';
  it('refuses malformed requests', async () => {
    const { privateKey } = await generateKeyPair('EdDSA');
    const streams = new Map<string, { config: StreamConfig; lastVerification?: number }>([['s1', { config: cfg() }]]);
    for (const r of [undefined, null, 5, 'x', {}, { stream_id: 5 }, { stream_id: 's1', state: 5 }]) {
      expect(await handleVerificationRequest(streams, r, 100, privateKey)).toEqual({ status: 400, error: MSG });
    }
    expect(await handleVerificationRequest(streams, { stream_id: 'zz' }, 100, privateKey)).toEqual({ status: 404, error: 'no such stream' });
  });
  it('429 strictly inside the interval, 204 at exactly the interval', async () => {
    const { privateKey } = await generateKeyPair('EdDSA');
    const streams = new Map<string, { config: StreamConfig; lastVerification?: number }>([['s1', { config: cfg({ min_verification_interval: 30 }), lastVerification: 100 }]]);
    expect(await handleVerificationRequest(streams, { stream_id: 's1' }, 129, privateKey)).toEqual({ status: 429, error: 'verification requested too soon' });
    const ok = await handleVerificationRequest(streams, { stream_id: 's1', state: 'q' }, 130, privateKey);
    expect(ok.status).toBe(204);
    expect(streams.get('s1')!.lastVerification).toBe(130);
    const ev = (decodeJwt((ok as { set: string }).set) as { events: Record<string, unknown> }).events[V];
    expect(ev).toEqual({ state: 'q' });
  });
});

describe('PollQueue and pushResponse: exact', () => {
  it('rejects an invalid maxEvents and never acknowledges by default', () => {
    const q = new PollQueue();
    for (const n of [-1, 1.5, Number.NaN]) expect(() => q.poll({ maxEvents: n })).toThrow('maxEvents must be a non-negative integer');
    q.enqueue('Stryker was here', 'set-a');
    expect(q.poll({})).toEqual({ sets: { 'Stryker was here': 'set-a' } });
    expect(q.depth).toBe(1);
  });
  it('maps every receiveSET failure code to the RFC 8935 error', () => {
    const e = (code: string) => (pushResponse({ ok: false, code, reason: 'r' }) as { body: { err: string; description: string } }).body;
    expect(pushResponse({ ok: true })).toEqual({ status: 202 });
    expect(e('verify_failed')).toEqual({ err: 'invalid_key', description: 'r' });
    expect(e('malformed')).toEqual({ err: 'invalid_request', description: 'r' });
    expect(e('oversize')).toEqual({ err: 'invalid_request', description: 'r' });
    expect(e('misconfigured')).toEqual({ err: 'access_denied', description: 'r' });
    expect(e('replay_store_error')).toEqual({ err: 'access_denied', description: 'r' });
    expect(e('anything_else')).toEqual({ err: 'invalid_request', description: 'r' });
  });
});

describe('assuranceLevelChangeSET: derived direction', () => {
  const order = ['aal1', 'aal2', 'aal3'];
  const direction = async (event: { current_level: string; previous_level?: string; change_direction?: 'increase' | 'decrease' }, ord?: string[]) => {
    const { privateKey } = await generateKeyPair('EdDSA');
    const jwt = await assuranceLevelChangeSET({ issuer: 'https://tx.example', audience: 'https://rs.example', key: privateKey, event: { namespace: 'NIST-AAL', event_timestamp: 6, ...event }, ...(ord ? { order: ord } : {}) });
    return (decodeJwt(jwt) as { events: Record<string, { change_direction?: string }> }).events[EVENT_TYPES.assuranceLevelChange]!.change_direction;
  };
  it('derives increase and decrease from the order', async () => {
    expect(await direction({ previous_level: 'aal1', current_level: 'aal2' }, order)).toBe('increase');
    expect(await direction({ previous_level: 'aal3', current_level: 'aal1' }, order)).toBe('decrease');
  });
  it('derives nothing when a level is unknown, levels are equal, or there is no order or previous level', async () => {
    expect(await direction({ previous_level: 'zzz', current_level: 'aal2' }, order)).toBeUndefined();
    expect(await direction({ previous_level: 'aal1', current_level: 'zzz' }, order)).toBeUndefined();
    expect(await direction({ previous_level: 'zzz', current_level: 'yyy' }, order)).toBeUndefined();
    expect(await direction({ previous_level: 'aal2', current_level: 'aal2' }, order)).toBeUndefined();
    expect(await direction({ previous_level: 'aal1', current_level: 'aal2' })).toBeUndefined();
    expect(await direction({ current_level: 'aal2' }, order)).toBeUndefined();
  });
  it('keeps an explicit direction even when the order disagrees', async () => {
    expect(await direction({ previous_level: 'aal3', current_level: 'aal1', change_direction: 'increase' }, order)).toBe('increase');
    expect(await direction({ previous_level: 'aal1', current_level: 'aal3', change_direction: 'decrease' }, order)).toBe('decrease');
  });
});
