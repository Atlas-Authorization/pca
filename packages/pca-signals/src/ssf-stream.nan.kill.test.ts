import { describe, expect, it } from 'vitest';
import { DELIVERY_PUSH, EVENT_TYPES, StreamHealth, type StreamConfig } from './index';

const A = EVENT_TYPES.grantRevoked;
const cfg = (over: Partial<StreamConfig> = {}): StreamConfig => ({
  stream_id: 's1', iss: 'https://tx.example', aud: 'https://rs.example', events_supported: [A], events_delivered: [A],
  delivery: { method: DELIVERY_PUSH, endpoint_url: 'https://rs.example/events' }, min_verification_interval: 30, ...over,
});
const bad = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];

describe('a non-finite clock or timeout never makes a stream look healthy', () => {
  // old code: a NaN or -Infinity clock never expired the request, so the stale ack below verified the stream
  it.each(bad)('ackVerification with a clock of %s refuses', (now) => {
    const h = new StreamHealth(cfg());
    const s = h.requestVerification(100) as string;
    expect(h.ackVerification(s, now)).toBe(false);
    expect(h.report(100).state).toBe('unverified');
  });
  it.each(bad)('requestVerification with a clock of %s issues nothing', (now) => {
    expect(new StreamHealth(cfg()).requestVerification(now)).toBeNull();
  });
  // old code: an infinite or NaN timeout left the request pending forever
  it.each(bad)('a verification timeout of %s issues nothing', (verifyTimeoutSec) => {
    expect(new StreamHealth(cfg(), { verifyTimeoutSec }).requestVerification(100)).toBeNull();
  });
  // old code: `-Infinity - lastVerified > within` is false, so the stream read as healthy and fresh
  it.each([Number.NaN, Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY])('report and revocationFreshWithin with a clock of %s', (now) => {
    const h = new StreamHealth(cfg({ min_verification_interval: 0 }));
    expect(h.ackVerification(h.requestVerification(100) as string, 100)).toBe(true);
    expect(h.report(now).state).not.toBe('healthy');
    expect(h.revocationFreshWithin(300, now)).toBe(false);
  });
  it('a NaN rate-limit interval or pending cap issues nothing', () => {
    const h = new StreamHealth(cfg({ min_verification_interval: Number.NaN }));
    expect(h.requestVerification(100)).not.toBeNull();
    expect(h.requestVerification(101)).toBeNull();
    expect(new StreamHealth(cfg(), { maxPending: Number.NaN }).requestVerification(100)).toBeNull();
  });
});
