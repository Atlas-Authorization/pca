import { describe, expect, it } from 'vitest';

import {
  type StepUpEvent,
  buildStepUpEvent,
  parseEvent,
  serializeEvent,
  signWebhook,
  verifyWebhook,
  webhookHeaders,
} from './index';

const AT = 1_700_000_000_000;

function sampleData(): Omit<StepUpEvent, 'id' | 'at'> & { at?: number } {
  return {
    type: 'step_up.approved',
    at: AT,
    grant_ref: 'grant_abc',
    action: { verb: 'stripe.refund', resource: 'pi_123' },
    tier: 2,
    actor: 'user_42',
  };
}

describe('buildStepUpEvent', () => {
  it('is content-addressed and stable', () => {
    const a = buildStepUpEvent('step_up.approved', sampleData());
    const b = buildStepUpEvent('step_up.approved', sampleData());
    expect(a.id).toBe(b.id);
    expect(a.id.length).toBeGreaterThan(0);
    expect(a).toEqual(b);
  });

  it('changes the id when any field changes', () => {
    const base = buildStepUpEvent('step_up.approved', sampleData());
    const diffResource = buildStepUpEvent('step_up.approved', {
      ...sampleData(),
      action: { verb: 'stripe.refund', resource: 'pi_999' },
    });
    const diffTier = buildStepUpEvent('step_up.approved', { ...sampleData(), tier: 3 });
    const diffType = buildStepUpEvent('step_up.denied', sampleData());
    expect(diffResource.id).not.toBe(base.id);
    expect(diffTier.id).not.toBe(base.id);
    expect(diffType.id).not.toBe(base.id);
  });

  it('defaults `at` to now and omits actor when absent', () => {
    const before = Date.now();
    const ev = buildStepUpEvent('step_up.created', {
      type: 'step_up.created',
      grant_ref: 'grant_x',
      action: { verb: 'db.delete', resource: 'row_1' },
      tier: 3,
    });
    expect(ev.at).toBeGreaterThanOrEqual(before);
    expect(ev.actor).toBeUndefined();
    expect('actor' in ev).toBe(false);
  });
});

describe('serializeEvent / parseEvent', () => {
  it('round-trips', () => {
    const ev = buildStepUpEvent('step_up.approved', sampleData());
    const parsed = parseEvent(serializeEvent(ev));
    expect(parsed).toEqual(ev);
  });

  it('round-trips an event without an actor', () => {
    const ev = buildStepUpEvent('step_up.expired', {
      type: 'step_up.expired',
      at: AT,
      grant_ref: 'grant_y',
      action: { verb: 'k8s.scale', resource: 'deploy/web' },
      tier: 2,
    });
    const parsed = parseEvent(serializeEvent(ev));
    expect(parsed).toEqual(ev);
    expect('actor' in parsed).toBe(false);
  });

  it('throws on garbage', () => {
    expect(() => parseEvent('not json at all {')).toThrow();
    expect(() => parseEvent('null')).toThrow();
    expect(() => parseEvent('42')).toThrow();
    expect(() => parseEvent(JSON.stringify({ id: 'x', type: 'nope', at: AT, grant_ref: 'g', action: { verb: 'v', resource: 'r' }, tier: 2 }))).toThrow();
    expect(() => parseEvent(JSON.stringify({ id: 'x', type: 'step_up.created', at: AT, grant_ref: 'g', action: { verb: 'v' }, tier: 2 }))).toThrow();
    expect(() => parseEvent(JSON.stringify({ id: 'x', type: 'step_up.created', at: AT, grant_ref: 'g', action: { verb: 'v', resource: 'r' }, tier: 5 }))).toThrow();
  });
});

describe('signWebhook / verifyWebhook', () => {
  const secret = 'whsec_test_123';
  const payload = serializeEvent(buildStepUpEvent('step_up.approved', sampleData()));
  const T = 1_700_000_100; // unix seconds

  it('accepts a correct signature', () => {
    const sig = signWebhook(secret, payload, { timestamp: T });
    expect(sig).toMatch(/^t=1700000100,v1=[0-9a-f]{64}$/);
    expect(verifyWebhook(secret, payload, sig, { now: T })).toBe(true);
  });

  it('accepts a correct signature from a Uint8Array secret', () => {
    const keyBytes = new TextEncoder().encode(secret);
    const sig = signWebhook(keyBytes, payload, { timestamp: T });
    expect(verifyWebhook(keyBytes, payload, sig, { now: T })).toBe(true);
  });

  it('rejects a tampered payload', () => {
    const sig = signWebhook(secret, payload, { timestamp: T });
    expect(verifyWebhook(secret, `${payload} `, sig, { now: T })).toBe(false);
  });

  it('rejects a wrong secret', () => {
    const sig = signWebhook(secret, payload, { timestamp: T });
    expect(verifyWebhook('whsec_wrong', payload, sig, { now: T })).toBe(false);
  });

  it('rejects a stale timestamp (older than tolerance)', () => {
    const sig = signWebhook(secret, payload, { timestamp: T });
    expect(verifyWebhook(secret, payload, sig, { now: T + 301 })).toBe(false);
    // still inside tolerance:
    expect(verifyWebhook(secret, payload, sig, { now: T + 299 })).toBe(true);
  });

  it('rejects a malformed header without throwing', () => {
    expect(verifyWebhook(secret, payload, 'garbage', { now: T })).toBe(false);
    expect(verifyWebhook(secret, payload, 't=1700000100', { now: T })).toBe(false);
    expect(verifyWebhook(secret, payload, 'v1=abcd', { now: T })).toBe(false);
    expect(verifyWebhook(secret, payload, 't=1700000100,v1=zz', { now: T })).toBe(false);
  });

  it('constant-time compare still accepts a valid signature of matching length', () => {
    const sig = signWebhook(secret, payload, { timestamp: T });
    // flip the final hex nibble -> same length, wrong bytes
    const bad = sig.replace(/.$/, (c) => (c === '0' ? '1' : '0'));
    expect(bad.length).toBe(sig.length);
    expect(verifyWebhook(secret, payload, sig, { now: T })).toBe(true);
    expect(verifyWebhook(secret, payload, bad, { now: T })).toBe(false);
  });
});

describe('webhookHeaders', () => {
  it('returns a verifiable PCA-Signature plus content-type', () => {
    const secret = 'whsec_hdr';
    const payload = '{"hello":"world"}';
    const T = 1_700_000_200;
    const headers = webhookHeaders(secret, payload, { timestamp: T });
    expect(headers['content-type']).toBe('application/json');
    const sig = headers['PCA-Signature'];
    expect(sig).toBeDefined();
    expect(verifyWebhook(secret, payload, sig ?? '', { now: T })).toBe(true);
  });
});
