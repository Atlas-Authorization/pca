import { afterEach, describe, expect, it, vi } from 'vitest';
import { replayKey } from '@atlasauth/pca';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { buildStepUpEvent, parseEvent, serializeEvent, signWebhook, verifyDelivery, verifyWebhook, webhookHeaders } from './index';

const SECRET = 'whsec_kill_test_0123456789abcdef';
const T = 1_700_000_000;
const base = () => ({ at: 1_700_000_000_000, grant_ref: 'g1', action: { verb: 'v.x', resource: 'r:1' }, tier: 2 as const, actor: 'u1' });
const event = () => buildStepUpEvent('step_up.approved', base());
const payload = () => serializeEvent(event());
const macOf = (sig: string) => sig.split('v1=')[1]!;
const edit = (patch: Record<string, unknown>) => JSON.stringify({ ...JSON.parse(payload()), ...patch });

afterEach(() => vi.useRealTimers());

describe('buildStepUpEvent', () => {
  it('carries the actor when given and omits the key when absent', () => {
    expect(event().actor).toBe('u1');
    const { actor: _a, ...noActor } = base();
    expect('actor' in buildStepUpEvent('step_up.created', noActor)).toBe(false);
  });
});

describe('parseEvent refusal reasons', () => {
  const cases: Array<[string, string]> = [
    ['5', 'parseEvent: not an object'],
    ['null', 'parseEvent: not an object'],
    [edit({ id: '' }), 'parseEvent: bad id'],
    [edit({ id: 5 }), 'parseEvent: bad id'],
    [edit({ type: 'nope' }), 'parseEvent: bad type'],
    [edit({ type: 5 }), 'parseEvent: bad type'],
    [edit({ at: 'x' }), 'parseEvent: bad at'],
    [payload().replace(/"at":\d+/, '"at":1e999'), 'parseEvent: bad at'],
    [edit({ grant_ref: 5 }), 'parseEvent: bad grant_ref'],
    [edit({ action: 'x' }), 'parseEvent: bad action'],
    [edit({ action: null }), 'parseEvent: bad action'],
    [edit({ action: { verb: 1, resource: 'r' } }), 'parseEvent: bad action fields'],
    [edit({ action: { verb: 'v', resource: 1 } }), 'parseEvent: bad action fields'],
    [edit({ action: {} }), 'parseEvent: bad action fields'],
    [edit({ tier: 4 }), 'parseEvent: bad tier'],
    [edit({ tier: '2' }), 'parseEvent: bad tier'],
    [edit({ actor: 5 }), 'parseEvent: bad actor'],
  ];
  it.each(cases)('%s', (s, msg) => {
    expect(() => parseEvent(s)).toThrow(new Error(msg));
  });
  it('accepts tier 3 and an actor-less event', () => {
    const e3 = buildStepUpEvent('step_up.created', { ...base(), tier: 3, actor: undefined });
    expect(parseEvent(serializeEvent(e3))).toEqual(e3);
  });
});

describe('signWebhook clock and bounds', () => {
  it('defaults to the current unix second and requires no opts', () => {
    vi.useFakeTimers();
    vi.setSystemTime(T * 1000 + 999);
    expect(signWebhook(SECRET, 'p')).toBe(`t=${T},v1=${bytesToHex(hmac(sha256, new TextEncoder().encode(SECRET), `${T}.p`))}`);
  });
  it('accepts timestamp 0 and refuses a negative one', () => {
    expect(signWebhook(SECRET, 'p', { timestamp: 0 }).startsWith('t=0,v1=')).toBe(true);
    expect(() => signWebhook(SECRET, 'p', { timestamp: -1 })).toThrow('signWebhook: timestamp must be a non-negative integer (unix seconds)');
  });
  it('webhookHeaders sets the content type', () => {
    expect(webhookHeaders(SECRET, 'p', { timestamp: T })['content-type']).toBe('application/json');
  });
});

describe('verifyWebhook header parsing', () => {
  const sig = () => signWebhook(SECRET, 'body', { timestamp: T });
  const ok = (h: string) => verifyWebhook(SECRET, 'body', h, { now: T });

  it('uses the real clock and default tolerance when no opts are given', () => {
    vi.useFakeTimers();
    vi.setSystemTime(T * 1000);
    expect(verifyWebhook(SECRET, 'body', sig())).toBe(true);
  });
  it('trims keys and values and skips parts without "="', () => {
    const m = macOf(sig());
    expect(ok(`t = ${T} , v1 = ${m}`)).toBe(true);
    expect(ok(`t=${T},v1=${m},junk`)).toBe(true);
    expect(ok(`t=${T},=x,v1=${m}`)).toBe(true);
    // a part without '=' whose text minus its last character is a real key must not be read as that key
    expect(ok(`t=${T},tx,v1=${m}`)).toBe(true);
  });
  it('ignores unknown keys even if their value is a valid mac', () => {
    expect(ok(`t=${T},sig=${macOf(sig())}`)).toBe(false);
  });
  it('refuses a header with no timestamp even when the mac matches the literal "undefined" timestamp', () => {
    const forged = bytesToHex(hmac(sha256, new TextEncoder().encode(SECRET), 'undefined.body'));
    expect(ok(`v1=${forged}`)).toBe(false);
  });
  it('refuses a header with a timestamp but no v1', () => {
    expect(ok(`t=${T}`)).toBe(false);
  });
  it('rotation: a malformed v1 candidate does not stop a later valid one', () => {
    expect(ok(`t=${T},v1=zz,v1=${macOf(sig())}`)).toBe(true);
  });
  it('enforces the header length cap at exactly 2048 characters', () => {
    const head = `t=${T},v1=${macOf(sig())},`;
    expect(ok(head + 'x'.repeat(2048 - head.length))).toBe(true);
    expect(ok(head + 'x'.repeat(2049 - head.length))).toBe(false);
  });
  it('refuses a non-string header, including a string-like object', () => {
    const fake = { length: 1, split: () => [`t=${T}`, `v1=${macOf(sig())}`] };
    expect(ok(fake as never)).toBe(false);
  });
  it('never throws: a throwing options getter yields false', () => {
    const opts = { get toleranceSec(): number { throw new Error('x'); } };
    expect(verifyWebhook(SECRET, 'body', sig(), opts)).toBe(false);
  });
});

describe('verifyDelivery', () => {
  it('uses the real clock for the replay window and a namespaced key', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(T * 1000);
    const calls: Array<[string, number, number]> = [];
    const replay = { consumeOnce: async (k: string, r: number, n: number) => (calls.push([k, r, n]), true) };
    const p = payload();
    const s = signWebhook(SECRET, p, { timestamp: T });
    expect((await verifyDelivery(SECRET, p, s, { replay, toleranceSec: 60 })).ok).toBe(true);
    expect(calls).toEqual([[replayKey('pca-stepup-event/v1', event().id), (T + 60) * 1000 + 1, T * 1000]]);
    calls.length = 0;
    await verifyDelivery(SECRET, p, s, { replay });
    expect(calls[0]![1]).toBe((T + 300) * 1000 + 1);
  });
  it('never throws: a throwing options getter yields a bad-signature verdict', async () => {
    const opts = { get replay(): never { throw new Error('x'); } };
    expect(await verifyDelivery(SECRET, 'p', 'h', opts as never)).toEqual({ ok: false, reason: 'bad signature' });
  });
});
