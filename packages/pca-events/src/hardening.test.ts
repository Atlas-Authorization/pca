import { InMemoryReplayStore } from '@atlasauth/pca';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import { describe, expect, it } from 'vitest';
import {
  MIN_SECRET_BYTES,
  buildStepUpEvent,
  parseEvent,
  serializeEvent,
  signWebhook,
  verifyDelivery,
  verifyWebhook,
  webhookHeaders,
} from './index';

const SECRET = 'whsec_0123456789abcdef0123456789';
const T = 1_700_000_100;
const event = buildStepUpEvent('step_up.approved', { type: 'step_up.approved', at: 1_700_000_000_000, grant_ref: 'g1', action: { verb: 'stripe.refund', resource: 'pi_1' }, tier: 2, actor: 'u1' });
const payload = serializeEvent(event);
const sig = signWebhook(SECRET, payload, { timestamp: T });

describe('the secret', () => {
  it('a secret under the minimum cannot sign and never verifies', () => {
    expect(MIN_SECRET_BYTES).toBe(16);
    for (const weak of ['', 'short', 'a'.repeat(15), new Uint8Array(0), new Uint8Array(15)]) {
      expect(() => signWebhook(weak, payload, { timestamp: T })).toThrow(`signWebhook: the secret must be at least 16 bytes`);
      expect(verifyWebhook(weak, payload, sig, { now: T })).toBe(false);
    }
    expect(() => signWebhook('a'.repeat(16), payload, { timestamp: T })).not.toThrow();
  });
  it('the empty-key forgery is refused: a signature made with an empty key does not verify under a real one', () => {
    const forged = `t=${T},v1=${bytesToHex(hmac(sha256, new Uint8Array(0), `${T}.${payload}`))}`;
    expect(verifyWebhook(SECRET, payload, forged, { now: T })).toBe(false);
    expect(verifyWebhook('', payload, forged, { now: T })).toBe(false); // the receiver with an empty key accepts nothing
  });
  it('an error or a refusal never contains the secret or the signature', () => {
    let msg = '';
    try {
      signWebhook('hunter2-too-short', payload, { timestamp: -1 });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).not.toContain('hunter2');
    const headers = webhookHeaders(SECRET, payload, { timestamp: T });
    expect(JSON.stringify(headers)).not.toContain(SECRET);
    expect(sig).not.toContain(SECRET);
  });
});

describe('timestamps and tolerance fail closed', () => {
  it('a non-finite or negative tolerance or clock never accepts', () => {
    expect(verifyWebhook(SECRET, payload, sig, { now: T, toleranceSec: Number.NaN })).toBe(false);
    expect(verifyWebhook(SECRET, payload, sig, { now: T, toleranceSec: -1 })).toBe(false);
    expect(verifyWebhook(SECRET, payload, sig, { now: Number.NaN })).toBe(false);
    expect(verifyWebhook(SECRET, payload, sig, { now: Infinity })).toBe(false);
    expect(verifyWebhook(SECRET, payload, sig, { now: T, toleranceSec: 0 })).toBe(true);
  });
  it('the tolerance is exact in both directions', () => {
    expect(verifyWebhook(SECRET, payload, sig, { now: T + 300 })).toBe(true);
    expect(verifyWebhook(SECRET, payload, sig, { now: T + 301 })).toBe(false);
    expect(verifyWebhook(SECRET, payload, sig, { now: T - 300 })).toBe(true);
    expect(verifyWebhook(SECRET, payload, sig, { now: T - 301 })).toBe(false);
  });
  it('signing refuses a timestamp that is not a non-negative integer', () => {
    for (const t of [Number.NaN, -1, 1.5, Infinity]) expect(() => signWebhook(SECRET, payload, { timestamp: t })).toThrow('signWebhook: timestamp must be a non-negative integer (unix seconds)');
  });
  it('a header timestamp in hex, exponent or fractional form is refused', () => {
    const mac = sig.split('v1=')[1] as string;
    for (const t of ['0x6553f1a4', '1.7e9', '1700000100.0', ' ', '', '-1700000100', '17000001000000000000']) expect(verifyWebhook(SECRET, payload, `t=${t},v1=${mac}`, { now: T })).toBe(false);
  });
  it('two different timestamps in one header are refused', () => {
    const mac = sig.split('v1=')[1] as string;
    expect(verifyWebhook(SECRET, payload, `t=${T},t=${T + 1},v1=${mac}`, { now: T })).toBe(false);
    expect(verifyWebhook(SECRET, payload, `t=${T + 1},t=${T},v1=${mac}`, { now: T })).toBe(false); // the last one alone would verify
    expect(verifyWebhook(SECRET, payload, `t=${T},t=${T},v1=${mac}`, { now: T })).toBe(true);
  });
  it('an oversized header is refused', () => {
    expect(verifyWebhook(SECRET, payload, `${sig},${'x=y,'.repeat(1000)}`, { now: T })).toBe(false);
  });
});

describe('secret rotation: several v1 entries', () => {
  const OLD = 'whsec_old_0123456789abcdef012345';
  it('any matching v1 is enough, in any position', () => {
    const oldMac = signWebhook(OLD, payload, { timestamp: T }).split('v1=')[1] as string;
    const newMac = sig.split('v1=')[1] as string;
    expect(verifyWebhook(SECRET, payload, `t=${T},v1=${oldMac},v1=${newMac}`, { now: T })).toBe(true);
    expect(verifyWebhook(SECRET, payload, `t=${T},v1=${newMac},v1=${oldMac}`, { now: T })).toBe(true);
    expect(verifyWebhook('whsec_other_0123456789abcdefghi', payload, `t=${T},v1=${oldMac},v1=${newMac}`, { now: T })).toBe(false);
  });
  it('a bad entry next to a good one does not hide the good one', () => {
    const mac = sig.split('v1=')[1] as string;
    expect(verifyWebhook(SECRET, payload, `t=${T},v1=zz,v1=${mac}`, { now: T })).toBe(true);
    expect(verifyWebhook(SECRET, payload, `t=${T},v1=${mac.slice(0, 62)},v1=${mac}`, { now: T })).toBe(true);
  });
  it('a truncated or extended mac never matches', () => {
    const mac = sig.split('v1=')[1] as string;
    expect(verifyWebhook(SECRET, payload, `t=${T},v1=${mac.slice(0, 62)}`, { now: T })).toBe(false);
    expect(verifyWebhook(SECRET, payload, `t=${T},v1=${mac}00`, { now: T })).toBe(false);
  });
});

describe('parseEvent checks the content address', () => {
  const tamper = (patch: object) => JSON.stringify({ ...JSON.parse(payload), ...patch });
  it('an event whose id is not the digest of its fields is refused', () => {
    for (const patch of [{ tier: 3 }, { actor: 'mallory' }, { grant_ref: 'g2' }, { at: 1 }, { action: { verb: 'stripe.refund', resource: 'pi_2' } }, { type: 'step_up.denied' }]) {
      expect(() => parseEvent(tamper(patch)), JSON.stringify(patch)).toThrow('parseEvent: id does not match the event content');
    }
  });
  it('a forged id is refused and a genuine one is accepted', () => {
    expect(() => parseEvent(tamper({ id: 'anything' }))).toThrow('id does not match');
    expect(parseEvent(payload)).toEqual(event);
  });
  it('extra members are dropped, not trusted', () => {
    expect(parseEvent(tamper({ approved_by_admin: true }))).toEqual(event);
  });
  it.each([[''], ['[]'], ['{}'], ['"x"'], ['{"id":""}']])('refuses %s', (s) => {
    expect(() => parseEvent(s)).toThrow();
  });
});

describe('verifyDelivery: one genuine delivery per event', () => {
  const opts = (replay = new InMemoryReplayStore()) => ({ replay, now: T });
  it('accepts a genuine delivery once and refuses the replay', async () => {
    const o = opts();
    expect(await verifyDelivery(SECRET, payload, sig, o)).toEqual({ ok: true, event });
    expect(await verifyDelivery(SECRET, payload, sig, o)).toEqual({ ok: false, reason: 'replayed delivery' });
  });
  it('a redelivery of the same event under a fresh signature is also the same event', async () => {
    const o = opts();
    await verifyDelivery(SECRET, payload, sig, o);
    const again = signWebhook(SECRET, payload, { timestamp: T + 10 });
    expect(await verifyDelivery(SECRET, payload, again, { ...o, now: T + 10 })).toEqual({ ok: false, reason: 'replayed delivery' });
  });
  it('a bad signature does not burn the event id', async () => {
    const o = opts();
    expect(await verifyDelivery('whsec_wrong_0123456789abcdefghi', payload, sig, o)).toEqual({ ok: false, reason: 'bad signature' });
    expect((await verifyDelivery(SECRET, payload, sig, o)).ok).toBe(true);
  });
  it('a correctly signed payload that is not a well-formed event is refused with the parse reason', async () => {
    const bad = JSON.stringify({ ...JSON.parse(payload), id: 'forged' });
    const s = signWebhook(SECRET, bad, { timestamp: T });
    expect(await verifyDelivery(SECRET, bad, s, opts())).toEqual({ ok: false, reason: 'parseEvent: id does not match the event content' });
    const junk = signWebhook(SECRET, 'not json', { timestamp: T });
    expect((await verifyDelivery(SECRET, 'not json', junk, opts())).ok).toBe(false);
  });
  it('without a replay store, or with one that throws, nothing is accepted', async () => {
    expect(await verifyDelivery(SECRET, payload, sig, { now: T } as never)).toEqual({ ok: false, reason: 'a replay store is required' });
    expect(await verifyDelivery(SECRET, payload, sig, { now: T, replay: { consumeOnce: async () => { throw new Error('redis://:pw@h'); } } })).toEqual({ ok: false, reason: 'replay store unavailable' });
  });
  it('a stale delivery is refused before the store is touched', async () => {
    let touched = false;
    const r = await verifyDelivery(SECRET, payload, sig, { now: T + 1000, replay: { consumeOnce: async () => ((touched = true), true) } });
    expect(r).toEqual({ ok: false, reason: 'bad signature' });
    expect(touched).toBe(false);
  });
  it('no refusal reason carries the secret or the payload', async () => {
    const reasons = [
      await verifyDelivery('whsec_wrong_0123456789abcdefghi', payload, sig, opts()),
      await verifyDelivery(SECRET, payload, 'garbage', opts()),
      await verifyDelivery(SECRET, payload, sig, { now: T } as never),
    ].map((r) => JSON.stringify(r));
    for (const r of reasons) {
      expect(r).not.toContain(SECRET);
      expect(r).not.toContain('pi_1');
    }
  });
});
