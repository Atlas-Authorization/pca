import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { decodePcaNeed, encodePcaNeed, pcaNeedDigest, pcaNeedFromChallenge, validatePcaNeed, type PcaNeed } from './pca-need';

const need: PcaNeed = { v: 1, kind: 'scope', verb: 'stripe.refund', resource: 'charge/ch_1', scopes: ['refunds:write'], limits: { 'money.usd': 40 } };
const enc = (o: unknown) => b64u(new TextEncoder().encode(JSON.stringify(o)));

describe('pca_need challenge parameter - T-581', () => {
  it('round-trips and the digest is stable', () => {
    const e = encodePcaNeed(need);
    expect(decodePcaNeed(e)).toEqual({ ok: true, need });
    expect(pcaNeedDigest(need)).toBe(pcaNeedDigest({ ...need }));
    expect(pcaNeedDigest(need)).not.toBe(pcaNeedDigest({ ...need, resource: 'charge/ch_2' }));
  });
  it('reads the parameter out of a multi-challenge header and ignores a header without it', () => {
    const e = encodePcaNeed(need);
    const h = `Bearer error="insufficient_scope", scope="refunds:write", pca_need="${e}", PCA-StepUp realm="pca"`;
    expect(pcaNeedFromChallenge(h)).toEqual({ ok: true, need });
    expect(pcaNeedFromChallenge('Bearer error="insufficient_scope", scope="a"')).toBeNull();
    expect(pcaNeedFromChallenge(undefined)).toBeNull();
    expect(pcaNeedFromChallenge('Bearer x_pca_need="abc"')).toBeNull();
  });
  const bad: Array<[string, unknown, string]> = [
    ['unpadded only: padding', `${encodePcaNeed(need)}=`, 'bad_base64'],
    ['not a string', 5, 'bad_base64'],
    ['empty', '', 'bad_base64'],
    ['over-long', 'A'.repeat(2049), 'too_long'],
    ['invalid utf8', b64u(new Uint8Array([0xff, 0xfe])), 'bad_utf8'],
    ['not json', b64u(new TextEncoder().encode('{')), 'bad_json'],
    ['duplicate keys', b64u(new TextEncoder().encode('{"v":1,"v":1}')), 'bad_json'],
    ['array', enc([]), 'bad_shape'],
    ['wrong version', enc({ ...need, v: 2 }), 'bad_version'],
    ['unknown kind', enc({ ...need, kind: 'admin' }), 'bad_kind'],
    ['unknown member', enc({ ...need, grant: 'x' }), 'unknown_member'],
    ['empty verb', enc({ ...need, verb: '' }), 'bad_field'],
    ['scope with space', enc({ ...need, scopes: ['a b'] }), 'bad_field'],
    ['negative limit', enc({ ...need, limits: { 'money.usd': -1 } }), 'bad_field'],
    ['non-finite limit', enc({ ...need, limits: { 'money.usd': null } }), 'bad_field'],
    ['tier on a scope need', enc({ ...need, tier: 2 }), 'bad_field'],
    ['escalate without tier', enc({ v: 1, kind: 'escalate', verb: 'v', resource: 'r' }), 'bad_field'],
    ['discharge with extra member', enc({ ...need, kind: 'discharge', discharges: [{ issuer: 'https://i', claim: 'c', x: 1 }] }), 'bad_field'],
    ['too many scopes', enc({ ...need, scopes: Array.from({ length: 17 }, (_, i) => `s${i}`) }), 'bad_field'],
  ];
  for (const [name, input, code] of bad) {
    it(`refuses ${name} with ${code}`, () => {
      expect(decodePcaNeed(input)).toEqual({ ok: false, code });
    });
  }
  it('accepts an escalation with a tier and a discharge list', () => {
    const e: PcaNeed = { v: 1, kind: 'escalate', verb: 'v', resource: 'r', tier: 3, discharges: [{ issuer: 'https://issuer.example', claim: 'kyc' }] };
    expect(validatePcaNeed(e)).toEqual({ ok: true, need: e });
  });
  it('encode refuses a malformed or over-large need rather than truncating', () => {
    expect(() => encodePcaNeed({ ...need, verb: '' })).toThrow(RangeError);
    const big: PcaNeed = { v: 1, kind: 'discharge', verb: 'v', resource: 'r', discharges: Array.from({ length: 16 }, () => ({ issuer: `https://${'a'.repeat(300)}`, claim: 'c' })) };
    expect(() => encodePcaNeed(big)).toThrow(/too large/);
  });
});
