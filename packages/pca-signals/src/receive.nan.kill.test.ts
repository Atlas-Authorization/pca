import { SignJWT, generateKeyPair } from 'jose';
import { describe, expect, it } from 'vitest';
import { EVENT_TYPES, createInMemorySetReplayStore, createRevocationState, isRevoked, receiveSET, type ReceiveSetOptions } from './index';

const ISS = 'https://transmitter.example';
const AUD = 'https://rs.example';
const NOW = 1_800_000_000;
const claims = { iss: ISS, aud: AUD, iat: NOW, jti: 'jti-1', events: { [EVENT_TYPES.grantRevoked]: { grant_ref: 'g1', reason: 'r', event_timestamp: NOW } } };
const opts = (over: Partial<ReceiveSetOptions> = {}): ReceiveSetOptions => ({ issuer: ISS, audience: AUD, replayStore: createInMemorySetReplayStore(), state: createRevocationState(), maxAgeSec: 3600, nowSec: NOW, ...over });

describe('receiveSET with a non-finite clock or skew never applies the SET', () => {
  // pre-fix: `iat > nowSec + skew` was false for a NaN operand and the staleness check is false for a NaN clock too
  it('clockSkewSec of NaN is iat_future', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const set = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', typ: 'secevent+jwt' }).sign(privateKey);
    const o = opts({ clockSkewSec: Number.NaN });
    const r = await receiveSET(set, publicKey, o);
    expect(r.ok === false && r.code).toBe('iat_future');
    expect(isRevoked(o.state, 'g1')).toBe(false);
  });
  it.each([Number.NaN, Number.NEGATIVE_INFINITY, Number.POSITIVE_INFINITY, 1e300, -1e300])('nowSec of %s', async (nowSec) => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const set = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', typ: 'secevent+jwt' }).sign(privateKey);
    const o = opts({ nowSec });
    expect((await receiveSET(set, publicKey, o)).ok).toBe(false);
    expect(isRevoked(o.state, 'g1')).toBe(false);
  });
  // old code: an infinite skew made `iat <= nowSec + skew` true for any iat, admitting a SET issued in the far future
  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])('clockSkewSec of %s', async (clockSkewSec) => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA');
    const set = await new SignJWT({ ...claims, iat: NOW + 10_000_000 }).setProtectedHeader({ alg: 'EdDSA', typ: 'secevent+jwt' }).sign(privateKey);
    const o = opts({ clockSkewSec });
    expect((await receiveSET(set, publicKey, o)).ok).toBe(false);
    expect(isRevoked(o.state, 'g1')).toBe(false);
  });
});
