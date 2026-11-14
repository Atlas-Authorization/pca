import { describe, expect, it } from 'vitest';
import {
  buildEAT, generateEatKeyPair, issueNonce, verifyChannelBinding, verifyEAT, verifyFreshAttestedEAT, verifyFreshness,
  type EatClaims,
} from './index';

// Audit-readiness: the fail-closed table of the README, one exact outcome per row.
const ISS = 'https://attester.atlasauth.net';
const CH = 'tls-exporter-live-channel';
const NOW = 1_700_000_000_000;
const policy = { endorsements: { issuers: [ISS] }, referenceValues: {} };
const mk = (over: Partial<Parameters<typeof buildEAT>[0]> = {}) => {
  const { publicKey, privateKey } = generateEatKeyPair();
  const nonce = issueNonce({ now: NOW }).value;
  const eat = buildEAT({ issuer: ISS, nonce, channelId: CH, key: privateKey, now: NOW, ...over });
  return { publicKey, privateKey, nonce, eat };
};
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const throwsMsg = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return (e as Error).message;
  }
  return '';
};

describe('EAT fail-closed table: building refuses unbound or unfresh evidence', () => {
  it('missing issuer, nonce or channel binding, or an unknown alg -> buildEAT throws the named reason', () => {
    const { privateKey } = generateEatKeyPair();
    expect(throwsMsg(() => buildEAT({ issuer: '', nonce: 'n', channelId: CH, key: privateKey }))).toBe('buildEAT: issuer is required');
    expect(throwsMsg(() => buildEAT({ issuer: ISS, nonce: '', channelId: CH, key: privateKey }))).toBe('buildEAT: nonce (eat_nonce) is required for freshness');
    expect(throwsMsg(() => buildEAT({ issuer: ISS, nonce: 'n', key: privateKey } as never))).toMatch(/channel binding .* is required/);
    expect(throwsMsg(() => buildEAT({ issuer: ISS, nonce: 'n', channelId: CH, key: privateKey, alg: 'HS256' as never }))).toBe("buildEAT: unsupported alg 'HS256'");
  });
});

describe('EAT fail-closed table: verifyEAT refusals carry exact reasons', () => {
  it('wrong signer, alg none, HS256 downgrade, missing parts, bad typ -> "EAT invalid: ..."', () => {
    const { eat } = mk();
    const other = generateEatKeyPair().publicKey;
    expect(throwsMsg(() => verifyEAT(eat, other))).toBe('EAT invalid: signature does not verify');
    const [h, p] = eat.split('.');
    expect(throwsMsg(() => verifyEAT(`${b64({ alg: 'none', typ: 'eat+jwt' })}.${p}.`, other))).toMatch(/^EAT invalid:/);
    expect(throwsMsg(() => verifyEAT(`${b64({ alg: 'HS256', typ: 'eat+jwt' })}.${p}.${'A'.repeat(43)}`, other))).toMatch(/^EAT invalid:/);
    expect(throwsMsg(() => verifyEAT(`${h}.${p}`, other))).toMatch(/^EAT invalid:/);
    expect(throwsMsg(() => verifyEAT(5 as never, other))).toBe('EAT invalid: token is not a string');
    const pub = mk();
    const wrongTyp = buildEAT({ issuer: ISS, nonce: 'n', channelId: CH, key: pub.privateKey, now: NOW });
    expect(throwsMsg(() => verifyEAT(wrongTyp, pub.publicKey, { typ: 'other+jwt' }))).toBe('EAT invalid: typ eat+jwt is not other+jwt');
  });

  it('unaccepted issuer and disallowed alg -> exact reasons', () => {
    const { eat, publicKey } = mk();
    expect(throwsMsg(() => verifyEAT(eat, publicKey, { issuer: 'https://evil.example' }))).toBe(`EAT invalid: iss ${ISS} is not an accepted issuer`);
    expect(throwsMsg(() => verifyEAT(eat, publicKey, { algorithms: ['ES256'] }))).toBe('EAT invalid: alg EdDSA not in the allowed set');
  });

  it('a payload edited after signing -> signature does not verify', () => {
    const { eat, publicKey } = mk();
    const [h, p, s] = eat.split('.');
    const claims = JSON.parse(Buffer.from(p!, 'base64url').toString());
    claims.iss = 'https://evil.example';
    expect(throwsMsg(() => verifyEAT(`${h}.${b64(claims)}.${s}`, publicKey))).toMatch(/^EAT invalid:/);
  });
});

describe('EAT fail-closed table: freshness and channel gates', () => {
  const claims = (over: Partial<EatClaims> = {}): EatClaims => ({ iss: ISS, iat: NOW / 1000, eat_nonce: 'n1', cnf: { tls_exporter: 'x' }, ...over }) as EatClaims;

  it('freshness: each missing or wrong input -> its own reason', () => {
    const f = (c: EatClaims, o: Partial<Parameters<typeof verifyFreshness>[1]> = {}) => verifyFreshness(c, { expectedNonce: 'n1', maxAgeMs: 60_000, now: NOW, ...o });
    expect(f(claims())).toEqual({ ok: true });
    expect(f(claims(), { expectedNonce: '' }).reason).toBe('no expected (server-issued) nonce supplied (fail closed)');
    expect(f(claims({ eat_nonce: undefined })).reason).toMatch(/no eat_nonce/);
    expect(f(claims({ eat_nonce: 'n2' })).reason).toMatch(/does not match the server-issued challenge/);
    expect(f(claims({ iat: undefined as never })).reason).toBe('EAT has no valid iat (cannot establish age)');
    expect(f(claims(), { maxAgeMs: 0 }).reason).toBe('invalid maxAgeMs');
    expect(f(claims(), { maxAgeMs: Number.NaN }).reason).toBe('invalid maxAgeMs');
    expect(f(claims({ iat: NOW / 1000 + 5 })).reason).toBe('EAT iat is in the future');
    expect(f(claims({ iat: NOW / 1000 - 61 })).reason).toMatch(/stale/);
    expect(f(claims({ iat: NOW / 1000 - 60 }))).toEqual({ ok: true }); // exactly maxAge is inside the window
    expect(f(claims({ iat: NOW / 1000 + 5 }), { clockSkewMs: 5000 })).toEqual({ ok: true });
  });

  it('channel: no expectation, no cnf, other channel, other key thumbprint -> own reason', () => {
    const { eat, publicKey } = mk();
    const c = verifyEAT(eat, publicKey);
    expect(verifyChannelBinding(c, {})).toEqual({ ok: false, reason: 'no expected channel binding supplied (fail closed)' });
    expect(verifyChannelBinding(c, { channelId: CH })).toEqual({ ok: true });
    expect(verifyChannelBinding(c, { channelId: 'other' }).reason).toMatch(/TLS-exporter channel binding mismatch/);
    expect(verifyChannelBinding({ ...c, cnf: undefined }, { channelId: CH }).reason).toMatch(/no channel\/key binding/);
    expect(verifyChannelBinding(c, { expectedCnf: { jkt: 'thumb' } }).reason).toBe('holder-key thumbprint (cnf.jkt) mismatch');
  });
});

describe('EAT fail-closed table: the end-to-end verdict', () => {
  it('each failing gate stops the pipeline with ok:false and no tier (signature, freshness, channel); unknown issuer -> not ok', async () => {
    const { eat, publicKey, nonce } = mk();
    const base = { verifyKey: publicKey, nonce, channelId: CH, policy, now: NOW };
    const sig = await verifyFreshAttestedEAT(eat, { ...base, verifyKey: generateEatKeyPair().publicKey });
    expect(sig).toMatchObject({ ok: false, reasons: ['EAT signature/claims invalid: EAT invalid: signature does not verify'] });
    expect(sig.tier).toBeUndefined();
    const stale = await verifyFreshAttestedEAT(eat, { ...base, now: NOW + 10 * 60_000 });
    expect(stale.ok).toBe(false);
    expect(stale.tier).toBeUndefined();
    expect(stale.reasons.at(-1)).toMatch(/stale/);
    const replay = await verifyFreshAttestedEAT(eat, { ...base, nonce: issueNonce({ now: NOW }).value });
    expect(replay.reasons.at(-1)).toMatch(/does not match the server-issued challenge/);
    const relay = await verifyFreshAttestedEAT(eat, { ...base, channelId: 'other-channel' });
    expect(relay.reasons.at(-1)).toMatch(/TLS-exporter channel binding mismatch/);
    const noChan = await verifyFreshAttestedEAT(eat, { verifyKey: publicKey, nonce, policy, now: NOW });
    expect(noChan.reasons.at(-1)).toBe('no expected channel binding supplied (fail closed)');
    const unendorsed = await verifyFreshAttestedEAT(eat, { ...base, policy: { endorsements: { issuers: ['https://other.example'] }, referenceValues: {} } });
    expect(unendorsed.ok).toBe(false);
  });

  it('an AMD hardware check that cannot pass (garbage report and chain) -> contraindicated, never affirming', async () => {
    const { eat, publicKey, nonce } = mk();
    const v = await verifyFreshAttestedEAT(eat, {
      verifyKey: publicKey, nonce, channelId: CH, policy, now: NOW,
      amd: { rawReport: new Uint8Array(10), vcek: new Uint8Array(4), ask: new Uint8Array(4), ark: new Uint8Array(4), family: 'milan' },
    });
    expect(v.ok).toBe(false);
    expect(v.tier).toBe('contraindicated');
    expect(v.reasons.at(-1)).toMatch(/^AMD hardware root verification failed:/);
  });
});
