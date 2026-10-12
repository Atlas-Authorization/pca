/** Mutation-kill suite for index.ts (EAT build/verify, freshness, channel binding, appraisal): exact reasons, boundaries, field parsing. */
import { createHash, createPrivateKey, generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AMD_SEV_SNP_HARDWARE_ROOT_LABEL,
  CHANNEL_BINDING_DOMAIN,
  DEFAULT_EAT_ALG,
  DEFAULT_MAX_AGE_MS,
  EAT_TYP,
  appraise,
  bindChannel,
  buildEAT,
  deriveChannelCnf,
  generateEatKeyPair,
  issueNonce,
  verifyChannelBinding,
  verifyEAT,
  verifyFreshAttestedEAT,
  verifyFreshness,
  type EatClaims,
  type EatCnf,
  type EatSevSnpEvidence,
  type ReferenceValues,
} from './index';

afterEach(() => vi.useRealTimers());

const enc = (v: unknown): string => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v), 'utf8').toString('base64url');
const sha = (s: string): string => createHash('sha256').update(CHANNEL_BINDING_DOMAIN).update(s).digest().toString('base64url');
const bad = (f: () => unknown): string => {
  try {
    f();
  } catch (e) {
    return (e as Error).message;
  }
  return 'NO THROW';
};

/** Hand-signed EAT with full control over header and payload. */
function forge(header: unknown, payload: unknown, key: KeyObject, alg: 'EdDSA' | 'ES256' = 'EdDSA'): string {
  const input = `${enc(header)}.${enc(payload)}`;
  const sig = alg === 'EdDSA' ? nodeSign(null, Buffer.from(input), key) : nodeSign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}
const hdr = (over: Record<string, unknown> = {}) => ({ alg: 'EdDSA', typ: 'eat+jwt', ...over });
const pl = (over: Record<string, unknown> = {}) => ({ iss: 'I', iat: 1000, ...over });

describe('constants and keys', () => {
  it('values', () => {
    expect(EAT_TYP).toBe('eat+jwt');
    expect(DEFAULT_EAT_ALG).toBe('EdDSA');
    expect(DEFAULT_MAX_AGE_MS).toBe(300_000);
    expect(CHANNEL_BINDING_DOMAIN).toBe('atlas-pca/eat-channel/v1');
  });
  it('generateEatKeyPair per algorithm', () => {
    expect(generateEatKeyPair().privateKey.asymmetricKeyType).toBe('ed25519');
    expect(generateEatKeyPair('EdDSA').privateKey.asymmetricKeyType).toBe('ed25519');
    const ec = generateEatKeyPair('ES256').privateKey;
    expect(ec.asymmetricKeyType).toBe('ec');
    expect(ec.asymmetricKeyDetails?.namedCurve).toBe('prime256v1');
    expect(bad(() => generateEatKeyPair('RS256' as never))).toBe("generateEatKeyPair: unsupported alg 'RS256'");
  });
});

describe('issueNonce', () => {
  it('random part is max(16, bytes ?? 32) bytes, then the issue time in base 36', () => {
    const n = issueNonce({ now: 1_700_000_000_000 });
    const [rand, time] = n.value.split('.') as [string, string];
    expect(Buffer.from(rand, 'base64url').length).toBe(32);
    expect(time).toBe((1_700_000_000_000).toString(36));
    expect(n.issuedAt).toBe(1_700_000_000_000);
    expect(Buffer.from(issueNonce({ bytes: 16 }).value.split('.')[0] as string, 'base64url').length).toBe(16);
    expect(Buffer.from(issueNonce({ bytes: 5 }).value.split('.')[0] as string, 'base64url').length).toBe(16);
    expect(Buffer.from(issueNonce({ bytes: 17 }).value.split('.')[0] as string, 'base64url').length).toBe(17);
    expect(Buffer.from(issueNonce({ bytes: 48 }).value.split('.')[0] as string, 'base64url').length).toBe(48);
    expect(issueNonce({ now: 0 }).value.endsWith('.0')).toBe(true);
    expect(issueNonce().value).not.toBe(issueNonce().value);
  });
  it('a non-finite or non-numeric now falls back to the clock', () => {
    vi.useFakeTimers();
    vi.setSystemTime(123_456);
    for (const now of [Number.NaN, Number.POSITIVE_INFINITY, '5' as never, undefined]) expect(issueNonce({ now }).issuedAt, String(now)).toBe(123_456);
    expect(issueNonce({ now: 7 }).issuedAt).toBe(7);
  });
});

describe('channel binding derivation', () => {
  it('deriveChannelCnf is domain-separated sha256, jkt only when non-empty', () => {
    expect(deriveChannelCnf('chan')).toEqual({ tls_exporter: sha('chan') });
    expect(Object.keys(deriveChannelCnf('chan', ''))).toEqual(['tls_exporter']);
    expect(Object.keys(deriveChannelCnf('chan', undefined))).toEqual(['tls_exporter']);
    expect(deriveChannelCnf('chan', 'thumb')).toEqual({ tls_exporter: sha('chan'), jkt: 'thumb' });
    expect(deriveChannelCnf('chan', 5 as never)).toEqual({ tls_exporter: sha('chan') });
    expect(sha('a')).not.toBe(sha('b'));
    expect(bad(() => deriveChannelCnf(''))).toBe('deriveChannelCnf: channelId is required');
    expect(bad(() => deriveChannelCnf(5 as never))).toBe('deriveChannelCnf: channelId is required');
  });
  it('bindChannel carries evidence, nonce and the derived cnf', () => {
    const ev = { x: 1 };
    expect(bindChannel(ev, 'chan', 'n1')).toEqual({ evidence: ev, nonce: 'n1', cnf: { tls_exporter: sha('chan') } });
    expect(bindChannel(ev, 'chan', 'n1').evidence).toBe(ev);
    expect(bad(() => bindChannel(ev, 'chan', ''))).toBe('bindChannel: a per-session nonce is required for freshness');
    expect(bad(() => bindChannel(ev, 'chan', 5 as never))).toBe('bindChannel: a per-session nonce is required for freshness');
    expect(bad(() => bindChannel(ev, '', 'n'))).toBe('deriveChannelCnf: channelId is required');
  });
});

describe('buildEAT', () => {
  const k = generateEatKeyPair();
  const decode = (t: string) => ({ h: JSON.parse(Buffer.from(t.split('.')[0] as string, 'base64url').toString()) as unknown, p: JSON.parse(Buffer.from(t.split('.')[1] as string, 'base64url').toString()) as unknown });
  it('wire form: header, claim order, iat in seconds', () => {
    const t = buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'chan', now: 1_700_000_999_999 });
    expect(Buffer.from(t.split('.')[0] as string, 'base64url').toString()).toBe('{"alg":"EdDSA","typ":"eat+jwt"}');
    expect(Buffer.from(t.split('.')[1] as string, 'base64url').toString()).toBe(`{"iss":"I","iat":1700000999,"eat_nonce":"N","cnf":{"tls_exporter":"${sha('chan')}"}}`);
    expect(t.split('.').length).toBe(3);
  });
  it('every optional claim, in a fixed order', () => {
    const measured = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o' };
    const sevsnp: EatSevSnpEvidence = { version: 2, measurement: 'aa' };
    const t = buildEAT({
      issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'c', now: 5000, ueid: 'U', sueid: 'S', oemid: 'O', dbgstat: 'disabled', measurements: [{ type: 'launch', value: 'v' }], measured, sevsnp,
    });
    expect(Object.keys(decode(t).p as object)).toEqual(['iss', 'iat', 'eat_nonce', 'cnf', 'ueid', 'sueid', 'oemid', 'dbgstat', 'measurements', 'measured', 'sevsnp']);
    const bare = buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'c', now: 5000 });
    expect(Object.keys(decode(bare).p as object)).toEqual(['iss', 'iat', 'eat_nonce', 'cnf']);
    for (const f of [{ ueid: '' }, { sueid: '' }, { oemid: '' }]) {
      expect(Object.keys(decode(buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'c', now: 5000, ...f })).p as object).length).toBe(5);
    }
  });
  it('argument errors, exact', () => {
    const base = { issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'c' };
    expect(bad(() => buildEAT({ ...base, issuer: '' }))).toBe('buildEAT: issuer is required');
    expect(bad(() => buildEAT({ ...base, issuer: 5 as never }))).toBe('buildEAT: issuer is required');
    expect(bad(() => buildEAT({ ...base, nonce: '' }))).toBe('buildEAT: nonce (eat_nonce) is required for freshness');
    expect(bad(() => buildEAT({ ...base, nonce: 5 as never }))).toBe('buildEAT: nonce (eat_nonce) is required for freshness');
    expect(bad(() => buildEAT({ ...base, alg: 'RS256' as never }))).toBe("buildEAT: unsupported alg 'RS256'");
    const noBind = 'buildEAT: a channel binding (channelId or channelBinding with a TLS exporter / holder-key thumbprint) is required (RA-TLS) — refusing to emit unbound evidence';
    expect(bad(() => buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N' }))).toBe(noBind);
    expect(bad(() => buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelBinding: {} }))).toBe(noBind);
    expect(bad(() => buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelBinding: { tls_exporter: 5, jkt: 5 } as never }))).toBe(noBind);
  });
  it('channel binding sources: id, explicit exporter, thumbprint, and precedence', () => {
    const cnfOf = (o: Record<string, unknown>) => (decode(buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', now: 1000, ...o } as never)).p as { cnf: unknown }).cnf;
    expect(cnfOf({ channelBinding: { jkt: 'J' } })).toEqual({ jkt: 'J' });
    expect(cnfOf({ channelBinding: { tls_exporter: 'E' } })).toEqual({ tls_exporter: 'E' });
    expect(cnfOf({ channelBinding: { tls_exporter: 'E', jkt: 'J' } })).toEqual({ tls_exporter: 'E', jkt: 'J' });
    expect(cnfOf({ channelId: 'c', channelBinding: { tls_exporter: 'E' } })).toEqual({ tls_exporter: 'E' });
    expect(cnfOf({ channelId: 'c', channelBinding: { jkt: 'J' } })).toEqual({ tls_exporter: sha('c'), jkt: 'J' });
    expect(cnfOf({ channelId: 'c' })).toEqual({ tls_exporter: sha('c') });
  });
  it('ES256 tokens, explicit EdDSA, and a pinned or live clock', () => {
    const es = generateEatKeyPair('ES256');
    const t = buildEAT({ issuer: 'I', key: es.privateKey, alg: 'ES256', nonce: 'N', channelId: 'c', now: 5000 });
    expect((decode(t).h as { alg: string }).alg).toBe('ES256');
    expect(Buffer.from(t.split('.')[2] as string, 'base64url').length).toBe(64);
    expect(verifyEAT(t, es.publicKey).iss).toBe('I');
    const ed = buildEAT({ issuer: 'I', key: k.privateKey, alg: 'EdDSA', nonce: 'N', channelId: 'c', now: 5000 });
    expect(Buffer.from(ed.split('.')[2] as string, 'base64url').length).toBe(64);
    vi.useFakeTimers();
    vi.setSystemTime(42_000);
    for (const now of [undefined, Number.NaN, Number.POSITIVE_INFINITY, '9' as never]) {
      expect((decode(buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'c', now })).p as { iat: number }).iat, String(now)).toBe(42);
    }
    expect((decode(buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'c', now: 0 })).p as { iat: number }).iat).toBe(0);
  });
});

describe('verifyEAT', () => {
  const k = generateEatKeyPair();
  const es = generateEatKeyPair('ES256');
  const tok = (h: unknown, p: unknown, key = k.privateKey, alg: 'EdDSA' | 'ES256' = 'EdDSA') => forge(h, p, key, alg);
  const v = (t: string, o = {}) => verifyEAT(t, k.publicKey, o);

  it('rejects non-strings and non-canonical spelling', () => {
    expect(bad(() => verifyEAT(5 as never, k.publicKey))).toBe('EAT invalid: token is not a string');
    expect(bad(() => verifyEAT('a.b', k.publicKey))).toMatch(/^EAT invalid: /);
    expect(bad(() => verifyEAT('a.b.c.d', k.publicKey))).toMatch(/^EAT invalid: /);
    const t = tok(hdr(), pl());
    const [h, p, s] = t.split('.') as [string, string, string];
    expect(bad(() => verifyEAT(`${h}.${p}.`, k.publicKey))).toMatch(/^EAT invalid: /);
    expect(bad(() => verifyEAT(`${h}=.${p}.${s}`, k.publicKey))).toMatch(/^EAT invalid: /);
    expect(bad(() => verifyEAT(`.${p}.${s}`, k.publicKey))).toMatch(/^EAT invalid: /);
    expect(bad(() => verifyEAT('x'.repeat((1 << 20) + 1), k.publicKey))).toMatch(/^EAT invalid: /);
  });
  it('algorithm header', () => {
    expect(bad(() => v(tok(hdr({ alg: 'none' }), pl())))).toBe('EAT invalid: missing or unsupported `alg` header');
    expect(bad(() => v(tok(hdr({ alg: 5 }), pl())))).toBe('EAT invalid: missing or unsupported `alg` header');
    expect(bad(() => v(tok({ typ: 'eat+jwt' }, pl())))).toBe('EAT invalid: missing or unsupported `alg` header');
    expect(bad(() => v(tok(hdr({ alg: 'ES256' }), pl(), es.privateKey, 'ES256'), { algorithms: ['EdDSA'] }))).toBe('EAT invalid: alg ES256 not in the allowed set');
    expect(bad(() => verifyEAT(tok(hdr({ alg: 'ES256' }), pl(), es.privateKey, 'ES256'), es.publicKey, { algorithms: ['EdDSA', 'ES256'] }))).toBe('NO THROW');
    expect(bad(() => v(tok(hdr(), pl()), { algorithms: ['ES256'] }))).toBe('EAT invalid: alg EdDSA not in the allowed set');
    expect(bad(() => v(tok(hdr(), pl()), { algorithms: [] }))).toBe('EAT invalid: alg EdDSA not in the allowed set');
  });
  it('typ header: case-insensitive media types with the application/ prefix optional', () => {
    for (const typ of ['eat+jwt', 'EAT+JWT', 'application/eat+jwt', 'Application/EAT+JWT']) expect(bad(() => v(tok(hdr({ typ }), pl()))), typ).toBe('NO THROW');
    for (const typ of ['jwt', 'text/eat+jwt', 'eat+jwt2', 'application/jwt', 'x/eat+jwt', 'application/application/eat+jwt', 5, undefined, null]) {
      expect(bad(() => v(tok(hdr({ typ }), pl()))), String(typ)).toBe(`EAT invalid: typ ${String(typ)} is not eat+jwt`);
    }
    expect(bad(() => v(tok(hdr({ typ: 'custom+jwt' }), pl()), { typ: 'custom+jwt' }))).toBe('NO THROW');
    expect(bad(() => v(tok(hdr({ typ: 'CUSTOM+JWT' }), pl()), { typ: 'application/custom+jwt' }))).toBe('NO THROW');
    expect(bad(() => v(tok(hdr({ typ: 'application/custom+jwt' }), pl()), { typ: 'CUSTOM+jwt' }))).toBe('NO THROW');
    expect(bad(() => v(tok(hdr({ typ: 'eat+jwt' }), pl()), { typ: 'custom+jwt' }))).toBe('EAT invalid: typ eat+jwt is not custom+jwt');
    expect(bad(() => v(tok(hdr({ typ: 'whatever' }), pl()), { requireTyp: false }))).toBe('NO THROW');
    expect(bad(() => v(tok({ alg: 'EdDSA' }, pl()), { requireTyp: false }))).toBe('NO THROW');
    expect(bad(() => v(tok({ alg: 'EdDSA' }, pl()), { requireTyp: true }))).toBe('EAT invalid: typ undefined is not eat+jwt');
  });
  it('signature', () => {
    const t = tok(hdr(), pl());
    expect(bad(() => verifyEAT(t, generateEatKeyPair().publicKey))).toBe('EAT invalid: signature does not verify');
    const [h, p, s] = t.split('.') as [string, string, string];
    expect(bad(() => v(`${h}.${enc(pl({ iss: 'Z' }))}.${s}`))).toBe('EAT invalid: signature does not verify');
    expect(bad(() => v(`${enc(hdr({ extra: 1 }))}.${p}.${s}`))).toBe('EAT invalid: signature does not verify');
  });
  it('mandatory claims', () => {
    expect(bad(() => v(tok(hdr(), { iat: 1 })))).toBe('EAT invalid: missing or non-string `iss`');
    expect(bad(() => v(tok(hdr(), { iss: 5, iat: 1 })))).toBe('EAT invalid: missing or non-string `iss`');
    expect(bad(() => v(tok(hdr(), { iss: 'I' })))).toBe('EAT invalid: missing or non-numeric `iat`');
    expect(bad(() => v(tok(hdr(), { iss: 'I', iat: '1' })))).toBe('EAT invalid: missing or non-numeric `iat`');
    expect(bad(() => v(tok(hdr(), { iss: 'I', iat: null })))).toBe('EAT invalid: missing or non-numeric `iat`');
    expect(v(tok(hdr(), { iss: '', iat: 0 }))).toEqual({ iss: '', iat: 0 });
  });
  it('issuer allow-list: string or array', () => {
    expect(bad(() => v(tok(hdr(), pl()), { issuer: 'I' }))).toBe('NO THROW');
    expect(bad(() => v(tok(hdr(), pl()), { issuer: 'J' }))).toBe('EAT invalid: iss I is not an accepted issuer');
    expect(bad(() => v(tok(hdr(), pl()), { issuer: ['J', 'I'] }))).toBe('NO THROW');
    expect(bad(() => v(tok(hdr(), pl()), { issuer: ['J', 'K'] }))).toBe('EAT invalid: iss I is not an accepted issuer');
    expect(bad(() => v(tok(hdr(), pl()), { issuer: [] }))).toBe('EAT invalid: iss I is not an accepted issuer');
    expect(bad(() => v(tok(hdr(), pl()), { issuer: '' }))).toBe('EAT invalid: iss I is not an accepted issuer');
  });
  it('claims are projected; wrongly typed claims are dropped', () => {
    const measured = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', weights_measured: true, system_prompt_digest: 'sp', tool_manifest_digest: 'tm', junk: 1 };
    const full = v(
      tok(hdr(), pl({
        eat_nonce: 'N', cnf: { tls_exporter: 'E', jkt: 'J', other: 1 }, ueid: 'U', sueid: 'S', oemid: 'O', dbgstat: 'disabled-permanently',
        measurements: [{ type: 'launch', value: 'v', extra: 1 }, { type: 5, value: 'x' }, { type: 'a' }, null, 'str'], measured,
        sevsnp: { version: 3, measurement: 'mm', reported_tcb: '123', guest_svn: 4, chip_id: 'cc', debug: false, degraded: true, junk: 1 },
      })),
    );
    expect(full).toStrictEqual({
      iss: 'I', iat: 1000, eat_nonce: 'N', cnf: { tls_exporter: 'E', jkt: 'J' }, ueid: 'U', sueid: 'S', measurements: [{ type: 'launch', value: 'v' }], dbgstat: 'disabled-permanently', oemid: 'O',
      measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', weights_measured: true, system_prompt_digest: 'sp', tool_manifest_digest: 'tm' },
      sevsnp: { version: 3, measurement: 'mm', reported_tcb: '123', guest_svn: 4, chip_id: 'cc', debug: false, degraded: true },
    });
    const junk = v(tok(hdr(), pl({ eat_nonce: 5, cnf: 'x', ueid: 5, sueid: 5, oemid: 5, dbgstat: 'loud', measurements: 'x', measured: { model_id: 'm' }, sevsnp: { version: '3', measurement: 'm' } })));
    expect(junk).toStrictEqual({ iss: 'I', iat: 1000 });
    expect(v(tok(hdr(), pl({ cnf: {} }))).cnf).toBeUndefined();
    expect(v(tok(hdr(), pl({ cnf: { tls_exporter: 5, jkt: 5 } }))).cnf).toBeUndefined();
    expect(v(tok(hdr(), pl({ cnf: { jkt: 'J' } }))).cnf).toStrictEqual({ jkt: 'J' });
    expect(v(tok(hdr(), pl({ cnf: { tls_exporter: 'E' } }))).cnf).toStrictEqual({ tls_exporter: 'E' });
    expect(v(tok(hdr(), pl({ cnf: [] }))).cnf).toBeUndefined();
    expect(v(tok(hdr(), pl({ measurements: [] }))).measurements).toBeUndefined();
    expect(v(tok(hdr(), pl({ measurements: [{ type: 5, value: 'x' }] }))).measurements).toBeUndefined();
    for (const d of ['enabled', 'disabled', 'disabled-since-boot', 'disabled-permanently', 'disabled-fully-and-permanently']) expect(v(tok(hdr(), pl({ dbgstat: d }))).dbgstat).toBe(d);
    expect(v(tok(hdr(), pl({ dbgstat: 5 }))).dbgstat).toBeUndefined();
    // measured: each mandatory member is required on its own
    for (const drop of ['model_id', 'weights_digest', 'runtime_measurement', 'operator']) {
      const m: Record<string, unknown> = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o' };
      m[drop] = 5;
      expect(v(tok(hdr(), pl({ measured: m }))).measured, drop).toBeUndefined();
    }
    expect(v(tok(hdr(), pl({ measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', weights_measured: 'yes', system_prompt_digest: 5, tool_manifest_digest: 5 } }))).measured).toStrictEqual({
      model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o',
    });
    expect(v(tok(hdr(), pl({ measured: [] }))).measured).toBeUndefined();
    // sevsnp: version/measurement mandatory, others typed; reported_tcb tolerant
    expect(v(tok(hdr(), pl({ sevsnp: { version: 3 } }))).sevsnp).toBeUndefined();
    expect(v(tok(hdr(), pl({ sevsnp: { measurement: 'm' } }))).sevsnp).toBeUndefined();
    expect(v(tok(hdr(), pl({ sevsnp: [] }))).sevsnp).toBeUndefined();
    expect(v(tok(hdr(), pl({ sevsnp: { version: 3, measurement: 'm', guest_svn: '1', chip_id: 5, debug: 'no', degraded: 'no' } }))).sevsnp).toStrictEqual({ version: 3, measurement: 'm' });
    expect(v(tok(hdr(), pl({ sevsnp: { version: 3, measurement: 'm', reported_tcb: 7 } }))).sevsnp?.reported_tcb).toBe(7);
    expect(v(tok(hdr(), pl({ sevsnp: { version: 3, measurement: 'm', reported_tcb: 'abc' } }))).sevsnp?.reported_tcb).toBe('abc');
    expect(v(tok(hdr(), pl({ sevsnp: { version: 3, measurement: 'm', reported_tcb: true } }))).sevsnp).toStrictEqual({ version: 3, measurement: 'm' });
    expect(v(tok(hdr(), pl({ sevsnp: { version: 3, measurement: 'm', reported_tcb: { bootloader: 1, tee: 2, snp: 3, microcode: 4, junk: 9 } } }))).sevsnp?.reported_tcb).toStrictEqual({ bootloader: 1, tee: 2, snp: 3, microcode: 4 });
    expect(v(tok(hdr(), pl({ sevsnp: { version: 3, measurement: 'm', reported_tcb: { bootloader: '1', tee: '2', snp: '3', microcode: '4' } } }))).sevsnp?.reported_tcb).toStrictEqual({});
    expect(v(tok(hdr(), pl({ sevsnp: { version: 3, measurement: 'm', reported_tcb: { snp: 3 } } }))).sevsnp?.reported_tcb).toStrictEqual({ snp: 3 });
  });
});

describe('verifyFreshness', () => {
  const claims = (over: Partial<EatClaims> = {}): EatClaims => ({ iss: 'I', iat: 1000, eat_nonce: 'abc', ...over });
  const NOW = 1_000_000 + 5000; // iat 1000 s = 1_000_000 ms
  const f = (c: EatClaims, o: Record<string, unknown> = {}) => verifyFreshness(c, { expectedNonce: 'abc', maxAgeMs: 10_000, now: NOW, ...o } as never);
  it('gates in order with exact reasons', () => {
    expect(f(claims())).toEqual({ ok: true });
    expect(f(claims(), { expectedNonce: '' })).toEqual({ ok: false, reason: 'no expected (server-issued) nonce supplied (fail closed)' });
    expect(f(claims(), { expectedNonce: 5 })).toEqual({ ok: false, reason: 'no expected (server-issued) nonce supplied (fail closed)' });
    expect(f(claims({ eat_nonce: undefined }))).toEqual({ ok: false, reason: 'EAT carries no eat_nonce — cannot establish freshness (replayable)' });
    expect(f(claims({ eat_nonce: '' }))).toEqual({ ok: false, reason: 'EAT carries no eat_nonce — cannot establish freshness (replayable)' });
    expect(f(claims({ eat_nonce: 5 as never }))).toEqual({ ok: false, reason: 'EAT carries no eat_nonce — cannot establish freshness (replayable)' });
    const mism = { ok: false, reason: 'eat_nonce does not match the server-issued challenge (replayed or relayed evidence)' };
    expect(f(claims({ eat_nonce: 'abd' }))).toEqual(mism);
    expect(f(claims({ eat_nonce: 'abcd' }))).toEqual(mism);
    expect(f(claims({ eat_nonce: 'ab' }))).toEqual(mism);
    expect(f(claims({ iat: '1' as never }))).toEqual({ ok: false, reason: 'EAT has no valid iat (cannot establish age)' });
    expect(f(claims({ iat: Number.NaN }))).toEqual({ ok: false, reason: 'EAT has no valid iat (cannot establish age)' });
    expect(f(claims({ iat: Number.POSITIVE_INFINITY }))).toEqual({ ok: false, reason: 'EAT has no valid iat (cannot establish age)' });
    for (const m of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) expect(f(claims(), { maxAgeMs: m }), String(m)).toEqual({ ok: false, reason: 'invalid maxAgeMs' });
    expect(f(claims(), { maxAgeMs: 1 }).ok).toBe(false);
  });
  it('future and stale boundaries with and without skew', () => {
    const iatMs = 1_000_000;
    expect(f(claims(), { now: iatMs })).toEqual({ ok: true });
    expect(f(claims(), { now: iatMs - 1 })).toEqual({ ok: false, reason: 'EAT iat is in the future' });
    expect(f(claims(), { now: iatMs - 5, clockSkewMs: 5 })).toEqual({ ok: true });
    expect(f(claims(), { now: iatMs - 6, clockSkewMs: 5 })).toEqual({ ok: false, reason: 'EAT iat is in the future' });
    expect(f(claims(), { now: iatMs + 10_000 })).toEqual({ ok: true });
    const stale = { ok: false, reason: 'EAT is stale (iat older than maxAgeMs) — expired/replayed attestation' };
    expect(f(claims(), { now: iatMs + 10_001 })).toEqual(stale);
    expect(f(claims(), { now: iatMs + 10_005, clockSkewMs: 5 })).toEqual({ ok: true });
    expect(f(claims(), { now: iatMs + 10_006, clockSkewMs: 5 })).toEqual(stale);
    // negative skew is clamped to zero
    expect(f(claims(), { now: iatMs - 1, clockSkewMs: -100 })).toEqual({ ok: false, reason: 'EAT iat is in the future' });
    expect(f(claims(), { now: iatMs + 10_001, clockSkewMs: -100 })).toEqual(stale);
  });
  it('the clock defaults to Date.now', () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000 + 1);
    expect(verifyFreshness(claims(), { expectedNonce: 'abc', maxAgeMs: 10 })).toEqual({ ok: true });
    vi.setSystemTime(1_000_000 + 100);
    expect(verifyFreshness(claims(), { expectedNonce: 'abc', maxAgeMs: 10 }).ok).toBe(false);
    for (const now of [Number.NaN, '5' as never, Number.POSITIVE_INFINITY]) expect(verifyFreshness(claims(), { expectedNonce: 'abc', maxAgeMs: 10, now }).ok, String(now)).toBe(false);
  });
});

describe('verifyChannelBinding', () => {
  const tls = sha('chan');
  const claims = (cnf?: EatCnf): EatClaims => ({ iss: 'I', iat: 1, ...(cnf ? { cnf } : {}) });
  it('nothing expected, nothing bound', () => {
    const none = { ok: false, reason: 'no expected channel binding supplied (fail closed)' };
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), {})).toEqual(none);
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { channelId: '' })).toEqual(none);
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { expectedCnf: {} })).toEqual(none);
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { expectedCnf: { tls_exporter: 5, jkt: 5 } as never })).toEqual(none);
    const unbound = { ok: false, reason: 'EAT carries no channel/key binding (cnf) — evidence is not bound to a live channel (RA-TLS)' };
    expect(verifyChannelBinding(claims(), { channelId: 'chan' })).toEqual(unbound);
    expect(verifyChannelBinding(claims({}), { channelId: 'chan' })).toEqual(unbound);
  });
  it('exporter and thumbprint are each compared', () => {
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { channelId: 'chan' })).toEqual({ ok: true });
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { channelId: 'other' })).toEqual({ ok: false, reason: 'TLS-exporter channel binding mismatch (evidence lifted to another channel?)' });
    expect(verifyChannelBinding(claims({ jkt: 'J' }), { channelId: 'chan' })).toEqual({ ok: false, reason: 'TLS-exporter channel binding mismatch (evidence lifted to another channel?)' });
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { expectedCnf: { tls_exporter: tls } })).toEqual({ ok: true });
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { expectedCnf: { tls_exporter: tls + 'x' } }).ok).toBe(false);
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { expectedCnf: { tls_exporter: tls.slice(1) } }).ok).toBe(false);
    expect(verifyChannelBinding(claims({ jkt: 'J' }), { expectedCnf: { jkt: 'J' } })).toEqual({ ok: true });
    expect(verifyChannelBinding(claims({ jkt: 'J' }), { expectedCnf: { jkt: 'K' } })).toEqual({ ok: false, reason: 'holder-key thumbprint (cnf.jkt) mismatch' });
    expect(verifyChannelBinding(claims({ jkt: 'J' }), { expectedCnf: { jkt: 'JJ' } })).toEqual({ ok: false, reason: 'holder-key thumbprint (cnf.jkt) mismatch' });
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { expectedCnf: { jkt: 'J' } })).toEqual({ ok: false, reason: 'holder-key thumbprint (cnf.jkt) mismatch' });
    expect(verifyChannelBinding(claims({ tls_exporter: tls, jkt: 'J' }), { channelId: 'chan', expectedCnf: { jkt: 'J' } })).toEqual({ ok: true });
    expect(verifyChannelBinding(claims({ tls_exporter: tls, jkt: 'J' }), { channelId: 'chan', expectedCnf: { jkt: 'K' } }).ok).toBe(false);
    expect(verifyChannelBinding(claims({ tls_exporter: tls, jkt: 'J' }), { channelId: 'other', expectedCnf: { jkt: 'J' } }).ok).toBe(false);
  });
  it('an explicit exporter overrides the one derived from channelId', () => {
    expect(verifyChannelBinding(claims({ tls_exporter: 'EXPLICIT' }), { channelId: 'chan', expectedCnf: { tls_exporter: 'EXPLICIT' } })).toEqual({ ok: true });
    expect(verifyChannelBinding(claims({ tls_exporter: tls }), { channelId: 'chan', expectedCnf: { tls_exporter: 'EXPLICIT' } }).ok).toBe(false);
  });
});

describe('appraise', () => {
  const M = 'ab'.repeat(48);
  const W = 'cd'.repeat(32);
  const measured = (o = {}) => ({ model_id: 'gpt', weights_digest: W, weights_measured: true, runtime_measurement: M, operator: 'op', ...o });
  const claims = (o: Partial<EatClaims> = {}): EatClaims => ({ iss: 'I', iat: 1, measured: measured(), sevsnp: { version: 3, measurement: M, reported_tcb: '100', guest_svn: 5, debug: false }, oemid: 'oem', ...o });
  const ap = (c: EatClaims, rv: ReferenceValues = {}, en = {}, ex = {}) => appraise(c, rv, en, ex);

  it('an empty policy is rejected, and each policy item alone counts as non-empty', () => {
    const empty = { tier: 'rejected', trustworthy: false, reasons: ['empty appraisal policy: no endorsements or reference values to appraise against (fail closed)'] };
    expect(ap(claims())).toEqual(empty);
    expect(ap(claims(), { measurements: [] }, { issuers: [] })).toEqual(empty);
    expect(ap(claims(), { requireMeasuredWeights: false, requireDebugDisabled: false })).toEqual(empty);
    expect(ap(claims(), { measurements: 'x' as never })).toEqual(empty);
    expect(ap(claims(), {}, { issuers: 'x' as never })).toEqual(empty);
    for (const rv of [{ measurements: [M] }, { models: ['gpt'] }, { weightsMeasurements: [W] }, { requireMeasuredWeights: true }, { minTcb: 1 }, { minGuestSvn: 0 }, { requireDebugDisabled: true }] as ReferenceValues[]) {
      expect(ap(claims(), rv).reasons, JSON.stringify(rv)).not.toEqual(empty.reasons);
    }
    for (const en of [{ issuers: ['I'] }, { oemids: ['oem'] }, { operators: ['op'] }]) expect(ap(claims(), {}, en).reasons, JSON.stringify(en)).not.toEqual(empty.reasons);
  });
  it('an empty list in one policy slot never counts as a policy and never filters', () => {
    const empty = ['empty appraisal policy: no endorsements or reference values to appraise against (fail closed)'];
    const slots: [string, ReferenceValues, Record<string, unknown>][] = [
      ['measurements', { measurements: [] }, {}], ['models', { models: [] }, {}], ['weightsMeasurements', { weightsMeasurements: [] }, {}],
      ['issuers', {}, { issuers: [] }], ['oemids', {}, { oemids: [] }], ['operators', {}, { operators: [] }],
    ];
    for (const [name, rv, en] of slots) expect(ap(claims(), rv, en).reasons, name).toEqual(empty);
    // beside a real policy item the empty list is skipped, not enforced
    const other: ReferenceValues = { minGuestSvn: 0 };
    for (const [name, rv, en] of slots) {
      const r = ap(claims({ measured: undefined, oemid: undefined, iss: 'unlisted', sevsnp: { version: 3, measurement: M, guest_svn: 1 } }), { ...other, ...rv }, en);
      expect(r, name).toEqual({ tier: 'affirming', trustworthy: true, reasons: ['guest_svn at or above reference minimum'] });
    }
  });
  it('a non-string oemid never matches even a (mistyped) numeric endorsement', () => {
    expect(ap(claims({ oemid: 5 as never }), {}, { oemids: [5 as never] })).toEqual({ tier: 'rejected', trustworthy: false, reasons: ['oemid absent or not endorsed (fail closed)'] });
  });
  it('the weights digest falls back to a weights measurement entry when the identity digest is empty', () => {
    const c: EatClaims = { iss: 'I', iat: 1, measured: measured({ weights_digest: '' }), measurements: [{ type: 'weights', value: W }] };
    expect(ap(c, { weightsMeasurements: [W] }).reasons).toEqual(['weights measurement matches a reference value']);
  });
  it('endorsements', () => {
    expect(ap(claims(), {}, { issuers: ['I'] })).toEqual({ tier: 'affirming', trustworthy: true, reasons: ['issuer endorsed'] });
    expect(ap(claims(), {}, { issuers: ['X'] })).toEqual({ tier: 'rejected', trustworthy: false, reasons: ['issuer I is not an endorsed attester'] });
    expect(ap(claims(), {}, { oemids: ['oem'] }).reasons).toEqual(['oemid endorsed']);
    expect(ap(claims(), {}, { oemids: ['x'] })).toEqual({ tier: 'rejected', trustworthy: false, reasons: ['oemid absent or not endorsed (fail closed)'] });
    expect(ap(claims({ oemid: undefined }), {}, { oemids: ['oem'] }).tier).toBe('rejected');
    expect(ap(claims({ oemid: 5 as never }), {}, { oemids: ['5'] }).tier).toBe('rejected');
    expect(ap(claims(), {}, { operators: ['op'] }).reasons).toEqual(['operator endorsed']);
    const op = { tier: 'rejected', trustworthy: false, reasons: ['hardware operator absent or not endorsed (fail closed)'] };
    expect(ap(claims(), {}, { operators: ['x'] })).toEqual(op);
    expect(ap(claims({ measured: undefined }), {}, { operators: ['op'] })).toEqual(op);
    expect(ap(claims({ measured: measured({ operator: '' }) }), {}, { operators: [''] })).toEqual(op);
    expect(ap(claims(), {}, { issuers: ['I'], oemids: ['oem'], operators: ['op'] }).reasons).toEqual(['issuer endorsed', 'oemid endorsed', 'operator endorsed']);
    // a failing endorsement carries the reasons of those that passed before it
    expect(ap(claims(), {}, { issuers: ['I'], oemids: ['x'] }).reasons).toEqual(['issuer endorsed', 'oemid absent or not endorsed (fail closed)']);
  });
  it('launch measurement', () => {
    expect(ap(claims(), { measurements: [M] })).toEqual({ tier: 'affirming', trustworthy: true, reasons: ['launch measurement matches a reference value'] });
    expect(ap(claims(), { measurements: [M.toUpperCase()] }).tier).toBe('affirming');
    expect(ap(claims({ measured: measured({ runtime_measurement: M.toUpperCase() }) }), { measurements: [M] }).tier).toBe('affirming');
    expect(ap(claims(), { measurements: ['ff'.repeat(48)] })).toEqual({ tier: 'contraindicated', trustworthy: false, reasons: ['launch measurement not in reference values'] });
    expect(ap(claims(), { measurements: ['ff', M] }).tier).toBe('affirming');
    const none = { tier: 'rejected', trustworthy: false, reasons: ['no launch measurement in evidence to compare against reference values (fail closed)'] };
    expect(ap({ iss: 'I', iat: 1 }, { measurements: [M] })).toEqual(none);
    expect(ap({ iss: 'I', iat: 1, measured: measured({ runtime_measurement: '' }) }, { measurements: [M] })).toEqual(none);
    // precedence: measured identity, then sevsnp block, then a launch / measurement entry
    expect(ap({ iss: 'I', iat: 1, measured: measured({ runtime_measurement: '11' }), sevsnp: { version: 3, measurement: M } }, { measurements: ['11'] }).tier).toBe('affirming');
    expect(ap({ iss: 'I', iat: 1, measured: measured({ runtime_measurement: '11' }), sevsnp: { version: 3, measurement: M } }, { measurements: [M] }).tier).toBe('contraindicated');
    expect(ap({ iss: 'I', iat: 1, sevsnp: { version: 3, measurement: M }, measurements: [{ type: 'launch', value: '22' }] }, { measurements: [M] }).tier).toBe('affirming');
    expect(ap({ iss: 'I', iat: 1, measurements: [{ type: 'weights', value: '33' }, { type: 'launch', value: '22' }] }, { measurements: ['22'] }).tier).toBe('affirming');
    expect(ap({ iss: 'I', iat: 1, measurements: [{ type: 'measurement', value: '44' }] }, { measurements: ['44'] }).tier).toBe('affirming');
    expect(ap({ iss: 'I', iat: 1, measurements: [{ type: 'runtime', value: '44' }] }, { measurements: ['44'] }).tier).toBe('rejected');
    expect(ap({ iss: 'I', iat: 1, sevsnp: { version: 3, measurement: 5 as never } }, { measurements: ['5'] }).tier).toBe('rejected');
    expect(ap({ iss: 'I', iat: 1, measured: { ...measured(), runtime_measurement: 5 as never }, sevsnp: { version: 3, measurement: M } }, { measurements: [M] }).tier).toBe('affirming');
  });
  it('model id', () => {
    expect(ap(claims(), { models: ['gpt'] }).reasons).toEqual(['model id matches a reference value']);
    expect(ap(claims(), { models: ['other'] })).toEqual({ tier: 'contraindicated', trustworthy: false, reasons: ['model id not in reference values (model swap?)'] });
    const none = { tier: 'rejected', trustworthy: false, reasons: ['no model id in evidence (fail closed)'] };
    expect(ap(claims({ measured: undefined }), { models: ['gpt'] })).toEqual(none);
    expect(ap(claims({ measured: measured({ model_id: '' }) }), { models: [''] })).toEqual(none);
    expect(ap(claims({ measured: measured({ model_id: 5 }) }), { models: ['5'] })).toEqual(none);
  });
  it('weights', () => {
    expect(ap(claims(), { requireMeasuredWeights: true }).reasons).toEqual(['weights digest is hardware-measured']);
    const hostAsserted = { tier: 'contraindicated', trustworthy: false, reasons: ['weights digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)'] };
    expect(ap(claims({ measured: measured({ weights_measured: false }) }), { requireMeasuredWeights: true })).toEqual(hostAsserted);
    expect(ap(claims({ measured: measured({ weights_measured: undefined }) }), { requireMeasuredWeights: true })).toEqual(hostAsserted);
    expect(ap(claims({ measured: undefined }), { requireMeasuredWeights: true })).toEqual(hostAsserted);
    expect(ap(claims({ measured: measured({ weights_measured: false }) }), { requireMeasuredWeights: false, models: ['gpt'] }).tier).toBe('affirming');
    expect(ap(claims(), { weightsMeasurements: [W] }).reasons).toEqual(['weights measurement matches a reference value']);
    expect(ap(claims(), { weightsMeasurements: [W.toUpperCase()] }).tier).toBe('affirming');
    expect(ap(claims({ measured: measured({ weights_digest: W.toUpperCase() }) }), { weightsMeasurements: [W] }).tier).toBe('affirming');
    expect(ap(claims(), { weightsMeasurements: ['00'] })).toEqual({ tier: 'contraindicated', trustworthy: false, reasons: ['weights measurement not in reference values (model swap / fine-tune?)'] });
    const none = { tier: 'rejected', trustworthy: false, reasons: ['no measured-weights digest in evidence (fail closed)'] };
    expect(ap({ iss: 'I', iat: 1 }, { weightsMeasurements: [W] })).toEqual(none);
    expect(ap(claims({ measured: measured({ weights_digest: '' }) }), { weightsMeasurements: [W] })).toEqual(none);
    expect(ap({ iss: 'I', iat: 1, measurements: [{ type: 'weights', value: W }] }, { weightsMeasurements: [W] }).tier).toBe('affirming');
    expect(ap({ iss: 'I', iat: 1, measurements: [{ type: 'weights', value: '' }] }, { weightsMeasurements: [W] })).toEqual(none);
    expect(ap({ iss: 'I', iat: 1, measurements: [{ type: 'launch', value: W }] }, { weightsMeasurements: [W] })).toEqual(none);
    expect(ap({ iss: 'I', iat: 1, measured: { ...measured(), weights_digest: 5 as never }, measurements: [{ type: 'weights', value: W }] }, { weightsMeasurements: [W] }).tier).toBe('affirming');
  });
  it('minimum TCB: shapes, packing order and boundaries', () => {
    const tcb = (t: unknown): EatClaims => claims({ sevsnp: { version: 3, measurement: M, reported_tcb: t as never } });
    const rv = (t: unknown): ReferenceValues => ({ minTcb: t as never });
    expect(ap(tcb('100'), rv('100')).reasons).toEqual(['TCB at or above reference minimum']);
    expect(ap(tcb('100'), rv('101'))).toEqual({ tier: 'contraindicated', trustworthy: false, reasons: ['reported TCB is below the reference minimum (downgrade / rollback)'] });
    expect(ap(tcb('101'), rv('100')).tier).toBe('affirming');
    expect(ap(tcb(100), rv(100)).tier).toBe('affirming');
    expect(ap(tcb(99), rv('100')).tier).toBe('contraindicated');
    expect(ap(tcb(100.9), rv(100)).tier).toBe('affirming');
    expect(ap(tcb(100.9), rv(101)).tier).toBe('contraindicated');
    expect(ap(tcb(' 100 '), rv('100')).tier).toBe('affirming');
    expect(ap(tcb('0'), rv(0)).tier).toBe('affirming');
    expect(ap(tcb(0), rv('0')).tier).toBe('affirming');
    const unknownMin = { tier: 'rejected', trustworthy: false, reasons: ['reference minTcb is not a comparable TCB version'] };
    for (const t of [-1, Number.NaN, Number.POSITIVE_INFINITY, 'abc', '1.5', '-1', '', '0x10', { snp: 256 }, { tee: -1 }, { bootloader: 1.5 }, { microcode: 300 }]) {
      expect(ap(tcb('100'), rv(t)), JSON.stringify(t)).toEqual(unknownMin);
    }
    const unknownEv = { tier: 'rejected', trustworthy: false, reasons: ['evidence TCB version is absent or an unknown format — failing closed (see 2025-10-27 GCP firmware drift)'] };
    for (const t of [undefined, -1, 'abc', '1.5', { snp: 256 }, { tee: 1.5 }, { bootloader: 256 }, { microcode: -1 }]) {
      expect(ap(tcb(t), rv(1)), JSON.stringify(t)).toEqual(unknownEv);
    }
    expect(ap(claims({ sevsnp: undefined }), rv(1))).toEqual(unknownEv);
    // component packing: bootloader | tee << 8 | snp << 48 | microcode << 56
    const order = [{ bootloader: 1 }, { bootloader: 255 }, { tee: 1 }, { tee: 255 }, { snp: 1 }, { snp: 255 }, { microcode: 1 }, { microcode: 255 }];
    for (let i = 0; i < order.length; i++) {
      for (let j = 0; j < order.length; j++) {
        const lo = order[i] as object;
        const hi = order[j] as object;
        const w = (o: object) => {
          const x = o as Record<string, number>;
          return (BigInt(x.bootloader ?? 0)) | (BigInt(x.tee ?? 0) << 8n) | (BigInt(x.snp ?? 0) << 48n) | (BigInt(x.microcode ?? 0) << 56n);
        };
        const want = w(lo) >= w(hi) ? 'affirming' : 'contraindicated';
        expect(ap(tcb(lo), rv(hi)).tier, `${JSON.stringify(lo)} vs ${JSON.stringify(hi)}`).toBe(want);
      }
    }
    expect(ap(tcb({ bootloader: 255, tee: 255, snp: 255, microcode: 255 }), rv({ bootloader: 255, tee: 255, snp: 255, microcode: 255 })).tier).toBe('affirming');
    expect(ap(tcb({}), rv({})).tier).toBe('affirming');
    expect(ap(tcb({ bootloader: 3, tee: 0, snp: 20, microcode: 210 }), rv({ bootloader: 3, tee: 0, snp: 20, microcode: 211 })).tier).toBe('contraindicated');
    // a decimal string and its structured twin compare equal
    const packed = ((3n) | (0n << 8n) | (20n << 48n) | (210n << 56n)).toString();
    expect(ap(tcb(packed), rv({ bootloader: 3, snp: 20, microcode: 210 })).tier).toBe('affirming');
    expect(ap(tcb({ bootloader: 3, snp: 20, microcode: 210 }), rv(packed)).tier).toBe('affirming');
    expect(ap(tcb((BigInt(packed) + 1n).toString()), rv({ bootloader: 3, snp: 20, microcode: 210 })).tier).toBe('affirming');
    expect(ap(tcb((BigInt(packed) - 1n).toString()), rv({ bootloader: 3, snp: 20, microcode: 210 })).tier).toBe('contraindicated');
    expect(ap(tcb('99999999999999999999999999'), rv('99999999999999999999999998')).tier).toBe('affirming');
  });
  it('minimum guest SVN', () => {
    expect(ap(claims(), { minGuestSvn: 5 }).reasons).toEqual(['guest_svn at or above reference minimum']);
    expect(ap(claims(), { minGuestSvn: 6 })).toEqual({ tier: 'contraindicated', trustworthy: false, reasons: ['guest_svn 5 below reference minimum 6'] });
    expect(ap(claims(), { minGuestSvn: 0 }).tier).toBe('affirming');
    const none = { tier: 'rejected', trustworthy: false, reasons: ['guest_svn absent (fail closed)'] };
    expect(ap(claims({ sevsnp: { version: 3, measurement: M } }), { minGuestSvn: 0 })).toEqual(none);
    expect(ap(claims({ sevsnp: undefined }), { minGuestSvn: 0 })).toEqual(none);
    expect(ap(claims({ sevsnp: { version: 3, measurement: M, guest_svn: Number.NaN } }), { minGuestSvn: 0 })).toEqual(none);
    expect(ap(claims({ sevsnp: { version: 3, measurement: M, guest_svn: '5' as never } }), { minGuestSvn: 0 })).toEqual(none);
  });
  it('debug status', () => {
    const rv: ReferenceValues = { requireDebugDisabled: true };
    expect(ap(claims(), rv).reasons).toEqual(['debug disabled']);
    for (const d of ['disabled', 'disabled-since-boot', 'disabled-permanently', 'disabled-fully-and-permanently'] as const) expect(ap(claims({ dbgstat: d, sevsnp: undefined }), rv).tier, d).toBe('affirming');
    const on = { tier: 'contraindicated', trustworthy: false, reasons: ['debug is enabled (host can inspect the guest — no confidentiality)'] };
    expect(ap(claims({ dbgstat: 'enabled' }), rv)).toEqual(on);
    expect(ap(claims({ dbgstat: 'enabled', sevsnp: { version: 3, measurement: M, debug: false } }), rv)).toEqual(on);
    expect(ap(claims({ sevsnp: { version: 3, measurement: M, debug: true } }), rv)).toEqual(on);
    expect(ap(claims({ dbgstat: 'disabled', sevsnp: { version: 3, measurement: M, debug: true } }), rv).tier).toBe('affirming');
    const unknown = { tier: 'rejected', trustworthy: false, reasons: ['debug status unknown — failing closed'] };
    expect(ap(claims({ sevsnp: { version: 3, measurement: M } }), rv)).toEqual(unknown);
    expect(ap(claims({ sevsnp: undefined }), rv)).toEqual(unknown);
    expect(ap(claims({ sevsnp: { version: 3, measurement: M, debug: 0 as never } }), rv)).toEqual(unknown);
    expect(ap(claims({ dbgstat: 'enabled' }), { requireDebugDisabled: false, models: ['gpt'] }).tier).toBe('affirming');
  });
  it('reason accumulation and the final tier', () => {
    const all = ap(claims(), { measurements: [M], models: ['gpt'], requireMeasuredWeights: true, weightsMeasurements: [W], minTcb: '100', minGuestSvn: 5, requireDebugDisabled: true }, { issuers: ['I'], oemids: ['oem'], operators: ['op'] });
    expect(all).toEqual({
      tier: 'affirming', trustworthy: true,
      reasons: [
        'issuer endorsed', 'oemid endorsed', 'operator endorsed', 'launch measurement matches a reference value', 'model id matches a reference value', 'weights digest is hardware-measured',
        'weights measurement matches a reference value', 'TCB at or above reference minimum', 'guest_svn at or above reference minimum', 'debug disabled',
      ],
    });
    const degraded = ap(claims({ sevsnp: { version: 3, measurement: M, degraded: true } }), { measurements: [M] });
    expect(degraded).toEqual({ tier: 'warning', trustworthy: true, reasons: ['launch measurement matches a reference value', 'evidence came from a degraded (version-tolerant) parse — review'] });
    expect(ap(claims({ sevsnp: { version: 3, measurement: M, degraded: false } }), { measurements: [M] }).tier).toBe('affirming');
    expect(ap(claims({ sevsnp: { version: 3, measurement: M, degraded: true } }), { measurements: [M] }, {}, { hardwareVerified: true }).tier).toBe('warning');
    const hw = ap(claims(), { measurements: [M] }, {}, { hardwareVerified: true });
    expect(hw).toEqual({
      tier: 'affirming-hw-rooted', trustworthy: true,
      reasons: ['launch measurement matches a reference value', `AMD SEV-SNP report signature + VCEK→ASK→ARK chain verified — ${AMD_SEV_SNP_HARDWARE_ROOT_LABEL}`],
    });
    expect(ap(claims(), { measurements: [M] }, {}, { hardwareVerified: true, hardwareRootLabel: 'my-root' }).reasons[1]).toBe('AMD SEV-SNP report signature + VCEK→ASK→ARK chain verified — my-root');
    expect(ap(claims(), { measurements: [M] }, {}, { hardwareVerified: false }).tier).toBe('affirming');
    expect(ap(claims(), { measurements: [M] }, {}, { hardwareVerified: 1 as never }).tier).toBe('affirming');
  });
  it('trustworthy follows the tier', () => {
    expect(ap(claims(), { measurements: ['ff'] }).trustworthy).toBe(false);
    expect(ap(claims(), { measurements: [M] }).trustworthy).toBe(true);
    expect(ap(claims({ sevsnp: undefined }), { minGuestSvn: 0 }).trustworthy).toBe(false);
  });
});

describe('size limit of an accepted EAT', () => {
  it('tokens beyond the 64 KiB default but within 1 MiB verify', () => {
    const k = generateEatKeyPair();
    const t = buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'c', now: 5000, oemid: 'x'.repeat(100_000) });
    expect(t.length).toBeGreaterThan(65_536);
    expect(verifyEAT(t, k.publicKey).oemid?.length).toBe(100_000);
    const huge = buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'c', now: 5000, oemid: 'x'.repeat(1_100_000) });
    expect(() => verifyEAT(huge, k.publicKey)).toThrow(/^EAT invalid: /);
  });
});

describe('verifyFreshAttestedEAT pipeline', () => {
  const k = generateEatKeyPair();
  const NOW = 1_700_000_000_000;
  const M = 'ab'.repeat(48);
  const build = (o: Record<string, unknown> = {}) =>
    buildEAT({ issuer: 'I', key: k.privateKey, nonce: 'N', channelId: 'chan', now: NOW, measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: M, operator: 'op' }, ...o });
  const run = (eat: string, o: Record<string, unknown> = {}) =>
    verifyFreshAttestedEAT(eat, { verifyKey: k.publicKey, nonce: 'N', channelId: 'chan', policy: { referenceValues: { measurements: [M] } }, now: NOW + 1000, ...o } as never);
  it('success reasons in order, with the claims', async () => {
    const r = await run(build());
    expect(r.ok).toBe(true);
    expect(r.tier).toBe('affirming');
    expect(r.reasons).toEqual(['signature + typ/iss verified', 'fresh (nonce + iat within window)', 'channel-bound (cnf matches live channel)', 'launch measurement matches a reference value']);
    expect(r.claims?.iss).toBe('I');
  });
  it('signature gate', async () => {
    const r = await run(build(), { verifyKey: generateEatKeyPair().publicKey });
    expect(r).toEqual({ ok: false, reasons: ['EAT signature/claims invalid: EAT invalid: signature does not verify'] });
    expect((await run(build(), { issuer: 'X' })).reasons).toEqual(['EAT signature/claims invalid: EAT invalid: iss I is not an accepted issuer']);
    expect((await run(build(), { issuer: ['X', 'I'] })).ok).toBe(true);
    expect((await run(build(), { algorithms: ['ES256'] })).reasons).toEqual(['EAT signature/claims invalid: EAT invalid: alg EdDSA not in the allowed set']);
    expect((await run(build(), { typ: 'other+jwt' })).reasons).toEqual(['EAT signature/claims invalid: EAT invalid: typ eat+jwt is not other+jwt']);
    expect((await run(build(), { typ: 'other+jwt', requireTyp: false })).ok).toBe(true);
    expect((await run(build(), { requireTyp: true })).ok).toBe(true);
    expect((await run(build(), { typ: undefined, issuer: undefined, algorithms: undefined, requireTyp: undefined })).ok).toBe(true);
  });
  it('freshness gate: nonce, age, skew and default window', async () => {
    const r = await run(build(), { nonce: 'other' });
    expect(r.ok).toBe(false);
    expect(r.reasons).toEqual(['signature + typ/iss verified', 'eat_nonce does not match the server-issued challenge (replayed or relayed evidence)']);
    expect(r.claims?.iss).toBe('I');
    expect(r.tier).toBeUndefined();
    expect((await run(build(), { now: NOW + DEFAULT_MAX_AGE_MS })).ok).toBe(true);
    expect((await run(build(), { now: NOW + DEFAULT_MAX_AGE_MS + 1 })).reasons[1]).toBe('EAT is stale (iat older than maxAgeMs) — expired/replayed attestation');
    expect((await run(build(), { maxAgeMs: 500 })).reasons[1]).toBe('EAT is stale (iat older than maxAgeMs) — expired/replayed attestation');
    expect((await run(build(), { maxAgeMs: 1000 })).ok).toBe(true);
    expect((await run(build(), { now: NOW - 3000 })).reasons[1]).toBe('EAT iat is in the future');
    expect((await run(build(), { now: NOW - 3000, clockSkewMs: 3000 })).ok).toBe(true);
    expect((await run(build(), { now: NOW - 3001, clockSkewMs: 3000 })).reasons[1]).toBe('EAT iat is in the future');
    vi.useFakeTimers();
    vi.setSystemTime(NOW + 10);
    expect((await run(build(), { now: undefined })).ok).toBe(true);
    vi.setSystemTime(NOW + 10 * DEFAULT_MAX_AGE_MS);
    expect((await run(build(), { now: undefined })).ok).toBe(false);
    expect((await run(build(), { now: Number.NaN })).ok).toBe(false);
  });
  it('channel gate: id, raw cnf, neither', async () => {
    expect((await run(build(), { channelId: 'other' })).reasons[2]).toBe('TLS-exporter channel binding mismatch (evidence lifted to another channel?)');
    expect((await run(build(), { channelId: undefined })).reasons[2]).toBe('no expected channel binding supplied (fail closed)');
    expect((await run(build(), { channelId: undefined, channelBinding: deriveChannelCnf('chan') })).ok).toBe(true);
    expect((await run(build(), { channelId: undefined, channelBinding: { tls_exporter: 'x' } })).reasons[2]).toBe('TLS-exporter channel binding mismatch (evidence lifted to another channel?)');
    expect((await run(build({ channelBinding: { jkt: 'J' }, channelId: undefined }), { channelId: undefined, channelBinding: { jkt: 'J' } })).ok).toBe(true);
    const failed = await run(build(), { channelId: 'other' });
    expect(failed.reasons.length).toBe(3);
    expect(failed.ok).toBe(false);
  });
  it('appraisal gate: tier, trust and policy defaults', async () => {
    const r = await run(build(), { policy: { referenceValues: { measurements: ['ff'] } } });
    expect(r.ok).toBe(false);
    expect(r.tier).toBe('contraindicated');
    expect(r.reasons[3]).toBe('launch measurement not in reference values');
    expect((await run(build(), { policy: {} })).tier).toBe('rejected');
    expect((await run(build(), { policy: { endorsements: { issuers: ['I'] } } })).reasons[3]).toBe('issuer endorsed');
    expect((await run(build(), { policy: { endorsements: { issuers: ['Z'] } } })).tier).toBe('rejected');
  });
  it('hardware verification failure is contraindicated with the cause', async () => {
    const r = await run(build(), { amd: { rawReport: new Uint8Array(10), vcek: new Uint8Array(1), ask: new Uint8Array(1), ark: new Uint8Array(1) } });
    expect(r.ok).toBe(false);
    expect(r.tier).toBe('contraindicated');
    expect(r.reasons.slice(0, 3)).toEqual(['signature + typ/iss verified', 'fresh (nonce + iat within window)', 'channel-bound (cnf matches live channel)']);
    expect(r.reasons[3]).toBe('AMD hardware root verification failed: exactly one of family or trustAnchorArkSpkiSha384 must be supplied (the ARK pin is never inferred)');
    expect(r.reasons.length).toBe(4);
    expect(r.claims?.iss).toBe('I');
    const fam = await run(build(), { amd: { rawReport: new Uint8Array(10), vcek: new Uint8Array(1), ask: new Uint8Array(1), ark: new Uint8Array(1), family: 'milan' } });
    expect(fam.reasons[3]).toMatch(/^AMD hardware root verification failed: /);
    expect(fam.reasons[3]).not.toContain('exactly one of');
    const pin = await run(build(), { amd: { rawReport: new Uint8Array(10), vcek: new Uint8Array(1), ask: new Uint8Array(1), ark: new Uint8Array(1), trustAnchorArkSpkiSha384: 'ab'.repeat(48) } });
    expect(pin.reasons[3]).not.toContain('exactly one of');
    const both = await run(build(), { amd: { rawReport: new Uint8Array(10), vcek: new Uint8Array(1), ask: new Uint8Array(1), ark: new Uint8Array(1), family: 'milan', trustAnchorArkSpkiSha384: 'ab'.repeat(48) } });
    expect(both.reasons[3]).toContain('exactly one of');
    void createPrivateKey;
    void generateKeyPairSync;
  });
});
