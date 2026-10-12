/** Mutation-kill suite for attest-allowlist.ts: every validation branch, boundary, message and check ordering. */
import { describe, expect, it } from 'vitest';
import {
  azureMaaPolicyFields,
  createAllowlistManifest,
  driverVersionSlotHex,
  gcpCsPolicyFields,
  intelDcapPolicyFields,
  nvidiaCcPolicyFields,
  projectAllowlist,
  revokeAllowlistEntry,
  sevSnpPolicyFields,
  signAllowlistManifest,
  verifyAllowlistDurable,
  verifyAllowlistManifest,
  type AllowlistEntry,
  type AllowlistIssuerKey,
  type AllowlistManifestBody,
  type SignedAllowlistManifest,
  type VerifyAllowlistResult,
} from './attest-allowlist';
import { createMemoryDurableKv, type DurableKv } from './durable-state';
import { generateKeyPair } from './keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from './pq';
import { b64u, hashCanonical } from './hash';

type Ok = Extract<VerifyAllowlistResult, { ok: true }>;
const T0 = Date.parse('2026-10-09T00:00:00Z');
const DAY = 86_400_000;
const H96 = (c: string) => c.repeat(96);
const H64 = (c: string) => c.repeat(64);
const URL1 = 'https://sharedwus.wus.attest.azure.net';

const ed = generateKeyPair();
const ed2 = generateKeyPair();
const ml = mlDsa65Keygen(new Uint8Array(32).fill(5));
const hyb = generateKeyPair();
const KEYS: Record<string, AllowlistIssuerKey> = {
  ops: { alg: 'ed25519', keys: { edPub: b64u(ed.publicKey) } },
  hyb: { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: b64u(hyb.publicKey), mlDsaPub: encodeMlDsaPublicKey(ml.publicKey) } },
};
const ent = (over: Partial<AllowlistEntry> = {}): AllowlistEntry => ({ kind: 'tdx-mrtd', value: H96('a'), label: 'L', ...over });
const body = (over: Partial<AllowlistManifestBody> = {}): AllowlistManifestBody => ({ version: 5, issuedAt: T0 - DAY, notBefore: T0 - DAY, expiresAt: T0 + 30 * DAY, entries: [ent()], ...over });
const signed = (b = body(), issuer = 'ops'): SignedAllowlistManifest => signAllowlistManifest(b, { issuer, alg: 'ed25519', secrets: { edSecret: ed.secretKey } });
const verify = (m: unknown, o: Partial<Parameters<typeof verifyAllowlistManifest>[1]> = {}) => verifyAllowlistManifest(m, { issuerKeys: KEYS, nowMs: T0, ...o });
const code = (r: VerifyAllowlistResult) => (r.ok ? 'ok' : r.code);
const reason = (r: VerifyAllowlistResult) => (r.ok ? 'ok' : r.reason);
const bad = (b: unknown, msg: string | RegExp) => expect(() => createAllowlistManifest(b as never)).toThrow(typeof msg === 'string' ? new TypeError(msg) : msg);
const E0 = (e: Partial<AllowlistEntry> | Record<string, unknown>) => body({ entries: [e as never] });

describe('parseBody: top-level structure', () => {
  const m = 'body must be an object with exactly version/issuedAt/notBefore/expiresAt/entries';
  it('refuses non-records and unknown keys', () => {
    for (const x of [null, undefined, [], 'x', 5]) bad(x, m);
    bad({ ...body(), extra: 1 }, m);
  });
  it('version must be a positive safe integer', () => {
    const v = 'version must be a positive integer';
    for (const version of ['1', 0, -1, 1.5, NaN, Number.MAX_SAFE_INTEGER + 1, undefined]) bad({ ...body(), version }, v);
    expect(createAllowlistManifest(body({ version: 1 })).version).toBe(1);
    expect(createAllowlistManifest(body({ version: Number.MAX_SAFE_INTEGER })).version).toBe(Number.MAX_SAFE_INTEGER);
  });
  it('times must be non-negative safe integers', () => {
    const m2 = 'issuedAt/notBefore/expiresAt must be integer epoch ms';
    for (const k of ['issuedAt', 'notBefore', 'expiresAt'] as const) {
      for (const val of [-1, 1.5, '5', undefined, NaN, Number.MAX_SAFE_INTEGER + 1]) bad({ ...body(), [k]: val }, m2);
    }
    expect(createAllowlistManifest({ version: 1, issuedAt: 0, notBefore: 0, expiresAt: 1, entries: [] })).toEqual({ version: 1, issuedAt: 0, notBefore: 0, expiresAt: 1, entries: [] });
  });
  it('window ordering', () => {
    bad(body({ notBefore: 100, expiresAt: 100, issuedAt: 50 }), 'notBefore must be before expiresAt');
    bad(body({ notBefore: 101, expiresAt: 100, issuedAt: 50 }), 'notBefore must be before expiresAt');
    expect(createAllowlistManifest(body({ notBefore: 99, expiresAt: 100, issuedAt: 100 })).issuedAt).toBe(100);
    bad(body({ notBefore: 50, expiresAt: 100, issuedAt: 101 }), 'issuedAt must not be after expiresAt');
  });
  it('entries bounded array', () => {
    const e = 'entries must be an array (bounded)';
    bad({ ...body(), entries: 'x' }, e);
    bad({ ...body(), entries: undefined }, e);
    bad({ ...body(), entries: {} }, e);
    const many = (n: number): AllowlistEntry[] => Array.from({ length: n }, (_, i) => ent({ value: i.toString(16).padStart(96, '0') }));
    expect(createAllowlistManifest(body({ entries: many(10_000) })).entries.length).toBe(10_000);
    bad(body({ entries: many(10_001) }), e);
  });
  it('output is a fresh canonical copy', () => {
    const input = body({ entries: [ent({ notAfter: undefined, revoked: undefined })] });
    const out = createAllowlistManifest(input);
    expect(out).toStrictEqual({ version: 5, issuedAt: T0 - DAY, notBefore: T0 - DAY, expiresAt: T0 + 30 * DAY, entries: [{ kind: 'tdx-mrtd', value: H96('a'), label: 'L' }] });
    expect(out.entries[0]).not.toBe(input.entries[0]);
  });
});

describe('parseBody: entries', () => {
  it('shape and index in the message', () => {
    for (const x of [null, [], 'x', 5]) bad(body({ entries: [ent(), x as never] }), 'entry 1: unexpected shape');
    bad(E0({ ...ent(), extra: 1 }), 'entry 0: unexpected shape');
    bad(body({ entries: [ent(), ent({ value: H96('b') }), { ...ent({ value: H96('c') }), z: 1 } as never] }), 'entry 2: unexpected shape');
  });
  it('kind', () => {
    for (const kind of ['nope', 5, undefined, null]) bad(E0({ ...ent(), kind }), 'entry 0: unknown kind');
    bad(E0({ ...ent(), kind: 'nope', label: '' }), 'entry 0: unknown kind'); // kind is checked before the label
  });
  it('value / label types, label bounds and control characters', () => {
    const t = 'entry 0: value and label must be strings';
    bad(E0({ ...ent(), value: 5 }), t);
    bad(E0({ ...ent(), label: 5 }), t);
    bad(E0({ ...ent(), label: undefined }), t);
    const l = 'entry 0: label must be 1..200 printable chars';
    bad(E0(ent({ label: '' })), l);
    bad(E0(ent({ label: 'x'.repeat(201) })), l);
    expect(createAllowlistManifest(E0(ent({ label: 'x'.repeat(200) }))).entries[0]!.label.length).toBe(200);
    expect(createAllowlistManifest(E0(ent({ label: 'x' }))).entries.length).toBe(1);
    for (const ch of ['\x00', '\x1f', '\x7f', '\n', '\t']) bad(E0(ent({ label: `a${ch}b` })), l);
    for (const ch of ['\x20', '\x7e', 'é', '\u0080']) expect(createAllowlistManifest(E0(ent({ label: `a${ch}b` }))).entries[0]!.label).toBe(`a${ch}b`);
    bad(E0({ ...ent({ label: '' }), value: 'zz' }), l); // label is checked before the value
  });
  it('96-hex kinds', () => {
    for (const kind of ['tdx-mrtd', 'tdx-rtmr', 'sev-snp-measurement', 'nvidia-measurement'] as const) {
      const msg = `entry 0: ${kind} must be 96 lowercase hex chars`;
      expect(createAllowlistManifest(E0(ent({ kind, value: H96('0') }))).entries.length).toBe(1);
      for (const value of [H96('A'), 'a'.repeat(95), 'a'.repeat(97), '', ` ${'a'.repeat(95)}`, `${'a'.repeat(95)}\n`, `${'a'.repeat(95)}g`, `x${H96('a')}`, `${H96('a')}x`]) bad(E0(ent({ kind, value })), msg);
    }
  });
  it('gcp-image-digest', () => {
    const msg = 'entry 0: gcp-image-digest must be sha256:<64 lowercase hex>';
    const k = 'gcp-image-digest' as const;
    expect(createAllowlistManifest(E0(ent({ kind: k, value: `sha256:${H64('f')}` }))).entries.length).toBe(1);
    for (const value of [H64('f'), `sha256:${H64('F')}`, `sha256:${'f'.repeat(63)}`, `sha256:${'f'.repeat(65)}`, `x sha256:${H64('f')}`, `sha256:${H64('f')}x`, `sha512:${H64('f')}`]) bad(E0(ent({ kind: k, value })), msg);
  });
  it('nvidia-driver-version', () => {
    const msg = 'entry 0: nvidia-driver-version must be a dotted version of at most 16 chars';
    const k = 'nvidia-driver-version' as const;
    for (const value of ['595.71.05', '1.2', '1.2.3', '1.2.3.4', '123456.123456.12', '0.0']) expect(createAllowlistManifest(E0(ent({ kind: k, value, label: 'd' }))).entries.length).toBe(1);
    for (const value of ['1', '', '1.2.3.4.5', '1234567.1', '1.1234567', '123456.123456.123', 'x1.2', '1.2x', '.1.2', '1.2.', '1..2', '1.2\n', 'a.b']) bad(E0(ent({ kind: k, value, label: 'd' })), msg);
  });
  it('maa kinds', () => {
    for (const kind of ['maa-chain-root-spki', 'maa-chain-intermediate-spki'] as const) {
      const msg = `entry 0: ${kind} must be 64 lowercase hex chars`;
      expect(createAllowlistManifest(E0(ent({ kind, value: H64('0') }))).entries.length).toBe(1);
      for (const value of [H64('A'), 'a'.repeat(63), 'a'.repeat(65), `x${H64('a')}`, `${H64('a')}x`]) bad(E0(ent({ kind, value })), msg);
    }
    const k = 'maa-signing-spki' as const;
    const vmsg = 'entry 0: maa-signing-spki must be 64 lowercase hex chars';
    for (const value of [H64('A'), 'a'.repeat(63), 'a'.repeat(65), `x${H64('a')}`, `${H64('a')}x`]) bad(E0(ent({ kind: k, value, label: URL1 })), vmsg);
    bad(E0(ent({ kind: k, value: 'zz', label: 'not a url' })), vmsg); // value is checked before the label
    const lmsg = 'entry 0: maa-signing-spki label must be the https issuer URL (no path, no trailing slash)';
    for (const label of ['https://a', URL1, 'https://a.b-c.d:443', 'https://a1', 'https://1a', 'https://a:1', 'https://a:12345', 'https://x.y']) {
      expect(createAllowlistManifest(E0(ent({ kind: k, value: H64('a'), label }))).entries.length).toBe(1);
    }
    for (const label of ['http://a.com', 'https://', 'https://a.com/', 'https://a.com/x', 'https://A.com', 'https://.a.com', 'https://a-', 'https://-a', 'https://a.com:123456', 'https://a.com:', `x${URL1}`, `${URL1}x y`, 'https://a.com?x', 'a.com']) {
      bad(E0(ent({ kind: k, value: H64('a'), label })), lmsg);
    }
  });
  it('attest-corroboration', () => {
    const k = 'attest-corroboration' as const;
    const vmsg = 'entry 0: attest-corroboration must be a 64 lowercase hex evidence digest';
    for (const value of [H64('A'), 'a'.repeat(63), 'a'.repeat(65), `x${H64('a')}`, `${H64('a')}x`]) bad(E0(ent({ kind: k, value, label: 'vantages=3;method=m' })), vmsg);
    const lmsg = 'entry 0: attest-corroboration label must be vantages=<n>;method=<text>';
    for (const label of ['vantages=1;method=m', 'vantages=3;method=a b', 'vantages=999;method=m', `vantages=3;method=${'x'.repeat(150)}`, 'vantages=9;method=~', 'vantages=12;method= ']) {
      expect(createAllowlistManifest(E0(ent({ kind: k, value: H64('a'), label }))).entries.length).toBe(1);
    }
    for (const label of ['vantages=0;method=m', 'vantages=1000;method=m', 'vantages=03;method=m', 'vantages=;method=m', 'vantages=3;method=', `vantages=3;method=${'x'.repeat(151)}`, 'vantages=3;method=é', 'vantages=3', 'Vantages=3;method=m', 'xvantages=3;method=m', 'vantages=a;method=m', 'vantages=3;methodx=m', 'vantages=3 ;method=m']) {
      bad(E0(ent({ kind: k, value: H64('a'), label })), lmsg);
    }
  });
  it('notAfter / revoked', () => {
    const na = 'entry 0: notAfter must be integer epoch ms';
    for (const notAfter of [-1, 1.5, '5', null, NaN]) bad(E0({ ...ent(), notAfter }), na);
    expect(createAllowlistManifest(E0(ent({ notAfter: 0 }))).entries[0]).toStrictEqual({ kind: 'tdx-mrtd', value: H96('a'), label: 'L', notAfter: 0 });
    const rv = 'entry 0: revoked, when present, must be true';
    for (const revoked of [false, 'true', 1, null, 0]) bad(E0({ ...ent(), revoked }), rv);
    expect(createAllowlistManifest(E0(ent({ revoked: true }))).entries[0]).toStrictEqual({ kind: 'tdx-mrtd', value: H96('a'), label: 'L', revoked: true });
    expect(createAllowlistManifest(E0(ent({ notAfter: 7, revoked: true }))).entries[0]).toStrictEqual({ kind: 'tdx-mrtd', value: H96('a'), label: 'L', notAfter: 7, revoked: true });
    bad(E0({ ...ent(), notAfter: -1, revoked: false }), na); // notAfter before revoked
    bad(E0({ ...ent({ value: 'zz' }), notAfter: -1 }), /entry 0: tdx-mrtd must be 96/); // value before notAfter
  });
  it('duplicates: kind+value (label counts only for maa-signing-spki)', () => {
    bad(body({ entries: [ent(), ent({ label: 'other' })] }), 'entry 1: duplicate tdx-mrtd value');
    expect(createAllowlistManifest(body({ entries: [ent(), ent({ kind: 'tdx-rtmr' })] })).entries.length).toBe(2);
    expect(createAllowlistManifest(body({ entries: [ent(), ent({ value: H96('b') })] })).entries.length).toBe(2);
    const m = (label: string) => ent({ kind: 'maa-signing-spki', value: H64('a'), label });
    expect(createAllowlistManifest(body({ entries: [m(URL1), m('https://other.example')] })).entries.length).toBe(2);
    bad(body({ entries: [m(URL1), m(URL1)] }), 'entry 1: duplicate maa-signing-spki value');
    expect(createAllowlistManifest(body({ entries: [ent({ kind: 'maa-chain-root-spki', value: H64('a') }), ent({ kind: 'maa-chain-intermediate-spki', value: H64('a') })] })).entries.length).toBe(2);
    // a tombstone for the same value is also a duplicate
    bad(body({ entries: [ent(), ent({ revoked: true })] }), 'entry 1: duplicate tdx-mrtd value');
  });
});

describe('verifyAllowlistManifest: structure checks and their order', () => {
  it('manifest shape', () => {
    const m = 'manifest has an unexpected shape';
    for (const x of [null, undefined, [], 'x', 5]) expect([code(verify(x)), reason(verify(x))]).toEqual(['malformed', m]);
    expect(reason(verify({ ...signed(), extra: 1 }))).toBe(m);
    expect(code(verify(signed()))).toBe('ok');
  });
  it('nowMs', () => {
    for (const nowMs of [T0 + 0.5, NaN, undefined, '5']) {
      const r = verifyAllowlistManifest(signed(), { issuerKeys: KEYS, nowMs: nowMs as never });
      expect([code(r), reason(r)]).toEqual(['malformed', 'nowMs must be an integer']);
    }
    const r = verifyAllowlistManifest(signed(), undefined as never);
    expect([code(r), reason(r)]).toEqual(['malformed', 'nowMs must be an integer']);
  });
  it('issuer / alg / sig / pq_sig typing', () => {
    const s = signed();
    for (const issuer of [5, '', 'x'.repeat(201), undefined]) expect([code(verify({ ...s, issuer })), reason(verify({ ...s, issuer }))]).toEqual(['malformed', 'issuer must be a string']);
    expect(code(verify({ ...s, issuer: 'x'.repeat(200) }))).toBe('unknown-issuer');
    for (const alg of [5, 'rsa', undefined, 'ED25519']) expect([code(verify({ ...s, alg })), reason(verify({ ...s, alg }))]).toEqual(['malformed', 'unknown signature alg']);
    for (const sig of [5, undefined, null]) expect([code(verify({ ...s, sig })), reason(verify({ ...s, sig }))]).toEqual(['malformed', 'sig must be a string']);
    for (const pq_sig of [5, null, {}]) expect([code(verify({ ...s, pq_sig })), reason(verify({ ...s, pq_sig }))]).toEqual(['malformed', 'pq_sig must be a string']);
    expect(reason(verify({ ...s, pq_sig: 'abc' }))).toBe('pq_sig presence does not match the suite');
    const h = signAllowlistManifest(body(), { issuer: 'hyb', alg: 'hybrid-ed25519-ml-dsa-65', secrets: { edSecret: hyb.secretKey, mlDsa: ml } });
    expect(code(verify(h))).toBe('ok');
    const { pq_sig: _p, ...noPq } = h;
    expect([code(verify(noPq)), reason(verify(noPq))]).toEqual(['malformed', 'pq_sig presence does not match the suite']);
  });
  it('a body error is reported verbatim as malformed, before issuer lookup', () => {
    const s = signed();
    const r = verify({ ...s, issuer: 'nobody', body: { ...s.body, version: 0 } });
    expect([code(r), reason(r)]).toEqual(['malformed', 'version must be a positive integer']);
    expect(reason(verify({ ...s, body: 5 }))).toMatch(/^body must be an object/);
  });
  it('issuer registry: unknown (incl. inherited names), alg mismatch, expiry', () => {
    const s = signed();
    expect([code(verify({ ...s, issuer: 'ghost' })), reason(verify({ ...s, issuer: 'ghost' }))]).toEqual(['unknown-issuer', "issuer 'ghost' is not registered"]);
    for (const issuer of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) expect(code(verify({ ...s, issuer }))).toBe('unknown-issuer');
    const h = signAllowlistManifest(body(), { issuer: 'ops', alg: 'hybrid-ed25519-ml-dsa-65', secrets: { edSecret: hyb.secretKey, mlDsa: ml } });
    const r = verify(h);
    expect([code(r), reason(r)]).toEqual(['alg-mismatch', "issuer is registered for 'ed25519', manifest claims 'hybrid-ed25519-ml-dsa-65'"]);
    const withExp = (notAfter: number) => ({ ops: { ...KEYS['ops']!, notAfter } });
    expect(code(verify(s, { issuerKeys: withExp(T0) }))).toBe('ok');
    const x = verify(s, { issuerKeys: withExp(T0 - 1) });
    expect([code(x), reason(x)]).toEqual(['issuer-expired', 'issuer key is past its notAfter']);
    expect(code(verify(s, { issuerKeys: { ops: { ...KEYS['ops']!, notAfter: 0 } } }))).toBe('issuer-expired');
  });
  it('signature verification precedes every policy check', () => {
    const s = signed();
    const forged = { ...s, body: { ...s.body, entries: [ent({ value: H96('b') })] } };
    const r = verify(forged, { nowMs: T0 + 400 * DAY, minVersion: 99, lastSeenVersion: 99 });
    expect([code(r), reason(r)]).toEqual(['bad-signature', 'signature does not verify under the registered issuer key']);
    const other = signAllowlistManifest(body(), { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ed2.secretKey } });
    expect(code(verify(other))).toBe('bad-signature');
    expect(code(verify({ ...s, sig: b64u(new Uint8Array(64)) }))).toBe('bad-signature');
  });
});

describe('verifyAllowlistManifest: policy boundaries', () => {
  const b = (o: Partial<AllowlistManifestBody>) => signed(body(o));
  it('not-yet-valid with skew (negative skew clamps to zero)', () => {
    const s = b({ notBefore: T0, issuedAt: T0 });
    expect(code(verify(s, { nowMs: T0 }))).toBe('ok');
    const r = verify(s, { nowMs: T0 - 1 });
    expect([code(r), reason(r)]).toEqual(['not-yet-valid', 'manifest is not yet valid']);
    expect(code(verify(s, { nowMs: T0 - 5, clockSkewMs: 5 }))).toBe('ok');
    expect(code(verify(s, { nowMs: T0 - 6, clockSkewMs: 5 }))).toBe('not-yet-valid');
    expect(code(verify(s, { nowMs: T0, clockSkewMs: -10 }))).toBe('ok');
    expect(code(verify(s, { nowMs: T0 - 1, clockSkewMs: -10 }))).toBe('not-yet-valid');
  });
  it('expiry with skew', () => {
    const s = b({ expiresAt: T0 + 1000 });
    expect(code(verify(s, { nowMs: T0 + 1000 }))).toBe('ok');
    const r = verify(s, { nowMs: T0 + 1001 });
    expect([code(r), reason(r)]).toEqual(['expired', 'manifest has expired']);
    expect(code(verify(s, { nowMs: T0 + 1005, clockSkewMs: 5 }))).toBe('ok');
    expect(code(verify(s, { nowMs: T0 + 1006, clockSkewMs: 5 }))).toBe('expired');
    expect(code(verify(s, { nowMs: T0 + 1000, clockSkewMs: -10 }))).toBe('ok');
    expect(code(verify(s, { nowMs: T0 + 1001, clockSkewMs: -10 }))).toBe('expired');
  });
  it('maxLifetimeMs', () => {
    const s = b({ notBefore: T0 - 100, issuedAt: T0 - 100, expiresAt: T0 + 100 });
    expect(code(verify(s, { maxLifetimeMs: 200 }))).toBe('ok');
    const r = verify(s, { maxLifetimeMs: 199 });
    expect([code(r), reason(r)]).toEqual(['lifetime-too-long', 'manifest lifetime exceeds maxLifetimeMs']);
    expect(code(verify(s, { maxLifetimeMs: 0 }))).toBe('lifetime-too-long');
    expect(code(verify(s))).toBe('ok');
  });
  it('minVersion', () => {
    const s = b({ version: 5 });
    expect(code(verify(s, { minVersion: 5 }))).toBe('ok');
    expect(code(verify(s, { minVersion: 1 }))).toBe('ok');
    const r = verify(s, { minVersion: 6 });
    expect([code(r), reason(r)]).toEqual(['below-min-version', 'version 5 < minVersion 6']);
  });
  it('rollback / conflict against the last seen version', () => {
    const s = b({ version: 5 });
    const dg = hashCanonical(s.body);
    expect(code(verify(s, { lastSeenVersion: 4 }))).toBe('ok');
    expect(code(verify(s, { lastSeenVersion: 5 }))).toBe('ok');
    expect(code(verify(s, { lastSeenVersion: 5, lastSeenDigest: dg }))).toBe('ok');
    expect(code(verify(s, { lastSeenVersion: 4, lastSeenDigest: 'other' }))).toBe('ok');
    const r = verify(s, { lastSeenVersion: 6 });
    expect([code(r), reason(r)]).toEqual(['rollback', 'version 5 is older than last seen 6']);
    const c = verify(s, { lastSeenVersion: 5, lastSeenDigest: 'x'.repeat(43) });
    expect([code(c), reason(c)]).toEqual(['conflict', 'same version as last seen but a different body']);
    // lastSeenDigest alone (without lastSeenVersion) is ignored
    expect(code(verify(s, { lastSeenDigest: 'x'.repeat(43) }))).toBe('ok');
  });
  it('checks fire in the documented order', () => {
    const s = b({ version: 1, notBefore: T0 + 10, issuedAt: T0 + 10, expiresAt: T0 + 20 + DAY });
    expect(code(verify(s, { maxLifetimeMs: 1, minVersion: 9, lastSeenVersion: 9 }))).toBe('not-yet-valid');
    const e = b({ version: 1, expiresAt: T0 - 1 });
    expect(code(verify(e, { maxLifetimeMs: 1, minVersion: 9, lastSeenVersion: 9 }))).toBe('expired');
    const l = b({ version: 1 });
    expect(code(verify(l, { maxLifetimeMs: 1, minVersion: 9, lastSeenVersion: 9 }))).toBe('lifetime-too-long');
    expect(code(verify(l, { minVersion: 9, lastSeenVersion: 9 }))).toBe('below-min-version');
    expect(code(verify(l, { lastSeenVersion: 9 }))).toBe('rollback');
  });
  it('ok result carries the parsed body, digest, issuer, alg and version', () => {
    const s = signed();
    const r = verify(s) as Ok;
    expect(r.ok).toBe(true);
    expect(r).toStrictEqual({ ok: true, body: s.body, issuer: 'ops', alg: 'ed25519', version: 5, digest: hashCanonical(s.body) });
  });
  it('internal failures are reported as malformed with the message', () => {
    const r = verifyAllowlistManifest(signed(), { issuerKeys: undefined as never, nowMs: T0 });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('malformed');
      expect(r.reason.length).toBeGreaterThan(5);
      expect(r.reason).not.toBe('verification error');
    }
  });
});

describe('verifyAllowlistDurable', () => {
  const dur = (m: unknown, kv: DurableKv, o: Partial<Parameters<typeof verifyAllowlistDurable>[1]> = {}) => verifyAllowlistDurable(m, { issuerKeys: KEYS, nowMs: T0, ...o }, kv);
  const hw = (b: AllowlistManifestBody) => ({ version: b.version, digest: hashCanonical(b) });
  it('issuer extraction', async () => {
    const kv = createMemoryDurableKv();
    for (const x of [null, [], 'x', 5, { issuer: 5 }, { issuer: 'x'.repeat(201) }]) {
      const r = await dur(x, kv);
      expect([code(r), reason(r)]).toEqual(['malformed', 'issuer must be a string']);
    }
    expect(code(await dur({ ...signed(), issuer: 'x'.repeat(200) }, kv))).toBe('unknown-issuer');
  });
  it('first accept stores the high-water mark; same / newer accepted; older and conflicting refused', async () => {
    const kv = createMemoryDurableKv();
    const m5 = signed(body({ version: 5 }));
    expect(code(await dur(m5, kv))).toBe('ok');
    expect(await kv.get('allowlist/ops')).toEqual(hw(m5.body));
    expect(code(await dur(m5, kv))).toBe('ok');
    const m6 = signed(body({ version: 6 }));
    expect(code(await dur(m6, kv))).toBe('ok');
    expect(await kv.get('allowlist/ops')).toEqual(hw(m6.body));
    const old = await dur(m5, kv);
    expect([code(old), reason(old)]).toEqual(['rollback', 'version 5 is older than last seen 6']);
    expect(await kv.get('allowlist/ops')).toEqual(hw(m6.body));
    const fork = signed(body({ version: 6, entries: [ent({ value: H96('b') })] }));
    const c = await dur(fork, kv);
    expect([code(c), reason(c)]).toEqual(['conflict', 'same version as last seen but a different body']);
    expect(await kv.get('allowlist/ops')).toEqual(hw(m6.body));
    // a failed verification does not touch the mark
    const kv2 = createMemoryDurableKv();
    expect(code(await dur({ ...m5, sig: b64u(new Uint8Array(64)) }, kv2))).toBe('bad-signature');
    expect(await kv2.get('allowlist/ops')).toBeUndefined();
  });
  it('a corrupt stored mark fails closed', async () => {
    const good = hw(signed().body);
    const corrupt: unknown[] = [null, 5, 'x', [], { version: '5', digest: good.digest }, { version: 5.5, digest: good.digest }, { version: 5 }, { version: 5, digest: 5 }, { version: 5, digest: 'A'.repeat(42) }, { version: 5, digest: 'A'.repeat(44) }, { version: 5, digest: `${'A'.repeat(42)}!` }, { version: Number.MAX_SAFE_INTEGER + 1, digest: good.digest }];
    for (const c of corrupt) {
      const kv = createMemoryDurableKv();
      await kv.set('allowlist/ops', c);
      const r = await dur(signed(), kv);
      expect([code(r), reason(r)]).toEqual(['malformed', 'persisted allowlist high-water mark is corrupt']);
    }
    for (const okv of [{ version: 0, digest: 'A'.repeat(43) }, { version: -3, digest: `${'a'.repeat(21)}-_${'9'.repeat(20)}` }]) {
      const kv = createMemoryDurableKv();
      await kv.set('allowlist/ops', okv);
      expect(code(await dur(signed(), kv))).toBe('ok');
    }
  });
  it('concurrent advancement is detected', async () => {
    const m = signed(body({ version: 5 }));
    const newer = { version: 6, digest: 'N'.repeat(43) };
    const kvNewer: DurableKv = {
      get: async () => undefined,
      set: async () => undefined,
      keys: async () => [],
      update: async (_k, fn) => fn(newer) ?? newer,
    };
    const r = await dur(m, kvNewer);
    expect([code(r), reason(r)]).toEqual(['rollback', 'a newer manifest was accepted concurrently']);
    const same = { version: 5, digest: 'N'.repeat(43) };
    const kvSame: DurableKv = { ...kvNewer, update: async () => same };
    const c = await dur(m, kvSame);
    expect([code(c), reason(c)]).toEqual(['conflict', 'same version as the stored high-water mark but a different body']);
    const kvCorrupt: DurableKv = { ...kvNewer, update: async (_k, fn) => fn('junk') ?? 'junk' };
    expect(reason(await dur(m, kvCorrupt))).toBe('a newer manifest was accepted concurrently');
    // the update callback: writes when nothing is stored / older is stored, leaves a newer or identical one
    const seen: unknown[] = [];
    const probe = (cur: unknown): DurableKv => ({ ...kvNewer, update: async (_k, fn) => (seen.push(fn(cur)), { version: 5, digest: hashCanonical(m.body) }) });
    await dur(m, probe(undefined));
    await dur(m, probe({ version: 4, digest: 'O'.repeat(43) }));
    await dur(m, probe({ version: 5, digest: hashCanonical(m.body) }));
    await dur(m, probe({ version: 6, digest: 'O'.repeat(43) }));
    expect(seen).toEqual([hw(m.body), hw(m.body), undefined, undefined]);
  });
  it('kv failures become malformed with the message (or a default)', async () => {
    const boom: DurableKv = { get: async () => { throw new Error('disk gone'); }, set: async () => undefined, update: async () => undefined, keys: async () => [] };
    const r = await dur(signed(), boom);
    expect([code(r), reason(r)]).toEqual(['malformed', 'disk gone']);
    const weird: DurableKv = { ...boom, get: async () => { throw 'str'; } };
    expect(reason(await dur(signed(), weird))).toBe('durable verification error');
  });
});

describe('sign / revoke / driver slot', () => {
  it('signAllowlistManifest validates, copies, and omits pq_sig for classical suites', () => {
    const s = signed();
    expect(Object.keys(s).sort()).toEqual(['alg', 'body', 'issuer', 'sig']);
    expect(() => signAllowlistManifest({ ...body(), version: 0 }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ed.secretKey } })).toThrow('version must be a positive integer');
    const h = signAllowlistManifest(body(), { issuer: 'hyb', alg: 'hybrid-ed25519-ml-dsa-65', secrets: { edSecret: hyb.secretKey, mlDsa: ml } });
    expect(typeof h.pq_sig).toBe('string');
  });
  it('revokeAllowlistEntry flips a matching entry or appends a tombstone; version + 1; prev untouched', () => {
    const prev = body({ entries: [ent(), ent({ value: H96('b'), label: 'keep' })] });
    const snapshot = JSON.stringify(prev);
    const times = { issuedAt: T0, notBefore: T0, expiresAt: T0 + DAY };
    const r1 = revokeAllowlistEntry(prev, { kind: 'tdx-mrtd', value: H96('a') }, times);
    expect(r1).toStrictEqual({ version: 6, ...times, entries: [{ kind: 'tdx-mrtd', value: H96('a'), label: 'L', revoked: true }, { kind: 'tdx-mrtd', value: H96('b'), label: 'keep' }] });
    expect(JSON.stringify(prev)).toBe(snapshot);
    const r2 = revokeAllowlistEntry(prev, { kind: 'tdx-mrtd', value: H96('c') }, times);
    expect(r2.entries[2]).toStrictEqual({ kind: 'tdx-mrtd', value: H96('c'), label: 'revoked', revoked: true });
    const r3 = revokeAllowlistEntry(prev, { kind: 'tdx-mrtd', value: H96('c'), label: 'why' }, times);
    expect(r3.entries[2]!.label).toBe('why');
    // a different kind with the same value does not match
    const r4 = revokeAllowlistEntry(prev, { kind: 'tdx-rtmr', value: H96('a') }, times);
    expect(r4.entries.length).toBe(3);
    expect(r4.entries[0]!.revoked).toBeUndefined();
    // maa-signing-spki matches by label as well
    const m = body({ entries: [ent({ kind: 'maa-signing-spki', value: H64('a'), label: URL1 })] });
    const hit = revokeAllowlistEntry(m, { kind: 'maa-signing-spki', value: H64('a'), label: URL1 }, times);
    expect(hit.entries.length).toBe(1);
    expect(hit.entries[0]!.revoked).toBe(true);
    const miss = revokeAllowlistEntry(m, { kind: 'maa-signing-spki', value: H64('a'), label: 'https://other.example' }, times);
    expect(miss.entries.length).toBe(2);
    expect(miss.entries[0]!.revoked).toBeUndefined();
    expect(miss.entries[1]).toStrictEqual({ kind: 'maa-signing-spki', value: H64('a'), label: 'https://other.example', revoked: true });
    // for other kinds the label is not part of the match
    const lab = revokeAllowlistEntry(prev, { kind: 'tdx-mrtd', value: H96('a'), label: 'different' }, times);
    expect(lab.entries.length).toBe(2);
    expect(lab.entries[0]!.revoked).toBe(true);
    expect(() => revokeAllowlistEntry(prev, { kind: 'tdx-mrtd', value: 'zz' }, times)).toThrow(/tdx-mrtd must be 96/);
  });
  it('driverVersionSlotHex', () => {
    expect(driverVersionSlotHex('595.71.05')).toBe(`${Buffer.from('595.71.05').toString('hex')}${'00'.repeat(7)}`);
    expect(driverVersionSlotHex('595.71.05').length).toBe(32);
    expect(driverVersionSlotHex('123456.123456.12').length).toBe(32);
    for (const v of ['1', 'x', '123456.123456.123', '', '1.2.3.4.5']) expect(() => driverVersionSlotHex(v)).toThrow(new TypeError('invalid driver version'));
  });
});

describe('projectAllowlist and policy field helpers', () => {
  const all: AllowlistEntry[] = [
    { kind: 'tdx-mrtd', value: H96('1'), label: 'a' },
    { kind: 'tdx-mrtd', value: H96('2'), label: 'b' },
    { kind: 'tdx-rtmr', value: H96('3'), label: 'c' },
    { kind: 'sev-snp-measurement', value: H96('4'), label: 'd' },
    { kind: 'gcp-image-digest', value: `sha256:${H64('5')}`, label: 'e' },
    { kind: 'nvidia-measurement', value: H96('6'), label: 'f' },
    { kind: 'nvidia-driver-version', value: '595.71.05', label: 'g' },
    { kind: 'maa-signing-spki', value: H64('7'), label: URL1 },
    { kind: 'maa-signing-spki', value: H64('8'), label: URL1 },
    { kind: 'maa-signing-spki', value: H64('9'), label: 'https://eus.example' },
    { kind: 'maa-chain-root-spki', value: H64('a'), label: 'r' },
    { kind: 'maa-chain-intermediate-spki', value: H64('b'), label: 'i' },
    { kind: 'attest-corroboration', value: H64('c'), label: 'vantages=3;method=m' },
  ];
  const ver = (entries: AllowlistEntry[], over: Partial<AllowlistManifestBody> = {}): Ok => verify(signed(body({ entries, ...over }))) as Ok;
  it('projects every kind in order, with version and expiry', () => {
    const v = ver(all);
    const p = projectAllowlist(v, { nowMs: T0 });
    expect(p).toStrictEqual({
      tdxMrtds: [H96('1'), H96('2')],
      tdxRtmrs: [H96('3')],
      sevSnpMeasurements: [H96('4')],
      imageDigests: [`sha256:${H64('5')}`],
      nvidiaMeasurements: [H96('6')],
      nvidiaDriverVersions: ['595.71.05'],
      nvidiaCcDriverVersions: [driverVersionSlotHex('595.71.05')],
      maaSigningSpkis: { [URL1]: [H64('7'), H64('8')], 'https://eus.example': [H64('9')] },
      maaChainRootSpkis: [H64('a')],
      maaChainIntermediateSpkis: [H64('b')],
      corroboration: [{ value: H64('c'), label: 'vantages=3;method=m' }],
      revoked: [],
      expired: [],
      version: 5,
      manifestExpiresAt: T0 + 30 * DAY,
    });
  });
  it('revoked entries are listed and deny the value everywhere of the same kind; per-entry expiry boundary', () => {
    const v = ver([
      { kind: 'tdx-mrtd', value: H96('1'), label: 'a', notAfter: T0 },
      { kind: 'tdx-mrtd', value: H96('2'), label: 'b', notAfter: T0 - 1 },
      { kind: 'tdx-rtmr', value: H96('3'), label: 'c' },
      { kind: 'sev-snp-measurement', value: H96('3'), label: 'd' },
      { kind: 'tdx-rtmr', value: H96('4'), label: 'tomb', revoked: true },
      { kind: 'maa-signing-spki', value: H64('7'), label: URL1 },
      { kind: 'maa-signing-spki', value: H64('7'), label: 'https://eus.example' },
      { kind: 'maa-signing-spki', value: H64('7'), label: 'https://third.example', revoked: true },
    ]);
    const p = projectAllowlist(v, { nowMs: T0 });
    expect(p.tdxMrtds).toEqual([H96('1')]);
    expect(p.expired).toEqual([{ kind: 'tdx-mrtd', value: H96('2'), label: 'b' }]);
    expect(p.tdxRtmrs).toEqual([H96('3')]);
    expect(p.sevSnpMeasurements).toEqual([H96('3')]);
    expect(p.revoked).toEqual([{ kind: 'tdx-rtmr', value: H96('4'), label: 'tomb' }, { kind: 'maa-signing-spki', value: H64('7'), label: 'https://third.example' }]);
    // a tombstone denies the value for the kind regardless of label
    expect(p.maaSigningSpkis).toEqual({});
    // later than T0 expires the first one too
    expect(projectAllowlist(v, { nowMs: T0 + 1 }).tdxMrtds).toEqual([]);
    expect(projectAllowlist(v, { nowMs: T0 + 1 }).expired.length).toBe(2);
  });
  it('a tombstone listed AFTER the live entry still denies it', () => {
    const v = { ok: true, body: { ...body(), entries: [{ kind: 'tdx-mrtd', value: H96('1'), label: 'a' }, { kind: 'tdx-mrtd', value: H96('1'), label: 't', revoked: true }, { kind: 'tdx-mrtd', value: H96('2'), label: 'b' }] } } as unknown as Ok;
    const q = projectAllowlist(v, { nowMs: T0 });
    expect(q.tdxMrtds).toEqual([H96('2')]);
    expect(q.revoked).toEqual([{ kind: 'tdx-mrtd', value: H96('1'), label: 't' }]);
  });
  it('policy field helpers omit empty lists and return copies', () => {
    const full = projectAllowlist(ver(all), { nowMs: T0 });
    expect(azureMaaPolicyFields(full)).toEqual({ tdxMrtds: [H96('1'), H96('2')], sevSnpMeasurements: [H96('4')], tdxRtmrs: [H96('3')] });
    expect(azureMaaPolicyFields(projectAllowlist(ver([all[0]!]), { nowMs: T0 }))).toStrictEqual({ tdxMrtds: [H96('1')] });
    expect(azureMaaPolicyFields(projectAllowlist(ver([all[3]!]), { nowMs: T0 }))).toStrictEqual({ sevSnpMeasurements: [H96('4')] });
    expect(azureMaaPolicyFields(projectAllowlist(ver([all[2]!]), { nowMs: T0 }))).toStrictEqual({ tdxRtmrs: [H96('3')] });
    expect(azureMaaPolicyFields(projectAllowlist(ver([all[6]!]), { nowMs: T0 }))).toStrictEqual({});
    expect(intelDcapPolicyFields(full)).toStrictEqual({ mrtds: [H96('1'), H96('2')], rtmrs: [H96('3')] });
    expect(intelDcapPolicyFields(projectAllowlist(ver([all[6]!]), { nowMs: T0 }))).toStrictEqual({ mrtds: [] });
    expect(sevSnpPolicyFields(full)).toStrictEqual({ measurements: [H96('4')] });
    expect(gcpCsPolicyFields(full)).toStrictEqual({ imageDigests: [`sha256:${H64('5')}`] });
    expect(nvidiaCcPolicyFields(full)).toStrictEqual({ measurements: [H96('6')], driverVersions: [driverVersionSlotHex('595.71.05')] });
    expect(nvidiaCcPolicyFields(projectAllowlist(ver([all[0]!]), { nowMs: T0 }))).toStrictEqual({ measurements: [] });
    const f = sevSnpPolicyFields(full);
    f.measurements.push('x');
    expect(sevSnpPolicyFields(full).measurements).toEqual([H96('4')]);
    const g = intelDcapPolicyFields(full);
    g.mrtds.pop();
    expect(full.tdxMrtds.length).toBe(2);
  });
});

describe('verifyAllowlistDurable: races against a real read-modify-write', () => {
  const m = signed(body({ version: 5 }));
  const ours = { version: 5, digest: hashCanonical(m.body) };
  /** A kv whose get() misses (a concurrent writer appears between get and update) and whose update() has real semantics. */
  const racy = (cur: unknown) => {
    let stored: unknown = cur;
    const kv: DurableKv = {
      get: async () => undefined,
      set: async () => undefined,
      keys: async () => [],
      update: async (_k, fn) => {
        const next = fn(stored);
        if (next !== undefined) stored = next;
        return stored;
      },
    };
    return { kv, stored: () => stored };
  };
  const dur = (kv: DurableKv) => verifyAllowlistDurable(m, { issuerKeys: KEYS, nowMs: T0 }, kv);
  it('same version with a different stored digest is a conflict and is NOT overwritten (versions are append-only)', async () => {
    const stored = { version: 5, digest: 'N'.repeat(43) };
    const r = racy(stored);
    expect(code(await dur(r.kv))).toBe('conflict');
    expect(r.stored()).toEqual(stored);
  });
  it('a stored mark of a lower version carrying our digest is still advanced', async () => {
    const r = racy({ version: 4, digest: ours.digest });
    expect(code(await dur(r.kv))).toBe('ok');
    expect(r.stored()).toEqual(ours);
  });
  it('a stored identical mark is left alone; a higher one wins', async () => {
    const same = racy(ours);
    expect(code(await dur(same.kv))).toBe('ok');
    expect(same.stored()).toEqual(ours);
    const hi = racy({ version: 9, digest: 'N'.repeat(43) });
    expect(code(await dur(hi.kv))).toBe('rollback');
    expect(hi.stored()).toEqual({ version: 9, digest: 'N'.repeat(43) });
  });
  it('an older value returned by the store after our write is not a conflict', async () => {
    const kv: DurableKv = { get: async () => undefined, set: async () => undefined, keys: async () => [], update: async () => ({ version: 4, digest: 'N'.repeat(43) }) };
    expect(code(await dur(kv))).toBe('ok');
  });
  it('a stored digest that is a non-string coercible to a valid one is corrupt', async () => {
    const kv = createMemoryDurableKv();
    await kv.set('allowlist/ops', { version: 5, digest: ['A'.repeat(43)] });
    expect(reason(await dur(kv))).toBe('persisted allowlist high-water mark is corrupt');
  });
  it('the store is not consulted for a non-string or oversized issuer', async () => {
    const calls: string[] = [];
    const kv: DurableKv = { get: async (k) => (calls.push(k), undefined), set: async () => undefined, keys: async () => [], update: async () => undefined };
    for (const issuer of [['ops'], 5, 'x'.repeat(201)]) {
      const r = await verifyAllowlistDurable({ ...signed(), issuer }, { issuerKeys: KEYS, nowMs: T0 }, kv);
      expect(reason(r)).toBe('issuer must be a string');
    }
    expect(calls).toEqual([]);
    await verifyAllowlistDurable({ ...signed(), issuer: 'x'.repeat(200) }, { issuerKeys: KEYS, nowMs: T0 }, kv);
    expect(calls).toEqual([`allowlist/${'x'.repeat(200)}`]);
  });
});
