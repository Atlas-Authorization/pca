/** 0.5 production tier: required replay store by default, alg/jwk type match, bounded in-memory store, RFC 8705 certificate binding. */
import { X509Certificate, createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { exportJWK, generateKeyPair as joseGen } from 'jose';
import type { JWK } from 'jose';
import { describe, expect, it } from 'vitest';
import {
  DPOP_INMEMORY_MAX_ENTRIES,
  DpopVerificationError,
  assertMtlsBound,
  createDpopProof,
  createInMemoryDpopReplayStore,
  dpopAlgMatchesJwk,
  mtlsCnf,
  mtlsThumbprint,
  runDpopReplayStoreConformance,
  verifyDpopProof,
} from './index';

const URL1 = 'https://api.example/v1/x';
const NOW = 1_800_000_000;

async function settle<T>(p: Promise<T>): Promise<{ ok: true; value: T } | { ok: false; code: string; message: string }> {
  try {
    return { ok: true, value: await p };
  } catch (e) {
    if (!(e instanceof DpopVerificationError)) throw e;
    return { ok: false, code: e.code, message: e.message };
  }
}
function settleSync(f: () => unknown): { ok: true } | { ok: false; code: string; message: string } {
  try {
    f();
    return { ok: true };
  } catch (e) {
    if (!(e instanceof DpopVerificationError)) throw e;
    return { ok: false, code: e.code, message: e.message };
  }
}

async function es256() {
  const { privateKey, publicKey } = await joseGen('ES256', { extractable: true });
  return { privateJwk: await exportJWK(privateKey), publicJwk: await exportJWK(publicKey) };
}
async function proofFor(k: { privateJwk: JWK; publicJwk: JWK }, jti = 'j1') {
  return createDpopProof({ method: 'POST', url: URL1, privateKey: k.privateJwk, publicJwk: k.publicJwk, iat: NOW, jti });
}
const base = { method: 'POST', url: URL1, maxAgeSec: 60, nowSec: NOW };

describe('replay store is required by default (DoD-1, DoD-8)', () => {
  it('no store and no flag: refused with the exact code and message; nothing is accepted', async () => {
    const p = await proofFor(await es256());
    expect(await settle(verifyDpopProof(p, base))).toEqual({
      ok: false,
      code: 'replay_store_required',
      message: 'no replay store configured; replay cannot be detected',
    });
  });
  it('an explicit requireReplayStore:false opts out; a store or a seenJti set satisfies the default', async () => {
    const k = await es256();
    expect((await settle(verifyDpopProof(await proofFor(k, 'a'), { ...base, requireReplayStore: false }))).ok).toBe(true);
    expect((await settle(verifyDpopProof(await proofFor(k, 'b'), { ...base, replayStore: createInMemoryDpopReplayStore() }))).ok).toBe(true);
    expect((await settle(verifyDpopProof(await proofFor(k, 'c'), { ...base, seenJti: new Set<string>() }))).ok).toBe(true);
  });
  it('the default is checked before the proof is parsed (a garbage proof still reports the missing store)', async () => {
    expect(await settle(verifyDpopProof('x', base))).toEqual({
      ok: false,
      code: 'replay_store_required',
      message: 'no replay store configured; replay cannot be detected',
    });
  });
});

describe('the declared alg must belong to the embedded jwk', () => {
  const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
  // The check runs before the signature, so a placeholder signature is enough to reach it.
  const unsigned = (alg: string, jwk: unknown): string =>
    `${b64({ typ: 'dpop+jwt', alg, jwk })}.${b64({ htm: 'POST', htu: URL1, iat: NOW, jti: 'j1' })}.${Buffer.alloc(64).toString('base64url')}`;
  const ec = (crv: string): JWK => ({ kty: 'EC', crv, x: 'AAAA', y: 'AAAA' });
  const okp: JWK = { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' };
  const rsa: JWK = { kty: 'RSA', n: 'AAAA', e: 'AQAB' };

  const mismatched: Array<[string, JWK]> = [
    ['EdDSA', ec('P-256')],
    ['EdDSA', rsa],
    ['ES256', okp],
    ['ES256', ec('P-384')],
    ['ES384', ec('P-256')],
    ['ES512', ec('P-384')],
    ['PS256', ec('P-256')],
    ['RS256', okp],
  ];
  it.each(mismatched)('%s over %j is refused as alg_jwk_mismatch', async (alg, jwk) => {
    expect(await settle(verifyDpopProof(unsigned(alg, jwk), { ...base, requireReplayStore: false }))).toEqual({
      ok: false,
      code: 'alg_jwk_mismatch',
      message: `alg '${alg}' does not match the embedded jwk key type`,
    });
  });
  it('a matching pair passes this check and is then judged by the signature', async () => {
    const r = await settle(verifyDpopProof(unsigned('ES256', ec('P-256')), { ...base, requireReplayStore: false }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('signature');
  });
  it('an algorithm outside the allow-list is not reported as a type mismatch', async () => {
    const r = await settle(verifyDpopProof(unsigned('HS256', okp), { ...base, requireReplayStore: false }));
    expect(r.ok === false && r.code).toBe('signature');
  });
  it('dpopAlgMatchesJwk: the whole table', () => {
    const yes: Array<[string, JWK]> = [
      ['EdDSA', okp],
      ['EdDSA', { kty: 'OKP', crv: 'Ed448', x: 'AAAA' }],
      ['ES256', ec('P-256')],
      ['ES384', ec('P-384')],
      ['ES512', ec('P-521')],
      ['PS256', rsa],
      ['RS256', rsa],
    ];
    for (const [a, j] of yes) expect(dpopAlgMatchesJwk(a, j), `${a} ${j.kty}`).toBe(true);
    for (const [a, j] of mismatched) expect(dpopAlgMatchesJwk(a, j), `${a} ${j.kty}`).toBe(false);
    expect(dpopAlgMatchesJwk('EdDSA', { kty: 'OKP', crv: 'X25519', x: 'AAAA' })).toBe(false);
    expect(dpopAlgMatchesJwk('none', okp)).toBe(false);
    expect(dpopAlgMatchesJwk('HS256', { kty: 'oct' })).toBe(false);
    expect(dpopAlgMatchesJwk('RS384', rsa)).toBe(false);
  });
});

describe('the in-memory replay store is bounded and fails closed when full', () => {
  it('default capacity constant', () => {
    expect(DPOP_INMEMORY_MAX_ENTRIES).toBe(100_000);
  });
  it('refuses to evict a live entry: the next new key throws, an existing key is still reported as a replay', () => {
    const s = createInMemoryDpopReplayStore({ maxEntries: 2 });
    expect(s.addIfAbsent('a', 200, 100)).toBe(true);
    expect(s.addIfAbsent('b', 200, 100)).toBe(true);
    expect(() => s.addIfAbsent('c', 200, 100)).toThrow('replay store is full');
    expect(s.addIfAbsent('a', 200, 150)).toBe(false);
  });
  it('expired entries are reclaimed to make room, at the boundary nowSec >= expiresAtSec', () => {
    const s = createInMemoryDpopReplayStore({ maxEntries: 1 });
    expect(s.addIfAbsent('a', 200, 100)).toBe(true);
    expect(() => s.addIfAbsent('b', 400, 199)).toThrow('replay store is full');
    expect(s.addIfAbsent('b', 400, 200)).toBe(true);
    expect(() => s.addIfAbsent('a', 600, 250)).toThrow('replay store is full');
  });
  it('a full store makes the verifier fail closed with replay_store_error', async () => {
    const k = await es256();
    const store = createInMemoryDpopReplayStore({ maxEntries: 1 });
    expect((await settle(verifyDpopProof(await proofFor(k, 'a'), { ...base, replayStore: store }))).ok).toBe(true);
    expect(await settle(verifyDpopProof(await proofFor(k, 'b'), { ...base, replayStore: store }))).toEqual({
      ok: false,
      code: 'replay_store_error',
      message: 'replay store failed: replay store is full',
    });
  });
  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])('maxEntries %s is a misconfiguration', (n) => {
    expect(settleSync(() => createInMemoryDpopReplayStore({ maxEntries: n }))).toEqual({
      ok: false,
      code: 'misconfigured',
      message: 'maxEntries must be a positive integer',
    });
  });
  it('still passes the replay-store conformance suite', async () => {
    expect(await runDpopReplayStoreConformance(() => createInMemoryDpopReplayStore())).toEqual([]);
  });
});

// ---- RFC 8705: certificate-bound tokens ------------------------------------------------------

function derNode(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const n = body.length;
  const len = n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
/** A minimal self-signed Ed25519 X.509 v3 certificate, assembled byte by byte (Node cannot create certificates). */
function testCert(cn: string) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const algId = derNode(0x30, derNode(0x06, Buffer.from([0x2b, 0x65, 0x70])));
  const name = derNode(0x30, derNode(0x31, derNode(0x30, derNode(0x06, Buffer.from([0x55, 0x04, 0x03])), derNode(0x0c, Buffer.from(cn)))));
  const validity = derNode(0x30, derNode(0x17, Buffer.from('250101000000Z')), derNode(0x17, Buffer.from('450101000000Z')));
  const tbs = derNode(
    0x30,
    derNode(0xa0, derNode(0x02, Buffer.from([2]))),
    derNode(0x02, Buffer.from([1])),
    algId,
    name,
    validity,
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
  );
  const cert = derNode(0x30, tbs, algId, derNode(0x03, Buffer.concat([Buffer.from([0]), nodeSign(null, tbs, privateKey)])));
  const b64 = cert.toString('base64').replace(/.{1,64}/g, '$&\n');
  return { der: cert, pem: `-----BEGIN CERTIFICATE-----\n${b64}-----END CERTIFICATE-----\n`, publicKey };
}
const sha256b64u = (b: Uint8Array): string => createHash('sha256').update(b).digest('base64url');

describe('RFC 8705 x5t#S256 certificate binding', () => {
  const c = testCert('mtls-test-client');
  it('the hand-built certificate is a real, self-signed X.509 certificate', () => {
    const x = new X509Certificate(c.der);
    expect(x.verify(c.publicKey)).toBe(true);
    expect(x.subject).toBe('CN=mtls-test-client');
  });
  it('thumbprint equals base64url(SHA-256(DER)) and the hex fingerprint Node reports, for DER and PEM', () => {
    const want = sha256b64u(c.der);
    const x = new X509Certificate(c.der);
    expect(Buffer.from(want, 'base64url').toString('hex').toUpperCase()).toBe(x.fingerprint256.replace(/:/g, ''));
    expect(mtlsThumbprint(c.der)).toBe(want);
    expect(mtlsThumbprint(c.pem)).toBe(want);
    expect(mtlsThumbprint(new Uint8Array(c.der))).toBe(want);
    expect(mtlsCnf(c.der)).toEqual({ 'x5t#S256': want });
  });
  it('a bound certificate passes and returns the confirmation', () => {
    const cnf = { 'x5t#S256': sha256b64u(c.der) };
    expect(assertMtlsBound(c.der, cnf)).toEqual(cnf);
    expect(assertMtlsBound(c.pem, { ...cnf, other: 1 })).toEqual(cnf);
  });
  it('a different certificate is refused as x5t', () => {
    const other = testCert('someone-else');
    expect(settleSync(() => assertMtlsBound(other.der, { 'x5t#S256': sha256b64u(c.der) }))).toEqual({
      ok: false,
      code: 'x5t',
      message: 'client certificate thumbprint does not match cnf x5t#S256',
    });
  });
  it('a one-character change, a truncation and a padded spelling of the thumbprint are refused', () => {
    const good = sha256b64u(c.der);
    const flipped = (good[0] === 'A' ? 'B' : 'A') + good.slice(1);
    for (const bad of [flipped, good.slice(0, -1), `${good}=`, good.toLowerCase() === good ? good.toUpperCase() : good.toLowerCase()]) {
      expect(settleSync(() => assertMtlsBound(c.der, { 'x5t#S256': bad })), bad).toMatchObject({ ok: false, code: 'x5t' });
    }
  });
  it.each([undefined, null, 'str', 5, {}, { 'x5t#S256': '' }, { 'x5t#S256': 5 }, { x5t: 'abc' }, []])('cnf %j has no usable thumbprint', (cnf) => {
    expect(settleSync(() => assertMtlsBound(c.der, cnf))).toEqual({
      ok: false,
      code: 'x5t_missing',
      message: "cnf has no 'x5t#S256' thumbprint",
    });
  });
  it('a certificate that does not parse is refused as cert, never compared', () => {
    const cnf = { 'x5t#S256': sha256b64u(new Uint8Array([1, 2, 3])) };
    for (const bad of [new Uint8Array([1, 2, 3]), new Uint8Array(0), 'not a certificate', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n']) {
      const r = settleSync(() => assertMtlsBound(bad, cnf));
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.code).toBe('cert');
        expect(r.message.startsWith('not an X.509 certificate: ')).toBe(true);
      }
    }
    expect(settleSync(() => assertMtlsBound(undefined as unknown as Uint8Array, cnf))).toMatchObject({ ok: false, code: 'cert' });
  });
  it('a truncated or tampered DER certificate is refused as cert or as x5t, never accepted', () => {
    const cnf = { 'x5t#S256': sha256b64u(c.der) };
    expect(settleSync(() => assertMtlsBound(c.der.subarray(0, c.der.length - 10), cnf))).toMatchObject({ ok: false });
    const t = Buffer.from(c.der);
    t[t.length - 1] = (t[t.length - 1] ?? 0) ^ 1; // signature byte: still parses, different thumbprint
    expect(settleSync(() => assertMtlsBound(t, cnf))).toMatchObject({ ok: false, code: 'x5t' });
  });
});
