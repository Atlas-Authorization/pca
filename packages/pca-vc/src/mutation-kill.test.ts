/**
 * Mutation-kill tests for the VC bridge: base58btc / did:key codecs, passport <-> SD-JWT VC, and the RFC 9421 (HTTP message signature)
 * signer/verifier. Malformed credentials and signature bases are assembled by hand so every parse rule is exercised on its own.
 */
import { generateKeyPairSync, sign as nodeSign, type KeyObject } from 'node:crypto';
import { SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import type { AgentPassport } from '@atlasauth/pca';
import {
  AGENT_PASSPORT_CONTEXT,
  AGENT_PASSPORT_VC_TYPE,
  VC_CONTEXT,
  base58btcDecode,
  base58btcEncode,
  didKeyFromEd25519,
  ed25519FromDidKey,
  passportToVC,
  signRequestMessage,
  verifyPassportVC,
  verifyRequestSignature,
} from './index';

const kp = generateKeyPairSync('ed25519');
const other = generateKeyPairSync('ed25519');
const rawPub = (k: KeyObject) => new Uint8Array(Buffer.from((k.export({ format: 'jwk' }) as { x: string }).x, 'base64url'));
const decodePayload = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[1] as string, 'base64url').toString());
const b64u = (s: string) => Buffer.from(s).toString('base64url');
const err = async (p: Promise<unknown> | (() => unknown)): Promise<string> => {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    return (e as Error).message;
  }
  throw new Error('no throw');
};

describe('base58btc', () => {
  it('known vectors and leading zeros', () => {
    const enc = (s: string) => base58btcEncode(new TextEncoder().encode(s));
    expect(enc('')).toBe('');
    expect(enc('Hello World!')).toBe('2NEpo7TZRRrLZSi2U');
    expect(base58btcEncode(Uint8Array.from([0]))).toBe('1');
    expect(base58btcEncode(Uint8Array.from([0, 0, 0]))).toBe('111');
    expect(base58btcEncode(Uint8Array.from([0, 0, 1]))).toBe('112');
    expect(base58btcEncode(Uint8Array.from([0xff]))).toBe('5Q');
    expect(base58btcEncode(Uint8Array.from([0, 0xff, 0xff]))).toBe('1LUv');
    expect(base58btcDecode('2NEpo7TZRRrLZSi2U')).toStrictEqual(new TextEncoder().encode('Hello World!'));
    expect(base58btcDecode('')).toStrictEqual(new Uint8Array(0));
    expect(base58btcDecode('1')).toStrictEqual(Uint8Array.from([0]));
    expect(base58btcDecode('112')).toStrictEqual(Uint8Array.from([0, 0, 1]));
    expect(base58btcDecode('111')).toStrictEqual(Uint8Array.from([0, 0, 0]));
    expect(base58btcDecode('5Q')).toStrictEqual(Uint8Array.from([0xff]));
    expect(base58btcDecode('1LUv')).toStrictEqual(Uint8Array.from([0, 0xff, 0xff]));
    for (const n of [1, 2, 31, 32, 33, 100]) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff);
      expect(base58btcDecode(base58btcEncode(b))).toStrictEqual(b);
      const z = Uint8Array.from([0, 0, ...b]);
      expect(base58btcDecode(base58btcEncode(z))).toStrictEqual(z);
    }
  });
  it('rejects bad characters and over-long input', () => {
    for (const bad of ['0', 'O', 'I', 'l', 'a b', '+', '=']) expect(() => base58btcDecode(`1${bad}`)).toThrow('pca-vc: invalid base58btc character');
    expect(() => base58btcDecode('2'.repeat(1025))).toThrow('pca-vc: base58btc input too long');
    expect(base58btcDecode('2'.repeat(1024)).length).toBeGreaterThan(0);
  });
});

describe('did:key', () => {
  it('round-trips and has the expected shape', () => {
    const raw = rawPub(kp.publicKey);
    const did = didKeyFromEd25519(raw);
    expect(did.startsWith('did:key:z6Mk')).toBe(true);
    expect(ed25519FromDidKey(did)).toStrictEqual(raw);
    const w3c = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'; // W3C did:key spec example
    expect(didKeyFromEd25519(ed25519FromDidKey(w3c))).toBe(w3c);
  });
  it('length and prefix errors', () => {
    for (const n of [0, 31, 33]) expect(() => didKeyFromEd25519(new Uint8Array(n))).toThrow('pca-vc: Ed25519 public key must be 32 bytes');
    expect(() => ed25519FromDidKey('did:web:x')).toThrow('pca-vc: not a did:key:z… identifier');
    expect(() => ed25519FromDidKey('did:key:6Mk')).toThrow('pca-vc: not a did:key:z… identifier');
    expect(() => ed25519FromDidKey(`did:key:z${'2'.repeat(65)}`)).toThrow('pca-vc: did:key is not an Ed25519 (0xed01) key');
  });
  it('multicodec prefix and total length are all checked', () => {
    const msg = 'pca-vc: did:key is not an Ed25519 (0xed01) key';
    const mk = (bytes: number[]) => `did:key:z${base58btcEncode(Uint8Array.from(bytes))}`;
    const key = Array.from(rawPub(kp.publicKey));
    expect(ed25519FromDidKey(mk([0xed, 0x01, ...key]))).toStrictEqual(rawPub(kp.publicKey));
    expect(() => ed25519FromDidKey(mk([0xed, 0x02, ...key]))).toThrow(msg);
    expect(() => ed25519FromDidKey(mk([0xee, 0x01, ...key]))).toThrow(msg);
    expect(() => ed25519FromDidKey(mk([0xe7, 0x01, ...key]))).toThrow(msg);
    expect(() => ed25519FromDidKey(mk([0xed, 0x01, ...key, 0]))).toThrow(msg);
    expect(() => ed25519FromDidKey(mk([0xed, 0x01, ...key.slice(1)]))).toThrow(msg);
    expect(() => ed25519FromDidKey(mk([0x00, 0x01, ...key]))).toThrow(msg);
  });
});

const passport = (o: Partial<AgentPassport> = {}): AgentPassport => ({
  id: 'pp-1',
  model_id: 'm/1',
  operator: 'acme',
  hardware_rooted: true,
  issued_at: 1_700_000_000,
  weights_digest: 'sha256:w',
  system_prompt_digest: 'sha256:p',
  tool_manifest_digest: 'sha256:t',
  runtime_measurement: '42',
  ...o,
});
const issueVc = (p: AgentPassport, extra: Record<string, unknown> = {}) =>
  passportToVC(p, { issuerKey: kp.privateKey, issuerDid: 'did:key:zISS', subjectDid: 'did:key:zSUB', ...extra } as never);

describe('passportToVC', () => {
  it('emits the SD-JWT VC structure with one disclosure per measured field', async () => {
    const before = Math.floor(Date.now() / 1000);
    const vc = await issueVc(passport({ weights_measured: false }));
    const parts = vc.split('~');
    expect(parts[parts.length - 1]).toBe('');
    const jwt = parts[0] as string;
    const discs = parts.slice(1, -1);
    const header = JSON.parse(Buffer.from(jwt.split('.')[0] as string, 'base64url').toString());
    expect(header).toStrictEqual({ alg: 'EdDSA', typ: 'vc+sd-jwt' });
    const p = decodePayload(jwt);
    expect(p.iss).toBe('did:key:zISS');
    expect(p.sub).toBe('did:key:zSUB');
    expect(p.iat).toBeGreaterThanOrEqual(before);
    expect(p.iat).toBeLessThan(before + 10);
    expect('exp' in p).toBe(false);
    expect(p._sd_alg).toBe('sha-256');
    expect(p.vc['@context']).toStrictEqual([VC_CONTEXT, AGENT_PASSPORT_CONTEXT]);
    expect(p.vc.type).toStrictEqual(['VerifiableCredential', AGENT_PASSPORT_VC_TYPE]);
    const cs = p.vc.credentialSubject;
    expect(Object.keys(cs).sort()).toEqual(['_sd', 'hardware_rooted', 'id', 'issued_at', 'model_id', 'operator', 'passport_id', 'weights_measured']);
    expect(cs).toMatchObject({ id: 'did:key:zSUB', passport_id: 'pp-1', model_id: 'm/1', operator: 'acme', hardware_rooted: true, issued_at: 1_700_000_000, weights_measured: false });
    const decoded = discs.map((d) => JSON.parse(Buffer.from(d, 'base64url').toString()) as [string, string, string]);
    expect(decoded.map((d) => d[1])).toEqual(['weights_digest', 'system_prompt_digest', 'tool_manifest_digest', 'runtime_measurement']);
    expect(decoded.map((d) => d[2])).toEqual(['sha256:w', 'sha256:p', 'sha256:t', '42']);
    for (const d of decoded) expect(d[0]).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(new Set(decoded.map((d) => d[0])).size).toBe(4);
    const { createHash } = await import('node:crypto');
    expect(cs._sd).toStrictEqual(discs.map((d) => createHash('sha256').update(d, 'ascii').digest().toString('base64url')));
  });
  it('omits what is absent: no weights_measured, no _sd and no _sd_alg without digests', async () => {
    const bare = passport();
    delete bare.weights_digest;
    delete bare.system_prompt_digest;
    delete bare.tool_manifest_digest;
    delete bare.runtime_measurement;
    const vc = await issueVc(bare);
    expect(vc.split('~')).toHaveLength(2);
    const p = decodePayload(vc.split('~')[0] as string);
    expect('_sd_alg' in p).toBe(false);
    expect('_sd' in p.vc.credentialSubject).toBe(false);
    expect('weights_measured' in p.vc.credentialSubject).toBe(false);
    const one = await issueVc(passport({ system_prompt_digest: undefined, tool_manifest_digest: undefined, runtime_measurement: undefined, weights_measured: true }));
    const p1 = decodePayload(one.split('~')[0] as string);
    expect(p1.vc.credentialSubject._sd).toHaveLength(1);
    expect(p1.vc.credentialSubject.weights_measured).toBe(true);
    expect(one.split('~')).toHaveLength(3);
  });
  it('ttlSec sets the expiry relative to now (zero included)', async () => {
    const now = Math.floor(Date.now() / 1000);
    const e = decodePayload((await issueVc(passport(), { ttlSec: 100 })).split('~')[0] as string);
    expect(e.exp - e.iat).toBe(100);
    expect(Math.abs(e.iat - now)).toBeLessThan(5);
    const z = decodePayload((await issueVc(passport(), { ttlSec: 0 })).split('~')[0] as string);
    expect(z.exp).toBe(z.iat);
  });
});

describe('verifyPassportVC', () => {
  const sd = (field: string, value: unknown, salt = 'salt0123456789abcdefgh') => b64u(JSON.stringify([salt, field, value]));
  const dig = async (d: string) => (await import('node:crypto')).createHash('sha256').update(d, 'ascii').digest().toString('base64url');
  const cs0 = { id: 'did:key:zSUB', passport_id: 'pp-1', model_id: 'm/1', operator: 'acme', hardware_rooted: false, issued_at: 5 };
  const vc0 = { '@context': [VC_CONTEXT, AGENT_PASSPORT_CONTEXT], type: ['VerifiableCredential', AGENT_PASSPORT_VC_TYPE], credentialSubject: cs0 };
  async function craft(over: { vc?: unknown; payload?: Record<string, unknown>; header?: Record<string, unknown>; discs?: string[]; key?: KeyObject; cs?: Record<string, unknown>; vcOver?: Record<string, unknown> } = {}) {
    const vc = 'vc' in over ? over.vc : { ...vc0, ...(over.vcOver ?? {}), credentialSubject: over.cs ?? cs0 };
    const payload: Record<string, unknown> = { iss: 'did:key:zISS', ...(vc === undefined ? {} : { vc }), ...(over.payload ?? {}) };
    const jwt = await new SignJWT(payload).setProtectedHeader({ alg: 'EdDSA', typ: 'vc+sd-jwt', ...(over.header ?? {}) } as never).sign(over.key ?? kp.privateKey);
    return [jwt, ...(over.discs ?? [])].map((p) => `${p}~`).join('');
  }
  const verify = (s: string) => verifyPassportVC(s, kp.publicKey);

  it('round trip returns the passport, issuer and subject', async () => {
    const full = passport({ weights_measured: false });
    const r = await verify(await issueVc(full));
    expect(r).toStrictEqual({ passport: full, issuerDid: 'did:key:zISS', subjectDid: 'did:key:zSUB' });
    const bare = await verify(await craft());
    expect(bare.passport).toStrictEqual({ id: 'pp-1', model_id: 'm/1', operator: 'acme', hardware_rooted: false, issued_at: 5 });
    expect('weights_measured' in bare.passport).toBe(false);
    expect(Object.keys((await verify(await issueVc(passport({ weights_digest: undefined })))).passport)).not.toContain('weights_digest');
  });
  it('structural and header errors', async () => {
    expect(await err(verify(''))).toBe('pca-vc: empty SD-JWT');
    expect(await err(verify('~abc~'))).toBe('pca-vc: empty SD-JWT');
    expect(await err(verify('abc'))).toMatch(/./);
    expect(await err(verify(await craft({ header: { typ: 'JWT' } })))).toBe("pca-vc: header typ must be 'vc+sd-jwt'");
    expect(await err(verifyPassportVC(await craft(), other.publicKey))).toMatch(/signature/i);
    const j = await craft();
    expect(await err(verify(`${j}!!!~`))).toMatch(/./);
    expect(await err(verify(j.slice(0, -1) + '.'))).toMatch(/./);
  });
  it('vc claim checks', async () => {
    for (const vc of [undefined, 'x', 5, null, ['a']]) expect(await err(verify(await craft({ vc })))).toBe('pca-vc: missing vc claim');
    const ctxMsg = `pca-vc: @context must begin with ${VC_CONTEXT}`;
    for (const ctx of ['x', [], ['https://other'], [AGENT_PASSPORT_CONTEXT, VC_CONTEXT], undefined]) expect(await err(verify(await craft({ vcOver: { '@context': ctx } })))).toBe(ctxMsg);
    const typeMsg = `pca-vc: type must include VerifiableCredential and ${AGENT_PASSPORT_VC_TYPE}`;
    for (const type of ['VerifiableCredential', [], ['VerifiableCredential'], [AGENT_PASSPORT_VC_TYPE], undefined, 5]) expect(await err(verify(await craft({ vcOver: { type } })))).toBe(typeMsg);
    await verify(await craft({ vcOver: { type: ['Other', AGENT_PASSPORT_VC_TYPE, 'VerifiableCredential'] } }));
    await verify(await craft({ vcOver: { '@context': [VC_CONTEXT] } }));
    for (const cs of [undefined, 'x', 5, null, ['a']]) expect(await err(verify(await craft({ vc: { ...vc0, credentialSubject: cs } })))).toBe('pca-vc: missing credentialSubject');
    expect(await err(verify(await craft({ cs: { ...cs0, _sd_alg: 'sha-256' } })))).toBe('pca-vc: _sd_alg must be a top-level claim');
    expect(await err(verify(await craft({ payload: { _sd_alg: 'sha-512' } })))).toBe('pca-vc: unsupported _sd_alg (require sha-256)');
    await verify(await craft({ payload: { _sd_alg: 'sha-256' } }));
  });
  it('subject fields are type-checked with their names', async () => {
    const bad = async (patch: Record<string, unknown>, msg: string) => expect(await err(verify(await craft({ cs: { ...cs0, ...patch } })))).toBe(msg);
    await bad({ passport_id: 5 }, 'pca-vc: expected string for passport_id');
    await bad({ passport_id: undefined }, 'pca-vc: expected string for passport_id');
    await bad({ model_id: 5 }, 'pca-vc: expected string for model_id');
    await bad({ operator: null }, 'pca-vc: expected string for operator');
    await bad({ hardware_rooted: 'true' }, 'pca-vc: expected boolean for hardware_rooted');
    await bad({ hardware_rooted: undefined }, 'pca-vc: expected boolean for hardware_rooted');
    await bad({ issued_at: '5' }, 'pca-vc: expected number for issued_at');
    await bad({ issued_at: undefined }, 'pca-vc: expected number for issued_at');
    await bad({ weights_measured: 'yes' }, 'pca-vc: expected boolean for weights_measured');
    await bad({ id: 5 }, 'pca-vc: expected string for credentialSubject.id');
    expect(await err(verify(await craft({ payload: { iss: 5 } })))).toBe('pca-vc: expected string for iss');
    expect(await err(verify(await craft({ payload: { iss: undefined } })))).toBe('pca-vc: expected string for iss');
    expect((await verify(await craft({ cs: { ...cs0, weights_measured: true } }))).passport.weights_measured).toBe(true);
  });
  it('disclosures: digest membership, duplicates, shape, names and values', async () => {
    const w = sd('weights_digest', 'sha256:w');
    const w2 = sd('weights_digest', 'sha256:other', 'differentsalt0123456789');
    const sdOf = async (...d: string[]) => ({ ...cs0, _sd: await Promise.all(d.map(dig)) });
    const ok = await verify(await craft({ cs: await sdOf(w), discs: [w] }));
    expect(ok.passport.weights_digest).toBe('sha256:w');
    expect(await err(verify(await craft({ cs: await sdOf(w), discs: [sd('weights_digest', 'sha256:x')] })))).toBe('pca-vc: disclosure does not match any _sd digest');
    expect(await err(verify(await craft({ cs: cs0, discs: [w] })))).toBe('pca-vc: disclosure does not match any _sd digest');
    expect(await err(verify(await craft({ cs: await sdOf(w), discs: [w, w] })))).toBe('pca-vc: duplicate disclosure');
    expect(await err(verify(await craft({ cs: await sdOf(w, w2), discs: [w, w2] })))).toBe("pca-vc: disclosure claim 'weights_digest' appears more than once");
    const forged = sd('operator', 'evil');
    expect(await err(verify(await craft({ cs: await sdOf(forged), discs: [forged] })))).toBe("pca-vc: unexpected disclosure claim 'operator'");
    const notJson = b64u('not json');
    expect(await err(verify(await craft({ cs: await sdOf(notJson), discs: [notJson] })))).toBe('pca-vc: malformed disclosure');
    for (const shape of [['s', 'weights_digest'], ['s', 'weights_digest', 'v', 'extra'], { a: 1 }, 'str']) {
      const d = b64u(JSON.stringify(shape));
      expect(await err(verify(await craft({ cs: await sdOf(d), discs: [d] })))).toBe('pca-vc: malformed disclosure');
    }
    const num = sd(5 as never, 'v');
    expect(await err(verify(await craft({ cs: await sdOf(num), discs: [num] })))).toBe('pca-vc: expected string for disclosure name');
    const nv = sd('weights_digest', 7);
    expect(await err(verify(await craft({ cs: await sdOf(nv), discs: [nv] })))).toBe('pca-vc: expected string for disclosure value');
    // non-string _sd entries are ignored; a non-array _sd means no digest can match
    expect((await verify(await craft({ cs: { ...cs0, _sd: [5, null, await dig(w)] }, discs: [w] }))).passport.weights_digest).toBe('sha256:w');
    expect(await err(verify(await craft({ cs: { ...cs0, _sd: await dig(w) }, discs: [w] })))).toBe('pca-vc: disclosure does not match any _sd digest');
    expect(await err(verify(await craft({ cs: { ...cs0, _sd: [5] }, discs: [w] })))).toBe('pca-vc: disclosure does not match any _sd digest');
    // empty trailing segments are tolerated
    expect((await verify(`${await craft({ cs: await sdOf(w), discs: [w] })}~`)).passport.weights_digest).toBe('sha256:w');
  });
});

/* ---------------------------------------------------------------------------------------------------------------- */
describe('RFC 9421 request signatures', () => {
  const URL1 = 'https://api.example.com/v1/pay?x=1';
  const sigBase = (lines: [string, string][], params: string) => [...lines.map(([k, v]) => `"${k}": ${v}`), `"@signature-params": ${params}`].join('\n');
  const rawSign = (base: string, key = kp.privateKey) => `sig1=:${nodeSign(null, Buffer.from(base), key).toString('base64')}:`;
  /** Sign an arbitrary signature-params string over an arbitrary component list (bypassing the signer's own rules). */
  const forge = (params: string, lines: [string, string][], key = kp.privateKey) => rawSign(sigBase(lines, params), key);
  const NOW = 1_700_000_000;
  const hdr = { 'X-Req': ' val ', Host: 'api.example.com' };

  it('signRequestMessage produces a verifiable, exactly-shaped RFC 9421 signature', () => {
    const s = signRequestMessage({ method: 'post', url: URL1, headers: { 'X-B': ' b ', 'x-a': 'a' }, key: kp.privateKey, keyid: 'k1', created: NOW });
    const params = `("@method" "@target-uri" "host" "x-a" "x-b");created=${NOW};keyid="k1";alg="ed25519"`;
    expect(s.signatureInput).toBe(`sig1=${params}`);
    expect(s.signature).toMatch(/^sig1=:[A-Za-z0-9+/=]+:$/);
    expect('signatureAgent' in s).toBe(false);
    const base = sigBase([['@method', 'POST'], ['@target-uri', URL1], ['host', 'api.example.com'], ['x-a', 'a'], ['x-b', 'b']], params);
    expect(s.signature).toBe(rawSign(base)); // Ed25519 is deterministic: the exact base string was signed
  });
  it('an explicit host header is kept; signature-agent is covered, quoted and tagged', () => {
    const s = signRequestMessage({ method: 'GET', url: URL1, headers: { host: 'proxy.internal' }, key: kp.privateKey, keyid: 'k', created: NOW, signatureAgent: 'https://agent.example' });
    const params = `("@method" "@target-uri" "host" "signature-agent");created=${NOW};keyid="k";alg="ed25519";tag="web-bot-auth"`;
    expect(s.signatureInput).toBe(`sig1=${params}`);
    expect(s.signatureAgent).toBe('"https://agent.example"');
    expect(s.signature).toBe(rawSign(sigBase([['@method', 'GET'], ['@target-uri', URL1], ['host', 'proxy.internal'], ['signature-agent', '"https://agent.example"']], params)));
  });
  it('created defaults to the current time in seconds', () => {
    const now = Math.floor(Date.now() / 1000);
    const s = signRequestMessage({ method: 'GET', url: URL1, headers: {}, key: kp.privateKey, keyid: 'k' });
    const c = Number(/created=(\d+)/.exec(s.signatureInput)?.[1]);
    expect(Math.abs(c - now)).toBeLessThan(5);
    expect(signRequestMessage({ method: 'GET', url: URL1, headers: {}, key: kp.privateKey, keyid: 'k', created: 0 }).signatureInput).toContain('created=0;');
  });

  const signed = (extra: Record<string, unknown> = {}, headers: Record<string, string> = hdr) => {
    const s = signRequestMessage({ method: 'POST', url: URL1, headers, key: kp.privateKey, keyid: 'k1', created: NOW, ...extra } as never);
    return { ...s, args: { method: 'POST', url: URL1, headers, signatureInput: s.signatureInput, signature: s.signature } };
  };
  const ok = (a: Record<string, unknown>, key: KeyObject = kp.publicKey) => verifyRequestSignature(a as never, key);

  it('verifies an honest signature and rejects any tamper', () => {
    const s = signed();
    expect(ok(s.args)).toBe(true);
    expect(ok(s.args, other.publicKey)).toBe(false);
    expect(ok({ ...s.args, method: 'GET' })).toBe(false);
    expect(ok({ ...s.args, url: `${URL1}2` })).toBe(false);
    expect(ok({ ...s.args, headers: { ...hdr, 'X-Req': 'changed' } })).toBe(false);
    expect(ok({ ...s.args, headers: { ...hdr, 'x-req': ' \tval\t ' } })).toBe(true); // values are trimmed before signing/verifying
    expect(ok({ ...s.args, headers: { 'X-REQ': 'val' } })).toBe(true); // header names case-insensitive; host derived from the URL
    expect(ok({ ...s.args, signatureInput: s.signatureInput.replace('k1', 'k2') })).toBe(false);
  });
  it('requiredComponents', () => {
    const s = signed();
    expect(ok({ ...s.args, requiredComponents: ['@method', 'host'] })).toBe(true);
    expect(ok({ ...s.args, requiredComponents: [] })).toBe(true);
    expect(ok({ ...s.args, requiredComponents: ['@authority'] })).toBe(false);
    expect(ok({ ...s.args, requiredComponents: ['@method', 'x-nope'] })).toBe(false);
  });
  it('alg parameter: absent is fine, anything but ed25519 is refused (even when correctly signed)', () => {
    const lines: [string, string][] = [['@method', 'POST']];
    const p = (alg: string) => `("@method");created=${NOW};keyid="k"${alg}`;
    const a = (alg: string) => ({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${p(alg)}`, signature: forge(p(alg), lines) });
    expect(ok(a(''))).toBe(true);
    expect(ok(a(';alg="ed25519"'))).toBe(true);
    expect(ok(a(';alg="rsa-pss-sha512"'))).toBe(false);
    expect(ok(a(';alg="rsa"'))).toBe(false);
    expect(ok(a(';alg=""'))).toBe(false);
    expect(ok(a(';alg="ED25519"'))).toBe(false);
  });
  it('freshness window: maxAgeSec and 5 s of allowed clock lead, inclusive at the edges', () => {
    const s = signed();
    const w = (o: Record<string, unknown>) => ok({ ...s.args, ...o });
    expect(w({ maxAgeSec: 60, nowSec: NOW + 60 })).toBe(true);
    expect(w({ maxAgeSec: 60, nowSec: NOW + 61 })).toBe(false);
    expect(w({ maxAgeSec: 0, nowSec: NOW })).toBe(true);
    expect(w({ maxAgeSec: 60, nowSec: NOW - 5 })).toBe(true);
    expect(w({ maxAgeSec: 60, nowSec: NOW - 6 })).toBe(false);
    expect(w({ nowSec: NOW + 100000 })).toBe(true); // no window configured
    const noCreated = `("@method");keyid="k"`;
    expect(ok({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${noCreated}`, signature: forge(noCreated, [['@method', 'POST']]), maxAgeSec: 60, nowSec: NOW })).toBe(false);
    expect(ok({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${noCreated}`, signature: forge(noCreated, [['@method', 'POST']]) })).toBe(true);
    const real = Math.floor(Date.now() / 1000);
    const fresh = signRequestMessage({ method: 'POST', url: URL1, headers: {}, key: kp.privateKey, keyid: 'k', created: real - 10 });
    expect(ok({ method: 'POST', url: URL1, headers: {}, ...fresh, maxAgeSec: 60 })).toBe(true);
    expect(ok({ method: 'POST', url: URL1, headers: {}, ...fresh, maxAgeSec: 5 })).toBe(false);
  });
  it('signature-agent: taken from the request headers, else from args, else refused', () => {
    const s = signRequestMessage({ method: 'GET', url: URL1, headers: {}, key: kp.privateKey, keyid: 'k', created: NOW, signatureAgent: 'https://a.example' });
    const base = { method: 'GET', url: URL1, headers: {}, signatureInput: s.signatureInput, signature: s.signature };
    expect(ok(base)).toBe(false);
    expect(ok({ ...base, signatureAgent: s.signatureAgent })).toBe(true);
    expect(ok({ ...base, signatureAgent: '"https://evil.example"' })).toBe(false);
    expect(ok({ ...base, headers: { 'Signature-Agent': s.signatureAgent } })).toBe(true);
    expect(ok({ ...base, headers: { 'Signature-Agent': '"https://other"' }, signatureAgent: s.signatureAgent })).toBe(false); // the header wins over the argument
  });
  it('component identifiers: @authority, whitespace handling and strict quoting', () => {
    const lines: [string, string][] = [['@authority', 'api.example.com'], ['@method', 'POST']];
    const a = (params: string, ls = lines, extra: Record<string, unknown> = {}) => ({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${params}`, signature: forge(params, ls), ...extra });
    const P = (inner: string) => `(${inner});created=${NOW}`;
    expect(ok(a(P('"@authority" "@method"')))).toBe(true);
    expect(ok(a(P('  "@authority"   "@method"  ')))).toBe(true);
    expect(ok(a(P('"@authority"\t"@method"')))).toBe(true);
    expect(ok(a(P('')))).toBe(false); // verifies only if the base had no component lines
    const emptyBase = `();created=${NOW}`;
    expect(ok({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${emptyBase}`, signature: forge(emptyBase, []) })).toBe(true);
    const blank = `(  );created=${NOW}`;
    expect(ok({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${blank}`, signature: forge(blank, []) })).toBe(true);
    for (const inner of ['@authority', 'x"@authority"', '"@authority"x', '"@authority" @method', '"@authority"y "@method"']) {
      const params = P(inner);
      expect(ok({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${params}`, signature: forge(params, lines) })).toBe(false);
    }
    for (const params of [`junk("@method");created=${NOW}`, `"@method";created=${NOW}`, `("@method";created=${NOW}`, `)("@method"`, ` ("@method");created=${NOW}`]) {
      expect(ok({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${params}`, signature: forge(params, [['@method', 'POST']]) })).toBe(false);
    }
    // ')' at index 0 is not a parameter list
    const odd = `)"@method"(;created=${NOW}`;
    expect(ok({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${odd}`, signature: forge(odd, []) })).toBe(false);
    // a covered header absent from the request cannot be verified
    const absent = `("x-absent");created=${NOW}`;
    expect(ok({ method: 'POST', url: URL1, headers: {}, signatureInput: `sig1=${absent}`, signature: forge(absent, [['x-absent', 'v']]) })).toBe(false);
  });
  it('label and signature-wrapper parsing', () => {
    const s = signed();
    const params = s.signatureInput.slice(s.signatureInput.indexOf('=') + 1);
    const sigB64 = s.signature.slice(s.signature.indexOf('=') + 1);
    expect(ok({ ...s.args, signatureInput: params })).toBe(false); // no label separator
    expect(ok({ ...s.args, signatureInput: `=${params}` })).toBe(true); // empty label: separator at index 0 is still a separator
    expect(ok({ ...s.args, signatureInput: `other=${params}` })).toBe(true);
    expect(ok({ ...s.args, signature: sigB64 })).toBe(false);
    expect(ok({ ...s.args, signature: `=${sigB64}` })).toBe(true);
    expect(ok({ ...s.args, signature: `x=  ${sigB64}  ` })).toBe(true);
    expect(ok({ ...s.args, signature: `sig1=junk${sigB64}` })).toBe(false);
    expect(ok({ ...s.args, signature: `sig1=${sigB64}junk` })).toBe(false);
    expect(ok({ ...s.args, signature: `sig1=${sigB64.slice(1, -1)}` })).toBe(false);
    expect(ok({ ...s.args, signature: 'sig1=::' })).toBe(false);
    expect(ok({ ...s.args, signature: 'sig1=:AAAA:' })).toBe(false);
  });
  it('a malformed URL or header set never throws', () => {
    const s = signed();
    expect(ok({ ...s.args, url: 'not a url', headers: {} })).toBe(false);
    expect(ok({ ...s.args, signatureInput: undefined })).toBe(false);
  });
});

describe('RFC 9421 parsing: remaining strictness', () => {
  const sigBase = (lines: [string, string][], params: string) => [...lines.map(([k, v]) => `"${k}": ${v}`), `"@signature-params": ${params}`].join('\n');
  const URL1 = 'https://api.example.com/v1/pay?x=1';
  const sign = (params: string, lines: [string, string][]) => `sig1=:${nodeSign(null, Buffer.from(sigBase(lines, params)), kp.privateKey).toString('base64')}:`;
  const run = (signatureInput: string, signature: string) => verifyRequestSignature({ method: 'POST', url: URL1, headers: {}, signatureInput, signature } as never, kp.publicKey);
  it('a parameter list without a closing parenthesis is refused even if the remainder parses', () => {
    const params = '("@method"  ';
    expect(run(`sig1=${params}`, sign(params, [['@method', 'POST']]))).toBe(false);
    const ok = '("@method")';
    expect(run(`sig1=${ok}`, sign(ok, [['@method', 'POST']]))).toBe(true);
  });
  it('a component token with leading junk before the opening quote is refused', () => {
    const params = '(x"@method");created=1';
    expect(run(`sig1=${params}`, sign(params, [['@method', 'POST']]))).toBe(false);
  });
  it('the label separator is required in both fields (no "=" anywhere means malformed)', () => {
    const params = '("@method")';
    const full = sign(params, [['@method', 'POST']]);
    expect(run(params, full)).toBe(false);
    expect(run(`sig1=${params}`, full)).toBe(true);
    const sig = full.slice(full.indexOf('=') + 1); // ":base64:" (padding '=' removed below)
    const unpadded = sig.replace(/=+/g, '');
    expect(unpadded.includes('=')).toBe(false);
    expect(run(`sig1=${params}`, unpadded)).toBe(false);
    expect(run(`sig1=${params}`, `x=${unpadded}`)).toBe(true);
  });
  it('an explicit Host header is covered as sent, not replaced by the URL host', () => {
    const headers = { Host: 'proxy.internal', 'X-A': 'a' };
    const s = signRequestMessage({ method: 'POST', url: URL1, headers, key: kp.privateKey, keyid: 'k', created: 100 });
    expect(verifyRequestSignature({ method: 'POST', url: URL1, headers, ...s } as never, kp.publicKey)).toBe(true);
    expect(verifyRequestSignature({ method: 'POST', url: URL1, headers: { ...headers, Host: 'other' }, ...s } as never, kp.publicKey)).toBe(false);
  });
});
