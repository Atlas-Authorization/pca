// Oracle: @atlasauth/pca-webauthn (WebAuthn / FIDO2 assertion verify as a PCA step-up co-sign, COSE_Key reader, challenge
// derivation, SPC payment check). Writes out/ref-webauthn-py.json.gz. Bytes are {"$bytes"}; ES256 signatures are generated with
// deterministic RFC 6979 so the corpus is stable. verifyAssertion is wrapped to return {result, regression}: the reference's
// onSignCountRegression hook is recorded. A throw only requires the native to refuse; a failed result's `reason` is compared
// exactly except for the two reasons that carry a runtime error message.
import crypto from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { Oracle, refWrite } from './lib.mjs';

let ctr = 0;
(crypto as any).randomBytes = (n: number) => crypto.createHash('sha256').update('webauthn-oracle/' + ctr++).digest().subarray(0, n);
syncBuiltinESMExports();
let wctr = 0;
Object.defineProperty(globalThis.crypto, 'getRandomValues', { value: (arr: Uint8Array) => { arr.set(crypto.createHash('sha256').update('webauthn-oracle-grv/' + wctr++).digest().subarray(0, arr.length)); return arr; }, configurable: true });

const M: any = await import('../../../packages/pca-webauthn/src/index.ts');
const P: any = await import('@atlasauth/pca');
const N: any = await import('@noble/curves/p256');
const o = new Oracle('webauthn-py', 'tools/pca-audit/oracles/webauthn-py.mts', 'TS-reference oracle for @atlasauth/pca-webauthn.');

const sha = (b: Uint8Array | Buffer | string) => new Uint8Array(crypto.createHash('sha256').update(b as any).digest());
const cat = (...a: Uint8Array[]) => new Uint8Array(Buffer.concat(a.map((x) => Buffer.from(x))));
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const hex = (s: string) => new Uint8Array(Buffer.from(s.replace(/\s+/g, ''), 'hex'));
const be32 = (n: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return new Uint8Array(b); };
const fromJ = (v: any): any => {
  if (v === null || typeof v !== 'object' || v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return v.map(fromJ);
  const ks = Object.keys(v);
  if (ks.length === 1 && ks[0] === '$bytes') return new Uint8Array(Buffer.from(v.$bytes, 'base64url'));
  return Object.fromEntries(ks.map((k) => [k, fromJ(v[k])]));
};

// ---- keys ----
const EC_D = new Uint8Array(32).map((_, i) => (i * 5 + 9) & 0xff);
const EC_PUB65 = new Uint8Array(N.p256.getPublicKey(EC_D, false));
const EC_X = EC_PUB65.slice(1, 33), EC_Y = EC_PUB65.slice(33);
const EC_JWK = { kty: 'EC', crv: 'P-256', x: b64u(EC_X), y: b64u(EC_Y) };
const ED_SEED = new Uint8Array(32).fill(7);
const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const edPriv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8, Buffer.from(ED_SEED)]), format: 'der', type: 'pkcs8' });
const ED_PUB = new Uint8Array(crypto.createPublicKey(edPriv).export({ format: 'der', type: 'spki' }).subarray(12));
const ED_JWK = { kty: 'OKP', crv: 'Ed25519', x: b64u(ED_PUB) };
const cborBytes = (b: Uint8Array) => cat(Uint8Array.of(0x58, b.length), b);
const COSE_ES = cat(hex('a5 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y));
const COSE_ED = cat(hex('a4 01 01 03 27 20 06 21'), cborBytes(ED_PUB));

const N_ORDER = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
const derInt = (x: bigint) => { let h = x.toString(16); if (h.length & 1) h = '0' + h; if (parseInt(h[0], 16) & 8) h = '00' + h; return hex(h); };
const tlv = (tag: number, v: Uint8Array) => (v.length < 128 ? cat(Uint8Array.of(tag, v.length), v) : cat(Uint8Array.of(tag, 0x81, v.length), v));
const derSig = (r: bigint, s: bigint) => tlv(0x30, cat(tlv(2, derInt(r)), tlv(2, derInt(s))));
const compact = (r: bigint, s: bigint) => hex(r.toString(16).padStart(64, '0') + s.toString(16).padStart(64, '0'));
function ecSign(signed: Uint8Array, wantHigh?: boolean) {
  const sig = N.p256.sign(sha(signed), EC_D, { lowS: false });
  let { r, s } = sig;
  const high = s > N_ORDER >> 1n;
  if (wantHigh !== undefined && wantHigh !== high) s = N_ORDER - s;
  return { r, s };
}

// ---- a real PCActn for the challenge helpers ----
const sPrin = new Uint8Array(32).fill(1), sAgent = new Uint8Array(32).fill(2);
const pk = (s: Uint8Array) => P.encodeKey(P.publicKeyOf(s));
const { grant } = P.mintGrant({ principalSecret: sPrin, principalPublic: pk(sPrin), holder: pk(sPrin), goal: 'g', envelope: { predicates: [{ verb: 'revoke_session', resource: 'session:*' }], caveats: [{ type: 'expires', at: 1_700_003_600_000 }], agent_binding: {}, risk_policy: P.DEFAULT_RISK_POLICY } });
const chain = [grant, P.delegate(grant, pk(sAgent), [{ type: 'expires', at: 1_700_000_600_000 }], sPrin)];
const PCACTN = JSON.parse(JSON.stringify(P.buildPCActn({ grant, chain, plan: [{ id: 'n1', verb: 'revoke_session', resource: 'session:s2', params_digest: undefined, reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: sAgent, aud: 'rs', now: 1_700_000_000_000, ttlMs: 600_000, nonce: 'n' })));
const { sig: _s, threshold: _t, pq_sig: _p, ...BODY } = PCACTN;
const DIGEST = sha(P.thresholdMessage(PCACTN));
const RENDER = sha(new TextEncoder().encode('render'));

// ---- constants ----
await o.run('constants', 'caps', () => ({ MAX_AUTHENTICATOR_DATA_BYTES: M.MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES: M.MAX_CLIENT_DATA_BYTES, MAX_SIGNATURE_BYTES: M.MAX_SIGNATURE_BYTES }), []);

// ---- coseKeyToJwk ----
const ck = (n: string, b: any) => o.run('coseKeyToJwk', n, (x: any) => M.coseKeyToJwk(fromJ(x)), [b]);
await ck('es256', COSE_ES);
await ck('eddsa', COSE_ED);
await ck('es256 trailing bytes', cat(COSE_ES, hex('ff ff')));
await ck('es256 key order shuffled', cat(hex('a5 20 01 22'), cborBytes(EC_Y), hex('21'), cborBytes(EC_X), hex('01 02 03 26')));
await ck('es256 extra labels', cat(hex('a7 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y), hex('18 64 18 65 19 01 00 20')));
await ck('es256 duplicate kty later wins', cat(hex('a6 01 01 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('es256 duplicate x later wins', cat(hex('a5 01 02 20 01 21'), cborBytes(new Uint8Array(32)), hex('21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('map count 1-byte arg', cat(hex('b8 05 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('map count 2-byte arg', cat(hex('b9 00 05 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('map count 4-byte arg', cat(hex('ba 00 00 00 05 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('key encoded with 1-byte arg', cat(hex('a5 18 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('kty with 2-byte arg', cat(hex('a5 01 19 00 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('byte string 2-byte length', cat(hex('a5 01 02 03 26 20 01 21 59 00 20'), EC_X, hex('22'), cborBytes(EC_Y)));
await ck('byte string 4-byte length', cat(hex('a5 01 02 03 26 20 01 21 5a 00 00 00 20'), EC_X, hex('22'), cborBytes(EC_Y)));
await ck('byte string short x', cat(hex('a5 01 02 03 26 20 01 21'), cborBytes(EC_X.slice(1)), hex('22'), cborBytes(EC_Y)));
await ck('byte string long y', cat(hex('a5 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(cat(EC_Y, Uint8Array.of(0)))));
await ck('byte string length past end', hex('a5 01 02 03 26 20 01 21 58 40 00'));
await ck('byte string length 4-byte huge', hex('a5 01 02 03 26 20 01 21 5a ff ff ff ff 00'));
await ck('missing y', cat(hex('a4 01 02 03 26 20 01 21'), cborBytes(EC_X)));
await ck('missing x', cat(hex('a4 01 02 03 26 20 01 22'), cborBytes(EC_Y)));
await ck('missing crv', cat(hex('a4 01 02 03 26 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('crv P-384', cat(hex('a5 01 02 03 26 20 02 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y)));
await ck('x is an integer', cat(hex('a5 01 02 03 26 20 01 21 05 22'), cborBytes(EC_Y)));
await ck('okp crv X25519', cat(hex('a4 01 01 03 27 20 04 21'), cborBytes(ED_PUB)));
await ck('okp crv missing', cat(hex('a3 01 01 03 27 21'), cborBytes(ED_PUB)));
await ck('okp missing x', hex('a3 01 01 03 27 20 06'));
await ck('okp short x', cat(hex('a4 01 01 03 27 20 06 21'), cborBytes(ED_PUB.slice(1))));
await ck('okp long x', cat(hex('a4 01 01 03 27 20 06 21'), cborBytes(cat(ED_PUB, Uint8Array.of(0)))));
await ck('kty RSA (3)', hex('a2 01 03 03 26'));
await ck('kty missing', hex('a1 03 26'));
await ck('kty negative', hex('a1 01 20'));
await ck('kty byte string', hex('a1 01 41 02'));
await ck('empty map', hex('a0'));
await ck('empty input', new Uint8Array(0));
await ck('truncated one byte', hex('a5'));
await ck('truncated mid-key', hex('a5 01'));
await ck('truncated mid-arg', hex('b9 00'));
await ck('truncated 4-byte arg', hex('ba 00 00 00'));
await ck('not a map (uint)', hex('01'));
await ck('not a map (bytes)', hex('41 00'));
await ck('not a map (array)', hex('80'));
await ck('text string major 3', hex('63 61 62 63'));
await ck('map with text key', hex('a1 61 61 01'));
await ck('map with bytes key', hex('a1 41 01 01'));
await ck('map with map key', hex('a1 a0 01'));
await ck('map with negative zero-ish key -1', hex('a1 20 01'));
await ck('indefinite map', hex('bf 01 02 ff'));
await ck('indefinite byte string', hex('5f 41 01 ff'));
await ck('8-byte arg', hex('1b 00 00 00 00 00 00 00 01'));
await ck('8-byte map count', hex('bb 00 00 00 00 00 00 00 01 01 02'));
await ck('reserved ai 28', hex('1c'));
await ck('array value ignored label fails', cat(hex('a6 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y), hex('18 64 80')));
await ck('tag value', hex('a1 01 c2 41 01'));
await ck('simple value', hex('a1 01 f6'));
await ck('text value', hex('a1 01 61 61'));
await ck('map count exceeds data', hex('ba ff ff ff ff 01 02'));
await ck('nested map value depth 3', cat(hex('a6 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y), hex('18 64 a1 01 a1 01 a0')));
await ck('nested map value depth 60', cat(hex('a6 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y), hex('18 64'), ...Array.from({ length: 60 }, () => hex('a1 01')), hex('00')));
await ck('nested map value truncated', cat(hex('a6 01 02 03 26 20 01 21'), cborBytes(EC_X), hex('22'), cborBytes(EC_Y), hex('18 64 a1 01')));
await ck('map value array not allowed anywhere', hex('a1 01 81 01'));
for (const bad of ['abc', null, 5, [1, 2], {}]) await o.run('coseKeyToJwk', `type ${JSON.stringify(bad)}`, M.coseKeyToJwk, [bad]);

// ---- parseAuthenticatorData ----
const pa = (n: string, b: any) => o.run('parseAuthenticatorData', n, (x: any) => M.parseAuthenticatorData(fromJ(x)), [b]);
const ADBASE = cat(sha('example.com'), Uint8Array.of(0x05), be32(5));
for (const len of [0, 1, 36]) await pa(`short ${len}`, ADBASE.slice(0, len));
await pa('exact 37', ADBASE);
await pa('with tail', cat(ADBASE, new Uint8Array(100).fill(9)));
for (const f of [0, 1, 2, 4, 8, 16, 32, 64, 128, 0x45, 0xff, 0x5d, 0xa5]) await pa(`flags ${f}`, cat(sha('x'), Uint8Array.of(f), be32(0)));
for (const c of [0, 1, 255, 256, 65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff]) await pa(`signCount ${c}`, cat(sha('x'), Uint8Array.of(0x01), be32(c)));
for (const bad of [null, 'abc', 5, [], {}, 'x'.repeat(40)]) await o.run('parseAuthenticatorData', `type ${JSON.stringify(bad)}`, M.parseAuthenticatorData, [bad]);

// ---- challenge helpers ----
const chal = (fn: string, n: string, ...a: any[]) => o.run(fn, n, (...x: any[]) => { const r = M[fn](...x.map(fromJ)); return r; }, a);
for (const fn of ['buildStepUpChallenge', 'stepUpChallengeB64u']) {
  await chal(fn, 'pcactn', PCACTN);
  await chal(fn, 'pcactn body', BODY);
  await chal(fn, 'pcactn sig changed', { ...PCACTN, sig: 'AAAA' });
  await chal(fn, 'pcactn threshold changed', { ...PCACTN, threshold: { x: 1 } });
  await chal(fn, 'pcactn action changed', { ...PCACTN, action: { ...PCACTN.action, resource: 'session:other' } });
  await chal(fn, 'digest bytes', DIGEST);
  await chal(fn, 'digest string', b64u(DIGEST));
  await chal(fn, 'bytes 31', DIGEST.slice(1));
  await chal(fn, 'bytes 33', cat(DIGEST, Uint8Array.of(0)));
  await chal(fn, 'bytes empty', new Uint8Array(0));
  await chal(fn, 'string 42 chars', b64u(DIGEST).slice(1));
  await chal(fn, 'string padded', b64u(DIGEST) + '=');
  await chal(fn, 'string non canonical', b64u(DIGEST).slice(0, -1) + 'B');
  await chal(fn, 'string std alphabet', Buffer.from(DIGEST).toString('base64'));
  await chal(fn, 'string empty', '');
  await chal(fn, 'null', null);
}
for (const fn of ['buildApprovalChallenge', 'approvalChallengeForActn']) {
  await chal(fn, 'pcactn', PCACTN, b64u(RENDER));
  await chal(fn, 'digest bytes', DIGEST, b64u(RENDER));
  await chal(fn, 'digest string', b64u(DIGEST), b64u(RENDER));
  await chal(fn, 'render bad', PCACTN, 'AAAA');
  await chal(fn, 'render empty', PCACTN, '');
  await chal(fn, 'render padded', PCACTN, b64u(RENDER) + '=');
  await chal(fn, 'render not a string', PCACTN, 5);
  await chal(fn, 'digest bad', DIGEST.slice(1), b64u(RENDER));
  await chal(fn, 'other render', PCACTN, b64u(sha('other')));
}

// ---- spcPaymentError ----
const SPC_E = { topOrigin: 'https://pay.example.com', total: { currency: 'EUR', value: '12.50' }, payeeName: 'Acme' };
const SPC_P = { rpId: 'example.com', topOrigin: 'https://pay.example.com', total: { currency: 'EUR', value: '12.50' }, payeeName: 'Acme' };
const spc = (n: string, p: any, e: any, rp = 'example.com') => o.run('spcPaymentError', n, M.spcPaymentError, [p, e, rp]);
await spc('equal', SPC_P, SPC_E);
await spc('equal with payee origin', { ...SPC_P, payeeOrigin: 'https://acme.example' }, { ...SPC_E, payeeOrigin: 'https://acme.example' });
await spc('payee origin only', { ...SPC_P, payeeOrigin: 'https://acme.example' }, { topOrigin: SPC_E.topOrigin, total: SPC_E.total, payeeOrigin: 'https://acme.example' });
for (const bad of [null, 5, 'x', [], undefined]) await spc(`payment ${JSON.stringify(bad)}`, bad, SPC_E);
await spc('payment empty object', {}, SPC_E);
await spc('expectation names no payee', SPC_P, { topOrigin: SPC_E.topOrigin, total: SPC_E.total });
await spc('expectation payee null', SPC_P, { ...SPC_E, payeeName: null });
await spc('rpId differs', { ...SPC_P, rpId: 'evil.example' }, SPC_E);
await spc('rpId missing', { ...SPC_P, rpId: undefined }, SPC_E);
await spc('rpId param differs', SPC_P, SPC_E, 'other.example');
await spc('topOrigin differs', { ...SPC_P, topOrigin: 'https://evil.example' }, SPC_E);
await spc('topOrigin missing both', { ...SPC_P, topOrigin: undefined }, { ...SPC_E, topOrigin: undefined });
await spc('topOrigin null vs missing', { ...SPC_P, topOrigin: null }, { ...SPC_E, topOrigin: undefined });
await spc('total missing', { ...SPC_P, total: undefined }, SPC_E);
await spc('total not object', { ...SPC_P, total: 5 }, SPC_E);
await spc('total array', { ...SPC_P, total: [] }, SPC_E);
await spc('currency differs', { ...SPC_P, total: { currency: 'USD', value: '12.50' } }, SPC_E);
await spc('value differs', { ...SPC_P, total: { currency: 'EUR', value: '12.5' } }, SPC_E);
await spc('value number', { ...SPC_P, total: { currency: 'EUR', value: 12.5 } }, SPC_E);
await spc('payeeName differs', { ...SPC_P, payeeName: 'Evil' }, SPC_E);
await spc('payeeName missing', { ...SPC_P, payeeName: undefined }, SPC_E);
await spc('payeeOrigin differs', { ...SPC_P, payeeOrigin: 'x' }, { ...SPC_E, payeeOrigin: 'y' });
await spc('payeeOrigin signed but not expected', { ...SPC_P, payeeOrigin: 'x' }, SPC_E);
await spc('expectation total missing throws', SPC_P, { topOrigin: SPC_E.topOrigin, payeeName: 'Acme' });
await spc('expectation null throws', SPC_P, null);

// ---- verifyAssertion ----
const RP = 'example.com', ORIGIN = 'https://example.com';
type B = Record<string, any>;
function build(b: B = {}) {
  const challenge: Uint8Array = b.challenge ?? DIGEST;
  const cd = b.clientData ?? { type: b.type ?? 'webauthn.get', challenge: b64u(challenge), origin: b.origin ?? ORIGIN, ...(b.cdExtra ?? {}) };
  for (const k of Object.keys(cd)) if (cd[k] === undefined) delete cd[k];
  const clientBytes: Uint8Array = b.clientBytes ?? new Uint8Array(Buffer.from(JSON.stringify(cd)));
  const ad: Uint8Array = b.authData ?? cat(sha(b.rpIdForHash ?? RP), Uint8Array.of(b.flags ?? 0x05), be32(b.signCount ?? 5), b.authTail ?? new Uint8Array(0));
  const signed = cat(ad, sha(clientBytes));
  const alg = b.alg ?? 'es256';
  let sig: Uint8Array;
  if (b.sig) sig = b.sig;
  else if (alg === 'eddsa') sig = new Uint8Array(crypto.sign(null, Buffer.from(signed), edPriv));
  else { const { r, s } = ecSign(signed, b.high); sig = b.compactSig ? compact(r, s) : derSig(r, s); }
  const key = 'pk' in b ? b.pk : alg === 'eddsa' ? ED_JWK : EC_JWK;
  const expect: B = { expected_challenge: challenge, rp_id: RP, origins: [ORIGIN], require_uv: true, stored_sign_count: 0, ...(b.expect ?? {}) };
  for (const k of Object.keys(expect)) if (expect[k] === undefined) delete expect[k];
  const assertion: B = { authenticator_data: ad, client_data_json: clientBytes, signature: sig, public_key: key, ...(b.asr ?? {}) };
  for (const k of Object.keys(assertion)) if (assertion[k] === undefined) delete assertion[k];
  return [assertion, expect];
}
async function verW(a: any, e: any) {
  const regression: any[] = [];
  const asr: any = {}, ex: any = {};
  for (const [k, c] of Object.entries({ authenticator_data: 'authenticatorData', client_data_json: 'clientDataJSON', signature: 'signature', public_key: 'publicKey' })) if (k in a) asr[c] = fromJ(a[k]);
  for (const [k, c] of Object.entries({ expected_challenge: 'expectedChallenge', rp_id: 'rpId', origins: 'origins', require_uv: 'requireUV', require_low_s: 'requireLowS', stored_sign_count: 'storedSignCount', reject_cross_origin: 'rejectCrossOrigin', payment: 'payment' })) if (k in e) ex[c] = fromJ(e[k]);
  ex.onSignCountRegression = (info: any) => regression.push(info);
  return { result: M.verifyAssertion(asr, ex), regression };
}
const va = (n: string, b: B = {}) => { const [a, e] = build(b); return o.run('verifyAssertion', n, verW, [a, e]); };

await va('es256 der ok');
await va('es256 compact ok', { compactSig: true });
await va('es256 cose key', { pk: COSE_ES });
await va('es256 high s default accepted', { high: true });
await va('es256 high s requireLowS', { high: true, expect: { require_low_s: true } });
await va('es256 low s requireLowS', { high: false, expect: { require_low_s: true } });
await va('es256 requireLowS false', { high: true, expect: { require_low_s: false } });
await va('es256 requireLowS truthy not true', { high: true, expect: { require_low_s: 1 } });
await va('es256 compact high s requireLowS', { high: true, compactSig: true, expect: { require_low_s: true } });
await va('eddsa jwk ok', { alg: 'eddsa' });
await va('eddsa cose key', { alg: 'eddsa', pk: COSE_ED });
await va('eddsa signature 63 bytes', { alg: 'eddsa', sig: new Uint8Array(63) });
await va('eddsa wrong key', { alg: 'eddsa', pk: { ...ED_JWK, x: b64u(new Uint8Array(32).fill(1)) } });
await va('eddsa small order key', { alg: 'eddsa', pk: { ...ED_JWK, x: b64u(hex('0100000000000000000000000000000000000000000000000000000000000000')) }, sig: hex('01' + '00'.repeat(31) + '00'.repeat(32)) });
await va('wrong key type for sig (es256 sig, eddsa key)', { pk: ED_JWK });
await va('wrong key type for sig (eddsa sig, es256 key)', { alg: 'eddsa', pk: EC_JWK });
// requireUV and flags
await va('uv not set, required', { flags: 0x01 });
await va('uv not set, not required', { flags: 0x01, expect: { require_uv: false } });
await va('uv not set, require_uv absent', { flags: 0x01, expect: { require_uv: undefined } });
await va('up not set', { flags: 0x04 });
await va('flags all', { flags: 0xff });
await va('flags backup', { flags: 0x1d });
await va('flags attested/extension', { flags: 0xc5 });
await va('auth tail present', { authTail: new Uint8Array(50).fill(3) });
// challenge
await va('challenge differs', { expect: { expected_challenge: sha('other') } });
await va('expected challenge as string', { expect: { expected_challenge: b64u(DIGEST) } });
await va('expected challenge string bad', { expect: { expected_challenge: 'not*base64' } });
await va('expected challenge null', { expect: { expected_challenge: null } });
await va('expected challenge absent', { expect: { expected_challenge: undefined } });
await va('expected challenge empty bytes', { expect: { expected_challenge: new Uint8Array(0) } });
await va('expected challenge empty string', { expect: { expected_challenge: '' } });
await va('client challenge empty both', { challenge: new Uint8Array(0), expect: { expected_challenge: new Uint8Array(0) } });
await va('client challenge padded', { cdExtra: { challenge: b64u(DIGEST) + '=' } });
await va('client challenge standard alphabet', { cdExtra: { challenge: Buffer.from(DIGEST).toString('base64') } });
await va('client challenge non canonical', { cdExtra: { challenge: b64u(DIGEST).slice(0, -1) + 'B' } });
await va('client challenge missing', { cdExtra: { challenge: undefined } });
await va('client challenge number', { cdExtra: { challenge: 5 } });
await va('client challenge truncated', { cdExtra: { challenge: b64u(DIGEST).slice(0, 20) } });
// type / origin / rp
await va('type create', { type: 'webauthn.create' });
await va('type missing', { cdExtra: { type: undefined } });
await va('type number', { cdExtra: { type: 5 } });
await va('type payment.get without payment expectation', { type: 'payment.get' });
await va('origin differs', { origin: 'https://evil.example' });
await va('origin trailing slash', { origin: ORIGIN + '/' });
await va('origin missing', { cdExtra: { origin: undefined } });
await va('origin number', { cdExtra: { origin: 5 } });
await va('origin case', { origin: 'https://Example.com' });
await va('origins second entry', { origin: 'https://b.example', expect: { origins: [ORIGIN, 'https://b.example'] } });
await va('origins with non-strings', { expect: { origins: [5, null, ORIGIN] } });
await va('origins empty', { expect: { origins: [] } });
await va('origins not array', { expect: { origins: ORIGIN } });
await va('origins absent', { expect: { origins: undefined } });
await va('rpId hash differs', { rpIdForHash: 'evil.example' });
await va('rpId empty', { expect: { rp_id: '' } });
await va('rpId absent', { expect: { rp_id: undefined } });
await va('rpId number', { expect: { rp_id: 5 } });
await va('rpId unicode', { rpIdForHash: 'café.example', expect: { rp_id: 'café.example' } });
await va('rpId lone surrogate', { rpIdForHash: '�', expect: { rp_id: '\ud800' } });
// crossOrigin
await va('crossOrigin true', { cdExtra: { crossOrigin: true } });
await va('crossOrigin false', { cdExtra: { crossOrigin: false } });
await va('crossOrigin string', { cdExtra: { crossOrigin: 'false' } });
await va('crossOrigin null', { cdExtra: { crossOrigin: null } });
await va('crossOrigin true accepted', { cdExtra: { crossOrigin: true }, expect: { reject_cross_origin: false } });
await va('crossOrigin string accepted', { cdExtra: { crossOrigin: 'x' }, expect: { reject_cross_origin: false } });
await va('crossOrigin true reject null', { cdExtra: { crossOrigin: true }, expect: { reject_cross_origin: null } });
await va('crossOrigin true reject true', { cdExtra: { crossOrigin: true }, expect: { reject_cross_origin: true } });
// clientDataJSON shapes
const cdb = (s: string | Uint8Array) => (typeof s === 'string' ? new Uint8Array(Buffer.from(s, 'utf8')) : s);
const goodCd = JSON.stringify({ type: 'webauthn.get', challenge: b64u(DIGEST), origin: ORIGIN });
await va('clientData with BOM', { clientBytes: cat(hex('ef bb bf'), cdb(goodCd)) });
await va('clientData invalid utf8', { clientBytes: cat(cdb(goodCd.slice(0, -1)), hex('c3 28'), cdb('}')) });
await va('clientData surrogate utf8', { clientBytes: hex('ed a0 80') });
await va('clientData overlong', { clientBytes: hex('c0 af') });
await va('clientData not json', { clientBytes: cdb('nope') });
await va('clientData empty', { clientBytes: new Uint8Array(0) });
await va('clientData array', { clientBytes: cdb('[]') });
await va('clientData null', { clientBytes: cdb('null') });
await va('clientData number', { clientBytes: cdb('5') });
await va('clientData string', { clientBytes: cdb('"x"') });
await va('clientData NaN', { clientBytes: cdb('{"type":NaN}') });
await va('clientData trailing comma', { clientBytes: cdb(goodCd.slice(0, -1) + ',}') });
await va('clientData whitespace around', { clientBytes: cdb(' \n' + goodCd + '\t ') });
await va('clientData duplicate key last wins', { clientBytes: cdb(`{"type":"x","type":"webauthn.get","challenge":"${b64u(DIGEST)}","origin":"${ORIGIN}"}`) });
await va('clientData escapes', { clientBytes: cdb(`{"type":"webauthn\\u002eget","challenge":"${b64u(DIGEST)}","origin":"https:\\/\\/example.com"}`) });
await va('clientData extra members', { cdExtra: { extra: [1, { a: null }], tokenBinding: { status: 'supported' } } });
await va('clientData deep nesting value', { clientBytes: cdb(`{"type":"webauthn.get","challenge":"${b64u(DIGEST)}","origin":"${ORIGIN}","x":${'['.repeat(100)}${']'.repeat(100)}}`) });
// signature over what
await va('signature over tampered clientData', { clientBytes: cdb(goodCd + ' ') , sig: build({})[0].signature });
await va('signature tampered der', { sig: (() => { const s = build({})[0].signature as Uint8Array; const c = new Uint8Array(s); c[c.length - 1] ^= 1; return c; })() });
await va('signature empty', { sig: new Uint8Array(0) });
await va('signature all zero 64', { sig: new Uint8Array(64) });
await va('signature 64 bytes starting 0x30 compact', { sig: cat(Uint8Array.of(0x30), new Uint8Array(63).fill(1)) });
await va('signature size cap', { sig: new Uint8Array(1025) });
await va('signature size cap boundary', { sig: new Uint8Array(1024) });
// DER shapes (signatures over the real signed data with crafted encodings)
{
  const signed = (() => { const [a] = build({}); return cat(a.authenticator_data, sha(a.client_data_json)); })();
  const { r, s } = ecSign(signed, false);
  const ri = derInt(r), si = derInt(s);
  const seq = (x: Uint8Array) => tlv(0x30, x);
  await va('der canonical', { sig: derSig(r, s) });
  await va('der leading zero r', { sig: seq(cat(tlv(2, cat(Uint8Array.of(0), ri)), tlv(2, si))) });
  await va('der leading zero s', { sig: seq(cat(tlv(2, ri), tlv(2, cat(Uint8Array.of(0), si)))) });
  await va('der negative r', { sig: seq(cat(tlv(2, ri.slice(ri[0] === 0 ? 1 : 0)), tlv(2, si))) });
  await va('der trailing byte', { sig: cat(derSig(r, s), Uint8Array.of(0)) });
  await va('der trailing inside seq', { sig: seq(cat(tlv(2, ri), tlv(2, si), Uint8Array.of(0))) });
  await va('der long-form length', { sig: cat(Uint8Array.of(0x30, 0x81, derSig(r, s).length - 2), derSig(r, s).slice(2)) });
  await va('der long-form length nonminimal', { sig: cat(Uint8Array.of(0x30, 0x82, 0x00, derSig(r, s).length - 2), derSig(r, s).slice(2)) });
  await va('der wrong tag', { sig: cat(Uint8Array.of(0x31), derSig(r, s).slice(1)) });
  await va('der wrong int tag', { sig: seq(cat(tlv(3, ri), tlv(2, si))) });
  await va('der length too long', { sig: cat(Uint8Array.of(0x30, derSig(r, s).length - 1), derSig(r, s).slice(2)) });
  await va('der length too short', { sig: cat(Uint8Array.of(0x30, derSig(r, s).length - 3), derSig(r, s).slice(2)) });
  await va('der r zero', { sig: derSig(0n, s) });
  await va('der s zero', { sig: derSig(r, 0n) });
  await va('der r = n', { sig: derSig(N_ORDER, s) });
  await va('der s = n', { sig: derSig(r, N_ORDER) });
  await va('der r > n', { sig: derSig(N_ORDER + 5n, s) });
  await va('der empty ints', { sig: seq(cat(tlv(2, new Uint8Array(0)), tlv(2, new Uint8Array(0)))) });
  await va('der one int', { sig: seq(tlv(2, ri)) });
  await va('der three ints', { sig: seq(cat(tlv(2, ri), tlv(2, si), tlv(2, si))) });
  await va('compact r=0', { sig: compact(0n, s) });
  await va('compact s=n', { sig: compact(r, N_ORDER) });
  await va('compact valid', { sig: compact(r, s) });
  await va('compact 65 bytes', { sig: cat(compact(r, s), Uint8Array.of(0)) });
  await va('compact 63 bytes', { sig: compact(r, s).slice(1) });
}
// public key shapes
for (const [n, k] of Object.entries({
  'jwk es256 with alg': { ...EC_JWK, alg: 'ES256' }, 'jwk es256 padded coords': { ...EC_JWK, x: EC_JWK.x + '=' }, 'jwk es256 std alphabet': { ...EC_JWK, x: Buffer.from(EC_X).toString('base64') }, 'jwk es256 short x': { ...EC_JWK, x: EC_JWK.x.slice(2) },
  'jwk es256 non-canonical y': { ...EC_JWK, y: EC_JWK.y.slice(0, -1) + 'B' }, 'jwk es256 non-canonical x': { ...EC_JWK, x: EC_JWK.x.slice(0, -1) + 'B' }, 'jwk es256 x number': { ...EC_JWK, x: 5 }, 'jwk es256 missing y': { kty: 'EC', crv: 'P-256', x: EC_JWK.x }, 'jwk es256 wrong crv': { ...EC_JWK, crv: 'P-384' }, 'jwk es256 point off curve': { ...EC_JWK, y: b64u(new Uint8Array(32).fill(5)) },
  'jwk okp wrong crv': { ...ED_JWK, crv: 'Ed448' }, 'jwk okp short x': { ...ED_JWK, x: 'AAAA' }, 'jwk rsa': { kty: 'RSA', n: 'AQAB', e: 'AQAB' }, 'jwk no kty': { x: 'a' }, 'jwk empty': {}, 'null': null, 'string': 'abc', 'number': 5, 'array': [], 'cose garbage': hex('a1 01 03'), 'cose empty': new Uint8Array(0), 'cose truncated': COSE_ES.slice(0, 20),
})) await va(`key ${n}`, { pk: k });
await va('key absent', { pk: undefined });
// sizes
await va('authData size cap boundary', { authTail: new Uint8Array(4096 - 37) });
await va('authData over cap', { authTail: new Uint8Array(4096 - 36) });
await va('clientData size cap boundary', { clientBytes: cdb(goodCd.slice(0, -1) + ',"p":"' + 'a'.repeat(8192 - goodCd.length - 7) + '"}') });
await va('clientData over cap', { clientBytes: cdb(goodCd.slice(0, -1) + ',"p":"' + 'a'.repeat(8192 - goodCd.length - 6) + '"}') });
await va('authData short 36', { authData: cat(sha(RP), Uint8Array.of(5), new Uint8Array(3)) });
await va('authData empty', { authData: new Uint8Array(0) });
// field types
for (const k of ['authenticator_data', 'client_data_json', 'signature']) {
  await va(`${k} string`, { asr: { [k]: 'abc' } });
  await va(`${k} missing`, { asr: { [k]: undefined } });
  await va(`${k} number array`, { asr: { [k]: [1, 2, 3] } });
  await va(`${k} null`, { asr: { [k]: null } });
}
// counters
for (const [n, st, sc] of [['both zero', 0, 0], ['stored zero reported positive', 0, 5], ['stored equals reported', 5, 5], ['reported lower', 9, 5], ['reported higher', 4, 5], ['stored positive reported zero', 3, 0], ['max', 0xfffffffe, 0xffffffff], ['max equal', 0xffffffff, 0xffffffff], ['stored too big', 0x100000000, 5], ['stored negative', -1, 5], ['stored fraction', 1.5, 5], ['stored -0', -0, 5], ['stored string', '0', 5], ['stored null', null, 5], ['stored bool', false, 5], ['stored array', [], 5]] as const)
  await va(`counter ${n}`, { signCount: sc, expect: { stored_sign_count: st } });
await va('counter missing', { expect: { stored_sign_count: undefined } });
await va('counter regression with bad signature does not call hook', { signCount: 1, sig: new Uint8Array(64), expect: { stored_sign_count: 9 } });
await va('counter invalid uint32 with bad signature', { sig: new Uint8Array(64), expect: { stored_sign_count: -1 } });
// SPC
const spcCd = (extra: any) => ({ type: 'payment.get', payment: { ...SPC_P, ...extra } });
const spcB = (cdExtra: any, expectExtra: any = {}) => ({ clientData: { type: 'payment.get', challenge: b64u(DIGEST), origin: ORIGIN, payment: { ...SPC_P, ...cdExtra } }, expect: { payment: SPC_E, ...expectExtra } });
await va('spc ok', spcB({}));
await va('spc plain get refused when expectation set', { expect: { payment: SPC_E } });
await va('spc payment.get without payment data', { clientData: { type: 'payment.get', challenge: b64u(DIGEST), origin: ORIGIN }, expect: { payment: SPC_E } });
await va('spc total differs', spcB({ total: { currency: 'EUR', value: '99.00' } }));
await va('spc payee differs', spcB({ payeeName: 'Evil' }));
await va('spc topOrigin differs', spcB({ topOrigin: 'https://evil.example' }));
await va('spc rpId differs', spcB({ rpId: 'evil.example' }));
await va('spc expectation no payee', spcB({}, { payment: { topOrigin: SPC_E.topOrigin, total: SPC_E.total } }));
await va('spc expectation null', spcB({}, { payment: null }));
await va('spc expectation total missing', spcB({}, { payment: { topOrigin: SPC_E.topOrigin, payeeName: 'Acme' } }));
void spcCd;
// expect shapes
await va('expect missing storedSignCount reported first', { expect: { stored_sign_count: undefined, rp_id: undefined } });
await va('assertion extra members ignored', { asr: { extra: 1 } });

refWrite(o, 'webauthn-py');
