// Oracle: @atlasauth/pca-webauthn (WebAuthn / FIDO2 assertion verification as the PCA step-up co-sign: COSE_Key reader, authenticatorData
// header, step-up / approval challenges, Secure Payment Confirmation, verifyAssertion). Deterministic: keys come from seeds, EdDSA and
// RFC 6979 ECDSA signatures are reproducible. Writes out/ref-webauthn.json.gz.
// Bytes are {"$bytes": b64url} anywhere in the args (also nested). A throw requires the native to throw.
// PORTING (fn -> Java net.atlasauth.pca.webauthn.Webauthn; comparison = canonical JSON equality unless noted)
//   constants()                              {MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES, MAX_SIGNATURE_BYTES}
//   coseKeyToJwk(bytes)                      coseKeyToJwk(byte[]) -> JWK map
//   parseAuthenticatorData(bytes)            parseAuthenticatorData(b) -> null | {rpIdHash:bytes, flags:{up,uv,be,bs,at,ed}, signCount}; a non-bytes arg -> null
//   buildStepUpChallenge / buildApprovalChallenge(x, renderDigest) / approvalChallengeForActn / stepUpChallengeB64u   same names; bytes or string results
//   spcPaymentError(payment, expectation, rpId)  exact string | null
//   verifyAssertion(assertion, expect)       {result, hook}: result = {ok:true, alg, signCount, flags} | {ok:false, reason}; a reason that starts
//                                            "public key could not be resolved:" or "verification error (fail closed):" is cut at the colon (the
//                                            tail is the JS engine's message). expect.hook:true installs onSignCountRegression and `hook` lists its calls.
import * as M0 from '@atlasauth/pca-webauthn';
import { createHash } from 'node:crypto';
import { Oracle, refWrite, seed, variants } from './lib.mjs';
import { b64, ecKit, edKit, rev, unb, utf8 } from './idkit.mjs';

const M: any = (M0 as any).default ?? M0;
const o = new Oracle('webauthn', 'tools/pca-audit/oracles/webauthn.mts', 'TS-reference oracle for the WebAuthn step-up co-sign.');
const sha = (u: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(u).digest());
const bytes = (u: ArrayLike<number>) => ({ $bytes: b64(Uint8Array.from(u)) });
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

// ---- CBOR builders ----
const head = (major: number, n: number): number[] => (n < 24 ? [(major << 5) | n] : n < 256 ? [(major << 5) | 24, n] : n < 65536 ? [(major << 5) | 25, n >> 8, n & 255] : [(major << 5) | 26, (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const cInt = (n: number): number[] => (n >= 0 ? head(0, n) : head(1, -1 - n));
const cBytes = (b: ArrayLike<number>): number[] => [...head(2, b.length), ...Array.from(b)];
const cMap = (pairs: Array<[number[], number[]]>): number[] => [...head(5, pairs.length), ...pairs.flatMap(([k, v]) => [...k, ...v])];
const E = ecKit('P-256', 'webauthn/es256');
const E_HIGH = ecKit('P-256', 'webauthn/es256-b');
const ED = edKit('webauthn/ed25519');
const ED2 = edKit('webauthn/ed25519-b');
const E2 = ecKit('P-256', 'webauthn/other');
const E384 = ecKit('P-384', 'webauthn/p384');
const coseEc = (k: any, over: Array<[number[], number[]]> = []): number[] => cMap([[cInt(1), cInt(2)], [cInt(3), cInt(-7)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(unb(k.pub.x))], [cInt(-3), cBytes(unb(k.pub.y))], ...over]);
const coseEd = (k: any): number[] => cMap([[cInt(1), cInt(1)], [cInt(3), cInt(-8)], [cInt(-1), cInt(6)], [cInt(-2), cBytes(unb(k.pub.x))]]);

// ---- constants ----
await o.run('constants', 'all', () => ({ MAX_AUTHENTICATOR_DATA_BYTES: M.MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES: M.MAX_CLIENT_DATA_BYTES, MAX_SIGNATURE_BYTES: M.MAX_SIGNATURE_BYTES }), []);

// ---- coseKeyToJwk ----
const cose = (name: string, b: any) => o.run('coseKeyToJwk', name, (x: any) => M.coseKeyToJwk(rev(x)), [b]);
const EC1 = coseEc(E), ED1 = coseEd(ED);
await cose('ec2', bytes(EC1));
await cose('okp', bytes(ED1));
await cose('ec2 extra label first', bytes(cMap([[cInt(7), cInt(9)], [cInt(1), cInt(2)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(unb(E.pub.x))], [cInt(-3), cBytes(unb(E.pub.y))]])));
await cose('ec2 duplicate kty (last wins)', bytes(cMap([[cInt(1), cInt(1)], [cInt(1), cInt(2)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(unb(E.pub.x))], [cInt(-3), cBytes(unb(E.pub.y))]])));
await cose('ec2 trailing bytes', bytes([...EC1, 0xff, 0xff]));
await cose('okp trailing bytes', bytes([...ED1, 1]));
for (let i = 0; i < EC1.length; i++) await cose(`ec2 prefix ${i}`, bytes(EC1.slice(0, i)));
for (let i = 0; i < ED1.length; i += 3) await cose(`okp prefix ${i}`, bytes(ED1.slice(0, i)));
for (const [n, k] of [['kty 3', 3], ['kty 0', 0], ['kty -1', -1], ['kty 1000', 1000], ['kty 70000', 70000]] as const) await cose('ec2 ' + n, bytes(cMap([[cInt(1), cInt(k)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(unb(E.pub.x))], [cInt(-3), cBytes(unb(E.pub.y))]])));
for (const [n, c] of [['crv 2', 2], ['crv 6', 6], ['crv 0', 0], ['crv -1', -1], ['crv 300', 300]] as const) {
  await cose('ec2 ' + n, bytes(cMap([[cInt(1), cInt(2)], [cInt(-1), cInt(c)], [cInt(-2), cBytes(unb(E.pub.x))], [cInt(-3), cBytes(unb(E.pub.y))]])));
  await cose('okp ' + n, bytes(cMap([[cInt(1), cInt(1)], [cInt(-1), cInt(c)], [cInt(-2), cBytes(unb(ED.pub.x))]])));
}
const xy = (xl: number, yl: number) => bytes(cMap([[cInt(1), cInt(2)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(new Uint8Array(xl).fill(7))], [cInt(-3), cBytes(new Uint8Array(yl).fill(9))]]));
for (const [x, y] of [[31, 32], [32, 31], [33, 32], [32, 33], [0, 0], [64, 64], [32, 32], [300, 32]]) await cose(`ec2 coords ${x},${y}`, xy(x, y));
for (const l of [0, 31, 32, 33, 57, 300]) await cose(`okp x ${l}`, bytes(cMap([[cInt(1), cInt(1)], [cInt(-1), cInt(6)], [cInt(-2), cBytes(new Uint8Array(l).fill(5))]])));
await cose('ec2 missing x', bytes(cMap([[cInt(1), cInt(2)], [cInt(-1), cInt(1)], [cInt(-3), cBytes(unb(E.pub.y))]])));
await cose('ec2 missing y', bytes(cMap([[cInt(1), cInt(2)], [cInt(-1), cInt(1)], [cInt(-2), cBytes(unb(E.pub.x))]])));
await cose('ec2 x not bytes', bytes(cMap([[cInt(1), cInt(2)], [cInt(-1), cInt(1)], [cInt(-2), cInt(5)], [cInt(-3), cBytes(unb(E.pub.y))]])));
await cose('ec2 missing crv', bytes(cMap([[cInt(1), cInt(2)], [cInt(-2), cBytes(unb(E.pub.x))], [cInt(-3), cBytes(unb(E.pub.y))]])));
await cose('okp missing x', bytes(cMap([[cInt(1), cInt(1)], [cInt(-1), cInt(6)]])));
await cose('missing kty', bytes(cMap([[cInt(-1), cInt(1)]])));
await cose('empty map', bytes([0xa0]));
await cose('not a map: int', bytes([0x01]));
await cose('not a map: bytes', bytes([0x41, 1]));
await cose('not a map: array', bytes([0x80]));
await cose('not a map: text', bytes([0x61, 0x61]));
await cose('not a map: tag', bytes([0xc1, 0x01]));
await cose('not a map: simple', bytes([0xf6]));
await cose('empty', bytes([]));
await cose('indefinite map', bytes([0xbf, 0x01, 0x02, 0xff]));
await cose('8-byte arg map', bytes([0xbb, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0x02]));
await cose('map arg 24', bytes([0xb8, 0, ...[]]));
await cose('map arg 25 truncated', bytes([0xb9, 0, 5, 0x01, 0x02]));
await cose('map arg 26 truncated', bytes([0xba, 0, 0, 0, 5, 0x01, 0x02]));
await cose('map text key', bytes([0xa1, 0x61, 0x61, 0x01]));
await cose('map bytes key', bytes([0xa1, 0x41, 0x01, 0x01]));
await cose('map map value', bytes([0xa1, 0x01, 0xa0]));
await cose('map array value', bytes([0xa1, 0x01, 0x80]));
await cose('map text value', bytes([0xa2, 0x01, 0x62, 0x68, 0x69, 0x02, 0x03]));
await cose('big int key', bytes([0xa1, 0x1a, 0xff, 0xff, 0xff, 0xff, 0x01]));
await cose('neg int key', bytes([0xa1, 0x3a, 0xff, 0xff, 0xff, 0xff, 0x01]));
await cose('bytes length overruns', bytes([0xa1, 0x01, 0x59, 0xff, 0xff, 0x00]));
await cose('bytes arg 26 huge', bytes([0xa1, 0x01, 0x5a, 0xff, 0xff, 0xff, 0xff]));
await cose('ai 28', bytes([0xa1, 0x01, 0x1c]));
for (const [n, v] of [['string', 'abc'], ['null', null], ['number', 5], ['array', [1, 2]], ['object', {}]] as const) await cose('arg ' + n, v);
for (let b = 0; b < 256; b += 5) await cose(`first byte ${b}`, bytes([b, 1, 2, 3]));

// ---- parseAuthenticatorData ----
const ad = (n: number, flags = 0x05, signCount = 0) => { const b = new Uint8Array(n); for (let i = 0; i < Math.min(n, 32); i++) b[i] = (i * 7 + 3) & 255; if (n > 32) b[32] = flags; if (n >= 37) new DataView(b.buffer).setUint32(33, signCount, false); for (let i = 37; i < n; i++) b[i] = i & 255; return b; };
for (const n of [0, 1, 31, 32, 33, 36, 37, 38, 55, 100, 4096, 4097]) await o.run('parseAuthenticatorData', `len ${n}`, (x: any) => M.parseAuthenticatorData(rev(x)), [bytes(ad(n))]);
for (let f = 0; f < 256; f++) await o.run('parseAuthenticatorData', `flags ${f}`, (x: any) => M.parseAuthenticatorData(rev(x)), [bytes(ad(37, f, f * 1000))]);
for (const sc of [0, 1, 255, 256, 65535, 65536, 2 ** 24, 2 ** 31 - 1, 2 ** 31, 2 ** 32 - 1]) await o.run('parseAuthenticatorData', `signCount ${sc}`, (x: any) => M.parseAuthenticatorData(rev(x)), [bytes(ad(37, 5, sc))]);
for (const [n, v] of [['null', null], ['string', 'x'], ['array', [1, 2, 3]], ['number', 5], ['object', {}]] as const) await o.run('parseAuthenticatorData', `arg ${n}`, (x: any) => M.parseAuthenticatorData(rev(x)), [v]);

// ---- challenges ----
const PC = { ver: 2, aud: 'rs', iat: 1_800_000_000_000, exp: 1_800_000_600_000, cap_chain: [{ issuer: 'a', holder: 'b', caveats: [] }], action: { verb: 'pay', resource: 'acct:1', params: { n: 5, tags: ['a', 'b'] } }, nonce: 'n', sig: 'x', threshold: { t: 2 }, pq_sig: 'y' };
const D32 = b64(sha(utf8('digest')));
const RD = b64(sha(utf8('render')));
const stepIn: Array<[string, any]> = [
  ['pcactn', PC], ['pcactn no sig/threshold/pq_sig', (({ sig, threshold, pq_sig, ...b }) => b)(PC)], ['pcactn other sig', { ...PC, sig: 'zzz', threshold: undefined, pq_sig: 'q' }], ['pcactn key order', { nonce: 'n', ...PC }],
  ['pcactn extra member', { ...PC, extra: [1, { a: null }] }], ['pcactn float', { ...PC, caution: 0.25 }], ['pcactn neg zero', { ...PC, caution: -0 }], ['pcactn big int', { ...PC, big: 2 ** 53 }], ['pcactn unicode', { ...PC, u: 'café 😀' }],
  ['pcactn lone surrogate', { ...PC, u: '\ud800' }], ['pcactn deep', { ...PC, d: JSON.parse('['.repeat(40) + ']'.repeat(40)) }], ['empty object', {}], ['array', [1, 2]], ['empty array', []], ['null', null], ['number', 5], ['boolean', true],
  ['digest bytes', bytes(sha(utf8('d')))], ['digest bytes 31', bytes(new Uint8Array(31))], ['digest bytes 33', bytes(new Uint8Array(33))], ['digest bytes 0', bytes(new Uint8Array(0))],
  ['digest b64u', D32], ['digest padded', D32 + '='], ['digest std alphabet', D32.replace(/-/g, '+').replace(/_/g, '/') + 'x'], ['digest short', D32.slice(0, -1)], ['digest long', D32 + 'A'], ['digest empty', ''], ['digest trailing bits', D32.slice(0, -1) + (D32.endsWith('A') ? 'B' : 'A')],
  ['digest 64 bytes', b64(new Uint8Array(64))], ['digest space', D32 + ' '],
];
for (const [n, v] of stepIn) {
  await o.run('buildStepUpChallenge', n, (x: any) => M.buildStepUpChallenge(rev(x)), [v]);
  await o.run('stepUpChallengeB64u', n, (x: any) => M.stepUpChallengeB64u(rev(x)), [v]);
  for (const [rn, rd] of [['ok', RD], ['bad', 'x'], ['padded', RD + '='], ['empty', ''], ['null', null], ['number', 5]] as const) {
    if (rn !== 'ok' && !['pcactn', 'digest b64u', 'digest bytes'].includes(n)) continue;
    await o.run('buildApprovalChallenge', `${n} / ${rn}`, (x: any, r: any) => M.buildApprovalChallenge(rev(x), r), [v, rd]);
    await o.run('approvalChallengeForActn', `${n} / ${rn}`, (x: any, r: any) => M.approvalChallengeForActn(rev(x), r), [v, rd]);
  }
}

// ---- spcPaymentError ----
const PAYE = { topOrigin: 'https://pay.example.com', total: { currency: 'EUR', value: '12.50' }, payeeName: 'ACME', payeeOrigin: 'https://acme.example' };
const PAY = { rpId: 'login.example.com', topOrigin: 'https://pay.example.com', total: { currency: 'EUR', value: '12.50' }, payeeName: 'ACME', payeeOrigin: 'https://acme.example' };
const spc = (n: string, p: any, e: any, rp = 'login.example.com') => o.run('spcPaymentError', n, M.spcPaymentError, [p, e, rp]);
await spc('equal', PAY, PAYE);
await spc('payee name only', PAY, { ...PAYE, payeeOrigin: undefined });
await spc('payee origin only', PAY, { ...PAYE, payeeName: undefined });
await spc('no payee expected', PAY, { ...PAYE, payeeName: undefined, payeeOrigin: undefined });
await spc('expected payee not signed', { ...PAY, payeeName: undefined }, PAYE);
await spc('wrong rpId arg', PAY, PAYE, 'other');
for (const [n, p] of Object.entries({ missing: undefined, null: null, string: 'x', number: 5, array: [], empty: {}, 'rpId missing': { ...PAY, rpId: undefined }, 'rpId other': { ...PAY, rpId: 'x' }, 'rpId number': { ...PAY, rpId: 5 },
  'top other': { ...PAY, topOrigin: 'https://evil' }, 'top missing': { ...PAY, topOrigin: undefined }, 'total missing': { ...PAY, total: undefined }, 'total string': { ...PAY, total: 'x' }, 'total array': { ...PAY, total: [] },
  'cur other': { ...PAY, total: { currency: 'USD', value: '12.50' } }, 'val other': { ...PAY, total: { currency: 'EUR', value: '12.5' } }, 'val number': { ...PAY, total: { currency: 'EUR', value: 12.5 } }, 'cur missing': { ...PAY, total: { value: '12.50' } },
  'name other': { ...PAY, payeeName: 'Evil' }, 'origin other': { ...PAY, payeeOrigin: 'https://evil' }, 'name number': { ...PAY, payeeName: 5 }, extra: { ...PAY, extra: 1 } })) await spc(`payment ${n}`, p, PAYE);
for (const [n, e] of Object.entries({ 'top missing': { ...PAYE, topOrigin: undefined }, 'payee null': { ...PAYE, payeeName: null }, 'total missing': { ...PAYE, total: undefined } })) await spc(`expectation ${n}`, PAY, e);
await spc('expectation top missing, payment top missing', { ...PAY, topOrigin: undefined }, { ...PAYE, topOrigin: undefined });

// ---- verifyAssertion ----
const RP = 'login.example.com', ORIGIN = 'https://login.example.com';
const CH = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const cat = (...p: Uint8Array[]) => { const out = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let k = 0; for (const x of p) { out.set(x, k); k += x.length; } return out; };
const authData = (signCount: number, flags = 0x05, size = 37, rp = RP) => { const out = new Uint8Array(size); out.set(sha(utf8(rp)).subarray(0, Math.min(32, size)), 0); if (size > 32) out[32] = flags; if (size >= 37) new DataView(out.buffer).setUint32(33, signCount, false); return out; };
const clientData = (over: any = {}) => utf8(JSON.stringify({ type: 'webauthn.get', challenge: b64(CH), origin: ORIGIN, crossOrigin: false, ...over }));
const derOf = (sig: Uint8Array): Uint8Array => {
  const enc = (v: Uint8Array) => { let i = 0; while (i < v.length - 1 && v[i] === 0) i++; let x = Array.from(v.subarray(i)); if ((x[0] as number) & 0x80) x = [0, ...x]; return [0x02, x.length, ...x]; };
  const r = enc(sig.subarray(0, 32)), s = enc(sig.subarray(32));
  return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
};
const highS = (sig: Uint8Array): Uint8Array => {
  const s = BigInt('0x' + Buffer.from(sig.subarray(32)).toString('hex'));
  const hs = s > N / 2n ? s : N - s;
  return cat(sig.subarray(0, 32), new Uint8Array(Buffer.from(hs.toString(16).padStart(64, '0'), 'hex')));
};
const lowS = (sig: Uint8Array): Uint8Array => {
  const s = BigInt('0x' + Buffer.from(sig.subarray(32)).toString('hex'));
  const ls = s > N / 2n ? N - s : s;
  return cat(sig.subarray(0, 32), new Uint8Array(Buffer.from(ls.toString(16).padStart(64, '0'), 'hex')));
};
type Mk = { kit?: any; signCount?: number; flags?: number; authSize?: number; client?: any; clientBytes?: Uint8Array; sig?: 'der' | 'raw' | 'high-der' | 'high-raw'; pub?: 'jwk' | 'cose'; signRp?: string; tamper?: (a: any) => any };
function mk(m: Mk = {}) {
  const kit = m.kit ?? E;
  const a = authData(m.signCount ?? 1, m.flags ?? 0x05, m.authSize ?? 37, m.signRp ?? RP);
  const c = m.clientBytes ?? clientData(m.client);
  const signed = cat(a, sha(c));
  let sig = kit.sign(signed);
  if (kit.alg === 'ES256') {
    const fmt = m.sig ?? 'der';
    if (fmt.startsWith('high')) sig = highS(sig); else sig = lowS(sig);
    if (fmt.endsWith('der')) sig = derOf(sig);
  }
  const pk = m.pub === 'cose' ? (kit.alg === 'ES256' ? coseEc(kit) : coseEd(kit)) : null;
  return { authenticatorData: bytes(a), clientDataJSON: bytes(c), signature: bytes(sig), publicKey: pk ? bytes(pk) : { ...kit.pub, ...(kit.alg === 'ES256' ? { alg: 'ES256' } : { alg: 'EdDSA' }) } };
}
const EXP = (over: any = {}) => ({ expectedChallenge: bytes(CH), rpId: RP, origins: [ORIGIN], requireUV: true, storedSignCount: 0, ...over });
const normReason = (r: any) => (r && typeof r.reason === 'string' ? { ...r, reason: r.reason.replace(/^(public key could not be resolved|verification error \(fail closed\)):.*$/s, '$1') } : r);
async function verifyW(assertion: any, expect: any) {
  const e: any = rev(expect);
  const calls: any[] = [];
  if (e.hook) { delete e.hook; e.onSignCountRegression = (i: any) => calls.push(i); }
  const result = M.verifyAssertion(rev(assertion), e);
  return { result: normReason(result), hook: calls };
}
const va = (n: string, a: any, e: any = EXP()) => o.run('verifyAssertion', n, verifyW, [a, e]);
const MKS: Array<[string, Mk]> = [['es256 der', {}], ['es256 raw', { sig: 'raw' }], ['es256 high-s der', { sig: 'high-der' }], ['es256 high-s raw', { sig: 'high-raw' }], ['es256 cose', { pub: 'cose' }], ['ed25519', { kit: ED }], ['ed25519 cose', { kit: ED, pub: 'cose' }], ['es256 other key', { kit: E_HIGH }]];
for (const [n, m] of MKS) {
  await va('valid ' + n, mk(m));
  await va('valid ' + n + ' lowS required', mk(m), EXP({ requireLowS: true }));
  await va('valid ' + n + ' string challenge', mk(m), EXP({ expectedChallenge: b64(CH) }));
}
const A = mk();
const withA = (over: any) => ({ ...A, ...over });
// types and sizes
for (const f of ['authenticatorData', 'clientDataJSON', 'signature']) for (const [n, v] of [['string', 'abc'], ['null', null], ['number', 5], ['array', [1, 2]], ['object', {}], ['missing', undefined]] as const) await va(`${f} ${n}`, withA({ [f]: v }));
await va('authData 4096', mk({ authSize: 4096 }));
await va('authData 4097', mk({ authSize: 4097 }));
await va('authData 36', mk({ authSize: 36 }));
await va('authData 0', withA({ authenticatorData: bytes([]) }));
await va('clientData 8192', mk({ clientBytes: clientData({ pad: 'a'.repeat(8192 - clientData({ pad: '' }).length) }) }));
await va('clientData 8193', mk({ clientBytes: clientData({ pad: 'a'.repeat(8193 - clientData({ pad: '' }).length) }) }));
await va('signature 1024', withA({ signature: bytes(new Uint8Array(1024).fill(1)) }));
await va('signature 1025', withA({ signature: bytes(new Uint8Array(1025).fill(1)) }));
await va('signature empty', withA({ signature: bytes([]) }));
await va('signature 64 zero', withA({ signature: bytes(new Uint8Array(64)) }));
await va('signature 63', withA({ signature: bytes(new Uint8Array(63).fill(1)) }));
await va('signature 71 starts 0x30', withA({ signature: bytes(Uint8Array.from([0x30, ...new Uint8Array(70).fill(1)])) }));
// client data shapes
for (const [n, b] of [['not utf8', Uint8Array.from([0xff, 0xfe, 0x7b, 0x7d])], ['bom json', cat(Uint8Array.from([0xef, 0xbb, 0xbf]), clientData())], ['not json', utf8('nope')], ['array', utf8('[]')], ['string', utf8('"x"')], ['null', utf8('null')], ['number', utf8('5')], ['empty', utf8('')],
  ['duplicate key', utf8(`{"type":"webauthn.get","type":"webauthn.get","challenge":"${b64(CH)}","origin":"${ORIGIN}"}`)], ['whitespace', utf8(' ' + JSON.stringify({ type: 'webauthn.get', challenge: b64(CH), origin: ORIGIN }))],
  ['extra members', clientData({ extra: { a: [1] }, tokenBinding: { status: 'present' } })], ['unicode', clientData({ u: 'café 😀' })], ['no crossOrigin', utf8(JSON.stringify({ type: 'webauthn.get', challenge: b64(CH), origin: ORIGIN }))]] as Array<[string, Uint8Array]>)
  await va('client ' + n, mk({ clientBytes: b }));
for (const [k, vs] of Object.entries({
  type: [undefined, null, 5, '', 'webauthn.create', 'payment.get', 'WEBAUTHN.GET', ['webauthn.get'], {}, true],
  challenge: [undefined, null, 5, '', b64(CH) + '=', b64(CH).replace(/-/g, '+'), b64(CH.slice(0, 31)), b64(new Uint8Array(33)), b64(CH).slice(0, -1), b64(CH).slice(0, -1) + 'B', ' ' + b64(CH), [b64(CH)]],
  origin: [undefined, null, 5, '', 'https://evil.example.com', 'https://login.example.com/', 'HTTPS://LOGIN.EXAMPLE.COM', 'http://login.example.com', 'https://login.example.com:443', ['https://login.example.com']],
  crossOrigin: [true, false, null, 0, 1, 'false', 'true', [], {}],
}) as Array<[string, any[]]>) for (const [i, v] of vs.entries()) {
  await va(`client ${k}=${JSON.stringify(v)} #${i}`, mk({ client: { [k]: v } }));
  if (k === 'crossOrigin') await va(`client crossOrigin=${JSON.stringify(v)} allowed #${i}`, mk({ client: { [k]: v } }), EXP({ rejectCrossOrigin: false }));
}
await va('client crossOrigin absent', mk({ clientBytes: utf8(JSON.stringify({ type: 'webauthn.get', challenge: b64(CH), origin: ORIGIN })) }), EXP({ rejectCrossOrigin: true }));
// challenge expectations
await va('expected challenge other bytes', A, EXP({ expectedChallenge: bytes(new Uint8Array(32).fill(1)) }));
await va('expected challenge empty bytes', A, EXP({ expectedChallenge: bytes([]) }));
await va('expected challenge 31 bytes', A, EXP({ expectedChallenge: bytes(CH.slice(0, 31)) }));
for (const [n, v] of [['string other', b64(new Uint8Array(32).fill(1))], ['string padded', b64(CH) + '='], ['string empty', ''], ['string bad', '!!!'], ['null', null], ['number', 5], ['array', []], ['missing', undefined], ['object', {}]] as const) await va('expected challenge ' + n, A, EXP({ expectedChallenge: v }));
// expectations
for (const [n, e] of Object.entries({
  'rpId empty': { rpId: '' }, 'rpId missing': { rpId: undefined }, 'rpId number': { rpId: 5 }, 'rpId other': { rpId: 'other.example.com' }, 'rpId upper': { rpId: 'LOGIN.EXAMPLE.COM' },
  'origins empty': { origins: [] }, 'origins missing': { origins: undefined }, 'origins string': { origins: ORIGIN }, 'origins null': { origins: null }, 'origins several': { origins: ['https://a', ORIGIN, 'https://b'] }, 'origins non-string': { origins: [5, null, ORIGIN] },
  'origins other': { origins: ['https://other'] }, 'requireUV false': { requireUV: false }, 'requireUV missing': { requireUV: undefined }, 'requireUV 1': { requireUV: 1 }, 'requireUV string': { requireUV: 'yes' }, 'requireUV empty string': { requireUV: '' },
  'requireLowS 1': { requireLowS: 1 }, 'requireLowS false': { requireLowS: false },
  'stored missing': { storedSignCount: undefined }, 'stored null': { storedSignCount: null }, 'stored string': { storedSignCount: '0' }, 'stored -1': { storedSignCount: -1 }, 'stored 1.5': { storedSignCount: 1.5 }, 'stored 2^32': { storedSignCount: 2 ** 32 },
  'stored 2^32-1': { storedSignCount: 2 ** 32 - 1 }, 'stored -0': { storedSignCount: -0 }, 'stored 1': { storedSignCount: 1 }, 'stored 0': { storedSignCount: 0 }, 'stored 5': { storedSignCount: 5 }, 'stored true': { storedSignCount: true }, 'stored 1e21': { storedSignCount: 1e21 },
})) {
  await va('expect ' + n, A, EXP(e));
  await va('expect ' + n + ' (ed)', mk({ kit: ED }), EXP(e));
}
// flags
for (const [n, f] of [['no UP', 0x04], ['no UV', 0x01], ['UP+UV', 0x05], ['UP+UV+BE+BS', 0x1d], ['all', 0xff], ['none', 0x00], ['AT', 0x45], ['ED', 0x85], ['BE', 0x09], ['BS only', 0x11]] as const) {
  await va('flags ' + n, mk({ flags: f }));
  await va('flags ' + n + ' no UV required', mk({ flags: f }), EXP({ requireUV: false }));
}
await va('rpIdHash other', mk({ signRp: 'other.example.com' }));
// sign counter
for (const [r, s] of [[0, 0], [1, 0], [5, 4], [5, 5], [5, 6], [0, 5], [100, 99], [2 ** 32 - 1, 2 ** 32 - 2], [2 ** 32 - 1, 2 ** 32 - 1], [1, 2 ** 32 - 1], [0, 1], [2 ** 31, 2 ** 31 - 1]] as const) {
  await va(`signCount reported ${r} stored ${s}`, mk({ signCount: r }), EXP({ storedSignCount: s }));
  await va(`signCount reported ${r} stored ${s} hook`, mk({ signCount: r }), EXP({ storedSignCount: s, hook: true }));
}
await va('hook not called on bad signature', withA({ signature: bytes(new Uint8Array(64)) }), EXP({ storedSignCount: 9, hook: true }));
// signatures: tampering, wrong key, key shapes
{
  const sigb = unb(A.signature.$bytes);
  for (const i of [0, 5, 10, 20, sigb.length - 1]) { const t = Uint8Array.from(sigb); t[i] = (t[i] as number) ^ 1; await va(`sig flip byte ${i}`, withA({ signature: bytes(t) })); }
  await va('sig trailing byte', withA({ signature: bytes([...sigb, 0]) }));
  await va('sig der non-minimal int', withA({ signature: bytes(Uint8Array.from([0x30, sigb[1] + 1, 0x02, sigb[3] + 1, 0x00, ...sigb.subarray(4, 4 + sigb[3]), ...sigb.subarray(4 + sigb[3])])) }));
  await va('sig der length byte off', withA({ signature: bytes(Uint8Array.from([0x30, sigb[1] - 1, ...sigb.subarray(2)])) }));
  await va('sig der not a sequence', withA({ signature: bytes(Uint8Array.from([0x31, ...sigb.subarray(1)])) }));
  await va('sig der extra trailing', withA({ signature: bytes(Uint8Array.from([0x30, sigb[1] + 1, ...sigb.subarray(2), 0])) }));
}
await va('wrong key', withA({ publicKey: { ...E2.pub, alg: 'ES256' } }));
await va('ed wrong key', mk({ kit: ED }), EXP());
await va('ed sig, other ed key', { ...mk({ kit: ED }), publicKey: { ...ED2.pub } });
await va('ed sig under es key', { ...mk({ kit: ED }), publicKey: E.pub });
await va('es sig under ed key', { ...A, publicKey: ED.pub });
for (const [n, k] of Object.entries({
  'jwk no kty': { crv: 'P-256', x: E.pub.x, y: E.pub.y }, 'jwk kty RSA': { kty: 'RSA', n: 'a', e: 'b' }, 'jwk P-384': E384.pub, 'jwk EC crv missing': { kty: 'EC', x: E.pub.x, y: E.pub.y }, 'jwk EC x missing': { kty: 'EC', crv: 'P-256', y: E.pub.y },
  'jwk EC x short': { kty: 'EC', crv: 'P-256', x: b64(new Uint8Array(31)), y: E.pub.y }, 'jwk EC x padded': { ...E.pub, x: E.pub.x + '=' }, 'jwk EC x std alphabet': { ...E.pub, x: E.pub.x.replace(/-/g, '+').replace(/_/g, '/') },
  'jwk EC off curve': { ...E.pub, y: b64(new Uint8Array(32).fill(3)) }, 'jwk EC x number': { ...E.pub, x: 5 }, 'jwk EC with d': { ...E.pub, d: 'x' }, 'jwk EC y trailing bits': { ...E.pub, y: E.pub.y.slice(0, -1) + (E.pub.y.endsWith('A') ? 'B' : 'A') },
  'jwk OKP X25519': { kty: 'OKP', crv: 'X25519', x: ED.pub.x }, 'jwk OKP crv missing': { kty: 'OKP', x: ED.pub.x }, 'jwk OKP x missing': { kty: 'OKP', crv: 'Ed25519' }, 'jwk OKP x short': { kty: 'OKP', crv: 'Ed25519', x: 'AAAA' },
  'jwk empty': {}, 'jwk null': null, 'jwk string': 'x', 'jwk number': 5, 'jwk array': [], 'jwk oct': { kty: 'oct', k: 'AAAA' }, 'cose garbage': bytes([1, 2, 3]), 'cose empty': bytes([]), 'cose truncated': bytes(coseEc(E).slice(0, 20)), 'cose P-384 crv': bytes(cMap([[cInt(1), cInt(2)], [cInt(-1), cInt(2)], [cInt(-2), cBytes(unb(E.pub.x))], [cInt(-3), cBytes(unb(E.pub.y))]])),
  'cose unsupported kty': bytes(cMap([[cInt(1), cInt(3)]])),
})) await va('key ' + n, withA({ publicKey: k }));
await va('key missing', withA({ publicKey: undefined }));
await va('key ed small-order', { ...mk({ kit: ED }), publicKey: { kty: 'OKP', crv: 'Ed25519', x: b64(Uint8Array.from([1, ...new Uint8Array(31)])) } });
{
  const s = mk({ kit: ED });
  const sg = unb(s.signature.$bytes);
  await va('ed sig flipped', { ...s, signature: bytes(Uint8Array.from(sg, (x, i) => (i === 3 ? x ^ 1 : x))) });
  await va('ed sig S not canonical', { ...s, signature: bytes(Uint8Array.from([...sg.subarray(0, 32), ...Uint8Array.from(sg.subarray(32), (x, i) => (i === 31 ? x | 0xf0 : x))])) });
  await va('ed sig short', { ...s, signature: bytes(sg.subarray(0, 63)) });
  await va('ed sig long', { ...s, signature: bytes([...sg, 0]) });
}
// secure payment confirmation
const SPC_CLIENT = (p: any = PAY, extra: any = {}) => ({ type: 'payment.get', payment: p, ...extra });
await va('spc ok', mk({ client: SPC_CLIENT() }), EXP({ payment: PAYE }));
await va('spc ok ed', mk({ kit: ED, client: SPC_CLIENT() }), EXP({ payment: PAYE }));
await va('spc but plain get signed', A, EXP({ payment: PAYE }));
await va('plain expected but payment.get signed', mk({ client: SPC_CLIENT() }));
await va('spc wrong total', mk({ client: SPC_CLIENT({ ...PAY, total: { currency: 'EUR', value: '99.00' } }) }), EXP({ payment: PAYE }));
await va('spc wrong payee', mk({ client: SPC_CLIENT({ ...PAY, payeeName: 'Evil' }) }), EXP({ payment: PAYE }));
await va('spc wrong rpId', mk({ client: SPC_CLIENT({ ...PAY, rpId: 'other' }) }), EXP({ payment: PAYE }));
await va('spc wrong top origin', mk({ client: SPC_CLIENT({ ...PAY, topOrigin: 'https://evil' }) }), EXP({ payment: PAYE }));
await va('spc missing payment', mk({ client: { type: 'payment.get' } }), EXP({ payment: PAYE }));
await va('spc no payee in expectation', mk({ client: SPC_CLIENT() }), EXP({ payment: { ...PAYE, payeeName: undefined, payeeOrigin: undefined } }));
await va('spc bad challenge', mk({ client: SPC_CLIENT(PAY, { challenge: b64(new Uint8Array(32)) }) }), EXP({ payment: PAYE }));
await va('spc payment null expectation', mk({ client: SPC_CLIENT() }), EXP({ payment: null }));
// structural variants of a valid ES256 / client data (re-signed)
const CLIENT0 = { type: 'webauthn.get', challenge: b64(CH), origin: ORIGIN, crossOrigin: false };
for (const [n, v] of variants(CLIENT0, { hostile: [null, true, 0, 1.5, '', 'x', [], {}, 2 ** 53] })) await va('client var ' + n, mk({ clientBytes: utf8(JSON.stringify(v)) }));

refWrite(o, 'webauthn');
