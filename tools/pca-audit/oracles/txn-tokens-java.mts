// Oracle: @atlasauth/pca-txn-tokens (RFC 8693 act projection, EdDSA Transaction Tokens: mint and verify). Deterministic: Date.now is
// pinned to T0, Ed25519 signs deterministically, an explicit `txn` removes the only random claim. Writes out/ref-txn-tokens-java.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule):
//   subActChain(chain), actDepth(claim), toRfc8693Act(claim)   -> same names (JSON compare; a throw requires a throw)
//   toTransactionToken(args)  -> toTransactionToken with the clock pinned to T0 = 1_800_000_000_000 ms; args.issuerKey = {label} (the
//                                32-byte seed = sha256("atlas-pca-conformance/<label>")) or {len:n} (n zero bytes). Result {header, payload,
//                                verified, token?}: header / payload = the decoded token (the random uuid in `jti`, and in `txn` when the input
//                                has none, is replaced by "<uuid>"); verified = the token verifies under the label's public key at T0; token =
//                                the exact compact string, present only when no random claim is involved.
//   fromTransactionToken(token, key, opts) -> fromTransactionToken; key = {pubLabel} (the raw 32-byte public key of that seed) or {len:n};
//                                opts.nowMs = verification time; opts.seen = absent | 'fresh' | 'seen' | 'throws' | 'truthy' (the seenTxn hook:
//                                false / true / throws / returns 1). Result {ok:true, result, consumed:[[id, exp]...]} or {ok:false, code
//                                ('replay_store_required' or 'other'), consumed}.
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { jwtVerify } from 'jose';
import * as M0 from '@atlasauth/pca-txn-tokens';
import { Oracle, seed, refWrite } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const o = new Oracle('txn-tokens-java', 'tools/pca-audit/oracles/txn-tokens-java.mts', 'TS-reference oracle for the RFC 8693 act projection and Transaction Tokens.');

const T0 = 1_800_000_000_000;
const realNow = Date.now;
Date.now = () => T0;

const b64u = (b: Uint8Array | Buffer | string) => Buffer.from(b as any).toString('base64url');
const PKCS8_ED = Buffer.from('302e020100300506032b657004220420', 'hex');
const priv = (l: string) => createPrivateKey({ key: Buffer.concat([PKCS8_ED, Buffer.from(seed(l))]), format: 'der', type: 'pkcs8' });
const pubRaw = (l: string) => new Uint8Array(Buffer.from(createPublicKey(priv(l)).export({ format: 'jwk' }).x as string, 'base64url'));
const mk = (header: any, payload: any, l = 'txn/issuer') => {
  const h = b64u(JSON.stringify(header)), p = b64u(JSON.stringify(payload));
  return `${h}.${p}.${b64u(nodeSign(null, Buffer.from(`${h}.${p}`), priv(l)))}`;
};
const keyDesc = (k: any) => (k === undefined ? undefined : k.label !== undefined ? new Uint8Array(seed(k.label)) : k.pubLabel !== undefined ? pubRaw(k.pubLabel) : new Uint8Array(k.len));

const PUB = b64u(pubRaw('txn/principal'));
const CH = (n = 2): any[] => Array.from({ length: n }, (_, i) => ({ issuer: i === 0 ? PUB : 'holder' + (i - 1), holder: 'holder' + i }));
const ACTION = { verb: 'stripe.refund', resource: 'charge:ch_1', aud: 'https://rs.example.com' };
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// ---- pure projections
const chains: any[] = [CH(1), CH(2), CH(5), [], null, 'x', {}, [{ issuer: PUB, holder: '' }], [{ issuer: '', holder: 'h' }], [{ holder: 'h' }], [{ issuer: PUB }], [null], [5], [{ issuer: PUB, holder: 'h' }, { issuer: 'h' }], [{ issuer: PUB, holder: 'h' }, { holder: 5 }]];
for (const [i, c] of chains.entries()) await o.run('subActChain', `c${i}`, M.subActChain, [c]);
const claims: any[] = [{ sub: 'a' }, { sub: 'a', act: { sub: 'b' } }, { sub: 'a', act: { sub: 'b', act: { sub: 'c', act: { sub: 'd' } } } }, { sub: 'a', act: null }, { sub: 'a', act: {} }, { sub: 'a', act: { act: { sub: 'x' } } },
  { sub: 'a', act: 5 }, { sub: 'a', act: 'x' }, { sub: 'a', act: [] }, { sub: 'a', act: { sub: null, act: { sub: 'q' } } }, { act: { sub: 'b' } }, {}, [], null, 5, 'x', { sub: 'a', act: { sub: 'b', act: 5 } }, { sub: 'a', act: { sub: 'b', act: { sub: 'c', extra: 1 } } }, { sub: 1, act: { sub: 2 } }];
for (const [i, c] of claims.entries()) { await o.run('actDepth', `c${i}`, M.actDepth, [c]); await o.run('toRfc8693Act', `c${i}`, M.toRfc8693Act, [c]); }
for (const n of [1, 2, 3, 6]) { const sc = M.subActChain(CH(n)); await o.run('actDepth', `chain${n}`, M.actDepth, [sc]); await o.run('toRfc8693Act', `chain${n}`, M.toRfc8693Act, [sc]); }

// ---- minting
const mintWrap = async (args: any) => {
  const { issuerKey, ...rest } = args;
  const token = await M.toTransactionToken({ ...rest, ...(issuerKey !== undefined ? { issuerKey: keyDesc(issuerKey) } : {}) });
  const [h, p] = token.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  const random = payload.jti !== undefined || args.txn === undefined;
  if (typeof payload.jti === 'string' && UUID_RE.test(payload.jti)) payload.jti = '<uuid>';
  if (args.txn === undefined && typeof payload.txn === 'string' && UUID_RE.test(payload.txn)) payload.txn = '<uuid>';
  let verified = false;
  try { await jwtVerify(token, createPublicKey(priv(issuerKey.label)), { algorithms: ['EdDSA'], currentDate: new Date(T0) }); verified = true; } catch { /* false */ }
  return { header, payload, verified, ...(random ? {} : { token }) };
};
const BASE: any = { chain: CH(2), action: ACTION, issuerKey: { label: 'txn/issuer' }, issuer: 'https://tts.example.com', scope: 'refund', reqWl: 'billing' };
let n = 0;
const MINT = (label: string, args: any) => o.run('toTransactionToken', `${label}#${n++}`, mintWrap, [args]);
await MINT('draft default', BASE);
await MINT('draft explicit txn', { ...BASE, txn: 'txn-1' });
await MINT('draft explicit', { ...BASE, profile: 'draft-11', txn: 'txn-1', ttlSec: 30 });
await MINT('legacy', { ...BASE, profile: 'legacy' });
await MINT('legacy one hop', { ...BASE, profile: 'legacy', chain: CH(1) });
await MINT('draft one hop', { ...BASE, chain: CH(1), txn: 't' });
await MINT('draft long chain', { ...BASE, chain: CH(6), txn: 't' });
await MINT('trust domain', { ...BASE, trustDomain: 'td.example.com', txn: 't' });
await MINT('ttl fraction', { ...BASE, ttlSec: 1.5, txn: 't' });
await MINT('ttl huge int', { ...BASE, ttlSec: 86400 * 3650, txn: 't' });
for (const [label, ov] of Object.entries({
  'no issuer': { issuer: undefined }, 'empty issuer': { issuer: '' }, 'issuer number': { issuer: 5 }, 'no action': { action: undefined }, 'action null': { action: null }, 'action verb number': { action: { ...ACTION, verb: 5 } }, 'action no aud': { action: { verb: 'v', resource: 'r' } },
  'action extra': { action: { ...ACTION, extra: 1 } }, 'action empty strings': { action: { verb: '', resource: '', aud: '' } }, 'chain empty': { chain: [] }, 'chain bad': { chain: [{ issuer: PUB }] }, 'chain absent': { chain: undefined },
  'ttl zero': { ttlSec: 0 }, 'ttl neg': { ttlSec: -1 }, 'ttl string': { ttlSec: '5' }, 'ttl null': { ttlSec: null }, 'no scope': { scope: undefined }, 'empty scope': { scope: '' }, 'no reqWl': { reqWl: undefined }, 'empty reqWl': { reqWl: '' },
  'empty trust': { trustDomain: '' }, 'trust number': { trustDomain: 5 }, 'txn empty': { txn: '' }, 'txn number': { txn: 5 }, 'bad profile': { profile: 'v2' }, 'profile empty': { profile: '' }, 'key short': { issuerKey: { len: 31 } }, 'key long': { issuerKey: { len: 33 } },
  'key absent': { issuerKey: undefined }, 'unicode': { issuer: 'https://tts.example.com/é', scope: 'a b', reqWl: 'wl x', txn: 'tx😀' },
} as Record<string, any>)) {
  await MINT(`draft ${label}`, { ...BASE, txn: 't', ...ov });
  await MINT(`legacy ${label}`, { ...BASE, profile: 'legacy', ...ov });
}

// ---- verifying
const mint = async (over: any = {}) => (M.toTransactionToken({ ...BASE, txn: 'txn-1', ...over, issuerKey: new Uint8Array(seed('txn/issuer')) }) as Promise<string>);
const draftTok = await mint();
const legacyTok = await mint({ profile: 'legacy' });
const draftTok1 = await mint({ chain: CH(1) });
const AUD = ACTION.aud;
const PL: any = { tctx: ACTION, act: { sub: 'holder0', act: { sub: 'holder1' } }, txn: 'txn-1', scope: 'refund', req_wl: 'billing', iat: T0 / 1000, iss: 'https://tts.example.com', sub: PUB, aud: AUD, exp: T0 / 1000 + 120 };
const HD = { alg: 'EdDSA', typ: 'txntoken+jwt' };
const LPL: any = { tctx: ACTION, act: PL.act, iat: PL.iat, iss: PL.iss, sub: PUB, aud: AUD, exp: PL.exp, jti: 'jti-1' };
const LHD = { alg: 'EdDSA', typ: 'txn_token+jwt' };
const key = { pubLabel: 'txn/issuer' };
const verifyWrap = async (token: any, k: any, opts: any) => {
  const consumed: any[] = [];
  try {
    const { seen, nowMs, ...rest } = opts ?? {};
    const seenTxn = seen === undefined ? undefined : async (id: string, exp: number) => {
      consumed.push([id, exp]);
      if (seen === 'throws') throw new Error('store down');
      if (seen === 'seen') return true;
      if (seen === 'truthy') return 1 as any;
      return false;
    };
    const r = await M.fromTransactionToken(token, keyDesc(k), { ...rest, ...(nowMs !== undefined ? { now: new Date(nowMs) } : {}), ...(seenTxn ? { seenTxn } : {}) });
    return { ok: true, result: r, consumed };
  } catch (e: any) {
    return { ok: false, code: e?.code === 'replay_store_required' ? 'replay_store_required' : 'other', consumed };
  }
};
const O: any = { audience: AUD, nowMs: T0, seen: 'fresh' };
const OL: any = { profile: 'legacy', nowMs: T0, seen: 'fresh' };
let vn = 0;
const V = (label: string, token: any, k: any = key, opts: any = O) => o.run('fromTransactionToken', `${label}#${vn++}`, verifyWrap, [token, k, opts]);
await V('draft ok', draftTok);
await V('draft one hop', draftTok1);
await V('legacy ok', legacyTok, key, OL);
await V('legacy ok seen unchecked', legacyTok, key, { profile: 'legacy', nowMs: T0, replayCheck: 'unchecked' });
await V('draft read as legacy', draftTok, key, OL);
await V('legacy read as draft', legacyTok);
const HOST: any[] = [null, true, false, 0, -1, 1.5, '', 'x', [], ['x'], {}, { x: 1 }, { verb: 'v' }, { verb: 'v', resource: 'r', aud: 'a' }, { foo: 'bar' }];
for (const k of Object.keys(PL)) {
  const del = { ...PL }; delete del[k];
  await V(`draft claim ${k} deleted`, mk(HD, del));
  for (const [i, h] of HOST.entries()) await V(`draft claim ${k} = host${i}`, mk(HD, { ...PL, [k]: h }));
}
for (const k of Object.keys(LPL)) {
  const del = { ...LPL }; delete del[k];
  await V(`legacy claim ${k} deleted`, mk(LHD, del), key, OL);
  for (const [i, h] of HOST.entries()) await V(`legacy claim ${k} = host${i}`, mk(LHD, { ...LPL, [k]: h }), key, OL);
}
for (const [label, c] of Object.entries({
  'rctx object': { rctx: { a: 1 } }, 'rctx null': { rctx: null }, 'rctx array': { rctx: [] }, 'rctx string': { rctx: 'x' }, 'free tctx': { tctx: { anything: [1, 2] } }, 'tctx partial': { tctx: { verb: 'v' } }, 'tctx full other aud': { tctx: { verb: 'v', resource: 'r', aud: 'a' } },
  'tctx empty': { tctx: {} }, 'act deep': { act: { sub: 'a', act: { sub: 'b', act: { sub: 'c' } } } }, 'act extra members': { act: { sub: 'a', extra: 1, act: { sub: 'b', zz: [1] } } }, 'aud array': { aud: [AUD] }, 'aud array two': { aud: [AUD, 'o'] }, 'aud other': { aud: 'other' },
  'expired': { exp: T0 / 1000 - 1 }, 'exp equal now': { exp: T0 / 1000 }, 'exp next sec': { exp: T0 / 1000 + 1 }, 'iat future': { iat: T0 / 1000 + 1000 }, 'nbf future': { nbf: T0 / 1000 + 1000 }, 'extra': { foo: 1 },
} as Record<string, any>)) { await V(`draft ${label}`, mk(HD, { ...PL, ...c })); await V(`legacy ${label}`, mk(LHD, { ...LPL, ...c }), key, OL); }
for (const [label, h] of Object.entries({ 'typ missing': { alg: 'EdDSA' }, 'typ JWT': { alg: 'EdDSA', typ: 'JWT' }, 'typ legacy on draft': LHD, 'typ upper': { alg: 'EdDSA', typ: 'TXNTOKEN+JWT' }, 'typ app': { alg: 'EdDSA', typ: 'application/txntoken+jwt' }, 'typ number': { alg: 'EdDSA', typ: 5 }, 'alg none': { alg: 'none', typ: HD.typ },
  'alg ES256': { alg: 'ES256', typ: HD.typ }, 'alg HS256': { alg: 'HS256', typ: HD.typ }, 'no alg': { typ: HD.typ }, 'crit b64': { ...HD, crit: ['b64'], b64: true }, 'crit b64 false': { ...HD, crit: ['b64'], b64: false }, 'crit unknown': { ...HD, crit: ['q'], q: 1 }, 'kid': { ...HD, kid: 'x' } } as Record<string, any>)) {
  await V(`header ${label}`, mk(h, PL));
}
await V('signed by other key', mk(HD, PL, 'txn/other'));
await V('wrong pub key', draftTok, { pubLabel: 'txn/other' });
await V('pub short', draftTok, { len: 31 });
await V('pub long', draftTok, { len: 33 });
await V('pub zeros', draftTok, { len: 32 });
const [th, tp, ts] = draftTok.split('.');
for (const [label, t] of Object.entries({ empty: '', one: 'x', two: `${th}.${tp}`, four: `${draftTok}.x`, 'sig flipped': `${th}.${tp}.${ts.slice(0, -2)}${ts.at(-2) === 'A' ? 'B' : 'A'}${ts.at(-1)}`, 'sig empty': `${th}.${tp}.`, 'payload swapped': `${th}.${b64u(JSON.stringify({ ...PL, sub: 'evil' }))}.${ts}`,
  padded: `${th}=.${tp}.${ts}`, 'leading space': ` ${draftTok}`, 'header array': `${b64u('[1]')}.${tp}.${ts}`, 'payload array': `${th}.${b64u('[1]')}.${ts}`, 'too long': 'a'.repeat(16385), 'at limit': 'a'.repeat(16384), 'long valid shape': `${'a'.repeat(5000)}.${'b'.repeat(5000)}.${'c'.repeat(5000)}` } as Record<string, string>)) await V(`token ${label}`, t);
await o.run('fromTransactionToken', 'token number', verifyWrap, [5, key, O]);
await o.run('fromTransactionToken', 'token null', verifyWrap, [null, key, O]);
for (const [label, ov] of Object.entries({
  'no opts': null, 'no audience': { audience: undefined }, 'empty audience': { audience: '' }, 'audience number': { audience: 5 }, 'audience other': { audience: 'other' }, 'no replay': { seen: undefined }, 'unchecked': { seen: undefined, replayCheck: 'unchecked' }, 'unchecked other': { seen: undefined, replayCheck: 'yes' },
  'seen': { seen: 'seen' }, 'throws': { seen: 'throws' }, 'truthy': { seen: 'truthy' }, 'seen and unchecked': { seen: 'seen', replayCheck: 'unchecked' }, 'tol': { clockToleranceSec: 5 }, 'tol neg': { clockToleranceSec: -5 }, 'tol big': { clockToleranceSec: 1e6 },
  'now late': { nowMs: T0 + 121_000 }, 'now at exp': { nowMs: T0 + 120_000 }, 'now before exp': { nowMs: T0 + 119_999 }, 'now late tol': { nowMs: T0 + 125_000, clockToleranceSec: 10 }, 'now early': { nowMs: T0 - 10_000 }, 'now early tol': { nowMs: T0 - 10_000, clockToleranceSec: 10 },
  'profile bad': { profile: 'v2' }, 'profile legacy': { profile: 'legacy' }, 'profile explicit': { profile: 'draft-11' },
} as Record<string, any>)) {
  await V(`opts ${label}`, draftTok, key, ov === null ? undefined : { ...O, ...ov });
  await V(`opts legacy ${label}`, legacyTok, key, ov === null ? undefined : { ...OL, ...ov });
}

Date.now = realNow;
refWrite(o, 'txn-tokens-java');
