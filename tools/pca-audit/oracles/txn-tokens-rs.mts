// Oracle: @atlasauth/pca-txn-tokens (OAuth Transaction Tokens: sub/act custody chains, issue + verify, legacy and draft-11
// profiles). Deterministic: tokens to verify are signed here with Ed25519 seeds over hand-built (also hostile) headers and claims.
// Writes out/ref-txn-tokens-rs.json.gz (the rust lane's corpus; txn-tokens.mts is the shared one).
//   subActChain(chain) / actDepth(claim) / toRfc8693Act(claim)       JSON value or a throw
//   toTransactionToken({...args, seed})   issue is random (iat, exp, jti / txn): out = {header, claims} of the issued token with
//                                         iat removed, exp replaced by `ttl` (= exp - iat) and jti / txn replaced by `true` when
//                                         generated (a given `txn` is kept); a throw is a throw
//   fromTransactionToken(jwt, pkB64u, {profile?, audience?, clockToleranceSec?, nowMs?, seen?: [ids] | null, unchecked?})
//                                         {chain, action, tctx, claims} or a throw; `seen` is the set the seenTxn callback answers from
//                                         (absent = no callback)
import { ed25519 } from '@noble/curves/ed25519';
import { Oracle, refWrite, seed } from './lib.mjs';

const M: any = await import('../../../packages/pca-txn-tokens/src/index.ts');
const o = new Oracle('txn-tokens-rs', 'tools/pca-audit/oracles/txn-tokens-rs.mts', 'TS-reference oracle for OAuth Transaction Tokens (custody chain, issue, verify).');
const b64u = (b: Uint8Array | string) => Buffer.from(b).toString('base64url');
const SK = seed('ref-txn/issuer');
const PK = b64u(ed25519.getPublicKey(SK));
const OTHER = b64u(ed25519.getPublicKey(seed('ref-txn/other')));
const NOW = 1_800_000_000;

// ---- custody chains -----------------------------------------------------------------------------------------------------
const hop = (issuer: any, holder: any) => ({ id: 'c', issuer, holder, caveats: [] });
const chains: any[] = [[hop('P', 'A')], [hop('P', 'A'), hop('A', 'B'), hop('B', 'C')], [], null, 'x', [hop('', 'A')], [hop('P', '')], [hop('P', 'A'), hop('A', 5)], [{}], [hop(7, 'A')]];
for (const [i, c] of chains.entries()) await o.run('subActChain', `c${i}`, M.subActChain, [c]);
const claims: any[] = [{ sub: 'P' }, { sub: 'P', act: { sub: 'A' } }, { sub: 'P', act: { sub: 'A', act: { sub: 'B', act: { sub: 'C' } } } }, null, 'x', 5, {}, { act: null }, { sub: 'P', act: { sub: 'A', act: 0 } }];
for (const [i, c] of claims.entries()) {
  await o.run('actDepth', `a${i}`, M.actDepth, [c]);
  await o.run('toRfc8693Act', `a${i}`, M.toRfc8693Act, [c]);
}

// ---- issue --------------------------------------------------------------------------------------------------------------
const decode = (t: string) => t.split('.').slice(0, 2).map((s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8')));
const issue = async (a: any) => {
  const { seed: s, ...rest } = a;
  const tok = await M.toTransactionToken({ ...rest, issuerKey: new Uint8Array(Buffer.from(s, 'base64url')) });
  const [header, c] = decode(tok);
  const { iat, exp, jti, txn, ...keep } = c;
  return { header, claims: { ...keep, ttl: exp - iat, ...(jti !== undefined ? { jti: true } : {}), ...(txn !== undefined ? { txn: a.txn !== undefined ? txn : true } : {}) } };
};
const ACT = { verb: 'files.read', resource: 'files/a', aud: 'https://rs.example.com' };
const C3 = chains[1];
const SKB = b64u(SK);
const issues: any[] = [
  { chain: C3, action: ACT, issuer: 'https://as.example', seed: SKB, profile: 'legacy' },
  { chain: C3, action: ACT, issuer: 'https://as.example', seed: SKB, scope: 'files', reqWl: 'wl-1' },
  { chain: chains[0], action: ACT, issuer: 'https://as.example', seed: SKB, scope: 'files', reqWl: 'wl-1', txn: 'T-1', trustDomain: 'td.example', ttlSec: 30 },
  { chain: C3, action: ACT, issuer: 'https://as.example', seed: SKB, scope: 'files' }, { chain: C3, action: ACT, issuer: 'https://as.example', seed: SKB, reqWl: 'w' },
  { chain: C3, action: ACT, issuer: 'https://as.example', seed: SKB, scope: 's', reqWl: 'w', trustDomain: '' }, { chain: C3, action: ACT, issuer: '', seed: SKB, profile: 'legacy' },
  { chain: C3, action: { verb: 'v', resource: 'r' }, issuer: 'i', seed: SKB, profile: 'legacy' }, { chain: C3, action: null, issuer: 'i', seed: SKB, profile: 'legacy' },
  { chain: [], action: ACT, issuer: 'i', seed: SKB, profile: 'legacy' }, { chain: C3, action: ACT, issuer: 'i', seed: SKB, profile: 'legacy', ttlSec: 0 },
  { chain: C3, action: ACT, issuer: 'i', seed: SKB, profile: 'legacy', ttlSec: -5 }, { chain: C3, action: ACT, issuer: 'i', seed: b64u(new Uint8Array(31)), profile: 'legacy' },
  { chain: C3, action: ACT, issuer: 'i', seed: SKB, profile: 'other', scope: 's', reqWl: 'w' }, { chain: C3, action: ACT, issuer: 'i', seed: SKB, profile: 'legacy', ttlSec: 1.5 },
];
for (const [i, a] of issues.entries()) await o.run('toTransactionToken', `i${i}`, issue, [a]);

// ---- verify -------------------------------------------------------------------------------------------------------------
const enc = (x: any) => b64u(typeof x === 'string' ? x : JSON.stringify(x));
const sign = (h: any, p: any, s = SK) => {
  const input = `${enc(h)}.${enc(p)}`;
  return `${input}.${b64u(ed25519.sign(new TextEncoder().encode(input), s))}`;
};
const HD = { alg: 'EdDSA', typ: 'txntoken+jwt' };
const HL = { alg: 'EdDSA', typ: 'txn_token+jwt' };
const AUD = 'td.example';
const D = { iat: NOW, exp: NOW + 60, aud: AUD, sub: 'P', txn: 'T-1', scope: 'files', req_wl: 'wl', tctx: ACT, act: { sub: 'A', act: { sub: 'B' } }, iss: 'https://as.example' };
const L = { iat: NOW, exp: NOW + 60, aud: ACT.aud, sub: 'P', jti: 'J-1', tctx: ACT, act: { sub: 'A' }, iss: 'i' };
const OD = { audience: AUD, nowMs: NOW * 1000 + 500, seen: [] };
const OL = { profile: 'legacy', nowMs: NOW * 1000, unchecked: true };
const without = (x: any, k: string) => { const { [k]: _, ...r } = x; return r; };
const V: Array<[string, any, any, any?]> = [
  ['draft ok', sign(HD, D), OD], ['legacy ok', sign(HL, L), OL], ['legacy seen ok', sign(HL, L), { ...OL, unchecked: undefined, seen: ['x'] }],
  ['legacy replay', sign(HL, L), { ...OL, unchecked: undefined, seen: ['J-1'] }], ['draft replay', sign(HD, D), { ...OD, seen: ['T-1'] }],
  ['no replay store', sign(HD, D), { audience: AUD, nowMs: NOW * 1000 }], ['draft no audience', sign(HD, D), { nowMs: NOW * 1000, unchecked: true }],
  ['bad profile', sign(HD, D), { ...OD, profile: 'x' }], ['wrong audience', sign(HD, D), { ...OD, audience: 'other' }], ['aud array', sign(HD, { ...D, aud: ['x', AUD] }), OD],
  ['aud number', sign(HD, { ...D, aud: 5 }), OD], ['typ legacy under draft', sign(HL, D), OD], ['typ draft under legacy', sign(HD, L), OL], ['typ upper', sign({ ...HD, typ: 'TXNTOKEN+JWT' }, D), OD],
  ['typ application/', sign({ ...HD, typ: 'application/txntoken+jwt' }, D), OD], ['typ missing', sign({ alg: 'EdDSA' }, D), OD], ['alg ES256', sign({ ...HD, alg: 'ES256' }, D), OD],
  ['alg none', sign({ ...HD, alg: 'none' }, D), OD], ['crit', sign({ ...HD, crit: ['x'], x: 1 }, D), OD], ['other key', sign(HD, D, seed('ref-txn/other')), OD],
  ['verify key other', sign(HD, D), OD, OTHER], ['verify key short', sign(HD, D), OD, b64u(new Uint8Array(31))], ['expired', sign(HD, { ...D, exp: NOW }), OD],
  ['expired tolerance', sign(HD, { ...D, exp: NOW }), { ...OD, clockToleranceSec: 5 }], ['nbf future', sign(HD, { ...D, nbf: NOW + 10 }), OD],
  ['nbf tolerance', sign(HD, { ...D, nbf: NOW + 10 }), { ...OD, clockToleranceSec: 10 }], ['iat string', sign(HD, { ...D, iat: 'x' }), OD], ['exp string', sign(HD, { ...D, exp: 'x' }), OD],
  ...['iat', 'exp', 'aud', 'sub', 'txn', 'scope', 'req_wl'].map((k) => [`draft missing ${k}`, sign(HD, without(D, k)), OD] as [string, any, any]),
  ['legacy missing exp', sign(HL, without(L, 'exp')), OL], ['legacy missing iat', sign(HL, without(L, 'iat')), OL], ['txn empty', sign(HD, { ...D, txn: '' }), OD],
  ['scope number', sign(HD, { ...D, scope: 1 }), OD], ['sub empty', sign(HD, { ...D, sub: '' }), OD], ['sub missing legacy', sign(HL, without(L, 'sub')), OL],
  ['tctx missing', sign(HD, without(D, 'tctx')), OD], ['tctx array', sign(HD, { ...D, tctx: [] }), OD], ['tctx opaque draft', sign(HD, { ...D, tctx: { purpose: 'x' } }), OD],
  ['tctx opaque legacy', sign(HL, { ...L, tctx: { purpose: 'x' } }), OL], ['tctx partial', sign(HD, { ...D, tctx: { verb: 'v' } }), OD], ['rctx ok', sign(HD, { ...D, rctx: { ip: '1' } }), OD],
  ['rctx bad', sign(HD, { ...D, rctx: 'x' }), OD], ['rctx bad legacy', sign(HL, { ...L, rctx: 'x' }), OL], ['act none', sign(HD, without(D, 'act')), OD],
  ['act null', sign(HD, { ...D, act: null }), OD], ['act array', sign(HD, { ...D, act: [] }), OD], ['act no sub', sign(HD, { ...D, act: { act: { sub: 'x' } } }), OD],
  ['act deep bad', sign(HD, { ...D, act: { sub: 'A', act: { sub: '' } } }), OD], ['legacy no jti seen', sign(HL, without(L, 'jti')), { ...OL, unchecked: undefined, seen: [] }],
  ['oversize', 'a'.repeat(16385), OD], ['two parts', 'a.b', OD], ['padded', sign(HD, D) + '=', OD], ['header array', sign([1], D), OD], ['payload array', sign(HD, [1]), OD],
  ['dup claim', sign(HD, '{"sub":"P","sub":"Q"}'), OD], ['payload extra', sign(HD, { ...D, extra: { a: [1, 2] } }), OD], ['not string', 5, OD],
];
const verify = async (jwt: any, pk: string, w: any) => {
  const seen = w.seen ? new Set(w.seen) : undefined;
  return M.fromTransactionToken(jwt, new Uint8Array(Buffer.from(pk, 'base64url')), {
    ...(w.profile !== undefined ? { profile: w.profile } : {}), ...(w.audience !== undefined ? { audience: w.audience } : {}),
    ...(w.clockToleranceSec !== undefined ? { clockToleranceSec: w.clockToleranceSec } : {}), ...(w.nowMs !== undefined ? { now: new Date(w.nowMs) } : {}),
    ...(seen ? { seenTxn: (id: string) => seen.has(id) } : {}), ...(w.unchecked ? { replayCheck: 'unchecked' } : {}),
  });
};
for (const [n, jwt, w, pk] of V) await o.run('fromTransactionToken', n, verify, [jwt, pk ?? PK, w]);

refWrite(o, 'txn-tokens-rs');
