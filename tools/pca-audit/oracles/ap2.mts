// Oracle: @atlasauth/pca-ap2 (AP2 mandates as SD-JWT credentials: strict SD-JWT parsing and disclosure processing, ES256,
// RFC 7638 thumbprints, mandate validators and minor units, open-mandate constraint evaluation, issuance / presentation /
// verification of delegation chains, PCA terms -> open mandates, settlement payloads, the redeem ledger).
// Writes out/ref-ap2.json.gz.
//
// Determinism: keys are derived from labels (d = sha256("atlas-pca-conformance/ap2/<label>")), salts are counters
// ("salt-000000000001" base64url), the clock is T0 = 1_800_000_000 s. ECDSA signatures are randomized, so every token in an
// argument was signed once at generation time (the vectors verify; they are not reproducible byte for byte), and a fn that
// SIGNS (issue*, present*, sign*) is compared with every signature segment replaced by "SIG" (stripSig).
//
// PORTING (fn(args) -> native entry point, comparison rule). Values are JSON; numbers compare by value; Uint8Array is
// {"$bytes": b64url}; a {"$throws"} case requires the native to refuse. Key arguments are LABELS (a string): the native derives
// the key pair from the label exactly as above (d = sha256 bytes, public point = d*G) and uses the public JWK or the private key.
//   b64uEncode(s) / b64uDecode(s, what) / parseJson(text, what) / isSdAlg(v) / sdDigest(value, alg?)  -> Sdjwt.*
//   assertP256Jwk(jwk, what)           -> returns the JWK itself when valid
//   jwkThumbprint(jwk)                 -> Sdjwt.jwkThumbprint
//   hopSdJwt(token)                    -> parse the hop, then Sdjwt.hopSdJwt(jwt, disclosures)
//   parseSdJwtHop(token)               -> {raw, jwt, header, payload, disclosures, sdAlg, signingInput, signature: bytes}
//   sdHashOf(token, alg?) / issuerJwtHashOf(token, alg?)   -> digest of the parsed hop (alg defaults to the hop's _sd_alg)
//   verifyHopSignature(token, jwk) / verifyJwtEs256(jwt, jwk) / parseJwt(jwt, what) ({header,payload,signingInput,signature})
//   processDisclosures(payload, disclosures, alg)
//   disclosureBuilder(alg, ops)        -> new builder with salts "salt-NNNNNNNNNNNN"; ops [{kind:'element',value}|{kind:'property',name,value}];
//                                         result {results: [placeholder object | digest string], disclosures}
//   signSdJwt({header, payload, disclosures, key}) / signJwtEs256({header, payload, key})  -> signatures replaced by "SIG"
//   ap2KeyPairFromPrivateJwk(label, mut?)  -> public JWK of the key built from the label's private JWK (mut: {x?, y?, d?, kty?} overrides)
//   currencyExponent / toMinorUnits / fromMinorUnits / *Problems / assertValid(kind, value, what) / constants
//   merchantMatches / checkPaymentConstraints(open, closed, {openCheckoutHash?, context?, now}) / projectCheckout / checkoutTotal /
//     checkCheckoutConstraints
//   splitChain(token)
//   verifyKbHop(hopToken, prevToken, prevMandate, {terminal, expectedAudience, expectedNonce, now, skew}, label)
//   verifyDelegationChain / verifyCheckoutChain / verifyPaymentChain / verifyPurchase / redeemPurchase: the options object holds
//     issuerKeys / merchantKeys as {kid: jwk}: the resolver returns the entry whose name equals header.kid (a string), else nothing.
//     Result projection: {ok:false, reason (an "invalid JSON (...)" detail is masked as "invalid JSON (*)"), violations?} or
//     {ok:true, hops:[{index, kind, claims, mandate}], open?, closed?, checkoutJwt?, checkout?, openHash?}.
//     redeemPurchase additionally takes a ledger spec and answers {result, calls}: spec 'none' = no ledger, else
//     {mode: 'ok'|'replayed'|'throw'|'undefined', ctx?, releaseThrows?}; calls = [["reserve", openHash, txId, amount] | ["release", openHash, txId]].
//   issueOpenPaymentMandate / issueOpenCheckoutMandate / presentClosedPayment / presentClosedCheckout (one JSON object, see wrappers below)
//   ap2BudgetMax / ap2BudgetReads / riskRatio / pcaBindingNonce / paymentConstraintsFromTerms / pcaOpenClaim /
//     openPaymentMandateFromPca / openCheckoutMandateFromPca
//   toAtomicUnits(amount, decimals) / x402Settlement(payment, ctx) / stripeSptSettlement(payment, ctx)
//   buildPcaPaymentBinding(input)       -> Ap2.buildPcaPaymentBinding (agentSeed = label; Ed25519, so compared in full; amount etc. as JSON)
// verifyPcaBinding needs the PCA core verifier entry and constraintsWithinTerms is not exported: neither is covered here.
import fs from 'node:fs';
import { createECDH, createHash } from 'node:crypto';
import * as M0 from '@atlasauth/pca-ap2';
import * as C0 from '@atlasauth/pca';
import * as P0 from '@atlasauth/pca-payments';
import { Oracle, refWrite, rng, reparse, capture, variants, seed } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const C: any = (C0 as any).default ?? C0;
const P: any = (P0 as any).default ?? P0;
const o = new Oracle('ap2', 'tools/pca-audit/oracles/ap2.mts', 'TS-reference oracle for the AP2 mandate package.');

// ------------------------------------------------------------------------------------------------ plumbing
let dropped = 0;
const ENGINE = /Cannot read prop|is not a function|is not iterable|of undefined|of null|is not defined|Cannot destructure|Invalid array length|Maximum call stack/;
/** Record fn(...args) after re-parsing the args; a case whose answer is an engine-specific message is dropped. */
async function run(fn: string, name: string, ref: (...a: any[]) => any, args: any[]) {
  const a = reparse(args);
  const out = await capture(ref, a);
  if (ENGINE.test(JSON.stringify(out))) { dropped++; return false; }
  return o.add(fn, name, a, out);
}
const maskReason = (s: any) => (typeof s === 'string' ? s.replace(/invalid JSON \(.*\)$/s, 'invalid JSON (*)') : s);
const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString('base64url');

const T0 = 1_800_000_000;
const keyCache = new Map<string, any>();
function keyFor(label: string) {
  const hit = keyCache.get(label);
  if (hit) return hit;
  const d = createHash('sha256').update(`atlas-pca-conformance/ap2/${label}`).digest();
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();
  const jwk = { kty: 'EC', crv: 'P-256', d: b64u(d), x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)), kid: label };
  const kp = M.ap2KeyPairFromPrivateJwk(jwk);
  keyCache.set(label, kp);
  return kp;
}
const pubOf = (label: string) => ({ kty: 'EC', crv: 'P-256', x: keyFor(label).publicJwk.x, y: keyFor(label).publicJwk.y });
function counterSalt(): () => string {
  let n = 0;
  return () => Buffer.from(`salt-${String(++n).padStart(12, '0')}`).toString('base64url');
}
/** Every compact JWT's signature segment replaced by SIG (disclosures hold no dots, so they are left alone). */
const stripSig = (t: string) => t.split('~').map((s) => (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(s) ? s.replace(/\.[A-Za-z0-9_-]+$/, '.SIG') : s)).join('~');

const MERCH = { id: 'merchant_1', name: 'Demo Merchant', website: 'https://demo-merchant.example' };
const MERCH2 = { id: 'merchant_2', name: 'Other Merchant' };
const INSTR = { id: 'spt_1', type: 'shared_payment_token', description: 'Visa 4242' };
const PISP = { legal_name: 'Pay Co Ltd', brand_name: 'PayCo', domain_name: 'payco.example' };

// ------------------------------------------------------------------------------------------------ scenario factory
interface P {
  currency?: string; sdAlg?: string; quantity?: number; price?: number; total?: number; amount?: number; exp?: number; maxTx?: number; budget?: number;
  frequency?: string; maxOcc?: number; hashMode?: string; payeeOpen?: any; paymentAmountOpen?: any; instrumentOpen?: any; pispOpen?: any; execOpen?: string;
  pisp?: any; executionDate?: string; riskData?: any; closedExp?: number; pca?: any; payee?: any; instrument?: any; allowedPayees?: any[]; skipReference?: boolean;
  referenceOverride?: string; closedIat?: number; checkoutAud?: string; paymentAud?: string; extraConstraints?: any[];
}
function scenario(p: P = {}) {
  const issuer = keyFor('issuer'), agent = keyFor('agent'), merchantKey = keyFor('merchant');
  const salt = counterSalt();
  const cur = p.currency ?? 'USD';
  const qty = p.quantity ?? 2, price = p.price ?? 2000, total = p.total ?? qty * price;
  const sdAlg = p.sdAlg;
  const base = { issuer: { privateKey: issuer.privateKey, kid: 'issuer-1' }, agentJwk: agent.publicJwk, iat: T0 - 100, exp: p.exp ?? T0 + 3600, salt, ...(sdAlg ? { sdAlg } : {}) };
  const openCheckout = M.issueOpenCheckoutMandate({
    ...base,
    constraints: [
      { type: 'checkout.line_items', items: [{ id: 'line_1', acceptable_items: [{ id: 'sku-1', title: 'Widget' }, { id: 'sku-2', title: 'Widget Pro' }], quantity: qty }] },
      { type: 'checkout.allowed_merchants', allowed: [MERCH] },
    ],
  });
  const checkoutPayload = { id: 'chk_1', merchant: MERCH, currency: cur, line_items: [{ id: 'li_1', item: { id: 'sku-1', title: 'Widget', price }, quantity: qty }], totals: [{ type: 'total', amount: total }] };
  const checkoutJwt = M.signJwtEs256({ header: { kid: 'merchant-1' }, payload: checkoutPayload, privateKey: merchantKey.privateKey });
  const checkoutChain = M.presentClosedCheckout({ open: openCheckout, agentKey: agent, checkoutJwt, aud: p.checkoutAud ?? 'merchant', nonce: 'nonce-c', iat: T0, salt, ...(p.closedExp !== undefined ? { exp: p.closedExp } : {}) });
  const checkoutHash = M.sdDigest(checkoutJwt, sdAlg ?? 'sha-256');
  const openHash = M.sdHashOf(M.parseSdJwtHop(openCheckout));
  const constraints: any[] = [
    { type: 'payment.amount_range', currency: cur, min: 0, max: p.maxTx ?? 50000 },
    { type: 'payment.allowed_payees', allowed: p.allowedPayees ?? [MERCH] },
    ...(p.skipReference ? [] : [{ type: 'payment.reference', conditional_transaction_id: p.referenceOverride ?? openHash }]),
    { type: 'payment.budget', currency: cur, max: p.budget ?? 1000 },
    { type: 'payment.agent_recurrence', frequency: p.frequency ?? 'ON_DEMAND', ...(p.maxOcc !== undefined ? { max_occurrences: p.maxOcc } : { max_occurrences: 5 }) },
    ...(p.extraConstraints ?? []),
  ];
  const openPayment = M.issueOpenPaymentMandate({
    ...base, constraints,
    ...(p.payeeOpen ? { payee: p.payeeOpen } : {}), ...(p.paymentAmountOpen ? { paymentAmount: p.paymentAmountOpen } : {}),
    ...(p.instrumentOpen ? { paymentInstrument: p.instrumentOpen } : {}), ...(p.pispOpen ? { pisp: p.pispOpen } : {}), ...(p.execOpen !== undefined ? { executionDate: p.execOpen } : {}),
    ...(p.pca ? { pca: p.pca } : {}),
  });
  const paymentChain = M.presentClosedPayment({
    open: openPayment, agentKey: agent, aud: p.paymentAud ?? 'credential-provider', nonce: 'nonce-p', iat: p.closedIat ?? T0, salt, transactionId: checkoutHash,
    payee: p.payee ?? MERCH, paymentAmount: { amount: p.amount ?? total, currency: cur }, paymentInstrument: p.instrument ?? INSTR,
    ...(p.hashMode ? { hashMode: p.hashMode } : {}), ...(p.pisp ? { pisp: p.pisp } : {}), ...(p.executionDate !== undefined ? { executionDate: p.executionDate } : {}),
    ...(p.riskData ? { riskData: p.riskData } : {}), ...(p.closedExp !== undefined ? { exp: p.closedExp } : {}),
  });
  return { openCheckout, checkoutChain, checkoutJwt, checkoutHash, openHash, openPayment, paymentChain, cur, total };
}

const issuerKeys = () => ({ 'issuer-1': pubOf('issuer') });
const merchantKeys = () => ({ 'merchant-1': pubOf('merchant') });
const chainOpts = (extra: any = {}) => ({ issuerKeys: issuerKeys(), merchantKeys: merchantKeys(), expectedAudience: 'merchant', expectedNonce: 'nonce-c', now: T0 + 10, ...extra });
const payOpts = (s: any, extra: any = {}) => ({ issuerKeys: issuerKeys(), expectedAudience: 'credential-provider', expectedNonce: 'nonce-p', now: T0 + 10, openCheckoutHash: s.openHash, expectedTransactionId: s.checkoutHash, ...extra });
const purchOpts = (extra: any = {}) => ({
  issuerKeys: issuerKeys(), merchantKeys: merchantKeys(), checkout: { expectedAudience: 'merchant', expectedNonce: 'nonce-c' },
  payment: { expectedAudience: 'credential-provider', expectedNonce: 'nonce-p' }, now: T0 + 10, ...extra,
});

// ------------------------------------------------------------------------------------------------ option / result wrappers
const resolver = (m: any) => (h: any) => (m && typeof h.kid === 'string' && Object.prototype.hasOwnProperty.call(m, h.kid) ? m[h.kid] : undefined);
const num = (v: any) => (v === undefined ? {} : { v });
const baseOpts = (c: any) => ({
  resolveIssuerKey: resolver(c.issuerKeys), resolveMerchantKey: resolver(c.merchantKeys), expectedAudience: c.expectedAudience, expectedNonce: c.expectedNonce,
  ...(c.now !== undefined ? { now: c.now } : {}), ...(c.clockSkewSeconds !== undefined ? { clockSkewSeconds: c.clockSkewSeconds } : {}),
});
const hopOut = (h: any) => ({ index: h.index, kind: h.kind, claims: h.claims, mandate: h.mandate });
function projChain(r: any) {
  if (!r.ok) return { ok: false, reason: maskReason(r.reason), ...(r.violations ? { violations: r.violations } : {}) };
  return {
    ok: true, hops: r.hops.map(hopOut),
    ...(r.open ? { open: r.open, closed: r.closed } : {}),
    ...(r.checkoutJwt ? { checkoutJwt: r.checkoutJwt, checkout: r.checkout } : {}),
    ...(r.openHash ? { openHash: r.openHash } : {}),
  };
}
const projPurchase = (r: any) => (r.ok ? { ok: true, checkout: projChain(r.checkout), payment: projChain(r.payment) } : { ok: false, reason: maskReason(r.reason) });
const purchOptsOf = (c: any) => ({
  resolveIssuerKey: resolver(c.issuerKeys), resolveMerchantKey: resolver(c.merchantKeys), checkout: c.checkout, payment: c.payment,
  ...(c.context !== undefined ? { context: c.context } : {}), ...(c.now !== undefined ? { now: c.now } : {}), ...(c.clockSkewSeconds !== undefined ? { clockSkewSeconds: c.clockSkewSeconds } : {}),
});

// ------------------------------------------------------------------------------------------------ token mutations
function flip(s: string, i: number) { return s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1); }
function tokenMutations(tok: string): [string, string][] {
  const out: [string, string][] = [];
  const parts = tok.split('~');
  parts.forEach((p, i) => {
    if (!p) return;
    if (p.includes('.')) {
      const sg = p.split('.');
      sg.forEach((x, j) => { if (x) out.push([`flip jwt${i}.${j}`, [...parts.slice(0, i), [...sg.slice(0, j), flip(x, Math.floor(x.length / 2)), ...sg.slice(j + 1)].join('.'), ...parts.slice(i + 1)].join('~')]); });
      out.push([`sig${i} short`, [...parts.slice(0, i), sg.slice(0, 2).join('.') + '.' + 'A'.repeat(84), ...parts.slice(i + 1)].join('~')]);
      out.push([`sig${i} zero`, [...parts.slice(0, i), sg.slice(0, 2).join('.') + '.' + 'A'.repeat(86), ...parts.slice(i + 1)].join('~')]);
      out.push([`sig${i} dropped`, [...parts.slice(0, i), sg.slice(0, 2).join('.') + '.', ...parts.slice(i + 1)].join('~')]);
    } else {
      out.push([`flip disclosure${i}`, [...parts.slice(0, i), flip(p, Math.floor(p.length / 2)), ...parts.slice(i + 1)].join('~')]);
      out.push([`drop segment${i}`, [...parts.slice(0, i), ...parts.slice(i + 1)].join('~')]);
      out.push([`dup segment${i}`, [...parts.slice(0, i + 1), p, ...parts.slice(i + 1)].join('~')]);
    }
  });
  out.push(['no trailing ~', tok.replace(/~$/, '')], ['trailing kb', tok + 'x'], ['double trailing', tok + '~'], ['leading ~', '~' + tok], ['~~ as ~', tok.replace('~~', '~')]);
  out.push(['doubled', tok + tok], ['empty', ''], ['a', 'a'], ['~', '~'], ['~~', '~~'], ['truncated', tok.slice(0, Math.floor(tok.length / 2))]);
  const hops = tok.split('~~');
  if (hops.length === 2) out.push(['hop swap', `${hops[1]}~~${hops[0]}~`], ['second hop only', hops[1]], ['first hop only', hops[0] + '~'], ['third hop', `${hops[0]}~~${hops[1]}~~${hops[1]}`]);
  return out;
}
const sample = <T,>(xs: T[], k: number, label: string): T[] => {
  const r = rng(Number.parseInt(createHash('sha256').update(label).digest('hex').slice(0, 8), 16));
  const ys = [...xs];
  for (let i = ys.length - 1; i > 0; i--) { const j = r.int(0, i); [ys[i], ys[j]] = [ys[j]!, ys[i]!]; }
  return ys.slice(0, k);
};

// ================================================================================================ sdjwt: pure
for (const [i, s] of ['', 'a', 'hello', 'héllo wörld', '日本語', '😀', '\ud800', 'a\udc00b', '\u0000', 'x'.repeat(200), '{"a":1}'].entries()) await run('b64uEncode', `s${i}`, M.b64uEncode, [s]);
for (const [i, s] of ['', 'AA', 'AQ', 'AR', 'Zg', 'Zh', 'Zm8', 'Zm9v', 'A', 'AAA', 'AAAAA', 'A=', 'A==', 'ab+/', 'ab-_', ' AA', 'AA ', 'AA\n', 'é', 'AAAA\u0000', '-_-_', 'Zm9vYg', 'Zm9vYh', 'x'.repeat(43), 'x'.repeat(86)].entries()) await run('b64uDecode', `s${i}`, M.b64uDecode, [s, 'thing']);
const JSON_TEXTS = [
  '{}', '[]', 'null', 'true', '1', '"x"', '{"a":1}', '{"a":1,"a":2}', '{"a":{"b":1,"b":1}}', '{"a":[{"b":1},{"b":2}]}', '[{"a":1,"a":1}]', '{"a":1,"b":{"a":2}}',
  '{"a\\u0041":1,"aA":2}', '{"a":"b","a":"c"}', '{"__proto__":1,"__proto__":2}', '{"__proto__":{"x":1}}', '{"a":1,}', '{"a":}', '', ' ', '{', '[1,]', "{'a':1}", '{"a":01}',
  '{"a":1.0}', '{"a":1e3}', '{"a":-0}', '{"a":9007199254740993}', '﻿{}', '{"a":"\\ud800"}', '{"1":1,"b":2,"0":3}', '{"b":1,"a":2}', '  {"a" : [ 1 , 2 ] }  ',
  '{"a":1}x', '{"a":1}{"a":2}', '[[[[[[[[[[1]]]]]]]]]]', '{"a":"x\\"y","a":1}', '{"a":{"b":{"c":1,"c":2}}}', '{"":1,"":2}', '[{"a":1},{"a":2}]', '{"a":[1,{"a":2}],"b":null}',
];
for (const [i, t] of JSON_TEXTS.entries()) await run('parseJson', `t${i}`, M.parseJson, [t, 'doc']);
for (const [i, v] of [null, true, 1, 'sha-256', 'sha-384', 'sha-512', 'sha-1', 'SHA-256', 'sha256', '', [], {}, 'sha-256 '].entries()) await run('isSdAlg', `v${i}`, M.isSdAlg, [v]);
for (const [i, [v, alg]] of ([['hello', undefined], ['hello', 'sha-256'], ['hello', 'sha-384'], ['hello', 'sha-512'], ['', 'sha-256'], [' ~ ', 'sha-256'], ['\x7f', 'sha-256'], ['\x1f', 'sha-256'], ['é', 'sha-256'], ['a'.repeat(300), 'sha-512'], ['~~', 'sha-384'], ['a.b.c~d~', 'sha-256'], ['x', 'sha-1']] as any[]).entries()) {
  await run('sdDigest', `v${i}`, M.sdDigest, alg === undefined ? [v] : [v, alg]);
}

// JWKs
const goodJwk: any = pubOf('agent');
const jwkVars: [string, any][] = [['good', goodJwk], ['good+kid', { ...goodJwk, kid: 'k' }], ['good+alg', { ...goodJwk, alg: 'ES256' }], ['good+use', { ...goodJwk, use: 'sig' }], ['issuer', pubOf('issuer')]];
for (const [l, v] of variants(goodJwk, { depth: 2 })) jwkVars.push([l, v]);
for (const [i, v] of [null, 'x', 1, [], [goodJwk], {}, { ...goodJwk, d: keyFor('agent').publicJwk.x }, { ...goodJwk, alg: 'RS256' }, { ...goodJwk, alg: null }, { ...goodJwk, x: goodJwk.x.slice(0, 42) }, { ...goodJwk, x: goodJwk.x + 'A' },
  { ...goodJwk, y: goodJwk.x }, { ...goodJwk, x: 'A'.repeat(43), y: 'A'.repeat(43) }, { ...goodJwk, x: '_'.repeat(43) }, { ...goodJwk, x: goodJwk.x.slice(0, 42) + 'B' }, { ...goodJwk, x: goodJwk.x.slice(0, 42) + '_' },
  { ...goodJwk, crv: 'P-384' }, { ...goodJwk, kty: 'RSA' }, { ...goodJwk, x: goodJwk.x.replace(/./, '+') }].entries()) jwkVars.push([`hostile${i}`, v]);
for (const [l, v] of sample(jwkVars, 70, 'jwk')) {
  await run('assertP256Jwk', l, (j: any, w: string) => M.assertP256Jwk(j, w), [v, 'key']);
  await run('jwkThumbprint', l, (j: any) => M.jwkThumbprint(j), [v]);
}
// the unused low bits of the last base64url char: an alias of the same coordinate
{
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  for (const f of ['x', 'y']) for (let k = 0; k < 4; k++) {
    const v = B64.indexOf(goodJwk[f][42]);
    const alias = { ...goodJwk, [f]: goodJwk[f].slice(0, 42) + B64[(v & ~3) | k] };
    await run('assertP256Jwk', `alias-${f}${k}`, (j: any, w: string) => M.assertP256Jwk(j, w), [alias, 'key']);
  }
}
for (const l of ['issuer', 'agent', 'merchant', 'evil']) await run('jwkThumbprint', `label-${l}`, M.jwkThumbprint, [pubOf(l)]);
// key pairs from private JWKs (the public part derived from d)
const privOf = (label: string) => {
  const d = createHash('sha256').update(`atlas-pca-conformance/ap2/${label}`).digest();
  const ecdh = createECDH('prime256v1'); ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();
  return { kty: 'EC', crv: 'P-256', d: b64u(d), x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)), kid: label };
};
for (const [i, mut] of ([{}, { kid: undefined }, { kid: 5 }, { x: pubOf('issuer').x }, { y: pubOf('issuer').y }, { kty: 'RSA' }, { crv: 'P-384' }, { d: 'A'.repeat(43) }, { d: 'x' }, { d: undefined }, { x: undefined }] as any[]).entries()) {
  await run('ap2KeyPairFromPrivateJwk', `m${i}`, (label: string, m: any) => M.ap2KeyPairFromPrivateJwk({ ...privOf(label), ...m }).publicJwk, ['agent', mut]);
}

// ------------------------------------------------------------------------------------------------ scenarios
const S0 = scenario();
const SC: Record<string, ReturnType<typeof scenario>> = {
  default: S0,
  sha384: scenario({ sdAlg: 'sha-384' }),
  sha512: scenario({ sdAlg: 'sha-512' }),
  issuerHash: scenario({ hashMode: 'issuer_jwt_hash' }),
  jpy: scenario({ currency: 'JPY', price: 3000, budget: 500 }),
  kwd: scenario({ currency: 'KWD', price: 1500, budget: 100.5 }),
  rich: scenario({ pisp: PISP, executionDate: '2027-01-15T10:00:00Z', riskData: { score: 3 }, closedExp: T0 + 1800, pca: { v: 1, grant: { a: 1 }, terms: { c: 'USD' } }, payeeOpen: MERCH, instrumentOpen: INSTR, pispOpen: PISP }),
  preset: scenario({ paymentAmountOpen: { amount: 4000, currency: 'USD' }, payeeOpen: MERCH, instrumentOpen: INSTR, execOpen: '2027-01-15T10:00:00Z', executionDate: '2027-01-15T10:00:00Z' }),
  presetBad: scenario({ paymentAmountOpen: { amount: 1, currency: 'USD' }, payeeOpen: MERCH2, instrumentOpen: { id: 'x', type: 'card' }, pispOpen: PISP, execOpen: '2030-01-01' }),
  overRange: scenario({ amount: 60000, total: 60000, price: 30000 }),
  overBudget: scenario({ budget: 10 }),
  wrongPayee: scenario({ payee: MERCH2 }),
  wrongRef: scenario({ referenceOverride: 'wrong' }),
  monthly: scenario({ frequency: 'MONTHLY', maxOcc: 2 }),
  amountDiffers: scenario({ amount: 3999 }),
  expired: scenario({ exp: T0 - 90 }),
  nonAscii: scenario({ allowedPayees: [{ id: 'merchant_1', name: 'Démo 日本', website: 'https://demo-merchant.example' }, MERCH2] }),
  recurNoRange: scenario({ extraConstraints: [{ type: 'payment.execution_date', not_before: '2027-01-01', not_after: '2027-12-31T23:59:59Z' }, { type: 'payment.allowed_payment_instruments', allowed: [INSTR] }, { type: 'payment.allowed_pisps', allowed: [PISP] }], pisp: PISP, executionDate: '2027-06-01T00:00:00+02:00' }),
};
const NAMES = Object.keys(SC);

// parse / hop-level functions over every hop of every token
const hopTokens: [string, string][] = [];
for (const n of ['default', 'sha384', 'sha512', 'issuerHash', 'rich']) for (const [k, t] of [['oc', SC[n]!.openCheckout], ['cc', SC[n]!.checkoutChain], ['op', SC[n]!.openPayment], ['pc', SC[n]!.paymentChain]] as const) {
  M.splitChain(t).forEach((h: string, i: number) => hopTokens.push([`${n}/${k}${i}`, h]));
}
for (const [l, h] of hopTokens) {
  await run('parseSdJwtHop', l, (t: string) => { const x = M.parseSdJwtHop(t); return { ...x }; }, [h]);
  await run('hopSdJwt', l, (t: string) => { const x = M.parseSdJwtHop(t); return M.hopSdJwt({ jwt: x.jwt, disclosures: x.disclosures }); }, [h]);
  await run('sdHashOf', l, (t: string, a?: string) => M.sdHashOf(M.parseSdJwtHop(t), a), [h]);
  await run('issuerJwtHashOf', l, (t: string, a?: string) => M.issuerJwtHashOf(M.parseSdJwtHop(t), a), [h]);
  await run('processDisclosures', l, (t: string) => { const x = M.parseSdJwtHop(t); return M.processDisclosures(x.payload, x.disclosures, x.sdAlg); }, [h]);
}
for (const a of ['sha-256', 'sha-384', 'sha-512', 'sha-1']) {
  await run('sdHashOf', `alg-${a}`, (t: string, al: string) => M.sdHashOf(M.parseSdJwtHop(t), al), [hopTokens[0]![1], a]);
  await run('issuerJwtHashOf', `alg-${a}`, (t: string, al: string) => M.issuerJwtHashOf(M.parseSdJwtHop(t), al), [hopTokens[0]![1], a]);
}
// hostile hop strings
const HOP_HOSTILE = ['', '~', 'a', 'a~', 'a.b.c~', '.b.c~', 'a..c~', 'a.b.~', 'a.b.c.d~', 'e30.e30.AA~', 'e30.e30.AAAA~', 'e30.e30.AAAA~~', 'e30.e30.AAAA~x~', 'e30.e30.AAAA~e30~',
  'W10.e30.AAAA~', 'e30.W10.AAAA~', 'e30.e30.AAA~', 'e30.eyJfc2RfYWxnIjoic2hhLTUxMiJ9.AAAA~', 'e30.eyJfc2RfYWxnIjoic2hhLTEifQ.AAAA~', 'e30.eyJfc2RfYWxnIjpudWxsfQ.AAAA~', 'e30.eyJfc2RfYWxnIjo1fQ.AAAA~',
  'e30.eyJhIjoxLCJhIjoyfQ.AAAA~', 'e30.e30.AAAA~AAAA~AAAA~', 'e30.e30.é~', 'ZQ.e30.AAAA~', '/w.e30.AAAA~', 'e3', '5.e30.AAAA~'];
for (const [i, t] of HOP_HOSTILE.entries()) {
  await run('parseSdJwtHop', `hostile${i}`, (x: string) => ({ ...M.parseSdJwtHop(x) }), [t]);
  await run('splitChain', `hostile${i}`, M.splitChain, [t]);
}
for (const [i, t] of ['x', 'a~~b~~c', 'a~~b~~c~~d~~e~~f~~g~~h', 'a~~b~~c~~d~~e~~f~~g~~h~~i', '~~', 'a~~~~b', 'a~b~~c~d~', 'a~~'].entries()) await run('splitChain', `t${i}`, M.splitChain, [t]);
for (const [n, s] of Object.entries(SC).slice(0, 3)) for (const [k, t] of [['oc', s.openCheckout], ['cc', s.checkoutChain], ['op', s.openPayment], ['pc', s.paymentChain]] as const) await run('splitChain', `${n}/${k}`, M.splitChain, [t]);

// disclosure processing over crafted payloads
const dsalt = (n: number) => Buffer.from(`salt-${String(n).padStart(12, '0')}`).toString('base64url');
const enc = (v: any) => Buffer.from(JSON.stringify(v)).toString('base64url');
const dig = (raw: string, alg = 'sha-256') => M.sdDigest(raw, alg);
const dProp = (n: number, name: string, value: any) => enc([dsalt(n), name, value]);
const dElem = (n: number, value: any) => enc([dsalt(n), value]);
const pA = dProp(1, 'a', 1), pB = dProp(2, 'b', { x: 1 }), pC = dProp(3, 'c', [1, 2]), eD = dElem(4, 'd1'), eE = dElem(5, { k: 'v' }), pNest = dProp(6, 'n', { _sd: [dig(dProp(7, 'inner', 'deep'))] }), pInner = dProp(7, 'inner', 'deep');
const PD: [string, any, string[]][] = [
  ['plain', { x: 1 }, []],
  ['sd single', { _sd: [dig(pA)] }, [pA]],
  ['sd multiple + decoy', { _sd: [dig(pA), 'decoyDigestAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', dig(pB)], z: 1 }, [pA, pB]],
  ['sd holder withheld', { _sd: [dig(pA), dig(pB)] }, [pA]],
  ['sd none disclosed', { _sd: [dig(pA)] }, []],
  ['array element', { list: [{ '...': dig(eD) }, 'plain', { '...': dig(eE) }] }, [eD, eE]],
  ['array decoy', { list: [{ '...': 'decoy' }, 1] }, []],
  ['nested sd', { _sd: [dig(pNest)] }, [pNest, pInner]],
  ['nested missing inner', { _sd: [dig(pNest)] }, [pNest]],
  ['unreferenced', { x: 1 }, [pA]],
  ['duplicate disclosure', { _sd: [dig(pA)] }, [pA, pA]],
  ['digest twice', { _sd: [dig(pA), dig(pA)] }, [pA]],
  ['digest in two places', { _sd: [dig(pA)], o: { _sd: [dig(pA)] } }, [pA]],
  ['property from array pos', { list: [{ '...': dig(pA) }] }, [pA]],
  ['element from property pos', { _sd: [dig(eD)] }, [eD]],
  ['collision', { a: 5, _sd: [dig(pA)] }, [pA]],
  ['collision later', { _sd: [dig(pA)], a: 5 }, [pA]],
  ['_sd not array', { _sd: 'x' }, []],
  ['_sd null', { _sd: null }, []],
  ['_sd non-string', { _sd: [1] }, []],
  ['placeholder extra key', { list: [{ '...': dig(eD), x: 1 }] }, [eD]],
  ['placeholder non-string', { list: [{ '...': 5 }] }, []],
  ['dots key', { '...': 'x' }, []],
  ['_sd_alg dropped', { _sd_alg: 'sha-256', a: 1 }, []],
  ['reserved _sd', { _sd: [dig(dProp(9, '_sd', 1))] }, [dProp(9, '_sd', 1)]],
  ['reserved dots', { _sd: [dig(dProp(9, '...', 1))] }, [dProp(9, '...', 1)]],
  ['empty salt', { _sd: [dig(enc(['', 'a', 1]))] }, [enc(['', 'a', 1])]],
  ['salt non-string', { _sd: [dig(enc([1, 'a', 1]))] }, [enc([1, 'a', 1])]],
  ['name non-string', { _sd: [dig(enc(['s', 1, 1]))] }, [enc(['s', 1, 1])]],
  ['4 elements', { _sd: [dig(enc(['s', 'a', 1, 2]))] }, [enc(['s', 'a', 1, 2])]],
  ['1 element', { _sd: [dig(enc(['s']))] }, [enc(['s'])]],
  ['not array', { _sd: [dig(enc({ a: 1 }))] }, [enc({ a: 1 })]],
  ['bad b64', { _sd: ['x'] }, ['!!']],
  ['non-canonical b64', { _sd: ['x'] }, ['AB']],
  ['bad utf8', { _sd: ['x'] }, [Buffer.from([0xff, 0xfe]).toString('base64url')]],
  ['bad json', { _sd: ['x'] }, [Buffer.from('[1,').toString('base64url')]],
  ['dup key in disclosure', { _sd: ['x'] }, [Buffer.from('["s","a",{"k":1,"k":2}]').toString('base64url')]],
  ['empty disclosure string', { _sd: ['x'] }, ['']],
  ['deep ok', (() => { let v: any = { _sd: [dig(pA)] }; for (let i = 0; i < 30; i++) v = { n: v }; return v; })(), [pA]],
  ['deep too deep', (() => { let v: any = { x: 1 }; for (let i = 0; i < 40; i++) v = { n: v }; return v; })(), []],
  ['deep array', { list: (() => { let v: any = [1]; for (let i = 0; i < 33; i++) v = [v]; return v; })() }, []],
  ['__proto__ claim', { _sd: [dig(dProp(11, '__proto__', { polluted: 1 }))] }, [dProp(11, '__proto__', { polluted: 1 })]],
  ['numeric keys', { _sd: [dig(dProp(12, '1', 'one'))], '2': 'two', b: 3, '0': 'zero' }, [dProp(12, '1', 'one')]],
  ['value null', { _sd: [dig(dProp(13, 'n', null))] }, [dProp(13, 'n', null)]],
  ['unicode', { _sd: [dig(dProp(14, 'naïve', '日本'))] }, [dProp(14, 'naïve', '日本')]],
];
for (const [l, payload, ds] of PD) {
  for (const alg of ['sha-256', 'sha-512']) {
    const ds2 = alg === 'sha-256' ? ds : ds;
    await run('processDisclosures', `${l}/${alg}`, M.processDisclosures, [payload, ds2, alg]);
  }
}
// sha-384 / sha-512 digests need their own placeholders
for (const alg of ['sha-384', 'sha-512']) {
  await run('processDisclosures', `sd single/${alg}-own`, M.processDisclosures, [{ _sd: [dig(pA, alg)] }, [pA], alg]);
  await run('processDisclosures', `array element/${alg}-own`, M.processDisclosures, [{ list: [{ '...': dig(eD, alg) }] }, [eD], alg]);
}

// disclosureBuilder
const BOPS: [string, string | undefined, any[]][] = [
  ['elements', undefined, [{ kind: 'element', value: { id: 'a' } }, { kind: 'element', value: 'x' }, { kind: 'element', value: null }]],
  ['properties', 'sha-256', [{ kind: 'property', name: 'k', value: 1 }, { kind: 'property', name: 'é', value: [1, { a: 'b' }] }]],
  ['mixed 384', 'sha-384', [{ kind: 'element', value: 1 }, { kind: 'property', name: 'p', value: { z: 1, a: 2 } }]],
  ['mixed 512', 'sha-512', [{ kind: 'property', name: 'p', value: ' \ud800"\\' }, { kind: 'element', value: 1.5 }]],
  ['empty', undefined, []],
  ['numeric keys', 'sha-256', [{ kind: 'element', value: { '2': 'b', '1': 'a', z: 0, '0': 'z' } }]],
];
for (const [l, alg, ops] of BOPS) {
  await run('disclosureBuilder', l, (a: string | null, os: any[]) => {
    const b = M.disclosureBuilder(a ?? undefined, counterSalt());
    const results = os.map((op: any) => (op.kind === 'element' ? b.element(op.value) : b.property(op.name, op.value)));
    return { results, disclosures: b.disclosures };
  }, [alg ?? null, ops]);
}

// JWT parse / verify (hop signatures and merchant JWTs)
const jwtCases: [string, string][] = [];
for (const [n, s] of Object.entries(SC)) jwtCases.push([`${n}/checkout_jwt`, s.checkoutJwt]);
for (const [i, t] of ['', 'a', 'a.b', 'a.b.c', 'a.b.c.d', 'e30.e30.AA', 'e30.e30.AAAA', 'W10.e30.AAAA', 'e30.W10.AAAA', 'e30..AAAA', '.e30.AAAA', 'e30.e30.A', 'e30.e30.AAA', 'e30.e30.é', 'e30.e30.AB', 'eyJhIjoxLCJhIjoyfQ.e30.AAAA'].entries()) jwtCases.push([`hostile${i}`, t]);
for (const m of tokenMutations(S0.checkoutJwt)) jwtCases.push([`mut/${m[0]}`, m[1]]);
for (const [l, t] of jwtCases) {
  await run('parseJwt', l, (x: string, w: string) => ({ ...M.parseJwt(x, w) }), [t, 'jwt']);
  for (const k of ['merchant', 'issuer']) await run('verifyJwtEs256', `${l}/${k}`, (x: string, j: any) => M.verifyJwtEs256(M.parseJwt(x, 'jwt'), j), [t, pubOf(k)]);
}
// hop signatures: verified under the open mandate's agent key / the issuer key
for (const [l, h] of hopTokens) for (const k of ['issuer', 'agent']) await run('verifyHopSignature', `${l}/${k}`, (t: string, j: any) => M.verifyHopSignature(M.parseSdJwtHop(t), j), [h, pubOf(k)]);
for (const [i, jwk] of [{ ...goodJwk, d: 'x' }, { kty: 'EC' }, null, { ...goodJwk, alg: 'ES384' }].entries()) await run('verifyHopSignature', `badkey${i}`, (t: string, j: any) => M.verifyHopSignature(M.parseSdJwtHop(t), j), [hopTokens[0]![1], jwk]);
// aliases of the agent key coordinates (unused low bits of the last base64url char) verify the closed hop like the key itself
for (const f of ['x', 'y']) for (let k = 0; k < 4; k++) {
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const v = B64.indexOf(goodJwk[f][42]);
  await run('verifyHopSignature', `alias-${f}${k}`, (t: string, j: any) => M.verifyHopSignature(M.parseSdJwtHop(t), j), [M.splitChain(S0.paymentChain)[1], { ...goodJwk, [f]: goodJwk[f].slice(0, 42) + B64[(v & ~3) | k] }]);
}
// alg other than ES256: re-sign a header with another alg by hand is impossible (signSdJwt pins ES256): flip the header alg instead
for (const alg of ['ES384', 'none', 'HS256', 'es256']) {
  const h = M.parseSdJwtHop(S0.openCheckout);
  const hdr = Buffer.from(JSON.stringify({ ...h.header, alg })).toString('base64url');
  const tok = [hdr, ...h.jwt.split('.').slice(1)].join('.') + '~' + h.disclosures.map((d: string) => d + '~').join('');
  await run('verifyHopSignature', `alg-${alg}`, (t: string, j: any) => M.verifyHopSignature(M.parseSdJwtHop(t), j), [tok, pubOf('issuer')]);
}

// signing (signature segments masked)
const hdrVars: any[] = [{ typ: 'dc+sd-jwt' }, { typ: 'kb+sd-jwt', kid: 'k1' }, { typ: 'x', x5c: ['MIIB', 'MIIC'] }, { typ: 'x', alg: 'none' }, { typ: 'é' }, { typ: 'x', '2': 'a', '1': 'b' }];
for (const [i, h] of hdrVars.entries()) {
  await run('signSdJwt', `h${i}`, (a: any) => stripSig(M.signSdJwt({ header: a.header, payload: a.payload, disclosures: a.disclosures, privateKey: keyFor(a.key).privateKey })), [{ header: h, payload: { a: 1, b: [1, 2], '1': 'x' }, disclosures: i % 2 ? ['d1', 'd2'] : [], key: 'issuer' }]);
  await run('signJwtEs256', `h${i}`, (a: any) => stripSig(M.signJwtEs256({ header: a.header, payload: a.payload, privateKey: keyFor(a.key).privateKey })), [{ header: h, payload: { id: 'x', n: 1.5, s: '日本\ud800' }, key: 'merchant' }]);
}
// ES256 round trip: what we sign verifies (checked here once, so a broken generator fails loudly)
{
  const t = M.signSdJwt({ header: { typ: 'x' }, payload: { a: 1 }, disclosures: [], privateKey: keyFor('issuer').privateKey });
  if (!M.verifyHopSignature(M.parseSdJwtHop(t), pubOf('issuer'))) throw new Error('self-verify failed');
}

// ================================================================================================ mandates
for (const c of ['USD', 'EUR', 'JPY', 'KRW', 'VND', 'BHD', 'KWD', 'TND', 'CLF', 'UYW', 'XYZ', 'usd', 'US', 'USDD', '', 'U1D', 'ÜSD', ' USD', 'USD ', 'ISK', 'XPF']) await run('currencyExponent', c || 'empty', M.currencyExponent, [c]);
for (const v of [null, 5, true, [], {}]) await run('currencyExponent', `hostile-${JSON.stringify(v)}`, M.currencyExponent, [v]);
const MAJORS = [0, 0.01, 0.1, 0.2, 0.29, 0.3, 1, 1.005, 1.01, 1.5, 2.5, 120.5, 120.55, 120.555, 999.99, 1e6, 12345678.9, 0.1 + 0.2, 4503599627370495.5, 90071992547409.91, 90071992547409.92, 9007199254740991, 9007199254740992, 1e15, 1e21, 1e22, 5e-324, 1e-7, -0, -1, -0.01, 0.005, 0.0049999, 0.015, 0.025, 1234.5678, 10.001, 10.0001, 0.0005];
for (const c of ['USD', 'JPY', 'KWD', 'CLF']) for (const [i, m] of MAJORS.entries()) await run('toMinorUnits', `${c}/${i}`, M.toMinorUnits, [m, c]);
for (const [i, v] of [null, '5', true, [], {}, 'x'].entries()) await run('toMinorUnits', `hostile${i}`, M.toMinorUnits, [v, 'USD']);
await run('toMinorUnits', 'bad-currency', M.toMinorUnits, [1, 'xx']);
for (const c of ['USD', 'JPY', 'KWD', 'CLF']) for (const [i, m] of [0, 1, 5, 99, 100, 12050, 9007199254740991, 9007199254740992, -1, -0, 1.5, 1e21, 123456789].entries()) await run('fromMinorUnits', `${c}/${i}`, M.fromMinorUnits, [m, c]);
for (const [i, v] of [null, '5', true, [], {}].entries()) await run('fromMinorUnits', `hostile${i}`, M.fromMinorUnits, [v, 'USD']);

// validators: valid seeds + structural variants
const dis = (s: any) => ({ open: M.parseSdJwtHop(s.openPayment), openC: M.parseSdJwtHop(s.openCheckout) });
const mandatesOf = (s: any) => {
  const chainP = M.verifyDelegationChain(s.paymentChain, baseOpts(payOpts(s)));
  const chainC = M.verifyDelegationChain(s.checkoutChain, baseOpts(chainOpts()));
  return { openPayment: chainP.hops[0].mandate, closedPayment: chainP.hops[1].mandate, openCheckout: chainC.hops[0].mandate, closedCheckout: chainC.hops[1].mandate };
};
const MS = mandatesOf(S0), MR = mandatesOf(SC.rich!), MJ = mandatesOf(SC.jpy!);
const VALID: [string, string, any][] = [
  ['openPaymentMandateProblems', 'op', MS.openPayment], ['openPaymentMandateProblems', 'opRich', MR.openPayment], ['openPaymentMandateProblems', 'opJpy', MJ.openPayment],
  ['paymentMandateProblems', 'cp', MS.closedPayment], ['paymentMandateProblems', 'cpRich', MR.closedPayment],
  ['openCheckoutMandateProblems', 'oc', MS.openCheckout], ['checkoutMandateProblems', 'cc', MS.closedCheckout],
];
const fullPayConstraints = { vct: 'mandate.payment.open.1', cnf: { jwk: goodJwk }, iat: 1, exp: 2, constraints: [
  { type: 'payment.agent_recurrence', frequency: 'DAILY', max_occurrences: 3 }, { type: 'payment.allowed_payees', allowed: [MERCH] }, { type: 'payment.allowed_payment_instruments', allowed: [INSTR] },
  { type: 'payment.allowed_pisps', allowed: [PISP] }, { type: 'payment.amount_range', currency: 'USD', max: 10, min: 1 }, { type: 'payment.budget', currency: 'USD', max: 10.5 },
  { type: 'payment.execution_date', not_before: 'a', not_after: 'b' }, { type: 'payment.reference', conditional_transaction_id: 'x' }], payee: MERCH, payment_amount: { amount: 1, currency: 'USD' }, payment_instrument: INSTR, pisp: PISP, execution_date: 'd', risk_data: {}, x_pca: {} };
const fullCheckout = { vct: 'mandate.checkout.open.1', cnf: { jwk: goodJwk }, iat: 1, exp: 2, constraints: [{ type: 'checkout.allowed_merchants', allowed: [MERCH, MERCH2] }, { type: 'checkout.line_items', items: [{ id: 'l', acceptable_items: [{ id: 'a', title: 't' }], quantity: 2 }] }], x_pca: { a: 1 } };
VALID.push(['openPaymentMandateProblems', 'full', fullPayConstraints], ['openCheckoutMandateProblems', 'full', fullCheckout]);
for (const [fn, l, seed] of VALID) {
  await run(fn, `valid/${l}`, (M as any)[fn], [seed]);
  for (const [vl, v] of sample([...variants(seed, { depth: 5 })], 70, `${fn}/${l}`)) await run(fn, `${l}/${vl}`, (M as any)[fn], [v]);
}
for (const fn of ['openPaymentMandateProblems', 'paymentMandateProblems', 'openCheckoutMandateProblems', 'checkoutMandateProblems']) for (const [i, v] of [null, 1, 'x', [], [1], true].entries()) await run(fn, `nonobject${i}`, (M as any)[fn], [v]);
// constraint-level problem coverage (one document per constraint shape, then edits)
const cbase = (c: any) => ({ ...fullPayConstraints, constraints: [c, { type: 'payment.reference', conditional_transaction_id: 'x' }] });
for (const [i, c] of ([
  { type: 'payment.agent_recurrence', frequency: 'HOURLY' }, { type: 'payment.agent_recurrence', frequency: 'DAILY', max_occurrences: 0 }, { type: 'payment.agent_recurrence', frequency: 'DAILY', max_occurrences: 1.5 },
  { type: 'payment.agent_recurrence', frequency: 'DAILY', max_occurrences: null }, { type: 'payment.amount_range', currency: 'USD', max: 5, min: 6 }, { type: 'payment.amount_range', currency: 'USD', max: 5.5 },
  { type: 'payment.amount_range', currency: 'usd', max: -1 }, { type: 'payment.amount_range', currency: 'USD', max: 5, min: null }, { type: 'payment.budget', currency: 'USD', max: -1 }, { type: 'payment.budget', currency: 'USD', max: '5' },
  { type: 'payment.budget', currency: 'USD', max: -0 }, { type: 'payment.execution_date', not_before: 5 }, { type: 'payment.execution_date', not_after: null }, { type: 'payment.execution_date' }, { type: 'payment.reference' },
  { type: 'payment.reference', conditional_transaction_id: '' }, { type: 'payment.allowed_payees' }, { type: 'payment.allowed_payees', allowed: [{ id: 'a' }] }, { type: 'payment.allowed_payees', allowed: [{ id: 'a', name: 'n', website: 5 }] },
  { type: 'payment.allowed_payees', allowed: [1] }, { type: 'payment.allowed_payment_instruments', allowed: [{ id: 'a' }] }, { type: 'payment.allowed_payment_instruments', allowed: [{ id: 'a', type: 't', description: 5 }] },
  { type: 'payment.allowed_pisps', allowed: [{ legal_name: 'a' }] }, { type: 'payment.allowed_pisps', allowed: 5 }, { type: 'payment.nope' }, { type: 5 }, 'x', null, [], {}, { type: 'payment.allowed_payees', allowed: [] },
] as any[]).entries()) await run('openPaymentMandateProblems', `constraint${i}`, M.openPaymentMandateProblems, [cbase(c)]);
const ccbase = (c: any) => ({ ...fullCheckout, constraints: [c] });
for (const [i, c] of ([
  { type: 'checkout.line_items' }, { type: 'checkout.line_items', items: [] }, { type: 'checkout.line_items', items: [1] }, { type: 'checkout.line_items', items: [{ id: '', acceptable_items: [], quantity: 0 }] },
  { type: 'checkout.line_items', items: [{ id: 'a', acceptable_items: [{ id: 'x' }], quantity: 1.5 }] }, { type: 'checkout.line_items', items: [{ id: 'a', acceptable_items: 'x', quantity: 1 }] },
  { type: 'checkout.line_items', items: [{ id: 'a', acceptable_items: [1], quantity: -1 }] }, { type: 'checkout.allowed_merchants' }, { type: 'checkout.allowed_merchants', allowed: [{}] }, { type: 'checkout.other' }, 5, null,
] as any[]).entries()) await run('openCheckoutMandateProblems', `constraint${i}`, M.openCheckoutMandateProblems, [ccbase(c)]);
for (const [i, v] of [{ ...fullPayConstraints, constraints: [] }, { ...fullPayConstraints, constraints: 'x' }, { ...fullPayConstraints, constraints: null }, { ...fullPayConstraints, vct: 'mandate.payment.1' }, { ...fullPayConstraints, iat: -1 }, { ...fullPayConstraints, exp: 1.5 }, { ...fullPayConstraints, iat: null },
  { ...fullPayConstraints, x_pca: null }, { ...fullPayConstraints, x_pca: [] }, { ...fullPayConstraints, cnf: { jwk: { ...goodJwk, d: 'x' } } }, { ...fullPayConstraints, cnf: {} }, { ...fullPayConstraints, cnf: null }].entries()) await run('openPaymentMandateProblems', `doc${i}`, M.openPaymentMandateProblems, [v]);
for (const [i, kind] of (['openPayment', 'closedPayment', 'openCheckout', 'closedCheckout'] as const).entries()) {
  const fnName = ['openPaymentMandateProblems', 'paymentMandateProblems', 'openCheckoutMandateProblems', 'checkoutMandateProblems'][i]!;
  const seed = (MS as any)[kind];
  await run('assertValid', `ok/${kind}`, (k: string, v: any, w: string) => M.assertValid(v, (M as any)[k], w), [fnName, seed, 'mandate']);
  await run('assertValid', `bad/${kind}`, (k: string, v: any, w: string) => M.assertValid(v, (M as any)[k], w), [fnName, { ...seed, vct: 'nope' }, 'mandate']);
  await run('assertValid', `bad2/${kind}`, (k: string, v: any, w: string) => M.assertValid(v, (M as any)[k], w), [fnName, { ...seed, iat: -1, exp: 'x', x_pca: 5 }, 'wrapped']);
}
await run('constants', 'all', () => ({
  VCT_CHECKOUT: M.VCT_CHECKOUT, VCT_CHECKOUT_OPEN: M.VCT_CHECKOUT_OPEN, VCT_PAYMENT: M.VCT_PAYMENT, VCT_PAYMENT_OPEN: M.VCT_PAYMENT_OPEN, PCA_CLAIM: M.PCA_CLAIM,
  FREQUENCIES: M.FREQUENCIES, AP2_COMMIT: M.AP2_COMMIT, PCA_BINDING_VERSION: M.PCA_BINDING_VERSION, TYP_TERMINAL: M.TYP_TERMINAL, TYP_INTERMEDIATE: M.TYP_INTERMEDIATE,
}), []);

// ================================================================================================ constraints
const merchants: any[] = [MERCH, MERCH2, { id: 'merchant_1' }, { name: 'Demo Merchant', website: 'https://demo-merchant.example' }, { name: 'Demo Merchant' }, { id: '', name: 'Demo Merchant', website: 'https://demo-merchant.example' },
  { id: 'merchant_1', name: 'Other' }, { id: 'merchant_9', name: 'Demo Merchant', website: 'https://demo-merchant.example' }, { id: 5 }, { id: 0, name: 'n', website: 'w' }, {}, { name: 'n', website: '' }];
for (const [i, a] of merchants.entries()) for (const [j, b] of merchants.entries()) await run('merchantMatches', `${i}-${j}`, M.merchantMatches, [a, b]);

const OPEN_BASE = MS.openPayment, CLOSED_BASE = MS.closedPayment;
const withC = (c: any[], extra: any = {}) => ({ ...OPEN_BASE, constraints: c, ...extra });
const clo = (over: any = {}) => ({ ...CLOSED_BASE, ...over });
const ctx = (a: number, u: number, last?: number) => ({ totalAmount: a, totalUses: u, ...(last !== undefined ? { lastUsedDate: last } : {}) });
const AR = { type: 'payment.amount_range', currency: 'USD', min: 100, max: 5000 };
const BU = { type: 'payment.budget', currency: 'USD', max: 100 };
const RE = { type: 'payment.reference', conditional_transaction_id: 'REF' };
const rec = (frequency: string, max_occurrences?: number) => ({ type: 'payment.agent_recurrence', frequency, ...(max_occurrences !== undefined ? { max_occurrences } : {}) });
const pcCases: [string, any, any, any][] = [];
const addPC = (l: string, open: any, closed: any, opts: any) => pcCases.push([l, open, closed, opts]);
const NOW = { now: T0 };
// amount range
for (const [l, amt, cur] of [['at max', 5000, 'USD'], ['over max', 5001, 'USD'], ['at min', 100, 'USD'], ['under min', 99, 'USD'], ['zero', 0, 'USD'], ['cur mismatch', 1000, 'EUR'], ['cur lower', 1000, 'usd']] as any[]) addPC(`range ${l}`, withC([AR]), clo({ payment_amount: { amount: amt, currency: cur } }), NOW);
addPC('range no min', withC([{ type: 'payment.amount_range', currency: 'USD', max: 10 }]), clo({ payment_amount: { amount: 11, currency: 'USD' } }), NOW);
addPC('range min only violated twice', withC([{ type: 'payment.amount_range', currency: 'EUR', min: 50, max: 60 }]), clo({ payment_amount: { amount: 10, currency: 'USD' } }), NOW);
addPC('range fractional', withC([{ type: 'payment.amount_range', currency: 'USD', min: 0, max: 5000.5 }]), clo({ payment_amount: { amount: 5000.25, currency: 'USD' } }), NOW);
// payees / instruments / pisps
addPC('payees match id', withC([{ type: 'payment.allowed_payees', allowed: [MERCH2, MERCH] }]), clo(), NOW);
addPC('payees no match', withC([{ type: 'payment.allowed_payees', allowed: [MERCH2] }]), clo(), NOW);
addPC('payees empty', withC([{ type: 'payment.allowed_payees', allowed: [] }]), clo(), NOW);
addPC('payees name site', withC([{ type: 'payment.allowed_payees', allowed: [{ name: 'Demo Merchant', website: 'https://demo-merchant.example' }] }]), clo({ payee: { id: 'z', name: 'Demo Merchant', website: 'https://demo-merchant.example' } }), NOW);
addPC('payees name only', withC([{ type: 'payment.allowed_payees', allowed: [{ name: 'Demo Merchant' }] }]), clo({ payee: { id: 'z', name: 'Demo Merchant' } }), NOW);
addPC('instruments match', withC([{ type: 'payment.allowed_payment_instruments', allowed: [INSTR] }]), clo(), NOW);
addPC('instruments no match', withC([{ type: 'payment.allowed_payment_instruments', allowed: [{ id: 'other', type: 'card' }] }]), clo(), NOW);
addPC('pisps match', withC([{ type: 'payment.allowed_pisps', allowed: [PISP] }]), clo({ pisp: PISP }), NOW);
addPC('pisps missing', withC([{ type: 'payment.allowed_pisps', allowed: [PISP] }]), clo(), NOW);
addPC('pisps differ', withC([{ type: 'payment.allowed_pisps', allowed: [PISP] }]), clo({ pisp: { ...PISP, brand_name: 'X' } }), NOW);
// reference
addPC('ref ok', withC([RE]), clo(), { ...NOW, openCheckoutHash: 'REF' });
addPC('ref wrong', withC([RE]), clo(), { ...NOW, openCheckoutHash: 'OTHER' });
addPC('ref missing', withC([RE]), clo(), NOW);
addPC('ref empty', withC([RE]), clo(), { ...NOW, openCheckoutHash: '' });
// budget
for (const [l, max, past, amt] of [['fits', 100, 0, 4000], ['exact', 100, 6000, 4000], ['over', 100, 6001, 4000], ['frac max', 0.29, 0, 29], ['frac over', 0.29, 0, 30], ['0.1+0.2', 0.30000000000000004, 0, 30], ['0.57', 0.57, 0, 57], ['1.15', 1.15, 0, 115], ['not whole', 0.005, 0, 0], ['huge', 1e15, 0, 5], ['zero', 0, 0, 0], ['zero over', 0, 0, 1]] as any[]) {
  addPC(`budget ${l}`, withC([{ type: 'payment.budget', currency: 'USD', max }]), clo({ payment_amount: { amount: amt, currency: 'USD' } }), { ...NOW, context: ctx(past, 0) });
}
addPC('budget no ctx', withC([BU]), clo(), NOW);
addPC('budget cur mismatch', withC([{ type: 'payment.budget', currency: 'EUR', max: 100 }]), clo(), { ...NOW, context: ctx(0, 0) });
for (const [l, c] of [['neg', ctx(-1, 0)], ['frac', ctx(1.5, 0)], ['str', { totalAmount: '1', totalUses: 0 }], ['neg0', ctx(-0, 0)], ['uses frac', ctx(0, 1.5)], ['last neg', ctx(0, 0, -5)], ['last null', { totalAmount: 0, totalUses: 0, lastUsedDate: null }], ['missing', { totalUses: 0 }], ['big', ctx(2 ** 53, 0)], ['empty', {}]] as any[]) {
  addPC(`budget badctx ${l}`, withC([BU]), clo(), { ...NOW, context: c });
  addPC(`recur badctx ${l}`, withC([AR, BU, rec('DAILY', 3)]), clo(), { ...NOW, context: c });
}
// recurrence
addPC('recur needs range+budget', withC([rec('ON_DEMAND', 3)]), clo(), { ...NOW, context: ctx(0, 0) });
addPC('recur needs budget', withC([AR, rec('ON_DEMAND', 3)]), clo(), { ...NOW, context: ctx(0, 0) });
addPC('recur max ok', withC([AR, BU, rec('ON_DEMAND', 3)]), clo(), { ...NOW, context: ctx(0, 2) });
addPC('recur max hit', withC([AR, BU, rec('ON_DEMAND', 3)]), clo(), { ...NOW, context: ctx(0, 3) });
addPC('recur max no ctx', withC([AR, BU, rec('ON_DEMAND', 3)]), clo(), NOW);
addPC('recur on-demand no max no ctx', withC([AR, BU, rec('ON_DEMAND')]), clo(), NOW);
const MID = 1_800_000_000 + 12 * 3600; // 2027-01-15 08:00 UTC, a Friday
for (const f of ['DAILY', 'WEEKLY', 'BIWEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUALLY', 'HOURLY']) {
  for (const [l, last] of [['none', undefined], ['same day', MID - 3600], ['day start', 1_799_971_200 + 0], ['prev day', MID - 86400], ['prev week', MID - 7 * 86400], ['prev month', MID - 31 * 86400], ['prev quarter', MID - 100 * 86400], ['prev year', MID - 370 * 86400], ['future', MID + 86400], ['zero', 0]] as any[]) {
    addPC(`recur ${f} ${l}`, withC([AR, BU, rec(f)]), clo(), { now: MID, context: ctx(0, 1, last) });
  }
  addPC(`recur ${f} no ctx`, withC([AR, BU, rec(f)]), clo(), { now: MID });
}
for (const now of [0, 1, 86399, 86400, 3 * 86400 - 1, 3 * 86400, 1_735_689_600, 1_735_689_599, 1_704_067_200, 1_709_251_200, 1_719_792_000, 1_800_000_000.5, 4102444800, 8.64e12]) {
  for (const f of ['WEEKLY', 'BIWEEKLY', 'MONTHLY', 'QUARTERLY']) for (const last0 of new Set([0, now - 1, now - 7 * 86400, now - 14 * 86400, now - 100 * 86400].map((x) => Math.max(0, x)))) addPC(`recur-clock ${f} now ${now} last ${last0}`, withC([AR, BU, rec(f)]), clo(), { now, context: ctx(0, 1, last0) });
}
// execution date
const ED = (nb?: any, na?: any) => ({ type: 'payment.execution_date', ...(nb !== undefined ? { not_before: nb } : {}), ...(na !== undefined ? { not_after: na } : {}) });
for (const [l, closedDate, nb, na] of [
  ['inside', '2027-01-15T10:00:00Z', '2027-01-01', '2027-02-01'], ['before', '2026-12-31T23:59:59Z', '2027-01-01', '2027-02-01'], ['after', '2027-02-01T00:00:01Z', '2027-01-01', '2027-02-01'],
  ['edge before', '2027-01-01', '2027-01-01', '2027-02-01'], ['edge after', '2027-02-01', '2027-01-01', '2027-02-01'], ['offset', '2027-01-15T10:00:00+05:30', '2027-01-15T04:30:00Z', '2027-01-15T04:30:00Z'],
  ['offset neg', '2027-01-15T10:00:00-08:00', '2027-01-15T18:00:00Z', '2027-01-15T18:00:00.000Z'], ['fraction', '2027-01-15T10:00:00.1234567Z', '2027-01-15T10:00:00.123Z', '2027-01-15T10:00:00.123Z'],
  ['fraction short', '2027-01-15T10:00:00.5Z', '2027-01-15T10:00:00.500Z', undefined], ['bad date', 'not a date', '2027-01-01', undefined], ['Feb 30', '2027-02-30', '2027-01-01', undefined], ['leap day', '2028-02-29', '2028-02-29', '2028-02-29'],
  ['non-leap day', '2027-02-29', undefined, '2030-01-01'], ['hour 24', '2027-01-15T24:00:00Z', undefined, '2030-01-01'], ['sec 60', '2027-01-15T10:00:60Z', undefined, '2030-01-01'], ['min 60', '2027-01-15T10:60:00Z', undefined, '2030-01-01'],
  ['offset 24', '2027-01-15T10:00:00+24:00', undefined, '2030-01-01'], ['offset min 60', '2027-01-15T10:00:00+01:60', undefined, '2030-01-01'], ['no zone', '2027-01-15T10:00:00', undefined, '2030-01-01'], ['lower z', '2027-01-15T10:00:00z', undefined, '2030-01-01'],
  ['lower t', '2027-01-15t10:00:00Z', undefined, '2030-01-01'], ['space', '2027-01-15 10:00:00Z', undefined, '2030-01-01'], ['trailing nl', '2027-01-15\n', undefined, '2030-01-01'], ['month 00', '2027-00-10', undefined, '2030-01-01'], ['month 13', '2027-13-10', undefined, '2030-01-01'],
  ['day 00', '2027-01-00', undefined, '2030-01-01'], ['year 0000', '0000-01-01', '0000-01-01', undefined], ['year 9999', '9999-12-31T23:59:59Z', undefined, '9999-12-31T23:59:59Z'], ['bad bound', '2027-01-15', 'garbage', 'also bad'], ['bound null', '2027-01-15', null, undefined],
  ['bound num', '2027-01-15', 5, undefined], ['frac 10 digits', '2027-01-15T10:00:00.1234567890Z', undefined, '2030-01-01'], ['date-only bound', '2027-01-15T00:00:00Z', '2027-01-15', '2027-01-15'], ['expanded year', '+002027-01-15', undefined, '2030-01-01'],
] as any[]) addPC(`exec ${l}`, withC([ED(nb, na)]), clo({ execution_date: closedDate }), NOW);
addPC('exec immediate in window', withC([ED('2026-01-01', '2030-01-01')]), clo(), { now: T0 });
addPC('exec immediate before window', withC([ED('2030-01-01')]), clo(), { now: T0 });
addPC('exec immediate after window', withC([ED(undefined, '2020-01-01')]), clo(), { now: T0 });
addPC('exec immediate no bounds', withC([ED()]), clo(), { now: T0 });
addPC('exec closed null', withC([ED('2020-01-01')]), clo({ execution_date: null }), NOW);
addPC('exec closed num', withC([ED('2020-01-01')]), clo({ execution_date: 5 }), NOW);
// pre-set claims
addPC('preset all match', withC([AR], { payee: MERCH, payment_amount: CLOSED_BASE.payment_amount, payment_instrument: INSTR, pisp: PISP, execution_date: 'x' }), clo({ pisp: PISP, execution_date: 'x' }), NOW);
addPC('preset all differ', withC([AR], { payee: MERCH2, payment_amount: { amount: 1, currency: 'USD' }, payment_instrument: { id: 'q', type: 'card' }, pisp: PISP, execution_date: 'y' }), clo({ execution_date: 'x' }), NOW);
addPC('preset key order', withC([AR], { payment_amount: { currency: 'USD', amount: CLOSED_BASE.payment_amount.amount }, payment_instrument: { type: INSTR.type, description: INSTR.description, id: INSTR.id } }), clo(), NOW);
addPC('preset number forms', withC([AR], { payment_amount: { amount: 4000.0, currency: 'USD' } }), clo({ payment_amount: { amount: 4000, currency: 'USD' } }), NOW);
addPC('preset pisp vs missing', withC([AR], { pisp: PISP }), clo(), NOW);
addPC('preset exec vs missing', withC([AR], { execution_date: 'x' }), clo(), NOW);
addPC('preset payee name only', withC([AR], { payee: { id: 'merchant_1', name: 'Totally different' } }), clo(), NOW);
addPC('unknown constraint', withC([{ type: 'payment.mystery' }]), clo(), NOW);
addPC('unknown constraint number type', withC([{ type: 5 }]), clo(), NOW);
addPC('empty constraints', withC([]), clo(), NOW);
addPC('multi violations', withC([AR, { type: 'payment.allowed_payees', allowed: [MERCH2] }, RE, BU, ED('2030-01-01')], { payee: MERCH2 }), clo({ payment_amount: { amount: 5000000, currency: 'EUR' } }), { now: T0, context: ctx(0, 0) });
for (const [l, open, closed, opts] of pcCases) await run('checkPaymentConstraints', l, M.checkPaymentConstraints, [open, closed, opts]);

// projectCheckout / checkoutTotal / checkCheckoutConstraints
const CHK = { id: 'chk_1', merchant: MERCH, currency: 'USD', line_items: [{ id: 'li_1', item: { id: 'sku-1', title: 'Widget', price: 2000 }, quantity: 2 }], totals: [{ type: 'total', amount: 4000 }] };
await run('projectCheckout', 'valid', M.projectCheckout, [CHK]);
for (const [l, v] of sample([...variants(CHK, { depth: 5 })], 160, 'checkout')) await run('projectCheckout', l, M.projectCheckout, [v]);
for (const [i, v] of ([{ ...CHK, merchant: { id: 'm', name: 'n', website: 5 } }, { ...CHK, merchant: { id: 'm', name: 'n', extra: 1 } }, { ...CHK, status: 'x', links: [] }, { ...CHK, line_items: [{ ...CHK.line_items[0], item: { ...CHK.line_items[0]!.item, price: 1.5 } }] },
  { ...CHK, line_items: [{ ...CHK.line_items[0], quantity: 0 }] }, { ...CHK, totals: [] }, { ...CHK, totals: [{ type: 'total', amount: 1.5 }] }, { ...CHK, currency: 'usd' }, { ...CHK, id: '' }, { ...CHK, line_items: [] }] as any[]).entries()) await run('projectCheckout', `doc${i}`, M.projectCheckout, [v]);
for (const [i, t] of ([[{ type: 'total', amount: 5 }], [], [{ type: 'total', amount: 5 }, { type: 'total', amount: 6 }], [{ type: 'subtotal', amount: 5 }], [{ type: 'subtotal', amount: 1 }, { type: 'total', amount: 7 }, { type: 'tax', amount: 1 }], [{ type: 'total', amount: 0 }]] as any[]).entries()) await run('checkoutTotal', `t${i}`, M.checkoutTotal, [{ ...CHK, totals: t }]);
const lineItem = (id: string, price = 100, quantity = 1) => ({ id: `li_${id}`, item: { id, title: id, price }, quantity });
const chkWith = (items: any[], merchant: any = MERCH) => ({ id: 'c', currency: 'USD', line_items: items, totals: [{ type: 'total', amount: 1 }], ...(merchant ? { merchant } : {}) });
const LI = (items: { id: string; quantity: number; ok: string[] }[]) => ({ type: 'checkout.line_items', items: items.map((it) => ({ id: it.id, quantity: it.quantity, acceptable_items: it.ok.map((x) => ({ id: x, title: x })) })) });
const OC = (c: any[]) => ({ ...MS.openCheckout, constraints: c });
const flowCases: [string, any[], any[]][] = [
  ['exact', [lineItem('a', 1, 2)], [{ id: 'r', quantity: 2, ok: ['a', 'b'] }]], ['too many', [lineItem('a', 1, 3)], [{ id: 'r', quantity: 2, ok: ['a'] }]], ['too few', [lineItem('a', 1, 1)], [{ id: 'r', quantity: 2, ok: ['a'] }]],
  ['wrong sku', [lineItem('z', 1, 1)], [{ id: 'r', quantity: 1, ok: ['a'] }]], ['empty acceptable', [lineItem('a', 1, 1)], [{ id: 'r', quantity: 1, ok: [] }]], ['two slots', [lineItem('a', 1, 1), lineItem('b', 1, 1)], [{ id: 'r1', quantity: 1, ok: ['a'] }, { id: 'r2', quantity: 1, ok: ['b'] }]],
  ['slot swap needed', [lineItem('a', 1, 1), lineItem('b', 1, 1)], [{ id: 'r1', quantity: 1, ok: ['a', 'b'] }, { id: 'r2', quantity: 1, ok: ['a'] }]], ['augmenting path', [lineItem('a', 1, 2), lineItem('b', 1, 1)], [{ id: 'r1', quantity: 2, ok: ['a', 'b'] }, { id: 'r2', quantity: 1, ok: ['a'] }]],
  ['unsatisfiable', [lineItem('a', 1, 2), lineItem('b', 1, 1)], [{ id: 'r1', quantity: 2, ok: ['a'] }, { id: 'r2', quantity: 1, ok: ['a'] }]], ['same sku twice', [lineItem('a', 1, 1), { ...lineItem('a', 1, 1), id: 'second' }], [{ id: 'r', quantity: 2, ok: ['a'] }]],
  ['no reqs', [lineItem('a')], []], ['many', Array.from({ length: 6 }, (_, i) => lineItem(`s${i}`, 1, i + 1)), Array.from({ length: 3 }, (_, j) => ({ id: `r${j}`, quantity: 7, ok: [`s${j}`, `s${j + 1}`, `s${j + 2}`, `s${5 - j}`] }))],
  ['big qty', [lineItem('a', 1, 9007199254740000)], [{ id: 'r', quantity: 9007199254740000, ok: ['a'] }]], ['big qty over', [lineItem('a', 1, 9007199254740000), lineItem('b', 1, 900)], [{ id: 'r', quantity: 9007199254740000, ok: ['a', 'b'] }]],
];
for (const [l, items, reqs] of flowCases) await run('checkCheckoutConstraints', `flow ${l}`, M.checkCheckoutConstraints, [OC([LI(reqs)]), chkWith(items)]);
await run('checkCheckoutConstraints', 'empty cart', M.checkCheckoutConstraints, [OC([LI([{ id: 'r', quantity: 1, ok: ['a'] }])]), chkWith([])]);
for (const [l, allowed, merchant] of [['allowed', [MERCH], MERCH], ['not allowed', [MERCH2], MERCH], ['missing merchant', [MERCH], null], ['name site', [{ name: 'Demo Merchant', website: 'https://demo-merchant.example' }], { id: 'z', name: 'Demo Merchant', website: 'https://demo-merchant.example' }], ['empty allowed', [], MERCH]] as any[]) {
  await run('checkCheckoutConstraints', `merchants ${l}`, M.checkCheckoutConstraints, [OC([{ type: 'checkout.allowed_merchants', allowed }]), chkWith([lineItem('a')], merchant)]);
}
await run('checkCheckoutConstraints', 'unknown', M.checkCheckoutConstraints, [OC([{ type: 'checkout.mystery' }]), chkWith([lineItem('a')])]);
await run('checkCheckoutConstraints', 'both', M.checkCheckoutConstraints, [OC([{ type: 'checkout.allowed_merchants', allowed: [MERCH2] }, LI([{ id: 'r', quantity: 1, ok: ['x'] }])]), chkWith([lineItem('a')])]);

// ================================================================================================ chain: generic hops
const ALL: Record<string, string> = {};
for (const [n, s] of Object.entries(SC)) Object.assign(ALL, { [`${n}/cc`]: s.checkoutChain, [`${n}/pc`]: s.paymentChain, [`${n}/oc`]: s.openCheckout, [`${n}/op`]: s.openPayment });
const gOpts = (extra: any = {}) => ({ issuerKeys: issuerKeys(), expectedAudience: 'credential-provider', expectedNonce: 'nonce-p', now: T0 + 10, ...extra });
const dc = (t: string, c: any) => projChain(M.verifyDelegationChain(t, baseOpts(c)));
for (const n of NAMES) {
  await run('verifyDelegationChain', `${n}/pc`, (t: string, c: any) => dc(t, c), [SC[n]!.paymentChain, gOpts()]);
  await run('verifyDelegationChain', `${n}/cc`, (t: string, c: any) => dc(t, c), [SC[n]!.checkoutChain, gOpts({ expectedAudience: 'merchant', expectedNonce: 'nonce-c' })]);
}
await run('verifyDelegationChain', 'open only', (t: string, c: any) => dc(t, c), [S0.openPayment, gOpts()]);
for (const [l, t] of sample(tokenMutations(S0.paymentChain), 34, 'dc-mut-pc')) await run('verifyDelegationChain', `pc/${l}`, (x: string, c: any) => dc(x, c), [t, gOpts()]);
for (const [l, t] of sample(tokenMutations(S0.checkoutChain), 24, 'dc-mut-cc')) await run('verifyDelegationChain', `cc/${l}`, (x: string, c: any) => dc(x, c), [t, gOpts({ expectedAudience: 'merchant', expectedNonce: 'nonce-c' })]);
const gv: [string, any][] = [
  ['no issuer keys', gOpts({ issuerKeys: {} })], ['wrong issuer key', gOpts({ issuerKeys: { 'issuer-1': pubOf('evil') } })], ['bad issuer key', gOpts({ issuerKeys: { 'issuer-1': { kty: 'EC' } } })], ['key by other kid', gOpts({ issuerKeys: { other: pubOf('issuer') } })],
  ['aud mismatch', gOpts({ expectedAudience: 'other' })], ['nonce mismatch', gOpts({ expectedNonce: 'other' })], ['empty aud', gOpts({ expectedAudience: '' })], ['empty nonce', gOpts({ expectedNonce: '' })],
  ['undefined aud', gOpts({ expectedAudience: undefined })], ['now = exp', gOpts({ now: T0 + 3600 })], ['now = exp + skew', gOpts({ now: T0 + 3660 })], ['now = exp + skew + 1', gOpts({ now: T0 + 3661 })], ['now before iat', gOpts({ now: T0 - 1000 })],
  ['now iat - skew', gOpts({ now: T0 - 60 })], ['now iat - skew - 1', gOpts({ now: T0 - 61 })], ['skew 0', gOpts({ clockSkewSeconds: 0, now: T0 - 1 })], ['skew 0 at exp', gOpts({ clockSkewSeconds: 0, now: T0 + 3601 })], ['skew large', gOpts({ clockSkewSeconds: 1e9, now: T0 + 1e8 })],
  ['skew negative', gOpts({ clockSkewSeconds: -5 })], ['fractional now', gOpts({ now: T0 + 0.5 })],
];
for (const [l, c] of gv) await run('verifyDelegationChain', `opts/${l}`, (t: string, x: any) => dc(t, x), [S0.paymentChain, c]);
for (const [l, c] of gv.slice(0, 6)) await run('verifyDelegationChain', `opts-sha384/${l}`, (t: string, x: any) => dc(t, x), [SC.sha384!.paymentChain, c]);
// hand-built chains: intermediate hops, typ, crit, cnf rules, binding-hash rules, times
{
  const issuer = keyFor('issuer'), agent = keyFor('agent'), agent2 = keyFor('merchant');
  const salt = counterSalt();
  const root = M.issueOpenPaymentMandate({ issuer: { privateKey: issuer.privateKey, kid: 'issuer-1' }, agentJwk: agent.publicJwk, iat: T0 - 100, exp: T0 + 3600, salt, constraints: [{ type: 'payment.reference', conditional_transaction_id: 'r' }] });
  const rootHop = M.parseSdJwtHop(root);
  const hopTok = (key: any, header: any, mandate: any, extra: any = {}, use: 'sd_hash' | 'issuer_jwt_hash' | null = 'sd_hash', prev = rootHop, moreDisc: string[] = []) => {
    const b = M.disclosureBuilder('sha-256', salt);
    const el = b.element(mandate);
    const payload = { delegate_payload: [el], iat: T0, aud: 'credential-provider', nonce: 'nonce-p', ...(use ? { [use]: use === 'sd_hash' ? M.sdHashOf(prev) : M.issuerJwtHashOf(prev) } : {}), _sd_alg: 'sha-256', ...extra };
    return M.signSdJwt({ header, payload, disclosures: 'delegate_payload' in extra ? [] : [...b.disclosures, ...moreDisc], privateKey: key.privateKey });
  };
  const chain = (...hops: string[]) => [root, ...hops].join('~');
  const mid = hopTok(agent, { typ: 'kb+sd-jwt+kb' }, { vct: 'x', cnf: { jwk: agent2.publicJwk } });
  const midHop = M.parseSdJwtHop(mid);
  const term = (extra: any = {}, header: any = { typ: 'kb+sd-jwt' }, mandate: any = { vct: 'x' }, key = agent2, use: any = 'sd_hash') => hopTok(key, header, mandate, extra, use, midHop);
  const gen: [string, string][] = [
    ['three hops ok', chain(mid, term())], ['three hops kb-sd-jwt', chain(hopTok(agent, { typ: 'kb-sd-jwt+kb' }, { cnf: { jwk: agent2.publicJwk } }), term())],
    ['intermediate wrong typ', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { cnf: { jwk: agent2.publicJwk } }), term())],
    ['terminal intermediate typ', chain(hopTok(agent, { typ: 'kb+sd-jwt+kb' }, { x: 1 }))],
    ['no typ', chain(hopTok(agent, {}, { x: 1 }))], ['typ number', chain(hopTok(agent, { typ: 5 }, { x: 1 }))], ['crit on hop', chain(hopTok(agent, { typ: 'kb+sd-jwt', crit: ['x'] }, { x: 1 }))],
    ['terminal with cnf', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { cnf: { jwk: agent2.publicJwk } }))], ['intermediate without cnf', chain(hopTok(agent, { typ: 'kb+sd-jwt+kb' }, { x: 1 }), term())],
    ['wrong signer', chain(hopTok(agent2, { typ: 'kb+sd-jwt' }, { x: 1 }))], ['both hashes', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { issuer_jwt_hash: M.issuerJwtHashOf(rootHop) }))],
    ['neither hash', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, {}, null))], ['issuer_jwt_hash ok', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, {}, 'issuer_jwt_hash'))],
    ['sd_hash wrong', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { sd_hash: 'AAAA' }))], ['sd_hash number', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { sd_hash: 5 }))],
    ['issuer hash as sd', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { sd_hash: M.issuerJwtHashOf(rootHop) }, null))],
    ['no iat', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { iat: undefined }))], ['iat null', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { iat: null }))], ['iat string', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { iat: '5' }))],
    ['iat future', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { iat: T0 + 100000 }))], ['iat float', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { iat: 1.5 }))],
    ['exp past', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { exp: 5 }))], ['exp float', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { exp: 1.5 }))], ['exp null', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { exp: null }))],
    ['mandate exp past', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1, exp: 5 }))], ['mandate iat future', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1, iat: T0 + 99999 }))],
    ['aud array', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { aud: ['credential-provider'] }))], ['nonce number', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { nonce: 5 }))],
    ['no delegate_payload', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { delegate_payload: undefined }))], ['delegate_payload object', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { delegate_payload: {} }))],
    ['delegate_payload two', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { delegate_payload: [{ a: 1 }, { b: 2 }] }))], ['delegate_payload empty', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { delegate_payload: [] }))],
    ['delegate_payload scalar', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { delegate_payload: ['x'] }))], ['delegate_payload plain mandate', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { delegate_payload: [{ vct: 'x' }] }))],
    ['_sd_alg sha-512', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { _sd_alg: 'sha-512' }))], ['_sd_alg bad', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, { _sd_alg: 'md5' }))],
    ['extra disclosure', chain(hopTok(agent, { typ: 'kb+sd-jwt' }, { x: 1 }, {}, 'sd_hash', rootHop, [dProp(1, 'a', 1)]))],
    ['mandate cnf bad jwk', chain(hopTok(agent, { typ: 'kb+sd-jwt+kb' }, { cnf: { jwk: { kty: 'EC' } } }), term())], ['mandate cnf scalar', chain(hopTok(agent, { typ: 'kb+sd-jwt+kb' }, { cnf: 5 }), term())],
    ['more than 8 hops', chain(...Array.from({ length: 8 }, () => mid))],
    ['root crit', (() => { const t = M.signSdJwt({ header: { typ: 'dc+sd-jwt', kid: 'issuer-1', crit: ['x'] }, payload: { delegate_payload: [{ vct: 'x' }] }, disclosures: [], privateKey: issuer.privateKey }); return t; })()],
    ['root plain mandate', M.signSdJwt({ header: { typ: 'dc+sd-jwt', kid: 'issuer-1' }, payload: { delegate_payload: [{ vct: 'x', cnf: { jwk: agent.publicJwk } }] }, disclosures: [], privateKey: issuer.privateKey })],
    ['root no kid', M.signSdJwt({ header: { typ: 'dc+sd-jwt' }, payload: { delegate_payload: [{ vct: 'x' }] }, disclosures: [], privateKey: issuer.privateKey })],
    ['root exp past', M.signSdJwt({ header: { typ: 'dc+sd-jwt', kid: 'issuer-1' }, payload: { delegate_payload: [{ vct: 'x' }], exp: 5 }, disclosures: [], privateKey: issuer.privateKey })],
    ['root iat future', M.signSdJwt({ header: { typ: 'dc+sd-jwt', kid: 'issuer-1' }, payload: { delegate_payload: [{ vct: 'x' }], iat: T0 + 1e6 }, disclosures: [], privateKey: issuer.privateKey })],
    ['root mandate exp str', M.signSdJwt({ header: { typ: 'dc+sd-jwt', kid: 'issuer-1' }, payload: { delegate_payload: [{ vct: 'x', exp: '5' }] }, disclosures: [], privateKey: issuer.privateKey })],
  ];
  for (const [l, t] of gen) await run('verifyDelegationChain', `built/${l}`, (x: string, c: any) => dc(x, c), [t, gOpts()]);
  // verifyKbHop over the first closed hop of a real payment chain and the hand-built ones
  const pcParts = M.splitChain(S0.paymentChain);
  const openMandate = MS.openPayment;
  const kbo = (extra: any = {}) => ({ terminal: true, expectedAudience: 'credential-provider', expectedNonce: 'nonce-p', now: T0 + 10, skew: 60, ...extra });
  const kb = (h: string, prev: string, pm: any, op: any, label: string) => (() => { const v = M.verifyKbHop(M.parseSdJwtHop(h), { hop: M.parseSdJwtHop(prev), mandate: pm }, op, label); return { index: v.index, kind: v.kind, claims: v.claims, mandate: v.mandate }; })();
  const kbCases: [string, any[]][] = [
    ['ok terminal', [pcParts[1], pcParts[0], openMandate, kbo(), 'hop 1']], ['not terminal', [pcParts[1], pcParts[0], openMandate, kbo({ terminal: false }), 'hop 1']], ['aud wrong', [pcParts[1], pcParts[0], openMandate, kbo({ expectedAudience: 'x' }), 'L']],
    ['nonce wrong', [pcParts[1], pcParts[0], openMandate, kbo({ expectedNonce: 'x' }), 'L']], ['aud undefined', [pcParts[1], pcParts[0], openMandate, kbo({ expectedAudience: undefined }), 'L']], ['now late', [pcParts[1], pcParts[0], openMandate, kbo({ now: T0 + 1e7 }), 'L']],
    ['now early', [pcParts[1], pcParts[0], openMandate, kbo({ now: 5 }), 'L']], ['skew big', [pcParts[1], pcParts[0], openMandate, kbo({ now: 5, skew: 1e12 }), 'L']], ['prev mandate without cnf', [pcParts[1], pcParts[0], { vct: 'x' }, kbo(), 'L']],
    ['prev mandate other key', [pcParts[1], pcParts[0], { cnf: { jwk: pubOf('evil') } }, kbo(), 'L']], ['prev wrong hop', [pcParts[1], S0.openCheckout, openMandate, kbo(), 'L']], ['intermediate ok', [mid, root, M.verifyDelegationChain(chain(mid, term()), baseOpts(gOpts())).hops[0].mandate, kbo({ terminal: false }), 'hop 1']],
    ['intermediate as terminal', [mid, root, M.verifyDelegationChain(chain(mid, term()), baseOpts(gOpts())).hops[0].mandate, kbo(), 'hop 1']],
  ];
  for (const [l, a] of kbCases) await run('verifyKbHop', l, kb, a);
}

// ================================================================================================ typed chains
const cc = (t: string, c: any) => projChain(M.verifyCheckoutChain(t, { ...baseOpts(c) }));
const pcv = (t: string, c: any) => projChain(M.verifyPaymentChain(t, { ...baseOpts(c), openCheckoutHash: c.openCheckoutHash, ...(c.context !== undefined ? { context: c.context } : {}), ...(c.expectedTransactionId !== undefined ? { expectedTransactionId: c.expectedTransactionId } : {}) }));
for (const n of NAMES) {
  const s = SC[n]!;
  await run('verifyCheckoutChain', n, cc, [s.checkoutChain, chainOpts()]);
  for (const [l, ctxv] of [['no ctx', undefined], ['zero', ctx(0, 0)], ['spent', ctx(99000, 4)], ['all used', ctx(0, 5)], ['used today', ctx(0, 1, T0 - 100)]] as any[]) {
    await run('verifyPaymentChain', `${n}/${l}`, pcv, [s.paymentChain, payOpts(s, { ...(ctxv !== undefined ? { context: ctxv } : {}) })]);
  }
  await run('verifyPurchase', n, (a: string, b: string, c: any) => projPurchase(M.verifyPurchase(a, b, purchOptsOf(c))), [s.checkoutChain, s.paymentChain, purchOpts({ context: ctx(0, 0) })]);
  await run('verifyPurchase', `${n}/no ctx`, (a: string, b: string, c: any) => projPurchase(M.verifyPurchase(a, b, purchOptsOf(c))), [s.checkoutChain, s.paymentChain, purchOpts()]);
}
for (const [l, extra] of [['aud', { expectedAudience: 'x' }], ['nonce', { expectedNonce: 'x' }], ['no merchant key', { merchantKeys: {} }], ['wrong merchant key', { merchantKeys: { 'merchant-1': pubOf('evil') } }], ['merchant key by agent', { merchantKeys: { 'merchant-1': pubOf('agent') } }], ['bad merchant key', { merchantKeys: { 'merchant-1': { kty: 'x' } } }],
  ['no issuer', { issuerKeys: {} }], ['expired', { now: T0 + 100000 }], ['early', { now: T0 - 100000 }]] as any[]) await run('verifyCheckoutChain', `opts/${l}`, cc, [S0.checkoutChain, chainOpts(extra)]);
for (const [l, t] of sample(tokenMutations(S0.checkoutChain), 40, 'cc-mut')) await run('verifyCheckoutChain', `mut/${l}`, cc, [t, chainOpts()]);
for (const [l, t] of sample(tokenMutations(S0.paymentChain), 40, 'pc-mut')) await run('verifyPaymentChain', `mut/${l}`, pcv, [t, payOpts(S0)]);
for (const [l, extra] of [['aud', { expectedAudience: 'x' }], ['nonce', { expectedNonce: 'x' }], ['ref', { openCheckoutHash: 'x' }], ['ref undefined', { openCheckoutHash: undefined }], ['txid', { expectedTransactionId: 'x' }], ['txid undefined', { expectedTransactionId: undefined }],
  ['ctx budget', { context: ctx(99900, 0) }], ['ctx uses', { context: ctx(0, 5) }], ['expired', { now: T0 + 100000 }], ['skew', { clockSkewSeconds: 0, now: T0 + 3601 }]] as any[]) await run('verifyPaymentChain', `opts/${l}`, pcv, [S0.paymentChain, payOpts(S0, extra)]);
// cross-wired chains: the wrong token in the wrong slot
await run('verifyCheckoutChain', 'payment token', cc, [S0.paymentChain, chainOpts({ expectedAudience: 'credential-provider', expectedNonce: 'nonce-p' })]);
await run('verifyPaymentChain', 'checkout token', pcv, [S0.checkoutChain, payOpts(S0, { expectedAudience: 'merchant', expectedNonce: 'nonce-c' })]);
await run('verifyCheckoutChain', 'open only', cc, [S0.openCheckout, chainOpts()]);
await run('verifyPaymentChain', 'open only', pcv, [S0.openPayment, payOpts(S0)]);
// purchases: cross scenarios
for (const [l, a, b, extra] of [
  ['mix sha', 'default', 'sha384', {}], ['mix currency', 'jpy', 'default', {}], ['mix wrong payee', 'default', 'wrongPayee', {}], ['mix amount differs', 'default', 'amountDiffers', {}], ['mix other checkout', 'kwd', 'kwd', {}],
  ['swapped', 'default', 'default', { swap: true }], ['overBudget', 'default', 'overBudget', { context: ctx(0, 0) }], ['no total', 'default', 'default', { merchantKeys: {} }],
] as any[]) {
  const A = SC[a]!, B = SC[b]!;
  const [t1, t2] = extra.swap ? [A.paymentChain, A.checkoutChain] : [A.checkoutChain, B.paymentChain];
  await run('verifyPurchase', `cross/${l}`, (x: string, y: string, c: any) => projPurchase(M.verifyPurchase(x, y, purchOptsOf(c))), [t1, t2, purchOpts({ context: ctx(0, 0), ...extra, swap: undefined })]);
}
// checkout whose JWT has no merchant / total variants (merchant-signed payloads built by hand)
{
  const issuer = keyFor('issuer'), agent = keyFor('agent'), mk = keyFor('merchant');
  const variants2: [string, any][] = [
    ['no merchant', { ...CHK, merchant: undefined }], ['two totals', { ...CHK, totals: [{ type: 'total', amount: 4000 }, { type: 'total', amount: 4000 }] }], ['no total', { ...CHK, totals: [{ type: 'subtotal', amount: 4000 }] }], ['other currency', { ...CHK, currency: 'EUR' }],
    ['other merchant', { ...CHK, merchant: { ...MERCH2, id: 'merchant_2' } }], ['bad payload', { ...CHK, line_items: [] }], ['extra fields', { ...CHK, status: 'ready', links: [{ type: 'terms', url: 'https://x' }], line_items: [{ ...CHK.line_items[0], totals: [] }] }],
  ];
  for (const [l, payload] of variants2) {
    const salt = counterSalt();
    const base = { issuer: { privateKey: issuer.privateKey, kid: 'issuer-1' }, agentJwk: agent.publicJwk, iat: T0 - 100, exp: T0 + 3600, salt };
    const oc = M.issueOpenCheckoutMandate({ ...base, constraints: [{ type: 'checkout.line_items', items: [{ id: 'line_1', acceptable_items: [{ id: 'sku-1', title: 'Widget' }], quantity: 2 }] }] });
    const jwt = M.signJwtEs256({ header: { kid: 'merchant-1' }, payload, privateKey: mk.privateKey });
    const cch = M.presentClosedCheckout({ open: oc, agentKey: agent, checkoutJwt: jwt, aud: 'merchant', nonce: 'nonce-c', iat: T0, salt });
    await run('verifyCheckoutChain', `hand/${l}`, cc, [cch, chainOpts()]);
    const ohash = M.sdHashOf(M.parseSdJwtHop(oc));
    const op = M.issueOpenPaymentMandate({ ...base, constraints: [{ type: 'payment.amount_range', currency: 'USD', max: 50000 }, { type: 'payment.allowed_payees', allowed: [MERCH] }, { type: 'payment.reference', conditional_transaction_id: ohash }] });
    const pch = M.presentClosedPayment({ open: op, agentKey: agent, aud: 'credential-provider', nonce: 'nonce-p', iat: T0, salt, transactionId: M.sdDigest(jwt), payee: MERCH, paymentAmount: { amount: 4000, currency: 'USD' }, paymentInstrument: INSTR });
    await run('verifyPurchase', `hand/${l}`, (x: string, y: string, c: any) => projPurchase(M.verifyPurchase(x, y, purchOptsOf(c))), [cch, pch, purchOpts()]);
  }
}
// redeemPurchase
const redeem = async (a: string, b: string, c: any, spec: any) => {
  const calls: any[] = [];
  const ledger = spec === 'none' ? undefined : {
    reserve: async (h: string, t: string, amt: number) => { calls.push(['reserve', h, t, amt]); if (spec.mode === 'throw') throw new Error('down'); if (spec.mode === 'replayed') return 'replayed'; if (spec.mode === 'undefined') return undefined; return spec.ctx ?? { totalAmount: 0, totalUses: 0 }; },
    release: async (h: string, t: string) => { calls.push(['release', h, t]); if (spec.releaseThrows) throw new Error('release failed'); },
  };
  const r = await M.redeemPurchase(a, b, purchOptsOf(c), ledger);
  return { result: r.ok ? projPurchase(r) : { ok: false, reason: maskReason(r.reason) }, calls };
};
for (const n of NAMES) await run('redeemPurchase', `${n}/ok`, redeem, [SC[n]!.checkoutChain, SC[n]!.paymentChain, purchOpts(), { mode: 'ok' }]);
for (const [l, spec] of [['none', 'none'], ['replayed', { mode: 'replayed' }], ['throw', { mode: 'throw' }], ['undefined', { mode: 'undefined' }], ['spent', { mode: 'ok', ctx: { totalAmount: 99000, totalUses: 1 } }], ['uses', { mode: 'ok', ctx: { totalAmount: 0, totalUses: 5 } }],
  ['bad ctx', { mode: 'ok', ctx: { totalAmount: -1, totalUses: 0 } }], ['release throws', { mode: 'ok', ctx: { totalAmount: 99000, totalUses: 1 }, releaseThrows: true }], ['ctx last', { mode: 'ok', ctx: { totalAmount: 0, totalUses: 1, lastUsedDate: T0 } }]] as any[]) {
  await run('redeemPurchase', `monthly/${l}`, redeem, [SC.monthly!.checkoutChain, SC.monthly!.paymentChain, purchOpts(), spec]);
  await run('redeemPurchase', `default/${l}`, redeem, [S0.checkoutChain, S0.paymentChain, purchOpts(), spec]);
}
await run('redeemPurchase', 'bad checkout', redeem, [S0.paymentChain, S0.paymentChain, purchOpts(), { mode: 'ok' }]);
await run('redeemPurchase', 'bad payment', redeem, [S0.checkoutChain, S0.checkoutChain, purchOpts(), { mode: 'ok' }]);
await run('redeemPurchase', 'over zero ctx', redeem, [SC.overBudget!.checkoutChain, SC.overBudget!.paymentChain, purchOpts(), { mode: 'ok' }]);
await run('redeemPurchase', 'caller ctx ignored', redeem, [S0.checkoutChain, S0.paymentChain, purchOpts({ context: ctx(99999999, 99) }), { mode: 'ok' }]);

// ================================================================================================ issuance / presentation
const OPEN_C = [{ type: 'checkout.line_items', items: [{ id: 'line_1', acceptable_items: [{ id: 'sku-1', title: 'Widget' }], quantity: 1 }] }];
const OPEN_P = [{ type: 'payment.amount_range', currency: 'USD', max: 100 }, { type: 'payment.allowed_payees', allowed: [MERCH, MERCH2] }, { type: 'payment.allowed_payment_instruments', allowed: [INSTR] }, { type: 'payment.reference', conditional_transaction_id: 'r' }, { type: 'payment.budget', currency: 'USD', max: 10 }];
const mkOpenInput = (a: any) => ({
  issuer: { privateKey: keyFor(a.issuerKey ?? 'issuer').privateKey, ...(a.kid !== undefined ? { kid: a.kid } : {}), ...(a.x5c ? { x5c: a.x5c } : {}) },
  agentJwk: a.agentJwk ?? pubOf(a.agentKey ?? 'agent'), iat: a.iat, exp: a.exp, ...(a.pca ? { pca: a.pca } : {}), ...(a.sdAlg ? { sdAlg: a.sdAlg } : {}), ...(a.typ !== undefined ? { typ: a.typ } : {}), salt: counterSalt(),
});
const openCommon = (over: any = {}) => ({ kid: 'issuer-1', iat: T0 - 100, exp: T0 + 3600, ...over });
const openPay = (a: any) => stripSig(M.issueOpenPaymentMandate({ ...mkOpenInput(a), constraints: a.constraints, ...(a.payee ? { payee: a.payee } : {}), ...(a.paymentAmount ? { paymentAmount: a.paymentAmount } : {}), ...(a.paymentInstrument ? { paymentInstrument: a.paymentInstrument } : {}), ...(a.pisp ? { pisp: a.pisp } : {}), ...(a.executionDate !== undefined ? { executionDate: a.executionDate } : {}) }));
const openChk = (a: any) => stripSig(M.issueOpenCheckoutMandate({ ...mkOpenInput(a), constraints: a.constraints }));
const issuePay: [string, any][] = [
  ['basic', openCommon({ constraints: OPEN_P })], ['kid none', { ...openCommon({ constraints: OPEN_P }), kid: undefined }], ['x5c', openCommon({ constraints: OPEN_P, x5c: ['MIIB', 'MIIC'] })], ['x5c empty', openCommon({ constraints: OPEN_P, x5c: [] })], ['typ', openCommon({ constraints: OPEN_P, typ: 'vc+sd-jwt' })],
  ['sha384', openCommon({ constraints: OPEN_P, sdAlg: 'sha-384' })], ['sha512', openCommon({ constraints: OPEN_P, sdAlg: 'sha-512' })], ['pca', openCommon({ constraints: OPEN_P, pca: { v: 1, '2': 'b', '1': 'a', z: [1, { y: 1.5 }] } })],
  ['all preset', openCommon({ constraints: OPEN_P, payee: MERCH, paymentAmount: { amount: 5, currency: 'USD' }, paymentInstrument: INSTR, pisp: PISP, executionDate: '2027-01-01' })],
  ['all constraint types', openCommon({ constraints: [...OPEN_P, { type: 'payment.agent_recurrence', frequency: 'DAILY', max_occurrences: 2 }, { type: 'payment.allowed_pisps', allowed: [PISP] }, { type: 'payment.execution_date', not_before: '2027-01-01' }] })],
  ['unicode', openCommon({ constraints: [{ type: 'payment.reference', conditional_transaction_id: 'é日本\ud800' }, { type: 'payment.allowed_payees', allowed: [{ id: 'é', name: '日本' }] }] })],
  ['no reference', openCommon({ constraints: [OPEN_P[0]] })], ['empty constraints', openCommon({ constraints: [] })], ['bad constraint', openCommon({ constraints: [{ type: 'payment.budget', currency: 'usd', max: -1 }, OPEN_P[3]] })],
  ['bad payee', openCommon({ constraints: OPEN_P, payee: { id: '' } })], ['bad amount', openCommon({ constraints: OPEN_P, paymentAmount: { amount: -1, currency: 'US' } })], ['bad iat', openCommon({ constraints: OPEN_P, iat: 1.5 })], ['bad exp', openCommon({ constraints: OPEN_P, exp: T0 - 1000 })],
  ['exp = iat', openCommon({ constraints: OPEN_P, exp: T0 - 100 })], ['iat 0', openCommon({ constraints: OPEN_P, iat: 0 })], ['no exp', { ...openCommon({ constraints: OPEN_P }), exp: undefined }], ['bad agent jwk', openCommon({ constraints: OPEN_P, agentJwk: { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' } })],
  ['agent jwk with kid', openCommon({ constraints: OPEN_P, agentJwk: { ...pubOf('agent'), kid: 'k', alg: 'ES256' } })], ['pca array', openCommon({ constraints: OPEN_P, pca: [] })],
];
for (const [l, a] of issuePay) await run('issueOpenPaymentMandate', l, openPay, [a]);
const issueChk: [string, any][] = [
  ['basic', openCommon({ constraints: OPEN_C })], ['merchants', openCommon({ constraints: [...OPEN_C, { type: 'checkout.allowed_merchants', allowed: [MERCH, MERCH2] }] })], ['sha512', openCommon({ constraints: OPEN_C, sdAlg: 'sha-512' })], ['x5c', openCommon({ constraints: OPEN_C, x5c: ['MIIB'] })],
  ['pca', openCommon({ constraints: OPEN_C, pca: { a: 1 } })], ['no line items', openCommon({ constraints: [{ type: 'checkout.allowed_merchants', allowed: [MERCH] }] })], ['empty items', openCommon({ constraints: [{ type: 'checkout.line_items', items: [] }] })],
  ['bad quantity', openCommon({ constraints: [{ type: 'checkout.line_items', items: [{ id: 'a', acceptable_items: [], quantity: 0 }] }] })], ['two items', openCommon({ constraints: [{ type: 'checkout.line_items', items: [{ id: 'a', acceptable_items: [{ id: 'x', title: 'X' }], quantity: 1 }, { id: 'b', acceptable_items: [{ id: 'y', title: 'Y' }, { id: 'z', title: 'Z' }], quantity: 3 }] }] })],
];
for (const [l, a] of issueChk) await run('issueOpenCheckoutMandate', l, openChk, [a]);

const presentHopIn = (a: any) => ({ open: a.open, agentKey: keyFor(a.agentKey ?? 'agent'), aud: a.aud, nonce: a.nonce, iat: a.iat, ...(a.exp !== undefined ? { exp: a.exp } : {}), ...(a.pca ? { pca: a.pca } : {}), ...(a.hashMode ? { hashMode: a.hashMode } : {}), salt: counterSalt() });
const presentPay = (a: any) => stripSig(M.presentClosedPayment({ ...presentHopIn(a), transactionId: a.transactionId, payee: a.payee, paymentAmount: a.paymentAmount, paymentInstrument: a.paymentInstrument, ...(a.pisp ? { pisp: a.pisp } : {}), ...(a.executionDate !== undefined ? { executionDate: a.executionDate } : {}), ...(a.riskData ? { riskData: a.riskData } : {}) }));
const presentChk = (a: any) => stripSig(M.presentClosedCheckout({ ...presentHopIn(a), checkoutJwt: a.checkoutJwt }));
const pBase = (over: any = {}) => ({ open: S0.openPayment, aud: 'credential-provider', nonce: 'n1', iat: T0, transactionId: 'tx_1', payee: MERCH, paymentAmount: { amount: 100, currency: 'USD' }, paymentInstrument: INSTR, ...over });
const presentPayCases: [string, any][] = [
  ['basic', pBase()], ['issuer hash', pBase({ hashMode: 'issuer_jwt_hash' })], ['sha384 open', pBase({ open: SC.sha384!.openPayment })], ['sha512 open', pBase({ open: SC.sha512!.openPayment })], ['all fields', pBase({ pisp: PISP, executionDate: '2027-01-01', riskData: { s: 1 }, exp: T0 + 100, pca: { v: 1 } })],
  ['exp 0', pBase({ exp: 0 })], ['no aud', pBase({ aud: '' })], ['no nonce', pBase({ nonce: '' })], ['bad iat', pBase({ iat: 1.5 })], ['bad open', pBase({ open: 'garbage' })], ['open empty', pBase({ open: '' })], ['bad amount', pBase({ paymentAmount: { amount: 1.5, currency: 'USD' } })],
  ['bad payee', pBase({ payee: { id: 'x' } })], ['bad instrument', pBase({ paymentInstrument: { id: '' } })], ['no tx', pBase({ transactionId: '' })], ['bad exp', pBase({ exp: -1 })], ['bad pisp', pBase({ pisp: { legal_name: 'x' } })], ['bad risk', pBase({ riskData: [] })],
  ['chained to chain', pBase({ open: S0.paymentChain })], ['unicode', pBase({ nonce: 'é', aud: '日本', transactionId: 'é' })], ['wrong key still signs', pBase({ agentKey: 'evil' })],
];
for (const [l, a] of presentPayCases) await run('presentClosedPayment', l, presentPay, [a]);
const cBase = (over: any = {}) => ({ open: S0.openCheckout, aud: 'merchant', nonce: 'n1', iat: T0, checkoutJwt: S0.checkoutJwt, ...over });
const presentChkCases: [string, any][] = [
  ['basic', cBase()], ['issuer hash', cBase({ hashMode: 'issuer_jwt_hash' })], ['sha384 open', cBase({ open: SC.sha384!.openCheckout })], ['sha512 open', cBase({ open: SC.sha512!.openCheckout })], ['exp pca', cBase({ exp: T0 + 5, pca: { a: 1 } })],
  ['no aud', cBase({ aud: '' })], ['bad iat', cBase({ iat: 0.5 })], ['empty jwt', cBase({ checkoutJwt: '' })], ['non-ascii jwt', cBase({ checkoutJwt: 'é.é.é' })], ['bad open', cBase({ open: 'x' })], ['bad exp', cBase({ exp: 1.5 })],
];
for (const [l, a] of presentChkCases) await run('presentClosedCheckout', l, presentChk, [a]);

// ================================================================================================ PCA terms -> AP2
const TERMS = (over: any = {}) => ({ currency: 'USD', perTransactionCap: 50000, cumulativeCap: 100000, merchants: ['merchant_1'], categories: [], periodEnd: (T0 + 7200) * 1000, maxTransactionsPerPeriod: 5, ...over });
const GRANT = { v: 2, issuer: 'iss', holder: 'hold', caveats: [{ t: 'x' }], sig: 'sig' };
const PMAND = (terms: any, grant: any = GRANT) => ({ grant, terms });
for (const cur of ['USD', 'JPY', 'KWD', 'EUR', 'BHD', 'CLF', 'KRW']) {
  for (const cap of [0, 1, 7, 29, 57, 99, 100, 101, 115, 1000, 1234, 99999, 100000, 123456789, 2 ** 53 - 1, 4503599627370496, 0.29 * 100, 33, 58, 14, 15, 28, 56, 114, 290, 570, 1150]) {
    await run('ap2BudgetMax', `${cur}/${cap}`, M.ap2BudgetMax, [cap, cur]);
  }
}
for (const [i, c] of [-1, 1.5, '5', null, -0, 2 ** 53, 1e21].entries()) await run('ap2BudgetMax', `bad${i}`, M.ap2BudgetMax, [c, 'USD']);
await run('ap2BudgetMax', 'bad currency', M.ap2BudgetMax, [5, 'xx']);
for (const cur of ['USD', 'JPY', 'KWD', 'CLF']) for (const [i, m] of [0, 0.29, 0.57, 1, 1.15, 10.5, 100, 1000, 123456.78, 0.001, 0.005, 99999999999, 4.35, 8.2, 1e15, 0.1 + 0.2, 1e-7].entries()) await run('ap2BudgetReads', `${cur}/${i}`, M.ap2BudgetReads, [m, cur]);
for (const [i, m] of [-1, '5', null, [], 1e300].entries()) await run('ap2BudgetReads', `bad${i}`, M.ap2BudgetReads, [m, 'USD']);
for (const [i, [a, c]] of ([[0, 100], [100, 300], [1, 3], [1, 7], [299, 300], [300, 300], [301, 300], [0, 0], [5, 0], [5, -1], [1, 1e12], [123456789, 987654321], [2, 3], [1, 6], [4, 9], [5000, 50000], [50000, 50000], [0.1, 0.3], [7, 11], [13, 17], [1e9, 3e9]] as number[][]).entries()) await run('riskRatio', `r${i}`, M.riskRatio, [a, c]);
const FACTS = { transactionId: 'tx_1', payeeId: 'merchant_1', amount: 4000, currency: 'USD', instrumentId: 'spt_1', openHash: 'hash', agentJkt: 'jkt' };
for (const [l, f] of [['basic', FACTS], ['order', { agentJkt: 'jkt', openHash: 'hash', instrumentId: 'spt_1', currency: 'USD', amount: 4000, payeeId: 'merchant_1', transactionId: 'tx_1' }], ['unicode', { ...FACTS, transactionId: 'é日本' }], ['big amount', { ...FACTS, amount: 2 ** 53 - 1 }],
  ['float amount', { ...FACTS, amount: 1.5 }], ['v override', { ...FACTS, v: 2 }], ['extra', { ...FACTS, extra: [1, { a: 1 }] }], ['missing', { transactionId: 'x' }], ['empty', {}], ['neg zero', { ...FACTS, amount: -0 }], ['too many digits', { ...FACTS, amount: 0.1234567890123456 }]] as any[]) await run('pcaBindingNonce', l, M.pcaBindingNonce, [f]);
const DT = (terms: any, merch = [MERCH, MERCH2]) => [terms, merch, 'REF'];
for (const [l, terms] of [['basic', TERMS()], ['no maxTx', (() => { const t: any = TERMS(); delete t.maxTransactionsPerPeriod; return t; })()], ['jpy', TERMS({ currency: 'JPY', perTransactionCap: 5000, cumulativeCap: 10000 })], ['kwd', TERMS({ currency: 'KWD', cumulativeCap: 12345 })], ['two merchants', TERMS({ merchants: ['merchant_1', 'merchant_2'] })],
  ['missing merchant', TERMS({ merchants: ['nope'] })], ['no merchants', TERMS({ merchants: [] })], ['float cap', TERMS({ perTransactionCap: 1.5 })], ['neg cap', TERMS({ cumulativeCap: -1 })], ['str cap', TERMS({ perTransactionCap: '5' })], ['bad currency', TERMS({ currency: 'xx' })],
  ['no currency', (() => { const t: any = TERMS(); delete t.currency; return t; })()], ['unrepresentable', TERMS({ currency: 'KWD', cumulativeCap: 2 ** 53 - 1 })], ['maxTx zero', TERMS({ maxTransactionsPerPeriod: 0 })], ['cap 0', TERMS({ perTransactionCap: 0, cumulativeCap: 0 })]] as any[]) {
  await run('paymentConstraintsFromTerms', l, M.paymentConstraintsFromTerms, DT(terms));
  await run('pcaOpenClaim', l, M.pcaOpenClaim, [PMAND(terms)]);
}
for (const [l, m] of [['grant undefined', { terms: TERMS() }], ['terms undefined', { grant: GRANT }], ['grant null', PMAND(TERMS(), null)], ['numbers', PMAND(TERMS(), { n: 1.0, m: -0, k: 1e21, '2': 'a', '1': 'b' })], ['unicode', PMAND(TERMS(), { s: 'é\ud800' })], ['nested', PMAND({ ...TERMS(), extra: { a: [1, [2, [3]]] } })]] as any[]) await run('pcaOpenClaim', `x/${l}`, M.pcaOpenClaim, [m]);
const fromIn = (a: any) => ({ issuer: { privateKey: keyFor('issuer').privateKey, kid: 'issuer-1' }, agentJwk: pubOf('agent'), merchants: a.merchants ?? [MERCH, MERCH2], iat: a.iat ?? T0, ...(a.exp !== undefined ? { exp: a.exp } : {}), salt: counterSalt() });
const fromCases: [string, any][] = [
  ['basic', { mandate: PMAND(TERMS()) }], ['explicit exp', { mandate: PMAND(TERMS()), exp: T0 + 3600 }], ['exp at period end', { mandate: PMAND(TERMS()), exp: T0 + 7200 }], ['exp past period end', { mandate: PMAND(TERMS()), exp: T0 + 7201 }],
  ['no period end', { mandate: PMAND((() => { const t: any = TERMS(); delete t.periodEnd; return t; })()) }], ['no period end explicit exp', { mandate: PMAND((() => { const t: any = TERMS(); delete t.periodEnd; return t; })()), exp: T0 + 100 }],
  ['period end fractional', { mandate: PMAND(TERMS({ periodEnd: (T0 + 7200) * 1000 + 999 })) }], ['exp before iat', { mandate: PMAND(TERMS()), exp: T0 - 5 }], ['missing merchant desc', { mandate: PMAND(TERMS()), merchants: [MERCH2] }],
  ['two merchants', { mandate: PMAND(TERMS({ merchants: ['merchant_1', 'merchant_2'] })) }], ['jpy', { mandate: PMAND(TERMS({ currency: 'JPY', perTransactionCap: 5000, cumulativeCap: 10000 })) }], ['bad cap', { mandate: PMAND(TERMS({ cumulativeCap: 1.5 })) }],
];
for (const [l, a] of fromCases) {
  await run('openPaymentMandateFromPca', l, (x: any) => stripSig(M.openPaymentMandateFromPca(x.mandate, { ...fromIn(x), checkoutReference: x.checkoutReference ?? 'REF' })), [a]);
  await run('openCheckoutMandateFromPca', l, (x: any) => stripSig(M.openCheckoutMandateFromPca(x.mandate, { ...fromIn(x), lineItems: x.lineItems ?? [{ id: 'line_1', acceptable_items: [{ id: 'sku-1', title: 'Widget' }], quantity: 2 }] })), [a]);
}

// ================================================================================================ settlement
const PAY = (over: any = {}) => ({ ...CLOSED_BASE, ...over });
for (const [i, [amount, currency, dec]] of ([[4000, 'USD', 6], [4000, 'USD', 2], [4000, 'USD', 0], [4000, 'USD', 1], [4050, 'USD', 1], [4000, 'USD', 18], [0, 'USD', 0], [1, 'USD', 6], [123456, 'JPY', 6], [123456, 'JPY', 0], [123456, 'JPY', 3], [1500, 'KWD', 6], [1500, 'KWD', 2], [1500, 'KWD', 3],
  [1501, 'KWD', 2], [9007199254740991, 'USD', 18], [9007199254740991, 'USD', 0], [9007199254740991, 'USD', 2], [1, 'CLF', 4], [1, 'CLF', 3], [1, 'USD', 19], [1, 'USD', -1], [1, 'USD', 1.5], [-1, 'USD', 6], [1.5, 'USD', 6], [-0, 'USD', 6], [2 ** 53, 'USD', 6], [5, 'xx', 6], [100, 'USD', 6.0]] as any[]).entries()) {
  await run('toAtomicUnits', `a${i}`, M.toAtomicUnits, [{ amount, currency }, dec]);
}
for (const [i, d] of [null, '6', true, [], {}, 1e300].entries()) await run('toAtomicUnits', `dec-hostile${i}`, M.toAtomicUnits, [{ amount: 1, currency: 'USD' }, d]);
await run('toAtomicUnits', 'amount hostile', M.toAtomicUnits, [{ amount: '5', currency: 'USD' }, 6]);
const settle = (rail: string) => (p: any, ctxArg?: any) => (rail === 'x402' ? M.x402Settlement : M.stripeSptSettlement).settle(p, ctxArg ?? undefined);
const CTXS: [string, any][] = [['none', null], ['empty', {}], ['full', { resourceUrl: 'https://rs.example/r', payTo: '0xabc', network: 'base', asset: '0xusdc', decimals: 6, maxTimeoutSeconds: 120 }], ['decimals 2', { decimals: 2 }], ['decimals 0', { decimals: 0 }], ['decimals bad', { decimals: 19 }],
  ['decimals frac', { decimals: 1.5 }], ['decimals str', { decimals: '6' }], ['timeout 0', { maxTimeoutSeconds: 0 }], ['payTo only', { payTo: 'acct_1' }], ['payTo empty', { payTo: '' }], ['network only', { network: 'solana' }], ['unicode', { resourceUrl: 'https://é.example/日本', payTo: 'é' }]];
const PAYS: [string, any][] = [['basic', PAY()], ['stripe instrument', PAY({ payment_instrument: { id: 'spt_9', type: 'shared_payment_token' } })], ['card', PAY({ payment_instrument: { id: 'c', type: 'card' } })], ['jpy', PAY({ payment_amount: { amount: 3000, currency: 'JPY' } })],
  ['kwd', PAY({ payment_amount: { amount: 1500, currency: 'KWD' } })], ['unicode', PAY({ transaction_id: 'é日本', payee: { id: 'é', name: 'n' } })], ['rich', PAY({ pisp: PISP, risk_data: { a: 1 }, execution_date: '2027-01-01' })], ['mixed case currency', PAY({ payment_amount: { amount: 5, currency: 'EUR' } })]];
for (const [pl, p] of PAYS) for (const [cl, c] of CTXS) {
  await run('x402Settlement', `${pl}/${cl}`, settle('x402'), c === null ? [p] : [p, c]);
  await run('stripeSptSettlement', `${pl}/${cl}`, settle('stripe'), c === null ? [p] : [p, c]);
}
await run('x402Settlement', 'bad amount', settle('x402'), [PAY({ payment_amount: { amount: 1.5, currency: 'USD' } })]);
await run('x402Settlement', 'bad currency', settle('x402'), [PAY({ payment_amount: { amount: 5, currency: 'usd' } })]);

// ================================================================================================ PCA payment binding (Ed25519: deterministic)
{
  const principal = seed('ap2-principal'), agentSeed = seed('ap2-agent');
  const pk = (x: Uint8Array) => C.encodeKey(C.publicKeyOf(x));
  const mandateFor = (over: any = {}) => JSON.parse(JSON.stringify(P.buildPaymentMandate({
    principalSecret: principal, principalPublic: pk(principal), agentPublic: pk(agentSeed), merchants: ['merchant_1'], categories: [], currency: 'USD', perTransactionCap: 50000,
    autoApproveThreshold: 5000, cumulativeCap: 100000, periodMs: 7_200_000, periodStart: T0 * 1000, maxTransactionsPerPeriod: 5, now: T0 * 1000, ...over,
  })));
  const MAN: Record<string, any> = { base: mandateFor(), cats: mandateFor({ categories: ['5734'] }), jpy: mandateFor({ currency: 'JPY', perTransactionCap: 5000, cumulativeCap: 10000, autoApproveThreshold: 500 }) };
  const bind = (a: any) => M.buildPcaPaymentBinding({
    mandate: a.mandate, open: a.open, agentJwk: pubOf('agent'), agentSecret: seed(a.agentSeed), audience: a.audience, counter: a.counter, transactionId: a.transactionId,
    payee: a.payee, amount: a.amount, instrumentId: a.instrumentId, ...(a.category !== undefined ? { category: a.category } : {}), now: a.now,
    ...(a.cosign !== undefined ? { cosign: () => a.cosign } : {}),
  });
  const bi = (over: any = {}) => ({ mandate: MAN.base, open: S0.openPayment, agentSeed: 'ap2-agent', audience: 'atlas-instance', counter: 1, transactionId: 'tx_1', payee: MERCH, amount: { amount: 4000, currency: 'USD' }, instrumentId: 'spt_1', now: T0 * 1000, ...over });
  const BC: [string, any][] = [
    ['basic', bi()], ['category', bi({ mandate: MAN.cats, category: '5734' })], ['counter 7', bi({ counter: 7 })], ['amount 0', bi({ amount: { amount: 0, currency: 'USD' } })], ['amount 1', bi({ amount: { amount: 1, currency: 'USD' } })],
    ['amount at cap', bi({ amount: { amount: 50000, currency: 'USD' } })], ['amount over cap', bi({ amount: { amount: 60000, currency: 'USD' } })], ['amount 1/3', bi({ amount: { amount: 16667, currency: 'USD' } })], ['amount 1/7', bi({ amount: { amount: 7143, currency: 'USD' } })],
    ['fractional', bi({ amount: { amount: 1.5, currency: 'USD' } })], ['negative', bi({ amount: { amount: -1, currency: 'USD' } })], ['string amount', bi({ amount: { amount: '5', currency: 'USD' } })], ['big', bi({ amount: { amount: 2 ** 53 - 1, currency: 'USD' } })],
    ['jpy', bi({ mandate: MAN.jpy, amount: { amount: 3000, currency: 'JPY' } })], ['other currency', bi({ amount: { amount: 4000, currency: 'EUR' } })], ['other open', bi({ open: SC.sha384!.openPayment })], ['open chain', bi({ open: S0.paymentChain })], ['bad open', bi({ open: 'x' })],
    ['unicode ids', bi({ transactionId: 'é日本', instrumentId: 'ïnstr', payee: { id: 'merchant_é', name: 'n' } })], ['other seed', bi({ agentSeed: 'ap2-principal' })], ['aud empty', bi({ audience: '' })], ['cosign', bi({ cosign: { t: 2, shares: ['a', 'b'] } })],
    ['now other', bi({ now: T0 * 1000 + 123456 })], ['payee no id', bi({ payee: { name: 'x' } })],
  ];
  for (const [l, a] of BC) await run('buildPcaPaymentBinding', l, bind, [a]);
}

if (dropped) console.log(`dropped ${dropped} engine-message cases`);
if (process.env.AP2_SIZES) {
  const by: Record<string, [number, number]> = {};
  for (const c of o.cases) { const e = (by[c.fn] ??= [0, 0]); e[0]++; e[1] += JSON.stringify(c).length; }
  console.log(Object.entries(by).sort((a, b) => b[1][1] - a[1][1]).map(([k, v]) => `${k}: ${v[0]} cases ${(v[1] / 1024).toFixed(0)} KiB`).join('\n'));
}
refWrite(o, 'ap2');
