// Oracle: @atlasauth/pca-acp (ACP delegated payment tokens, x402 v1 + v2, x402 v2 HTTP transport, Stripe Shared Payment Tokens).
// Deterministic: fixed clock (every call passes `now`), Ed25519 keys derived from seeds (EdDSA signatures are deterministic), a fabricated
// PCActn (the package only reads cap_chain, aud, grant_ref, exp, action and hashes the rest). Writes out/ref-acp.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule). Values are JSON; compare by JSON value; a throw only requires the native to refuse.
//   constants()                                         -> the exported string / number constants as {name: value}
//   spendCapCaveat(max[, currency]) / merchantAllowCaveat(list) / merchantCategoryCaveat(list) / humanPresentCaveat([required])
//   extractPaymentAuthority(caveats)                    -> payment authority {maxAmount?, currency?, merchants|null, categories|null, humanPresentRequired}
//   checkPaymentAuthority(authority, request)           -> {ok, reason?}
//   mintDelegatedPaymentToken(pcActn, opts)             -> compact JWS string. opts.signingKey is a private OKP Ed25519 JWK; opts.now is always set.
//   verifyDelegatedPaymentToken(token, opts[, times])   -> normalized {ok, reason?, claims?, pcaResult?: {allow}}: opts.singleUse is a STORE SPEC
//       ("once" = a fresh store that grants each jti once, "always" = claim true, "never" = claim false, "throw" = claim throws, "truthy" = claim
//       returns a truthy non-boolean; any other value is passed through as is and is not a store). opts.verifyKey is a public JWK, opts.now is set.
//       Reasons that embed a library message are cut after "token signature did not verify" / "bound proof failed to verify"; pcaResult keeps only
//       {allow}. times > 1 runs the verify that many times over the SAME store and returns the list.
//   x402Challenge(resource, opts) / x402ChallengeV2(resource, opts)
//   x402Settle(payload, verifySpec[, settleSpec])       -> verifySpec is the verifier's constant answer ({ok, reason?, claims?}) or "throw"; settleSpec is
//       absent (no settle step), "echo" (receipt {jti, token}), "value" (receipt "receipt-1") or "throw".
//   acpX402Verifier(payload, opts[, times])             -> {ok, reason?, claims?} (normalized like verifyDelegatedPaymentToken; opts.singleUse is a store spec)
//   toAcpAllowance(claims)
//   resourceInfoProblems / requirementV2Problems / paymentRequiredV2Problems / paymentPayloadV2Problems / settlementResponseProblems / stripeSptProblems
//   encodePaymentRequiredHeader / decodePaymentRequiredHeader / encodePaymentSignatureHeader / decodePaymentSignatureHeader /
//   encodePaymentResponseHeader / decodePaymentResponseHeader
//   x402Negotiate(offered|null[, supported])            -> 1 | 2 | null
//   x402AcceptedMatches(offered, accepted) / normalizeX402Payload(raw)
//   readPaymentSignature(headers) / x402SettlementResponse(outcome, network) / x402PaymentSignatureHeaders(payload)
//   parseStripeSpt(t) / stripeSptUsable(t, use) / stripeUsageLimitsFor(authority) / stripeSptWithinClaims(t, claims)
import { createPrivateKey } from 'node:crypto';
import * as M0 from '@atlasauth/pca-acp';
import { Oracle, refWrite, seed, variants, reparse } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const HOST: any[] = [null, true, 0, -0, 1.5, 2 ** 53, '', 'x', '\ud800', [], {}, ['x']];
const vv = (x: any, op: any = {}) => variants(x, { hostile: HOST, ...op });
const o = new Oracle('acp', 'tools/pca-audit/oracles/acp.mts', 'TS-reference oracle for ACP delegated payment tokens, x402 v1/v2 and Stripe Shared Payment Tokens.');
const T0 = 1_800_000_000_000;

const privJwk = (label: string): any => {
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed(label))]);
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' }).export({ format: 'jwk' });
};
const SK = privJwk('acp/signer');
const PK = { kty: SK.kty, crv: SK.crv, x: SK.x };
const SK2 = privJwk('acp/other');
const PK2 = { kty: SK2.kty, crv: SK2.crv, x: SK2.x };

await o.run('constants', 'all', () => ({
  v: M.ACP_DELEGATED_TOKEN_VERSION, t: M.ACP_DELEGATED_TOKEN_TYPE, s: M.SPEND_CAP_CAVEAT, m: M.MERCHANT_ALLOW_CAVEAT, c: M.MERCHANT_CATEGORY_CAVEAT,
  h: M.HUMAN_PRESENT_CAVEAT, x1: M.X402_VERSION_1, x2: M.X402_VERSION_2, sup: M.X402_SUPPORTED_VERSIONS, pr: M.X402_V2_PAYMENT_REQUIRED_HEADER,
  ps: M.X402_PAYMENT_SIGNATURE_HEADER, pe: M.X402_PAYMENT_RESPONSE_HEADER, st: M.X402_HTTP_STATUS, spt: M.STRIPE_SPT_OBJECT,
}), []);

// ---- caveat builders
for (const [i, a] of ([[5], [0, 'usd'], [10000, 'USD'], [1, '']] as any[]).entries()) await o.run('spendCapCaveat', `c${i}`, M.spendCapCaveat, a);
for (const [i, l] of ([[], ['m1'], ['m1', 'm2', 'm1']] as any[]).entries()) {
  await o.run('merchantAllowCaveat', `l${i}`, M.merchantAllowCaveat, [l]);
  await o.run('merchantCategoryCaveat', `l${i}`, M.merchantCategoryCaveat, [l]);
}
await o.run('humanPresentCaveat', 'default', M.humanPresentCaveat, []);
await o.run('humanPresentCaveat', 'true', M.humanPresentCaveat, [true]);
await o.run('humanPresentCaveat', 'false', M.humanPresentCaveat, [false]);

// ---- extractPaymentAuthority
const CAV: any[][] = [
  [], [{ type: 'ttl', seconds: 5 }], [{ type: 'max_amount', max: 500 }], [{ type: 'max_amount', max: 500, currency: 'usd' }],
  [{ type: 'max_amount', max: 500, currency: 'usd' }, { type: 'max_amount', max: 300 }], [{ type: 'max_amount', max: 500, currency: 'usd' }, { type: 'max_amount', max: 300, currency: 'eur' }],
  [{ type: 'max_amount', max: 0 }], [{ type: 'max_amount', max: -1 }], [{ type: 'max_amount', max: 1.5 }], [{ type: 'max_amount', max: -0 }], [{ type: 'max_amount', max: 2 ** 53 }],
  [{ type: 'max_amount', max: '5' }], [{ type: 'max_amount' }], [{ type: 'max_amount', max: 5, currency: '' }], [{ type: 'max_amount', max: 5, currency: 5 }], [{ type: 'max_amount', max: 5, currency: null }],
  [{ type: 'merchant_allow', merchants: ['a', 'b', 'a'] }], [{ type: 'merchant_allow', merchants: ['a', 'b'] }, { type: 'merchant_allow', merchants: ['b', 'c'] }],
  [{ type: 'merchant_allow', merchants: ['a'] }, { type: 'merchant_allow', merchants: ['b'] }], [{ type: 'merchant_allow', merchants: [] }], [{ type: 'merchant_allow', merchants: 'a' }],
  [{ type: 'merchant_allow', merchants: [1] }], [{ type: 'merchant_allow' }],
  [{ type: 'merchant_category', categories: ['x', 'y'] }, { type: 'merchant_category', categories: ['y'] }], [{ type: 'merchant_category', categories: [null] }],
  [{ type: 'human_present', required: true }], [{ type: 'human_present', required: false }], [{ type: 'human_present', required: true }, { type: 'human_present', required: false }],
  [{ type: 'human_present', required: 'yes' }], [{ type: 'human_present' }],
  [{ type: 'max_amount', max: 100, currency: 'usd' }, { type: 'merchant_allow', merchants: ['m_1', 'm_2'] }, { type: 'merchant_category', categories: ['retail'] }, { type: 'human_present', required: true }, { type: 'scope', scope: 'x' }],
  [null], [5], ['x'], [{}], [{ type: 5 }], [[]], null, {}, 'abc', 5,
];
for (const [i, c] of CAV.entries()) await o.run('extractPaymentAuthority', `c${i}`, M.extractPaymentAuthority, [c]);

// ---- checkPaymentAuthority
const AUTHS = CAV.slice(0, 33).flatMap((c) => { try { return [M.extractPaymentAuthority(reparse(c))]; } catch { return []; } });
const REQS: any[] = [
  { amount: 100, currency: 'usd', merchant: 'm_1', category: 'retail', humanPresent: true }, { amount: 100, currency: 'usd', merchant: 'a' },
  { amount: 500, currency: 'usd', merchant: 'b' }, { amount: 501, currency: 'usd', merchant: 'b' }, { amount: 100, currency: 'eur', merchant: 'b' },
  { amount: 100, currency: 'usd', merchant: 'zzz' }, { amount: 100, currency: 'usd', merchant: 'b', category: 'x' }, { amount: 100, currency: 'usd', merchant: 'b', category: 'zz' },
  { amount: 100, currency: 'usd', merchant: 'b', category: null }, { amount: 100, currency: 'usd', merchant: 'b', humanPresent: false }, { amount: 100, currency: 'usd', merchant: 'b', humanPresent: 1 },
  { amount: 0, currency: 'usd', merchant: 'b' }, { amount: 1.5, currency: 'usd', merchant: 'b' }, { amount: -0, currency: 'usd', merchant: 'b' }, { amount: 2 ** 53, currency: 'usd', merchant: 'b' }, { amount: '5', currency: 'usd', merchant: 'b' },
  { amount: 5, currency: '', merchant: 'b' }, { amount: 5, currency: 'usd', merchant: '' }, { amount: 5, currency: 5, merchant: 'b' }, { amount: 5, currency: 'usd' }, { currency: 'usd', merchant: 'b' },
];
for (const [i, a] of AUTHS.entries()) for (const [j, r] of REQS.entries()) await o.run('checkPaymentAuthority', `a${i}r${j}`, M.checkPaymentAuthority, [a, r]);

// ---- fabricated PCActn + mint
const CAVEATS = [{ type: 'max_amount', max: 10000, currency: 'usd' }, { type: 'merchant_allow', merchants: ['m_1', 'm_2'] }, { type: 'merchant_category', categories: ['retail', 'food'] }, { type: 'human_present', required: true }];
const PC = (caveats: any[] = CAVEATS): any => ({
  ver: 2, aud: 'rs-acme', grant_ref: 'grant-1', iat: T0 - 1000, exp: T0 + 600_000, nonce: 'n-1',
  action: { verb: 'pay.checkout', resource: 'shop/checkout/1', params_digest: 'pd-1' },
  cap_chain: [{ id: 'grant-1', holder: 'root-holder', caveats: [] }, { id: 'cap-2', holder: 'leaf-holder', caveats }],
});
const MINT: any = {
  amount: 5000, currency: 'usd', merchant: 'm_1', session: 'cs_1', expiresAt: T0 + 300_000, paymentMethod: { type: 'shared_payment_token', token: 'spt_1' },
  signingKey: SK, now: T0, humanPresent: true, category: 'retail', issuer: 'agent-platform', kid: 'k1',
};
const noNowEdit = ([l, v]: [string, any]) => !l.startsWith('/now');
const mint = (pc: any, op: any) => M.mintDelegatedPaymentToken(pc, op);
const goodNow = (op: any) => Number.isFinite(op?.now);
const TOKEN: string = await mint(PC(), MINT);
await o.run('mintDelegatedPaymentToken', 'base', mint, [PC(), MINT]);
for (const [k, d] of Object.entries({ min: { jti: 'jti-fixed' }, nokid: { kid: undefined }, nocat: { category: undefined }, noiss: { issuer: undefined }, nohp: { humanPresent: undefined }, hpfalse: { humanPresent: false },
  alg: { alg: 'EdDSA' }, badalg: { alg: 'ES256' }, pm: { paymentMethod: { type: 'card', display: 'Visa 4242' } }, big: { amount: 10000 }, over: { amount: 10001 }, frac: { expiresAt: T0 + 300_000.5 },
  past: { expiresAt: T0 }, outlive: { expiresAt: T0 + 600_001 }, edge: { expiresAt: T0 + 600_000 }, nosess: { session: '' }, wrongcur: { currency: 'eur' }, wrongm: { merchant: 'm_3' }, pubkey: { signingKey: PK },
  utf: { session: 'cs_é ', merchant: 'm_1' }, nonow: { now: undefined }, } as any)) {
  if (k === 'nonow') continue;
  await o.run('mintDelegatedPaymentToken', `opt-${k}`, mint, [PC(), { ...MINT, ...d }]);
}
for (const [l, v] of vv(MINT, { maxPaths: 400 })) if (noNowEdit([l, v]) && goodNow(v) && (!l.startsWith('/signingKey') || l.startsWith('/signingKey/d =') || l === '/signingKey deleted')) await o.run('mintDelegatedPaymentToken', `opts ${l}`, mint, [PC(), v]);
const PCV = PC();
for (const [l, v] of vv(PCV, { maxPaths: 120 })) await o.run('mintDelegatedPaymentToken', `pc ${l}`, mint, [v, MINT]);
for (const [i, c] of CAV.slice(0, 33).entries()) await o.run('mintDelegatedPaymentToken', `cav${i}`, mint, [PC(c), { ...MINT, humanPresent: true }]);
await o.run('mintDelegatedPaymentToken', 'nochain', mint, [{ ...PC(), cap_chain: [] }, MINT]);

// ---- verify
const store = (spec: any): any => {
  if (spec === 'once') { const seen = new Set<string>(); return { claim: async (j: string) => (seen.has(j) ? false : (seen.add(j), true)) }; }
  if (spec === 'always') return { claim: async () => true };
  if (spec === 'never') return { claim: async () => false };
  if (spec === 'throw') return { claim: async () => { throw new Error('store down'); } };
  if (spec === 'truthy') return { claim: async () => 1 };
  return spec;
};
const normRes = (r: any): any => {
  const out: any = { ...r };
  if (typeof out.reason === 'string') out.reason = out.reason.replace(/^(token signature did not verify|bound proof failed to verify): .*$/s, '$1');
  if (out.pcaResult) out.pcaResult = { allow: out.pcaResult.allow };
  return out;
};
const vt = async (token: any, op: any, times = 1) => {
  const o2 = { ...op };
  if ('singleUse' in op) o2.singleUse = store(op.singleUse);
  const rs: any[] = [];
  for (let i = 0; i < times; i++) rs.push(normRes(await M.verifyDelegatedPaymentToken(token, o2)));
  return times === 1 ? rs[0] : rs;
};
const VER: any = { expectedMerchant: 'm_1', amount: 5000, verifyKey: PK, now: T0 + 1000, expectedCurrency: 'usd', singleUse: 'once' };
await o.run('verifyDelegatedPaymentToken', 'base', vt, [TOKEN, VER]);
await o.run('verifyDelegatedPaymentToken', 'twice', vt, [TOKEN, VER, 2]);
const vcases: [string, any, any][] = [
  ['lower', TOKEN, { amount: 100 }], ['over', TOKEN, { amount: 5001 }], ['expired', TOKEN, { now: T0 + 300_001 }], ['exp-edge', TOKEN, { now: T0 + 300_000 }], ['wrongm', TOKEN, { expectedMerchant: 'm_2' }],
  ['session', TOKEN, { expectedSession: 'cs_1' }], ['wrongsession', TOKEN, { expectedSession: 'cs_2' }], ['nullsession', TOKEN, { expectedSession: null }], ['wrongcur', TOKEN, { expectedCurrency: 'eur' }],
  ['nocur', TOKEN, { expectedCurrency: undefined }], ['nostore', TOKEN, { singleUse: undefined }], ['nonstrict', TOKEN, { strict: false, singleUse: undefined, expectedCurrency: undefined }],
  ['always', TOKEN, { singleUse: 'always' }], ['never', TOKEN, { singleUse: 'never' }], ['throw', TOKEN, { singleUse: 'throw' }], ['truthy', TOKEN, { singleUse: 'truthy' }], ['nullstore', TOKEN, { singleUse: null }],
  ['strstore', TOKEN, { singleUse: 'x' }], ['nonstrict-nullstore', TOKEN, { strict: false, singleUse: null }], ['nonstrict-numstore', TOKEN, { strict: false, singleUse: 5 }],
  ['wrongkey', TOKEN, { verifyKey: PK2 }], ['badalg', TOKEN, { alg: 'ES256' }], ['numalg', TOKEN, { alg: 5 }], ['nokey', TOKEN, { verifyKey: undefined }], ['privkey', TOKEN, { verifyKey: SK }],
  ['digest-ok', TOKEN, { pcActn: PC() }], ['digest-bad', TOKEN, { pcActn: { ...PC(), nonce: 'other' } }], ['grant-only', TOKEN, { grant: { id: 'grant-1' } }],
  ['grant-fake', TOKEN, { pcActn: PC(), grant: { id: 'grant-1', holder: 'root-holder', caveats: [] }, audience: 'rs-acme', insecureSkipPlanRootCheck: true }],
  ['noamt', TOKEN, { amount: undefined }], ['fracamt', TOKEN, { amount: 1.5 }], ['stramt', TOKEN, { amount: '5' }], ['negamt', TOKEN, { amount: -5 }],
];
for (const [k, t, d] of vcases) await o.run('verifyDelegatedPaymentToken', `case-${k}`, vt, [t, { ...VER, ...d }]);
// tampered / malformed tokens
const [H, P, S] = TOKEN.split('.');
const flip = (s: string, i: number) => s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
const b64 = (x: any) => Buffer.from(JSON.stringify(x)).toString('base64url');
const claims = JSON.parse(Buffer.from(P, 'base64url').toString());
const signedWith = async (c: any, op: any = {}) => { const cl = c; const hdr = { alg: 'EdDSA', typ: 'acp-delegated-payment' }; return (await import('node:crypto')).sign(null, Buffer.from(`${b64(hdr)}.${b64(cl)}`), createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed('acp/signer'))]), format: 'der', type: 'pkcs8' })); };
const resign = async (c: any, hdr: any = { alg: 'EdDSA', typ: 'acp-delegated-payment' }) => {
  const { sign } = await import('node:crypto');
  const signing = `${b64(hdr)}.${b64(c)}`;
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed('acp/signer'))]), format: 'der', type: 'pkcs8' });
  return `${signing}.${sign(null, Buffer.from(signing), key).toString('base64url')}`;
};
void signedWith;
const BADT: [string, any][] = [
  ['flip-sig', `${H}.${P}.${flip(S, 3)}`], ['flip-payload', `${H}.${flip(P, 5)}.${S}`], ['flip-header', `${flip(H, 4)}.${P}.${S}`], ['two', `${H}.${P}`], ['four', `${H}.${P}.${S}.x`], ['empty', ''],
  ['pad', `${H}.${P}=.${S}`], ['num', 5], ['null', null], ['obj', {}], ['nosig', `${H}.${P}.`], ['none', `${b64({ alg: 'none' })}.${P}.`],
  ['bad-typ', await resign(claims, { alg: 'EdDSA', typ: 'other' })], ['kid', await resign(claims, { alg: 'EdDSA', typ: 'acp-delegated-payment', kid: 'k9' })],
  ['hs256', await resign(claims, { alg: 'HS256' })], ['crit', await resign(claims, { alg: 'EdDSA', crit: ['x'], x: 1 })],
];
for (const [k, t] of BADT) await o.run('verifyDelegatedPaymentToken', `bad-${k}`, vt, [t, VER]);
// signed claim edits (a verifier sees a valid signature over odd claims)
for (const [l, v] of vv(claims, { maxPaths: 120 })) await o.run('verifyDelegatedPaymentToken', `claims ${l}`, vt, [await resign(v), VER]);
await o.run('verifyDelegatedPaymentToken', 'claims-array', vt, [await resign([1]), VER]);
await o.run('verifyDelegatedPaymentToken', 'claims-extra', vt, [await resign({ ...claims, extra: { a: [1, 2] } }), VER]);
// option variants (token fixed)
for (const [l, v] of vv(VER, { maxPaths: 150 })) if (noNowEdit([l, v]) && goodNow(v)) await o.run('verifyDelegatedPaymentToken', `opts ${l}`, vt, [TOKEN, v]);

// ---- x402 v1 challenge
const CH1: any = { amount: 100, currency: 'USDC', payTo: '0xabc', network: 'base', description: 'd', scheme: 'exact', mimeType: 'text/plain', error: 'e', maxTimeoutSeconds: 30 };
await o.run('x402Challenge', 'full', M.x402Challenge, ['https://x.test/r', CH1]);
await o.run('x402Challenge', 'min', M.x402Challenge, ['https://x.test/r', { amount: 1, currency: 'usd', payTo: 'p' }]);
await o.run('x402Challenge', 'nullish', M.x402Challenge, ['r', { ...CH1, network: null, scheme: null, error: null, description: null, mimeType: null, maxTimeoutSeconds: null }]);
for (const [l, v] of vv(CH1, { maxPaths: 60 })) await o.run('x402Challenge', l, M.x402Challenge, ['https://x.test/r', v]);

// ---- x402 v2
const RES: any = { url: 'https://x.test/r', description: 'd', mimeType: 'application/json', serviceName: 'svc', tags: ['a', 'b'], iconUrl: 'https://x.test/i.png' };
const REQ2: any = { scheme: 'exact', network: 'eip155:84532', amount: '1000', asset: 'usdc', payTo: '0xabc', maxTimeoutSeconds: 60, extra: { name: 'USDC' } };
const PR2: any = { x402Version: 2, error: 'e', resource: RES, accepts: [REQ2], extensions: { ext: { info: { a: 1 }, schema: { type: 'object' } } } };
const EXTRA_RES: any[] = ['https://x.test', 'http://a', 'ftp://a', 'x', '', 'https://', 'HTTPS://X.TEST/', ' https://x.test', 'javascript:alert(1)', 'https://x.test/\n', 'https://u:p@x.test', 'data:text/plain,hi', 'https://' + 'a'.repeat(2100)];
for (const [i, u] of EXTRA_RES.entries()) {
  await o.run('resourceInfoProblems', `url${i}`, M.resourceInfoProblems, [{ url: u }]);
  await o.run('resourceInfoProblems', `icon${i}`, M.resourceInfoProblems, [{ ...RES, iconUrl: u }]);
}
for (const [l, v] of vv(RES, { maxPaths: 120, lens: [32, 33] })) await o.run('resourceInfoProblems', l, M.resourceInfoProblems, [v]);
for (const [i, s] of (['a'.repeat(32), 'a'.repeat(33), 'é', 'a\tb', '~ ', '\x7f', ''] as string[]).entries()) await o.run('resourceInfoProblems', `svc${i}`, M.resourceInfoProblems, [{ url: 'https://x.test', serviceName: s, tags: [s] }]);
await o.run('resourceInfoProblems', 'tags6', M.resourceInfoProblems, [{ url: 'https://x.test', tags: ['1', '2', '3', '4', '5', '6'] }]);
for (const [l, v] of vv(REQ2, { maxPaths: 200 })) await o.run('requirementV2Problems', l, M.requirementV2Problems, [v]);
for (const [i, a] of (['0', '00', '01', '1', '10', '-1', '1.5', ' 1', '1 ', '9007199254740993', '1e3', ''] as string[]).entries()) await o.run('requirementV2Problems', `amount${i}`, M.requirementV2Problems, [{ ...REQ2, amount: a }]);
for (const [i, n] of (['eip155:1', 'ab:c', 'abcdefghi:x', 'eip155:', 'EIP155:1', 'eip155:1_a-b', 'eip155:' + 'a'.repeat(33), 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp', 'eip155'] as string[]).entries()) await o.run('requirementV2Problems', `net${i}`, M.requirementV2Problems, [{ ...REQ2, network: n }]);
for (const [l, v] of vv(PR2, { maxPaths: 150 })) await o.run('paymentRequiredV2Problems', l, M.paymentRequiredV2Problems, [v]);
for (const [l, v] of vv(PR2, { maxPaths: 100 })) await o.run('encodePaymentRequiredHeader', l, M.encodePaymentRequiredHeader, [v]);
await o.run('paymentRequiredV2Problems', 'two-accepts', M.paymentRequiredV2Problems, [{ ...PR2, accepts: [REQ2, { ...REQ2, amount: '0' }] }]);
await o.run('paymentRequiredV2Problems', 'ext-bad', M.paymentRequiredV2Problems, [{ ...PR2, extensions: { a: 1, b: { info: {}, schema: [] } } }]);
const HDR: string = M.encodePaymentRequiredHeader(PR2);
await o.run('encodePaymentRequiredHeader', 'base', M.encodePaymentRequiredHeader, [PR2]);
await o.run('decodePaymentRequiredHeader', 'base', M.decodePaymentRequiredHeader, [HDR]);
const b64s = (s: string) => Buffer.from(s, 'utf8').toString('base64');
for (const [i, v] of ([HDR.replace(/=+$/, ''), HDR + '=', HDR.slice(0, -1), HDR.slice(0, -2) + '!!', '', 'a', 'ab', 'abc', 'e30=', 'e30', b64s('{}'), b64s('null'), b64s('[1]'), b64s('{'), b64s(JSON.stringify(PR2) + ' '), b64s(' ' + JSON.stringify(PR2)),
  b64s(JSON.stringify({ ...PR2, x402Version: 1 })), HDR + '\n', ' ' + HDR, HDR.replace(/\+/g, '-'), 5, null, {}, '﻿' + HDR, b64s('﻿' + JSON.stringify(PR2)), Buffer.from([0xff, 0xfe, 0x7b, 0x7d]).toString('base64'), b64s('{"x402Version":2,"x402Version":2}')] as any[]).entries())
  await o.run('decodePaymentRequiredHeader', `v${i}`, M.decodePaymentRequiredHeader, [v]);
const CH2: any = { amount: 1000, asset: 'usdc', payTo: '0xabc', network: 'eip155:84532', scheme: 'exact', maxTimeoutSeconds: 30, extra: { n: 1 }, error: 'e', extensions: PR2.extensions };
await o.run('x402ChallengeV2', 'str', M.x402ChallengeV2, ['https://x.test/r', CH2]);
await o.run('x402ChallengeV2', 'info', M.x402ChallengeV2, [RES, CH2]);
await o.run('x402ChallengeV2', 'min', M.x402ChallengeV2, ['https://x.test/r', { amount: 1, asset: 'usd', payTo: 'p', network: 'eip155:1' }]);
for (const [i, r] of ([{ url: 'nope' }, {}, null, 5, ['x'], 'bad url', { ...RES, tags: 'x' }] as any[]).entries()) await o.run('x402ChallengeV2', `res${i}`, M.x402ChallengeV2, [r, CH2]);
for (const [l, v] of vv(CH2, { maxPaths: 60 })) await o.run('x402ChallengeV2', l, M.x402ChallengeV2, ['https://x.test/r', v]);
for (const [i, a] of ([[2, 1], [1], [2], [], undefined, [3], [3, 1], [1, 2, 3], [0], [2.5]] as any[]).entries()) {
  await o.run('x402Negotiate', `o${i}`, M.x402Negotiate, [a === undefined ? null : a]);
  for (const [j, s] of ([[2, 1], [1], [2], [], [3], [1, 3], [1, 2, 3]] as any[]).entries()) await o.run('x402Negotiate', `o${i}s${j}`, M.x402Negotiate, [a === undefined ? null : a, s]);
}
await o.run('x402AcceptedMatches', 'same', M.x402AcceptedMatches, [[REQ2], REQ2]);
await o.run('x402AcceptedMatches', 'reordered', M.x402AcceptedMatches, [[REQ2], { extra: { name: 'USDC' }, maxTimeoutSeconds: 60, payTo: '0xabc', asset: 'usdc', amount: '1000', network: 'eip155:84532', scheme: 'exact' }]);
await o.run('x402AcceptedMatches', 'second', M.x402AcceptedMatches, [[{ ...REQ2, amount: '5' }, REQ2], REQ2]);
await o.run('x402AcceptedMatches', 'none', M.x402AcceptedMatches, [[], REQ2]);
for (const [l, v] of vv(REQ2, { maxPaths: 100 })) await o.run('x402AcceptedMatches', l, M.x402AcceptedMatches, [[REQ2], v]);
await o.run('x402AcceptedMatches', 'deep-extra', M.x402AcceptedMatches, [[{ ...REQ2, extra: { b: [1, { z: 1, a: null }], a: 'é' } }], { ...REQ2, extra: { a: 'é', b: [1, { a: null, z: 1 }] } }]);

// ---- normalizeX402Payload / x402Settle / verifier
const V1P: any = { x402Version: 1, token: TOKEN, merchant: 'm_1', amount: 5000 };
const V2P: any = { x402Version: 2, accepted: REQ2, payload: { token: TOKEN }, resource: RES };
const V2S: any = { ...V2P, payload: { token: 'tok' } };
const V1S: any = { ...V1P, token: 'tok' };
for (const [l, v] of vv(V1S, { maxPaths: 100 })) await o.run('normalizeX402Payload', `v1 ${l}`, M.normalizeX402Payload, [v]);
for (const [l, v] of vv(V2S, { maxPaths: 150 })) await o.run('normalizeX402Payload', `v2 ${l}`, M.normalizeX402Payload, [v]);
for (const [i, v] of ([{}, { token: 't' }, { x402Version: 3, token: 't' }, { x402Version: '2', token: 't' }, { x402Version: null, token: 't' }, { x402Version: [1], token: 't' }, { x402Version: {}, token: 't' }, { x402Version: 2.0, accepted: REQ2, payload: { token: 't' } },
  { x402Version: 2, accepted: { ...REQ2, amount: '9007199254740993' }, payload: { token: 't' } }, { x402Version: 2, accepted: { ...REQ2, amount: '9007199254740991' }, payload: { token: 't' } }, { x402Version: 2, accepted: { ...REQ2, amount: '1' + '0'.repeat(400) }, payload: { token: 't' } },
  null, [], 'x', 5, { token: 't', amount: 1.5 }, { token: 't', amount: '5' }, { token: '', merchant: '' }] as any[]).entries()) await o.run('normalizeX402Payload', `x${i}`, M.normalizeX402Payload, [v]);

const settle = async (payload: any, vspec: any, sspec?: string) => {
  const verify = async () => { if (vspec === 'throw') throw new Error('verify down'); return JSON.parse(JSON.stringify(vspec)); };
  const so: any = { verify };
  if (sspec === 'echo') so.settle = async (_p: any, c: any) => ({ jti: c.jti, token: _p.token });
  else if (sspec === 'value') so.settle = async () => 'receipt-1';
  else if (sspec === 'throw') so.settle = async () => { throw new Error('settle down'); };
  else if (sspec === 'undef') so.settle = async () => undefined;
  return M.x402Settle(payload, so);
};
const VSPECS: any[] = [{ ok: true, claims: { jti: 'j1', merchant: 'm' } }, { ok: false }, { ok: false, reason: 'nope' }, { ok: false, reason: 'nope', claims: { jti: 'j' } }, { ok: false, claims: null }, { ok: true }, { ok: 1, claims: { jti: 'j2' } }, { ok: 0, claims: { jti: 'j' } },
  { ok: true, claims: { jti: 'j3' }, reason: 'ignored' }, { ok: false, reason: null }, 'throw'];
for (const [i, v] of VSPECS.entries()) for (const s of [undefined, 'echo', 'value', 'throw', 'undef']) {
  await o.run('x402Settle', `v${i}-${s}`, settle, s === undefined ? [V1S, v] : [V1S, v, s]);
}
for (const [l, v] of vv(V2S, { maxPaths: 80 })) await o.run('x402Settle', `payload ${l}`, settle, [v, VSPECS[0], 'echo']);
await o.run('x402Settle', 'bad-payload', settle, [{ x402Version: 7 }, VSPECS[0]]);

const av = async (payload: any, op: any, times = 1) => {
  const o2 = { ...op };
  if ('singleUse' in op) o2.singleUse = store(op.singleUse);
  const fn = M.acpX402Verifier(o2);
  const rs: any[] = [];
  for (let i = 0; i < times; i++) rs.push(normRes(await fn(payload)));
  return times === 1 ? rs[0] : rs;
};
const AVO: any = { verifyKey: PK, now: T0 + 1000, expectedMerchant: 'm_1', amount: 5000, expectedCurrency: 'usd', singleUse: 'once' };
await o.run('acpX402Verifier', 'v1', av, [V1P, AVO]);
await o.run('acpX402Verifier', 'v1-twice', av, [V1P, AVO, 2]);
await o.run('acpX402Verifier', 'v2', av, [V2P, { ...AVO, amount: 1000 }]);
await o.run('acpX402Verifier', 'v2-amount-from-accepted', av, [V2P, { ...AVO, amount: undefined, strict: false }]);
await o.run('acpX402Verifier', 'v2-offered', av, [V2P, { ...AVO, amount: 1000, offered: [REQ2] }]);
await o.run('acpX402Verifier', 'v2-not-offered', av, [V2P, { ...AVO, amount: 1000, offered: [{ ...REQ2, amount: '1' }] }]);
await o.run('acpX402Verifier', 'v1-offered-ignored', av, [V1P, { ...AVO, offered: [] }]);
for (const [k, d] of Object.entries({ nomerchant: { expectedMerchant: undefined }, noamount: { amount: undefined }, nonstrict: { strict: false, expectedMerchant: undefined, amount: undefined, singleUse: undefined, expectedCurrency: undefined },
  nonstrict2: { strict: false, expectedMerchant: undefined, amount: undefined, singleUse: 'always' }, emptym: { expectedMerchant: '' }, badamt: { amount: 1.5 }, over: { amount: 6000 }, wrongm: { expectedMerchant: 'zz' },
  nostore: { singleUse: undefined }, session: { expectedSession: 'cs_1' }, never: { singleUse: 'never' }, throwing: { singleUse: 'throw' }, wrongkey: { verifyKey: PK2 } } as any)) {
  await o.run('acpX402Verifier', `o-${k}`, av, [V1P, { ...AVO, ...d }]);
}
for (const [l, v] of vv(V1P, { maxPaths: 80 })) await o.run('acpX402Verifier', `payload ${l}`, av, [v, AVO]);
await o.run('acpX402Verifier', 'v1-from-payload', av, [V1P, { ...AVO, strict: false, expectedMerchant: undefined, amount: undefined }]);
await o.run('acpX402Verifier', 'v1-payload-wrong', av, [{ ...V1P, merchant: 'zz' }, { ...AVO, strict: false, expectedMerchant: undefined, amount: undefined }]);
await o.run('acpX402Verifier', 'v1-payload-amount', av, [{ ...V1P, amount: 9999 }, { ...AVO, strict: false, expectedMerchant: undefined, amount: undefined }]);

// ---- toAcpAllowance
const CL: any = { typ: 'acp-delegated-payment', ver: 1, jti: 'j', session: 'cs_1', merchant: 'm_1', amount: 5000, currency: 'USD', iat: T0, exp: T0 + 300_000.7, humanPresent: true };
await o.run('toAcpAllowance', 'base', M.toAcpAllowance, [CL]);
for (const [i, e] of ([0, -1, 1, 8.64e15, 8.64e15 + 1, -8.64e15, 253402300799999, 253402300800000, -62198755200000, -62167219200001, 951782400000, 1e21, 1.9, -1.9, 4102444800000] as number[]).entries()) await o.run('toAcpAllowance', `exp${i}`, M.toAcpAllowance, [{ ...CL, exp: e }]);
for (const [i, c] of (['usd', 'US', 'usdc', 'ÜSD', 'İİİ', 'EUR', 'eur '] as string[]).entries()) await o.run('toAcpAllowance', `cur${i}`, M.toAcpAllowance, [{ ...CL, currency: c }]);
for (const n of [255, 256, 257]) await o.run('toAcpAllowance', `merchant${n}`, M.toAcpAllowance, [{ ...CL, merchant: 'm'.repeat(n) }]);
for (const [l, v] of vv(CL, { maxPaths: 200 })) await o.run('toAcpAllowance', l, M.toAcpAllowance, [v]);

// ---- Stripe SPT
const SPT: any = {
  id: 'spt_123', object: 'shared_payment.granted_token', created: 1_700_000_000, livemode: true, deactivated_at: null, deactivated_reason: null,
  usage_limits: { currency: 'usd', max_amount: 10000, expires_at: 1_800_000_000 }, usage_details: { amount_captured: { value: 2000, currency: 'usd' } },
  payment_method_details: { type: 'card', card: { last4: '4242' } }, agent_details: { name: 'a' }, shared_metadata: { k: 'v' }, risk_details: null,
};
await o.run('stripeSptProblems', 'base', M.stripeSptProblems, [SPT]);
await o.run('parseStripeSpt', 'base', M.parseStripeSpt, [SPT]);
for (const [l, v] of vv(SPT, { maxPaths: 300 })) {
  await o.run('stripeSptProblems', l, M.stripeSptProblems, [v]);
  if (l.length % 3 === 0) await o.run('parseStripeSpt', l, M.parseStripeSpt, [v]);
}
for (const [i, v] of ([null, 5, 'x', [], undefined] as any[]).entries()) await o.run('stripeSptProblems', `nonobj${i}`, M.stripeSptProblems, [v === undefined ? null : v]);
const U: any = { now: 1_700_000_100, amount: 1000, currency: 'USD' };
await o.run('stripeSptUsable', 'base', M.stripeSptUsable, [SPT, U]);
for (const [k, d] of Object.entries({ all: { amount: 8000 }, over: { amount: 8001 }, zero: { amount: 0 }, frac: { amount: 1.5 }, nownotint: { now: 1.5 }, test: { livemode: false }, live: { livemode: true }, nullmode: { livemode: null }, wrongcur: { currency: 'eur' },
  expired: { now: 1_800_000_000 }, justbefore: { now: 1_799_999_999 }, nocur: { currency: undefined } } as any)) await o.run('stripeSptUsable', `use-${k}`, M.stripeSptUsable, [SPT, { ...U, ...d }]);
for (const [k, d] of Object.entries({ consumed: { deactivated_reason: 'consumed' }, deact: { deactivated_at: 1_700_000_050 }, deactfuture: { deactivated_at: 1_700_000_200 }, deactedge: { deactivated_at: 1_700_000_100 }, test: { livemode: false },
  noexp: { usage_limits: { currency: 'usd', max_amount: 10000 } }, nullexp: { usage_limits: { currency: 'usd', max_amount: 10000, expires_at: null } }, nocaptured: { usage_details: null }, capeur: { usage_details: { amount_captured: { value: 1, currency: 'eur' } } },
  full: { usage_details: { amount_captured: { value: 10000, currency: 'usd' } } }, bad: { id: 'x' }, upper: { usage_limits: { currency: 'USD', max_amount: 1 } } } as any)) await o.run('stripeSptUsable', `tok-${k}`, M.stripeSptUsable, [{ ...SPT, ...d }, U]);
for (const [l, v] of vv(U, { maxPaths: 100 })) await o.run('stripeSptUsable', `use ${l}`, M.stripeSptUsable, [SPT, v]);
for (const [i, v] of ([null, 5, {}] as any[]).entries()) await o.run('stripeSptUsable', `nonobj${i}`, M.stripeSptUsable, [v, U]);
const AUTH: any = { maxAmount: 5000, currency: 'USD', expiresAtMs: T0 };
await o.run('stripeUsageLimitsFor', 'base', M.stripeUsageLimitsFor, [AUTH]);
await o.run('stripeUsageLimitsFor', 'noexp', M.stripeUsageLimitsFor, [{ maxAmount: 5, currency: 'eur' }]);
for (const [i, e] of ([1, 999, 1000, 1999.9, 0, -1, 1e15, 0.5] as number[]).entries()) await o.run('stripeUsageLimitsFor', `exp${i}`, M.stripeUsageLimitsFor, [{ ...AUTH, expiresAtMs: e }]);
for (const [l, v] of vv(AUTH, { maxPaths: 100 })) await o.run('stripeUsageLimitsFor', l, M.stripeUsageLimitsFor, [v]);
const CLM: any = { amount: 10000, currency: 'USD', exp: 1_800_000_000_000 };
await o.run('stripeSptWithinClaims', 'base', M.stripeSptWithinClaims, [SPT, CLM]);
for (const [k, d] of Object.entries({ cur: { currency: 'eur' }, amt: { amount: 9999 }, exp: { exp: 1_799_999_999_999 }, nonnum: { amount: '10000' }, nonnum2: { amount: '9999' }, undef: { amount: undefined }, nullamt: { amount: null }, strexp: { exp: '1800000000000' }, bool: { amount: true }, arr: { amount: [10000] }, frac: { amount: 10000.5 } } as any))
  await o.run('stripeSptWithinClaims', `claims-${k}`, M.stripeSptWithinClaims, [SPT, { ...CLM, ...d }]);
await o.run('stripeSptWithinClaims', 'noexp', M.stripeSptWithinClaims, [{ ...SPT, usage_limits: { currency: 'usd', max_amount: 100 } }, CLM]);
await o.run('stripeSptWithinClaims', 'bad', M.stripeSptWithinClaims, [{ ...SPT, id: 'x' }, CLM]);
for (const [l, v] of vv(CLM, { maxPaths: 100 })) await o.run('stripeSptWithinClaims', l, M.stripeSptWithinClaims, [SPT, v]);

// ---- x402 v2 HTTP transport
const PAY2: any = { x402Version: 2, resource: RES, accepted: REQ2, payload: { token: 'tok' }, extensions: { a: 1 } };
const SET_OK: any = { success: true, transaction: '0xabc', network: 'eip155:84532', payer: '0xp', amount: '1000', extensions: { a: 1 } };
const SET_BAD: any = { success: false, errorReason: 'insufficient_funds', transaction: '', network: 'eip155:84532', payer: '0xp' };
for (const [l, v] of vv(PAY2, { maxPaths: 200 })) {
  await o.run('paymentPayloadV2Problems', l, M.paymentPayloadV2Problems, [v]);
  if (l.length % 3 === 0) await o.run('encodePaymentSignatureHeader', l, M.encodePaymentSignatureHeader, [v]);
}
for (const [n, s] of Object.entries({ ok: SET_OK, bad: SET_BAD })) for (const [l, v] of vv(s, { maxPaths: 200 })) {
  await o.run('settlementResponseProblems', `${n} ${l}`, M.settlementResponseProblems, [v]);
  await o.run('encodePaymentResponseHeader', `${n} ${l}`, M.encodePaymentResponseHeader, [v]);
}
for (const [i, v] of ([null, 5, [], 'x'] as any[]).entries()) {
  await o.run('paymentPayloadV2Problems', `nonobj${i}`, M.paymentPayloadV2Problems, [v]);
  await o.run('settlementResponseProblems', `nonobj${i}`, M.settlementResponseProblems, [v]);
}
for (const [i, v] of ([{ ...SET_OK, errorReason: 'x' }, { ...SET_OK, transaction: '' }, { ...SET_BAD, errorReason: '' }, { ...SET_BAD, errorReason: undefined }, { ...SET_BAD, transaction: 'tx' }, { ...SET_OK, amount: '01' }, { ...SET_OK, amount: '0' }, { ...SET_OK, amount: 5 }] as any[]).entries()) {
  await o.run('settlementResponseProblems', `x${i}`, M.settlementResponseProblems, [v]);
  await o.run('encodePaymentResponseHeader', `x${i}`, M.encodePaymentResponseHeader, [v]);
}
const SIG: string = M.encodePaymentSignatureHeader(PAY2);
const RESP: string = M.encodePaymentResponseHeader(SET_OK);
await o.run('encodePaymentSignatureHeader', 'base', M.encodePaymentSignatureHeader, [PAY2]);
await o.run('encodePaymentResponseHeader', 'base', M.encodePaymentResponseHeader, [SET_OK]);
await o.run('encodePaymentResponseHeader', 'base-bad', M.encodePaymentResponseHeader, [SET_BAD]);
await o.run('x402PaymentSignatureHeaders', 'base', M.x402PaymentSignatureHeaders, [PAY2]);
await o.run('x402PaymentSignatureHeaders', 'bad', M.x402PaymentSignatureHeaders, [{ ...PAY2, x402Version: 1 }]);
for (const [i, v] of ([SIG, SIG.replace(/=+$/, ''), SIG + '=', '', 'a', 'e30=', b64s('{}'), b64s('null'), b64s('{'), SIG + '\n', 5, null, {}, b64s(JSON.stringify({ ...PAY2, x402Version: 1 })), b64s(JSON.stringify(PAY2) + '  ')] as any[]).entries())
  await o.run('decodePaymentSignatureHeader', `v${i}`, M.decodePaymentSignatureHeader, [v]);
for (const [i, v] of ([RESP, RESP.replace(/=+$/, ''), RESP + '=', '', 'e30=', b64s('{}'), b64s('{'), 5, null, M.encodePaymentResponseHeader(SET_BAD), b64s(JSON.stringify({ ...SET_OK, success: 'yes' }))] as any[]).entries())
  await o.run('decodePaymentResponseHeader', `v${i}`, M.decodePaymentResponseHeader, [v]);
const HDRS: any[] = [
  { 'PAYMENT-SIGNATURE': SIG }, { 'payment-signature': SIG }, { 'Payment-Signature': [SIG, 'zzz'] }, { 'payment-signature': [] }, {}, { 'x-other': 'a' }, { 'PAYMENT-SIGNATURE': '' }, { 'payment-signature': 'e30=' }, { 'payment-signature': '!!' },
  { 'payment-signature': null }, { 'payment-signature': 5 }, { 'Payment-Signature': 'bad', 'PAYMENT-SIGNATURE': SIG }, { 'payment-signature': [null] }, { 'payment-signature': [''] },
];
for (const [i, h] of HDRS.entries()) await o.run('readPaymentSignature', `h${i}`, M.readPaymentSignature, [h]);
const SETS: any[] = [
  [{ settled: true, transaction: '0xabc', payer: '0xp', amount: '1000' }, 'eip155:84532'], [{ settled: true, transaction: '0xabc' }, 'eip155:84532'], [{ settled: true, transaction: '' }, 'eip155:84532'], [{ settled: true }, 'eip155:84532'],
  [{ settled: false, reason: 'no' }, 'eip155:84532'], [{ settled: false, reason: 'no', transaction: '0xt', payer: '0xp' }, 'eip155:84532'], [{ settled: false, reason: '' }, 'eip155:84532'], [{ settled: false }, 'eip155:84532'],
  [{ settled: false, reason: 'no', transaction: null }, 'eip155:84532'], [{ settled: true, transaction: '0xabc' }, 'bad'], [{ settled: true, transaction: '0xabc' }, null], [{ settled: 1, transaction: '0xabc' }, 'eip155:1'], [{ settled: 0, reason: 'r' }, 'eip155:1'],
  [{ settled: true, transaction: '0xabc', amount: '01' }, 'eip155:1'], [{ settled: true, transaction: 5 }, 'eip155:1'], [{ settled: false, reason: 'r', payer: 5 }, 'eip155:1'], [{ settled: 'yes', transaction: 'x', payer: null }, 'eip155:1'],
];
for (const [i, a] of SETS.entries()) await o.run('x402SettlementResponse', `s${i}`, M.x402SettlementResponse, a);

{ const by: any = {}; for (const c of o.cases) by[c.fn] = (by[c.fn] ?? 0) + JSON.stringify(c).length; console.log(JSON.stringify(by)); }
refWrite(o, 'acp');
