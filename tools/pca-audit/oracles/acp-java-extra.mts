// Oracle (extra, Java lane): ACP verifyDelegatedPaymentToken with a REAL grant and a REAL signed PCActn, so the full core re-verification
// runs to an allow (the base acp.mts uses a fabricated PCActn, which the core always refuses). Covers the audience tri-state of the core:
// a string, an explicit null (opt-out) and an omitted audience (fails closed).
// PORTING: verifyDelegatedPaymentToken(token, opts[, times]) -> Acp.verifyDelegatedPaymentToken, as in acp.mts; the result is normalized
// {ok, reason?, claims?, pcaResult?: {allow}} (reasons cut after the library message). opts.singleUse = "once" is the store spec of acp.mts.
// Writes out/ref-acp-java-extra.json.gz. Deterministic: Ed25519 keys from seed(label), fixed clock.
import { createPrivateKey } from 'node:crypto';
import * as M0 from '@atlasauth/pca-acp';
import * as C0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';

const M: any = (M0 as any).default ?? M0;
const C: any = (C0 as any).default ?? C0;
const o = new Oracle('acp-java-extra', 'tools/pca-audit/oracles/acp-java-extra.mts', 'TS-reference oracle for ACP with a real grant (Java lane).');
const T0 = 1_800_000_000_000;
const J = (x: any) => JSON.parse(JSON.stringify(x));
const privJwk = (label: string): any => createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seed(label))]), format: 'der', type: 'pkcs8' }).export({ format: 'jwk' });
const SK = privJwk('acp/signer');
const PK = { kty: SK.kty, crv: SK.crv, x: SK.x };
const pr = seed('acpx/principal'), ag = seed('acpx/agent');
const pk = (s: Uint8Array) => C.encodeKey(C.publicKeyOf(s));
const CAVEATS = [{ type: 'max_amount', max: 10000, currency: 'usd' }, { type: 'merchant_allow', merchants: ['m_1', 'm_2'] }, { type: 'merchant_category', categories: ['retail', 'food'] }, { type: 'human_present', required: true }];
const GRANT = J(C.mintRoot({ principalSecret: pr, principalPublic: pk(pr), holder: pk(ag), caveats: CAVEATS }));
const plan = [{ id: 'pay', verb: 'pay.checkout', resource: 'shop/checkout/1' }];
const PC = (over: any = {}) => J(C.buildPCActn({ grant: GRANT, chain: [GRANT], plan, nodeId: 'pay', counter: 1, signerSecret: ag, aud: 'rs-acme', now: T0 - 1000, ttlMs: 600_000, nonce: 'n-1', ...over }));
const MINT: any = { amount: 5000, currency: 'usd', merchant: 'm_1', session: 'cs_1', expiresAt: T0 + 300_000, paymentMethod: { type: 'shared_payment_token', token: 'spt_1' }, signingKey: SK, now: T0, humanPresent: true, category: 'retail', issuer: 'agent-platform', kid: 'k1' };
const pcActn = PC();
const TOKEN: string = await M.mintDelegatedPaymentToken(pcActn, MINT);
const store = () => { const seen = new Set<string>(); return { claim: async (j: string) => (seen.has(j) ? false : (seen.add(j), true)) }; };
const norm = (r: any) => {
  const out: any = { ...r };
  if (typeof out.reason === 'string') out.reason = out.reason.replace(/^(token signature did not verify|bound proof failed to verify): .*$/s, '$1');
  if (out.pcaResult) out.pcaResult = { allow: out.pcaResult.allow };
  return out;
};
const vt = async (token: any, op: any) => { const o2 = { ...op }; if ('singleUse' in op) o2.singleUse = store(); return norm(await M.verifyDelegatedPaymentToken(token, o2)); };
const VER: any = { expectedMerchant: 'm_1', amount: 5000, verifyKey: PK, now: T0 + 1000, expectedCurrency: 'usd', singleUse: 'once' };
let n = 0;
const add = (name: string, d: any, token = TOKEN) => o.run('verifyDelegatedPaymentToken', `${name}#${n++}`, vt, [token, { ...VER, ...d }]);
const full = { pcActn, grant: GRANT, insecureSkipPlanRootCheck: true };
await add('allow string aud', { ...full, audience: 'rs-acme' });
await add('allow null aud', { ...full, audience: null });
await add('omitted aud', full);
await add('wrong aud', { ...full, audience: 'other' });
await add('empty aud', { ...full, audience: '' });
await add('no skip no roots', { pcActn, grant: GRANT, audience: 'rs-acme' });
await add('roots listed', { pcActn, grant: GRANT, audience: 'rs-acme', authorizedPlanRoots: [pcActn.plan.root] });
await add('roots other', { pcActn, grant: GRANT, audience: 'rs-acme', authorizedPlanRoots: ['x'] });
await add('roots empty', { pcActn, grant: GRANT, audience: 'rs-acme', authorizedPlanRoots: [] });
await add('now late', { ...full, audience: 'rs-acme', now: T0 + 700_000 });
await add('now early', { ...full, audience: 'rs-acme', now: T0 - 200_000 });
await add('other grant', { ...full, audience: 'rs-acme', grant: J(C.mintRoot({ principalSecret: pr, principalPublic: pk(pr), holder: pk(ag), caveats: [] })) });
await add('tampered pcactn', { ...full, audience: 'rs-acme', pcActn: { ...pcActn, counter: 9 } });
await add('grant only', { grant: GRANT, audience: 'rs-acme' });
await add('digest only', { pcActn });
console.log('cases', o.cases.length);
refWrite(o, 'acp-java-extra');
