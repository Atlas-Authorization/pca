// Oracle (extra, Java lane): the parts of @atlasauth/pca-payments that sit on the core decision and the optimistic path.
//   authorizeChargeCore(mandate, charge, grant)   -> Payments.authorizeCharge(mandate, charge, grant) with the DEFAULT core decision (no decider)
//   openChargeBond(pcactn, opts, seedB64u)        -> Payments.openChargeBond(pcactn, OpenOptions, Keys.edFromSeed(unb64u(seed))); the claim
//                                                    (Ed25519: deterministic, compared in full) or {"$throws"}
// opts = {bondRef, claimedR, challengeWindowMs?, issuedAt?, serverNow?}. Mandates, charges and budgets mirror payments.mts. Deterministic.
// Writes out/ref-payments-java-extra.json.gz.
import * as C0 from '@atlasauth/pca';
import * as P0 from '@atlasauth/pca-payments';
import { Oracle, refWrite, seed } from './lib.mjs';

const C: any = (C0 as any).default ?? C0;
const P: any = (P0 as any).default ?? P0;
const { publicKeyOf, encodeKey } = C;
const o = new Oracle('payments-java-extra', 'tools/pca-audit/oracles/payments-java-extra.mts', 'TS-reference oracle for the payments decision default and bonds (Java lane).');
const T0 = 1_800_000_000_000;
const sk = { principal: seed('payx-principal'), agent: seed('payx-agent') };
const pk = (s: Uint8Array) => encodeKey(publicKeyOf(s));
const seedB64 = Buffer.from(sk.agent).toString('base64url');
const J = (x: any) => JSON.parse(JSON.stringify(x));
const base: any = {
  principalSecret: sk.principal, principalPublic: pk(sk.principal), agentPublic: pk(sk.agent), merchants: ['openai', 'aws'], categories: ['5734', '5817'],
  currency: 'USD', perTransactionCap: 500, autoApproveThreshold: 200, cumulativeCap: 1000, periodMs: 30 * 86_400_000, periodStart: T0, maxTransactionsPerPeriod: 5,
  replenishPerCosign: 400, goal: 'buy compute', goalSalt: 'c2FsdC0wMDAx', now: T0,
};
const M: Record<string, any> = { base: J(P.buildPaymentMandate(base)), minimal: J(P.buildPaymentMandate({ ...base, merchants: ['m1'], currency: 'EUR', perTransactionCap: 100, autoApproveThreshold: 0, cumulativeCap: 100, maxTransactionsPerPeriod: undefined, periodMs: undefined })) };
// Number values are plain JSON numbers here; the byte-valued fields of a mandate (none) need no conversion.
const ch = (over: any = {}): any => ({ merchant: 'openai', amount: 50, category: '5734', currency: 'USD', now: T0 + 1000, recentChargeTimes: [], ...over });
const authorize = (m: any, c: any, g: any) => P.authorizeCharge(m, c, g);
let n = 0;
const run = (fn: string, name: string, ref: any, args: any[]) => o.run(fn, `${name}#${n++}`, ref, args);

const charges: any[] = [ch(), ch({ amount: 0 }), ch({ amount: 199 }), ch({ amount: 200 }), ch({ amount: 201 }), ch({ amount: 499 }), ch({ amount: 500 }), ch({ amount: 501 }), ch({ amount: 1000 }), ch({ amount: 1.5 }), ch({ amount: -1 }),
  ch({ merchant: 'aws' }), ch({ merchant: 'nope' }), ch({ merchant: '' }), ch({ merchant: '*' }), ch({ category: '5817' }), ch({ category: 'x' }), ch({ category: undefined }), ch({ currency: 'EUR' }),
  ch({ now: T0 + 31 * 86_400_000 }), ch({ now: T0 - 1 }), ch({ recentChargeTimes: [T0, T0, T0, T0, T0] }), ch({ recentChargeTimes: [T0, T0, T0, T0] }), ch({ recentChargeTimes: 'x' }), ch({ amount: 300, category: 'x' })];
for (const [mk, m] of Object.entries(M)) for (const [i, c] of charges.entries()) {
  if (mk !== 'base' && i > 8) continue;
  await run('authorizeChargeCore', `${mk}/${i}`, authorize, [m, J(c), m.grant]);
}
const budgets: any[] = [{ B: 1000, tau: T0, asOf: T0 }, { B: 40, tau: T0, asOf: T0 }, { B: 50, tau: T0, asOf: T0 }, { B: 0, tau: T0, asOf: T0 }, { B: 5000, tau: T0, asOf: T0 }, { B: 49.5, tau: T0, asOf: T0 },
  { B: 1000, tau: T0 - 3_600_000 }, { B: 1000, tau: T0, asOf: T0 - 100_000 }, { B: 1000 }, {}, null];
for (const [i, b] of budgets.entries()) for (const [j, a] of [1, 50, 300, 999].entries())
  await run('authorizeChargeCore', `budget/${i}/${j}`, authorize, [{ ...M.base, budget: b }, ch({ amount: a }), M.base.grant]);
for (const [k, [m, c, g]] of Object.entries({
  nullGrant: [M.base, ch(), null], otherGrant: [M.base, ch(), M.minimal.grant], noTerms: [{ ...M.base, terms: undefined }, ch(), M.base.grant],
  capTerms: [{ ...M.base, terms: { ...M.base.terms, perTransactionCap: 9999 } }, ch(), M.base.grant], mandateNull: [null, ch(), M.base.grant],
}) as any) await run('authorizeChargeCore', `tamper/${k}`, authorize, [m, c, g]);

// bonds over a charge PCActn
const bond = (p: any, opts: any, seed64: string) => P.openChargeBond(p, opts, new Uint8Array(Buffer.from(seed64, 'base64url')));
const mk = (c: any, over: any = {}) => J(P.chargeToPCActn(M.base, c, { signerSecret: sk.agent, aud: 'inst_1', counter: 3, now: T0 + 500, ...over }).pcactn);
const pcs: any[] = [mk(ch()), mk(ch({ amount: 500 })), mk(ch({ merchant: 'aws', amount: 7 }))];
const irr = J(pcs[0]); irr.action.reversibility_class = 'irreversible';
const noRc = J(pcs[0]); delete noRc.action.reversibility_class;
const optSets: any[] = [
  { bondRef: 'b1', claimedR: 0.1, serverNow: T0 + 1000 }, { bondRef: 'b1', claimedR: 0, serverNow: T0 }, { bondRef: 'b2', claimedR: 1, serverNow: T0, challengeWindowMs: 60_000 },
  { bondRef: 'b', claimedR: 0.25, serverNow: T0, issuedAt: T0 + 4000, challengeWindowMs: 1000 }, { bondRef: 'b', claimedR: 0.25, serverNow: T0, issuedAt: T0 + 5001 },
  { bondRef: 'b', claimedR: 0.25, serverNow: T0, challengeWindowMs: 999 }, { bondRef: 'b', claimedR: 0.25, serverNow: T0, challengeWindowMs: 86_400_000 }, { bondRef: 'b', claimedR: 0.25, serverNow: T0, challengeWindowMs: 86_400_001 },
  { bondRef: 'b', claimedR: 0.333333333333, serverNow: T0 }, { bondRef: '', claimedR: 0.1, serverNow: T0 }, { bondRef: 'é', claimedR: 0.1e-5, serverNow: T0, challengeWindowMs: 1.5 },
];
for (const [i, p] of [...pcs, irr, noRc].entries()) for (const [j, op] of optSets.entries()) await run('openChargeBond', `${i}/${j}`, bond, [p, op, seedB64]);
console.log('cases', o.cases.length);
refWrite(o, 'payments-java-extra');
