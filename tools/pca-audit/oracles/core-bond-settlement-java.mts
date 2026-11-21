// Oracle: bond settlement (bond-settlement.ts, bond-store.ts StoreBondLedger, optimistic.ts verifyClaim / verifyFraudProof / adjudicateDispute),
// TS reference. Written for the Java lane (BondSettlement, BondSettlementPlanner, OptimisticAdjudication, StoreBondLedger); reusable by any native.
// Ed25519 only (the deterministic suite): ML-DSA settlement records are covered by verifySettlement vectors (TS-signed, pinned).
// Deterministic: keys from seed(label), fixed clock T0, no randomness.
//
// PORTING (fn(args) -> native entry point, comparison rule; every result compared by JSON value)
//   computeSlashSplit(amount, policy, dest)        -> {amount, challengerReward, victimCompensation, treasuryRemainder, challengerAccount?, victimAccount, treasuryAccount}
//   quantizeUp(x) / toMicros(x) / exactAdd(a,b,sign)  -> number; toMicros returns {"$bigint": decimal} or null
//   applyBondMoves(balances{acct:n}, moves)        -> {acct: balance} for the accounts the moves touch
//   bondAmount(policy, exposure)                   -> number (policy {floor,k,curve?}; throws on a bad curve)
//   settlementEvidenceDigest(claim, verdict) / revocationEvidenceDigest(claim, capId) / disputeEvidenceDigest(claim, verdict) -> b64u digest
//   verifySettlement(record, guardianPub, pin|null) with pin = {pqPins: {ed25519 b64u: pq_pk b64u}} -> boolean;  settlementRecordDigest(record), settlementCommit(salt, record), verifySettlementCommit(commit, salt, record)
//   verifyClaim(claim, pcactn, signerPub, serverNow, windowPolicy|null) -> {ok, reason?}
//   verifyFraudProof(claim, proof, grant, snapshot)  -> {fraudulent, slashBondRef?, reason}
//   adjudicateDispute(claim, dispute, grant, snapshot, oracleTable|null, rMargin|null) -> DisputeVerdict; the oracle resolves table[input] (absent: undefined)
//   ledger(fixtures, cfg, ops) -> one result per op over a fresh StoreBondLedger on a memory store. Strings "@name" anywhere in an op are replaced by fixtures[name].
//     cfg {epoch?, escrow?, bondPolicy?, splitPolicy?, windowMs?{min,max,skew,default}}; guardian seed "bond/guardian"; clock starts at T0.
//     ops: ["clock",v|null] ["deposit",acct,n] ["balance",acct] ["status",id] ["bond",id] ["challenge",id] ["pub"]
//          ["openClaim",{claim,pcactn,signerPublic,amount,depositor,exposure?}] ["openBond",{claimId,amount,depositor,exposure?}]
//          ["release",id] ["releaseUnreg",id] ["slash",params] ["slashDispute",params] ["slashRevoke",params] ["slashCounter",params]
//          (a params.oracleTable object becomes the objective oracle) ["kvSet",raw] ["kvGet"]
//     an op that throws records {"$err": code} (BondStoreError code, "RangeError", else "Error").
import { Oracle, refWrite, rng, seed, jsonOut } from './lib.mjs';
import * as PCA0 from '@atlasauth/pca';

const P: any = (PCA0 as any).default ?? PCA0;
const { mintGrant, publicKeyOf, encodeKey, decide, DEFAULT_RISK_POLICY, mlDsa65Keygen, encodeMlDsaPublicKey } = P;
const { createMemoryDurableKv } = await import('../../../packages/pca/src/durable-state.ts');
const S: any = await import('../../../packages/pca/src/bond-settlement.ts');
const B: any = await import('../../../packages/pca/src/bond-store.ts');
const O: any = await import('../../../packages/pca/src/optimistic.ts');

const o = new Oracle('core-bond-settlement-java', 'tools/pca-audit/oracles/core-bond-settlement-java.mts', 'TS-reference oracle for bond settlement (planner, store ledger, claim / fraud-proof / dispute verdicts).');
const T0 = 1_800_000_000_000;
const key = (l: string) => { const sk = seed('bond/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const GUARD = key('guardian'), AG = key('agent'), PR = key('principal');
const J = (x: any) => JSON.parse(JSON.stringify(x));

// ---------------------------------------------------------------- fixtures
const preds = [{ verb: 'charge', resource: 'merchant:*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }, { verb: 'read', resource: '*' }];
const GRANT = J(mintGrant({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, goal: 'pay', salt: 'c2FsdC1zYWx0LXNhbHQ', envelope: { predicates: preds, caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant);
const GRANT_OTHER = J(mintGrant({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, goal: 'pay2', salt: 'c2FsdC1zYWx0LXNhbHQ', envelope: { predicates: preds, caveats: [{ type: 'max_blast_radius', max: 0.3 }], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant);
const act = (amount: number, rc?: string) => ({ action: { verb: 'charge', resource: 'merchant:m1', params: { amount }, ...(rc ? { reversibility_class: rc } : {}) } });
const LOW = { semanticDistance: 0.2, reversibility: 0.9, blastRadius: 0.1, taint: 0, confidence: 0.9, age: 0 };
const HIGH = { semanticDistance: 0.9, reversibility: 0.1, blastRadius: 0.9, taint: 0.5, confidence: 0.3, age: 0.5 };
const snap = (a: any, risk: any = LOW) => ({ now: T0, action: a, risk, budget: { B: 1, tau: T0 } });
const SNAPS: Record<string, any> = {
  ok: snap(act(10, 'reversible')), deny: snap(act(500, 'reversible')), irr: snap(act(10, 'irreversible')), high: snap(act(10, 'reversible'), HIGH),
  mid: snap(act(10, 'reversible'), { ...LOW, blastRadius: 0.5, semanticDistance: 0.5 }), cc: { ...snap(act(10, 'reversible')), caveatContext: { reversibilityClass: 'reversible', blastRadius: 0.1 } },
  norisk: { now: T0, action: act(10, 'reversible'), budget: { B: 1, tau: T0 } },
};
const decOf = (s: any, g: any = GRANT) => decide({ ...s, grant: g });
const R = (s: string) => decOf(SNAPS[s]).r;
const pcOf = (name: string, s: string) => J({ id: name, ...SNAPS[s === 'irr' ? 'ok' : s].action }); // the claimed action looks reversible; the server-held snapshot says otherwise
const mkClaim = (ref: string, pc: any, claimedR: number, extra: any = {}) => J(O.openOptimistic(pc, { bondRef: ref, claimedR, challengeWindowMs: extra.window ?? 60_000, issuedAt: extra.issuedAt, serverNow: extra.serverNow ?? T0 }, AG.sk));

const fx: Record<string, any> = { grant: GRANT, grantOther: GRANT_OTHER };
for (const [n, s] of Object.entries(SNAPS)) fx['snap_' + n] = J(s);
const claimSpecs: Array<[string, string, number | ((r: number) => number), any?]> = [
  ['ok', 'ok', (r) => r], ['low', 'ok', () => 0], ['deny', 'deny', (r) => r], ['irr', 'irr', (r) => r], ['high', 'high', (r) => r], ['mid', 'mid', (r) => r], ['mid-low', 'mid', (r) => r / 2],
  ['cc', 'cc', (r) => r], ['norisk', 'norisk', (r) => r], ['ok-hi', 'ok', (r) => r + 0.5],
];
const claimR: Record<string, number> = {};
for (const [n, s, rf, extra] of claimSpecs) {
  const r = R(s);
  const cr = typeof rf === 'function' ? rf(r) : rf;
  claimR[n] = cr;
  fx['pc_' + n] = pcOf(n, s);
  fx['claim_' + n] = mkClaim('b-' + n, fx['pc_' + n], cr, extra);
}
// claim variants that fail verification
fx.claim_short = mkClaim('b-short', fx.pc_ok, claimR.ok, { window: 5000 }); // under the 30 s floor, over the hard minimum
fx.claim_tiny = mkClaim('b-tiny', fx.pc_ok, claimR.ok, { window: 1000 });
fx.claim_long = mkClaim('b-long', fx.pc_ok, claimR.ok, { window: 3_600_000 });
fx.claim_skew = mkClaim('b-skew', fx.pc_ok, claimR.ok, { issuedAt: T0 + 4000 });
fx.claim_badsig = { ...fx.claim_ok, bond_ref: 'b-badsig' };
fx.claim_irrclass = { ...fx.claim_ok, bond_ref: 'b-irrc', reversibility_class: 'irreversible' };
fx.claim_noref = (() => { const c = { ...fx.claim_ok }; delete (c as any).bond_ref; return c; })();
fx.claim_emptyref = { ...fx.claim_ok, bond_ref: '' };
fx.claim_nan = { ...fx.claim_ok, claimed_r: 'x', bond_ref: 'b-nan' };
for (const v of ['short', 'tiny', 'long', 'skew', 'badsig', 'irrclass', 'noref', 'emptyref', 'nan']) fx['pc_' + v] = fx.pc_ok;
// proofs
const fileProof = (c: string, p: string, s: string, extra: any = {}) => J(O.fileFraudProof({ claim: fx['claim_' + c], pcactn: fx['pc_' + p], grant: GRANT, openSnapshot: SNAPS[s], ...extra }));
for (const n of ['low', 'deny', 'irr', 'high', 'mid-low', 'ok-hi']) fx['proof_' + n] = fileProof(n, n, n.replace('-low', '').replace('-hi', ''));
fx['proof_low'] = fileProof('low', 'low', 'ok');
fx['proof_ok-hi'] = fileProof('ok-hi', 'ok-hi', 'ok');
const manualProof = (c: string, s: string, extra: any = {}) => {
  const d = decOf(SNAPS[s]);
  const cl = fx['claim_' + c];
  return J({ pcactn_digest: cl.pcactn_digest, bond_ref: cl.bond_ref, claimed_r: cl.claimed_r, kind: 'risk-understated', decision: { releaseGuardianShare: d.releaseGuardianShare, r: d.r, optimisticAllowed: d.requiredThreshold.optimisticAllowed }, evidence: {}, r_margin: 1e-9, reason: 'x', ...extra });
};
fx.proof_honest = manualProof('ok', 'ok');
fx.proof_mismatch = manualProof('low', 'ok', { decision: { releaseGuardianShare: true, r: 0.999, optimisticAllowed: true } });
fx.proof_wrongbond = { ...fx.proof_low, bond_ref: 'someone-else' };
fx.proof_wrongdigest = { ...fx.proof_low, pcactn_digest: 'AAAA' };
fx.proof_bigmargin = { ...fx.proof_low, r_margin: 10 };
fx.proof_negmargin = { ...fx.proof_low, r_margin: -5 };
fx.proof_nomargin = (() => { const p = { ...fx.proof_low }; delete (p as any).r_margin; return p; })();
fx.proof_nodecision = (() => { const p = { ...fx.proof_low }; delete (p as any).decision; return p; })();
fx.proof_flipdec = { ...fx.proof_low, decision: { ...fx.proof_low.decision, releaseGuardianShare: false } };
fx.proof_flipopt = { ...fx.proof_low, decision: { ...fx.proof_low.decision, optimisticAllowed: !fx.proof_low.decision.optimisticAllowed } };
// disputes
const disp = (c: string, input: string, extra: any = {}) => ({ pcactn_digest: fx['claim_' + c].pcactn_digest, bond_ref: fx['claim_' + c].bond_ref, input, ...extra });
for (const n of ['ok', 'low', 'mid', 'cc']) {
  for (const i of ['blastRadius', 'semanticDistance', 'reversibility', 'reversibility_class']) fx[`disp_${n}_${i}`] = disp(n, i, i === 'reversibility_class' ? { asserted_class: 'irreversible' } : { asserted_value: 0.9 });
}
fx.disp_badinput = disp('ok', 'nonsense');
fx.disp_wrongbond = { ...fx.disp_ok_blastRadius, bond_ref: 'x' };
fx.disp_wrongdigest = { ...fx.disp_ok_blastRadius, pcactn_digest: 'x' };
const ORAC: Record<string, any> = {
  fraudBlast: { blastRadius: { input: 'blastRadius', value: 0.95, valid: true } },
  fraudSem: { semanticDistance: { input: 'semanticDistance', value: 1, valid: true } },
  fraudRev: { reversibility: { input: 'reversibility', value: 0, valid: true } },
  fraudClass: { reversibility_class: { input: 'reversibility_class', class: 'irreversible', valid: true } },
  upholdBlast: { blastRadius: { input: 'blastRadius', value: 0.1, valid: true } },
  upholdClass: { reversibility_class: { input: 'reversibility_class', class: 'reversible', valid: true } },
  upholdSem: { semanticDistance: { input: 'semanticDistance', value: 0.2, valid: true } },
  invalid: { blastRadius: { input: 'blastRadius', value: 0.95, valid: false, reason: 'no registry' } },
  invalidNoReason: { blastRadius: { input: 'blastRadius', valid: false } },
  wrongInput: { blastRadius: { input: 'semanticDistance', value: 0.95, valid: true } },
  noValue: { blastRadius: { input: 'blastRadius', valid: true } },
  nanValue: { blastRadius: { input: 'blastRadius', value: 'high', valid: true } },
  emptyClass: { reversibility_class: { input: 'reversibility_class', class: '', valid: true } },
  noClass: { reversibility_class: { input: 'reversibility_class', valid: true } },
  missing: {},
  validTruthy: { blastRadius: { input: 'blastRadius', value: 0.95, valid: 1 } },
  classOnNumeric: { blastRadius: { input: 'blastRadius', class: 'x', value: 0.95, valid: true } },
};
const oracleOf = (t: any) => (t ? { resolve: (input: string) => t[input] } : undefined);

// ---------------------------------------------------------------- pure functions
const sp = (c: number, v: number) => ({ challengerBps: c, victimBps: v });
const AMOUNTS = [1, 2, 3, 7, 10, 40, 100, 1000, 0.000001, 0.000003, 0.5, 1.5, 12.345678, 33.333333, 99999999.999999, 0.1 + 0.2, 27.500000000000004, 1e9, 1e15, 1e15 + 2, 3e20, 2 ** 53, 0.0000005, 1.23456789, 123456789.123456, 4.5e-7, 0.999999, 999999999999999.9];
const POLICIES = [sp(5000, 4000), sp(0, 0), sp(10000, 0), sp(0, 10000), sp(3333, 3333), sp(1, 1), sp(10000, 1), sp(2500, 2500), sp(5000.5, 0), sp(-1, 0), sp(0, 10001), sp(6000, 5000), { challengerBps: 5000 }, {}, sp(9999, 1)];
const DESTS = [{ challengerAccount: 'chal', victimAccount: 'pool', treasuryAccount: 'treasury' }, { challengerAccount: null, victimAccount: 'pool', treasuryAccount: 'treasury' }, { victimAccount: 'pool', treasuryAccount: 'treasury' },
  { challengerAccount: 'chal', victimAccount: '', treasuryAccount: 'treasury' }, { challengerAccount: 'chal', victimAccount: 'pool', treasuryAccount: '' }, { challengerAccount: 'chal', victimAccount: 'pool' }];
let n = 0;
for (const a of AMOUNTS) for (const [pi, p] of POLICIES.slice(0, 5).entries()) await o.run('computeSlashSplit', `c${n++}/a${a}/p${pi}`, S.computeSlashSplit, [a, p, DESTS[0]]);
for (const a of [100, 12.345678, 0.5, 1e15 + 2]) for (const p of POLICIES.slice(5)) await o.run('computeSlashSplit', `c${n++}/pol/${a}/${JSON.stringify(p)}`, S.computeSlashSplit, [a, p, DESTS[0]]);
for (const a of [100, 12.345678, 3e20]) for (const [di, d] of DESTS.entries()) await o.run('computeSlashSplit', `c${n++}/dest/${a}/${di}`, S.computeSlashSplit, [a, POLICIES[0], d]);
for (const a of [0, -1, 1e-300]) await o.run('computeSlashSplit', `c${n++}/bad/${a}`, S.computeSlashSplit, [a, POLICIES[0], DESTS[0]]);
const NUMS = [0, 1, 0.5, 1e-7, 4.9999e-7, 5e-7, 1.0000004, 12.3456789, 27.500000000000004, 0.1 + 0.2, 1e9, 1e15, 1e15 + 1, 3e20, -1, 0.000001, 0.0000015, 2.675, 1.005, 123456.7890123, 1e21, 0.3];
for (const x of NUMS) { await o.run('quantizeUp', `q/${x}`, S.quantizeUp, [x]); await o.run('toMicros', `m/${x}`, (v: number) => { const r = S.toMicros(v); return r === null ? null : { $bigint: r.toString() }; }, [x]); }
for (const a of [0, 1, 0.1, 0.2, 12.345678, 1e9, 1e15, 3e20, 0.0000005, 5]) for (const b of [0, 0.2, 0.1, 5, 12.345678, 0.0000005, 1e15]) for (const sg of [1, -1]) await o.run('exactAdd', `a/${a}/${b}/${sg}`, S.exactAdd, [a, b, sg]);
const mvs = (...m: any[]) => m.map(([account, op, amount]) => ({ account, op, amount }));
const applyCases: Array<[string, any, any[]]> = [
  ['basic', { a: 10 }, mvs(['a', 'debit', 4], ['b', 'credit', 4])], ['overdraft', { a: 1 }, mvs(['a', 'debit', 4])], ['exact', { a: 0.3 }, mvs(['a', 'debit', 0.1], ['a', 'debit', 0.2])],
  ['order', { a: 1 }, mvs(['b', 'credit', 5], ['b', 'debit', 5], ['a', 'debit', 1])], ['negamt', { a: 5 }, mvs(['a', 'debit', -1])], ['strAmt', { a: 5 }, mvs(['a', 'debit', '1'])],
  ['empty', {}, []], ['sub-micro', { a: 1 }, mvs(['a', 'credit', 0.0000005])], ['nan-ish', { a: 5 }, mvs(['a', 'credit', null])], ['big', { a: 1e15 }, mvs(['a', 'credit', 1e15], ['a', 'debit', 0.5])],
];
for (const [name, bal, moves] of applyCases) await o.run('applyBondMoves', name, (b: any, m: any) => Object.fromEntries(S.applyBondMoves((a: string) => b[a] ?? 0, m)), [bal, moves]);
const BP = (extra: any = {}) => ({ floor: 1, k: 1, ...extra });
const policiesBA: any[] = [BP(), BP({ floor: 10, k: 2 }), BP({ k: 0.5 }), BP({ curve: { kind: 'linear' } }), BP({ curve: { kind: 'power', gamma: 1 } }), BP({ curve: { kind: 'power', gamma: 2 } }), BP({ curve: { kind: 'power', gamma: 1.5 } }),
  BP({ curve: { kind: 'power', gamma: 0.5 } }), BP({ curve: { kind: 'power' } }), BP({ curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 1 }, { upTo: 100, marginalK: 2 }, { upTo: 1e9, marginalK: 5 }] } }),
  BP({ curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 2 }, { upTo: 100, marginalK: 1 }] } }), BP({ curve: { kind: 'piecewise', tiers: [] } }), BP({ curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 1 }, { upTo: 5, marginalK: 2 }] } }),
  BP({ curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: -1 }] } }), BP({ curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 1 }] } }), BP({ curve: { kind: 'piecewise' } }), BP({ curve: { kind: 'zigzag' } }), BP({ k: 0.1 + 0.2 })];
for (const [pi, p] of policiesBA.entries()) for (const e of [0, 1, 5, 10, 10.5, 50, 100, 250.75, 1e6, 1e12, -3, 0.0000001, 33.333333]) await o.run('bondAmount', `ba/${pi}/${e}`, S.bondAmount, [p, e]);
// records and digests: planner output over deterministic transitions
const planner = new S.BondSettlementPlanner({ guardianSecret: GUARD.sk });
const plannerEp = new S.BondSettlementPlanner({ guardianSecret: GUARD.sk, guardianEpoch: 3 });
const mlKey = mlDsa65Keygen(new Uint8Array(32).fill(5));
const plannerH = new S.BondSettlementPlanner({ guardianSecret: GUARD.sk, suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: mlKey } });
const plannerM = new S.BondSettlementPlanner({ guardianSecret: GUARD.sk, suite: { alg: 'ml-dsa-65', mlDsa: mlKey } });
const emptyView = (bonds: any = {}, bal: any = { alice: 1000 }) => ({ bond: (id: string) => bonds[id], balanceOf: (a: string) => bal[a] ?? 0, openTotals: () => ({ count: 0, sum: 0 }) });
const openRec = (p: any, ref: string, amount: number) => J(p.planOpen(emptyView(), { claimId: ref, amount, depositor: 'alice', now: T0 }).record);
const REC: Record<string, any> = {};
REC.open = openRec(planner, 'r1', 40);
REC.openEp = openRec(plannerEp, 'r1', 40);
REC.openH = openRec(plannerH, 'r1', 40);
REC.openM = openRec(plannerM, 'r1', 40);
REC.release = J(planner.planRelease(emptyView({ r1: { claimId: 'r1', amount: 40, depositor: 'alice', status: 'open' } }), { claimId: 'r1', now: T0 + 1 }).record);
const slashRec = (p: any, extra: any = {}) => J(p.planSlashOnRevocation(emptyView({ [fx.claim_ok.bond_ref]: { claimId: fx.claim_ok.bond_ref, amount: 40, depositor: 'alice', status: 'open' } }), { claimId: fx.claim_ok.bond_ref, claim: fx.claim_ok, revokedCapId: 'cap-1', treasury: 'treasury', now: T0 + 2, ...extra }).record);
REC.slash = slashRec(planner, { challengerAccount: 'chal' });
REC.slashAnon = slashRec(planner);
REC.slashEp = slashRec(plannerEp, { challengerAccount: 'chal', compensationAccount: 'pool-x' });
REC.slashH = slashRec(plannerH, { challengerAccount: 'chal' });
REC.slashM = slashRec(plannerM, { challengerAccount: 'chal' });
const verdictLow = O.verifyFraudProof(fx.claim_low, fx.proof_low, GRANT, SNAPS.ok);
const verdictDeny = O.verifyFraudProof(fx.claim_deny, fx.proof_deny, GRANT, SNAPS.deny);
const dverdict = O.adjudicateDispute({ claim: fx.claim_ok, dispute: fx.disp_ok_blastRadius, grant: GRANT, openSnapshot: SNAPS.ok, oracle: oracleOf(ORAC.fraudBlast) });
const pins = { [GUARD.pk]: encodeMlDsaPublicKey(mlKey.publicKey) };
const guardPk = GUARD.pk;
const tamper = (r: any, f: any) => ({ ...r, ...f });
const VR: Array<[string, any, any, any]> = [];
for (const [k, r] of Object.entries(REC)) {
  const pq = k.endsWith('H') || k.endsWith('M');
  VR.push([k, r, guardPk, pq ? { pqPins: pins } : null]);
  if (pq) VR.push([k + '/nopin', r, guardPk, null], [k + '/wrongpin', r, guardPk, { pqPins: { [GUARD.pk]: encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(6)).publicKey) } }]);
  VR.push([k + '/wrongkey', r, AG.pk, null], [k + '/amount', tamper(r, { amount: 41 }), guardPk, pq ? { pqPins: pins } : null], [k + '/nosig', (() => { const c = { ...r }; delete c.sig; return c; })(), guardPk, pq ? { pqPins: pins } : null],
    [k + '/sigtype', tamper(r, { sig: 5 }), guardPk, pq ? { pqPins: pins } : null], [k + '/at', tamper(r, { at: r.at + 1 }), guardPk, pq ? { pqPins: pins } : null]);
}
VR.push(['badalg', tamper(REC.open, { alg: 'rot13' }), guardPk, null], ['algnull', tamper(REC.open, { alg: null }), guardPk, null], ['algstr-ed', tamper(REC.open, { alg: 'ed25519' }), guardPk, null],
  ['null', null, guardPk, null], ['arr', [], guardPk, null], ['str', 'x', guardPk, null], ['epoch-strip', (() => { const c = { ...REC.openEp }; delete c.guardian_epoch; return c; })(), guardPk, null],
  ['extra', tamper(REC.open, { extra: 1 }), guardPk, null], ['split-tamper', tamper(REC.slash, { split: { ...REC.slash.split, challengerReward: 1 } }), guardPk, null]);
for (const [name, r, pk, pn] of VR) await o.run('verifySettlement', name, S.verifySettlement, [r, pk, pn]);
for (const [name, r] of Object.entries(REC)) {
  await o.run('settlementRecordDigest', name, S.settlementRecordDigest, [r]);
  const commit = S.settlementCommit('salt-1', r);
  await o.run('settlementCommit', name, S.settlementCommit, ['salt-1', r]);
  await o.run('verifySettlementCommit', name + '/ok', S.verifySettlementCommit, [commit, 'salt-1', r]);
  await o.run('verifySettlementCommit', name + '/wrongsalt', S.verifySettlementCommit, [commit, 'salt-2', r]);
  await o.run('verifySettlementCommit', name + '/wrongrec', S.verifySettlementCommit, [commit, 'salt-1', REC.open]);
}
await o.run('settlementCommit', 'empty-salt', S.settlementCommit, ['', REC.open]);
await o.run('verifySettlementCommit', 'empty-salt', S.verifySettlementCommit, ['x', '', REC.open]);
await o.run('verifySettlementCommit', 'garbage', S.verifySettlementCommit, [5, 'salt-1', REC.open]);
// evidence digests
for (const cn of ['ok', 'low', 'deny', 'norisk']) {
  await o.run('settlementEvidenceDigest', `${cn}/low`, S.settlementEvidenceDigest, [fx['claim_' + cn], J(verdictLow)]);
  await o.run('settlementEvidenceDigest', `${cn}/deny`, S.settlementEvidenceDigest, [fx['claim_' + cn], J(verdictDeny)]);
  await o.run('settlementEvidenceDigest', `${cn}/none`, S.settlementEvidenceDigest, [fx['claim_' + cn], { fraudulent: false, reason: 'r' }]);
  await o.run('revocationEvidenceDigest', cn, S.revocationEvidenceDigest, [fx['claim_' + cn], 'cap-1']);
  await o.run('disputeEvidenceDigest', cn, S.disputeEvidenceDigest, [fx['claim_' + cn], J(dverdict)]);
}
await o.run('disputeEvidenceDigest', 'noval', S.disputeEvidenceDigest, [fx.claim_ok, { outcome: 'indeterminate', input: 'blastRadius', reason: 'x' }]);
await o.run('revocationEvidenceDigest', 'other-cap', S.revocationEvidenceDigest, [fx.claim_ok, 'cap-2']);
// verifyClaim
const WP = { minWindowMs: 1000, maxWindowMs: 86_400_000, maxSkewMs: 5000, defaultWindowMs: 300_000 };
const vc = (name: string, claim: any, pc: any, pub: string, now: number, wp: any = null) => o.run('verifyClaim', name, (c: any, p: any, k: string, t: number, w: any) => O.verifyClaim(c, p, k, w ? { serverNow: t, windowPolicy: w } : { serverNow: t }), [claim, pc, pub, now, wp]);
for (const cn of ['ok', 'low', 'deny', 'irr', 'short', 'tiny', 'long', 'skew', 'badsig', 'irrclass', 'noref', 'emptyref', 'nan', 'norisk']) {
  const pcn = cn.startsWith('short') || cn === 'tiny' || cn === 'long' || cn === 'skew' || cn === 'badsig' || cn === 'irrclass' || cn === 'noref' || cn === 'emptyref' || cn === 'nan' ? 'ok' : cn;
  for (const now of [T0, T0 + 4999, T0 + 5001, T0 - 6000, T0 + 61_000]) await vc(`${cn}/${now - T0}`, fx['claim_' + cn], fx['pc_' + pcn], AG.pk, now);
  await vc(`${cn}/wrongpc`, fx['claim_' + cn], fx.pc_deny, AG.pk, T0);
  await vc(`${cn}/wrongkey`, fx['claim_' + cn], fx['pc_' + pcn], GUARD.pk, T0);
  await vc(`${cn}/strict`, fx['claim_' + cn], fx['pc_' + pcn], AG.pk, T0, { ...WP, minWindowMs: 20_000, maxWindowMs: 120_000, maxSkewMs: 1 });
}
for (const [name, c] of [['null', null], ['str', 'x'], ['num', 5], ['arr', []], ['obj', {}], ['bool', true]] as any[]) await vc('shape/' + name, c, fx.pc_ok, AG.pk, T0);
// verifyFraudProof
const vf = (name: string, claim: any, proof: any, grant: any, snapshot: any) => o.run('verifyFraudProof', name, O.verifyFraudProof, [claim, proof, grant, snapshot]);
const PROOFS = ['low', 'deny', 'irr', 'high', 'mid-low', 'ok-hi', 'honest', 'mismatch', 'wrongbond', 'wrongdigest', 'bigmargin', 'negmargin', 'nomargin', 'nodecision', 'flipdec', 'flipopt'];
const CLAIMS_FOR = ['ok', 'low', 'deny', 'irr', 'high', 'mid-low', 'ok-hi'];
const SNAP_FOR: Record<string, string> = { ok: 'ok', low: 'ok', deny: 'deny', irr: 'irr', high: 'high', 'mid-low': 'mid', 'ok-hi': 'ok' };
for (const pn of PROOFS) for (const cn of CLAIMS_FOR) await vf(`${pn}/${cn}`, fx['claim_' + cn], fx['proof_' + pn], GRANT, SNAPS[SNAP_FOR[cn]]);
for (const sn of Object.keys(SNAPS)) for (const cn of ['low', 'deny']) { await vf(`snap/${sn}/${cn}`, fx['claim_' + cn], fx['proof_' + cn], GRANT, SNAPS[sn]); await vf(`other-grant/${sn}/${cn}`, fx['claim_' + cn], fx['proof_' + cn], GRANT_OTHER, SNAPS[sn]); }
for (const [name, p] of [['null', null], ['str', 'x'], ['num', 5], ['arr', []], ['obj', {}]] as any[]) await vf('proofshape/' + name, fx.claim_low, p, GRANT, SNAPS.ok);
for (const [name, s] of [['null', null], ['str', 'x'], ['num', 0], ['arr', []], ['obj', {}]] as any[]) await vf('snapshape/' + name, fx.claim_low, fx.proof_low, GRANT, s);
await vf('nogrant', fx.claim_low, fx.proof_low, null, SNAPS.ok);
await vf('badgrant', fx.claim_low, fx.proof_low, { ...GRANT, sig: 'AAAA' }, SNAPS.ok);
// adjudicateDispute
const ad = (name: string, claim: any, d: any, grant: any, snapshot: any, table: any, rm: any = null) => o.run('adjudicateDispute', name, (c: any, dd: any, g: any, s: any, t: any, r: any) => O.adjudicateDispute({ claim: c, dispute: dd, grant: g, openSnapshot: s, oracle: oracleOf(t), rMargin: r ?? undefined }), [claim, d, grant, snapshot, table, rm]);
for (const [on, t] of Object.entries(ORAC)) for (const cn of ['ok', 'low', 'mid', 'cc']) for (const inp of ['blastRadius', 'semanticDistance', 'reversibility', 'reversibility_class']) {
  const sn = cn === 'low' ? 'ok' : cn;
  await ad(`${on}/${cn}/${inp}`, fx['claim_' + cn], fx[`disp_${cn}_${inp}`], GRANT, SNAPS[sn], t);
}
for (const rm of [0, 1e-9, 0.5, 1, -1]) for (const on of ['upholdBlast', 'fraudBlast']) await ad(`margin/${on}/${rm}`, fx.claim_ok, fx.disp_ok_blastRadius, GRANT, SNAPS.ok, ORAC[on], rm);
await ad('grant-other', fx.claim_ok, fx.disp_ok_blastRadius, GRANT_OTHER, SNAPS.ok, ORAC.upholdBlast);
await ad('norisk', fx.claim_norisk, disp('norisk', 'blastRadius'), GRANT, SNAPS.norisk, ORAC.fraudBlast);
await ad('norisk-up', fx.claim_norisk, disp('norisk', 'blastRadius'), GRANT, SNAPS.norisk, ORAC.upholdBlast);
for (const [name, d] of [['badinput', fx.disp_badinput], ['wrongbond', fx.disp_wrongbond], ['wrongdigest', fx.disp_wrongdigest], ['null', null], ['str', 'x'], ['arr', []], ['noinput', {}]] as any[]) await ad('dshape/' + name, fx.claim_ok, d, GRANT, SNAPS.ok, ORAC.fraudBlast);
for (const [name, s] of [['null', null], ['str', 'x'], ['arr', []], ['obj', {}]] as any[]) await ad('sshape/' + name, fx.claim_ok, fx.disp_ok_blastRadius, GRANT, s, ORAC.fraudBlast);
await ad('nooracle', fx.claim_ok, fx.disp_ok_blastRadius, GRANT, SNAPS.ok, null);

// ---------------------------------------------------------------- store ledger sequences
const errName = (e: any): string => (typeof e?.code === 'string' ? e.code : e instanceof RangeError ? 'RangeError' : 'Error');
const resolve = (fxs: any, v: any): any => (typeof v === 'string' && v.startsWith('@') ? structuredClone(fxs[v.slice(1)]) : Array.isArray(v) ? v.map((x) => resolve(fxs, x)) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, resolve(fxs, x)])) : v);
async function ledgerRun(fxs: any, cfg: any, ops: any[]): Promise<any[]> {
  const kv = createMemoryDurableKv();
  const store = new B.KvBondStore(kv);
  let clock: any = T0;
  const wp = cfg.windowMs ? { minWindowMs: cfg.windowMs.min, maxWindowMs: cfg.windowMs.max, maxSkewMs: cfg.windowMs.skew, defaultWindowMs: cfg.windowMs.default } : undefined;
  const ledger = new B.StoreBondLedger({ store, guardianSecret: GUARD.sk, clock: () => clock, ...(cfg.epoch !== undefined ? { guardianEpoch: cfg.epoch } : {}), ...(cfg.escrow ? { escrowAccount: cfg.escrow } : {}), ...(cfg.bondPolicy ? { bondPolicy: cfg.bondPolicy } : {}), ...(cfg.splitPolicy ? { slashSplitPolicy: cfg.splitPolicy } : {}), ...(wp ? { windowPolicy: wp } : {}) });
  const out: any[] = [];
  const prm = (p: any) => { const q = resolve(fxs, p); if (q && q.oracleTable) { q.oracle = oracleOf(q.oracleTable); delete q.oracleTable; } return q; };
  for (const op of ops) {
    try {
      let v: any;
      switch (op[0]) {
        case 'clock': clock = op[1]; v = null; break;
        case 'deposit': v = await ledger.deposit(op[1], op[2]); break;
        case 'balance': v = await ledger.balanceOf(op[1]); break;
        case 'status': v = await ledger.bondStatus(op[1]); break;
        case 'bond': v = (await ledger.getBond(op[1])) ?? null; break;
        case 'challenge': v = await ledger.challengeStatus(op[1]); break;
        case 'pub': v = ledger.guardianPublicKey; break;
        case 'openClaim': v = await ledger.openClaim(prm(op[1])); break;
        case 'openBond': v = await ledger.openBond(prm(op[1])); break;
        case 'release': v = await ledger.release(op[1]); break;
        case 'releaseUnreg': v = await ledger.releaseUnregistered(op[1]); break;
        case 'slash': v = await ledger.slashBond(prm(op[1])); break;
        case 'slashDispute': v = await ledger.slashBondOnDispute(prm(op[1])); break;
        case 'slashRevoke': v = await ledger.slashBondOnRevocation(prm(op[1])); break;
        case 'slashCounter': v = await ledger.slashCounterBond(prm(op[1])); break;
        case 'kvSet': await kv.set('pca-bond-store/v1', op[1]); v = null; break;
        case 'kvGet': v = await kv.get('pca-bond-store/v1'); break;
        default: throw new Error('op');
      }
      out.push(jsonOut(v) ?? null);
    } catch (e) {
      out.push({ $err: errName(e) });
    }
  }
  return out;
}
const usedFx = (ops: any[]) => { const s = JSON.stringify(ops); const m: Record<string, any> = {}; for (const k of Object.keys(fx)) if (s.includes(`"@${k}"`)) m[k] = fx[k]; return m; };
const seqCases: Array<[string, any, any[]]> = [];
const seq = (name: string, cfg: any, ops: any[]) => seqCases.push([name, cfg, ops]);
const oc = (c: string, amount = 40, extra: any = {}) => ['openClaim', { claim: `@claim_${c}`, pcactn: `@pc_${c}`, signerPublic: AG.pk, amount, depositor: 'alice', ...extra }];
const sl = (c: string, p: string, extra: any = {}) => ['slash', { claimId: fx['claim_' + c].bond_ref, claim: `@claim_${c}`, fraudProof: `@proof_${p}`, grant: '@grant', openSnapshot: `@snap_${SNAP_FOR[c]}`, treasury: 'treasury', ...extra }];
const sd = (c: string, input: string, table: string, extra: any = {}) => ['slashDispute', { claimId: fx['claim_' + c].bond_ref, claim: `@claim_${c}`, dispute: `@disp_${c}_${input}`, grant: '@grant', openSnapshot: `@snap_${SNAP_FOR[c] ?? c}`, oracleTable: ORAC[table], treasury: 'treasury', ...extra }];
const sr = (c: string, extra: any = {}) => ['slashRevoke', { claimId: fx['claim_' + c].bond_ref, claim: `@claim_${c}`, revokedCapId: 'cap-1', treasury: 'treasury', ...extra }];
const dep = (a = 'alice', n = 1000) => ['deposit', a, n];
const T = (ms: number) => ['clock', T0 + ms];
const refOf = (c: string) => fx['claim_' + c].bond_ref;
seq('lifecycle', {}, [['pub'], ['status', 'b-ok'], ['bond', 'b-ok'], dep(), oc('ok'), ['balance', 'alice'], ['balance', 'escrow'], ['status', 'b-ok'], ['challenge', 'b-ok'], ['release', 'b-ok'], T(59_999), ['release', 'b-ok'], T(60_000), ['release', 'b-ok'], T(60_001), ['challenge', 'b-ok'], ['release', 'b-ok'], ['release', 'b-ok'], ['balance', 'alice'], ['balance', 'escrow'], ['status', 'b-ok'], ['bond', 'b-ok'], sl('low', 'low'), ['release', 'b-low']]);
seq('open-replay', {}, [dep(), oc('ok'), oc('ok'), oc('ok', 41), oc('ok', 40, { depositor: 'bob' }), dep('bob'), oc('ok', 40, { depositor: 'bob' }), ['balance', 'alice'], ['bond', 'b-ok'], ['kvGet']]);
seq('open-failures', {}, [dep(), oc('badsig'), oc('irrclass'), oc('noref'), oc('emptyref'), oc('nan'), oc('short'), oc('tiny'), oc('long'), oc('skew'), ['openClaim', { claim: '@claim_ok', pcactn: '@pc_deny', signerPublic: AG.pk, amount: 40, depositor: 'alice' }], ['openClaim', { claim: '@claim_ok', pcactn: '@pc_ok', signerPublic: GUARD.pk, amount: 40, depositor: 'alice' }], ['openClaim', { claim: null, pcactn: '@pc_ok', signerPublic: AG.pk, amount: 40, depositor: 'alice' }], ['status', 'b-ok'], ['balance', 'alice'], ['kvGet']]);
seq('skew-clock', {}, [dep(), T(4999), oc('ok'), T(-4999), oc('low'), T(10_000), oc('mid'), T(-20_000), oc('deny'), ['clock', null], oc('irr'), ['release', 'b-ok'], ['status', 'b-ok']]);
seq('window-policy', { windowMs: { min: 20_000, max: 120_000, skew: 100, default: 60_000 } }, [dep(), oc('ok'), oc('short'), oc('long'), oc('skew'), ['challenge', 'b-ok']]);
seq('window-floor-hard', { windowMs: { min: 1000, max: 86_400_000, skew: 5000, default: 300_000 } }, [dep(), oc('short'), oc('tiny'), oc('ok')]);
seq('balance-and-caps', { bondPolicy: { floor: 10, k: 2, maxOpenClaims: 2, maxOpenAmount: 100 } }, [dep('alice', 100), oc('ok', 5), oc('ok', 9.99), oc('ok', 10), oc('low', 10), oc('mid', 10), oc('deny', 95), ['release', 'b-ok'], T(61_000), ['release', 'b-ok'], ['release', 'b-ok'], oc('deny', 60), oc('high', 60), ['balance', 'alice'], ['balance', 'escrow']]);
seq('exposure', { bondPolicy: { floor: 1, k: 1, maxOpenClaims: 5, maxOpenAmount: 1e9, curve: { kind: 'power', gamma: 2 } } }, [dep('alice', 1e6), oc('ok', 50, { exposure: 10 }), oc('low', 100, { exposure: 10 }), oc('mid', 100.5, { exposure: 10 }), oc('deny', 1e5, { exposure: 300 }), ['balance', 'alice']]);
seq('exposure-pw', { bondPolicy: { floor: 2, k: 1.5, maxOpenClaims: 5, maxOpenAmount: 1e9, curve: { kind: 'piecewise', tiers: [{ upTo: 10, marginalK: 1 }, { upTo: 100, marginalK: 3 }] } } }, [dep('alice', 1e6), oc('ok', 14.9, { exposure: 10 }), oc('ok', 15, { exposure: 10 }), oc('low', 500, { exposure: 100 }), oc('mid', 600, { exposure: 200 })]);
seq('fraud-slash', {}, [dep(), oc('low'), ['challenge', 'b-low'], sl('low', 'low', { challengerAccount: 'chal' }), sl('low', 'low', { challengerAccount: 'chal' }), sl('low', 'low', { challengerAccount: 'other' }), sl('low', 'low'), ['release', 'b-low'], T(70_000), ['release', 'b-low'], ['status', 'b-low'], ['bond', 'b-low'], ['balance', 'chal'], ['balance', 'pca:pool:compensation'], ['balance', 'treasury'], ['balance', 'escrow'], ['balance', 'alice']]);
seq('fraud-anon', {}, [dep(), oc('low'), sl('low', 'low'), ['balance', 'treasury'], ['balance', 'chal'], ['balance', 'pca:pool:compensation'], ['bond', 'b-low']]);
seq('fraud-splitpolicy', { splitPolicy: { challengerBps: 3333, victimBps: 3333 }, escrow: 'vault', epoch: 7 }, [dep('alice', 100.123456), oc('low', 33.333333), sl('low', 'low', { challengerAccount: 'chal', compensationAccount: 'pool-9' }), ['balance', 'chal'], ['balance', 'pool-9'], ['balance', 'treasury'], ['balance', 'vault'], ['bond', 'b-low']]);
seq('fraud-splitoverride', {}, [dep(), oc('low', 33.333333), sl('low', 'low', { challengerAccount: 'chal', splitPolicy: { challengerBps: 10000, victimBps: 0 } }), ['balance', 'chal'], ['balance', 'treasury']]);
seq('fraud-splitbad', {}, [dep(), oc('low'), sl('low', 'low', { challengerAccount: 'chal', splitPolicy: { challengerBps: 9000, victimBps: 2000 } }), sl('low', 'low', { challengerAccount: 'chal', splitPolicy: { challengerBps: 1.5, victimBps: 0 } }), ['status', 'b-low']]);
seq('fraud-treasury-missing', {}, [dep(), oc('low'), sl('low', 'low', { treasury: '' }), sl('low', 'low', { treasury: null }), ['status', 'b-low']]);
seq('fraud-ref-mismatch', {}, [dep(), oc('low'), ['slash', { claimId: 'b-other', claim: '@claim_low', fraudProof: '@proof_low', grant: '@grant', openSnapshot: '@snap_ok', treasury: 'treasury' }], ['slash', { claimId: 'b-low', claim: '@claim_ok', fraudProof: '@proof_low', grant: '@grant', openSnapshot: '@snap_ok', treasury: 'treasury' }], ['status', 'b-low']]);
for (const [pn, cn] of [['deny', 'deny'], ['irr', 'irr'], ['high', 'high'], ['mid-low', 'mid-low'], ['ok-hi', 'ok-hi'], ['honest', 'ok'], ['mismatch', 'low'], ['bigmargin', 'low'], ['negmargin', 'low'], ['nomargin', 'low'], ['nodecision', 'low'], ['flipdec', 'low'], ['flipopt', 'low'], ['wrongbond', 'low'], ['wrongdigest', 'low']]) {
  seq('proof/' + pn, {}, [dep(), oc(cn), sl(cn, pn, { challengerAccount: 'chal' }), ['status', refOf(cn)], ['balance', 'chal'], ['balance', 'treasury'], ['bond', refOf(cn)]]);
}
seq('grant-wrong', {}, [dep(), oc('low'), ['slash', { claimId: 'b-low', claim: '@claim_low', fraudProof: '@proof_low', grant: '@grantOther', openSnapshot: '@snap_ok', treasury: 'treasury' }], ['slash', { claimId: 'b-low', claim: '@claim_low', fraudProof: '@proof_low', grant: null, openSnapshot: '@snap_ok', treasury: 'treasury' }], ['slash', { claimId: 'b-low', claim: '@claim_low', fraudProof: '@proof_low', grant: '@grant', openSnapshot: null, treasury: 'treasury' }], ['status', 'b-low']]);
seq('slash-window', {}, [dep(), oc('low'), T(60_000), sl('low', 'low'), T(60_001), sl('low', 'low'), ['status', 'b-low'], ['release', 'b-low'], ['status', 'b-low']]);
seq('slash-clock-back', {}, [dep(), oc('low'), T(100_000), ['release', 'b-low'], T(0), sl('low', 'low'), T(1_000_000), ['balance', 'alice']]);
seq('claim-mismatch', {}, [dep(), oc('low'), ['slash', { claimId: 'b-low', claim: { ...fx.claim_low, claimed_r: 0.5 }, fraudProof: '@proof_low', grant: '@grant', openSnapshot: '@snap_ok', treasury: 'treasury' }], sl('low', 'low'), ['status', 'b-low']]);
seq('unregistered', {}, [dep(), ['openBond', { claimId: 'b-low', amount: 10, depositor: 'alice' }], sl('low', 'low'), ['release', 'b-low'], ['releaseUnreg', 'b-low'], ['releaseUnreg', 'b-low'], ['status', 'b-low'], ['challenge', 'b-low'], oc('low'), ['balance', 'alice']]);
seq('releaseUnreg-registered', {}, [dep(), oc('ok'), ['releaseUnreg', 'b-ok'], T(70_000), ['releaseUnreg', 'b-ok'], ['release', 'b-ok'], ['releaseUnreg', 'nope'], ['release', 'nope']]);
seq('openBond', {}, [dep(), ['openBond', { claimId: 'cb1', amount: 10, depositor: 'alice' }], ['openBond', { claimId: 'cb1', amount: 10, depositor: 'alice' }], ['openBond', { claimId: 'cb1', amount: 11, depositor: 'alice' }], ['openBond', { claimId: 'cb2', amount: 0, depositor: 'alice' }], ['openBond', { claimId: 'cb2', amount: -1, depositor: 'alice' }], ['openBond', { claimId: '', amount: 5, depositor: 'alice' }], ['openBond', { claimId: 'cb3', amount: 5, depositor: '' }], ['openBond', { claimId: 'cb3', amount: 5000, depositor: 'alice' }], ['openBond', { claimId: 'cb3', amount: 0.0000004, depositor: 'alice' }], ['balance', 'alice'], ['bond', 'cb1']]);
seq('revocation', {}, [dep(), oc('ok'), sr('ok', { challengerAccount: 'chal' }), sr('ok', { challengerAccount: 'chal' }), sr('ok', { revokedCapId: 'cap-2' }), ['status', 'b-ok'], ['balance', 'chal'], ['bond', 'b-ok']]);
seq('revocation-late', {}, [dep(), oc('ok'), T(500_000), sr('ok'), ['status', 'b-ok']]);
seq('revocation-bad', {}, [dep(), oc('ok'), sr('ok', { revokedCapId: '' }), sr('ok', { revokedCapId: null }), sr('ok', { treasury: '' }), sr('low'), ['openBond', { claimId: 'zz', amount: 5, depositor: 'alice' }], ['slashRevoke', { claimId: 'zz', claim: '@claim_ok', revokedCapId: 'cap', treasury: 'treasury' }], ['slashRevoke', { claimId: 'b-ok', claim: '@claim_low', revokedCapId: 'cap', treasury: 'treasury' }], ['status', 'b-ok']]);
seq('revocation-after-release', {}, [dep(), oc('ok'), T(61_000), ['release', 'b-ok'], sr('ok'), ['status', 'b-ok']]);
seq('release-after-slash', {}, [dep(), oc('ok'), sr('ok'), ['release', 'b-ok'], T(61_000), ['release', 'b-ok'], sr('ok')]);
for (const [tn, cn, inp] of [['fraudBlast', 'ok', 'blastRadius'], ['fraudSem', 'ok', 'semanticDistance'], ['fraudRev', 'ok', 'reversibility'], ['fraudClass', 'ok', 'reversibility_class'], ['upholdBlast', 'ok', 'blastRadius'], ['upholdClass', 'ok', 'reversibility_class'],
  ['invalid', 'ok', 'blastRadius'], ['wrongInput', 'ok', 'blastRadius'], ['noValue', 'ok', 'blastRadius'], ['emptyClass', 'ok', 'reversibility_class'], ['fraudClass', 'cc', 'reversibility_class'], ['fraudBlast', 'cc', 'blastRadius'], ['fraudBlast', 'mid', 'blastRadius'], ['missing', 'ok', 'blastRadius']]) {
  seq(`dispute/${tn}/${cn}/${inp}`, {}, [dep(), oc(cn === 'cc' ? 'cc' : cn), sd(cn, inp, tn, { challengerAccount: 'chal' }), sd(cn, inp, tn, { challengerAccount: 'chal' }), ['status', refOf(cn)], ['balance', 'chal'], ['balance', 'treasury'], ['bond', refOf(cn)]]);
}
seq('dispute-window', {}, [dep(), oc('ok'), T(61_000), sd('ok', 'blastRadius', 'fraudBlast'), ['status', 'b-ok']]);
seq('dispute-margin', {}, [dep(), oc('ok'), sd('ok', 'blastRadius', 'upholdBlast', { rMargin: 1 }), sd('ok', 'blastRadius', 'fraudBlast', { rMargin: 5 }), sd('ok', 'blastRadius', 'fraudBlast', { rMargin: 0 }), ['status', 'b-ok']]);
const cs = (counter: string, c: string, input: string, table: string, extra: any = {}) => ['slashCounter', { counterBondId: counter, claim: `@claim_${c}`, dispute: `@disp_${c}_${input}`, grant: '@grant', openSnapshot: `@snap_${SNAP_FOR[c] ?? c}`, oracleTable: ORAC[table], treasury: 'treasury', ...extra }];
seq('counter-bond', {}, [dep('bob', 100), ['openBond', { claimId: 'cb-1', amount: 20, depositor: 'bob' }], cs('cb-1', 'ok', 'blastRadius', 'upholdBlast'), cs('cb-1', 'ok', 'blastRadius', 'upholdBlast'), ['status', 'cb-1'], ['balance', 'treasury'], ['balance', 'bob'], ['bond', 'cb-1'], ['release', 'cb-1'], ['releaseUnreg', 'cb-1']]);
seq('counter-bond-not-frivolous', {}, [dep('bob', 100), ['openBond', { claimId: 'cb-1', amount: 20, depositor: 'bob' }], cs('cb-1', 'ok', 'blastRadius', 'fraudBlast'), cs('cb-1', 'ok', 'blastRadius', 'invalid'), cs('nope', 'ok', 'blastRadius', 'upholdBlast'), cs('cb-1', 'ok', 'blastRadius', 'upholdBlast', { treasury: '' }), ['status', 'cb-1']]);
seq('counter-after-agent', {}, [dep(), oc('ok'), cs('b-ok', 'ok', 'blastRadius', 'upholdBlast'), ['status', 'b-ok'], ['balance', 'treasury'], ['bond', 'b-ok']]);
seq('counter-comp', { splitPolicy: { challengerBps: 100, victimBps: 100 } }, [dep('bob', 100), ['openBond', { claimId: 'cb-1', amount: 20.5, depositor: 'bob' }], cs('cb-1', 'ok', 'blastRadius', 'upholdBlast', { compensationAccount: 'victim', splitPolicy: { challengerBps: 5000, victimBps: 5000 } }), ['balance', 'victim'], ['balance', 'treasury'], ['bond', 'cb-1']]);
seq('epoch', { epoch: 0 }, [dep(), oc('ok'), ['bond', 'b-ok'], T(61_000), ['release', 'b-ok'], ['bond', 'b-ok']]);
seq('epoch-big', { epoch: 9007199254740991 }, [dep(), oc('low'), sl('low', 'low', { challengerAccount: 'c' }), ['bond', 'b-low']]);
seq('escrow-name', { escrow: 'treasury' }, [dep(), oc('low'), sl('low', 'low', { challengerAccount: 'chal' }), ['balance', 'treasury'], ['balance', 'escrow']]);
seq('deposits', {}, [['deposit', 'a', 1], ['deposit', 'a', 0.1], ['deposit', 'a', 0.2], ['balance', 'a'], ['deposit', 'a', 0], ['deposit', 'a', -1], ['deposit', '', 1], ['deposit', 'a', 1e15], ['deposit', 'a', 0.0000005], ['balance', 'a'], ['balance', 'nobody'], ['balance', ''], ['kvGet']]);
seq('corrupt-doc', {}, [['kvSet', { v: 2 }], ['balance', 'a'], ['deposit', 'a', 1], ['status', 'x'], ['kvSet', { v: 1, balances: [], bonds: [{ claimId: 'x' }], highWater: 0 }], ['status', 'x'], ['kvSet', { v: 1, balances: [['a', -1]], bonds: [], highWater: 0 }], ['balance', 'a'], ['kvSet', { v: 1, balances: [], bonds: [], highWater: -1 }], ['pub'], ['status', 'x'], ['kvSet', [1]], ['release', 'x']]);
seq('clock-invalid', {}, [dep(), ['clock', null], ['status', 'b-ok'], ['balance', 'alice'], ['challenge', 'b-ok'], oc('ok'), ['release', 'b-ok'], ['deposit', 'alice', 1], T(0), oc('ok'), ['clock', 'x'], ['release', 'b-ok']]);
seq('highwater', {}, [dep(), T(1_000_000), oc('low', 40, { }), ['clock', T0], ['challenge', 'b-low'], ['release', 'b-low'], T(1_200_000), ['release', 'b-low']]);
seq('same-ref-two-claims', {}, [dep(), oc('ok'), ['openClaim', { claim: { ...fx.claim_ok }, pcactn: '@pc_ok', signerPublic: AG.pk, amount: 40, depositor: 'alice' }], ['balance', 'alice']]);
for (const [name, cfg, ops] of seqCases) await o.run('ledger', name, ledgerRun, [usedFx(ops), cfg, ops]);
// seeded random walks over a fixed pool
const WCL = ['ok', 'low', 'deny', 'irr', 'high', 'mid', 'mid-low', 'cc'];
for (let sd0 = 1; sd0 <= 40; sd0++) {
  const r = rng(0xb04d + sd0);
  const ops: any[] = [dep('alice', r.pick([100, 500, 1000])), dep('bob', 200)];
  let t = 0;
  for (let i = 0; i < 36; i++) {
    const cn = r.pick(WCL);
    const k = r.pick(['open', 'open', 'release', 'slash', 'slash', 'rev', 'disp', 'counter', 'time', 'time', 'read', 'ob', 'relu']);
    const dpt = r.pick(['alice', 'alice', 'bob']);
    if (k === 'open') ops.push(oc(cn, r.pick([40, 40, 12, 7.5, 100, 1]), { depositor: dpt }));
    else if (k === 'release') ops.push(['release', refOf(cn)]);
    else if (k === 'relu') ops.push(['releaseUnreg', r.pick([refOf(cn), 'cb-1', 'cb-2'])]);
    else if (k === 'slash') { const p = r.pick(['low', 'deny', 'irr', 'high', 'mid-low', 'ok-hi']); ops.push(sl(cn, p, r.pick([{}, { challengerAccount: 'chal' }, { challengerAccount: 'chal', compensationAccount: 'victim' }]))); }
    else if (k === 'rev') ops.push(sr(cn, r.pick([{}, { challengerAccount: 'chal' }])));
    else if (k === 'disp') ops.push(sd(cn, r.pick(['blastRadius', 'semanticDistance', 'reversibility', 'reversibility_class']), r.pick(['fraudBlast', 'fraudSem', 'fraudRev', 'fraudClass', 'upholdBlast', 'upholdClass', 'invalid']), r.pick([{}, { challengerAccount: 'chal' }])));
    else if (k === 'counter') ops.push(cs(r.pick(['cb-1', 'cb-2', refOf(cn)]), cn, r.pick(['blastRadius', 'reversibility_class']), r.pick(['upholdBlast', 'upholdClass', 'fraudBlast'])));
    else if (k === 'ob') ops.push(['openBond', { claimId: r.pick(['cb-1', 'cb-2']), amount: r.pick([10, 20]), depositor: dpt }]);
    else if (k === 'time') { t += r.pick([-30_000, 10_000, 30_000, 61_000, 200_000]); ops.push(T(t)); }
    else ops.push(r.pick([['balance', 'alice'], ['balance', 'treasury'], ['balance', 'chal'], ['balance', 'escrow'], ['status', refOf(cn)], ['bond', refOf(cn)], ['challenge', refOf(cn)], ['balance', 'victim']]));
  }
  ops.push(['balance', 'alice'], ['balance', 'escrow'], ['balance', 'treasury'], ['kvGet']);
  await o.run('ledger', `walk${sd0}`, ledgerRun, [usedFx(ops), r.pick([{}, {}, { epoch: 4 }, { splitPolicy: { challengerBps: 2000, victimBps: 7000 } }]), ops]);
}

// outcome summary (a corpus that never reaches a committed slash is useless)
{
  const by: Record<string, number> = {};
  for (const c of o.cases) {
    if (c.fn !== 'ledger') continue;
    for (const x of c.out) { const k = x && x.$err ? 'err:' + x.$err : x && x.action ? 'rec:' + x.action : 'val'; by[k] = (by[k] ?? 0) + 1; }
  }
  console.log(JSON.stringify(by));
  const vf2: Record<string, number> = {};
  for (const c of o.cases) if (c.fn === 'verifyFraudProof') { const k = String(c.out.fraudulent) + ':' + String(c.out.reason).slice(0, 30); vf2[k] = (vf2[k] ?? 0) + 1; }
  console.log(JSON.stringify(vf2));
  const ad2: Record<string, number> = {};
  for (const c of o.cases) if (c.fn === 'adjudicateDispute') ad2[c.out.outcome] = (ad2[c.out.outcome] ?? 0) + 1;
  console.log(JSON.stringify(ad2));
}
refWrite(o, 'core-bond-settlement-java');
