// Oracle: core exports the Java lane ported in its sweep: chain-compact.ts (hopLeaf, hopsRoot, compactChain, compactChainShapeError, ChainMemo),
// receipt.ts (receiptFor, appendReceipt, verifyReceiptChain, receiptHead) and reputation.ts (reputation, priceCoverage, issueCoverageQuote,
// verifyCoverageQuote, InsuranceCapitalPool from bond-settlement.ts), TS reference. Reusable by any native.
// Ed25519 only; keys from seed(label); no clocks (every time is an argument).
//
// PORTING (fn(args) -> native entry point, comparison rule; every result compared by JSON value)
//   hopLeaf(cap) / hopsRoot(chain) / compactChain(chain) / compactChainShapeError(x)   (null result = no error)
//   chainMemo(ops): ["new",{maxEntries?,ttlMs?}] ["remember",chain,rootIssuer,now] -> compact | ["resolve",compact,now] -> {ok:true, view:{n,hashes,counts,leaf}} | {ok:false,reason}
//                   ["prune",now] ["forget",hopsRoot] -> bool  ["size"]   (a throw records {"$err":"Error"})
//   receiptFor(prev, seq, pcactn, {allow, checks?}, at|null) / appendReceipt(log, pcactn, {allow, checks?}, at|null) / verifyReceiptChain(log) / receiptHead(log)
//   reputation(input) / priceCoverage({score}, exposure, opts) / issueCoverageQuote(rep, exposure, now, ttlMs, opts|null) (underwriter seed "sweep/underwriter")
//   verifyCoverageQuote(quote, underwriter, now)  (underwriter "@u" = the seed's public key)
//   semanticSignal(r) / progressSignal(r) / objectiveSignal(r) -> "ok"|"escalate"|"deny";  tightenRiskInputs(baseline, objective) -> {reversibility, blastRadius, semanticDistance}
//   recommendPolicy(targetActions, perActionRisk, kappa|null) -> {kappa, bMax, autonomousBound, rationale} (throws on bad input);  autonomyBoundOf(policy{bMax,kappa}) -> number
//   subBudget(parent, alloc) / debitConsolidated(parent, sub, c) / debitConsolidatedPath(path, c) / rechargeFull(bMax, now) -> {ok, ...} | budget  (risk.ts; rechargeFull ignores its first argument)
//   approveClass(verbs, ttlMs, by, now, resource|null) / classApprovalCovers(a, verb, resource, now) / coveredByAny(list, verb, resource, now) / recordDecision(request, decision, by, at) / pendingRequests(reviews) / applyCosign(budget, policy{rho,bMax}, now, full) (approvals.ts)
//   pool(ops): ["new",initial] ["quote",rep,exposure,opts] ["collect",rep,exposure,opts] ["canCover",n] ["pay",n] ["state"]
import { Oracle, refWrite, seed, jsonOut } from './lib.mjs';
import * as PCA0 from '@atlasauth/pca';

const P: any = (PCA0 as any).default ?? PCA0;
const { mintRoot, delegate, publicKeyOf, encodeKey } = P;
const CC: any = await import('../../../packages/pca/src/chain-compact.ts');
const RC: any = await import('../../../packages/pca/src/receipt.ts');
const RP: any = await import('../../../packages/pca/src/reputation.ts');
const BS: any = await import('../../../packages/pca/src/bond-settlement.ts');
const FS: any = await import('../../../packages/pca/src/frontier-signals.ts');
const BF: any = await import('../../../packages/pca/src/budget-forecast.ts');
const RK: any = await import('../../../packages/pca/src/risk.ts');
const AP: any = await import('../../../packages/pca/src/approvals.ts');
const o = new Oracle('core-sweep-java', 'tools/pca-audit/oracles/core-sweep-java.mts', 'TS-reference oracle for chain compaction, receipts and reputation / underwriting.');
const T0 = 1_800_000_000_000;
const key = (l: string) => { const sk = seed('sweep/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const PR = key('principal'), A1 = key('a1'), A2 = key('a2'), A3 = key('a3'), UW = key('underwriter');
const J = (x: any) => JSON.parse(JSON.stringify(x));

// ---------------------------------------------------------------- chains
const cav = (n: number) => Array.from({ length: n }, (_, i) => ({ type: 'expires', at: T0 + 10_000_000 + i }));
const root = J(mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: A1.pk, caveats: cav(1) }));
const h1 = J(delegate(root, A2.pk, cav(2), A1.sk));
const h2 = J(delegate(h1, A3.pk, [], A2.sk));
const root2 = J(mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: A1.pk, caveats: [{ type: 'expires', at: T0 + 5 }, { type: 'max_blast_radius', max: 0.5 }] }));
const CH: Record<string, any[]> = { one: [root], two: [root, h1], three: [root, h1, h2], other: [root2], otherTwo: [root2, J(delegate(root2, A2.pk, cav(1), A1.sk))] };
const BADCH: Record<string, any> = { empty: [], reorder: [root, h2, h1], dropMid: [root, h2], dup: [root, root], tamper: [root, { ...h1, sig: 'AAAA' }], notArr: 'x', nullChain: null, tooDeep: Array.from({ length: 17 }, () => root), depth16: Array.from({ length: 16 }, () => root) };
for (const [n, c] of [...Object.entries(CH), ...Object.entries(BADCH)]) {
  await o.run('hopsRoot', n, CC.hopsRoot, [c]);
  await o.run('compactChain', n, CC.compactChain, [c]);
}
for (const [n, c] of Object.entries(CH)) { await o.run('hopLeaf', n, CC.hopLeaf, [c[c.length - 1]]); for (const hop of c) await o.run('hopLeaf', n + '/' + hop.id, CC.hopLeaf, [hop]); }
const compact = J(CC.compactChain(CH.three));
const del = (k: string) => { const c = { ...compact }; delete (c as any)[k]; return c; };
const SHAPES: Array<[string, any]> = [['ok', compact], ['null', null], ['str', 'x'], ['arr', []], ['num', 5], ['obj', {}], ['extra', { ...compact, x: 1 }], ['nov', del('v')], ['nokind', del('kind')], ['nodepth', del('depth')], ['noroot', del('hops_root')], ['noleaf', del('leaf')],
  ['v2', { ...compact, v: 2 }], ['vstr', { ...compact, v: '1' }], ['kind', { ...compact, kind: 'x' }], ['depth0', { ...compact, depth: 0 }], ['depth17', { ...compact, depth: 17 }], ['depth16', { ...compact, depth: 16 }], ['depth1.5', { ...compact, depth: 1.5 }], ['depthstr', { ...compact, depth: '3' }], ['depthneg', { ...compact, depth: -1 }],
  ['root42', { ...compact, hops_root: compact.hops_root.slice(1) }], ['root44', { ...compact, hops_root: compact.hops_root + 'A' }], ['rootnum', { ...compact, hops_root: 5 }], ['leafnull', { ...compact, leaf: null }], ['leafarr', { ...compact, leaf: [] }], ['leafstr', { ...compact, leaf: 'x' }]];
for (const [n, c] of SHAPES) await o.run('compactChainShapeError', n, CC.compactChainShapeError, [c]);

async function memoRun(ops: any[]): Promise<any[]> {
  let memo: any = null;
  const out: any[] = [];
  for (const op of ops) {
    try {
      let v: any = null;
      switch (op[0]) {
        case 'new': memo = new CC.ChainMemo(op[1] ?? {}); break;
        case 'remember': v = memo.rememberVerified(op[1], op[2], op[3]); break;
        case 'resolve': { const r = memo.resolve(op[1], op[2]); v = r.ok ? { ok: true, view: { n: r.view.n, hashes: Array.from({ length: r.view.n }, (_, i) => r.view.hash(i)), counts: Array.from({ length: r.view.n }, (_, i) => r.view.count(i)), leaf: r.view.leaf } } : r; break; }
        case 'prune': memo.prune(op[1]); break;
        case 'forget': v = memo.forget(op[1]); break;
        case 'size': v = memo.size; break;
        default: throw new Error('op');
      }
      out.push(jsonOut(v) ?? null);
    } catch { out.push({ $err: 'Error' }); }
  }
  return out;
}
const cmp = (n: string) => J(CC.compactChain(CH[n]));
const memoCases: Array<[string, any[]]> = [
  ['basic', [['new', {}], ['resolve', cmp('three'), T0], ['remember', CH.three, PR.pk, T0], ['size'], ['resolve', cmp('three'), T0], ['resolve', cmp('three'), T0 + 3_600_000], ['resolve', cmp('three'), T0 + 3_600_001], ['size'], ['resolve', cmp('three'), T0]]],
  ['depths', [['new', {}], ['remember', CH.one, PR.pk, T0], ['remember', CH.two, PR.pk, T0], ['remember', CH.three, PR.pk, T0], ['size'], ['resolve', cmp('one'), T0], ['resolve', cmp('two'), T0], ['resolve', cmp('three'), T0], ['resolve', { ...cmp('two'), depth: 3 }, T0], ['resolve', { ...cmp('three'), leaf: h1 }, T0], ['resolve', { ...cmp('three'), leaf: { ...h2, caveats: [{ type: 'expires', at: 1 }] } }, T0], ['resolve', { ...cmp('three'), hops_root: cmp('two').hops_root }, T0]]],
  ['bad-chains', [['new', {}], ['remember', BADCH.empty, PR.pk, T0], ['remember', BADCH.reorder, PR.pk, T0], ['remember', BADCH.dropMid, PR.pk, T0], ['remember', BADCH.dup, PR.pk, T0], ['remember', BADCH.tamper, PR.pk, T0], ['remember', BADCH.notArr, PR.pk, T0], ['remember', BADCH.tooDeep, PR.pk, T0], ['remember', CH.three, A1.pk, T0], ['remember', CH.three, PR.pk, 1.5], ['remember', CH.three, PR.pk, 'x'], ['size']]],
  ['ttl', [['new', { ttlMs: 1000 }], ['remember', CH.two, PR.pk, T0], ['resolve', cmp('two'), T0 + 1000], ['resolve', cmp('two'), T0 + 1001], ['size'], ['remember', CH.two, PR.pk, T0 + 5000], ['resolve', cmp('two'), T0 + 5999], ['new', { ttlMs: 99_999_999_999 }], ['remember', CH.two, PR.pk, T0], ['resolve', cmp('two'), T0 + 3_600_000], ['resolve', cmp('two'), T0 + 3_600_001]]],
  ['full', [['new', { maxEntries: 2 }], ['remember', CH.one, PR.pk, T0], ['remember', CH.two, PR.pk, T0], ['remember', CH.three, PR.pk, T0], ['remember', CH.two, PR.pk, T0 + 10], ['size'], ['remember', CH.three, PR.pk, T0 + 4_000_000], ['size'], ['resolve', cmp('one'), T0 + 4_000_000], ['resolve', cmp('three'), T0 + 4_000_000]]],
  ['prune-forget', [['new', {}], ['remember', CH.one, PR.pk, T0], ['remember', CH.two, PR.pk, T0 + 1000], ['prune', T0 + 3_600_500], ['size'], ['forget', cmp('two').hops_root], ['forget', cmp('two').hops_root], ['size'], ['resolve', cmp('two'), T0], ['prune', T0 + 10_000_000], ['size']]],
  ['resolve-hostile', [['new', {}], ['remember', CH.three, PR.pk, T0], ['resolve', null, T0], ['resolve', 'x', T0], ['resolve', {}, T0], ['resolve', cmp('three'), 1.5], ['resolve', cmp('three'), 'x'], ['resolve', { ...cmp('three'), extra: 1 }, T0], ['resolve', { ...cmp('three'), leaf: null }, T0], ['resolve', { ...cmp('three'), leaf: { ...h2, caveats: 'x' } }, T0]]],
  ['other-root', [['new', {}], ['remember', CH.other, PR.pk, T0], ['remember', CH.otherTwo, PR.pk, T0], ['resolve', cmp('other'), T0], ['resolve', cmp('otherTwo'), T0], ['resolve', cmp('one'), T0]]],
];
for (const [name, ops] of memoCases) await o.run('chainMemo', name, memoRun, [ops]);

// ---------------------------------------------------------------- receipts
const pc = (n: number, verb = 'charge', extra: any = {}) => ({ iat: T0 + n, action: { verb, resource: 'merchant:m' + n, params: { amount: n } }, ...extra });
const CHECKS = [undefined, null, {}, { sig: 'ok', window: 'ok' }, { a: 'x', b: 'ñ' }];
for (const [ci, ch] of CHECKS.entries()) for (const allow of [true, false]) for (const at of [null, 5, T0 + 99]) {
  const v = ch === undefined ? { allow } : { allow, checks: ch };
  await o.run('receiptFor', `c${ci}/${allow}/${at}`, RC.receiptFor, ['', 0, pc(1), v, at]);
  await o.run('receiptFor', `p${ci}/${allow}/${at}`, RC.receiptFor, ['PREVHASH', 7, pc(2, 'refund'), v, at]);
}
async function receiptRun(ops: any[]): Promise<any[]> {
  let log: any[] = [];
  const out: any[] = [];
  for (const op of ops) {
    try {
      let v: any = null;
      switch (op[0]) {
        case 'append': log = RC.appendReceipt(log, op[1], op[2], op[3] ?? undefined); v = log[log.length - 1]; break;
        case 'head': v = RC.receiptHead(log); break;
        case 'verify': v = RC.verifyReceiptChain(log); break;
        case 'set': log = JSON.parse(JSON.stringify(op[1])); break;
        case 'tamper': log = JSON.parse(JSON.stringify(log)); if (op[3] === '$del') delete log[op[1]][op[2]]; else log[op[1]][op[2]] = op[3]; break;
        case 'swap': { const l = JSON.parse(JSON.stringify(log)); [l[op[1]], l[op[2]]] = [l[op[2]], l[op[1]]]; log = l; break; }
        case 'drop': log = log.filter((_, i) => i !== op[1]); break;
        case 'truncate': log = log.slice(0, op[1]); break;
        default: throw new Error('op');
      }
      out.push(jsonOut(v) ?? null);
    } catch { out.push({ $err: 'Error' }); }
  }
  return out;
}
const appends = (n: number) => Array.from({ length: n }, (_, i) => ['append', pc(i + 1, i % 2 ? 'refund' : 'charge'), { allow: i % 3 !== 0, ...(i % 2 ? { checks: { sig: 'ok', i: String(i) } } : {}) }, i % 4 === 0 ? T0 + i : null]);
const rcases: Array<[string, any[]]> = [
  ['empty', [['head'], ['verify']]], ['chain5', [...appends(5), ['head'], ['verify']]],
  ['tamper-body', [...appends(5), ['tamper', 2, 'verb', 'x'], ['verify']]], ['tamper-hash', [...appends(5), ['tamper', 3, 'hash', 'AAAA'], ['verify']]], ['tamper-prev', [...appends(5), ['tamper', 1, 'prev', 'zz'], ['verify']]],
  ['tamper-seq', [...appends(5), ['tamper', 4, 'seq', 9], ['verify']]], ['tamper-outcome', [...appends(4), ['tamper', 0, 'outcome', 'allow'], ['verify']]], ['tamper-at', [...appends(4), ['tamper', 0, 'at', 1], ['verify']]],
  ['tamper-extra', [...appends(3), ['tamper', 1, 'note', 'x'], ['verify']]], ['tamper-checks', [...appends(3), ['tamper', 1, 'checks', { z: 1 }], ['verify']]], ['tamper-checks-del', [...appends(3), ['tamper', 1, 'checks', '$del'], ['verify']]], ['tamper-hash-del', [...appends(3), ['tamper', 1, 'hash', '$del'], ['verify']]],
  ['swap', [...appends(4), ['swap', 1, 2], ['verify']]], ['drop-mid', [...appends(4), ['drop', 1], ['verify']]], ['drop-first', [...appends(4), ['drop', 0], ['verify'], ['head']]], ['truncate', [...appends(4), ['truncate', 2], ['verify'], ['head'], ['append', pc(9), { allow: true }, null], ['verify']]],
  ['append-after-tamper', [...appends(3), ['tamper', 2, 'seq', 7], ['append', pc(9), { allow: false }, null], ['verify']]],
  ['append-noiat', [['append', { action: { verb: 'v', resource: 'r' } }, { allow: true }, 5], ['verify']]],
  ['set-junk', [['set', [{ seq: 0, prev: '', hash: 'x' }]], ['verify'], ['head']], ], ['set-empty-obj', [['set', [{}]], ['verify']]], ['set-seq-str', [['set', [{ seq: '0' }]], ['verify']]],
];
for (const [name, ops] of rcases) await o.run('receiptChain', name, receiptRun, [ops]);

// ---------------------------------------------------------------- reputation
const ev = (outcome: string, n = 0) => ({ outcome, n });
const dsp = (id: string, slashed: boolean, extra: any = {}) => ({ id, subject: 'agent-1', slashed, at: 1000, ...extra });
const mix = (a: number, s: number, d: number) => [...Array(a).fill(0).map(() => ev('auto')), ...Array(s).fill(0).map(() => ev('step_up')), ...Array(d).fill(0).map(() => ev('deny'))];
const INPUTS: Array<[string, any]> = [
  ['empty', { subject: 'agent-1' }], ['empty-arrays', { subject: 'agent-1', events: [], disputes: [] }], ['clean', { subject: 'agent-1', events: mix(10, 0, 0) }], ['stepups', { subject: 'agent-1', events: mix(7, 3, 0) }], ['denies', { subject: 'agent-1', events: mix(7, 0, 3) }],
  ['both', { subject: 'agent-1', events: mix(5, 3, 2) }], ['allDeny', { subject: 'agent-1', events: mix(0, 0, 4) }], ['executed', { subject: 'agent-1', events: [ev('executed'), ev('executed')] }], ['rate-3', { subject: 'agent-1', events: mix(2, 0, 1) }], ['rate-6', { subject: 'agent-1', events: mix(5, 0, 1) }], ['rate-7', { subject: 'agent-1', events: mix(6, 0, 1) }],
  ['rate-1of8', { subject: 'agent-1', events: mix(7, 0, 1) }], ['rate-1of200', { subject: 'agent-1', events: mix(199, 0, 1) }], ['step-1of3', { subject: 'agent-1', events: mix(2, 1, 0) }], ['step-1of7', { subject: 'agent-1', events: mix(6, 1, 0) }],
  ['slash1', { subject: 'agent-1', events: mix(10, 0, 0), disputes: [dsp('d1', true)] }], ['slash2', { subject: 'agent-1', events: mix(10, 0, 0), disputes: [dsp('d1', true), dsp('d2', true)] }], ['slash3', { subject: 'agent-1', events: mix(10, 0, 0), disputes: [dsp('d1', true), dsp('d2', true), dsp('d3', true)] }],
  ['slash9', { subject: 'agent-1', disputes: Array.from({ length: 9 }, (_, i) => dsp('d' + i, true)) }], ['noslash', { subject: 'agent-1', disputes: [dsp('d1', false)] }], ['dups', { subject: 'agent-1', events: mix(2, 0, 0), disputes: [dsp('d1', true), dsp('d1', true), dsp('d2', false), dsp('d2', true)] }],
  ['sat', { subject: 'agent-1', events: mix(0, 0, 10), disputes: [dsp('d1', true), dsp('d2', true), dsp('d3', true), dsp('d4', true)] }], ['amount', { subject: 'agent-1', disputes: [dsp('d1', true, { amount: 5 }), dsp('d2', false, { amount: 0 })] }],
  ['no-subject', {}], ['empty-subject', { subject: '' }], ['num-subject', { subject: 5 }], ['obj-subject', { subject: { a: 1 } }], ['arr-subject', { subject: [1, 2] }], ['null-subject', { subject: null }], ['events-str', { subject: 'a', events: 'x' }], ['events-null', { subject: 'a', events: null }], ['disputes-null', { subject: 'a', disputes: null }], ['disputes-obj', { subject: 'a', disputes: {} }],
  ['bad-outcome', { subject: 'agent-1', events: [ev('auto'), ev('bogus')] }], ['null-event', { subject: 'agent-1', events: [null] }], ['no-outcome', { subject: 'agent-1', events: [{}] }], ['num-outcome', { subject: 'agent-1', events: [{ outcome: 1 }] }],
  ['d-noid', { subject: 'agent-1', disputes: [{ subject: 'agent-1', slashed: true, at: 1 }] }], ['d-emptyid', { subject: 'agent-1', disputes: [dsp('', true)] }], ['d-othersubject', { subject: 'agent-1', disputes: [dsp('d1', true, { subject: 'agent-2' })] }], ['d-slashed-str', { subject: 'agent-1', disputes: [dsp('d1', 'yes' as any)] }],
  ['d-at-neg', { subject: 'agent-1', disputes: [dsp('d1', true, { at: -1 })] }], ['d-at-str', { subject: 'agent-1', disputes: [dsp('d1', true, { at: '1' })] }], ['d-amount-neg', { subject: 'agent-1', disputes: [dsp('d1', true, { amount: -1 })] }], ['d-amount-null', { subject: 'agent-1', disputes: [dsp('d1', true, { amount: null })] }], ['d-amount-str', { subject: 'agent-1', disputes: [dsp('d1', true, { amount: 'x' })] }], ['d-null', { subject: 'agent-1', disputes: [null] }],
  ['unicode-subject', { subject: 'ä\u{1F600}', events: mix(3, 1, 0) }],
];
for (const [n, i] of INPUTS) await o.run('reputation', n, RP.reputation, [i]);
const SCORES = [0, 0.1, 0.24, 0.25, 0.2500001, 0.5, 0.75, 0.9, 0.9999, 1, 0.333333, -0.1, 1.1, NaN as any, 'x' as any, null as any];
const EXPS = [0, 1, 100, 1234.5678, 1e6, 1e12, 0.000001, -5, 3e20];
const POPTS: any[] = [null, {}, { baseRate: 0.02 }, { riskLoad: 0 }, { riskLoad: 10, minScore: 0.5 }, { minScore: 0 }, { minScore: 1 }, { baseRate: 0, riskLoad: 1 }, { baseRate: 0.015, riskLoad: 2.5, minScore: 0.3 }];
for (const s of SCORES) for (const e of EXPS) await o.run('priceCoverage', `s${s}/e${e}`, (rep: any, exposure: number, opts: any) => RP.priceCoverage(rep, exposure, opts ?? undefined), [s === null || typeof s !== 'number' || Number.isNaN(s) ? { score: s === null ? null : typeof s === 'string' ? s : undefined } : { score: s }, e, null]);
for (const s of [0.1, 0.25, 0.5, 0.8, 1]) for (const e of [100, 1234.5678]) for (const [pi, po] of POPTS.entries()) await o.run('priceCoverage', `opt/${s}/${e}/${pi}`, (rep: any, exposure: number, opts: any) => RP.priceCoverage(rep, exposure, opts ?? undefined), [{ score: s }, e, po]);
const mkRep = (score: number, subject = 'agent-1') => ({ subject, actions: 3, autos: 3, stepUps: 0, denies: 0, slashes: 0, disputes: 0, score, factors: [] });
const issue = (rep: any, exposure: number, now: number, ttl: number, opts: any) => J(RP.issueCoverageQuote({ rep, exposure, underwriterSecret: UW.sk, now, ttlMs: ttl, ...(opts ? { opts } : {}) }));
for (const sc of [0, 0.2, 0.25, 0.5, 0.9, 1]) for (const e of [0, 100, 1234.5678]) for (const po of [null, { baseRate: 0.02, riskLoad: 2 }]) await o.run('issueCoverageQuote', `s${sc}/e${e}/${po ? 'o' : 'd'}`, (rep: any, exposure: number, now: number, ttl: number, opts: any) => RP.issueCoverageQuote({ rep, exposure, underwriterSecret: UW.sk, now, ttlMs: ttl, ...(opts ? { opts } : {}) }), [mkRep(sc), e, T0, 60_000, po]);
for (const [name, rep, e, now, ttl] of [['neg-exposure', mkRep(0.5), -1, T0, 1000], ['nan-ttl', mkRep(0.5), 1, T0, 0], ['neg-ttl', mkRep(0.5), 1, T0, -5], ['score-2', mkRep(2), 1, T0, 1000], ['score-neg', mkRep(-1), 1, T0, 1000], ['score-str', { ...mkRep(0.5), score: 'x' }, 1, T0, 1000], ['no-subject', { score: 0.5 }, 1, T0, 1000]] as any[])
  await o.run('issueCoverageQuote', name, (rep: any, exposure: number, now: number, ttl: number, opts: any) => RP.issueCoverageQuote({ rep, exposure, underwriterSecret: UW.sk, now, ttlMs: ttl }), [rep, e, now, ttl, null]);
const Q = issue(mkRep(0.7), 1000, T0, 60_000, null), QD = issue(mkRep(0.1), 1000, T0, 60_000, null), QO = issue(mkRep(0.7), 1000, T0, 60_000, { baseRate: 0.02, riskLoad: 2, minScore: 0.3 });
const tq = (q: any, f: any) => ({ ...q, ...f });
const VQ: Array<[string, any, string, number]> = [['ok', Q, '@u', T0 + 1], ['ok-declined', QD, '@u', T0], ['ok-opts', QO, '@u', T0 + 59_999], ['at-issue', Q, '@u', T0], ['before', Q, '@u', T0 - 1], ['at-expiry', Q, '@u', T0 + 60_000], ['after', Q, '@u', T0 + 60_001],
  ['wrong-underwriter', Q, PR.pk, T0], ['no-underwriter', Q, '', T0], ['premium', tq(Q, { premium: 1 }), '@u', T0], ['coverage', tq(Q, { coverage: 1 }), '@u', T0], ['declined', tq(Q, { declined: true }), '@u', T0], ['score', tq(Q, { score: 0.71 }), '@u', T0], ['exposure', tq(Q, { exposure: 999 }), '@u', T0], ['baseRate', tq(Q, { baseRate: 0.5 }), '@u', T0],
  ['sig', tq(Q, { sig: 'AAAA' }), '@u', T0], ['nosig', (() => { const c = { ...Q }; delete c.sig; return c; })(), '@u', T0], ['v2', tq(Q, { v: 2 }), '@u', T0], ['null', null, '@u', T0], ['str', 'x', '@u', T0], ['arr', [], '@u', T0], ['num-str', tq(Q, { exposure: '1000' }), '@u', T0], ['subject-num', tq(Q, { subject: 5 }), '@u', T0], ['declined-str', tq(Q, { declined: 'no' }), '@u', T0],
  ['extra-field', tq(Q, { extra: 1 }), '@u', T0], ['underwriter-swap', tq(Q, { underwriter: PR.pk }), PR.pk, T0], ['now-nan', Q, '@u', NaN as any]];
for (const [n, q, uw, now] of VQ) await o.run('verifyCoverageQuote', n, (qq: any, u: string, t: any) => RP.verifyCoverageQuote(qq, { underwriter: u === '@u' ? UW.pk : u, now: t === null ? NaN : t }), [q, uw, Number.isNaN(now) ? null : now]);

async function poolRun(ops: any[]): Promise<any[]> {
  let pool: any = null;
  const out: any[] = [];
  for (const op of ops) {
    try {
      let v: any = null;
      switch (op[0]) {
        case 'new': pool = new BS.InsuranceCapitalPool(op[1]); v = pool.state(); break;
        case 'quote': v = pool.quote(op[1], op[2], op[3] ?? undefined); break;
        case 'collect': v = pool.collectPremium(op[1], op[2], op[3] ?? undefined); break;
        case 'canCover': v = pool.canCover(op[1]); break;
        case 'pay': v = pool.payClaim(op[1]); break;
        case 'state': v = pool.state(); break;
        default: throw new Error('op');
      }
      out.push(jsonOut(v) ?? null);
    } catch { out.push({ $err: 'Error' }); }
  }
  return out;
}
const r = (s: number) => ({ score: s });
const pcases: Array<[string, any[]]> = [
  ['basic', [['new', 1000], ['collect', r(0.9), 1000, null], ['collect', r(0.5), 2000, null], ['state'], ['canCover', 1000], ['canCover', 1e9], ['pay', 500], ['pay', 700], ['pay', 100000], ['state']]],
  ['empty', [['new', 0], ['pay', 1], ['canCover', 0], ['canCover', 1], ['collect', r(1), 100, null], ['pay', 1], ['pay', 0], ['pay', -1], ['state']]],
  ['declined', [['new', 10], ['collect', r(0.1), 1000, null], ['collect', r(0.25), 1000, null], ['collect', r(2), 1000, null], ['collect', { score: 'x' }, 1000, null], ['state']]],
  ['quote', [['new', 5], ['quote', r(0.8), 100, null], ['quote', r(0.8), 100, { baseRate: 0.1 }], ['state']]],
  ['bad-new', [['new', -1], ['state']]], ['bad-new-str', [['new', 'x']]], ['float', [['new', 0.1], ['collect', r(0.7), 0.3, null], ['collect', r(0.7), 0.3, null], ['pay', 0.003], ['state'], ['pay', 0.004], ['state']]],
  ['opts', [['new', 0], ['collect', r(0.6), 5000, { baseRate: 0.05, riskLoad: 1 }], ['collect', r(0.6), 5000, { minScore: 0.9 }], ['state'], ['pay', 200], ['canCover', 50]]],
  ['exhaust', [['new', 100], ['pay', 100], ['pay', 0.000001], ['canCover', 0], ['collect', r(1), 10000, null], ['pay', 100], ['state']]],
];
for (const [name, ops] of pcases) await o.run('pool', name, poolRun, [ops]);
// ---------------------------------------------------------------- frontier signals and budget forecast
const SIGN_IN: any[] = [null, undefined, 'x', 5, [], {}, { ok: true }, { ok: false }, { ok: 'yes' }, { ok: 1 }, { ok: null }, { ok: false, reason: 'exploration-exhausted' }, { ok: false, reason: 'budget-exceeded' }, { ok: false, reason: 'other' }, { ok: false, reason: 5 }, { ok: true, reason: 'budget-exceeded' }, { ok: false, reason: '' },
  { mode: 'none' }, { mode: 'objective' }, { mode: 'mismatch' }, { mode: 'mismatch', onMismatch: 'heuristic' }, { mode: 'mismatch', onMismatch: 'deny' }, { mode: 'mismatch', onMismatch: 'x' }, { mode: 'unknown' }, { mode: 5 }, { mode: 'objective', onMismatch: 'heuristic' }, { mode: 'NONE' }];
for (const [i, x] of SIGN_IN.entries()) for (const f of ['semanticSignal', 'progressSignal', 'objectiveSignal']) await o.run(f, 'c' + i, FS[f], [x === undefined ? null : x]);
const RIN: any[] = [{ reversibility: 0.5, blastRadius: 0.5, semanticDistance: 0.5 }, { reversibility: 1, blastRadius: 0, semanticDistance: 0 }, { reversibility: 0.2, blastRadius: 0.9, semanticDistance: 1 }, { reversibility: 0.9, blastRadius: 0.1, semanticDistance: 0.3 }, { reversibility: 0.5, blastRadius: 0.5 }, { reversibility: 'x', blastRadius: 0.5, semanticDistance: 0.5 }, { reversibility: 0.5, blastRadius: null, semanticDistance: 0.5 }, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: 'x' }, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: -3 }, {}, { reversibility: 0, blastRadius: 1, semanticDistance: 0 }];
for (const [i, b] of RIN.entries()) for (const [j, ob] of RIN.entries()) await o.run('tightenRiskInputs', `c${i}x${j}`, FS.tightenRiskInputs, [b, ob]);
for (const n of [0, 1, 10, 100, 12.5, -5, 1e6, 0.001, 3e20]) for (const r of [0, 1e-9, 1e-6, 0.001, 0.1, 0.25, 0.333, 0.5, 1, 2, -1]) await o.run('recommendPolicy', `n${n}/r${r}`, (a: number, b: number, k: any) => BF.recommendPolicy(a, b, k === null ? {} : { kappa: k }), [n, r, null]);
for (const k of [0.5, 2, 3.7, 0, -1, 1e-9, 100]) await o.run('recommendPolicy', `kappa${k}`, (a: number, b: number, kk: any) => BF.recommendPolicy(a, b, { kappa: kk }), [10, 0.1, k]);
for (const [n, r] of [['x', 1], [1, 'x'], [null, 1], [1, null]] as any[]) await o.run('recommendPolicy', `bad${n}/${r}`, (a: any, b: any, k: any) => BF.recommendPolicy(a, b, {}), [n, r, null]);
for (const p of [{ bMax: 10, kappa: 2 }, { bMax: 0, kappa: 1 }, { bMax: -4, kappa: 2 }, { bMax: 10, kappa: 0 }, { bMax: 10, kappa: -1 }, { bMax: 7, kappa: 3 }, { bMax: 1e9, kappa: 1e-3 }, { bMax: 5, kappa: 'x' }, { bMax: 5 }, { bMax: 0.1, kappa: 0.3 }]) await o.run('autonomyBoundOf', JSON.stringify(p), BF.autonomyBoundOf, [p]);
// ---------------------------------------------------------------- multi-agent budget algebra (risk.ts)
const TB = [{ B: 10, tau: 1000, asOf: 2000 }, { B: 10, tau: 1000 }, { B: 0, tau: 5 }, { B: 5.5, tau: 0, asOf: 0 }, { B: 1e9, tau: 1, asOf: 3 }, { B: 3, tau: 1000, asOf: 2000, note: 'x' }, { B: 'x', tau: 1 }, { tau: 1 }, { B: 4 }];
const AMT = [0, 1, 3, 4, 5.5, 10, 10.0000001, 11, -1, 1e12, 0.1, 0.2, 0.3];
for (const [pi, p] of TB.entries()) for (const a of AMT) await o.run('subBudget', `p${pi}/a${a}`, RK.subBudget, [p, a]);
for (const [pi, p] of TB.slice(0, 6).entries()) for (const [si, sb] of TB.slice(0, 6).entries()) for (const c of [0, 1, 3, 5.5, 10, 11, -2, 0.1]) await o.run('debitConsolidated', `p${pi}/s${si}/c${c}`, RK.debitConsolidated, [p, sb, c]);
const PATHS: any[][] = [[], [{ B: 10, tau: 1 }], [{ B: 10, tau: 1 }, { B: 4, tau: 1, asOf: 5 }], [{ B: 10, tau: 1 }, { B: 4, tau: 1 }, { B: 1, tau: 1 }], [{ B: 3, tau: 1 }, { B: 4, tau: 1 }, { B: 5, tau: 1 }], [{ B: 'x', tau: 1 }], [{ B: 10, tau: 1 }, { tau: 1 }], [{ B: 0, tau: 1 }]];
for (const [pi, p] of PATHS.entries()) for (const c of [0, 1, 3, 4, 4.5, 5, 10, -1, 0.3]) await o.run('debitConsolidatedPath', `p${pi}/c${c}`, RK.debitConsolidatedPath, [p, c]);
for (const bm of [0, 1, 10, 5.5, -1, 1e9, 0.1]) for (const now of [0, 1000, 1_800_000_000_000, -5]) await o.run('rechargeFull', `b${bm}/n${now}`, (bmax: number, n: number) => RK.rechargeFull({ B: 1, tau: 1 }, bmax, n), [bm, now]);
// ---------------------------------------------------------------- approvals (pure half)
const VERBSETS = [['charge'], ['refund', 'charge'], ['read', 'write', 'delete'], [], ['é', 'z', 'a', '\u{1F600}']];
for (const [vi, vs] of VERBSETS.entries()) for (const res of [null, '*', 'merchant:*', 'merchant:m1', 'x']) for (const ttl of [0, 1000, 3_600_000]) await o.run('approveClass', `v${vi}/${res}/${ttl}`, (a: string[], t: number, by: string, now: number, r: any) => AP.approveClass(a, { ttlMs: t, by, now, ...(r === null ? {} : { resource: r }) }), [vs, ttl, 'alice', 1_800_000_000_000, res]);
const CA = (resource: any, grantedAt = 1000, ttlMs = 5000, verbs = ['charge', 'refund']) => ({ id: 'x', verbs, ...(resource === null ? {} : { resource }), grantedAt, ttlMs, by: 'alice' });
for (const [ri, a] of [CA(null), CA('*'), CA('merchant:*'), CA('merchant:m1'), CA('merchant:m1*'), CA(''), CA('*x'), CA('merchant:m1', 1000, 0), CA('*', 1000, 5000, [])].entries()) for (const verb of ['charge', 'read', '']) for (const res of ['merchant:m1', 'merchant:m2', 'merchant:', 'other', '']) for (const now of [999, 1000, 3000, 5999, 6000]) await o.run('classApprovalCovers', `a${ri}/${verb}/${res}/${now}`, AP.classApprovalCovers, [a, verb, res, now]);
const ALL = [CA('merchant:*'), CA('other', 1000, 100), CA(null, 5000, 1000, ['read'])];
for (const verb of ['charge', 'read']) for (const res of ['merchant:m1', 'other', 'x']) for (const now of [1500, 5500, 7000]) { await o.run('coveredByAny', `${verb}/${res}/${now}`, AP.coveredByAny, [ALL, verb, res, now]); await o.run('coveredByAny', `empty/${verb}/${res}/${now}`, AP.coveredByAny, [[], verb, res, now]); }
for (const dec of ['approve', 'deny']) await o.run('recordDecision', dec, (r: any, d: any, by: string, at: number) => AP.recordDecision(r, d, by, at), [{ id: 'req-1', verb: 'charge' }, dec, 'alice', 1234]);
const REVS = [{ kind: 'auto' }, { kind: 'deny', reason: 'x' }, { kind: 'step_up', request: { id: 'r1', tier: 2 } }, { kind: 'step_up', request: { id: 'r2', tier: 3 } }];
for (const [i, rv] of [[], REVS, [REVS[0]], [REVS[2], REVS[0], REVS[3]], [REVS[1]]].entries()) await o.run('pendingRequests', 'c' + i, AP.pendingRequests, [rv]);
for (const b of [{ B: 0, tau: 1 }, { B: 5, tau: 1, asOf: 2 }, { B: 9.5, tau: 0 }, { B: 100, tau: 0 }]) for (const pol of [{ rho: 3, bMax: 10 }, { rho: 0, bMax: 10 }, { rho: 100, bMax: 10 }, { rho: 3, bMax: 0 }, { rho: -1, bMax: 10 }, { rho: 0.1, bMax: 0.3 }]) for (const full of [false, true]) await o.run('applyCosign', `${JSON.stringify(b)}/${JSON.stringify(pol)}/${full}`, (bb: any, pp: any, now: number, f: boolean) => AP.applyCosign(bb, pp, now, f ? { full: true } : {}), [b, pol, 5000, full]);
refWrite(o, 'core-sweep-java');
