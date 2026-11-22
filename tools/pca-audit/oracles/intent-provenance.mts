// Oracle: @atlasauth/pca-intent provenance banner, friction floor and within-grant regret (provenance.ts). Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   provenanceBanner(level, what?) / isTainted(level) / provenanceFriction(base, sensitivity, level)   IntentProvenance.*
//   regret(case) / report(cases, scale?)   case = {feasible, chosen, admits, utility}: admits in {"all","none","amountLe50","verbRefund"}, utility in {"amount","negAmount","zero","nan","amountPlusPrefer"}
//     (amount = the outcome's numeric action.params.amount, 0 when absent; negAmount = -amount; zero = 0; nan = NaN; amountPlusPrefer = amount + 1000 when recipient is "bob"):
//     withinGrantRegret / regretReport with those predicates
import * as P0 from '../../../packages/pca-intent/src/provenance';
import { Oracle, refWrite } from './lib.mjs';

const P: any = (P0 as any).default ?? P0;
const o = new Oracle('intent-provenance', 'tools/pca-audit/oracles/intent-provenance.mts', 'TS-reference oracle for provenance and regret.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const A = 'action.params.';
const amt = (x: any) => (typeof x.values[A + 'amount'] === 'number' ? x.values[A + 'amount'] : 0);
const ADM: Record<string, any> = { all: () => true, none: () => false, amountLe50: (x: any) => amt(x) <= 50, verbRefund: (x: any) => x.verb === 'stripe.refund' };
const UTIL: Record<string, any> = { amount: amt, negAmount: (x: any) => -amt(x), zero: () => 0, nan: () => NaN, amountPlusPrefer: (x: any) => amt(x) + (x.values[A + 'recipient'] === 'bob' ? 1000 : 0) };
const bind = (c: any) => ({ feasible: c.feasible, chosen: c.chosen, admits: ADM[c.admits], utility: UTIL[c.utility] });
const levels = ['trusted', 'first_party', 'tool', 'web', 'agent', 'bogus', ''];
for (const l of levels) { await run('provenanceBanner', P.provenanceBanner, [l]); await run('provenanceBanner', P.provenanceBanner, [l, 'amount']); await run('provenanceBanner', P.provenanceBanner, [l, '']); await run('isTainted', P.isTainted, [l]); }
for (const b of ['tap', 'hold', 'typed', 'device']) for (const s of ['material', 'critical', 'other']) for (const l of levels) await run('provenanceFriction', P.provenanceFriction, [b, s, l]);
for (const b of ['bogus', '']) for (const l of ['trusted', 'web']) await run('provenanceFriction', P.provenanceFriction, [b, 'critical', l]);
const out = (amount: number | string | undefined, recipient = 'bob', verb = 'stripe.refund') => ({ verb, values: { ...(amount === undefined ? {} : { [A + 'amount']: amount }), [A + 'recipient']: recipient } });
const feas = [out(10), out(40, 'alice'), out(50), out(80), out(120, 'bob'), out('x'), out(undefined), out(30, 'bob', 'gmail.send')];
const cases: any[] = [];
for (const admits of Object.keys(ADM)) for (const utility of Object.keys(UTIL)) for (const chosen of [out(10), out(80), out(40, 'alice'), out(undefined), out(30, 'bob', 'gmail.send')]) cases.push({ feasible: feas, chosen, admits, utility });
cases.push({ feasible: [], chosen: out(10), admits: 'all', utility: 'amount' }, { feasible: [out(10)], chosen: out(10), admits: 'all', utility: 'amount' }, { feasible: [out(10), out(20)], chosen: out(10), admits: 'none', utility: 'amount' });
for (const c of cases) await run('regret', (cc: any) => P.withinGrantRegret(bind(cc)), [c]);
const groups: any[][] = [[], cases.slice(0, 5), cases.slice(5, 30), cases.slice(30, 60), cases.filter((c) => c.admits === 'amountLe50' && c.utility === 'amount'), cases.filter((c) => c.utility === 'negAmount'), cases.filter((c) => c.utility === 'nan'), cases];
for (const g of groups) for (const scale of [undefined, 1, 100, 0, -5, 1000000]) await run('report', (cs: any[], sc?: number) => P.regretReport(cs.map(bind), sc), scale === undefined ? [g] : [g, scale]);
refWrite(o, 'intent-provenance');
