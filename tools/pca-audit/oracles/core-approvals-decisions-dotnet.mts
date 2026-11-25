// Oracle: the data half of approvals.ts that core-approvals-java does not cover: approveClass, recordDecision, applyCosign (TS reference).
// Every clock is an argument; nothing is random. Results compared by JSON value.
// PORTING (fn(args) -> native entry point):
//   approveClass(verbs[], {ttlMs, by, now, resource?})   -> the ClassApproval {id, verbs, resource?, grantedAt, ttlMs, by}
//   recordDecision(request{id,...}, decision, by, at)    -> {requestId, decision, by, at}
//   applyCosign(budget{B,tau,asOf?}, policy{rho,bMax}, now, {full?}) -> {B, tau, asOf}
import { Oracle, refWrite } from './lib.mjs';
const { approveClass, recordDecision, applyCosign }: any = await import('../../../packages/pca/src/approvals.ts');

const o = new Oracle('core-approvals-decisions-dotnet', 'tools/pca-audit/oracles/core-approvals-decisions-dotnet.mts', 'TS-reference oracle for approveClass, recordDecision and applyCosign.');
const T0 = 1_800_000_000_000;
const AC = (verbs: string[], opts: any) => approveClass(verbs, opts);

const VERB_SETS: [string, string[]][] = [['one', ['stripe.refund']], ['two', ['stripe.refund', 'gmail.send']], ['unsorted', ['gmail.send', 'stripe.refund', 'a.b']], ['empty', []], ['dup', ['x', 'x']], ['unicode', ['é.z', 'e.z', 'z.\u{1F600}', 'z.～']]];
for (const [n, v] of VERB_SETS) for (const [rn, res] of [['nores', undefined], ['star', '*'], ['prefix', 'acct:*'], ['exact', 'acct:1']] as [string, string | undefined][])
  await o.run('approveClass', `${n}-${rn}`, AC, [v, { ttlMs: 4 * 3600_000, by: 'p@example.com', now: T0, ...(res !== undefined ? { resource: res } : {}) }]);
await o.run('approveClass', 'ttl-zero', AC, [['a'], { ttlMs: 0, by: 'b', now: T0 }]);
await o.run('approveClass', 'ttl-frac', AC, [['a'], { ttlMs: 1500.5, by: 'b', now: T0 }]);
await o.run('approveClass', 'now-zero', AC, [['a'], { ttlMs: 10, by: 'b', now: 0 }]);
await o.run('approveClass', 'by-unicode', AC, [['a'], { ttlMs: 10, by: 'zoë "q"', now: T0 }]);
await o.run('approveClass', 'resource-empty', AC, [['a'], { ttlMs: 10, by: 'b', now: T0, resource: '' }]);

const RD = (r: any, d: string, by: string, at: number) => recordDecision(r, d, by, at);
for (const d of ['approve', 'deny']) await o.run('recordDecision', d, RD, [{ id: 'req-1', verb: 'x' }, d, 'p@example.com', T0]);
await o.run('recordDecision', 'at-zero', RD, [{ id: 'req-2' }, 'approve', 'b', 0]);
await o.run('recordDecision', 'by-unicode', RD, [{ id: 'req-3' }, 'deny', 'zoë', T0 + 1]);
await o.run('recordDecision', 'id-empty', RD, [{ id: '' }, 'approve', 'b', T0]);

const AP = (b: any, pol: any, now: number, opts: any) => applyCosign(b, pol, now, opts);
const POL = { rho: 0.25, bMax: 1 };
const BUDGETS: [string, any][] = [['mid', { B: 0.4, tau: T0 - 1000 }], ['asof', { B: 0.1, tau: T0 - 5000, asOf: T0 - 100 }], ['zero', { B: 0, tau: 0 }], ['full', { B: 1, tau: T0 }], ['near-cap', { B: 0.9, tau: T0 }]];
for (const [bn, b] of BUDGETS) for (const [fn, f] of [['partial', {}], ['full', { full: true }], ['full-false', { full: false }]] as [string, any][]) {
  await o.run('applyCosign', `${bn}-${fn}`, AP, [b, POL, T0, f]);
  await o.run('applyCosign', `${bn}-${fn}-bigrho`, AP, [b, { rho: 5, bMax: 2 }, T0, f]);
}
await o.run('applyCosign', 'rho-negative', AP, [{ B: 0.4, tau: 1 }, { rho: -1, bMax: 1 }, T0, {}]);
await o.run('applyCosign', 'rho-zero', AP, [{ B: 0.4, tau: 1 }, { rho: 0, bMax: 1 }, T0, {}]);
await o.run('applyCosign', 'bmax-zero', AP, [{ B: 0.4, tau: 1 }, { rho: 0.2, bMax: 0 }, T0, {}]);
await o.run('applyCosign', 'bmax-negative-full', AP, [{ B: 0.4, tau: 1 }, { rho: 0.2, bMax: -3 }, T0, { full: true }]);
refWrite(o, 'core-approvals-decisions-dotnet');
