// Oracle: the salted ledger commit (entryCommit / verifyOpening / ledgerRootOf), the v2 goal parser, the profile revocation scope and
// exposure window, and the budget-allocation caveat, TS reference. Written for the Kotlin lane; reusable by any native. No keys, no clock.
//
// PORTING (fn(args) -> native entry point; results compared by JSON value, a reference throw = the native throws):
//   entryCommit(salt, pcactn)            -> b64u digest
//   verifyOpening(commit, opening)       -> boolean (never throws)
//   ledgerRootOf(commits[])              -> b64u root
//   parseIntentGoalV2(goal)              -> null | {session, mapDigest}
//   profileRevocationScope(profileId)    -> string
//   revocationExposureEnd(t, maxAge, skew|null) -> number
//   budgetAllocCaveat(limit)             -> {type, limit}
import { Oracle, refWrite } from './lib.mjs';
const { b64u }: any = await import('../../../packages/pca/src/hash.ts');
const L: any = await import('../../../packages/pca/src/ledger.ts');
const S: any = await import('../../../packages/pca/src/intent-session.ts');
const R: any = await import('../../../packages/pca/src/intent-revocation.ts');
const C: any = await import('../../../packages/pca/src/capability.ts');

const o = new Oracle('core-kotlin-gaps', 'tools/pca-audit/oracles/core-kotlin-gaps.mts', 'TS-reference oracle for the salted ledger commit, the v2 goal parser, profile revocation scope / exposure window and the budget-allocation caveat.');
const pcs: any[] = [
  { id: 'a', action: { verb: 'charge', resource: 'merchant:m1', params: { amount: 10 } } },
  { id: 'b', action: { verb: 'read', resource: '*' }, extra: [1, 2, { z: null }] },
  { action: { verb: 'x', resource: 'y', params: { n: 1.5, s: 'é', t: true } } },
  {},
];
const salts = ['s1', 's2', 'salt-with-unicode-é', ''];
for (const [pi, p] of pcs.entries()) for (const [si, s] of salts.entries()) {
  await o.run('entryCommit', `p${pi}/s${si}`, L.entryCommit, [s, p]);
  const c = L.entryCommit(s, p);
  await o.run('verifyOpening', `ok/p${pi}/s${si}`, L.verifyOpening, [c, { salt: s, pcactn: p }]);
  await o.run('verifyOpening', `wrongsalt/p${pi}/s${si}`, L.verifyOpening, [c, { salt: s + 'x', pcactn: p }]);
  await o.run('verifyOpening', `wrongpc/p${pi}/s${si}`, L.verifyOpening, [c, { salt: s, pcactn: pcs[(pi + 1) % pcs.length] }]);
}
for (const bad of [null, 'x', 5, [], {}, { salt: 's1' }, { pcactn: pcs[0] }, { salt: 5, pcactn: pcs[0] }]) await o.run('verifyOpening', `bad/${JSON.stringify(bad)}`, L.verifyOpening, ['AAAA', bad]);
for (const n of [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 33]) await o.run('ledgerRootOf', `n${n}`, L.ledgerRootOf, [Array.from({ length: n }, (_, i) => `c${i}`)]);
await o.run('ledgerRootOf', 'odd-text', L.ledgerRootOf, [['', 'é', 'a b', '\u0000']]);
const s32 = b64u(new Uint8Array(32).fill(1)), d32 = b64u(new Uint8Array(32).fill(2));
let gi = 0;
for (const g of [`pca-intent:v2:${s32}:${d32}`, `pca-intent:v2c:${s32}:${d32}`, `pca-intent:v2:${s32}:${d32}:x`, `pca-intent:v2:${s32}`, `pca-intent:v2:${s32}:short`, `pca-intent:v2:short:${d32}`, `pca-intent:v1:${s32}`, 'pca-intent:v2:', '', null, 5, `pca-intent:v2:${s32}=:${d32}`])
  await o.run('parseIntentGoalV2', `g${gi++}`, S.parseIntentGoalV2, [g]);
for (const p of ['p1', '', 'a:b', 'é']) await o.run('profileRevocationScope', `p/${JSON.stringify(p)}`, R.profileRevocationScope, [p]);
for (const [t, m, k] of [[1000, 300000, null], [1000, 60000, 0], [0, 0, null], [1e12, 5, 7], [-5, 10, 1]] as any[]) await o.run('revocationExposureEnd', `e/${t}/${m}/${k}`, (a: number, b: number, c: number | null) => (c === null ? R.revocationExposureEnd(a, b) : R.revocationExposureEnd(a, b, c)), [t, m, k]);
for (const lim of [0, 1, 5.5, 1e9]) await o.run('budgetAllocCaveat', `l/${lim}`, C.budgetAllocCaveat, [lim]);
refWrite(o, 'core-kotlin-gaps');
