// Oracle: every export of packages/pca/src/frontier-signals.ts (the tighten-or-escalate typing of the intent-frontier results: semanticSignal,
// progressSignal, objectiveSignal, tightenRiskInputs), TS reference. Writes out/ref-frontier-signals.json.gz. Pure and deterministic: no keys, no clock.
// Case shape (as every sibling): {fn, name, args, out}; `out` is what the reference returned, or {"$throws": message}.
//
// PORTING (fn(args) -> native entry point; results compared by JSON value; a reference throw = the native refuses)
//   {"$num":"NaN"|"Infinity"|"-Infinity"} anywhere in args = that non-finite double (plain JSON cannot carry them). -0 is written as -0 and is significant
//   in `out` (min(0, -0) is -0, max(-0, 0) is 0). A null argument = undefined / null (both are "no result").
//   semanticSignal [result]     -> "ok" | "escalate" | "deny": a non-array object whose `ok` is a boolean gives ok / escalate; everything else denies
//   progressSignal [result]     -> the same, and ok:false escalates only for the string reasons "exploration-exhausted" and "budget-exceeded" (exact match)
//   objectiveSignal [res]       -> "ok" for mode "none" / "objective", and for mode "mismatch" only when onMismatch is exactly "heuristic"; else "deny"
//   tightenRiskInputs [baseline, objective] -> {reversibility, blastRadius, semanticDistance}: when all four of baseline / objective reversibility and
//                                  blastRadius are finite NUMBERS (a numeric string is not), reversibility = min, blastRadius = max; otherwise 0 and 1.
//                                  semanticDistance = objective.semanticDistance when a finite number, else 1. No clamping: 2 and -1 pass through.
//                                  A null / missing baseline or objective is a refusal (the three signal functions never refuse).
import { Oracle, refWrite } from './lib.mjs';

const F: any = await import('../../../packages/pca/src/frontier-signals.ts');
const o = new Oracle('frontier-signals', 'tools/pca-audit/oracles/frontier-signals.mts', 'TS-reference oracle for packages/pca/src/frontier-signals.ts.');
const NUM: any = { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity };
const revive = (v: any): any => Array.isArray(v) ? v.map(revive)
  : v && typeof v === 'object' ? ('$num' in v && Object.keys(v).length === 1 ? NUM[v.$num] : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, revive(x)]))) : v;
let n = 0;
const run = (fn: string, name: string, args: any[]) => o.run(fn, `${name}#${n++}`, (...a: any[]) => F[fn](...a.map(revive)), args);
const nan = { $num: 'NaN' }, inf = { $num: 'Infinity' }, ninf = { $num: '-Infinity' };

// results that are not a result at all (every signal function denies them)
const JUNK: any[] = [null, true, false, 0, 1, '', 'ok', 'true', [], [true], [{ ok: true }], {}];
const OKS: any[] = [true, false, 'true', 'false', 1, 0, null, {}, [], [true], nan];
for (const fn of ['semanticSignal', 'progressSignal', 'objectiveSignal']) for (const j of JUNK) await run(fn, 'junk/' + JSON.stringify(j), [j]);

for (const ok of OKS) {
  await run('semanticSignal', 'ok/' + JSON.stringify(ok), [{ ok }]);
  await run('semanticSignal', 'ok+extra/' + JSON.stringify(ok), [{ ok, score: 0.9, quorum: 3, reason: 'budget-exceeded' }]);
}
for (const r of [{ OK: true }, { Ok: true }, { ok: true, mode: 'none' }, { result: { ok: true } }, { ok: false, reason: 'exploration-exhausted' }]) await run('semanticSignal', 'shape/' + JSON.stringify(r), [r]);

const REASONS: any[] = ['exploration-exhausted', 'budget-exceeded', 'Exploration-Exhausted', 'BUDGET-EXCEEDED', 'budget-exceeded ', ' budget-exceeded', 'budget_exceeded', 'budget-exceeded\u0000',
  'exploration', '', 'no-progress', 'bad-signature', 'seq-gap', 'prev-mismatch', 'goal-mismatch', 'malformed', 'guard-violated', 'potential-error', 'constructor', '__proto__', 'has',
  null, 5, true, ['budget-exceeded'], { reason: 'budget-exceeded' }];
for (const ok of OKS) await run('progressSignal', 'ok/' + JSON.stringify(ok), [{ ok }]);
for (const reason of REASONS) for (const ok of [false, true, 'false', null]) await run('progressSignal', `reason/${JSON.stringify(reason)}/${JSON.stringify(ok)}`, [{ ok, reason }]);
await run('progressSignal', 'charge', [{ ok: true, charge: 1 }]);
await run('progressSignal', 'no-ok', [{ reason: 'budget-exceeded' }]);

const MODES: any[] = ['none', 'objective', 'mismatch', 'None', 'OBJECTIVE', 'mismatch ', '', 'heuristic', 'deny', 'constructor', null, 5, true, ['none'], {}];
const ONMIS: any[] = [undefined, 'heuristic', 'deny', 'Heuristic', 'heuristic ', '', null, true, 1, ['heuristic'], {}];
for (const mode of MODES) for (const onMismatch of ONMIS) await run('objectiveSignal', `mode/${JSON.stringify(mode)}/${JSON.stringify(onMismatch)}`, [{ mode, onMismatch }]);
await run('objectiveSignal', 'no-mode/heuristic', [{ onMismatch: 'heuristic' }]);
await run('objectiveSignal', 'full/objective', [{ mode: 'objective', inputs: { reversibility: 0.5, blastRadius: 0.25, semanticDistance: 0.125 }, r: 0.5, evidenceDigest: 'sha256:x' }]);
await run('objectiveSignal', 'full/mismatch-deny', [{ mode: 'mismatch', reasons: ['calibration set does not match the committed digest'], onMismatch: 'deny' }]);
await run('objectiveSignal', 'full/mismatch-heuristic', [{ mode: 'mismatch', reasons: ['x'], onMismatch: 'heuristic' }]);
await run('objectiveSignal', 'snake-case', [{ mode: 'mismatch', on_mismatch: 'heuristic' }]);

// tightenRiskInputs: the value grid for each pair, then every position holding a non-finite / non-number value
const V: any[] = [0, -0, 0.25, 0.5, 1, 2, -1, 1e-9, 5e-324, 2 ** 53, 0.1 + 0.2];
const BAD: any[] = [nan, inf, ninf, '0.5', '', null, undefined, true, [], [0.5], {}];
const tr = (name: string, b: any, ob: any) => run('tightenRiskInputs', name, [b, ob]);
for (const a of V) for (const b of V) {
  await tr(`rev/${a}/${b}`, { reversibility: a, blastRadius: 0.25 }, { reversibility: b, blastRadius: 0.5, semanticDistance: 0.125 });
  await tr(`blast/${Object.is(a, -0) ? '-0' : a}/${Object.is(b, -0) ? '-0' : b}`, { reversibility: 0.75, blastRadius: a }, { reversibility: 0.5, blastRadius: b, semanticDistance: 0.125 });
}
for (const [i, bad] of BAD.entries()) {
  await tr(`bad/b.rev/${i}`, { reversibility: bad, blastRadius: 0.25 }, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: 0.125 });
  await tr(`bad/b.blast/${i}`, { reversibility: 0.75, blastRadius: bad }, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: 0.125 });
  await tr(`bad/o.rev/${i}`, { reversibility: 0.75, blastRadius: 0.25 }, { reversibility: bad, blastRadius: 0.5, semanticDistance: 0.125 });
  await tr(`bad/o.blast/${i}`, { reversibility: 0.75, blastRadius: 0.25 }, { reversibility: 0.5, blastRadius: bad, semanticDistance: 0.125 });
  await tr(`bad/o.sd/${i}`, { reversibility: 0.75, blastRadius: 0.25 }, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: bad });
  await tr(`bad/all/${i}`, { reversibility: bad, blastRadius: bad }, { reversibility: bad, blastRadius: bad, semanticDistance: bad });
  // a non-finite semanticDistance together with finite risk inputs, and the reverse, are independent
  await tr(`bad/b.sd-ignored/${i}`, { reversibility: 0.75, blastRadius: 0.25, semanticDistance: bad }, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: 0.125 });
}
for (const sd of V) await tr(`sd/${Object.is(sd, -0) ? '-0' : sd}`, { reversibility: 0.75, blastRadius: 0.25 }, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: sd });
await tr('extra-members', { reversibility: 0.75, blastRadius: 0.25, taint: 1, age: 1 }, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: 0.125, taint: 0, confidence: 1 });
await tr('empty/empty', {}, {});
await tr('empty-baseline', {}, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: 0.125 });
await tr('empty-objective', { reversibility: 0.75, blastRadius: 0.25 }, {});
for (const [bn, b] of [['null', null], ['number', 5], ['string', 'x'], ['array', []]] as any[]) {
  await tr(`nonobj-baseline/${bn}`, b, { reversibility: 0.5, blastRadius: 0.5, semanticDistance: 0.125 });
  await tr(`nonobj-objective/${bn}`, { reversibility: 0.75, blastRadius: 0.25 }, b);
}
console.log('cases', o.cases.length);
refWrite(o, 'frontier-signals');
