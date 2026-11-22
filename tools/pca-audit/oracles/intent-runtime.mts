// Oracle: @atlasauth/pca-intent runtime digests (runtime.ts), effect postconditions (effects.ts), trust ramp parts (ramp.ts), question cards (ux.ts).
// The learner-bound functions take a stub learner in the reference ({omega, acceptance: () => p}); the native takes (vs, o, p).
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality):
//   pcactnActionOf(vs, o)                       IntentRuntime.pcactnActionOf
//   judgeInputOf(omega, o, p, ctx)              IntentRuntime.judgeInputOf(verbSpace(omega, o.verb), o, p, ctx)
//   calibrationDigest(c) / icAttDigest(att) / jitConsentDigest(req) / foldSemanticRisk(r, att)
//   jitConsentRequest(omega, o, p, ctx)         IntentRuntime.jitConsentRequest(vs, o, p, ctx.intentRef, ctx.mapDigest)
//   defaultPostconditions()                     IntentEffects.DEFAULT_POSTCONDITIONS
//   effectContext(vs, o, effect) / checkPostconditions(vs, o, effect, pcs?)
//   signalLabel(s) / narrowStart(omega, slots, opts) / driftRun(opts, seq) -> list of states (or throw on bad opts)
//   questionCard(omega, q) / parseCardAnswer(card, input)
import * as RT0 from '../../../packages/pca-intent/src/runtime';
import * as EF0 from '../../../packages/pca-intent/src/effects';
import * as RA0 from '../../../packages/pca-intent/src/ramp';
import * as UX0 from '../../../packages/pca-intent/src/ux';
import * as OM0 from '../../../packages/pca-intent/src/omega';
import { Oracle, refWrite } from './lib.mjs';

const RT: any = (RT0 as any).default ?? RT0;
const EF: any = (EF0 as any).default ?? EF0;
const RA: any = (RA0 as any).default ?? RA0;
const UX: any = (UX0 as any).default ?? UX0;
const O: any = (OM0 as any).default ?? OM0;
const o = new Oracle('intent-runtime', 'tools/pca-audit/oracles/intent-runtime.mts', 'TS-reference oracle for intent runtime, effects, ramp and cards.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const amt = (op: string, v: number) => ({ field: 'action.params.amount', op, value: v });
const om = O.deriveOmega({ policies: [{ predicates: [
  { verb: 'stripe.refund', where: [amt('lte', 100), { field: 'action.params.recipient', op: 'in', value: ['bob', 'alice'] }] },
  { verb: 'stripe.charge', where: [amt('lte', 50)] }, { verb: 'gmail.send', where: [{ field: 'action.params.to', op: 'prefix', value: 'team-' }] },
  { verb: 'files.write', resource: '/shared/*' }, { verb: 'calendar.create_event', where: [{ field: 'env.hour', op: 'gte', value: 9 }] },
  { verb: 'github.merge_pr', resource: 'org/repo' }, { verb: 'slack.post_message', where: [{ field: 'action.params.channel', op: 'eq', value: 'general' }] }, { verb: 'zzz.custom', where: [amt('lte', 5)] }] }] });
const ctx = { intentRef: 'ref1', mapDigest: 'md1', statementText: 'refund up to 100', slots: { verbs: ['stripe.refund'], constraints: [] }, goalCommitment: 'gc1' };
const outs: { vs: any; ov: any; f: number }[] = [];
for (const vs of om.verbs) { const t = O.verbCellCount(vs); for (const f of [0, Math.floor(t / 2), t - 1]) if (f < t) outs.push({ vs, ov: O.cellRep(vs, O.decodeCell(vs, f)), f }); }

// ---- runtime ----
for (const { vs, ov } of outs) {
  await run('pcactnActionOf', RT.pcactnActionOf, [vs, ov]);
  await run('judgeInputOf', (omg: any, oo: any, p: number, c: any) => RT.judgeInputOf({ omega: omg, acceptance: () => p }, oo, c), [{ ...om, verbs: [vs] }, ov, 0.37, ctx]);
  await run('jitConsentRequest', (omg: any, oo: any, p: number, c: any) => RT.jitConsentRequest({ omega: omg, acceptance: () => p }, oo, c), [{ ...om, verbs: [vs] }, ov, 0.123456, { intentRef: 'r', mapDigest: 'm' }]);
}
const reqs: any[] = [RT.jitConsentRequest({ omega: { ...om, verbs: [outs[0].vs] }, acceptance: () => 0.5 }, outs[0].ov, { intentRef: 'r', mapDigest: 'm' }), { v: 1, kind: 'x' }, {}];
for (const r of reqs) await run('jitConsentDigest', RT.jitConsentDigest, [r]);
for (const c of [{ alpha: 0.1, samples: [{ score: 0.9, faithful: true }, { score: 0.2, faithful: false }] }, { alpha: 0.05, samples: [] }, { alpha: 0.1, samples: [{ score: 0.5, faithful: true, extra: 1 }] }]) await run('calibrationDigest', RT.calibrationDigest, [c]);
const atts: any[] = [{ v: 1, kind: 'pca-ic-att', intent_ref: 'a', map_digest: 'b', action_digest: 'c', goal_commitment: 'd', verdict_digests: ['x', 'y'], calibration_digest: null, k: 2, ok: true, agree_count: 2, aggregate_score_ppm: 850000, cutoff_ppm: null },
  { v: 1, kind: 'pca-ic-att', intent_ref: 'a', map_digest: 'b', action_digest: 'c', goal_commitment: 'd', verdict_digests: [], calibration_digest: 'z', k: 1, ok: false, agree_count: 0, aggregate_score_ppm: 0, cutoff_ppm: 500000, reason: 'nope' }, { aggregate_score_ppm: 1000000 }, { aggregate_score_ppm: -5 }, { aggregate_score_ppm: 2000000 }];
for (const a of atts) { await run('icAttDigest', RT.icAttDigest, [a]); for (const r of [0, 0.1, 0.5, 0.9, 1]) await run('foldSemanticRisk', RT.foldSemanticRisk, [r, a]); }

// ---- effects ----
await run('defaultPostconditions', () => EF.DEFAULT_POSTCONDITIONS, []);
const effects: any[] = [{ amount: 5, recipient: 'bob' }, { amount: 600, recipient: 'bob' }, { amount: 5 }, {}, { amount: -1, recipient: 'x' }, { amount: 'x', recipient: 'bob' }, { recipient: 'zzz' }, { to: 'team-1', channel: 'general', path: '/shared/a', repo: 'org/repo', hour: 9 },
  { to: 'evil', channel: 'other', path: '/other', repo: 'other/repo', hour: 3 }, { amount: null }, { amount: 5, extra: { deep: 1 } }];
for (const { vs, ov } of outs) for (const e of effects) {
  await run('checkPostconditions', EF.checkPostconditions, [vs, ov, e]);
}
for (const { vs, ov } of outs.slice(0, 3)) await run('effectContext', EF.effectContext, [vs, ov, { amount: 1 }]);
const customPcs: any[] = [{ id: 'c1', verb: 'stripe.refund', description: 'd', where: [{ any_of: [{ field: 'env.effect.amount', op: 'lte', value: 10 }, { not: { field: 'env.effect.recipient', op: 'eq', value: 'x' } }] }] },
  { id: 'c2', verb: 'stripe.refund', description: 'd', where: [{ all_of: [{ field: 'env.effect.k', op: 'eq', ref: 'env.effect.m' }] }] }, { id: 'c3', verb: 'stripe.refund', description: 'd', where: [{ field: 'env.effect.q', op: 'gt', ref: 'action.params.nope' }] }];
for (const { vs, ov } of outs.filter((x) => x.vs.verb === 'stripe.refund')) for (const e of [{ amount: 5, recipient: 'x', k: 1, m: 1 }, { amount: 50, recipient: 'x', k: 1, m: 2 }, { amount: 5 }, {}]) {
  await run('checkPostconditions', EF.checkPostconditions, [vs, ov, e, customPcs]);
  await run('checkPostconditions', EF.checkPostconditions, [vs, ov, e, []]);
}

// ---- ramp ----
for (const s of ['jit-approve', 'principal-confirm', 'jit-refuse', 'challenge-upheld', 'judge-deny-upheld', 'postcondition-violation', 'bogus']) await run('signalLabel', RA.signalLabel, [s]);
for (const sl of [{ verbs: ['stripe.refund'], constraints: [] }, { verbs: [], constraints: [] }, { verbs: ['stripe.refund', 'gmail.send', 'nope'], constraints: [] }]) for (const opts of [undefined, {}, { slotNullMass: 0.3 }, { otherNullMass: 0.99 }, { slotNullMass: 0.1, otherNullMass: 0.8 }]) await run('narrowStart', (omg: any, s: any, oo: any) => RA.narrowStart(omg, s, oo ?? {}), [om, sl, opts ?? {}]);
const drift = (opts: any, seq: boolean[]) => { const d = new RA.DriftDetector(opts); const out: any[] = []; for (const x of seq) out.push(d.update(x)); out.push(d.state); d.reset(); out.push(d.state); return out; };
const seqs: boolean[][] = [[], [true], [true, true], [false, false, false], [true, false, true, true, true, true], Array(40).fill(false), [...Array(10).fill(false), ...Array(6).fill(true)], [true, true, true, true, true, true, true, true, false, false, false, false, false, false, false, false, false, false]];
for (const opts of [{}, { rho0: 0.01, rho1: 0.5 }, { h: 1 }, { h: 10 }, { rho0: 0.1, rho1: 0.2, h: 2 }, { rho0: 0, rho1: 0.2 }, { rho0: 0.3, rho1: 0.2 }, { rho0: 0.1, rho1: 1 }, { h: 0 }, { h: -1 }]) for (const sq of seqs) await run('driftRun', drift, [opts, sq]);

// ---- ux ----
for (const vs of om.verbs) {
  const t = O.verbCellCount(vs);
  for (const f of [0, Math.floor(t / 2), t - 1]) if (f < t) await run('questionCard', (omg: any, q: any) => UX.questionCard(omg, q), [{ ...om, verbs: [vs] }, { verb: vs.verb, cell: O.decodeCell(vs, f) }]);
}
await run('questionCard', (omg: any, q: any) => UX.questionCard(omg, q), [om, { verb: 'nope', cell: [] }]);
await run('questionCard', (omg: any, q: any) => UX.questionCard(omg, q), [{ ...om, verbs: [om.verbs[0]] }, { verb: om.verbs[0].verb, cell: [99, 0] }]);
const refundVs = om.verbs.find((v: any) => v.verb === 'stripe.refund');
const tR = O.verbCellCount(refundVs);
const cards = [0, Math.floor(tR / 2), tR - 1].map((f) => UX.questionCard({ ...om, verbs: [refundVs] }, { verb: 'stripe.refund', cell: O.decodeCell(refundVs, f) }));
const amtSlot = cards[1].partial.find((s: any) => s.path === 'action.params.amount'); const recSlot = cards[1].partial.find((s: any) => s.path === 'action.params.recipient');
const inputs: any[] = [{ answer: 'yes' }, { answer: 'no' }, { answer: 'bogus' }, {}, { answer: 'partly' },
  { answer: 'partly', path: 'action.params.amount', upTo: amtSlot.lo }, { answer: 'partly', path: 'action.params.amount', upTo: amtSlot.hi }, { answer: 'partly', path: 'action.params.amount', upTo: amtSlot.hi - 1 }, { answer: 'partly', path: 'action.params.amount', upTo: amtSlot.lo - 1 },
  { answer: 'partly', path: 'action.params.amount', upTo: 1.5 }, { answer: 'partly', path: 'action.params.amount', upTo: '5' }, { answer: 'partly', path: 'action.params.amount', from: amtSlot.lo }, { answer: 'partly', path: 'action.params.amount', from: amtSlot.lo + 1 }, { answer: 'partly', path: 'action.params.amount', from: amtSlot.hi },
  { answer: 'partly', path: 'action.params.amount', from: amtSlot.hi + 1 }, { answer: 'partly', path: 'action.params.amount', except: [amtSlot.lo] }, { answer: 'partly', path: 'action.params.amount', except: [amtSlot.hi, amtSlot.lo, amtSlot.lo] }, { answer: 'partly', path: 'action.params.amount', except: [] },
  { answer: 'partly', path: 'action.params.amount', except: [amtSlot.hi + 1] }, { answer: 'partly', path: 'action.params.amount', except: ['x'] }, { answer: 'partly', path: 'action.params.amount', except: 'abc' }, { answer: 'partly', path: 'action.params.amount', except: null },
  { answer: 'partly', path: 'action.params.amount', except: 5 }, { answer: 'partly', path: 'action.params.amount' }, { answer: 'partly', path: 'action.params.amount', notFor: ['x'] },
  { answer: 'partly', path: 'action.params.recipient', notFor: ['bob', 'bob', '', 5, 'eve'] }, { answer: 'partly', path: 'action.params.recipient', notFor: [] }, { answer: 'partly', path: 'action.params.recipient', notFor: [1, ''] }, { answer: 'partly', path: 'action.params.recipient' }, { answer: 'partly', path: 'action.params.recipient', notFor: 'bob' }, { answer: 'partly', path: 'action.params.recipient', upTo: 3 },
  { answer: 'partly', path: 'nope' }, { answer: 'partly', path: 5 }, { answer: 'partly', path: null }, { answer: 'partly', newField: 'action.params.currency', notFor: ['usd', 'eur', 'usd'] }, { answer: 'partly', newField: 'action.params.currency', notFor: [] },
  { answer: 'partly', newField: 'action.resource', notFor: ['/x'] }, { answer: 'partly', newField: 'action.params.amount', notFor: ['x'] }, { answer: 'partly', newField: 'Action.params.x', notFor: ['x'] }, { answer: 'partly', newField: 'action.params.1x', notFor: ['x'] }, { answer: 'partly', newField: 5, notFor: ['x'] },
  { answer: 'partly', newField: 'action.params.currency' }, { answer: 'partly', newField: 'action.params.currency', notFor: 'usd' }, { answer: 'partly', newField: 'action.params.cur\n', notFor: ['x'] }];
for (const c of cards) for (const i of inputs) await run('parseCardAnswer', UX.parseCardAnswer, [c, i]);
refWrite(o, 'intent-runtime');
