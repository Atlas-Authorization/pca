// Oracle: @atlasauth/pca-intent lazy just-in-time elicitation (jit.ts): decideVisit, cellCoords, cellFromCoords, deltaCells, deltaPredicates, intentRequiredBody / signedIntentRequired,
// walletCheckIntentRequired, mintDelta. Deterministic: keys from fixed seeds, fixed salts, fixed clocks.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   visitScenario(omega, mapOpts, observations, lifted, conform, ceilingNames, inEffective) -> decideVisit(...) (IntentJit.decideVisit); ceiling names: "all" (true), "none" (false),
//     "amountLe60" (the amount value, when a number, is <= 60; other outcomes pass), "notGmail" (verb != gmail.send)
//   cellCoords(vs, cell) / cellFromCoords(vs, coords)    IntentJit.cellCoords / cellFromCoords (null or the index list)
//   deltaScenario(omega, mapOpts, prevObservations, nextObservations) -> {cells: {verb: [0/1...]}, predicates}: deltaCells(prev, next) (next = prev's observations followed by nextObservations)
//   requiredScenario(input, vsVerb, cell, kidSeed) -> {body: intentRequiredBody, signed: signedIntentRequired(input, kid "site-1", site key from seed)}
//   walletScenario(omega, input, mutation, nowDelta) -> walletCheckIntentRequired over the signed body with fixed mutations
//   mintScenario(omega, mapOpts, prevObservations, nextObservations, mintArgs) -> mintDelta(prev, next, args + principal from the seed) or null
import * as J0 from '../../../packages/pca-intent/src/jit';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as INT0 from '../../../packages/pca/src/ext/intent';
import * as K0 from '../../../packages/pca/src/keys';
import { Oracle, refWrite, seed } from './lib.mjs';
import { sha256 } from '@noble/hashes/sha2';

const J: any = (J0 as any).default ?? J0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const INT: any = (INT0 as any).default ?? INT0;
const publicKeyOf: any = ((K0 as any).default ?? K0).publicKeyOf;
const o = new Oracle('intent-jit', 'tools/pca-audit/oracles/intent-jit.mts', 'TS-reference oracle for lazy JIT elicitation.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const dig = (x: string) => Buffer.from(sha256(new TextEncoder().encode(x))).toString('base64url');
const A = 'action.params.';
const num = (path: string, lo: number, hi: number, cuts: number[], dist = 'uniform') => ({ kind: 'num', path, lo, hi, cuts, dist });
const cat = (path: string, exacts: string[], prefixes: string[] = []) => ({ kind: 'cat', path, values: [...exacts.map((v) => ({ kind: 'exact', value: v })), ...prefixes.map((v) => ({ kind: 'prefix', value: v })), { kind: 'other', value: '⊥' }] });
const vsp = (verb: string, reversibility: string, weight: number, dims: any[]) => ({ verb, reversibility, weight, dims });
const refund = vsp('stripe.refund', 'irreversible', 0.5, [num(A + 'amount', 0, 100, [10, 50]), cat(A + 'recipient', ['bob'], ['team-'])]);
const send = vsp('gmail.send', 'rate_limited', 0.5, [cat(A + 'to', ['a', 'b'], ['p-'])]);
const OM = { v: 1, verbs: [refund, send], approximate: [] };
const OA = { v: 1, verbs: [{ ...refund, weight: 1 }], approximate: [] };
const mk = (omega: any, mo: any, obs: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return l; };
const allCells = (vs: any): number[][] => { const t = O.verbCellCount(vs); const r: number[][] = []; for (let f = 0; f < t; f++) r.push(O.decodeCell(vs, f)); return r; };
const ob = (vs: any, idx: number[], y: number, source = 'elicitation') => ({ verb: vs.verb, values: O.cellRep(vs, idx).values, y, source });
const cellsOfRefund = allCells(refund);

// ---- visit ----
const named: Record<string, any> = { all: () => true, none: () => false, amountLe60: (_vs: any, oc: any) => { const a = oc.values[A + 'amount']; return typeof a !== 'number' || a <= 60; }, notGmail: (_vs: any, oc: any) => oc.verb !== 'gmail.send' };
const visitScenario = (omega: any, mo: any, obs: any[], lifted: any, conform: any, ceil: string[], inEff: boolean) => J.decideVisit({ learner: mk(omega, mo, obs), lifted, conform, ceilings: ceil.map((c) => named[c]), inEffective: inEff });
const okConf = { ok: true, verb: { verb: 'stripe.refund' } };
const yesLow = cellsOfRefund.filter((c) => c[0] === 0).map((c) => ob(refund, c, 1));
const obsA = [...yesLow, ob(refund, [2, 0], 0), ob(refund, [1, 1], 1)];
const liftedOf = (idx: number[]) => O.cellRep(refund, idx);
for (const idx of [[0, 0], [0, 1], [1, 0], [1, 1], [2, 0], [2, 2], [1, 2]]) {
  for (const ceil of [[], ['all'], ['amountLe60'], ['none'], ['all', 'amountLe60', 'notGmail']]) for (const inEff of [false, true]) {
    await run('visitScenario', visitScenario, [OA, {}, obsA, liftedOf(idx), okConf, ceil, inEff]);
  }
  await run('visitScenario', visitScenario, [OA, { eta: 0.1 }, obsA, liftedOf(idx), okConf, [], false]);
  await run('visitScenario', visitScenario, [OA, {}, [...obsA, ob(refund, idx, 0, 'runtime')], liftedOf(idx), okConf, [], false]);
  await run('visitScenario', visitScenario, [OA, {}, [], liftedOf(idx), okConf, [], false]);
}
await run('visitScenario', visitScenario, [OA, {}, obsA, liftedOf([0, 0]), { ok: false, code: 'bad_type', reason: 'amount must be an integer' }, [], false]);
await run('visitScenario', visitScenario, [OA, {}, obsA, liftedOf([0, 0]), { ok: false, code: 'unknown_verb' }, ['none'], true]);
await run('visitScenario', visitScenario, [OA, {}, obsA, { verb: 'nope', values: {} }, okConf, [], false]);
await run('visitScenario', visitScenario, [OA, {}, obsA, { verb: 'stripe.refund', values: { [A + 'amount']: 1000, [A + 'recipient']: 'bob' } }, okConf, [], false]);
await run('visitScenario', visitScenario, [OM, {}, [], O.cellRep(send, [0]), okConf, ['notGmail'], false]);

// ---- coords ----
for (const vs of OM.verbs) for (const c of allCells(vs)) { await run('cellCoords', J.cellCoords, [vs, c]); await run('cellFromCoords', J.cellFromCoords, [vs, J.cellCoords(vs, c)]); }
const vsR = refund;
for (const bad of [{}, { [A + 'amount']: [1, 1] }, { [A + 'amount']: [1, 2], [A + 'recipient']: ['bob'] }, { [A + 'amount']: [1, 1], [A + 'recipient']: ['nobody'] }, { [A + 'amount']: [1, 1], [A + 'recipient']: ['bob', 'x'] }, { [A + 'amount']: [1, 1], [A + 'recipient']: [] },
  { [A + 'amount']: ['1', '1'], [A + 'recipient']: ['bob'] }, { [A + 'amount']: [1.5, 1.5], [A + 'recipient']: ['bob'] }, { [A + 'amount']: [1], [A + 'recipient']: ['bob'] }, { [A + 'amount']: [99, 99], [A + 'recipient']: ['bob'] }, { [A + 'amount']: [1, 1], [A + 'recipient']: [5] },
  { [A + 'amount']: [1, 1], [A + 'recipient']: ['team-'] }, { [A + 'amount']: [1, 1], [A + 'recipient']: ['⊥'] }, { [A + 'amount']: [1, 1], [A + 'other']: ['bob'] }, { [A + 'amount']: [1, 1], [A + 'recipient']: ['bob'], extra: [1] }, { [A + 'amount']: 5, [A + 'recipient']: ['bob'] }, { [A + 'amount']: [-1, -1], [A + 'recipient']: ['bob'] }])
  await run('cellFromCoords', J.cellFromCoords, [vsR, bad]);

// ---- delta ----
const deltaScenario = (omega: any, mo: any, a: any[], b: any[]) => {
  const prev = mk(omega, mo, a); const next = mk(omega, mo, [...a, ...b]);
  const d = J.deltaCells(prev, next);
  const cells: any = {}; for (const [k, v] of d) cells[k] = Array.from(v as Uint8Array);
  return { cells, predicates: J.deltaPredicates(next.omega, d) };
};
await run('deltaScenario', deltaScenario, [OA, {}, [], yesLow]);
await run('deltaScenario', deltaScenario, [OA, {}, yesLow, [ob(refund, [1, 0], 1), ob(refund, [1, 1], 1)]]);
await run('deltaScenario', deltaScenario, [OA, {}, yesLow, [ob(refund, [1, 0], 0)]]);
await run('deltaScenario', deltaScenario, [OA, {}, yesLow, []]);
await run('deltaScenario', deltaScenario, [OA, {}, obsA, cellsOfRefund.map((c) => ob(refund, c, 1))]);
await run('deltaScenario', deltaScenario, [OM, {}, yesLow, [...allCells(send).map((c) => ob(send, c, 1)), ob(refund, [1, 0], 1)]]);
await run('deltaScenario', deltaScenario, [OM, { eta: 0.1 }, [], [...allCells(send).map((c) => ob(send, c, 1))]]);

// ---- intent_required ----
const unseed = (x: string) => new Uint8Array(Buffer.from(x, 'base64url'));
const SITE = seed('intent-jit/site'); const SITE_SEED = Buffer.from(SITE).toString('base64url'); const SITE_PK = Buffer.from(publicKeyOf(SITE)).toString('base64url');
const PRINC = seed('intent-jit/principal'); const PRINC_SEED = Buffer.from(PRINC).toString('base64url'); const PRINC_PK = Buffer.from(publicKeyOf(PRINC)).toString('base64url');
const KEYS = [{ kid: 'site-1', alg: 'ed25519', pk: SITE_PK }];
const pcactn = (verb: string, resource = '*', extra: any = {}) => ({ v: 2, node: 'n1', action: { verb, resource, params_digest: dig('p-' + verb), reversibility_class: 'irreversible' }, ...extra });
const reqIn = (over: any = {}) => ({ session: dig('s'), mapDigest: dig('m'), schemaDigest: dig('schema'), pcactn: pcactn('stripe.refund'), questionId: 'q-1', friction: 'tap', deliveredTo: 'wallet', expiresAt: 2_000_000_000_000, ...over });
const requiredScenario = (omega: any, verb: string, cell: number[], inp: any, siteSeed: string) => {
  const vs = omega.verbs.find((v: any) => v.verb === verb);
  const body = J.intentRequiredBody({ ...inp, vs, cell });
  return { body, signed: J.signedIntentRequired({ ...inp, vs, cell }, 'site-1', unseed(siteSeed)) };
};
for (const idx of [[0, 0], [1, 1], [2, 2]]) for (const over of [{}, { friction: 'hold', deliveredTo: 'agent' }, { questionId: 'a_b-9' }, { expiresAt: 0 }, { session: 'short' }, { friction: 'nope' }, { questionId: '' }, { deliveredTo: 'x' }, { mapDigest: 5 }]) {
  await run('requiredScenario', requiredScenario, [OM, 'stripe.refund', idx, reqIn(over), SITE_SEED]);
}
await run('requiredScenario', requiredScenario, [OM, 'gmail.send', [1], reqIn({ pcactn: pcactn('gmail.send') }), SITE_SEED]);
await run('requiredScenario', requiredScenario, [OM, 'nope', [0], reqIn(), SITE_SEED]);

const NOW = 1_800_000_000_000;
const walletScenario = (omega: any, inp: any, mutation: string, now: number, lifted: any, session: string, mapDigest: string, siteSeed: string) => {
  const vs = omega.verbs.find((v: any) => v.verb === 'stripe.refund');
  let body: any = J.signedIntentRequired({ ...inp, vs, cell: [1, 0] }, 'site-1', unseed(siteSeed));
  body = JSON.parse(JSON.stringify(body));
  if (mutation === 'coords') body.cell.coords[A + 'amount'] = [2, 2];
  else if (mutation === 'verb') body.cell.verb = 'gmail.send';
  else if (mutation === 'sig') body.sig.value = body.sig.value.slice(0, -2) + 'AA';
  else if (mutation === 'kid') body.sig.kid = 'other';
  else if (mutation === 'session') body.session = dig('other');
  else if (mutation === 'action') body.action_digest = dig('other');
  else if (mutation === 'null') body = null;
  return J.walletCheckIntentRequired(body, { keys: [{ kid: 'site-1', alg: 'ed25519', pk: Buffer.from(publicKeyOf(unseed(siteSeed))).toString('base64url') }], now, session, mapDigest, omegaTilde: omega, lifted, pcactn: inp.pcactn });
};
const liftedA = O.cellRep(refund, [1, 0]);
for (const mutation of ['none', 'coords', 'verb', 'sig', 'kid', 'session', 'action', 'null']) {
  await run('walletScenario', walletScenario, [OM, reqIn(), mutation, NOW, liftedA, dig('s'), dig('m'), SITE_SEED]);
}
await run('walletScenario', walletScenario, [OM, reqIn(), 'none', 2_100_000_000_000, liftedA, dig('s'), dig('m'), SITE_SEED]);
await run('walletScenario', walletScenario, [OM, reqIn(), 'none', NOW, liftedA, dig('other'), dig('m'), SITE_SEED]);
await run('walletScenario', walletScenario, [OM, reqIn(), 'none', NOW, liftedA, dig('s'), dig('other'), SITE_SEED]);
await run('walletScenario', walletScenario, [OM, reqIn(), 'none', NOW, O.cellRep(refund, [2, 0]), dig('s'), dig('m'), SITE_SEED]);
await run('walletScenario', walletScenario, [OM, reqIn(), 'none', NOW, { verb: 'nope', values: {} }, dig('s'), dig('m'), SITE_SEED]);
await run('walletScenario', walletScenario, [OM, reqIn(), 'none', NOW, { verb: 'stripe.refund', values: { [A + 'amount']: 5000, [A + 'recipient']: 'bob' } }, dig('s'), dig('m'), SITE_SEED]);
await run('walletScenario', walletScenario, [OM, reqIn({ pcactn: pcactn('stripe.refund', '*', { extra: 1 }) }), 'none', NOW, liftedA, dig('s'), dig('m'), SITE_SEED]);
await run('walletScenario', walletScenario, [OM, reqIn(), 'none', 1.5, liftedA, dig('s'), dig('m'), SITE_SEED]);

// ---- mint ----
const SALT = 'fixed-salt-0123456789ab';
const baseMint = (over: any = {}) => ({ holder: PRINC_PK, session: dig('s'), seq: 1, root: dig('root'), mapDigest: dig('m1'), salt: SALT, ...over });
const g0 = INT.mintSessionGrant({ principalSecret: PRINC, principalPublic: PRINC_PK, holder: PRINC_PK, session: dig('s'), seq: 0, root: dig('root'), mapDigest: dig('m0'), predicates: [], salt: SALT }).grant;
const mintScenario = (omega: any, mo: any, a: any[], b: any[], args: any, princSeed: string) => {
  const prev = mk(omega, mo, a); const next = mk(omega, mo, [...a, ...b]);
  const r = J.mintDelta(prev, next, { principalSecret: unseed(princSeed), principalPublic: Buffer.from(publicKeyOf(unseed(princSeed))).toString('base64url'), ...args });
  return r;
};
for (const [a, b] of [[[], yesLow], [yesLow, [ob(refund, [1, 0], 1), ob(refund, [1, 1], 1)]], [yesLow, [ob(refund, [1, 0], 0)]], [yesLow, []]] as any[]) {
  await run('mintScenario', mintScenario, [OA, {}, a, b, { ...baseMint(), prevGrant: g0 }, PRINC_SEED]);
  await run('mintScenario', mintScenario, [OA, {}, a, b, { ...baseMint({ prev: g0.id }), prevGrant: g0 }, PRINC_SEED]);
  await run('mintScenario', mintScenario, [OA, {}, a, b, { ...baseMint({ prev: dig('wrong') }), prevGrant: g0 }, PRINC_SEED]);
  await run('mintScenario', mintScenario, [OA, {}, a, b, { ...baseMint({ mapForm: 'commit', caveats: [{ type: 'reversibility_max', class: 'reversible' }] }), prevGrant: g0 }, PRINC_SEED]);
}
await run('mintScenario', mintScenario, [OA, {}, yesLow, [ob(refund, [1, 0], 1)], { ...baseMint({ mapDigest: 'short' }), prevGrant: g0 }, PRINC_SEED]);
await run('mintScenario', mintScenario, [OA, {}, yesLow, [ob(refund, [1, 0], 1)], { ...baseMint({ seq: 0 }), prevGrant: g0 }, PRINC_SEED]);
refWrite(o, 'intent-jit');
