// Oracle: @atlasauth/pca-intent TrustRamp (ramp.ts) over signed runtime observations (core ext/intent signIntentObservation / verifyIntentObservation). Deterministic: keys from fixed seeds.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   signObservation(o, seedB64u)           IntentObservation.signIntentObservation(o, seed bytes) -> signed observation (a throw requires a throw)
//   verifyObservation(o, opts)             IntentObservation.verifyIntentObservation(o, opts.expectedSigner, opts.pqPins) -> {ok, reason?} ("malformed intent observation: ..." reasons are not in the corpus)
//   rampScenario(omega, mapOpts, observations, driftOpts, ops) -> per-op results then {log, frozen, pending, metrics}
//     driftOpts: {rho0?, rho1?, h?} (IntentTrustRamp ctor, a throw requires a throw); ops: record{outcome, signal} -> RampRecord; observe{obs, ctx{mapDigest, trustedSigners, verify?}} ->
//     {ok:true, record} | {ok:false, reason}; rebase{omega, mapOpts, observations}; state -> {frozen, pending, drift}
import * as RA0 from '../../../packages/pca-intent/src/ramp';
import * as M0 from '../../../packages/pca-intent/src/map';
import * as O0 from '../../../packages/pca-intent/src/omega';
import * as INT0 from '../../../packages/pca/src/ext/intent';
import * as K0 from '../../../packages/pca/src/keys';
import { Oracle, refWrite, seed } from './lib.mjs';
import { sha256 } from '@noble/hashes/sha2';

const RA: any = (RA0 as any).default ?? RA0;
const M: any = (M0 as any).default ?? M0;
const O: any = (O0 as any).default ?? O0;
const INT: any = (INT0 as any).default ?? INT0;
const publicKeyOf: any = ((K0 as any).default ?? K0).publicKeyOf;
const o = new Oracle('intent-ramp', 'tools/pca-audit/oracles/intent-ramp.mts', 'TS-reference oracle for the intent trust ramp.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const runKeep = async (fn: string, f: any, args: any[]) => { try { const r = f(...JSON.parse(JSON.stringify(args))); if (JSON.stringify(r)?.includes('malformed intent observation')) return; } catch {} await run(fn, f, args); };
const dig = (x: string) => Buffer.from(sha256(new TextEncoder().encode(x))).toString('base64url');
const SD = ['a', 'b', 'c'].map((l) => seed('intent-ramp/' + l));
const SDS = SD.map((s) => Buffer.from(s).toString('base64url'));
const PK = SD.map((s) => Buffer.from(publicKeyOf(s)).toString('base64url'));
const MD = dig('map');
const A = 'action.params.';
const flat = { verb: 'v.a', reversibility: 'reversible', weight: 1, dims: [{ kind: 'num', path: A + 'a', lo: 0, hi: 11, cuts: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11], dist: 'uniform' }] };
const OM = { v: 1, verbs: [flat], approximate: [] };
const vs = OM.verbs[0];
const rep = (i: number) => O.cellRep(vs, [i]);
const allYes = Array.from({ length: 12 }, (_, i) => ({ verb: 'v.a', values: rep(i).values, y: 1, source: 'elicitation' }));
const mk = (omega: any, mo: any, obs: any[]) => { const l = M.createLearner(omega, mo); for (const x of obs) l.observe({ verb: x.verb, values: x.values }, x.y, x.source); return l; };

// ---- signed observations ----
const ob = { map_digest: MD, verb: 'v.a', values: { [A + 'a']: 3 }, y: 1, source: 'runtime', observed_at: 1_800_000_000_000 };
const ok0 = (extra: any = {}) => ({ ...ob, ...extra });
const signed = INT.signIntentObservation(ok0(), SD[0]);
const sgn = (x: any, i = 0) => INT.signIntentObservation(x, SD[i]);
const sobs: any[] = [ok0(), ok0({ y: 0 }), ok0({ source: 'witness' }), ok0({ source: 'elicitation' }), ok0({ source: 'import' }), ok0({ values: { [A + 'a']: 3, 'action.resource': 'x' } }), ok0({ values: {} }), ok0({ pcactn_digest: dig('p') }), ok0({ observed_at: 0 }), ok0({ values: { [A + 'a']: -2.5 } })];
const sbad: any[] = [ok0({ y: 2 }), ok0({ y: '1' }), ok0({ source: 'x' }), ok0({ verb: '' }), ok0({ verb: 5 }), ok0({ map_digest: 'short' }), ok0({ values: [] }), ok0({ values: { a: true } }), ok0({ values: { a: null } }), ok0({ observed_at: -1 }), ok0({ observed_at: 1.5 }), ok0({ pcactn_digest: 'x' }), ok0({ pcactn_digest: null }), ok0({ signer: dig('s') })];
for (const s of [...sobs, ...sbad]) for (const i of [0, 1]) await runKeep('signObservation', (x: any, sd: string) => INT.signIntentObservation(x, new Uint8Array(Buffer.from(sd, 'base64url'))), [s, SDS[i]]);
const vc: any[] = [signed, ...sobs.map((s) => sgn(s)), sgn(ok0(), 1), { ...signed, y: 0 }, { ...signed, sig: 5 }, { ...signed, sig: 'AAAA' }, { ...signed, sig: undefined }, { ...signed, verb: 'x' }, { ...signed, values: { [A + 'a']: 4 } }, { ...signed, signer: PK[1] },
  { ...signed, alg: 'ed25519' }, { ...signed, alg: 'ml-dsa-65', pq_pk: 'AAAA' }, { ...signed, alg: 'hybrid-ed25519-ml-dsa-65', pq_pk: 'AAAA', pq_sig: 'AAAA' }, { ...signed, alg: 'nope' }, { ...signed, alg: 5 }, { ...signed, pq_pk: 'x' }, { ...signed, pq_sig: 'x' }, { ...signed, extra: 1 }, null, 5, 'x', [], {}, ...sbad.map((s) => ({ ...s, sig: signed.sig }))];
for (const c of vc) { await runKeep('verifyObservation', INT.verifyIntentObservation, [c, {}]); await runKeep('verifyObservation', INT.verifyIntentObservation, [c, { expectedSigner: PK[0] }]); }
await runKeep('verifyObservation', INT.verifyIntentObservation, [sgn(ok0(), 1), { expectedSigner: PK[0] }]);
await runKeep('verifyObservation', INT.verifyIntentObservation, [{ ...signed, alg: 'ml-dsa-65', pq_pk: 'AAAA' }, { pqPins: { [PK[0]]: 'AAAA' } }]);

// ---- ramp ----
const rec = (i: number, signal: string) => ({ op: 'record', outcome: rep(i), signal });
const sig = (i: number, y: number, k = 0, extra: any = {}) => sgn({ map_digest: MD, verb: 'v.a', values: rep(i).values, y, source: 'runtime', observed_at: 5, ...extra }, k);
const ctx = (extra: any = {}) => ({ mapDigest: MD, trustedSigners: [PK[0], PK[1]], ...extra });
const SIGNALS = ['jit-approve', 'principal-confirm', 'jit-refuse', 'challenge-upheld', 'judge-deny-upheld', 'postcondition-violation'];
const rampScenario = (omega: any, mo: any, obs: any[], dopts: any, ops: any[]) => {
  const ramp = new RA.TrustRamp(mk(omega, mo, obs), dopts);
  const out: any[] = [];
  for (const op of ops) {
    if (op.op === 'record') out.push(ramp.record(op.outcome, op.signal));
    else if (op.op === 'observe') out.push(ramp.recordObservation(op.obs, op.ctx));
    else if (op.op === 'rebase') { ramp.rebase(mk(op.omega, op.mapOpts, op.observations)); out.push({ frozen: ramp.frozen, pending: ramp.pending.length }); }
    else out.push({ frozen: ramp.frozen, pending: ramp.pending, drift: ramp.drift.state });
  }
  return [out, { log: ramp.log, frozen: ramp.frozen, pending: ramp.pending, metrics: ramp.learner.metrics() }];
};
const state = { op: 'state' };
for (const s of SIGNALS) await run('rampScenario', rampScenario, [OM, {}, allYes, {}, [rec(0, s), state, rec(0, s), rec(1, s), state]]);
await run('rampScenario', rampScenario, [OM, {}, allYes, {}, [rec(0, 'jit-refuse'), state, rec(1, 'jit-refuse'), state, rec(2, 'jit-approve'), state, rec(3, 'principal-confirm'), rec(4, 'challenge-upheld'), state, { op: 'rebase', omega: OM, mapOpts: {}, observations: allYes }, state, rec(5, 'jit-approve'), state]]);
await run('rampScenario', rampScenario, [OM, {}, allYes.slice(0, 6), { rho0: 0.05, rho1: 0.5, h: 1 }, [rec(0, 'jit-approve'), rec(8, 'jit-refuse'), rec(9, 'jit-approve'), state, rec(1, 'judge-deny-upheld'), rec(2, 'jit-approve'), state, rec(6, 'postcondition-violation'), state]]);
await run('rampScenario', rampScenario, [OM, {}, allYes, { h: 100 }, Array.from({ length: 8 }, (_, i) => rec(i, 'jit-refuse')).concat([state])]);
await run('rampScenario', rampScenario, [OM, { eta: 0.1 }, allYes, {}, [rec(0, 'jit-refuse'), rec(1, 'jit-refuse'), rec(2, 'jit-approve'), state]]);
for (const d of [{ rho0: 0 }, { rho0: 0.5, rho1: 0.4 }, { rho1: 1 }, { h: 0 }, { h: -1 }]) await run('rampScenario', rampScenario, [OM, {}, allYes, d, [state]]);
await run('rampScenario', rampScenario, [OM, {}, [], {}, [rec(0, 'jit-approve'), rec(0, 'jit-refuse'), state, { op: 'record', outcome: { verb: 'nope', values: {} }, signal: 'jit-refuse' }, { op: 'record', outcome: { verb: 'v.a', values: { [A + 'a']: 99 } }, signal: 'jit-approve' }, state]]);
// signed observations through the ramp
const sops = (list: any[]) => [...list.map((x) => ({ op: 'observe', obs: x, ctx: ctx() })), state];
await run('rampScenario', rampScenario, [OM, {}, allYes, {}, sops([sig(0, 0), sig(1, 0), sig(2, 1), sig(3, 0, 1), sig(4, 1, 1)])]);
await run('rampScenario', rampScenario, [OM, {}, allYes, {}, sops([sig(0, 0, 2), sig(1, 0, 0, { source: 'witness' }), sig(2, 0, 0, { map_digest: dig('other') }), { ...sig(3, 0), y: 1 }, sig(5, 1, 0, { source: 'import' }), null, 5])]);
await run('rampScenario', rampScenario, [OM, {}, allYes, {}, [{ op: 'observe', obs: sig(0, 0), ctx: ctx({ trustedSigners: [] }) }, { op: 'observe', obs: sig(0, 0), ctx: ctx({ verify: { expectedSigner: PK[1] } }) }, { op: 'observe', obs: sig(0, 0), ctx: ctx({ verify: { expectedSigner: PK[0] } }) }, state]]);
refWrite(o, 'intent-ramp');
