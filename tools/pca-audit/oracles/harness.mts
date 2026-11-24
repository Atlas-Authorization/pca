// Oracle: @atlasauth/pca-harness (the attested orchestration harness: plan inclusion, taint fold, trust budget, signing; the allowlisting
// attestation verifier). Deterministic: fixed clock, fixed nonce sequence, Ed25519 key derived from a label (no key material in the corpus).
// PORTING (fn(args) -> native entry point, comparison rule; all by JSON value, a throw requires the native to refuse):
//   consts                                  HARNESS_VERSION, HARNESS_MODEL_ID, ENFORCED_CHECKS: Harness.* constants
//   computeHarnessMeasurement(v, checks, policy)  Harness.computeHarnessMeasurement: exact string, or throws
//   harnessAttest(config, ctx)              Harness.createHarnessAttestationVerifier(config).apply(ctx): the hook result map
//   harness(spec)                           scenario over a Harness. spec {opts, steps}: opts {audience, label (agent key = Ed25519 seed sha256('atlas-pca-conformance/' + label)),
//                                           grant, chain?, plan, budget, policy?, baseRisk?, ttlMs?, manifest?, attestation?, noPlan?}; the clock is constant between steps and the nonce
//                                           of the k-th emitted-or-attempted build is 'n<k>' (k counts every nonce() call). Steps: {op:'now', t} | {op:'step', oracle}: oracle
//                                           {kind:'cand', c} returns c, {kind:'throw', msg} throws Error(msg), {kind:'bad', v} returns v. Result: {$err:true} if the constructor
//                                           threw, else {steps: [result per step], budget, counter, planRoot, measurement}
// Not ported: the default random nonce source (a native uses its own RNG when no nonce supplier is given).
import * as H0 from '@atlasauth/pca-harness';
import * as C0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';

const H: any = (H0 as any).default ?? H0;
const C: any = (C0 as any).default ?? C0;
const o = new Oracle('harness', 'tools/pca-audit/oracles/harness.mts', 'TS-reference oracle for @atlasauth/pca-harness.');
let n = 0;
const run = (fn: string, name: string, ref: (...a: any[]) => any, args: any[]) => o.run(fn, `${name}#${n++}`, ref, args);

await run('consts', 'all', () => ({ HARNESS_VERSION: H.HARNESS_VERSION, HARNESS_MODEL_ID: H.HARNESS_MODEL_ID, ENFORCED_CHECKS: H.ENFORCED_CHECKS }), []);

// ---- measurement ----------------------------------------------------------------------------------------------------------
const pol = C.DEFAULT_RISK_POLICY;
const pols: any[] = [pol, { ...pol, theta1: 0.3 }, { ...pol, kappa: 2 }, { ...pol, weights: { ...pol.weights, alpha: 0.5 } }, { weights: { alpha: 1 }, theta1: 0.1, theta2: 0.2, kappa: 1 }, { weights: {} }, { theta1: 1 }, {}, { ...pol, extra: 1, lambda: 9 },
  { weights: null, theta1: null }, { weights: { alpha: 0.1234567 }, theta1: 0.000001, theta2: 1e-7, kappa: 1e21 }];
const checkSets: any[] = [H.ENFORCED_CHECKS, [], ['a'], ['b', 'a'], ['plan_inclusion_before_signing'], H.ENFORCED_CHECKS.slice(0, 2), [1, null, 'x'], 'str'];
for (const v of ['0.1.0', '0.2.0', '', 'x']) for (const [ci, cs] of checkSets.entries()) for (const [pi, p] of pols.entries()) await run('computeHarnessMeasurement', `${v}/${ci}/${pi}`, H.computeHarnessMeasurement, [v, cs, p]);
await run('computeHarnessMeasurement', 'null-policy', H.computeHarnessMeasurement, ['0.1.0', [], null]);
await run('computeHarnessMeasurement', 'undefined-checks', H.computeHarnessMeasurement, ['0.1.0', undefined, pol]);

// ---- allowlisting verifier ------------------------------------------------------------------------------------------------
const M1 = 'm1'.padEnd(43, 'a'), M2 = 'm2'.padEnd(43, 'b');
const attest = (config: any, ctx: any) => H.createHarnessAttestationVerifier(config)(ctx);
const ctxOf = (att: any) => ({ pcactn: { attestation: att } });
const configs: any[] = [
  { measurements: [M1] }, { measurements: [M1, M2] }, { measurements: [] }, { measurements: ['', M1] }, { measurements: [5, null, M1] }, { measurements: 'nope' }, { measurements: [M1], required: false }, { measurements: [M1], required: true },
  { measurements: [M1], required: 0 }, { measurements: [M1], expectedModelId: true }, { measurements: [M1], expectedModelId: '@x/y' }, { measurements: [M1], expectedModelId: false }, { measurements: [M1], expectedModelId: '' }, { measurements: [M1], expectedModelId: 5 },
  { measurements: [M1], required: false, expectedModelId: true }, {}, { required: false },
];
const atts: any[] = [
  { measurement: M1, model_id: '@atlasauth/pca-harness' }, { measurement: M1, model_id: '@x/y' }, { measurement: M1 }, { measurement: M2, model_id: '@atlasauth/pca-harness' }, { measurement: 'other', model_id: '@atlasauth/pca-harness' }, { measurement: '', model_id: '@atlasauth/pca-harness' },
  { model_id: '@atlasauth/pca-harness' }, { measurement: 5 }, { measurement: null, model_id: null }, { measurement: M1, model_id: null }, { measurement: M1, model_id: 5 }, { measurement: M1, model_id: ['a', 'b'] }, { measurement: M1, model_id: {} }, { measurement: M1, model_id: true }, {}, null, 'x', 5, [],
  { measurement: M1, model_id: '' },
];
for (const [ci, c] of configs.entries()) for (const [ai, a] of atts.entries()) await run('harnessAttest', `${ci}/${ai}`, attest, [c, ctxOf(a)]);
for (const c of configs.slice(0, 8)) for (const [i, ctx] of ([null, {}, { pcactn: null }, { pcactn: {} }, { pcactn: { attestation: undefined } }, 5, 'x', []] as any[]).entries()) await run('harnessAttest', `ctx${i}-${JSON.stringify(c).slice(0, 25)}`, attest, [c, ctx]);
await run('harnessAttest', 'config-null', attest, [null, ctxOf(atts[0])]);

// ---- harness scenarios ----------------------------------------------------------------------------------------------------
const T0 = 1_800_000_000_000;
const label = 'harness-agent';
const pub = C.encodeKey(C.publicKeyOf(seed(label)));
const principal = seed('harness-principal');
const grant = C.mintRoot({ principalSecret: principal, principalPublic: C.encodeKey(C.publicKeyOf(principal)), holder: pub, caveats: [] });
const pd = (p: any) => C.paramsDigest(p);
const plan = [
  { id: 'n1', verb: 'read', resource: 'doc:1' },
  { id: 'n2', verb: 'summarize', resource: 'doc:1' },
  { id: 'n3', verb: 'send', resource: 'mail:x', params_digest: pd({ to: 'a' }), reversibility_class: 'irreversible' },
  { id: 'n4', verb: 'tag', resource: 'doc:2', reversibility_class: 'reversible', pre: [{ k: 1 }], post: [{ k: 2 }] },
];
const budget = (B: number, dt = 0) => ({ B, tau: T0 - dt, asOf: T0 - dt });
const AUD = 'ins_harness';
const baseOpts = (extra: any = {}) => ({ audience: AUD, label, grant, plan, budget: budget(1), ...extra });
const harness = (spec: any) => {
  let t = T0;
  let k = 0;
  const op = spec.opts;
  let h: any;
  try {
    h = new H.Harness({
      grant: op.grant, ...(op.chain !== undefined ? { chain: op.chain } : {}), agentSecret: seed(op.label), plan: op.plan, audience: op.audience, budget: op.budget,
      ...(op.policy !== undefined ? { policy: op.policy } : {}), ...(op.baseRisk !== undefined ? { baseRisk: op.baseRisk } : {}), now: () => t, ...(op.ttlMs !== undefined ? { ttlMs: op.ttlMs } : {}),
      ...(op.manifest !== undefined ? { measurementManifest: op.manifest } : {}), nonce: () => `n${k++}`, ...(op.attestation !== undefined ? { attestation: op.attestation } : {}),
    });
  } catch { return { $err: true }; }
  const steps = (async () => {
    const outs: any[] = [];
    for (const st of spec.steps) {
      if (st.op === 'now') { t = st.t; outs.push(null); continue; }
      const orc = st.oracle;
      outs.push(await h.step(() => { if (orc.kind === 'throw') throw new Error(orc.msg); return orc.kind === 'bad' ? orc.v : orc.c; }));
    }
    return outs;
  })();
  return steps.then((s: any) => ({ steps: s, budget: h.budget, counter: h.counter, planRoot: h.planRoot, measurement: h.harnessMeasurement() }));
};
const cand = (c: any) => ({ op: 'step', oracle: { kind: 'cand', c } });
const S = (...c: any[]) => c.map(cand);
const read = { verb: 'read', resource: 'doc:1', nodeId: 'n1' };
const sum = { verb: 'summarize', resource: 'doc:1', nodeId: 'n2' };
const trusted = [{ ref: 'brief', provenance: 'trusted' }];
const tainted = [{ ref: 'web', provenance: 'untrusted' }];
const scenarios: any[] = [
  { opts: baseOpts(), steps: S(read) },
  { opts: baseOpts(), steps: S(read, sum, read) },
  { opts: baseOpts(), steps: S({ ...read, inputs: trusted }, { ...sum, inputs: tainted }, { ...read, inputs: [...trusted, ...tainted] }) },
  { opts: baseOpts(), steps: S({ ...read, params: { a: 1 } }, { ...sum, params: {} }, { ...read, params: undefined }) },
  { opts: baseOpts(), steps: S({ verb: 'transfer', resource: 'bank:9', nodeId: 'wire', params: { amount: 1 } }) },
  { opts: baseOpts(), steps: S({ verb: 'transfer', resource: 'doc:1', nodeId: 'n1' }, { verb: 'read', resource: 'doc:2', nodeId: 'n1' }, { verb: 'read', resource: 'doc:1', nodeId: 'n2' }) },
  { opts: baseOpts(), steps: S({ ...read, nodeId: '' }, { ...read, nodeId: 5 }, { ...read, nodeId: undefined }, { verb: 5, resource: 'doc:1', nodeId: 'n1' }, { verb: 'read', resource: null, nodeId: 'n1' }) },
  { opts: baseOpts(), steps: [{ op: 'step', oracle: { kind: 'bad', v: null } }, { op: 'step', oracle: { kind: 'bad', v: 5 } }, { op: 'step', oracle: { kind: 'bad', v: 'x' } }, { op: 'step', oracle: { kind: 'bad', v: [] } }, { op: 'step', oracle: { kind: 'bad', v: {} } }, { op: 'step', oracle: { kind: 'throw', msg: 'boom' } }, { op: 'step', oracle: { kind: 'throw', msg: '' } }, cand(read)] },
  { opts: baseOpts(), steps: S({ ...read, inputs: 'x' }, { ...read, inputs: null }, { ...read, inputs: {} }, { ...read, inputs: 5 }) },
  { opts: baseOpts(), steps: S({ ...read, inputs: [null] }, { ...read, inputs: [5, 'x', []] }, { ...read, inputs: [{ ref: 'a' }] }, { ...read, inputs: [{ ref: 5, provenance: 'trusted' }] }, { ...read, inputs: [{ ref: 'a', provenance: 'Trusted' }] }, { ...read, inputs: [{ provenance: 'trusted' }] }, { ...read, inputs: [{ ref: 'a', provenance: 'trusted', extra: 1 }] }, { ...read, inputs: [] }) },
  { opts: baseOpts(), steps: S({ verb: 'send', resource: 'mail:x', nodeId: 'n3', params: { to: 'a' } }, { verb: 'send', resource: 'mail:x', nodeId: 'n3', params: { to: 'b' } }, { verb: 'send', resource: 'mail:x', nodeId: 'n3' }) },
  { opts: baseOpts(), steps: S({ verb: 'tag', resource: 'doc:2', nodeId: 'n4' }, { verb: 'tag', resource: 'doc:2', nodeId: 'n4', inputs: tainted }) },
  // budgets and the clock
  ...[0, 0.05, 0.1, 0.11, 0.2, 0.5, 0.0999999, 1].map((B) => ({ opts: baseOpts({ budget: budget(B) }), steps: S(read, read, read, sum, { ...read, inputs: tainted }) })),
  ...[0, 1000, 60_000, 3_600_000, 1e9].map((dt) => ({ opts: baseOpts({ budget: budget(1, dt) }), steps: S(read, sum) })),
  { opts: baseOpts({ budget: budget(1) }), steps: [{ op: 'now', t: T0 + 100_000 }, ...S(read), { op: 'now', t: T0 + 200_000 }, ...S(sum), { op: 'now', t: T0 + 100_000 }, ...S(read)] },
  { opts: baseOpts({ budget: budget(0.3) }), steps: [...S(read), { op: 'now', t: T0 + 1_000_000 }, ...S(read, sum)] },
  { opts: baseOpts({ budget: { B: 1, tau: T0, asOf: T0 + 5000 } }), steps: [...S(read), { op: 'now', t: T0 + 1000 }, ...S(read)] },
  // policies
  ...[{ ...pol, theta1: 1, theta2: 1 }, { ...pol, theta1: 0, theta2: 0 }, { ...pol, theta1: 0.05, theta2: 0.2 }, { ...pol, kappa: 3 }, { ...pol, kappa: 0 }, { ...pol, lambda: 0.1 }, { ...pol, lambda: 0 }, { ...pol, weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 } },
    { ...pol, weights: { ...pol.weights, delta: 2 } }, { ...pol, weights: { ...pol.weights, alpha: -1 } }, { ...pol, theta1: 0.5, theta2: 0.4 }, { ...pol, kappa: -1 }].map((p) => ({ opts: baseOpts({ policy: p }), steps: S(read, { ...read, inputs: tainted }, sum, { verb: 'send', resource: 'mail:x', nodeId: 'n3', params: { to: 'a' } }, { verb: 'tag', resource: 'doc:2', nodeId: 'n4' }) })),
  // base risk
  ...[{ semanticDistance: 0.9 }, { reversibility: 0 }, { blastRadius: 0.55 }, { confidence: 0.3333333 }, { age: 0.7 }, { semanticDistance: 0.123456789, blastRadius: 0.987654321 }, { extra: 1, other: 'x' }, { taint: 0 }, { semanticDistance: 2, reversibility: -1 }, {}].map((b) => ({ opts: baseOpts({ baseRisk: b }), steps: S(read, { ...read, inputs: tainted }) })),
  // construction
  { opts: baseOpts({ ttlMs: 1000 }), steps: S(read) }, { opts: baseOpts({ ttlMs: 0 }), steps: S(read) },
  { opts: baseOpts({ attestation: { operator: 'op1' } }), steps: S(read, sum) }, { opts: baseOpts({ attestation: { operator: 'op1', epoch: 7 } }), steps: S(read) },
  { opts: baseOpts({ manifest: ['x'] }), steps: S(read) }, { opts: baseOpts({ manifest: [] }), steps: [] },
  { opts: baseOpts({ chain: [grant] }), steps: S(read) }, { opts: baseOpts({ chain: [] }), steps: S(read) },
  { opts: baseOpts({ audience: '' }), steps: [] }, { opts: baseOpts({ audience: null }), steps: [] }, { opts: baseOpts({ audience: 5 }), steps: [] },
  { opts: baseOpts({ plan: [] }), steps: [] }, { opts: baseOpts({ plan: null }), steps: [] }, { opts: baseOpts({ plan: [plan[0], plan[0]] }), steps: [] }, { opts: baseOpts({ plan: [plan[0]] }), steps: S(read, sum) },
  { opts: baseOpts({ budget: null }), steps: [] }, { opts: baseOpts({ budget: { B: 1, tau: T0 } }), steps: [] }, { opts: baseOpts({ budget: { B: -1, tau: T0, asOf: T0 } }), steps: [] }, { opts: baseOpts({ budget: { B: 1, tau: 'x', asOf: T0 } }), steps: [] },
  { opts: baseOpts({ budget: { B: '1', tau: T0, asOf: T0 } }), steps: [] }, { opts: baseOpts({ budget: { B: 1, tau: T0, asOf: null } }), steps: [] },
  { opts: baseOpts({ label: 'short' }), steps: S(read) },
];
for (const [i, s] of scenarios.entries()) await run('harness', `${i}`, harness, [s]);

refWrite(o, 'harness');
