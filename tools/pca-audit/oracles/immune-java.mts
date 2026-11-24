// Oracle: the behavioural immune system's write side (adapt, noWidenViolation, signed tightening proposals, the durable store), TS reference. Written for the Java lane; reusable by any native.
// Ed25519 only; guardian keys come from seed('immune/<label>'); clocks are arguments.
// PORTING (fn(args) -> native entry point; comparison: JSON value; a reference throw means the native throws):
//   adapt(base, assessment) / noWidenViolation(base, adapted) / policyDigest(p) / immuneStateDigest(s)
//   issueTighteningProposal(base, state, epoch, now, guardianLabel)   -> the signed proposal (guardian secret = seed('immune/'+label))
//   applyTightening(base, proposal, opts)    opts.guardian "@g" = the public key of seed('immune/g'); opts.state optional; never throws
//   store(subject, ops)  ops run in order over one in-memory kv, each result (or {"$err": "Error"}) collected:
//        ["seed", state] writes the stored state directly    ["get"]    ["observe", obs]    ["lastEpoch"]    ["apply", base, proposal, opts]
import { Oracle, refWrite, seed, rng, jsonOut } from './lib.mjs';
const { b64u }: any = await import('../../../packages/pca/src/hash.ts');
const { publicKeyOf }: any = await import('../../../packages/pca/src/keys.ts');
const { createMemoryDurableKv }: any = await import('../../../packages/pca/src/durable-state.ts');
const I: any = await import('../../../packages/pca/src/immune.ts');
const { DEFAULT_RISK_POLICY }: any = await import('../../../packages/pca/src/risk.ts');

const o = new Oracle('immune-java', 'tools/pca-audit/oracles/immune-java.mts', 'TS-reference oracle for the immune-system adaptation, signed tightening proposals and durable store.');
const sd = (l: string) => seed('immune/' + l);
const G = b64u(publicKeyOf(sd('g')));
const T0 = 1_800_000_000_000;
const clone = (x: any) => JSON.parse(JSON.stringify(x));
const R = rng(77);

// states: calm, drifting, step-up heavy, deny heavy
const states: any[] = [I.INITIAL_IMMUNE_STATE];
for (let i = 0; i < 24; i++) {
  let s = I.INITIAL_IMMUNE_STATE, at = T0;
  const n = R.int(1, 25), kind = i % 4;
  for (let j = 0; j < n; j++) {
    at += R.int(0, 5) * 600_000;
    const hot = kind >= 2 && j > n / 2;
    s = I.observe(s, { r: hot ? 0.6 + R.next() * 0.4 : R.next() * 0.3, at, stepUp: kind === 1 ? R.next() < 0.8 : hot && R.next() < 0.7, denied: kind === 3 && R.next() < 0.5 });
  }
  states.push(clone(s));
}
const assessments: any[] = states.map((s) => I.assess(s));
assessments.push({ level: 'high', score: null, signals: [], components: {} }, { level: 'high', score: 'x', signals: ['s'], components: {} }, { level: 'elevated', score: 0.5, signals: [], components: {} }, { level: 'high', score: 2, signals: ['a', 'b'], components: {} },
  { level: 'calm', score: -1, signals: [], components: {} }, { level: 'calm', score: 0, signals: ['ignored'], components: {} }, { level: 'high', score: 1e-300, signals: [], components: {} }, { level: 'elevated', score: 0.123456789, signals: [], components: {} });

const bases: any[] = [DEFAULT_RISK_POLICY, { ...DEFAULT_RISK_POLICY, kappa: 2.5, theta1: 0.1, theta2: 0.9 }, { ...DEFAULT_RISK_POLICY, theta1: 0, theta2: 0 }, { ...DEFAULT_RISK_POLICY, theta1: 1, theta2: 1, kappa: 1e300 },
  { ...DEFAULT_RISK_POLICY, extra: 'kept' }, { ...DEFAULT_RISK_POLICY, kappa: 0 }, { ...DEFAULT_RISK_POLICY, weights: undefined }, { ...DEFAULT_RISK_POLICY, theta1: 0.7, theta2: 0.3 }, { ...DEFAULT_RISK_POLICY, bMax: -1 }, null, 5, {}];
let k = 0;
for (const b of bases) for (const a of assessments) await o.run('adapt', 'ad' + k++, I.adapt, [b, a]);

// noWiden
const tight = (b: any, mut: any) => ({ ...clone(b), weights: { ...b.weights }, ...mut });
const B = DEFAULT_RISK_POLICY;
const adapteds: any[] = [B, tight(B, { kappa: 2 }), tight(B, { kappa: 0.5 }), tight(B, { theta1: 0.2 }), tight(B, { theta1: 0.3 }), tight(B, { theta2: 0.5 }), tight(B, { theta2: 0.7 }), tight(B, { lambda: 1 }), tight(B, { rho: 0 }), tight(B, { bMax: 2 }),
  tight(B, { weights: { ...B.weights, alpha: 0.3 } }), tight(B, { weights: { ...B.weights, zeta: 0 } }), tight(B, { kappa: 'x' }), tight(B, { kappa: null }), tight(B, { theta1: null }), tight(B, { weights: {} }), tight(B, { weights: undefined }), tight(B, { lambda: undefined }), {}, tight(B, { kappa: 1.0000001, theta1: 0.2499999 })];
for (const a of adapteds) await o.run('noWidenViolation', 'nw' + k++, I.noWidenViolation, [B, a]);
await o.run('noWidenViolation', 'nwbase' + k++, I.noWidenViolation, [{ ...B, weights: undefined }, B]);

for (const b of [B, tight(B, { kappa: 3 })]) await o.run('policyDigest', 'pd' + k++, I.policyDigest, [b]);
for (const s of states.slice(0, 10)) await o.run('immuneStateDigest', 'sd' + k++, I.immuneStateDigest, [s]);

const issue = (base: any, state: any, epoch: any, now: any, label: any) =>
  I.issueTighteningProposal({ base, state, epoch, now, guardianSecret: sd(label) });
for (const b of [B, bases[1], bases[4]]) for (const s of states) await o.run('issueTighteningProposal', 'is' + k++, issue, [b, s, 3, T0, 'g']);
for (const e of [0, 1, 2, 2 ** 53 - 1, 2 ** 53, -1, 1.5, '1', null, true]) await o.run('issueTighteningProposal', 'ie' + k++, issue, [B, states[5], e, T0, 'g']);
for (const n of [0, -5, null, 'x', 1.5]) await o.run('issueTighteningProposal', 'in' + k++, issue, [B, states[5], 1, n, 'g']);
for (const b of [bases[5], bases[6], bases[7], bases[8], null, 5, {}]) await o.run('issueTighteningProposal', 'ib' + k++, issue, [b, states[5], 1, T0, 'g']);
for (const s of [{}, null, { ...states[3], seeded: 1 }, { ...states[3], ewma: 5 }]) await o.run('issueTighteningProposal', 'iv' + k++, issue, [B, s, 1, T0, 'g']);
await o.run('issueTighteningProposal', 'ig' + k++, issue, [B, states[5], 1, T0, 'other']);

// apply
const hot = states.find((s, i) => i > 0 && I.assess(s).score >= 0.66) ?? states[states.length - 1];
const mid = states.find((s) => { const x = I.assess(s).score; return x > 0.2 && x < 0.6; }) ?? states[4];
const prop = (b: any, s: any, e: any, now: any, label = 'g') => clone(issue(b, s, e, now, label));
const opt = (x: any = {}) => ({ guardian: '@g', lastEpoch: 0, now: T0 + 1000, maxAgeMs: 60_000, ...x });
const fix = (x: any) => (x && x.guardian === '@g' ? { ...x, guardian: G } : x);
const good = prop(B, hot, 5, T0);
const cases: Array<[string, any, any, any]> = [];
cases.push(['ok', B, good, opt()], ['ok-mid', B, prop(B, mid, 1, T0), opt()], ['ok-state', B, good, opt({ state: hot })], ['state-mismatch', B, good, opt({ state: mid })], ['state-other', B, good, opt({ state: states[0] })], ['state-empty-obj', B, good, opt({ state: {} })],
  ['guardian-pin', B, good, opt({ guardian: G.slice(1) + 'A' })], ['guardian-missing', B, good, opt({ guardian: undefined })], ['guardian-num', B, good, opt({ guardian: 5 })],
  ['sig-bad', B, { ...good, sig: good.sig.slice(1) + 'A' }, opt()], ['sig-short', B, { ...good, sig: good.sig.slice(2) }, opt()], ['sig-empty', B, { ...good, sig: '' }, opt()], ['sig-num', B, { ...good, sig: 5 }, opt()], ['sig-missing', B, { ...good, sig: undefined }, opt()],
  ['v2', B, { ...good, v: 2 }, opt()], ['v-str', B, { ...good, v: '1' }, opt()], ['null', B, null, opt()], ['str', B, 'x', opt()], ['arr', B, [], opt()],
  ['other-guardian-sig', B, prop(B, hot, 5, T0, 'h'), opt()], ['base-mismatch', bases[1], good, opt()], ['base-invalid', bases[5], good, opt()], ['base-null', null, good, opt()],
  ['stale-old', B, good, opt({ now: T0 + 60_001 })], ['stale-edge', B, good, opt({ now: T0 + 60_000 })], ['stale-future', B, good, opt({ now: T0 - 1 })], ['stale-nan', B, good, opt({ now: null })], ['stale-maxage-null', B, good, opt({ maxAgeMs: null })], ['stale-maxage-missing', B, good, opt({ maxAgeMs: undefined })], ['stale-maxage-zero', B, good, opt({ maxAgeMs: 0, now: T0 })],
  ['epoch-eq', B, good, opt({ lastEpoch: 5 })], ['epoch-lt', B, good, opt({ lastEpoch: 6 })], ['epoch-gt-ok', B, good, opt({ lastEpoch: 4 })], ['epoch-last-null', B, good, opt({ lastEpoch: null })], ['epoch-last-str', B, good, opt({ lastEpoch: '1' })],
  ['opts-state-undefined', B, good, opt({ state: undefined })]);
// tampered claims need a re-signature to reach the later checks: sign by hand with the guardian key
const { sign }: any = await import('../../../packages/pca/src/keys.ts');
const { canonicalBytesLenient, utf8 }: any = await import('../../../packages/pca/src/hash.ts');
const resign = (claim0: any, label = 'g') => {
  const claim = Object.fromEntries(Object.entries(claim0).filter(([, v]) => v !== undefined)); // an absent key is what the wire carries
  const pre = utf8(I.TIGHTENING_DOMAIN), body = canonicalBytesLenient(claim), m = new Uint8Array(pre.length + body.length);
  m.set(pre); m.set(body, pre.length);
  return { ...claim, sig: b64u(sign(sd(label), m)) };
};
const { sig: _s, ...gc } = good;
cases.push(['re-ok', B, resign(gc), opt()], ['re-epoch-0', B, resign({ ...gc, epoch: 0 }), opt({ lastEpoch: -1 })], ['re-epoch-frac', B, resign({ ...gc, epoch: 5.5 }), opt()], ['re-epoch-neg0', B, resign({ ...gc, epoch: -0 }), opt({ lastEpoch: -1 })], ['re-epoch-big', B, resign({ ...gc, epoch: 2 ** 53 }), opt()],
  ['re-widens-kappa', B, resign({ ...gc, policy: { ...gc.policy, kappa: 0.5 } }), opt()], ['re-widens-theta', B, resign({ ...gc, policy: { ...gc.policy, theta2: 0.95 } }), opt()], ['re-widens-weight', B, resign({ ...gc, policy: { ...gc.policy, weights: { ...gc.policy.weights, alpha: 0.9 } } }), opt()],
  ['re-widens-lambda', B, resign({ ...gc, policy: { ...gc.policy, lambda: 9 } }), opt()], ['re-policy-invalid', B, resign({ ...gc, policy: { ...gc.policy, kappa: -1 } }), opt()], ['re-policy-null', B, resign({ ...gc, policy: null }), opt()], ['re-policy-missing', B, resign({ ...gc, policy: undefined }), opt()],
  ['re-issued-nan', B, resign({ ...gc, issued_at: 'x' }), opt()], ['re-issued-null', B, resign({ ...gc, issued_at: null }), opt()], ['re-base-digest', B, resign({ ...gc, base_digest: 'x' }), opt()], ['re-state-digest', B, resign({ ...gc, state_digest: 'x' }), opt({ state: hot })], ['re-state-digest-nostate', B, resign({ ...gc, state_digest: 'x' }), opt()],
  ['re-policy-swapped-state', B, resign({ ...gc, policy: { ...gc.policy, kappa: gc.policy.kappa + 1 } }), opt({ state: hot })], ['re-extra-field', B, resign({ ...gc, extra: 1 }), opt()], ['re-guardian-key', B, resign({ ...gc, guardian: G }, 'h'), opt()]);
for (const [n, b, p, op] of cases) await o.run('applyTightening', n, (bb: any, pp: any, oo: any) => I.applyTightening(bb, pp, fix(oo)), [b, p, op]);

// store
const store = async (subject: string, ops: any[]) => {
  const kv = createMemoryDurableKv();
  const st = I.createImmuneStore(kv, subject);
  const out: any[] = [];
  for (const op of ops) {
    try {
      if (op[0] === 'seed') { await kv.set(`immune/state/${subject}`, op[1]); out.push(null); }
      else if (op[0] === 'get') out.push(jsonOut(await st.get()));
      else if (op[0] === 'observe') out.push(jsonOut(await st.observe(op[1])));
      else if (op[0] === 'lastEpoch') out.push(await st.lastEpoch());
      else if (op[0] === 'apply') out.push(jsonOut(await st.apply(op[1], op[2], fix(op[3]))));
    } catch (e) { out.push({ $err: 'Error' }); }
  }
  return out;
};
const obsSeq = (n: number) => Array.from({ length: n }, (_, i) => ['observe', { r: (i % 5) / 4, at: T0 + i * 300_000, stepUp: i % 3 === 0, denied: i % 7 === 0 }]);
const ap = (b: any, e: number, extra: any = {}) => ['apply', b, prop(b, hot, e, T0), opt(extra)];
const SCEN: any[][] = [
  [['get']], [['lastEpoch']], obsSeq(12).concat([['get']]), [...obsSeq(30), ['get'], ['observe', { r: 2, at: 'x' }], ['observe', {}], ['get']],
  [ap(B, 1), ['lastEpoch'], ap(B, 1), ['lastEpoch'], ap(B, 2), ['lastEpoch'], ap(B, 2), ap(B, 1), ['lastEpoch']],
  [ap(B, 5), ap(B, 4), ap(B, 6, { maxAgeMs: 1 }), ['lastEpoch'], ap(B, 7), ['lastEpoch']],
  [['seed', { baseline: { n: 1.5 } }], ['observe', { r: 0.5, at: T0 }], ['get']], [['seed', null], ['observe', { r: 0.5, at: T0 }], ['get']], [['seed', states[7]], ['observe', { r: 0.9, at: T0 + 5, stepUp: true }], ['get']],
  [ap(bases[1], 1), ['apply', B, 'x', opt()], ['lastEpoch']], [['seed', states[7]], ['get']],
];
let si = 0;
for (const subj of ['alice', 'é/ü:1']) for (const ops of SCEN) await o.run('store', 'st' + si++, store, [subj, ops]);

refWrite(o, 'immune-java');
