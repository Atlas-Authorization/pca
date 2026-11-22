// Oracle: every export of packages/pca/src/progress.ts (proof-of-progress toward a committed intent: potentials + registry, goal commitment, step digests, trajectory
// anchoring, signed state attestations + the attested StateSource, the ProgressTracker, step / trajectory verification, signed steps), TS reference.
// Writes out/ref-progress.json.gz. Deterministic: keys from seed(label), no clock, fixed salts. Case shape (as every sibling): {fn, name, args, out}; `out` is
// what the reference returned, or {"$throws": message, code?}. Secrets appear only as seed labels: signProgressStep's secretKey is {"$bytes": {"$seed": label}} and a source's signerSecret is
// {"$seed": label}; the 32-byte key is sha256("atlas-pca-conformance/" + label) (the strip tool rewrites the generated key to the label, as for every sibling corpus).
//
// PORTING (fn(args) -> native entry point; results compared by JSON value; a reference throw = the native refuses; {"$err": m} inside a result list = that op refused)
//   specs (JSON descriptions of the host objects the reference is given):
//     potential kind K   "l1-feature-v1" | "dag-remaining-v1" | "dag-weighted-v1" (the built-ins) | "const:N" (always N) | "v" (returns state.v untouched) | "throws" | "negative" (-1)
//                        | "frac" (0.5) | "nan" (NaN) | "big" (2^53); the last six exist to reach the denials a bad potential causes
//     registry PRS       null (the default frozen registry) | {mode:"registry"|"record", potentials:[[id, K, embedder?], ...]}: "registry" = a PotentialRegistry with register() in
//                        order, "record" = the plain record {id: K} or {id:{fn:K, embedder}} (own keys only) accepted wherever a registry is
//     guard GD           null | "allow" | "deny" (returns false) | "throws" | "truthy" (returns the string "yes": only === true allows) | "action:<digest>" (forbids that action_digest)
//                        | "seq:<n>" (forbids that seq) | "after-v:<n>" (forbids a transition whose after.v === n)
//     attestation AV     null | "allow" | "deny" | "throws" | "truthy" | {attested:{trustedKeys, pqPins?, allowUnboundPq?, attestations:[...]}} (attestedStateVerifier over those)
//     source SRC (a StateSource): {kind:"memory", id, initial} | {kind:"attested", id, signerSecret, initial, alg?} (signs; ed25519 only here) | {kind:"liar-digest", id, initial} (state_digest
//                        is wrong) | {kind:"liar-source", id, initial} (reports another source id) | {kind:"throws", id} | {kind:"null", id} (returns null);
//                        observed state = the source's current world; ["apply", i, next] changes it
//   constants []                                   -> {PROGRESS_VERSION, PROGRESS_SIG_DOMAIN, TRAJECTORY_ANCHOR_DOMAIN, STATE_ATTESTATION_DOMAIN}
//   l1FeaturePotential [objective, state] / dagRemainingPotential / dagWeightedPotential -> non-negative safe integer, or refuses
//   registryOps [ops]                              -> list of results; first op builds the registry: ["new"] | ["defaults"] (mutable, three built-ins) | ["default-frozen"]
//                                                     (DEFAULT_POTENTIALS) | ["from", {id: K | {fn:K, embedder?}}]; then ["register", id, K, embedder?] (null) ["get", id] ->
//                                                     {embedder}|null ["has", id] ["ids"] (sorted) ["freeze"]; a refusal is {"$err": message}
//   goalDigest [goal] -> digest ; commitGoal [goal] -> {goal (canonical snapshot), commitment} ; verifyGoalCommitment [goal, commitment] -> bool (never throws)
//   stateDigest [state] / trajectoryHead [steps] / progressStepDigest [step] -> string ; trajectoryAnchorCommit [salt, head] -> digest ; verifyTrajectoryAnchor [commit, salt, head] -> bool
//   anchorTrajectoryHead [steps, salt, priorCommits] -> {head, salt, commit, index, ledgerHead:{size, root}} (a transparency ledger that already holds priorCommits; salt always given)
//   verifyStateAttestation [att, trustedPublicKey, pin|null] -> bool (pin = {pqPins?, allowUnboundPq?})
//   attestedStateVerifier [opts, step] -> bool (the hook built from opts, applied to step)
//   attestedSource [src, requests] -> list of observations or {"$err"} (an AttestedStateSource built from the src, observe() for each request, then its .attestations)  -> {observations, attestations}
//   tracker [goal, commitment, initial, PRS, GD, sources, ops] -> list of results (the constructor refusing makes the case a refusal): ["step", after, actionDigest] -> ProveResult
//       ["stepObserved", srcIndex, actionDigest] ["apply", srcIndex, next] (null) ["state"] ["currentStateDigest"] ["spent"] ["remaining"] ["reached"] ["steps"]
//   verifyProgressStep [goal, commitment, step, opts] / verifyTrajectory [goal, commitment, steps, opts] / verifySignedProgressStep [goal, commitment, signed, opts] /
//   verifySignedTrajectory [goal, commitment, signed, opts] -> the result object; opts = the reference options with registry as PRS, guard as GD, attestation as AV
//   signProgressStep [step, secretKey, holderPublicKey] -> {step, holder, sig}  (Ed25519 over the domain-separated binding; deterministic)
import * as PCA0 from '@atlasauth/pca';
import { Oracle, refWrite, seed, ser } from './lib.mjs';

const P: any = (PCA0 as any).default ?? PCA0;
const PG: any = await import('../../../packages/pca/src/progress.ts');
const { TransparencyLedger }: any = await import('../../../packages/pca/src/ledger.ts');
const { hashCanonical, b64u }: any = await import('../../../packages/pca/src/hash.ts');
const PQ: any = await import('../../../packages/pca/src/pq.ts');
const { publicKeyOf } = P;
const o = new Oracle('progress', 'tools/pca-audit/oracles/progress.mts', 'TS-reference oracle for packages/pca/src/progress.ts.');
const { capture } = await import('../oracles-base/lib.mjs') as any;

// ---------------------------------------------------------------- spec -> host objects
const NUM: any = { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity };
const revive = (v: any): any => Array.isArray(v) ? v.map(revive)
  : v && typeof v === 'object' ? ('$bytes' in v && Object.keys(v).length === 1 ? new Uint8Array(Buffer.from(v.$bytes, 'base64url')) : '$num' in v && Object.keys(v).length === 1 ? NUM[v.$num] : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, revive(x)]))) : v;
const kindFn = (k: string): any => {
  if (k === 'l1-feature-v1') return PG.l1FeaturePotential;
  if (k === 'dag-remaining-v1') return PG.dagRemainingPotential;
  if (k === 'dag-weighted-v1') return PG.dagWeightedPotential;
  if (k.startsWith('const:')) return () => Number(k.slice(6));
  if (k === 'v') return (_o: any, s: any) => s?.v;
  if (k === 'throws') return () => { throw new Error('potential boom'); };
  if (k === 'negative') return () => -1;
  if (k === 'frac') return () => 0.5;
  if (k === 'nan') return () => NaN;
  if (k === 'big') return () => 2 ** 53;
  throw new Error('bad potential kind ' + k);
};
const mkRegistry = (s: any): any => {
  if (s === null || s === undefined) return undefined;
  if (s.mode === 'record') return Object.fromEntries(s.potentials.map(([id, k, emb]: any[]) => [id, emb === undefined ? kindFn(k) : { fn: kindFn(k), embedder: emb }]));
  const r = new PG.PotentialRegistry();
  for (const [id, k, emb] of s.potentials) r.register(id, kindFn(k), emb);
  return r;
};
const mkGuard = (g: any): any => {
  if (g === null || g === undefined) return undefined;
  if (g === 'allow') return () => true;
  if (g === 'deny') return () => false;
  if (g === 'throws') return () => { throw new Error('guard boom'); };
  if (g === 'truthy') return () => 'yes';
  if (g.startsWith('action:')) return (t: any) => t.action_digest !== g.slice(7);
  if (g.startsWith('seq:')) return (t: any) => t.seq !== Number(g.slice(4));
  if (g.startsWith('after-v:')) return (t: any) => t.after?.v !== Number(g.slice(8));
  throw new Error('bad guard ' + g);
};
const mkAtt = (a: any): any => {
  if (a === null || a === undefined) return undefined;
  if (a === 'allow') return () => true;
  if (a === 'deny') return () => false;
  if (a === 'throws') return () => { throw new Error('att boom'); };
  if (a === 'truthy') return () => 'yes';
  return PG.attestedStateVerifier(a.attested);
};
const mkOpts = (opts: any): any => {
  const out: any = { ...(opts ?? {}) };
  if ('registry' in out) out.registry = mkRegistry(out.registry);
  if ('guard' in out) out.guard = mkGuard(out.guard);
  if ('attestation' in out) out.attestation = mkAtt(out.attestation);
  return out;
};
const mkSource = (s: any): any => {
  let world = JSON.parse(JSON.stringify(s.initial ?? null));
  const src: any = { set: (n: any) => { world = JSON.parse(JSON.stringify(n)); } };
  if (s.kind === 'attested') {
    const a = new PG.AttestedStateSource({ id: s.id, signerSecret: new Uint8Array(Buffer.from(s.signerSecret, 'base64url')), observeState: () => world, ...(s.alg ? { suite: { alg: s.alg } } : {}) });
    return Object.assign(a, { set: src.set });
  }
  const mem = new PG.InMemoryStateSource(s.initial ?? null, s.id);
  if (s.kind === 'memory') return Object.assign(mem, { set: (n: any) => mem.apply(n) });
  const wrap: any = { id: s.id, set: (n: any) => mem.apply(n), observe: (r: any) => {
    if (s.kind === 'throws') throw new Error('source boom');
    if (s.kind === 'null') return null;
    const ob = mem.observe(r);
    if (s.kind === 'liar-digest') return { ...ob, state_digest: 'x'.repeat(43) };
    if (s.kind === 'liar-source') return { ...ob, source: 'someone-else' };
    return ob;
  } };
  return wrap;
};

const jerr = (e: any) => ({ $err: e instanceof Error ? e.message : String(e) });
const REF: Record<string, (...a: any[]) => any> = {
  constants: () => ({ PROGRESS_VERSION: PG.PROGRESS_VERSION, PROGRESS_SIG_DOMAIN: PG.PROGRESS_SIG_DOMAIN, TRAJECTORY_ANCHOR_DOMAIN: PG.TRAJECTORY_ANCHOR_DOMAIN, STATE_ATTESTATION_DOMAIN: PG.STATE_ATTESTATION_DOMAIN }),
  l1FeaturePotential: (ob, st) => PG.l1FeaturePotential(ob, st),
  dagRemainingPotential: (ob, st) => PG.dagRemainingPotential(ob, st),
  dagWeightedPotential: (ob, st) => PG.dagWeightedPotential(ob, st),
  registryOps: (ops: any[][]) => {
    let r: any;
    return ops.map(([op, ...a]) => {
      try {
        if (op === 'new') { r = new PG.PotentialRegistry(); return null; }
        if (op === 'defaults') { r = PG.PotentialRegistry.defaults(); return null; }
        if (op === 'default-frozen') { r = PG.DEFAULT_POTENTIALS; return null; }
        if (op === 'from') { r = PG.PotentialRegistry.from(Object.fromEntries(Object.entries(a[0]).map(([id, v]: any) => [id, typeof v === 'string' ? kindFn(v) : { fn: kindFn(v.fn), embedder: v.embedder }]))); return null; }
        if (op === 'register') { r.register(a[0], kindFn(a[1]), a[2]); return null; }
        if (op === 'get') { const s = r.get(a[0]); return s ? { embedder: s.embedder ?? null } : null; }
        if (op === 'has') return r.has(a[0]);
        if (op === 'ids') return r.ids();
        if (op === 'freeze') { r.freeze(); return null; }
        throw new Error('bad op');
      } catch (e) { return jerr(e); }
    });
  },
  goalDigest: (g) => PG.goalDigest(g),
  commitGoal: (g) => PG.commitGoal(g),
  verifyGoalCommitment: (g, c) => PG.verifyGoalCommitment(g, c),
  stateDigest: (s) => PG.stateDigest(s),
  trajectoryHead: (st) => PG.trajectoryHead(st),
  progressStepDigest: (s) => PG.progressStepDigest(s),
  trajectoryAnchorCommit: (s, h) => PG.trajectoryAnchorCommit(s, h),
  verifyTrajectoryAnchor: (c, s, h) => PG.verifyTrajectoryAnchor(c, s, h),
  anchorTrajectoryHead: (steps, salt, prior) => { const l = new TransparencyLedger('p'); for (const c of prior) l.appendCommitment(c); const a = PG.anchorTrajectoryHead(l, steps, { salt }); return { ...a, ledgerHead: { size: a.ledgerHead.size, root: a.ledgerHead.root } }; },
  verifyStateAttestation: (a, k, pin) => PG.verifyStateAttestation(a, k, pin ?? undefined),
  attestedStateVerifier: (opts, step) => PG.attestedStateVerifier(opts)(step),
  attestedSource: async (src, reqs) => { const s = mkSource(src); const observations: any[] = []; for (const r of reqs) { try { observations.push(await s.observe(r)); } catch (e) { observations.push(jerr(e)); } } return { observations, attestations: s.attestations ?? null }; },
  tracker: async (goal, commitment, initial, prs, gd, sources, ops) => {
    const srcs = sources.map(mkSource);
    const t = new PG.ProgressTracker(goal, commitment ?? PG.goalDigest(goal), initial, mkRegistry(prs), { guard: mkGuard(gd) });
    const out: any[] = [];
    for (const [op, ...a] of ops) {
      try {
        if (op === 'step') out.push(t.step(a[0], a[1]));
        else if (op === 'stepObserved') out.push(await t.stepObserved(srcs[a[0]], a[1]));
        else if (op === 'apply') { srcs[a[0]].set(a[1]); out.push(null); }
        else if (op === 'steps') out.push(t.steps);
        else out.push((t as any)[op === 'currentStateDigest' ? 'currentStateDigest' : op]);
      } catch (e) { out.push(jerr(e)); }
    }
    return out;
  },
  verifyProgressStep: (g, c, s, opts) => PG.verifyProgressStep(g, c, s, mkOpts(opts)),
  verifyTrajectory: (g, c, st, opts) => PG.verifyTrajectory(g, c, st, mkOpts(opts)),
  verifySignedProgressStep: (g, c, s, opts) => PG.verifySignedProgressStep(g, c, s, mkOpts(opts)),
  verifySignedTrajectory: (g, c, st, opts) => PG.verifySignedTrajectory(g, c, st, mkOpts(opts)),
  signProgressStep: (s, sk, holder) => PG.signProgressStep(s, sk, holder),
};
let n = 0;
const add = async (fn: string, name: string, args: any[]) => {
  const js = JSON.parse(ser(args.map((x) => (x === undefined ? null : x))));
  o.add(fn, `${name}#${n++}`, js, await capture(REF[fn], revive(js)));
};
const J = (x: any) => JSON.parse(JSON.stringify(x));
const bk = (l: string) => { const sk = seed('progress/' + l); return { sk, b64: b64u(sk), pk: b64u(publicKeyOf(sk)) }; };
const H1 = bk('holder'), H2 = bk('holder2'), S1 = bk('source1'), S2 = bk('source2');

await add('constants', 'all', []);

// ---------------------------------------------------------------- potentials
const L1: [string, any, any][] = [['ok', { target: [0, 0, 0] }, { x: [1, -2, 3] }], ['zero', { target: [5, 5] }, { x: [5, 5] }], ['empty', { target: [] }, { x: [] }], ['neg', { target: [-5, 5] }, { x: [5, -5] }], ['len', { target: [1] }, { x: [1, 2] }],
  ['frac-t', { target: [0.5] }, { x: [1] }], ['frac-x', { target: [1] }, { x: [1.5] }], ['str', { target: ['1'] }, { x: [1] }], ['no-target', {}, { x: [1] }], ['no-x', { target: [1] }, {}], ['null-obj', null, { x: [1] }], ['null-state', { target: [1] }, null],
  ['not-array', { target: 'a' }, { x: 'b' }], ['big', { target: [2 ** 53 - 1] }, { x: [0] }], ['overflow', { target: [2 ** 53 - 1, 2 ** 53 - 1] }, { x: [0, 0] }], ['unsafe', { target: [2 ** 53] }, { x: [0] }], ['neg-zero', { target: [-0] }, { x: [0] }],
  ['sum-ok', { target: [4503599627370495, 4503599627370496] }, { x: [0, 0] }], ['null-elem', { target: [null] }, { x: [0] }], ['extra', { target: [1, 2], junk: 1 }, { x: [0, 0], other: 2 }]];
for (const [nm, ob, st] of L1) await add('l1FeaturePotential', nm, [ob, st]);
const T = (id: string, cost: any, deps?: any) => ({ id, cost, ...(deps === undefined ? {} : { deps }) });
const DAGS: [string, any, any][] = [['ok', { tasks: [T('a', 3), T('b', 4)] }, { done: ['a'] }], ['none-done', { tasks: [T('a', 3), T('b', 4)] }, { done: [] }], ['all-done', { tasks: [T('a', 3), T('b', 4)] }, { done: ['a', 'b'] }], ['empty', { tasks: [] }, { done: [] }],
  ['dup-id', { tasks: [T('a', 1), T('a', 2)] }, { done: [] }], ['unknown-done', { tasks: [T('a', 1)] }, { done: ['z'] }], ['dup-done', { tasks: [T('a', 1)] }, { done: ['a', 'a'] }], ['neg-cost', { tasks: [T('a', -1)] }, { done: [] }], ['frac-cost', { tasks: [T('a', 0.5)] }, { done: [] }],
  ['str-cost', { tasks: [T('a', '1')] }, { done: [] }], ['zero-cost', { tasks: [T('a', 0), T('b', 0)] }, { done: [] }], ['no-tasks', {}, { done: [] }], ['no-done', { tasks: [T('a', 1)] }, {}], ['tasks-str', { tasks: 'x' }, { done: [] }], ['done-str', { tasks: [] }, { done: 'x' }],
  ['overflow', { tasks: [T('a', 2 ** 53 - 1), T('b', 1)] }, { done: [] }], ['max', { tasks: [T('a', 2 ** 53 - 1)] }, { done: [] }], ['null-task', { tasks: [null] }, { done: [] }], ['num-id', { tasks: [{ id: 5, cost: 1 }] }, { done: [] }], ['empty-id', { tasks: [T('', 1)] }, { done: [] }],
  ['order', { tasks: [T('b', 2), T('a', 1)] }, { done: ['a'] }]];
for (const [nm, ob, st] of DAGS) await add('dagRemainingPotential', nm, [ob, st]);
const W: [string, any, any][] = [['ok', { tasks: [T('a', 1, []), T('b', 2, ['a']), T('c', 4, ['a', 'b'])] }, { done: ['a'] }], ['closed', { tasks: [T('a', 1), T('b', 2, ['a'])] }, { done: ['a', 'b'] }], ['skip-dep', { tasks: [T('a', 1), T('b', 2, ['a'])] }, { done: ['b'] }],
  ['none', { tasks: [T('a', 1), T('b', 2, ['a'])] }, { done: [] }], ['cycle', { tasks: [T('a', 1, ['b']), T('b', 1, ['a'])] }, { done: [] }], ['self-dep', { tasks: [T('a', 1, ['a'])] }, { done: [] }], ['unknown-dep', { tasks: [T('a', 1, ['q'])] }, { done: [] }],
  ['dup-dep', { tasks: [T('a', 1), T('b', 2, ['a', 'a'])] }, { done: ['a'] }], ['deps-str', { tasks: [T('a', 1, 'x')] }, { done: [] }], ['deps-mixed', { tasks: [T('a', 1, [5])] }, { done: [] }], ['dup-id', { tasks: [T('a', 1), T('a', 2)] }, { done: [] }],
  ['dup-done', { tasks: [T('a', 1)] }, { done: ['a', 'a'] }], ['unknown-done', { tasks: [T('a', 1)] }, { done: [5] }], ['neg-cost', { tasks: [T('a', -1)] }, { done: [] }], ['frac-cost', { tasks: [T('a', 1.5)] }, { done: [] }],
  ['diamond', { tasks: [T('s', 1), T('l', 2, ['s']), T('r', 3, ['s']), T('t', 4, ['l', 'r'])] }, { done: ['s', 'l'] }], ['long-chain', { tasks: Array.from({ length: 30 }, (_, i) => T('t' + i, i, i ? ['t' + (i - 1)] : [])) }, { done: Array.from({ length: 12 }, (_, i) => 't' + i) }],
  ['overflow', { tasks: [T('a', 2 ** 53 - 1), T('b', 1)] }, { done: [] }], ['null-task', { tasks: [null] }, { done: [] }], ['no-tasks', {}, { done: [] }], ['no-done', { tasks: [] }, {}], ['empty-id', { tasks: [T('', 1)] }, { done: [] }], ['empty', { tasks: [] }, { done: [] }],
  ['deps-null', { tasks: [{ id: 'a', cost: 1, deps: null }] }, { done: [] }]];
for (const [nm, ob, st] of W) await add('dagWeightedPotential', nm, [ob, st]);

// ---------------------------------------------------------------- registry
await add('registryOps', 'defaults', [[['defaults'], ['ids'], ['has', 'dag-remaining-v1'], ['has', 'nope'], ['get', 'l1-feature-v1'], ['get', 'nope'], ['register', 'extra', 'const:3', 'emb'], ['get', 'extra'], ['ids'], ['register', 'extra', 'const:3'],
  ['register', 'l1-feature-v1', 'const:1'], ['freeze'], ['register', 'late', 'const:1'], ['ids']]]);
await add('registryOps', 'default-frozen', [[['default-frozen'], ['ids'], ['register', 'x', 'const:1'], ['has', 'dag-weighted-v1'], ['get', 'dag-weighted-v1']]]);
await add('registryOps', 'new-id-rules', [[['new'], ['register', '', 'const:1'], ['register', 'x'.repeat(128), 'const:1'], ['register', 'x'.repeat(129), 'const:1'], ['register', 5, 'const:1'], ['register', null, 'const:1'], ['ids'], ['register', 'a', 'const:1', 5], ['register', 'b', 'const:1', ''], ['ids']]]);
await add('registryOps', 'proto-ids', [[['new'], ['register', '__proto__', 'const:1'], ['register', 'constructor', 'const:2'], ['has', 'toString'], ['has', '__proto__'], ['get', 'constructor'], ['get', 'valueOf'], ['ids']]]);
await add('registryOps', 'sorted', [[['new'], ['register', 'b', 'const:1'], ['register', 'a', 'const:1'], ['register', 'B', 'const:1'], ['register', 'é', 'const:1'], ['register', 'z', 'const:1'], ['ids']]]);
await add('registryOps', 'from', [[['from', { a: 'const:1', b: { fn: 'const:2', embedder: 'e' }, c: { fn: 'const:3' } }], ['ids'], ['get', 'a'], ['get', 'b'], ['get', 'c'], ['register', 'd', 'const:1']]]);
await add('registryOps', 'from-empty', [[['from', {}], ['ids']]]);

// ---------------------------------------------------------------- goals
const GOAL = (over: any = {}) => ({ objective: { target: [0, 0] }, potential: 'l1-feature-v1', embedder: '', metric: 'l1', epsilon: 2, explorationBudget: 5, ...over });
const GOALS: [string, any][] = [['base', GOAL()], ['no-embedder', (() => { const g: any = GOAL(); delete g.embedder; return g; })()], ['embedder', GOAL({ embedder: 'emb-v1' })], ['dag', GOAL({ objective: { tasks: [T('a', 3), T('b', 4)] }, potential: 'dag-remaining-v1', epsilon: 3, explorationBudget: 4 })],
  ['dagw', GOAL({ objective: { tasks: [T('a', 1), T('b', 2, ['a']), T('c', 4, ['b'])] }, potential: 'dag-weighted-v1', epsilon: 1, explorationBudget: 3 })], ['eps1', GOAL({ epsilon: 1 })], ['eps0', GOAL({ epsilon: 0 })], ['eps-neg', GOAL({ epsilon: -1 })], ['eps-frac', GOAL({ epsilon: 1.5 })],
  ['eps-str', GOAL({ epsilon: '1' })], ['eps-big', GOAL({ epsilon: 2 ** 53 })], ['eps-max', GOAL({ epsilon: 2 ** 53 - 1 })], ['budget0', GOAL({ explorationBudget: 0 })], ['budget-neg', GOAL({ explorationBudget: -1 })], ['budget-frac', GOAL({ explorationBudget: 0.5 })],
  ['budget-str', GOAL({ explorationBudget: '5' })], ['pot-empty', GOAL({ potential: '' })], ['pot-num', GOAL({ potential: 5 })], ['pot-unknown', GOAL({ potential: 'nope' })], ['metric-num', GOAL({ metric: 5 })], ['metric-empty', GOAL({ metric: '' })],
  ['embedder-num', GOAL({ embedder: 5 })], ['obj-null', GOAL({ objective: null })], ['obj-nested', GOAL({ objective: { z: [1, { b: 2, a: 1 }], y: null, x: 'é' } })], ['obj-float', GOAL({ objective: { f: 1.5 } })], ['obj-undefined', (() => { const g: any = GOAL(); delete g.objective; return g; })()],
  ['null', null], ['array', []], ['string', 'x'], ['extra', GOAL({ junk: 1 })], ['unicode', GOAL({ metric: 'mé', objective: { k: 'é' } })]];
for (const [gn, g] of GOALS) {
  await add('goalDigest', gn, [g]);
  await add('commitGoal', gn, [g]);
  const dg = (() => { try { return PG.goalDigest(revive(J(g ?? null))); } catch { return null; } })();
  await add('verifyGoalCommitment', gn + '/ok', [g, dg ?? 'x'.repeat(43)]);
  await add('verifyGoalCommitment', gn + '/bad', [g, 'x'.repeat(43)]);
}
for (const [a, b] of [['base', 'no-embedder'], ['base', 'embedder'], ['base', 'eps1']] as any[]) await add('verifyGoalCommitment', `cross/${a}-${b}`, [GOALS.find(([k]) => k === a)![1], PG.goalDigest(GOALS.find(([k]) => k === b)![1])]);
for (const c of [null, 5, '', {}, [], undefined]) await add('verifyGoalCommitment', 'commit/' + JSON.stringify(c), [GOALS[0][1], c]);

// ---------------------------------------------------------------- state digest, anchors
for (const [nm, st] of [['obj', { x: [1, 2] }], ['key-order', { b: 1, a: 2 }], ['null', null], ['num', 5], ['str', 'é'], ['nested', { a: { b: [{ c: null }] } }], ['float', { x: 1.5 }], ['nan', { x: { $num: 'NaN' } }], ['neg-zero', { x: -0 }], ['empty', {}], ['array', []], ['big', { n: 2 ** 53 }], ['unicode', { 'é': 'é' }], ['bool', true]] as any[]) await add('stateDigest', nm, [st]);
await add('trajectoryHead', 'empty', [[]]);
for (const [salt, head] of [['s', 'h'], ['', 'h'], ['s', ''], [5, 'h'], ['s', null], ['é', 'genesis'], ['a'.repeat(100), 'b'.repeat(100)], ['s', 'genesis']] as any[]) {
  await add('trajectoryAnchorCommit', JSON.stringify([salt, head]), [salt, head]);
  let c: any = 'x'.repeat(43); try { c = PG.trajectoryAnchorCommit(salt, head); } catch { /* keep */ }
  await add('verifyTrajectoryAnchor', JSON.stringify([salt, head]) + '/ok', [c, salt, head]);
  await add('verifyTrajectoryAnchor', JSON.stringify([salt, head]) + '/bad', [c + 'x', salt, head]);
}
await add('verifyTrajectoryAnchor', 'swap', [PG.trajectoryAnchorCommit('s', 'h'), 'h', 's']);

// ---------------------------------------------------------------- fixtures: real trackers build valid steps
const AD = (i: number) => hashCanonical({ action: i });
const build = async (goal: any, initial: any, afters: any[], prs: any = null, sources: any[] = [], gd: any = null) => {
  const commitment = PG.goalDigest(goal);
  const ops: any[] = afters.map((x, i) => (x && x.$observe !== undefined ? ['stepObserved', x.$observe, AD(i)] : ['step', x, AD(i)]));
  const res = await REF.tracker(goal, commitment, initial, prs, gd, sources.map(J), ops.map(J));
  return { commitment, res, steps: res.filter((r: any) => r && r.ok).map((r: any) => J(r.step)) };
};
const SC: [string, any, any, any[]][] = [
  ['l1', GOAL({ epsilon: 2, explorationBudget: 4 }), { x: [10, 10] }, [{ x: [8, 8] }, { x: [6, 6] }, { x: [6, 6] }, { x: [7, 6] }, { x: [4, 4] }, { x: [0, 0] }]],
  ['l1-all-progress', GOAL({ epsilon: 1, explorationBudget: 0 }), { x: [5, 5] }, [{ x: [4, 5] }, { x: [3, 5] }, { x: [0, 0] }]],
  ['dag', GOAL({ objective: { tasks: [T('a', 3), T('b', 4), T('c', 5)] }, potential: 'dag-remaining-v1', epsilon: 3, explorationBudget: 2 }), { done: [] }, [{ done: ['a'] }, { done: ['a', 'b'] }, { done: ['a', 'b', 'c'] }]],
  ['dagw', GOAL({ objective: { tasks: [T('a', 1), T('b', 2, ['a']), T('c', 4, ['b'])] }, potential: 'dag-weighted-v1', epsilon: 1, explorationBudget: 3 }), { done: [] }, [{ done: ['a'] }, { done: ['a', 'b'] }, { done: ['a', 'b', 'c'] }]],
  ['custom-v', GOAL({ potential: 'v', epsilon: 1, explorationBudget: 10, embedder: 'e' }), { v: 9 }, [{ v: 8 }, { v: 8 }, { v: 9 }, { v: 3 }, { v: 0 }]],
];
const CUSTOM_PRS = { mode: 'registry', potentials: [['v', 'v', 'e'], ['bad', 'throws']] };
const TRAJ: Record<string, { goal: any; commitment: string; steps: any[]; prs: any }> = {};
for (const [nm, goal, initial, afters] of SC) {
  const prs = nm === 'custom-v' ? CUSTOM_PRS : null;
  const b = await build(goal, initial, afters, prs);
  TRAJ[nm] = { goal, commitment: b.commitment, steps: b.steps, prs };
  await add('tracker', `script/${nm}`, [goal, null, initial, prs, null, [], [...afters.map((x, i) => ['step', x, AD(i)]), ['state'], ['currentStateDigest'], ['spent'], ['remaining'], ['reached'], ['steps']]]);
}
// tracker behaviours
const g1 = GOAL({ epsilon: 2, explorationBudget: 3 });
await add('tracker', 'denials', [g1, null, { x: [10, 10] }, null, null, [], [['step', { x: [9, 9] }, ''], ['step', { x: [9, 9] }, 5], ['step', { x: [9, 9] }, null], ['step', { x: [1] }, AD(1)], ['step', { x: [1.5, 1] }, AD(2)], ['step', null, AD(3)],
  ['step', { x: [10, 10] }, AD(4)], ['step', { x: [10, 11] }, AD(5)], ['step', { x: [10, 12] }, AD(6)], ['state'], ['spent'], ['step', { x: [10, 14] }, AD(7)], ['step', { x: [8, 10] }, AD(8)], ['spent'], ['remaining']]]);
await add('tracker', 'exhaust-exact', [GOAL({ epsilon: 3, explorationBudget: 2 }), null, { x: [4] }, null, null, [], [['step', { x: [3] }, AD(0)], ['step', { x: [3] }, AD(1)], ['spent'], ['step', { x: [3] }, AD(2)], ['step', { x: [0] }, AD(3)], ['reached']]]);
await add('tracker', 'goal-reached-small-gap', [GOAL({ epsilon: 5, explorationBudget: 0 }), null, { x: [2] }, null, null, [], [['step', { x: [0] }, AD(0)], ['reached'], ['step', { x: [0] }, AD(1)], ['step', { x: [1] }, AD(2)]]]);
await add('tracker', 'at-zero-no-progress', [GOAL({ epsilon: 1, explorationBudget: 2 }), null, { x: [0] }, null, null, [], [['step', { x: [0] }, AD(0)], ['step', { x: [0] }, AD(1)], ['step', { x: [0] }, AD(2)], ['spent']]]);
await add('tracker', 'ctor/commitment-mismatch', [g1, 'x'.repeat(43), { x: [1, 1] }, null, null, [], [['state']]]);
await add('tracker', 'ctor/unknown-potential', [GOAL({ potential: 'nope' }), null, { x: [1] }, null, null, [], [['state']]]);
await add('tracker', 'ctor/embedder-mismatch', [GOAL({ embedder: 'other' }), null, { x: [1] }, null, null, [], [['state']]]);
await add('tracker', 'ctor/embedder-mismatch-custom', [GOAL({ potential: 'v', embedder: '' }), null, { v: 1 }, CUSTOM_PRS, null, [], [['state']]]);
await add('tracker', 'ctor/bad-initial', [g1, null, { x: [1] }, null, null, [], [['state']]]);
await add('tracker', 'ctor/bad-initial-frac', [g1, null, { x: [1.5, 1] }, null, null, [], [['state']]]);
await add('tracker', 'ctor/potential-throws', [GOAL({ potential: 'bad' }), null, { v: 1 }, CUSTOM_PRS, null, [], [['state']]]);
await add('tracker', 'ctor/bad-goal', [GOAL({ epsilon: 0 }), null, { x: [1, 1] }, null, null, [], [['state']]]);
for (const k of ['negative', 'frac', 'nan', 'big', 'const:0', 'const:7']) await add('tracker', 'potential/' + k, [GOAL({ potential: 'p', embedder: '', epsilon: 1, explorationBudget: 5 }), null, { v: 5 }, { mode: 'registry', potentials: [['p', k]] }, null, [], [['reached'], ['step', { v: 4 }, AD(0)], ['state']]]);
await add('tracker', 'registry-record', [GOAL({ potential: 'v', embedder: 'e', epsilon: 1, explorationBudget: 3 }), null, { v: 3 }, { mode: 'record', potentials: [['v', 'v', 'e']] }, null, [], [['step', { v: 2 }, AD(0)], ['step', { v: 0 }, AD(1)], ['reached']]]);
await add('tracker', 'registry-record-unknown', [GOAL(), null, { x: [1, 1] }, { mode: 'record', potentials: [['v', 'v']] }, null, [], [['state']]]);
for (const gd of ['allow', 'deny', 'throws', 'truthy', 'action:' + AD(1), 'seq:1', 'after-v:7']) await add('tracker', 'guard/' + gd.slice(0, 8), [GOAL({ potential: 'v', embedder: 'e', epsilon: 1, explorationBudget: 5 }), null, { v: 9 }, CUSTOM_PRS, gd, [], [['step', { v: 8 }, AD(0)], ['step', { v: 7 }, AD(1)], ['step', { v: 7 }, AD(2)], ['step', { v: 6 }, AD(3)], ['spent'], ['steps']]]);
// observed state sources
const SRCS: [string, any][] = [['memory', { kind: 'memory', id: 'mem', initial: { x: [4, 4] } }], ['attested', { kind: 'attested', id: 'att', signerSecret: S1.b64, initial: { x: [4, 4] } }], ['liar-digest', { kind: 'liar-digest', id: 'ld', initial: { x: [4, 4] } }],
  ['liar-source', { kind: 'liar-source', id: 'ls', initial: { x: [4, 4] } }], ['throws', { kind: 'throws', id: 't' }], ['null', { kind: 'null', id: 'n' }]];
for (const [sn, src] of SRCS) await add('tracker', 'observed/' + sn, [GOAL({ epsilon: 1, explorationBudget: 2 }), null, { x: [6, 6] }, null, null, [src], [['apply', 0, { x: [5, 6] }], ['stepObserved', 0, AD(0)], ['apply', 0, { x: [5, 6] }], ['stepObserved', 0, AD(1)], ['apply', 0, { x: [0, 0] }], ['stepObserved', 0, AD(2)], ['stepObserved', 0, ''], ['steps'], ['spent']]]);
await add('tracker', 'observed/mixed-self-reported', [GOAL({ epsilon: 1, explorationBudget: 2 }), null, { x: [6, 6] }, null, null, [SRCS[0][1]], [['step', { x: [5, 6] }, AD(0)], ['apply', 0, { x: [3, 6] }], ['stepObserved', 0, AD(1)], ['steps']]]);
await add('tracker', 'observed/guard', [GOAL({ potential: 'v', embedder: 'e', epsilon: 1, explorationBudget: 2 }), null, { v: 3 }, CUSTOM_PRS, 'after-v:2', [{ kind: 'memory', id: 'm', initial: { v: 3 } }], [['apply', 0, { v: 2 }], ['stepObserved', 0, AD(0)], ['apply', 0, { v: 1 }], ['stepObserved', 0, AD(1)]]]);
// attested sources: the signed statement, domain separation and tamper cases
const REQ = (over: any = {}) => ({ action_digest: AD(1), goal_commitment: 'g'.repeat(43), prior_digest: 'p'.repeat(43), ...over });
await add('attestedSource', 'ok', [{ kind: 'attested', id: 'att', signerSecret: S1.b64, initial: { x: [1] } }, [REQ(), REQ({ action_digest: AD(2) }), REQ({ prior_digest: 'q'.repeat(43) })]]);
await add('attestedSource', 'other-key', [{ kind: 'attested', id: 'att', signerSecret: S2.b64, initial: { x: [1] } }, [REQ()]]);
await add('attestedSource', 'other-id', [{ kind: 'attested', id: 'att2', signerSecret: S1.b64, initial: { x: [1] } }, [REQ()]]);
await add('attestedSource', 'state-float', [{ kind: 'attested', id: 'att', signerSecret: S1.b64, initial: { x: 1.5 } }, [REQ()]]);
await add('attestedSource', 'memory', [{ kind: 'memory', id: 'mem', initial: { x: [1] } }, [REQ(), REQ()]]);
for (const bad of [{ id: '' }, { signerSecret: 'AAAA' }, { alg: 'bogus' }]) await add('attestedSource', 'ctor/' + Object.keys(bad)[0], [{ kind: 'attested', id: 'att', signerSecret: S1.b64, initial: null, ...bad }, [REQ()]]);

// ---------------------------------------------------------------- steps: forgery
const stepBody = (s: any) => { const { digest: _d, ...b } = s; return b; };
const redigest = (s: any) => ({ ...s, digest: hashCanonical({ t: 'pca-progress-step', v: PG.PROGRESS_VERSION, ...stepBody(s) }) });
const forge = (s: any, over: any) => redigest({ ...s, ...over });
const T1 = TRAJ.l1, V1 = T1.steps[0]; // progress step (10,10)->(8,8)
const EXP = T1.steps.find((s: any) => s.mode === 'exploration')!;
const stepCases: [string, any][] = [['ok', V1], ['ok-exploration', EXP], ['goal-commitment', forge(V1, { goal_commitment: 'x'.repeat(43) })], ['seq', forge(V1, { seq: 1 })], ['seq-neg', forge(V1, { seq: -1 })], ['seq-frac', forge(V1, { seq: 0.5 })],
  ['before-digest', forge(V1, { before_digest: 'x'.repeat(43) })], ['after-digest', forge(V1, { after_digest: 'x'.repeat(43) })], ['before-state', forge(V1, { before: { x: [9, 10] } })], ['after-state', forge(V1, { after: { x: [0, 0] } })],
  ['pot-before', forge(V1, { potential_before: 99 })], ['pot-after', forge(V1, { potential_after: 0 })], ['mode', forge(V1, { mode: 'exploration' })], ['mode-exp', forge(EXP, { mode: 'progress' })], ['charge', forge(V1, { charge: 1 })], ['charge-exp', forge(EXP, { charge: EXP.charge + 1 })],
  ['mode-bad', forge(V1, { mode: 'x' })], ['charge-frac', forge(V1, { charge: 0.5 })], ['source', forge(V1, { state_source: 'mem' })], ['evidence', forge(V1, { evidence_digest: 'e' })], ['prev', forge(V1, { prev: 'x'.repeat(43) })], ['action-digest', forge(V1, { action_digest: 'other' })],
  ['digest-stale', { ...V1, seq: 0, prev: 'genesis', digest: 'x'.repeat(43) }], ['digest-missing', (() => { const s = { ...V1 }; delete (s as any).digest; return s; })()], ['before-missing', (() => { const s = { ...V1 }; delete (s as any).before; return redigest(s); })()], ['after-missing', (() => { const s = { ...V1 }; delete (s as any).after; return redigest(s); })()],
  ['extra-field', redigest({ ...V1, junk: 1 })], ['extra-field-stale', { ...V1, junk: 1 }], ['null', null], ['array', []], ['string', 'x'], ['empty', {}], ['before-null', forge(V1, { before: null })], ['after-float', forge(V1, { after: { x: [8.5, 8] } })],
  ['state-key-order', forge(V1, { before: { x: [10, 10] } })], ['unknown-state-shape', forge(V1, { before: { y: [10, 10] }, after: { y: [8, 8] }, before_digest: PG.stateDigest({ y: [10, 10] }), after_digest: PG.stateDigest({ y: [8, 8] }) })],
  ['same-state', forge(V1, { after: V1.before, after_digest: V1.before_digest, potential_after: V1.potential_before, mode: 'exploration', charge: 2 })], ['goal-reaching', (() => { const s = T1.steps[T1.steps.length - 1]; return s; })()]];
for (const [sn, s] of stepCases) {
  await add('progressStepDigest', sn, [s]);
  await add('verifyProgressStep', `${sn}/plain`, [T1.goal, T1.commitment, s, null]);
  await add('verifyProgressStep', `${sn}/attest-off`, [T1.goal, T1.commitment, s, { requireAttestedState: false }]);
}
// options: expectations, trust, guards, registries, attestations
const ST = (s: any = V1) => s;
const O1: [string, any][] = [['seq-ok', { expectedSeq: 0, requireAttestedState: false }], ['seq-bad', { expectedSeq: 1, requireAttestedState: false }], ['prev-ok', { expectedPrev: 'genesis', requireAttestedState: false }], ['prev-bad', { expectedPrev: 'x', requireAttestedState: false }],
  ['action-ok', { expectedActionDigest: V1.action_digest, requireAttestedState: false }], ['action-bad', { expectedActionDigest: 'x', requireAttestedState: false }], ['before-ok', { expectedBeforeDigest: V1.before_digest, requireAttestedState: false }],
  ['before-bad', { expectedBeforeDigest: 'x', requireAttestedState: false }], ['after-ok', { expectedAfterDigest: V1.after_digest, requireAttestedState: false }], ['after-bad', { expectedAfterDigest: 'x', requireAttestedState: false }],
  ['self-reported-default', {}], ['self-reported-explicit-true', { requireAttestedState: true }], ['self-reported-null', { requireAttestedState: null }], ['trusted-empty', { trustedStateSources: [], requireAttestedState: false }], ['trusted-other', { trustedStateSources: ['mem'], requireAttestedState: false }],
  ['trusted-blank-listed', { trustedStateSources: [''], requireAttestedState: false }], ['trusted-blank-listed-default', { trustedStateSources: [''] }], ['guard-allow', { guard: 'allow', requireAttestedState: false }], ['guard-deny', { guard: 'deny', requireAttestedState: false }], ['guard-throws', { guard: 'throws', requireAttestedState: false }],
  ['guard-truthy', { guard: 'truthy', requireAttestedState: false }], ['guard-seq0', { guard: 'seq:0', requireAttestedState: false }], ['guard-seq1', { guard: 'seq:1', requireAttestedState: false }], ['att-allow', { attestation: 'allow', requireAttestedState: false }], ['att-deny', { attestation: 'deny', requireAttestedState: false }],
  ['att-throws', { attestation: 'throws', requireAttestedState: false }], ['att-truthy', { attestation: 'truthy', requireAttestedState: false }], ['registry-unknown', { registry: { mode: 'registry', potentials: [['x', 'const:1']] }, requireAttestedState: false }],
  ['registry-record-unknown', { registry: { mode: 'record', potentials: [['x', 'const:1']] }, requireAttestedState: false }], ['registry-const', { registry: { mode: 'registry', potentials: [['l1-feature-v1', 'const:3']] }, requireAttestedState: false }],
  ['registry-throws', { registry: { mode: 'registry', potentials: [['l1-feature-v1', 'throws']] }, requireAttestedState: false }], ['registry-embedder', { registry: { mode: 'registry', potentials: [['l1-feature-v1', 'l1-feature-v1', 'emb']] }, requireAttestedState: false }]];
for (const [on, op] of O1) await add('verifyProgressStep', 'opts/' + on, [T1.goal, T1.commitment, ST(), op]);
await add('verifyProgressStep', 'goal/tampered', [{ ...T1.goal, epsilon: 3 }, T1.commitment, V1, { requireAttestedState: false }]);
await add('verifyProgressStep', 'goal/wrong-commitment', [T1.goal, 'x'.repeat(43), V1, { requireAttestedState: false }]);
await add('verifyProgressStep', 'goal/null', [null, T1.commitment, V1, { requireAttestedState: false }]);
await add('verifyProgressStep', 'goal/step-other-goal', [TRAJ['l1-all-progress'].goal, TRAJ['l1-all-progress'].commitment, V1, { requireAttestedState: false }]);
// potential edge cases of classification (epsilon boundary): potential_before - epsilon vs potential_after
for (const [pb, pa, eps] of [[10, 8, 2], [10, 9, 2], [10, 10, 2], [10, 11, 2], [10, 0, 20], [1, 0, 5], [0, 0, 1], [0, 1, 1], [5, 3, 3], [2, 0, 1], [3, 2, 1]] as any[]) {
  const goal = GOAL({ potential: 'v', embedder: 'e', epsilon: eps, explorationBudget: 100 });
  const reg = CUSTOM_PRS;
  const before = { v: pb }, after = { v: pa };
  const cls = (() => { const req = pb - eps; if (pa <= req || (pa === 0 && pb > 0)) return { mode: 'progress', charge: 0 }; return { mode: 'exploration', charge: pa - req }; })();
  const body = { goal_commitment: PG.goalDigest(goal), seq: 0, before, after, before_digest: PG.stateDigest(before), after_digest: PG.stateDigest(after), action_digest: AD(9), mode: cls.mode, potential_before: pb, potential_after: pa, charge: cls.charge, state_source: 'src', evidence_digest: '', prev: 'genesis' };
  const step = redigest(body);
  await add('verifyProgressStep', `classify/${pb}-${pa}-${eps}`, [goal, PG.goalDigest(goal), step, { registry: reg, requireAttestedState: false }]);
  await add('verifyProgressStep', `classify/${pb}-${pa}-${eps}/flip`, [goal, PG.goalDigest(goal), forge(step, { mode: cls.mode === 'progress' ? 'exploration' : 'progress', charge: cls.mode === 'progress' ? 1 : 0 }), { registry: reg, requireAttestedState: false }]);
}

// ---------------------------------------------------------------- trajectories
const TOPT: [string, (t: any) => any][] = [['plain', () => ({ requireAttestedState: false })], ['default', () => ({})], ['default-trusted', () => ({ trustedStateSources: [''] })],
  ['initial-ok', (t) => ({ requireAttestedState: false, initial: t.steps[0]?.before })], ['initial-bad', () => ({ requireAttestedState: false, initial: { x: [99, 99] } })],
  ['initial-digest-ok', (t) => ({ requireAttestedState: false, initialDigest: t.steps[0]?.before_digest })], ['initial-digest-bad', () => ({ requireAttestedState: false, initialDigest: 'x' })],
  ['initial-both', (t) => ({ requireAttestedState: false, initial: { x: [99] }, initialDigest: t.steps[0]?.before_digest })], ['initial-float', () => ({ requireAttestedState: false, initial: { x: 1.5 } })],
  ['actions-ok', (t) => ({ requireAttestedState: false, expectedActionDigests: t.steps.map((s: any) => s.action_digest) })], ['actions-short', (t) => ({ requireAttestedState: false, expectedActionDigests: t.steps.map((s: any) => s.action_digest).slice(1) })],
  ['actions-long', (t) => ({ requireAttestedState: false, expectedActionDigests: [...t.steps.map((s: any) => s.action_digest), 'x'] })], ['actions-wrong', (t) => ({ requireAttestedState: false, expectedActionDigests: t.steps.map(() => 'x') })],
  ['guard-deny', () => ({ requireAttestedState: false, guard: 'deny' })], ['guard-seq2', () => ({ requireAttestedState: false, guard: 'seq:2' })], ['att-deny', () => ({ requireAttestedState: false, attestation: 'deny' })], ['att-allow', () => ({ requireAttestedState: false, attestation: 'allow' })]];
for (const [tn, t] of Object.entries(TRAJ)) for (const [on, fo] of TOPT) {
  await add('verifyTrajectory', `${tn}/${on}`, [t.goal, t.commitment, t.steps, fo(t)]);
  if (on === 'plain') {
    await add('trajectoryHead', tn, [t.steps]);
    await add('anchorTrajectoryHead', tn + '/fresh', [t.steps, 'salt-1', []]);
    await add('anchorTrajectoryHead', tn + '/prior', [t.steps, 'salt-2', ['c1', 'c2', 'c3']]);
  }
}
const T2 = TRAJ.l1;
const trajMut: [string, any[]][] = [['empty', []], ['not-array', 'x' as any], ['null', null as any], ['reorder', [T2.steps[1], T2.steps[0], ...T2.steps.slice(2)]], ['drop-first', T2.steps.slice(1)], ['drop-middle', [...T2.steps.slice(0, 2), ...T2.steps.slice(3)]], ['dup', [T2.steps[0], T2.steps[0], ...T2.steps.slice(1)]],
  ['truncate', T2.steps.slice(0, 3)], ['extra-null', [...T2.steps, null]], ['extra-junk', [...T2.steps, {}]], ['one', [T2.steps[0]]], ['tamper-middle', [T2.steps[0], forge(T2.steps[1], { charge: 9 }), ...T2.steps.slice(2)]],
  ['tamper-chain', [T2.steps[0], forge(T2.steps[1], { prev: 'x' }), ...T2.steps.slice(2)]], ['replace-tail', [...T2.steps.slice(0, 2), forge(T2.steps[2], { prev: T2.steps[1].digest, after: { x: [0, 0] }, after_digest: PG.stateDigest({ x: [0, 0] }), potential_after: 0, mode: 'progress', charge: 0 })]],
  ['discontinuous', [T2.steps[0], forge(T2.steps[1], { before: { x: [9, 9] }, before_digest: PG.stateDigest({ x: [9, 9] }), potential_before: 18 })]], ['budget-over', (() => { const g = TRAJ.l1; return g.steps; })()]];
for (const [mn, st] of trajMut) await add('verifyTrajectory', 'mut/' + mn, [T2.goal, T2.commitment, st, { requireAttestedState: false, initial: { x: [10, 10] } }]);
// the budget invariant: a trajectory whose recomputed charges exceed the committed budget
const rechain = (steps: any[], over: any) => { let prev = 'genesis'; return steps.map((s) => { const f = redigest({ ...s, ...over, prev }); prev = f.digest; return f; }); };
for (const b of [0, 1, 2, 3]) { const gb = GOAL({ epsilon: 2, explorationBudget: b }); await add('verifyTrajectory', 'budget/' + b, [gb, PG.goalDigest(gb), rechain(TRAJ.l1.steps, { goal_commitment: PG.goalDigest(gb) }), { requireAttestedState: false }]); }
await add('verifyTrajectory', 'goal-mismatch', [{ ...T2.goal, epsilon: 9 }, T2.commitment, T2.steps, { requireAttestedState: false }]);
await add('verifyTrajectory', 'registry-unknown', [T2.goal, T2.commitment, T2.steps, { requireAttestedState: false, registry: { mode: 'registry', potentials: [['x', 'const:1']] } }]);
await add('verifyTrajectory', 'empty/initial-unknown-potential', [T2.goal, T2.commitment, [], { requireAttestedState: false, initial: { x: [1] }, registry: { mode: 'registry', potentials: [['x', 'const:1']] } }]);
await add('verifyTrajectory', 'empty/initial-ok', [T2.goal, T2.commitment, [], { requireAttestedState: false, initial: { x: [3, 4] } }]);
await add('verifyTrajectory', 'empty/initial-bad-state', [T2.goal, T2.commitment, [], { requireAttestedState: false, initial: { x: [3] } }]);
await add('verifyTrajectory', 'empty/none', [T2.goal, T2.commitment, [], {}]);
await add('verifyTrajectory', 'goal-reached', [TRAJ['l1-all-progress'].goal, TRAJ['l1-all-progress'].commitment, TRAJ['l1-all-progress'].steps, { requireAttestedState: false }]);
await add('verifyTrajectory', 'custom-registry', [TRAJ['custom-v'].goal, TRAJ['custom-v'].commitment, TRAJ['custom-v'].steps, { requireAttestedState: false, registry: CUSTOM_PRS }]);
await add('verifyTrajectory', 'custom-registry-missing', [TRAJ['custom-v'].goal, TRAJ['custom-v'].commitment, TRAJ['custom-v'].steps, { requireAttestedState: false }]);

// ---------------------------------------------------------------- attested trajectories (a real attested source + the verifier hook)
{
  const goal = GOAL({ epsilon: 1, explorationBudget: 2 });
  const commitment = PG.goalDigest(goal);
  const srcSpec = { kind: 'attested', id: 'att', signerSecret: S1.b64, initial: { x: [6, 6] } };
  const ops: any[] = [];
  const worlds = [{ x: [5, 6] }, { x: [5, 6] }, { x: [3, 3] }, { x: [0, 0] }];
  worlds.forEach((w, i) => { ops.push(['apply', 0, w], ['stepObserved', 0, AD(i)]); });
  const res: any[] = await REF.tracker(goal, commitment, { x: [6, 6] }, null, null, [J(srcSpec)], J(ops));
  const steps = res.filter((r) => r && r.step).map((r) => J(r.step));
  // the attestations the source emitted during the run: re-run an identical source and collect them
  const s = mkSource(J(srcSpec));
  let prior = PG.stateDigest({ x: [6, 6] });
  const attestations: any[] = [];
  for (const [i, w] of worlds.entries()) { s.set(w); const ob = await s.observe({ action_digest: AD(i), goal_commitment: commitment, prior_digest: prior }); attestations.push(ob.evidence); prior = ob.state_digest; }
  const AVs: [string, any][] = [['ok', { attested: { trustedKeys: { att: S1.pk }, attestations } }], ['wrong-key', { attested: { trustedKeys: { att: S2.pk }, attestations } }], ['untrusted-source', { attested: { trustedKeys: { other: S1.pk }, attestations } }],
    ['no-attestations', { attested: { trustedKeys: { att: S1.pk }, attestations: [] } }], ['partial', { attested: { trustedKeys: { att: S1.pk }, attestations: attestations.slice(1) } }],
    ['tampered-sig', { attested: { trustedKeys: { att: S1.pk }, attestations: attestations.map((a, i) => (i === 1 ? { ...a, sig: a.sig.slice(0, -2) + 'AA' } : a)) } }],
    ['tampered-state', { attested: { trustedKeys: { att: S1.pk }, attestations: attestations.map((a, i) => (i === 1 ? { ...a, state_digest: 'x'.repeat(43) } : a)) } }],
    ['tampered-goal', { attested: { trustedKeys: { att: S1.pk }, attestations: attestations.map((a) => ({ ...a, goal_commitment: 'x'.repeat(43) })) } }],
    ['other-source-field', { attested: { trustedKeys: { att: S1.pk }, attestations: attestations.map((a) => ({ ...a, source: 'att2' })) } }],
    ['unknown-alg', { attested: { trustedKeys: { att: S1.pk }, attestations: attestations.map((a) => ({ ...a, alg: 'bogus' })) } }], ['alg-hybrid-no-pq', { attested: { trustedKeys: { att: S1.pk }, attestations: attestations.map((a) => ({ ...a, alg: 'hybrid-ed25519-ml-dsa-65' })) } }],
    ['alg-ml-dsa-no-pq', { attested: { trustedKeys: { att: S1.pk }, attestations: attestations.map((a) => ({ ...a, alg: 'ml-dsa-65', pq_pk: 'AAAA' })) } }], ['empty-key', { attested: { trustedKeys: { att: '' }, attestations } }],
    ['keys-null', { attested: { trustedKeys: null, attestations } }], ['att-junk', { attested: { trustedKeys: { att: S1.pk }, attestations: [null, 5, {}, ...attestations] } }]];
  for (const [an, av] of AVs) {
    await add('verifyTrajectory', 'attested/' + an, [goal, commitment, steps, { trustedStateSources: ['att'], attestation: av }]);
    await add('verifyProgressStep', 'attested/' + an + '/step1', [goal, commitment, steps[1], { trustedStateSources: ['att'], attestation: av }]);
    await add('attestedStateVerifier', an, [av.attested, steps[1] ?? null]);
  }
  await add('verifyTrajectory', 'attested/no-hook-needs-trusted-sources', [goal, commitment, steps, { trustedStateSources: ['att'] }]);
  await add('verifyTrajectory', 'attested/hook-but-untrusted-list', [goal, commitment, steps, { trustedStateSources: ['zzz'], attestation: AVs[0][1] }]);
  await add('verifyTrajectory', 'attested/default-no-trusted-list', [goal, commitment, steps, {}]);
  await add('verifyTrajectory', 'attested/tampered-evidence', [goal, commitment, steps.map((s: any, i: number) => (i === 1 ? forge(s, { evidence_digest: 'x'.repeat(43) }) : s)), { trustedStateSources: ['att'], attestation: AVs[0][1] }]);
  for (const [an, a] of attestations.slice(0, 2).entries()) {
    for (const [kn, k] of [['ok', S1.pk], ['other', S2.pk], ['empty', ''], ['num', 5], ['short', 'AAAA']] as any[]) await add('verifyStateAttestation', `a${an}/${kn}`, [a, k, null]);
    for (const [pn, pin] of [['pins', { pqPins: { [S1.pk]: 'AAAA' } }], ['unbound', { allowUnboundPq: true }]] as any[]) await add('verifyStateAttestation', `a${an}/pin/${pn}`, [a, S1.pk, pin]);
    for (const f of ['sig', 'source', 'goal_commitment', 'action_digest', 'prior_digest', 'state_digest']) {
      await add('verifyStateAttestation', `a${an}/del-${f}`, [Object.fromEntries(Object.entries(a).filter(([k]) => k !== f)), S1.pk, null]);
      await add('verifyStateAttestation', `a${an}/mut-${f}`, [{ ...a, [f]: typeof a[f] === 'string' ? a[f].slice(0, -1) + (a[f].endsWith('A') ? 'B' : 'A') : 'x' }, S1.pk, null]);
    }
  }
  for (const bad of [null, 5, 'x', [], {}]) await add('verifyStateAttestation', 'junk/' + JSON.stringify(bad), [bad, S1.pk, null]);
  // ML-DSA-65 and hybrid attestations signed by the reference with seed-derived PQ keys: verify-side cases (pins decide)
  const mlSeed = seed('progress/mldsa'); const ml = PQ.mlDsa65Keygen(mlSeed.slice(0, 32));
  const pqPk = PQ.encodeMlDsaPublicKey ? PQ.encodeMlDsaPublicKey(ml.publicKey) : b64u(ml.publicKey);
  for (const alg of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65']) {
    const src = new PG.AttestedStateSource({ id: 'att', signerSecret: S1.sk, observeState: () => ({ x: [1] }), suite: { alg, mlDsa: ml } });
    const ob = await src.observe({ action_digest: AD(0), goal_commitment: commitment, prior_digest: 'p'.repeat(43) });
    const a = J(ob.evidence);
    await add('verifyStateAttestation', `${alg}/no-pin`, [a, S1.pk, null]);
    await add('verifyStateAttestation', `${alg}/pinned`, [a, S1.pk, { pqPins: { [S1.pk]: a.pq_pk } }]);
    await add('verifyStateAttestation', `${alg}/wrong-pin`, [a, S1.pk, { pqPins: { [S1.pk]: pqPk.slice(0, -1) + (pqPk.endsWith('A') ? 'B' : 'A') } }]);
    await add('verifyStateAttestation', `${alg}/unbound`, [a, S1.pk, { allowUnboundPq: true }]);
    await add('verifyStateAttestation', `${alg}/wrong-pq-sig`, [{ ...a, pq_sig: a.pq_sig ? a.pq_sig.slice(0, -2) + 'AA' : undefined, sig: alg === 'ml-dsa-65' ? a.sig.slice(0, -2) + 'AA' : a.sig }, S1.pk, { pqPins: { [S1.pk]: a.pq_pk } }]);
    await add('verifyStateAttestation', `${alg}/downgrade`, [Object.fromEntries(Object.entries(a).filter(([k]) => k !== 'alg')), S1.pk, { pqPins: { [S1.pk]: a.pq_pk } }]);
  }
}

// ---------------------------------------------------------------- signed steps and trajectories
{
  const t = TRAJ.l1;
  const act = t.steps.map((s: any) => s.action_digest);
  const signedAll = t.steps.map((s: any) => J(PG.signProgressStep(s, H1.sk, H1.pk)));
  for (const [i, s] of t.steps.entries()) await add('signProgressStep', `step${i}`, [s, H1.sk, H1.pk]);
  await add('signProgressStep', 'other-key', [t.steps[0], H2.sk, H2.pk]);
  await add('signProgressStep', 'mismatched-holder', [t.steps[0], H1.sk, H2.pk]);
  const SO = (over: any = {}) => ({ expectedActionDigest: act[0], expectedHolder: H1.pk, requireAttestedState: false, ...over });
  const sg = signedAll[0];
  const SC2: [string, any, any][] = [['ok', sg, SO()], ['holder', sg, SO({ expectedHolder: H2.pk })], ['action', sg, SO({ expectedActionDigest: 'x' })], ['no-expected-holder', sg, (() => { const o2: any = SO(); delete o2.expectedHolder; return o2; })()],
    ['no-expected-action', sg, (() => { const o2: any = SO(); delete o2.expectedActionDigest; return o2; })()], ['bad-sig', { ...sg, sig: sg.sig.slice(0, -2) + 'AA' }, SO()], ['sig-other-key', J(PG.signProgressStep(t.steps[0], H2.sk, H1.pk)), SO()],
    ['sig-other-holder-field', J(PG.signProgressStep(t.steps[0], H1.sk, H2.pk)), SO({ expectedHolder: H2.pk })], ['holder-swapped', { ...sg, holder: H2.pk }, SO({ expectedHolder: H2.pk })], ['sig-empty', { ...sg, sig: '' }, SO()], ['sig-num', { ...sg, sig: 5 }, SO()],
    ['holder-num', { ...sg, holder: 5 }, SO()], ['step-null', { ...sg, step: null }, SO()], ['null', null, SO()], ['string', 'x', SO()], ['step-tampered', { ...sg, step: { ...sg.step, charge: 1 } }, SO()],
    ['step-reforged', { ...sg, step: forge(sg.step, { charge: 1 }) }, SO()], ['sig-for-other-step', { ...sg, sig: signedAll[1].sig }, SO()], ['goal-mismatch-step', J(PG.signProgressStep(forge(t.steps[0], { goal_commitment: 'x'.repeat(43) }), H1.sk, H1.pk)), SO()],
    ['self-reported-default', sg, SO({ requireAttestedState: undefined })], ['guard-deny', sg, SO({ guard: 'deny' })], ['seq-opt', sg, SO({ expectedSeq: 0 })], ['seq-opt-bad', sg, SO({ expectedSeq: 4 })], ['trusted', sg, SO({ trustedStateSources: [''] })],
    ['sig-b64-padded', { ...sg, sig: sg.sig + '==' }, SO()], ['sig-nonstrict-tail', { ...sg, sig: sg.sig.slice(0, -1) + (sg.sig.endsWith('A') ? 'B' : 'A') }, SO()]];
  for (const [sn, s, op] of SC2) await add('verifySignedProgressStep', sn, [t.goal, t.commitment, s, op]);
  const TO = (over: any = {}) => ({ expectedActionDigests: act, expectedHolder: H1.pk, requireAttestedState: false, ...over });
  const TS: [string, any, any][] = [['ok', signedAll, TO()], ['holder', signedAll, TO({ expectedHolder: H2.pk })], ['actions-short', signedAll, TO({ expectedActionDigests: act.slice(1) })], ['actions-long', signedAll, TO({ expectedActionDigests: [...act, 'x'] })],
    ['actions-wrong-at-2', signedAll, TO({ expectedActionDigests: act.map((a: string, i: number) => (i === 2 ? 'x' : a)) })], ['bad-sig-at-3', signedAll.map((s: any, i: number) => (i === 3 ? { ...s, sig: s.sig.slice(0, -2) + 'AA' } : s)), TO()],
    ['holder-at-1', signedAll.map((s: any, i: number) => (i === 1 ? { ...s, holder: H2.pk } : s)), TO()], ['junk-at-2', signedAll.map((s: any, i: number) => (i === 2 ? null : s)), TO()], ['reorder', [signedAll[1], signedAll[0], ...signedAll.slice(2)], TO()],
    ['not-array', 'x', TO()], ['initial', signedAll, TO({ initial: { x: [10, 10] } })], ['initial-bad', signedAll, TO({ initial: { x: [1, 1] } })], ['default-attest', signedAll, TO({ requireAttestedState: undefined })], ['guard', signedAll, TO({ guard: 'seq:3' })],
    ['empty', [], TO({ expectedActionDigests: [] })], ['tampered-step-resigned-wrong', signedAll.map((s: any, i: number) => (i === 1 ? { ...s, step: forge(s.step, { charge: 3 }) } : s)), TO()]];
  for (const [sn, s, op] of TS) await add('verifySignedTrajectory', sn, [t.goal, t.commitment, s, op]);
}
console.log('cases', o.cases.length);
refWrite(o, 'progress');
