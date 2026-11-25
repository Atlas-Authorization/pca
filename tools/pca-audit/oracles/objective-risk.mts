// Oracle: every function and constant of packages/pca/src/objective-risk.ts (canonical action, inverse registry + reversibility, resource graph + blast
// radius, native / BYO embedders, goal commitment + distance, split-conformal calibration, harm currency, objectiveRisk, objectiveRiskOracle), TS reference.
// Writes out/ref-objective-risk.json.gz. Pure and deterministic: no keys, no clock, no randomness. Case shape (as every sibling): {fn, name, args, out}; `out`
// is what the reference returned, or {"$throws": message}. objective-risk digests are LENIENT canonical hashes (sha256 over the canonical JSON that allows
// any finite double, printed like ECMAScript Number->string), so the digests of graphs, calibration sets and risk inputs depend on shortest-round-trip
// double formatting: that is what these cases pin down.
//
// PORTING (fn(args) -> native entry point; results compared by JSON value; a reference throw = the native refuses)
//   {"$num":"NaN"|"Infinity"|"-Infinity"} anywhere in args = that non-finite double (plain JSON cannot carry them); in `out` a non-finite double is the same form.
//   specs (JSON descriptions of the objects the reference builds):
//     action AS   {verb, resource, params?}
//     registry RGS   {trusted:[verifierId,...], entries:[[verb, {inverseKind, fidelity, verification?:{verifierId, evidenceDigest}}], ...]}: an
//                    InMemoryInverseRegistry(trusted) with register(verb, entry) applied in order (a later entry for the same verb replaces the earlier)
//     graph GS       {nodes:[{id, harm?:{unit:number}}], edges:[{from,to,kind}]}: nodes added in order (same id again replaces the node), then edges in order;
//                    an edge whose endpoint is not a node refuses ("edge endpoints must exist"): the whole case is a {"$throws"} refusal
//     embedder ES    {scheme:"native", config} | {scheme:"byo", descriptor, claimedModelId?, infer} where infer = {vector:[...]} (returns it for every action)
//                    | {throws:true} | {notArray:true} (returns a non-array) | {byLen:true} (vector of descriptor.dims numbers, component i = canonical-json
//                    length + i) | {scheme:"fixed", modelId, dims, config, vector} (a custom embedder returning `vector` verbatim, valid or not)
//     scope          null | {edgeKinds?:[...], maxDepth?:n}
//     ctx            objectiveRisk context {registry:RGS, authorizedKinds:[...], graph:GS, scope?, embedder:ES, goal:<GoalCommitment literal>,
//                    commitments:{registryDigest, graphDigest, calibrationDigest?}, denominations:[{id,ceiling,weight}], weights:{alpha..zeta}, taint, age,
//                    attestedUncertainty?, calibration?:[numbers]}
//   constants []                                   -> {METRIC, DEFAULT_EPSILON, NATIVE_SCHEME, DEFAULT_MAX_PARAM_LEAVES, DEFAULT_NATIVE_CONFIG}
//   canonicalAction [AS] -> {verb (trimmed, lowercased, NFC), resource (trimmed, NFC), params (all strings and keys NFC)} or refuses (non-string verb/resource,
//                    empty after trim, params not an object, duplicate key after NFC, a value without a stable encoding)
//   canonicalActionJson [canonicalAction] -> string ; canonicalActionDigest [canonicalAction] -> digest (lenient canonical hash)
//   registryOps [trusted, ops] -> results of ["register",verb,entry] (null) ["lookup",verb] (entry|null) ["trustedVerifiers"] ["digest"] on a new registry
//   registryDigest [RGS] -> digest
//   reversibility [{verb}, RGS, authorizedKinds] -> {class, value, inverseKind?}
//   graphBuild [GS] -> {size, digest} ; graphReachable [GS, start, scope] -> sorted ids ; graphNode [GS, id] -> {id, harm?}|null
//   blastRadius [{resource}, GS, scope] -> {count, reachable, normalized, harm}
//   nativeEmbed [config, canonicalAction] -> {modelId, dims, config (the committed {scheme, ...config}), vector} (config validation and the param-leaf cap refuse)
//   byoModelId [descriptor] -> string ; byoEmbed [descriptor, claimedModelId|null, infer, canonicalAction] -> {modelId, dims, vector} (refuses on a bad descriptor,
//                    a claimed id that is not the descriptor hash, an invalid vector, a component beyond the quantization range)
//   validateVector [v, dims] -> int[] (negative zero normalised) or refuses
//   conformanceCheck [ES, cases:[{action, vector}]] -> bool
//   commitGoal [ES, AS, epsilon|null] -> GoalCommitment (null = the default epsilon) or refuses ; verifyGoalCommitment [goal, ES] -> null | error string
//   vectorDistance [a, b, epsilon|null] -> number ; committedDistanceChecked [canonicalAction, goal, ES] -> {ok:true,value}|{ok:false,reason}
//   committedDistance [AS, goal, ES] -> number (1 on any failure)
//   calibrate [raw, scores] -> number ; conformalThreshold [scores, alpha] -> number (Infinity as {"$num":"Infinity"}) ; calibrationDigest [scores] -> digest
//   harmReport [units, denominations] -> {units, normalized}
//   objectiveRisk [AS, ctx] -> {r, valid, reasons, raw, inputs, reversibility, blast, harm, evidenceDigest}; an unencodable action is {valid:false}. One reference quirk is recorded as a refusal:
//                    a graph with a non-finite harm weight, or a calibration set with a non-finite score, makes the digest comparison throw (the native refuses; do not invent a verdict)
//   objectiveRiskOracle [ctx, input, snapshot] -> OracleResolution (the oracle's resolve(input, snapshot); snapshot = {action:{action:{verb,resource,params?}}})
import { Oracle, refWrite } from './lib.mjs';

const O: any = await import('../../../packages/pca/src/objective-risk.ts');
const o = new Oracle('objective-risk', 'tools/pca-audit/oracles/objective-risk.mts', 'TS-reference oracle for packages/pca/src/objective-risk.ts.');

const NUM: any = { NaN: NaN, Infinity: Infinity, '-Infinity': -Infinity };
const revive = (v: any): any => Array.isArray(v) ? v.map(revive)
  : v && typeof v === 'object' ? ('$num' in v && Object.keys(v).length === 1 ? NUM[v.$num] : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, revive(x)]))) : v;
// Object.fromEntries creates own properties even for "__proto__", like JSON.parse

const mkRegistry = (s: any) => { const r = new O.InMemoryInverseRegistry(s.trusted ?? []); for (const [v, e] of s.entries ?? []) r.register(v, e); return r; };
const mkGraph = (s: any) => { const g = new O.ResourceGraph(); for (const n of s.nodes ?? []) g.addNode(n); for (const e of s.edges ?? []) g.addEdge(e); return g; };
const mkEmbedder = (s: any) => {
  if (s.scheme === 'native') return O.nativeHashEmbedder(s.config);
  if (s.scheme === 'fixed') return { modelId: s.modelId, config: s.config, dims: s.dims, embed: () => s.vector };
  return mkByo(s.descriptor, s.claimedModelId ?? undefined, s.infer);
};
const inferOf = (i: any) => (j: string) => {
  if (i.throws) throw new Error('infer boom');
  if (i.notArray) return 'x' as any;
  if (i.byLen) return Array.from({ length: i.dims ?? 4 }, (_, k) => j.length + k);
  return i.vector;
};
const mkByo = (d: any, claimed: any, infer: any) => O.byoEmbedder(d, inferOf(infer.byLen ? { ...infer, dims: d.dims } : infer), claimed);
const mkCtx = (c: any) => ({
  registry: mkRegistry(c.registry), authorizedKinds: new Set<string>(c.authorizedKinds), graph: mkGraph(c.graph), ...(c.scope ? { scope: c.scope } : {}), embedder: mkEmbedder(c.embedder),
  goal: c.goal, commitments: c.commitments, denominations: c.denominations, weights: c.weights, taint: c.taint, age: c.age,
  ...(c.attestedUncertainty !== undefined ? { attestedUncertainty: c.attestedUncertainty } : {}), ...(c.calibration ? { calibration: c.calibration } : {}),
});
const sc = (s: any) => (s === null ? undefined : s);
const REF: Record<string, (...a: any[]) => any> = {
  constants: () => ({ METRIC: O.METRIC, DEFAULT_EPSILON: O.DEFAULT_EPSILON, NATIVE_SCHEME: O.NATIVE_SCHEME, DEFAULT_MAX_PARAM_LEAVES: O.DEFAULT_MAX_PARAM_LEAVES, DEFAULT_NATIVE_CONFIG: O.DEFAULT_NATIVE_CONFIG }),
  canonicalAction: (a) => O.canonicalAction(a),
  canonicalActionJson: (c) => O.canonicalActionJson(c),
  canonicalActionDigest: (c) => O.canonicalActionDigest(c),
  registryOps: (trusted, ops) => { const r = new O.InMemoryInverseRegistry(trusted); return ops.map(([op, ...a]: any[]) => op === 'register' ? (r.register(a[0], a[1]), null) : op === 'lookup' ? r.lookup(a[0]) ?? null : op === 'trustedVerifiers' ? r.trustedVerifiers() : r.digest()); },
  registryDigest: (s) => mkRegistry(s).digest(),
  reversibility: (a, s, kinds) => O.reversibility(a, mkRegistry(s), new Set(kinds)),
  graphBuild: (s) => { const g = mkGraph(s); return { size: g.size, digest: g.digest() }; },
  graphReachable: (s, start, scope) => mkGraph(s).reachable(start, sc(scope)),
  graphNode: (s, id) => mkGraph(s).node(id) ?? null,
  blastRadius: (a, s, scope) => O.blastRadius(a, mkGraph(s), sc(scope)),
  nativeEmbed: (cfg, a) => { const e = O.nativeHashEmbedder(cfg); return { modelId: e.modelId, dims: e.dims, config: e.config, vector: e.embed(a) }; },
  byoModelId: (d) => O.byoModelId(d),
  byoEmbed: (d, claimed, infer, a) => { const e = mkByo(d, sc(claimed), infer); return { modelId: e.modelId, dims: e.dims, vector: e.embed(a) }; },
  validateVector: (v, dims) => O.validateVector(v, dims),
  conformanceCheck: (es, cases) => O.conformanceCheck(mkEmbedder(es), cases),
  commitGoal: (es, a, eps) => (eps === null ? O.commitGoal(mkEmbedder(es), a) : O.commitGoal(mkEmbedder(es), a, eps)),
  verifyGoalCommitment: (g, es) => O.verifyGoalCommitment(g, mkEmbedder(es)),
  vectorDistance: (a, b, eps) => (eps === null ? O.vectorDistance(a, b) : O.vectorDistance(a, b, eps)),
  committedDistanceChecked: (c, g, es) => O.committedDistanceChecked(c, g, mkEmbedder(es)),
  committedDistance: (a, g, es) => O.committedDistance(a, g, mkEmbedder(es)),
  calibrate: (raw, scores) => O.calibrate(raw, scores),
  conformalThreshold: (scores, alpha) => O.conformalThreshold(scores, alpha),
  calibrationDigest: (scores) => O.calibrationDigest(scores),
  harmReport: (u, d) => O.harmReport(u, d),
  objectiveRisk: (a, c) => O.objectiveRisk(a, mkCtx(c)),
  objectiveRiskOracle: (c, input, snap) => O.objectiveRiskOracle(mkCtx(c)).resolve(input, snap),
};
let n = 0;
/** Record one case: the reference runs on the revived copy of the JSON args (non-finite numbers back to doubles). */
const { capture, ser } = await import('../oracles-base/lib.mjs') as any;
const add = async (fn: string, name: string, args: any[]) => {
  const js = JSON.parse(ser(args.map((x) => (x === undefined ? null : x))));
  o.add(fn, `${name}#${n++}`, js, await capture(REF[fn], revive(js)));
};
const A = (verb: string, resource: string, params?: any) => ({ verb, resource, ...(params === undefined ? {} : { params }) });

await add('constants', 'all', []);

// ---------------------------------------------------------------- canonical action
const CA: [string, any][] = [
  ['plain', A('Read', 'doc:1', { b: 1, a: [1, 2, { z: null, y: true }] })], ['no-params', A('read', 'doc:1')], ['empty-params', A('read', 'doc:1', {})], ['trim', A('  READ\t', '  doc:1  ')],
  ['nfd-verb', A('écrire', 'doc:1')], ['nfc-verb', A('écrire', 'doc:1')], ['nfd-res', A('x', 'café')], ['nfd-key', A('x', 'r', { 'é': 1 })], ['nfd-val', A('x', 'r', { k: 'é' })],
  ['dup-nfc-key', A('x', 'r', { 'é': 1, 'é': 2 })], ['proto-key', JSON.parse('{"verb":"x","resource":"r","params":{"__proto__":{"a":1},"b":2}}')], ['key-order', A('x', 'r', { b: 1, a: 2, c: { z: 1, y: 2 } })],
  ['astral', A('x', 'r', { k: '😀', '😀': 1 })], ['upper-nonascii', A('İX', 'r')], ['sharp-s', A('STRAßE', 'r')], ['long', A('x', 'r', { k: 'a'.repeat(5000) })],
  ['float', A('x', 'r', { amount: 1.5 })], ['neg-zero', A('x', 'r', { amount: -0 })], ['big-int', A('x', 'r', { amount: 2 ** 53 })], ['exp', A('x', 'r', { amount: 1e21 })], ['small', A('x', 'r', { amount: 1e-7 })],
  ['nested-array', A('x', 'r', { a: [[1, [2, [3]]]] })], ['extra-ignored', { verb: 'x', resource: 'r', params: {}, features: [1], scope: 'z' }],
  ['empty-verb', A('', 'r')], ['blank-verb', A('  ', 'r')], ['empty-res', A('x', '')], ['blank-res', A('x', ' \n')], ['num-verb', { verb: 5, resource: 'r' }], ['num-res', { verb: 'x', resource: 5 }],
  ['no-verb', { resource: 'r' }], ['no-res', { verb: 'x' }], ['null-action', null], ['params-null', { verb: 'x', resource: 'r', params: null }], ['params-array', A('x', 'r', [1])], ['params-str', A('x', 'r', 'p')],
  ['params-num', A('x', 'r', 5)], ['nan', A('x', 'r', { a: { $num: 'NaN' } })], ['inf', A('x', 'r', { a: { $num: 'Infinity' } })], ['verb-unicode-space', A(' x ', 'r')],
];
for (const [name, a] of CA) {
  await add('canonicalAction', name, [a]);
  let c: any = null;
  try { c = O.canonicalAction(revive(a)); } catch { /* refusal case */ }
  if (c) { await add('canonicalActionJson', name, [c]); await add('canonicalActionDigest', name, [c]); }
}
for (const [name, c] of [['hand', { verb: 'x', resource: 'r', params: { a: 1 } }], ['hand-float', { verb: 'x', resource: 'r', params: { a: 0.1 } }], ['hand-undecided', { verb: 'X', resource: ' r', params: {} }], ['hand-missing', { verb: 'x' }]] as any[]) {
  await add('canonicalActionJson', 'raw-' + name, [c]); await add('canonicalActionDigest', 'raw-' + name, [c]);
}

// ---------------------------------------------------------------- inverse registry, reversibility
const E = (kind: string, fid: string, v?: [string, string]) => ({ inverseKind: kind, fidelity: fid, ...(v ? { verification: { verifierId: v[0], evidenceDigest: v[1] } } : {}) });
const RGS: Record<string, any> = {
  empty: { trusted: [], entries: [] },
  full: { trusted: ['ver-b', 'ver-a'], entries: [['refund', E('charge', 'partial', ['ver-a', 'e1'])], ['unlock', E('lock', 'exact', ['ver-b', 'e2'])], ['untrusted', E('lock', 'exact', ['ver-x', 'e3'])], ['unverified', E('lock', 'exact')], ['unauthorized', E('nuke', 'exact', ['ver-a', 'e4'])]] },
  dupTrusted: { trusted: ['b', 'a', 'b', 'a'], entries: [['v', E('k', 'exact', ['a', 'd'])]] },
  replace: { trusted: ['a'], entries: [['v', E('k1', 'exact', ['a', 'd'])], ['v', E('k2', 'partial', ['a', 'd'])]] },
  weird: { trusted: ['a'], entries: [['v', { inverseKind: 'k', fidelity: 'bogus', verification: { verifierId: 'a', evidenceDigest: 'd' } }], ['w', { inverseKind: 'k', fidelity: 'exact', verification: { verifierId: 'a', evidenceDigest: 'd' }, extra: 1 }]] },
  unicode: { trusted: ['é', 'é'], entries: [['é', E('k', 'exact', ['é', 'd'])], ['é', E('k', 'partial', ['é', 'd'])]] },
  order: { trusted: ['a'], entries: [['b', E('k', 'exact', ['a', 'd'])], ['a', E('k', 'exact', ['a', 'd'])]] },
  order2: { trusted: ['a'], entries: [['a', E('k', 'exact', ['a', 'd'])], ['b', E('k', 'exact', ['a', 'd'])]] },
};
for (const [rn, rs] of Object.entries(RGS)) await add('registryDigest', rn, [rs]);
await add('registryOps', 'basic', [['b', 'a'], [['register', 'v', E('k', 'exact', ['a', 'd'])], ['lookup', 'v'], ['lookup', 'nope'], ['trustedVerifiers'], ['digest'], ['register', 'v', E('k2', 'partial')], ['lookup', 'v'], ['digest']]]);
await add('registryOps', 'empty', [[], [['lookup', 'x'], ['trustedVerifiers'], ['digest']]]);
await add('registryOps', 'proto', [[], [['register', '__proto__', E('k', 'exact')], ['register', 'constructor', E('k', 'exact')], ['lookup', '__proto__'], ['lookup', 'constructor'], ['lookup', 'toString'], ['digest']]]);
for (const [rn, rs] of Object.entries(RGS)) for (const verb of ['refund', 'unlock', 'untrusted', 'unverified', 'unauthorized', 'missing', 'v', 'w', 'é', 'é', 'constructor', '__proto__', 'a', 'b'])
  for (const [kn, kinds] of [['kinds', ['charge', 'lock', 'k', 'k1', 'k2']], ['none', []]] as any[]) await add('reversibility', `${rn}/${verb}/${kn}`, [{ verb }, rs, kinds]);

// ---------------------------------------------------------------- resource graph, blast radius
const N = (id: string, harm?: any) => ({ id, ...(harm ? { harm } : {}) });
const GRAPHS: Record<string, any> = {
  empty: { nodes: [], edges: [] },
  one: { nodes: [N('a')], edges: [] },
  chain: { nodes: [N('a', { rows: 10 }), N('b', { rows: 5, usd: 100 }), N('c', { usd: 0.1 }), N('d')], edges: [{ from: 'a', to: 'b', kind: 'fk' }, { from: 'b', to: 'c', kind: 'fk' }, { from: 'c', to: 'd', kind: 'route' }] },
  diamond: { nodes: [N('s'), N('l'), N('r'), N('t', { rows: 1 })], edges: [{ from: 's', to: 'l', kind: 'x' }, { from: 's', to: 'r', kind: 'y' }, { from: 'l', to: 't', kind: 'x' }, { from: 'r', to: 't', kind: 'x' }] },
  cycle: { nodes: [N('a', { rows: 3 }), N('b', { rows: 4 })], edges: [{ from: 'a', to: 'b', kind: 'k' }, { from: 'b', to: 'a', kind: 'k' }, { from: 'a', to: 'a', kind: 'k' }] },
  floats: { nodes: [N('a', { usd: 0.1 }), N('b', { usd: 0.2 }), N('c', { usd: 1e-7, rows: 1e21 })], edges: [{ from: 'a', to: 'b', kind: 'k' }, { from: 'b', to: 'c', kind: 'k' }] },
  badharm: { nodes: [N('a', { rows: -5, usd: 0, x: 3, y: { $num: 'NaN' }, z: { $num: 'Infinity' } }), N('b', { rows: 2 })], edges: [{ from: 'a', to: 'b', kind: 'k' }] },
  protoharm: { nodes: [JSON.parse('{"id":"a","harm":{"__proto__":5,"constructor":2,"toString":1,"rows":1}}'), N('b', { constructor: 4 })], edges: [{ from: 'a', to: 'b', kind: 'k' }] },
  dupnode: { nodes: [N('a', { rows: 1 }), N('b'), N('a', { rows: 9 })], edges: [{ from: 'a', to: 'b', kind: 'k' }] },
  dupedge: { nodes: [N('a'), N('b')], edges: [{ from: 'a', to: 'b', kind: 'k' }, { from: 'a', to: 'b', kind: 'k' }, { from: 'a', to: 'b', kind: 'j' }] },
  unicode: { nodes: [N('é'), N('é'), N('z'), N('😀')], edges: [{ from: 'é', to: 'z', kind: 'k' }, { from: 'é', to: '😀', kind: 'k' }] },
  badedge: { nodes: [N('a')], edges: [{ from: 'a', to: 'ghost', kind: 'k' }] },
  badedge2: { nodes: [N('a')], edges: [{ from: 'ghost', to: 'a', kind: 'k' }] },
  edgeorder1: { nodes: [N('a'), N('b'), N('c')], edges: [{ from: 'a', to: 'b', kind: 'k' }, { from: 'a', to: 'c', kind: 'k' }] },
  edgeorder2: { nodes: [N('c'), N('b'), N('a')], edges: [{ from: 'a', to: 'c', kind: 'k' }, { from: 'a', to: 'b', kind: 'k' }] },
  nulkind: { nodes: [N('a'), N('b')], edges: [{ from: 'a', to: 'b', kind: 'k\u0000x' }] },
  sorted: { nodes: [N('B'), N('a'), N('é'), N('Z'), N('😀'), N('～')], edges: [] },
};
const SCOPES: [string, any][] = [['none', null], ['empty', {}], ['kind-k', { edgeKinds: ['k'] }], ['kind-x', { edgeKinds: ['x'] }], ['kinds-none', { edgeKinds: [] }], ['d0', { maxDepth: 0 }], ['d1', { maxDepth: 1 }], ['d2', { maxDepth: 2 }], ['dneg', { maxDepth: -1 }],
  ['dfrac', { maxDepth: 1.5 }], ['dnull', { maxDepth: null }], ['dnan', { maxDepth: { $num: 'NaN' } }], ['both', { edgeKinds: ['x', 'y'], maxDepth: 1 }], ['dinf', { maxDepth: { $num: 'Infinity' } }]];
for (const [gn, g] of Object.entries(GRAPHS)) {
  await add('graphBuild', gn, [g]);
  for (const id of ['a', 's', 'missing', '', 'é', '__proto__']) await add('graphNode', `${gn}/${id}`, [g, id]);
  for (const start of ['a', 's', 'missing', 'é', 'B']) for (const [sn, scope] of SCOPES) {
    await add('graphReachable', `${gn}/${start}/${sn}`, [g, start, scope]);
    await add('blastRadius', `${gn}/${start}/${sn}`, [{ resource: start }, g, scope]);
  }
}

// ---------------------------------------------------------------- native embedder
const DEF = O.DEFAULT_NATIVE_CONFIG;
const NC = (over: any = {}) => ({ ...DEF, ...over, ...(over.fieldWeights ? { fieldWeights: { ...DEF.fieldWeights, ...over.fieldWeights } } : {}) });
const SMALL = NC({ dims: 16 });
const ACTS: [string, any][] = [
  ['basic', O.canonicalAction(A('transfer', 'acct:main', { amount: 10, to: 'acct:other' }))], ['no-params', O.canonicalAction(A('read', 'doc:1'))], ['unicode', O.canonicalAction(A('écrire', 'dossier/日本語', { k: '😀 x́' }))],
  ['nested', O.canonicalAction(A('x', 'r', { a: { b: [1, 'two', { c: null, d: true, e: 1.5 }] }, 'k.k': 'v' }))], ['words', O.canonicalAction(A('send mail', 'inbox: a-b_c/D', { subject: 'Hello, World! 42x' }))],
  ['one-char', O.canonicalAction(A('x', 'y'))], ['sep-heavy', O.canonicalAction(A('---', '///', { '': '' }))], ['long', O.canonicalAction(A('x', 'r'.repeat(300), { k: 'v'.repeat(100) }))],
  ['array-params', O.canonicalAction(A('x', 'r', { l: [3, 2, 1] }))], ['big', O.canonicalAction(A('x', 'r', { n: 2 ** 53, f: 1e21, g: 0.1 }))],
];
const CONFIGS: [string, any][] = [['default', DEF], ['small', SMALL], ['dims8', NC({ dims: 8 })], ['dims-prime', NC({ dims: 97 })], ['ngram1', NC({ dims: 32, ngramMin: 1, ngramMax: 1 })], ['ngram1-8', NC({ dims: 32, ngramMin: 1, ngramMax: 8 })],
  ['seed', NC({ dims: 32, seed: 'other-seed' })], ['seed-uni', NC({ dims: 32, seed: 'séed' })], ['weights0', NC({ dims: 32, fieldWeights: { verb: 0, resource: 0, param: 0 } })], ['weights-max', NC({ dims: 32, fieldWeights: { verb: 1000, resource: 1000, param: 1000 } })],
  ['digest-mode', NC({ dims: 32, paramMode: 'digest' })], ['leaves-mode', NC({ dims: 32, paramMode: 'leaves' })], ['cap2', NC({ dims: 32, maxParamLeaves: 2 })], ['cap1-digest', NC({ dims: 32, maxParamLeaves: 1, paramMode: 'digest' })],
  ['cap-big', NC({ dims: 32, maxParamLeaves: 1_000_000 })]];
for (const [cn, cfg] of CONFIGS) for (const [an, a] of ACTS) if (cn === 'default' || cn === 'small' || an === 'basic' || an === 'nested' || an === 'unicode') await add('nativeEmbed', `${cn}/${an}`, [cfg, a]);
// config validation (every refusal branch and boundary)
const BADCFG: [string, any][] = [['dims7', NC({ dims: 7 })], ['dims8', NC({ dims: 8 })], ['dims65537', NC({ dims: 65537 })], ['dims-frac', NC({ dims: 16.5 })], ['dims-str', NC({ dims: '16' })], ['dims-nan', NC({ dims: { $num: 'NaN' } })],
  ['dims-big', NC({ dims: 2 ** 53 })], ['ng0', NC({ ngramMin: 0 })], ['ng9', NC({ ngramMax: 9 })], ['ng-inv', NC({ ngramMin: 5, ngramMax: 3 })], ['ng-frac', NC({ ngramMin: 1.5 })], ['seed-empty', NC({ seed: '' })], ['seed-num', NC({ seed: 5 })],
  ['w-neg', NC({ fieldWeights: { verb: -1 } })], ['w-1001', NC({ fieldWeights: { param: 1001 } })], ['w-frac', NC({ fieldWeights: { resource: 0.5 } })], ['w-str', NC({ fieldWeights: { verb: '1' } })],
  ['cap0', NC({ maxParamLeaves: 0 })], ['cap-1e6+1', NC({ maxParamLeaves: 1_000_001 })], ['cap-frac', NC({ maxParamLeaves: 1.5 })], ['cap-null', NC({ maxParamLeaves: null })],
  ['mode-bad', NC({ paramMode: 'bad' })], ['mode-null', NC({ paramMode: null })], ['mode-upper', NC({ paramMode: 'LEAVES' })], ['no-weights', { dims: 16, ngramMin: 2, ngramMax: 4, seed: 's' }], ['extra-field', NC({ dims: 16, junk: 1 })], ['dims-65536', NC({ dims: 65536 })]];
for (const [bn, cfg] of BADCFG) await add('nativeEmbed', 'cfg/' + bn, [cfg, ACTS[1][1]]);
// param-leaf cap: exactly at, one over, default 256, digest mode ignores leaf count for the vector but not the cap
for (const [k, mode, cap] of [[2, 'leaves', 2], [3, 'leaves', 2], [2, 'digest', 2], [3, 'digest', 2], [256, 'leaves', undefined], [257, 'leaves', undefined], [257, 'digest', undefined], [0, 'leaves', 1], [1, 'leaves', 1]] as any[]) {
  const params = Object.fromEntries(Array.from({ length: k }, (_, i) => ['k' + String(i).padStart(3, '0'), i]));
  await add('nativeEmbed', `leaves/${k}/${mode}/${cap}`, [NC({ dims: 16, paramMode: mode, ...(cap ? { maxParamLeaves: cap } : {}) }), O.canonicalAction(A('x', 'r', params))]);
}
await add('nativeEmbed', 'leaves/array-counts', [NC({ dims: 16, maxParamLeaves: 3 }), O.canonicalAction(A('x', 'r', { a: [1, 2, 3, 4] }))]);
await add('nativeEmbed', 'leaves/empty-containers', [NC({ dims: 16, maxParamLeaves: 1 }), O.canonicalAction(A('x', 'r', { a: {}, b: [] }))]);
await add('nativeEmbed', 'canonical-not-required', [NC({ dims: 16 }), { verb: 'X', resource: ' r ', params: { b: 1, a: 2 } }]);

// ---------------------------------------------------------------- BYO
const BD = (over: any = {}) => ({ name: 'm', version: '1', weightsDigest: 'w'.repeat(43), runtime: 'onnx-int8', dims: 4, quantization: { bits: 8, scale: 0.5 }, inputEncoding: 'pca-canonical-action-json-v1', ...over });
const BDS: [string, any][] = [['ok', BD()], ['bits2', BD({ quantization: { bits: 2, scale: 1 } })], ['bits31', BD({ quantization: { bits: 31, scale: 1 } })], ['bits1', BD({ quantization: { bits: 1, scale: 1 } })], ['bits32', BD({ quantization: { bits: 32, scale: 1 } })],
  ['bits-frac', BD({ quantization: { bits: 8.5, scale: 1 } })], ['scale0', BD({ quantization: { bits: 8, scale: 0 } })], ['scale-neg', BD({ quantization: { bits: 8, scale: -1 } })], ['scale-nan', BD({ quantization: { bits: 8, scale: { $num: 'NaN' } } })],
  ['scale-str', BD({ quantization: { bits: 8, scale: '1' } })], ['dims0', BD({ dims: 0 })], ['dims-frac', BD({ dims: 1.5 })], ['dims1', BD({ dims: 1 })], ['enc-bad', BD({ inputEncoding: 'other' })], ['enc-missing', (() => { const d: any = BD(); delete d.inputEncoding; return d; })()],
  ['float-scale', BD({ quantization: { bits: 8, scale: 0.1 } })], ['extra', BD({ extra: [1, { a: 2 }] })], ['unicode', BD({ name: 'mé' })]];
for (const [bn, d] of BDS) {
  await add('byoModelId', bn, [d]);
  await add('byoEmbed', `${bn}/ok`, [d, null, { vector: [1, -2, 3, -4] }, ACTS[0][1]]);
}
const D0 = BD();
for (const [vn, vec] of [['zero', [0, 0, 0, 0]], ['neg-zero', [-0, 0, 1, -1]], ['qmax', [127, -127, 0, 1]], ['over-qmax', [128, 0, 0, 0]], ['under-qmin', [-128, 0, 0, 0]], ['short', [1, 2, 3]], ['long', [1, 2, 3, 4, 5]], ['frac', [1, 2, 3, 4.5]], ['unsafe', [2 ** 53, 0, 0, 0]],
  ['nan', [{ $num: 'NaN' }, 0, 0, 0]], ['str', ['1', 2, 3, 4]], ['null', [null, 0, 0, 0]], ['empty', []]] as any[]) await add('byoEmbed', 'vec/' + vn, [D0, null, { vector: vec }, ACTS[1][1]]);
await add('byoEmbed', 'infer/throws', [D0, null, { throws: true }, ACTS[1][1]]);
await add('byoEmbed', 'infer/notarray', [D0, null, { notArray: true }, ACTS[1][1]]);
await add('byoEmbed', 'infer/by-canonical-json-len', [D0, null, { byLen: true }, ACTS[0][1]]);
await add('byoEmbed', 'infer/by-canonical-json-len-2', [D0, null, { byLen: true }, ACTS[2][1]]);
await add('byoEmbed', 'claimed/ok', [D0, JSON.parse(JSON.stringify(O.byoModelId(D0))), { vector: [1, 2, 3, 4] }, ACTS[1][1]]);
await add('byoEmbed', 'claimed/other', [D0, 'byo:other', { vector: [1, 2, 3, 4] }, ACTS[1][1]]);
await add('byoEmbed', 'claimed/native-id', [D0, O.nativeHashEmbedder(SMALL).modelId, { vector: [1, 2, 3, 4] }, ACTS[1][1]]);
await add('byoEmbed', 'claimed/empty', [D0, '', { vector: [1, 2, 3, 4] }, ACTS[1][1]]);
// validateVector
const MAXC = (dims: number) => Math.floor(Math.sqrt(Number.MAX_SAFE_INTEGER / (2 * Math.max(1, dims))));
for (const [vn, v, d] of [['ok', [1, -2, 3], 3], ['neg-zero', [-0, 0], 2], ['empty-0', [], 0], ['len-mismatch', [1, 2], 3], ['not-array', 'x', 1], ['null', null, 1], ['frac', [0.5], 1], ['nan', [{ $num: 'NaN' }], 1], ['inf', [{ $num: 'Infinity' }], 1],
  ['at-limit-d1', [MAXC(1), -MAXC(1)], 2], ['over-limit-d1', [MAXC(1) + 1], 1], ['at-limit-d256', Array(256).fill(MAXC(256)), 256], ['over-limit-d256', Array(256).fill(MAXC(256) + 1), 256], ['unsafe', [2 ** 53], 1], ['str', ['1'], 1],
  ['dims-0-vec', [1], 0], ['big-d', [1, 2], 65536]] as any[]) await add('validateVector', vn, [v, d]);

// ---------------------------------------------------------------- goal commitment, distance
const ESN = (cfg: any = SMALL) => ({ scheme: 'native', config: cfg });
const ESB = (infer: any = { vector: [1, -2, 3, -4] }, d: any = D0, claimed: any = null) => ({ scheme: 'byo', descriptor: d, ...(claimed ? { claimedModelId: claimed } : {}), infer });
const ESF = (vector: any, dims = 4, modelId = 'fixed:1', config: any = { k: 1 }) => ({ scheme: 'fixed', modelId, dims, config, vector });
const GOALS: [string, any][] = [['basic', A('transfer', 'acct:main', { amount: 10 })], ['no-params', A('read', 'doc:1')], ['unicode', A('écrire', 'doc:日本')], ['upper', A('READ', ' doc:1 ')], ['bad-verb', A('', 'r')], ['bad-res', { verb: 'x' }], ['null', null]];
for (const [gn, g] of GOALS) { await add('commitGoal', `native/${gn}`, [ESN(), g, null]); await add('commitGoal', `byo/${gn}`, [ESB(), g, null]); }
for (const e of [null, 1, 1 / 4096, 0.5, 1e-9, 0, -1, 1.5, 2, { $num: 'NaN' }, { $num: 'Infinity' }, 0.1, 1 / 3, 1 / 1024]) await add('commitGoal', 'eps/' + JSON.stringify(e), [ESN(), GOALS[0][1], e]);
for (const [vn, vec, dims] of [['ok', [1, 2, 3, 4], 4], ['frac', [1, 2, 3, 0.5], 4], ['short', [1, 2], 4], ['not-array', 'x', 4], ['zero', [0, 0, 0, 0], 4], ['huge', [2 ** 40, 0, 0, 0], 4], ['neg-zero', [-0, 1, 0, 0], 4]] as any[]) await add('commitGoal', 'fixed/' + vn, [ESF(vec, dims), GOALS[0][1], null]);
await add('commitGoal', 'native/bad-config', [ESN(NC({ dims: 3 })), GOALS[0][1], null]);
await add('commitGoal', 'native/stuffed', [ESN(NC({ dims: 16, maxParamLeaves: 1 })), A('x', 'r', { a: 1, b: 2 }), null]);
const goalOf = (es: any, a: any, eps: any = null) => JSON.parse(ser(O.commitGoal(mkEmbedder(es), a, ...(eps === null ? [] : [eps]))));
const G = goalOf(ESN(), GOALS[0][1]);
const GB = goalOf(ESB(), GOALS[0][1]);
const GE = goalOf(ESN(), GOALS[0][1], 0.1);
const tweak = (g: any, k: string, v: any) => ({ ...g, [k]: v });
const GTAMP: [string, any][] = [['ok', G], ['ok-eps', GE], ['metric', tweak(G, 'metric', 'cosine')], ['eps-0', tweak(G, 'epsilon', 0)], ['eps-neg', tweak(G, 'epsilon', -1)], ['eps-2', tweak(G, 'epsilon', 2)], ['eps-1', tweak(G, 'epsilon', 1)], ['eps-str', tweak(G, 'epsilon', '1')],
  ['eps-changed', tweak(G, 'epsilon', 0.5)], ['commit', tweak(G, 'commit', 'x'.repeat(43))], ['commit-missing', (() => { const g = { ...G }; delete g.commit; return g; })()], ['model', tweak(G, 'embedderModelId', 'native:other')],
  ['config', tweak(G, 'config', { ...G.config, seed: 'x' })], ['vector', tweak(G, 'goalVector', [...G.goalVector.slice(1), 0])], ['vector-short', tweak(G, 'goalVector', G.goalVector.slice(1))], ['vector-frac', tweak(G, 'goalVector', [0.5, ...G.goalVector.slice(1)])],
  ['byo', GB], ['native-vs-byo', tweak(G, 'config', GB.config)], ['null', null], ['empty', {}], ['string', 'x'], ['config-order', { ...G, config: Object.fromEntries(Object.entries(G.config).reverse()) }]];
for (const [tn, g] of GTAMP) for (const [en, es] of [['native', ESN()], ['native-other', ESN(NC({ dims: 32 }))], ['byo', ESB()], ['fixed', ESF([1, 2, 3, 4])]] as any[]) await add('verifyGoalCommitment', `${tn}/${en}`, [g, es]);
// distance
const VD: [string, number[], number[]][] = [['same', [1, 2, 3], [1, 2, 3]], ['orth', [1, 0], [0, 1]], ['opposite', [1, 2], [-1, -2]], ['scaled', [1, 2, 3], [2, 4, 6]], ['near', [1000000, 1, 0], [1000000, 0, 1]], ['tiny-diff', [10 ** 7, 1], [10 ** 7, 2]],
  ['zero-a', [0, 0], [1, 2]], ['zero-b', [1, 2], [0, 0]], ['both-zero', [0, 0], [0, 0]], ['len', [1, 2], [1, 2, 3]], ['empty', [], []], ['neg-zero', [-0, 1], [0, 1]], ['acute', [3, 4], [4, 3]], ['obtuse', [3, 4], [-4, 3]], ['neg', [-1, -1], [-1, -2]],
  ['big', [94906265, 94906265], [94906265, 94906264]], ['mixed', [5, -3, 8, 0, 1], [-2, 7, 1, 4, 4]], ['one-dim', [3], [5]], ['one-dim-opp', [3], [-5]], ['nan', [{ $num: 'NaN' }, 1], [1, 1]] as any, ['frac', [0.5, 1], [1, 0.5]]];
for (const [vn, a, b] of VD) for (const e of [null, 1 / 4096, 0.1, 1, 1e-9, 0, -1, 2]) await add('vectorDistance', `${vn}/${e}`, [a, b, e]);
for (const dims of [8, 64, 256]) for (const [an, a] of ACTS.slice(0, 4)) {
  const es = ESN(NC({ dims })); const g = goalOf(es, GOALS[0][1]);
  await add('committedDistanceChecked', `${dims}/${an}`, [a, g, es]);
  await add('committedDistance', `${dims}/${an}`, [{ verb: a.verb, resource: a.resource, params: a.params }, g, es]);
}
for (const [gn, g] of GOALS) { await add('committedDistance', 'submit/' + gn, [g, G, ESN()]); }
for (const [tn, g] of GTAMP) { await add('committedDistanceChecked', 'tamper/' + tn, [ACTS[0][1], g, ESN()]); await add('committedDistance', 'tamper/' + tn, [GOALS[0][1], g, ESN()]); }
await add('committedDistanceChecked', 'embed-throws', [ACTS[0][1], goalOf(ESN(NC({ dims: 16, maxParamLeaves: 8 })), GOALS[0][1]), ESN(NC({ dims: 16, maxParamLeaves: 8 }))].map((x, i) => i === 0 ? O.canonicalAction(A('x', 'r', Object.fromEntries(Array.from({ length: 9 }, (_, k) => ['k' + k, k])))) : x));
await add('committedDistanceChecked', 'byo-bad-vector', [ACTS[0][1], goalOf(ESB(), GOALS[0][1]), ESB({ vector: [1, 2, 3, 4.5] })]);
await add('committedDistanceChecked', 'byo-throws', [ACTS[0][1], goalOf(ESB(), GOALS[0][1]), ESB({ throws: true })]);
await add('committedDistanceChecked', 'byo-ok', [ACTS[0][1], GB, ESB()]);
await add('committedDistanceChecked', 'byo-near', [ACTS[0][1], GB, ESB({ vector: [1, -2, 3, -3] })]);
await add('committedDistanceChecked', 'byo-opposite', [ACTS[0][1], GB, ESB({ vector: [-1, 2, -3, 4] })]);
for (const [en, es] of [['native', ESN()], ['byo', ESB()], ['byo-other', ESB({ vector: [1, 2, 3, 4] })], ['fixed', ESF([1, 2, 3, 4])]] as any[]) await add('conformanceCheck', 'es/' + en, [es, [{ action: A('x', 'y'), vector: O.nativeHashEmbedder(SMALL).embed(O.canonicalAction(A('x', 'y'))) }]]);
const SV = O.nativeHashEmbedder(SMALL);
for (const [cn, cases] of [['empty', []], ['ok', [{ action: A('read', 'doc:1'), vector: SV.embed(O.canonicalAction(A('read', 'doc:1'))) }, { action: A('Write', 'doc:2', { a: 1 }), vector: SV.embed(O.canonicalAction(A('Write', 'doc:2', { a: 1 }))) }]],
  ['one-off', [{ action: A('read', 'doc:1'), vector: SV.embed(O.canonicalAction(A('read', 'doc:1'))).map((x: number, i: number) => (i === 0 ? x + 1 : x)) }]], ['short', [{ action: A('read', 'doc:1'), vector: [1, 2] }]],
  ['bad-action', [{ action: A('', 'doc:1'), vector: [] }]], ['neg-zero', [{ action: A('read', 'doc:1'), vector: SV.embed(O.canonicalAction(A('read', 'doc:1'))).map((x: number) => (x === 0 ? -0 : x)) }]]] as any[]) await add('conformanceCheck', 'native/' + cn, [ESN(), cases]);

// ---------------------------------------------------------------- calibration, harm
const SC: [string, number[]][] = [['empty', []], ['one', [0.5]], ['five', [0.1, 0.2, 0.3, 0.4, 0.5]], ['unsorted', [0.9, 0.1, 0.5, 0.3, 0.7]], ['dups', [0.5, 0.5, 0.5, 0.2]], ['floats', [0.1, 0.2, 0.30000000000000004, 1 / 3, 1e-7, 1e21, 2 ** 53]], ['negative', [-1, 0, -0, 1]],
  ['nonfinite', [0.1, { $num: 'NaN' } as any, 0.3]], ['inf', [{ $num: 'Infinity' } as any, 0.2]], ['twenty', Array.from({ length: 20 }, (_, i) => i / 19)], ['neg-zero', [-0, 0]]];
for (const [sn, s] of SC) {
  await add('calibrationDigest', sn, [s]);
  for (const raw of [0, -0, 0.05, 0.1, 0.3, 0.5, 0.95, 1, 2, -1, 1e-9, { $num: 'NaN' }, { $num: 'Infinity' }, { $num: '-Infinity' }]) await add('calibrate', `${sn}/${JSON.stringify(raw)}`, [raw, s]);
  for (const a of [0, 0.01, 0.05, 0.1, 0.2, 0.5, 0.9, 1, 1.5, -0.1, { $num: 'NaN' }]) await add('conformalThreshold', `${sn}/${JSON.stringify(a)}`, [s, a]);
}
await add('calibrationDigest', 'order-a', [[3, 1, 2]]); await add('calibrationDigest', 'order-b', [[1, 2, 3]]);
const DEN = [{ id: 'rows', ceiling: 100, weight: 2 }, { id: 'usd', ceiling: 1000, weight: 1 }];
const UNITS: [string, any][] = [['empty', {}], ['rows', { rows: 50 }], ['both', { rows: 100, usd: 500 }], ['over', { rows: 1e9, usd: 1e9 }], ['neg', { rows: -5, usd: 10 }], ['other-only', { gb: 5 }], ['proto', JSON.parse('{"__proto__":3,"constructor":9,"rows":10}')],
  ['float', { rows: 33.3, usd: 0.1 }], ['nan', { rows: { $num: 'NaN' }, usd: 5 }], ['inf', { rows: { $num: 'Infinity' }, usd: 5 }], ['neg-zero', { rows: -0 }], ['str', { rows: '50' }]];
const DENS: [string, any][] = [['two', DEN], ['none', []], ['zero-weight', [{ id: 'rows', ceiling: 100, weight: 0 }]], ['zero-ceiling', [{ id: 'rows', ceiling: 0, weight: 1 }]], ['neg-weight', [{ id: 'rows', ceiling: 100, weight: -1 }, { id: 'usd', ceiling: 10, weight: 1 }]],
  ['dup', [{ id: 'rows', ceiling: 100, weight: 1 }, { id: 'rows', ceiling: 10, weight: 1 }]], ['proto-id', [{ id: '__proto__', ceiling: 1, weight: 1 }, { id: 'constructor', ceiling: 1, weight: 1 }, { id: 'toString', ceiling: 1, weight: 1 }]], ['nan', [{ id: 'rows', ceiling: { $num: 'NaN' }, weight: 1 }]],
  ['unequal', [{ id: 'rows', ceiling: 3, weight: 1 }, { id: 'usd', ceiling: 7, weight: 3 }, { id: 'gb', ceiling: 11, weight: 5 }]]];
for (const [un, u] of UNITS) for (const [dn, d] of DENS) await add('harmReport', `${un}/${dn}`, [u, d]);

// ---------------------------------------------------------------- objectiveRisk
const WT = { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 };
const REG0 = RGS.full, GR0 = GRAPHS.chain;
const base = (over: any = {}) => {
  const c: any = { registry: REG0, authorizedKinds: ['charge', 'lock'], graph: GR0, embedder: ESN(), denominations: DEN, weights: WT, taint: 0.2, age: 0.1, ...over };
  c.goal = over.goal ?? goalOf(c.embedder, A('refund', 'a'));
  c.commitments = { registryDigest: mkRegistry(c.registry).digest(), graphDigest: mkGraph(c.graph).digest(), ...(c.calibration ? { calibrationDigest: O.calibrationDigest(revive(c.calibration)) } : {}), ...(over.commitments ?? {}) };
  return c;
};
const SUBM: [string, any][] = [['refund-a', A('refund', 'a')], ['unlock-b', A('unlock', 'b')], ['untrusted', A('untrusted', 'c')], ['unknown-verb', A('delete', 'a')], ['unknown-res', A('refund', 'zzz')], ['upper', A('REFUND', ' a ')], ['d-leaf', A('refund', 'd')],
  ['params', A('refund', 'a', { amount: 5, reason: 'x' })], ['bad-action', A('', 'a')], ['dup-key', A('refund', 'a', { 'é': 1, 'é': 2 })], ['nan-param', A('refund', 'a', { x: { $num: 'NaN' } })], ['unauthorized', A('unauthorized', 'a')]];
for (const [sn, a] of SUBM) await add('objectiveRisk', 'base/' + sn, [a, base()]);
const CTXV: [string, any][] = [['scope-k', { scope: { edgeKinds: ['fk'] } }], ['scope-d1', { scope: { maxDepth: 1 } }], ['scope-both', { scope: { edgeKinds: ['route', 'fk'], maxDepth: 2 } }], ['no-denoms', { denominations: [] }], ['denoms-unequal', { denominations: DENS[8][1] }],
  ['taint0', { taint: 0 }], ['taint1', { taint: 1 }], ['taint-nan', { taint: { $num: 'NaN' } }], ['taint-inf', { taint: { $num: 'Infinity' } }], ['taint-neg', { taint: -3 }], ['age-nan', { age: { $num: 'NaN' } }], ['age-big', { age: 5 }],
  ['unc-0', { attestedUncertainty: 0 }], ['unc-half', { attestedUncertainty: 0.5 }], ['unc-1', { attestedUncertainty: 1 }], ['unc-2', { attestedUncertainty: 2 }], ['unc-neg', { attestedUncertainty: -1 }], ['unc-nan', { attestedUncertainty: { $num: 'NaN' } }],
  ['weights-0', { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 } }], ['weights-heavy', { weights: { alpha: 5, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 } }], ['weights-neg', { weights: { ...WT, alpha: -1 } }],
  ['calib', { calibration: [0.1, 0.2, 0.3, 0.4, 0.5] }], ['calib-empty', { calibration: [] }], ['calib-hi', { calibration: [0.9, 0.95, 0.99] }], ['calib-lo', { calibration: [0, 0, 0] }],
  ['graph-floats', { graph: GRAPHS.floats }], ['graph-empty', { graph: GRAPHS.empty }], ['graph-cycle', { graph: GRAPHS.cycle }], ['graph-badharm', { graph: GRAPHS.badharm }], ['registry-empty', { registry: RGS.empty }],
  ['byo', { embedder: ESB({ vector: [1, -2, 3, -4] }) }], ['byo-far', { embedder: ESB({ vector: [-1, 2, -3, 4] }) }], ['native-digest', { embedder: ESN(NC({ dims: 16, paramMode: 'digest' })) }], ['native-cap', { embedder: ESN(NC({ dims: 16, maxParamLeaves: 1 })) }]];
for (const [cn, over] of CTXV) for (const sn of ['refund-a', 'unlock-b', 'unknown-verb', 'params']) await add('objectiveRisk', `${cn}/${sn}`, [SUBM.find(([k]) => k === sn)![1], base(over)]);
// commitment mismatches (each reason, and several at once)
const okc = base();
const MIS: [string, any][] = [['registry', { commitments: { registryDigest: 'x' } }], ['graph', { commitments: { graphDigest: 'x' } }], ['both', { commitments: { registryDigest: 'x', graphDigest: 'y' } }],
  ['calib-undeclared', { calibration: [0.1, 0.2], commitments: { calibrationDigest: undefined } }], ['calib-wrong', { calibration: [0.1, 0.2], commitments: { calibrationDigest: 'x' } }],
  ['goal-tamper', { goal: tweak(okc.goal, 'commit', 'x') }], ['goal-model', { goal: tweak(okc.goal, 'embedderModelId', 'native:x') }], ['goal-eps', { goal: tweak(okc.goal, 'epsilon', 0.5) }], ['goal-metric', { goal: tweak(okc.goal, 'metric', 'x') }],
  ['goal-byo-vs-native', { goal: GB }], ['all', { commitments: { registryDigest: 'x', graphDigest: 'y' }, calibration: [1], goal: tweak(okc.goal, 'commit', 'z') }]];
for (const [mn, over] of MIS) await add('objectiveRisk', 'mismatch/' + mn, [SUBM[0][1], base(over)]);
// calibrationDigest in the context is optional when no calibration is used
await add('objectiveRisk', 'calib-digest-unused', [SUBM[0][1], base({ commitments: { calibrationDigest: 'whatever' } })]);
// harm saturation and the max(count, harm) blast rule
for (const gn of ['chain', 'diamond', 'floats', 'protoharm', 'unicode']) for (const res of ['a', 's', 'b', 'é']) await add('objectiveRisk', `graph/${gn}/${res}`, [A('refund', res), base({ graph: GRAPHS[gn], goal: undefined })]);

// ---------------------------------------------------------------- the dispute-game oracle
const SN = (a: any) => ({ action: { action: a } });
const INPUTS = ['reversibility_class', 'reversibility', 'blastRadius', 'semanticDistance', 'taint', 'x', '', null, 5];
for (const [sn, a] of SUBM.slice(0, 8)) for (const i of INPUTS) await add('objectiveRiskOracle', `${sn}/${i}`, [base(), i, SN({ verb: a.verb, resource: a.resource, ...(a.params ? { params: a.params } : {}) })]);
for (const [mn, snap] of [['no-action', {}], ['null', null], ['action-null', { action: null }], ['inner-null', { action: { action: null } }], ['no-verb', SN({ resource: 'a' })], ['no-res', SN({ verb: 'refund' })], ['verb-num', SN({ verb: 5, resource: 'a' })],
  ['params-array', SN({ verb: 'refund', resource: 'a', params: [1] })], ['params-null', SN({ verb: 'refund', resource: 'a', params: null })], ['empty-verb', SN({ verb: '', resource: 'a' })], ['extra', SN({ verb: 'refund', resource: 'a', params: {}, junk: 1 })]] as any[])
  for (const i of ['reversibility_class', 'blastRadius']) await add('objectiveRiskOracle', `snap/${mn}/${i}`, [base(), i, snap]);
for (const [mn, over] of MIS.slice(0, 5)) for (const i of ['reversibility', 'x']) await add('objectiveRiskOracle', `mismatch/${mn}/${i}`, [base(over), i, SN({ verb: 'refund', resource: 'a' })]);
console.log('cases', o.cases.length);
refWrite(o, 'objective-risk');
