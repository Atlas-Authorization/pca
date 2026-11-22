// Oracle: every export of packages/pca/src/taint.ts (the L4 information-flow taint lattice, the trusted-input registry, classifyRef, computeTaint),
// TS reference. Writes out/ref-taint.json.gz. Pure and deterministic: no keys, no clock. Case shape (as every sibling): {fn, name, args, out};
// `out` is what the reference returned, or {"$throws": message}.
//
// PORTING (fn(args) -> native entry point; results compared by JSON value; a reference throw = the native refuses)
//   registry spec (RS), used wherever a TrustedInputRegistry is needed:
//     {"records": [[digest, label], ...]}   an InMemoryTrustedInputRegistry filled by record(digest, label) in order (junk records are part of the test:
//                                           an empty digest or a label whose kind is not a level is ignored)
//     {"records": [...], "mode": "throws"}  lookup always throws
//     {"mode": "fixed", "fixed": <label|null>}  lookup returns exactly `fixed` for every digest, whatever its kind (null = undefined)
//     null                                  no registry at all (the context carries none)
//   graph spec (GS): null (no resource graph) | {"nodes": [id, ...]} | {"nodes": [...], "throws": true}  (node(id) returns {id} for a listed id,
//     undefined otherwise; "throws" makes it throw). Only node(id) is ever called.
//   ctx = {registry: RS, graph?: GS}
//   constants []                       -> {TAINT_LEVELS, BOTTOM, TOP}
//   isTaintLevel [x]                   -> bool (own property check: 'constructor', '__proto__', 'toString' are not levels)
//   labelRank [label] / taintValue [label]  -> number (an unknown / missing / non-string kind is the worst rank 4, value 1)
//   joinLabel [a, b]                   -> label (the higher rank wins; equal rank keeps the id only when both agree, else {kind}); a throw is recorded
//   joinLabels [labels]                -> label (empty list = {"kind":"agent"})
//   registry [ops]                     -> list of results: ["record",d,label] ["recordTrusted",d] ["recordFirstParty",d] ["recordTool",d,id] ["recordWeb",d]
//                                         (each returns null) ["lookup",d] -> label|null  ["size"] -> int  ["emptyLookup",d] -> null (EMPTY_REGISTRY)
//   classifyRef [ref, ctx]             -> label (a throwing registry makes the case a {"$throws"} refusal)
//   computeTaint [provenance, ctx]     -> {taint, label, refs:[{ref,label}], valid, reason?} (never throws)
import { Oracle, refWrite } from './lib.mjs';

const T: any = await import('../../../packages/pca/src/taint.ts');
const o = new Oracle('taint', 'tools/pca-audit/oracles/taint.mts', 'TS-reference oracle for packages/pca/src/taint.ts (taint lattice, registry, classification, computeTaint).');

const mkRegistry = (rs: any): any => {
  if (rs === null) return undefined;
  if (rs.mode === 'fixed') return { lookup: () => (rs.fixed === null ? undefined : rs.fixed) };
  if (rs.mode === 'throws') return { lookup: () => { throw new Error('registry boom'); } };
  const r = new T.InMemoryTrustedInputRegistry();
  for (const [d, l] of rs.records ?? []) r.record(d, l);
  return r;
};
const mkCtx = (c: any): any => {
  const ctx: any = { registry: mkRegistry(c.registry) };
  if (c.graph) ctx.resourceGraph = { node: (id: string) => { if (c.graph.throws) throw new Error('graph boom'); return c.graph.nodes.includes(id) ? { id } : undefined; } };
  return ctx;
};
const REF: Record<string, (...a: any[]) => any> = {
  constants: () => ({ TAINT_LEVELS: [...T.TAINT_LEVELS], BOTTOM: T.BOTTOM, TOP: T.TOP }),
  isTaintLevel: (x) => T.isTaintLevel(x),
  labelRank: (l) => T.labelRank(l),
  taintValue: (l) => T.taintValue(l),
  joinLabel: (a, b) => T.joinLabel(a, b),
  joinLabels: (ls) => T.joinLabels(ls),
  registry: (ops: any[][]) => {
    const r = new T.InMemoryTrustedInputRegistry();
    return ops.map(([op, ...a]) => {
      if (op === 'lookup') return r.lookup(a[0]) ?? null;
      if (op === 'size') return r.size;
      if (op === 'emptyLookup') return T.EMPTY_REGISTRY.lookup(a[0]) ?? null;
      (r as any)[op](...a);
      return null;
    });
  },
  classifyRef: (ref, c) => T.classifyRef(ref, mkCtx(c)),
  computeTaint: (p, c) => T.computeTaint(p, mkCtx(c)),
};
let n = 0;
const run = (fn: string, name: string, args: any[]) => o.run(fn, `${name}#${n++}`, REF[fn], args);

const LV = ['trusted', 'first_party', 'tool', 'web', 'agent'];
const L = (kind: string, id?: string): any => (id === undefined ? { kind } : { kind, id });
const LABELS: any[] = [L('trusted'), L('first_party'), L('tool'), L('tool', 'a'), L('tool', 'b'), L('web'), L('agent'), L('agent', 'x'), L('agent', 'y'), L('tool', ''),
  L('web', 'w'), L('trusted', 'z')];
const WEIRD: any[] = [null, {}, { kind: 'constructor' }, { kind: '__proto__' }, { kind: 'toString' }, { kind: 'hasOwnProperty' }, { kind: 'x' }, { kind: 5 }, { kind: null }, { kind: 'Trusted' }, { kind: ' web' }, 'agent', 5, [], { Kind: 'trusted' }];

await run('constants', 'all', []);
for (const x of [...LV, 'constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty', 'isPrototypeOf', '', 'Trusted', 'TRUSTED', ' web', 'web ', 'agent\u0000', null, 5, true, {}, [], ['agent'], { kind: 'agent' }]) await run('isTaintLevel', JSON.stringify(x), [x]);
for (const l of [...LABELS, ...WEIRD]) { await run('labelRank', JSON.stringify(l), [l]); await run('taintValue', JSON.stringify(l), [l]); }
for (const a of [...LABELS, ...WEIRD.slice(0, 8)]) for (const b of [...LABELS, ...WEIRD.slice(0, 8)]) await run('joinLabel', `${JSON.stringify(a)}|${JSON.stringify(b)}`, [a, b]);
for (const ls of [[], [LABELS[0]], [LABELS[0], LABELS[0]], [LABELS[1], LABELS[2]], [L('tool', 'a'), L('tool', 'b')], [L('tool', 'a'), L('tool', 'a')], [L('agent', 'x'), L('agent')],
  [LABELS[0], LABELS[1], LABELS[2], LABELS[5]], [LABELS[5], LABELS[2], LABELS[1], LABELS[0]], [LABELS[5], L('agent', 'q'), LABELS[0]], [L('tool', 'a'), L('tool', 'b'), L('tool', 'a')],
  [L('first_party'), L('first_party')], [{ kind: 'x' }], [{ kind: 'x' }, LABELS[0]], [LABELS[0], { kind: 'x' }], [{ kind: 'x' }, { kind: 'y' }], [null], [LABELS[0], null], [LABELS[6], null]] as any[][])
  await run('joinLabels', JSON.stringify(ls), [ls]);
// every permutation of a 3-label sample is the same join (order independence)
const P3 = [L('tool', 'a'), L('tool', 'b'), L('web')];
for (const p of [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]) await run('joinLabels', 'perm' + p.join(''), [p.map((i) => P3[i])]);

// registry ops
const REGOPS: [string, any[][]][] = [
  ['basic', [['recordTrusted', 'd1'], ['recordFirstParty', 'd2'], ['recordTool', 'd3', 'tl'], ['recordWeb', 'd4'], ['lookup', 'd1'], ['lookup', 'd2'], ['lookup', 'd3'], ['lookup', 'd4'], ['lookup', 'nope'], ['size']]],
  ['overwrite', [['recordTrusted', 'd'], ['lookup', 'd'], ['recordWeb', 'd'], ['lookup', 'd'], ['size']]],
  ['junk-digest', [['record', '', { kind: 'trusted' }], ['record', 5, { kind: 'trusted' }], ['record', null, { kind: 'trusted' }], ['size'], ['lookup', '']]],
  ['junk-label', [['record', 'd', { kind: 'bogus' }], ['record', 'e', null], ['record', 'f', {}], ['record', 'g', { kind: 'constructor' }], ['record', 'h', { kind: '__proto__' }], ['size'], ['lookup', 'd'], ['lookup', 'g']]],
  ['record-labels', [['record', 'a', { kind: 'tool', id: 'x', extra: 1 }], ['record', 'b', { kind: 'agent' }], ['record', 'c', { kind: 'agent', id: 'q' }], ['lookup', 'a'], ['lookup', 'b'], ['lookup', 'c'], ['size']]],
  ['tool-id', [['recordTool', 'd', ''], ['recordTool', 'e', 'id'], ['lookup', 'd'], ['lookup', 'e']]],
  ['proto-keys', [['recordTrusted', '__proto__'], ['recordWeb', 'constructor'], ['lookup', '__proto__'], ['lookup', 'constructor'], ['lookup', 'toString'], ['size']]],
  ['empty', [['size'], ['lookup', 'x'], ['emptyLookup', 'x'], ['emptyLookup', '']]],
  ['unicode', [['recordTrusted', 'é'], ['recordTrusted', 'é'], ['lookup', 'é'], ['lookup', 'é'], ['size']]],
];
for (const [name, ops] of REGOPS) await run('registry', name, [ops]);

// classifyRef / computeTaint over registries and graphs
const RS: Record<string, any> = {
  vouch: { records: [['d-trusted', L('trusted')], ['d-fp', L('first_party')], ['d-tool', L('tool', 'tl')], ['d-web', L('web')], ['d-agent', L('agent', 'ag')]] },
  trustedOnly: { records: [['t1', L('trusted')], ['t2', L('trusted')]] },
  empty: { records: [] },
  junk: { records: [['', L('trusted')], ['x', { kind: 'bogus' }], ['y', L('trusted')]] },
  none: null,
  throws: { mode: 'throws' },
  fixedBogus: { mode: 'fixed', fixed: { kind: 'bogus' } },
  fixedProto: { mode: 'fixed', fixed: { kind: 'constructor' } },
  fixedTrusted: { mode: 'fixed', fixed: L('trusted') },
  fixedNull: { mode: 'fixed', fixed: null },
};
const GS: Record<string, any> = { none: null, nodes: { nodes: ['res:a', 'res:b', 'd-web'] }, empty: { nodes: [] }, throws: { nodes: ['res:a'], throws: true } };
const LONG = 'r'.repeat(128), LONG1 = 'r'.repeat(129);
const REFS: any[] = ['d-trusted', 'd-fp', 'd-tool', 'd-web', 'd-agent', 't1', 'res:a', 'res:b', 'unknown', 'x', 'y', '', 5, null, undefined, {}, [], LONG, LONG1, '__proto__', 'constructor', 'é'];
for (const [rn, rs] of Object.entries(RS)) for (const [gn, gs] of Object.entries(GS)) for (const [i, r] of REFS.entries())
  await run('classifyRef', `${rn}/${gn}/${i}`, [r === undefined ? null : r, { registry: rs, ...(gs ? { graph: gs } : {}) }]);
await run('classifyRef', 'long-registered', [LONG1, { registry: { records: [[LONG1, L('web')]] } }]);

const PROVS: [string, any][] = [
  ['all-trusted', { trusted_refs: ['t1', 't2'] }], ['one-trusted', { trusted_refs: ['t1'] }], ['mixed', { trusted_refs: ['t1', 'd-fp', 'd-tool'] }], ['with-web', { trusted_refs: ['t1', 'd-web'] }],
  ['unverifiable', { trusted_refs: ['t1', 'unknown'] }], ['all-unknown', { trusted_refs: ['unknown'] }], ['graph-hit', { trusted_refs: ['res:a', 'res:b'] }], ['graph+reg', { trusted_refs: ['t1', 'res:a'] }],
  ['empty-refs', { trusted_refs: [] }], ['absent-refs', {}], ['refs-undefined', { trusted_refs: undefined }], ['refs-null', { trusted_refs: null }], ['refs-string', { trusted_refs: 't1' }], ['refs-object', { trusted_refs: { 0: 't1' } }],
  ['bad-elem-num', { trusted_refs: ['t1', 5] }], ['bad-elem-empty', { trusted_refs: ['t1', ''] }], ['bad-elem-null', { trusted_refs: [null] }], ['bad-elem-obj', { trusted_refs: [{}] }],
  ['claims-trusted', { trusted_refs: ['unknown'], taint_level: 'trusted', causal_hash: 'h' }], ['claims-extra', { trusted_refs: ['t1'], taint_level: 'agent', causal_hash: 'h', other: 1 }],
  ['dup', { trusted_refs: ['t1', 't1', 'unknown', 'unknown'] }], ['two-agent-ids', { trusted_refs: ['u1', 'u2'] }], ['long-ref', { trusted_refs: [LONG, LONG1] }], ['tools', { trusted_refs: ['d-tool', 'd-tool'] }],
  ['order-a', { trusted_refs: ['d-tool', 't1', 'd-web'] }], ['order-b', { trusted_refs: ['d-web', 'd-tool', 't1'] }], ['agent-reg', { trusted_refs: ['d-agent', 't1'] }], ['proto', { trusted_refs: ['__proto__', 'constructor'] }],
  ['unicode', { trusted_refs: ['é', 'é'] }],
  ['null', null], ['undefined', null], ['string', 'x'], ['number', 5], ['array', ['t1']], ['bool', true],
];
let pi = 0;
for (const [rn, rs] of Object.entries(RS)) for (const gn of ['none', 'nodes', 'throws']) for (const [pn, p] of PROVS)
  if (pi++ % 1 === 0) await run('computeTaint', `${rn}/${gn}/${pn}`, [p, { registry: rs, ...(GS[gn] ? { graph: GS[gn] } : {}) }]);
// a registry the reference rejects: a context with no registry at all, and a missing context
await run('computeTaint', 'noctx', [{ trusted_refs: ['t1'] }, { registry: null }]);
console.log('cases', o.cases.length);
refWrite(o, 'taint');
