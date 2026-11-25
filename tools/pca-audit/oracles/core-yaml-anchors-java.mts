// Oracle: the YAML text defsToYaml writes when the same object is referenced more than once (the yaml package writes an anchor on the first
// occurrence and an alias on every later one; anchors are numbered a1, a2, ... in the order the repeats are met). TS reference. Written for the
// Java lane; reusable by any native whose trees can share instances.
// PORTING: defsToYaml(ns, defs, rules, shared) -> the document text. Shared references cannot be written in JSON, so the arguments carry them:
//   `shared` maps an id to the object or array it names; anywhere inside defs, rules or a shared value, a node {"$ref": id} stands for THAT one
//   instance (build one container per id first, fill them, then substitute: cycles are allowed). Everything else is plain data.
import { Oracle, refWrite } from './lib.mjs';
const { defsToYaml }: any = await import('../../../packages/pca-actions/src/import/registry.ts');
const o = new Oracle('core-yaml-anchors-java', 'tools/pca-audit/oracles/core-yaml-anchors-java.mts', 'TS-reference oracle for defsToYaml with shared (anchored and aliased) objects.');

function materialize(shared: any, ...roots: any[]): any[] {
  const box: any = {};
  for (const [id, v] of Object.entries(shared ?? {})) box[id] = Array.isArray(v) ? [] : {};
  const sub = (x: any): any => {
    if (Array.isArray(x)) return x.map(sub);
    if (x && typeof x === 'object') {
      const ks = Object.keys(x);
      if (ks.length === 1 && ks[0] === '$ref') return box[x.$ref];
      return Object.fromEntries(ks.map((k) => [k, sub(x[k])]));
    }
    return x;
  };
  for (const [id, v] of Object.entries(shared ?? {})) {
    const filled: any = sub(v);
    if (Array.isArray(filled)) box[id].push(...filled); else Object.assign(box[id], filled);
  }
  return roots.map(sub);
}
const ref = (ns: any, defs: any, rules: any, shared: any) => { const [d, r] = materialize(shared, defs, rules); return defsToYaml(ns, d, r); };
const R = (id: string) => ({ $ref: id });
const def = (verb: string, extra: any = {}) => ({ verb, description: 'does a thing', reversibility: 'reversible', ...extra });
const LONG = 'word '.repeat(30).trim();
let k = 0;
const add = (name: string, defs: any, rules: any, shared: any) => o.run('defsToYaml', name + k++, ref, ['acme', defs, rules, shared]);

await add('none', [def('a.b.c')], {}, {});
await add('params-twice', [def('a.b.c', { params: R('p') }), def('a.b.d', { params: R('p') })], {}, { p: { id: 'string', n: 1 } });
await add('params-thrice', [def('a.b.c', { params: R('p') }), def('a.b.d', { params: R('p') }), def('a.b.e', { params: R('p') })], {}, { p: { id: 'string' } });
await add('order-second-sighting', [def('a.b.c', { params: { x: R('x'), y: R('y') } }), def('a.b.d', { params: { y: R('y'), x: R('x') } })], {}, { x: { v: 1 }, y: { v: 2 } });
await add('order-interleaved', [def('a.b.c', { params: { x: R('x'), y: R('y'), z: R('z') } }), def('a.b.d', { params: { z: R('z'), y: R('y'), x: R('x') } })], {}, { x: { v: 1 }, y: { v: 2 }, z: { v: 3 } });
await add('shared-array', [def('a.b.c', { traits: R('t') }), def('a.b.d', { traits: R('t') })], {}, { t: ['pca.pii', 'pca.destructive'] });
await add('shared-empty-map', [def('a.b.c', { params: R('e') }), def('a.b.d', { params: R('e') })], {}, { e: {} });
await add('shared-empty-seq', [def('a.b.c', { traits: R('e') }), def('a.b.d', { traits: R('e') })], {}, { e: [] });
await add('shared-in-seq-items', [def('a.b.c', { list: [R('m'), R('m'), R('m')] })], {}, { m: { a: 1, b: 'x' } });
await add('shared-seq-in-seq', [def('a.b.c', { list: [R('s'), [R('s')], R('s')] })], {}, { s: ['p', 'q'] });
await add('seq-of-maps-shared', [def('a.b.c', { list: [R('m'), { k: 1 }, R('m')] })], {}, { m: { a: 1, b: { c: 2 } } });
await add('nested-shared', [def('a.b.c', { p: R('outer'), q: R('inner') }), def('a.b.d', { p: R('outer') })], {}, { outer: { in: R('inner'), z: 1 }, inner: { w: 2 } });
await add('inner-first-twice', [def('a.b.c', { q: R('inner') }), def('a.b.d', { p: R('outer'), r: R('inner') })], {}, { outer: { in: R('inner'), z: 1 }, inner: { w: 2 } });
await add('same-def-twice', [R('d'), R('d')], {}, { d: def('a.b.c', { params: { x: 1 } }) });
await add('same-def-twice-with-rules', [R('d'), R('d')], { 'a.b.c': { required: ['x'] } }, { d: def('a.b.c') });
await add('rules-shared-two-verbs', [def('a.b.c'), def('a.b.d')], { 'a.b.c': R('r'), 'a.b.d': R('r') }, { r: { required: ['id'], max: 3 } });
await add('rules-shared-with-params', [def('a.b.c', { params: R('r') }), def('a.b.d')], { 'a.b.d': R('r') }, { r: { required: ['id'] } });
await add('alias-before-nothing-else', [def('a.b.c', { first: R('m') }), def('a.b.d', { second: R('m') }), def('a.b.e', { third: R('m') })], {}, { m: [1, 2, 3] });
await add('anchored-long-strings', [def('a.b.c', { p: R('l') }), def('a.b.d', { p: R('l') })], {}, { l: { text: LONG, more: 'y'.repeat(100), multi: 'one\ntwo\nthree' } });
await add('anchored-seq-long-first-item', [def('a.b.c', { p: R('l') }), def('a.b.d', { p: R('l') })], {}, { l: [LONG, LONG] });
await add('anchored-seq-of-seq', [def('a.b.c', { p: R('l') }), def('a.b.d', { p: R('l') })], {}, { l: [[1, 2], [3, [4, 5]], { a: [6] }] });
await add('index-keys', [def('a.b.c', { p: R('l') }), def('a.b.d', { p: R('l') })], {}, { l: { '10': 'a', '2': 'b', z: 'c', '01': 'd' } });
await add('quoted-values', [def('a.b.c', { p: R('l') }), def('a.b.d', { p: R('l') })], {}, { l: { a: 'true', b: '123', c: '', d: 'a: b', e: null, f: false, g: 1e21, h: -0 } });
await add('equal-not-same', [def('a.b.c', { p: { id: 1 } }), def('a.b.d', { p: { id: 1 } })], {}, {});
await add('cycle-map', [def('a.b.c', { p: R('c') })], {}, { c: { name: 'loop', self: R('c') } });
await add('cycle-seq', [def('a.b.c', { p: R('c') })], {}, { c: ['x', R('c')] });
await add('cycle-two', [def('a.b.c', { p: R('a') })], {}, { a: { to: R('b') }, b: { to: R('a') } });
await add('deep', [def('a.b.c', { l1: { l2: { l3: { l4: R('d') } } }, other: { l2: R('d') } })], {}, { d: { a: { b: { c: 'deep' } }, list: [1, { x: R('e') }] }, e: { n: 'e' } });
await add('many-shared', Array.from({ length: 6 }, (_, i) => def(`a.b.v${i}`, { p: R('p' + (i % 3)), q: R('p' + ((i + 1) % 3)) })), {}, { p0: { v: 0 }, p1: { v: 1 }, p2: { v: 2 } });
await add('anchor-vs-existing-key-a1', [def('a.b.c', { a1: 'user', p: R('m'), q: R('m') })], {}, { m: { k: 1 } });
for (const ns of ['acme', 'a: b']) await o.run('defsToYaml', 'ns' + k++, ref, [ns, [def('a.b.c', { p: R('m'), q: R('m') })], {}, { m: { k: 1 } }]);

refWrite(o, 'core-yaml-anchors-java');
