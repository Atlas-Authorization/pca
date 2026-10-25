// Oracle for the Kotlin predicate-DSL kill tests (KillPredTest.kt): runs the TS reference (packages/pca/src/predicates.ts)
// over contexts x paths (resolvePath), leaf conditions (every op x field x operand, value and ref forms), globs (`like`),
// `matches`, `member_of` closures, groupings, predicates and predicate lists. Deterministic.
//   <tsx> tools/pca-audit/kotlin-mutate/killPred-oracle-gen.mjs <pca-src-dir> sdks/kotlin-pca/test-data/killPred.json.gz
import fs from 'node:fs';
import zlib from 'node:zlib';
const src = process.argv[2];
const out = process.argv[3];
const pr = await import(`${src}/predicates.ts`);

const act = (params, extra = {}) => ({ verb: 'air.book', resource: 'skyair.example/bookings/7', ...(params === undefined ? {} : { params }), ...extra });
const C0 = {
  action: act({
    total: 38900, name: 'Ana', tags: ['a', 'b'], nested: { x: 1, y: { z: 'deep' } }, astral: '😀', empty: '', nul: null, t: true, f: false, neg: -5, float: 1.5, zero: 0, big: 9007199254740993, huge: 1e300,
    list: [10, 20, { k: 'v' }], user: { type: 'user::admin', tags: ['x'] }, plain: { type: 'user' }, tagsonly: { tags: ['a'] }, badtype: { type: 5 }, badtags: { tags: 'a' }, notag: { other: 1 }, s: 'abc', 'a b': 1, '': 'emptykey',
    eu: 'é', eu2: 'ü', zs: 'z', za: 'a', num_s: '5', nlist: [1, 2, 3], slist: ['x', 'y'], mixed: [1, 'a', null], objs: [{ a: 1 }, { a: 2 }], o1: { a: 1, b: 2 }, o2: { b: 2, a: 1 }, nested_list: [[1, 2], [3]],
    type_exact: 'user', type_prefix: 'user::x', type_near: 'users', type_colon: 'user:', ctype: { type: 'user', tags: [] }, emptyobj: {}, emptylist: [], g: 'ana', gt: 'emp', gl: ['emp', 'zzz'], gnone: 'zzz', gx: 'x',
  }, { reversibility_class: 'reversible' }),
  subject: { id: 'ana', role: 'admin', n: 7 },
  env: { cur: 'dev1', groups: { ana: 'staff', staff: ['emp', 'x', 5, 'staff'], emp: 'all', loop1: 'loop2', loop2: 'loop1', obj: {}, nul: null, num: 7, self: 'self', dup: ['a', 'a'], a: ['b', 'c'], b: 'd', c: 'd', d: [] }, flag: true, n: 3, canon: { add_ons: '["none"]' } },
};
const chain = {}; for (let i = 0; i < 10005; i++) chain[`n${i}`] = `n${i + 1}`;
const ctxs = [
  C0,
  { action: act(undefined) },
  { action: act(null) },
  { action: act(['a', 'b']) },
  { action: act('x') },
  { action: act({ a: 1 }) },
  {},
  null,
  { action: { verb: 5, resource: 'r' } },
  { action: { verb: 'v', resource: 5 } },
  { action: ['verb'] },
  { action: act({ p: 1 }), env: { g: chain, start: 'n0', t1: 'n9999', t2: 'n10000', t3: 'n10001', t4: 'n5' } },
  { action: act({ p: 1 }), subject: ['a'], env: 'e' },
  { action: act({ p: 1 }), subject: null, env: null },
  { action: act({ p: 1, a: { __proto__: null } }), env: { groups: { x: 'y' } } },
];
// own "__proto__" members come from JSON.parse
ctxs.push(JSON.parse('{"action":{"verb":"v","resource":"r","params":{"__proto__":{"x":1},"constructor":{"y":2},"prototype":3,"k":{"__proto__":"z"}}},"env":{"g":{"__proto__":"a","a":"b","constructor":"c","c":"__proto__"},"v1":"a","v2":"__proto__","v3":"constructor"}}'));
const HAS_PROTO = ctxs.length - 1;
const ctxJson = ctxs.map((c) => JSON.stringify(c));
const ctxsClean = ctxJson.map((j) => JSON.parse(j));
const ctxIndex = new Map();
const cidx = (c) => { const j = JSON.stringify(c); if (!ctxIndex.has(j)) { ctxsClean.push(JSON.parse(j)); ctxIndex.set(j, ctxsClean.length - 1); } return ctxIndex.get(j); };

const TRI = { true: 'T', false: 'F', unknown: 'U' };
const rp = [];
const cond = [];
const pred = [];
const preds = [];
const R = (path, ci) => { const r = pr.resolvePath(ctxsClean[ci], path); rp.push([path, ci, r.found, r.found ? (r.value === undefined ? null : r.value) : null]); };

// ---- resolvePath ----
const PATHS = ['', 'action', 'action.', '.action', 'action..verb', 'action.verb', 'action.resource', 'action.params', 'action.params.total', 'action.params.tags', 'action.params.tags.0', 'action.params.tags.1', 'action.params.tags.2', 'action.params.tags.00', 'action.params.tags.01', 'action.params.tags.-1',
  'action.params.tags.1.5', 'action.params.tags.1e0', 'action.params.tags.length', 'action.params.tags.', 'action.params.tags. 1', 'action.params.tags.+1', 'action.params.tags.1 ', 'action.params.tags.0x1', 'action.params.tags.99999999999999999999', 'action.params.tags.٣', 'action.params.list.2.k', 'action.params.list.2', 'action.params.list.3', 'action.params.list.10',
  'action.params.nested.x', 'action.params.nested.y.z', 'action.params.nested.y.z.q', 'action.params.nested.q', 'action.params.nul', 'action.params.nul.x', 'action.params.t', 'action.params.t.x', 'action.params.s.length', 'action.params.s.0', 'action.params.empty', 'action.params.' + '', 'action.params.a b', 'action.params..', 'action.params.',
  'action.__proto__', 'action.__proto__.x', 'action.constructor', 'action.constructor.name', 'action.prototype', 'action.params.__proto__', 'action.params.constructor', 'action.params.prototype', 'action.params.k.__proto__', 'action.params.toString', 'action.params.hasOwnProperty', 'action.params.valueOf',
  'subject', 'subject.id', 'subject.role', 'subject.n', 'subject.x', 'env', 'env.cur', 'env.groups', 'env.groups.ana', 'env.groups.staff.1', 'env.canon.add_ons', 'env.flag', 'foo', 'Action', 'ACTION.verb', 'action.Verb', 'tool', 'toolBinding', 'action.reversibility_class', 'actions.verb', 'subjects', 'envs', 'a.b', '.', '..', 'env.g.n0', 'env.g.n10004', 'env.g.n10005', 'env.g.n10006', 'env.start',
  'env.g.__proto__', 'env.g.constructor', 'env.v1', 'action.params.__proto__.x', 'action.params.constructor.y', 'action.params.prototype.x'];
for (const ci of ctxsClean.keys()) for (const p of PATHS) R(p, ci);
for (const p of [5, null, true, ['action'], { a: 1 }, 0, false, ['action', 'verb']]) for (const ci of [0, 1, 6, 7]) R(p, ci);

// ---- leaf conditions ----
const OPS = ['eq', 'ne', 'in', 'nin', 'lt', 'lte', 'gt', 'gte', 'prefix', 'like', 'matches', 'is_a', 'exists', 'member_of', 'xx', '', 'EQ', 'regex', 'contains'];
const FIELDS = ['action.params.total', 'action.params.name', 'action.params.tags', 'action.params.nested', 'action.params.nested.x', 'action.params.astral', 'action.params.empty', 'action.params.nul', 'action.params.t', 'action.params.f', 'action.params.neg', 'action.params.float', 'action.params.zero', 'action.params.big', 'action.params.huge',
  'action.params.list', 'action.params.user', 'action.params.plain', 'action.params.tagsonly', 'action.params.badtype', 'action.params.badtags', 'action.params.notag', 'action.params.s', 'action.params.missing', 'action.params', 'action.verb', 'action.resource', 'subject.id', 'subject.n', 'env.cur', 'env.n', 'env.flag', 'env.groups', 'action', 'zzz', 'subject', 'action.params.eu', 'action.params.num_s', 'action.params.o1', 'action.params.type_exact', 'action.params.type_prefix', 'action.params.type_near', 'action.params.type_colon', 'action.params.ctype', 'action.params.emptyobj', 'action.params.emptylist', 'action.params.g', 'action.params.gt', 'action.params.gl', 'action.params.gnone', 'action.params.gx', 'action.params.slist'];
const VALUES = [38900, 38900.0, '38900', 38899, 38901, 0, -0, 1, -5, 1.5, 1.4999999999999998, 2, 9007199254740992, 9007199254740993, 1e300, 1e301, 'Ana', 'ana', 'An', 'Ana ', '', 'a', 'ab', '😀', '\ud83d', 'é', 'ü', 'z', true, false, null, ['a', 'b'], ['b', 'a'], ['a'], ['a', 'b', 'c'], [], [38900], ['Ana', 'x'], [null], [1, 2, 3], { x: 1 }, { x: 1, y: { z: 'deep' } }, { y: { z: 'deep' }, x: 1 }, {}, [{ a: 1 }], { a: 1, b: 2 }, { b: 2, a: 1 },
  'air.book', 'air.', 'skyair.example/bookings/7', 'skyair', 'user', 'user::admin', 'x', 'admin', 'users', '5', 'a*', '*', '?', '*a*', 'A*', 'Ana*', '?na', 'A?a', '^A', 'A.a', 'A.*', '[A-Z].*', '[A-Z]na', '(?:A|B)na', 'A(', 'A{', '(a+)+', '(?:a|b)*', 'ana', 'staff', 'emp', 'all', 'zzz', ['emp'], ['zzz'], ['zzz', 'all'], ['all', 5], [5], 7, 'dev1', 'staff::x'];
const L = (field, op, extra) => ({ field, op, ...extra });
const cs = (c, ci) => { const t = pr.evaluateConditionTri(c, ctxsClean[ci]); cond.push([c, ci, TRI[t]]); };
for (const op of OPS) for (const f of FIELDS) {
  for (const v of VALUES) { if (typeof v === 'string' && !v.isWellFormed()) continue; cs(L(f, op, { value: v }), 0); }
  cs(L(f, op, {}), 0);
}
const REFS = ['action.params.total', 'action.params.name', 'action.params.tags', 'action.params.nested', 'action.params.s', 'action.params.missing', 'subject.id', 'env.cur', 'env.groups', 'action.params.g', 'action.params.gt', 'action.params.gl', 'action.params.f', 'action.params.empty', 'action.params.nul', 'zzz', 'action.params.type_exact', 'action.params.neg', 'action.params.float', 'action.params.big', 'action', ''];
for (const op of OPS) for (const f of FIELDS) for (const r of REFS) cs(L(f, op, { ref: r }), 0);
cs(L('action.params.total', 'eq', { ref: 5 }), 0); cs(L('action.params.total', 'eq', { ref: null }), 0); cs(L('action.params.total', 'eq', { ref: ['a'] }), 0);
cs(L('action.params.total', 'eq', { ref: 'action.params.total', value: 1 }), 0); cs(L('action.params.total', 'eq', { ref: 'action.params.missing', value: 38900 }), 0);
cs(L('action.params.total', 'exists', { ref: 'zzz' }), 0);
// field / op shapes
for (const f of [5, null, '', true, ['a'], {}, undefined]) for (const o of ['eq', 'exists']) cs({ field: f, op: o, value: 1 }, 0);
for (const o of [5, null, true, ['eq'], {}, undefined]) cs({ field: 'action.params.total', op: o, value: 38900 }, 0);
for (const c of [null, 5, 'x', true, [], [1], [{ field: 'action.params.total', op: 'exists' }], {}, { value: 1 }, { field: 'action.params.total' }, { op: 'eq' }, { all_of: [] }, { any_of: [] }, { all_of: 'x' }, { any_of: 5 }, { all_of: null }, { any_of: null }, { not: null }, { not: 5 }, { not: {} }, { not: [] }]) cs(c, 0);
// exists
for (const ci of ctxsClean.keys()) for (const f of ['action.params.total', 'action.params.missing', 'action.params', 'action.params.nul', 'action.verb', 'subject.id', 'env.cur', 'zzz', 'action.params.tags.0', 'action.params.tags.2']) for (const v of [undefined, true, false, null, 0, 1, 'false', 'x', []]) cs(v === undefined ? L(f, 'exists', {}) : L(f, 'exists', { value: v }), ci);
// other contexts: params availability, missing roots
for (const ci of ctxsClean.keys()) for (const f of ['action.params.total', 'action.params', 'action.params.p', 'action.params.a', 'action.verb', 'subject.id', 'env.cur', 'env.groups', 'action.params.k', 'env.g.a']) for (const [op, v] of [['eq', 1], ['eq', 'v'], ['ne', 1], ['nin', [1]], ['in', [1, 'v']], ['lt', 2], ['prefix', 'a'], ['is_a', 'x'], ['like', '*'], ['matches', '.*']])
  cs(L(f, op, { value: v }), ci);
for (const ci of ctxsClean.keys()) for (const f of ['action.params.total', 'action.verb', 'env.cur', 'action.params.p']) for (const r of ['action.params.total', 'action.params', 'action.params.p', 'action.verb', 'env.cur', 'action.params.a']) for (const op of ['eq', 'ne', 'in', 'member_of']) cs(L(f, op, { ref: r, collection: 'env.groups' }), ci);
// member_of
const MF = ['action.params.g', 'action.params.gt', 'action.params.gl', 'action.params.gnone', 'action.params.gx', 'action.params.total', 'action.params.name', 'action.params.s', 'subject.id', 'env.cur', 'action.params.empty', 'action.params.nul', 'action.params.missing'];
const MC = ['env.groups', 'env.canon', 'env.flag', 'env.cur', 'action.params.nested', 'action.params.tags', 'action.params.list', 'action.params.missing', 'zzz', '', 5, null, 'env', 'action.params', 'action.params.emptyobj', 'action.params.o1'];
const MV = ['staff', 'emp', 'all', 'zzz', 'x', 5, ['emp'], ['zzz', 'all'], ['all', 5], [5], [], ['staff'], 'ana', 'dup', 'a', 'd', 'self', 'loop1', 'loop2', 'obj', 'nul', 'num', true, null, {}, ['ana']];
for (const f of MF) for (const col of MC) for (const v of MV.slice(0, 12)) cs({ field: f, op: 'member_of', collection: col, value: v }, 0);
for (const f of MF.slice(0, 6)) for (const v of MV) cs({ field: f, op: 'member_of', collection: 'env.groups', value: v }, 0);
for (const f of MF) for (const col of ['env.groups', 'zzz']) for (const r of REFS) cs({ field: f, op: 'member_of', collection: col, ref: r }, 0);
cs({ field: 'action.params.g', op: 'member_of', collection: 'env.groups' }, 0);
cs({ field: 'action.params.g', op: 'member_of', value: 'all' }, 0);
for (const [fld, col] of [['action.params.g', 'env.groups'], ['subject.id', 'env.groups']]) for (const ref of ['env.cur', 'action.params.gt', 'action.params.gl', 'action.params.missing', 'action.params.total']) cs({ field: fld, op: 'member_of', collection: col, ref }, 0);
// closure over graphs (loops, fan-in, the 10,000-node bound, own __proto__ / constructor members)
for (const [s, t] of [['n0', 'n9999'], ['n0', 'n10000'], ['n0', 'n10001'], ['n5', 'n5'], ['n9998', 'n10000'], ['n9999', 'n10001'], ['n0', 'n5'], ['n0', 'n10005'], ['n10004', 'n10005'], ['n10005', 'n10006']]) {
  cs({ field: 'env.start', op: 'member_of', collection: 'env.g', value: t }, 11);
  const c = JSON.parse(JSON.stringify(ctxsClean[11])); c.env.start = s; const k = cidx(c); cs({ field: 'env.start', op: 'member_of', collection: 'env.g', value: t }, k);
}
for (const v of ['env.t1', 'env.t2', 'env.t3', 'env.t4']) cs({ field: 'env.start', op: 'member_of', collection: 'env.g', ref: v }, 11);
for (const [f, v] of [['env.v1', 'b'], ['env.v1', 'a'], ['env.v1', 'c'], ['env.v2', 'a'], ['env.v2', '__proto__'], ['env.v3', 'c'], ['env.v3', 'constructor'], ['env.v1', '__proto__'], ['env.v1', 'constructor']]) cs({ field: f, op: 'member_of', collection: 'env.g', value: v }, HAS_PROTO);
// groupings
const LEAFS = [L('action.params.total', 'eq', { value: 38900 }), L('action.params.total', 'eq', { value: 1 }), L('action.params.missing', 'eq', { value: 1 }), L('action.params.name', 'prefix', { value: 'A' }), L('action.params.name', 'prefix', { value: 'Z' }), L('action.params.nul', 'lt', { value: 1 }), L('action.params.t', 'exists', {}), L('zzz', 'exists', {}), { field: 5, op: 'eq' }];
for (const a of LEAFS) { cs({ not: a }, 0); cs({ all_of: [a] }, 0); cs({ any_of: [a] }, 0); for (const b of LEAFS) { cs({ all_of: [a, b] }, 0); cs({ any_of: [a, b] }, 0); cs({ all_of: [a, { not: b }] }, 0); cs({ any_of: [{ not: a }, b] }, 0); cs({ not: { all_of: [a, b] } }, 0); cs({ not: { any_of: [a, b] } }, 0); for (const c of LEAFS.slice(0, 5)) { cs({ all_of: [a, b, c] }, 0); cs({ any_of: [a, b, c] }, 0); } } }
cs({ all_of: [LEAFS[0]], any_of: [LEAFS[1]] }, 0); cs({ any_of: [LEAFS[1]], all_of: [LEAFS[0]] }, 0); cs({ not: LEAFS[1], all_of: [LEAFS[0]] }, 0); cs({ not: LEAFS[1], any_of: [LEAFS[0]] }, 0); cs({ not: LEAFS[0], field: 'x', op: 'exists' }, 0); cs({ all_of: [LEAFS[0]], field: 'zzz', op: 'exists', value: false }, 0);
cs({ all_of: [[LEAFS[0]]] }, 0); cs({ all_of: [5] }, 0); cs({ any_of: [null, LEAFS[0]] }, 0); cs({ all_of: [null] }, 0); cs({ not: { not: LEAFS[0] } }, 0); cs({ not: { not: { not: LEAFS[1] } } }, 0);
let deep = LEAFS[0]; for (let i = 0; i < 40; i++) deep = i % 2 ? { all_of: [deep] } : { any_of: [deep] }; cs(deep, 0);
let deep2 = LEAFS[0]; for (let i = 0; i < 300; i++) deep2 = { not: deep2 }; cs(deep2, 0);
let deep3 = LEAFS[0]; for (let i = 0; i < 2000; i++) deep3 = { not: deep3 }; cs(deep3, 0);

// ---- like (glob) and matches ----
const GLOBS = ['*', '**', '***', '?', '??', '', 'abc', 'a*', '*c', '*b*', 'a*c', 'a?c', 'a*b*c', 'a**c', '*a*b*c*', '?*', '*?', '?*?', 'a\\*c', 'a\\?c', 'a\\\\c', '\\a', '\\', 'abc\\', 'a\\', '\\\\', '\\*', '\\?', 'a*\\', '*\\', '?\\', 'ab?', '?bc', 'a?c*', '*a', 'ab*bc', 'a*a*a*b', '*a*a*a*b', 'abcabc', '*abc*', '*bc', '*ab', 'abc*', '*abc', 'a[bc]c', 'a.c', 'a+', '^abc$', '😀', '?', '??😀', '*😀', 'é*', '?é', '*\n*', 'a?', '?a', '*\r', 'x*y*z', '*,*', '\\\\*', '\\\\\\*', 'a\\\\*', '\\\\\\\\', 'a*bc*d'];
const SUBJ = ['', 'a', 'ab', 'abc', 'abcd', 'abcabc', 'ac', 'a*c', 'a?c', 'a\\c', '\\a', '\\', 'aXc', 'aXYc', 'aaab', 'aaaaaaaab', 'a'.repeat(300) + 'b', 'a'.repeat(512), 'a'.repeat(513), 'ab' + 'c'.repeat(100), '😀', 'a😀', '😀😀', 'é', 'éa', '\n', 'a\nb', '\r', ' ', '*', '?', 'abc\\', 'xyz', 'x,y', ',', 'xaybz', 'ABC', 'bc', 'b', 'c'];
const sctx = new Map();
const sc = (s) => { if (!sctx.has(s)) sctx.set(s, cidx({ action: act({ s }) })); return sctx.get(s); };
for (const g of GLOBS) for (const s of SUBJ) cs(L('action.params.s', 'like', { value: g }), sc(s));
for (const g of ['*', 'a*', '*a', '?'.repeat(512), '*'.repeat(512), 'a'.repeat(512), 'a'.repeat(513), '*'.repeat(513), '?'.repeat(513), 'a'.repeat(511), '?'.repeat(511)]) for (const s of ['a'.repeat(512), 'a'.repeat(513), 'a'.repeat(511), 'a', '']) cs(L('action.params.s', 'like', { value: g }), sc(s));
for (const s of [5, null, true, ['a'], { a: 1 }]) { cs(L('action.params.s', 'like', { value: 'a' }), cidx({ action: act({ s }) })); cs(L('action.params.s', 'prefix', { value: 'a' }), cidx({ action: act({ s }) })); cs(L('action.params.s', 'matches', { value: 'a' }), cidx({ action: act({ s }) })); cs(L('action.params.s', 'is_a', { value: 'a' }), cidx({ action: act({ s }) })); }
const MATCH = ['a', 'abc', 'a.c', 'a*', 'a+', '[a-c]+', '\\d+', '\\w+', '^abc$', 'abc|xyz', '(?:abc|xyz)', '(a|b)+', '(a+)+', '(a*)*', 'a{2,}', 'a{1,65}', '(?=a)', '\\1', '[', '(', 'a**', '.*', '.+', '', '?', '.'.repeat(200), '.'.repeat(201), 'a'.repeat(200), 'a'.repeat(201), '.{0,64}', 'a?'.repeat(21), 'a?'.repeat(22), 'a?'.repeat(23), 'a*a*a', 'a*a*a*', 'x|y|z', '(?:a|aa)+b', '\\s*', '[^,]*,[^,]*', 'ab?c', 'é', '😀', '.😀'];
for (const m of MATCH) for (const s of ['', 'a', 'abc', 'aaa', 'xyz', 'abcabc', '12', 'a1', 'aab', 'é', '😀', 'a😀', ' ', 'a,b', ',', 'a'.repeat(200), 'a'.repeat(512), 'a'.repeat(513), 'ab'.repeat(5)]) cs(L('action.params.s', 'matches', { value: m }), sc(s));
// regex work budget across a document: 64 evaluations, 8192 source chars, 5M steps, poisoning
const mt = (m, f = 'action.params.s') => L(f, 'matches', { value: m });
const manyCtx = cidx({ action: act({ s: 'a' }) });
for (const n of [1, 63, 64, 65, 66]) { cs({ all_of: Array.from({ length: n }, () => mt('a')) }, manyCtx); cs({ any_of: Array.from({ length: n }, () => mt('b')) }, manyCtx); cs({ any_of: [...Array.from({ length: n - 1 }, () => mt('b')), mt('a')] }, manyCtx); }
cs({ all_of: [...Array.from({ length: 64 }, () => mt('a')), mt('(')] }, manyCtx);
cs({ any_of: [mt('('), mt('a')] }, manyCtx);
cs({ any_of: [...Array.from({ length: 65 }, () => mt('b')), mt('a')] }, manyCtx);
cs({ all_of: [{ any_of: Array.from({ length: 40 }, () => mt('b')) }, { any_of: Array.from({ length: 40 }, () => mt('b')) }, mt('a')] }, manyCtx);
cs({ not: { any_of: Array.from({ length: 70 }, () => mt('b')) } }, manyCtx);
const big = 'x'.repeat(190);
for (const n of [40, 41, 42, 43, 44]) cs({ all_of: Array.from({ length: n }, () => mt(big + '.')) }, manyCtx);
const sub512 = cidx({ action: act({ s: 'a'.repeat(512) }) });
for (const n of [1, 2, 3, 4, 5, 6, 7]) cs({ all_of: Array.from({ length: n }, () => mt('.'.repeat(200))) }, sub512);
for (const n of [30, 31, 32, 33, 34, 35]) cs({ all_of: Array.from({ length: n }, () => mt('.'.repeat(60))) }, sub512);
cs({ any_of: [...Array.from({ length: 5 }, () => mt('b'.repeat(190))), mt('.')] }, sub512);

// ---- predicates ----
const VERBS = ['air.book', '*', 'air.', 'air.book ', 'AIR.BOOK', ['air.book'], ['*'], ['x', 'air.book'], ['x', 5, '*'], ['x', 5], [], ['x'], 5, null, {}, '', [['air.book']]];
const RESS = [undefined, 'skyair.example/bookings/7', '*', 'skyair.example/bookings/*', 'skyair.example/*', 'skyair.example/bookings/7*', 'skyair.example/bookings/77*', '*7', 'skyair.example/bookings/8', 're:skyair\\.example/bookings/\\d+', 're:skyair\\.example/bookings/\\d', 're:skyair\\.example', 're:.*', 're:(', 're:', 're:' + 'a'.repeat(200), 're:' + '.'.repeat(200), 're:' + '.'.repeat(201), 're:(a+)+', 're:skyair.*7', 're:a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?a?', 're:\\1', 5, null, true, ['x'], {}, '', 'skyair.example/bookings/7/', 're:*', 'RE:.*', 're:re:.*', '**', '*skyair*'];
for (const v of VERBS) for (const r of RESS) { const p = { verb: v }; if (r !== undefined) p.resource = r; pred.push([p, 0, pr.predicateMatches(p, ctxsClean[0])]); }
const longRes = ['a'.repeat(512), 'a'.repeat(513), 'a'.repeat(511), 'b'.repeat(512)];
for (const lr of longRes) { const k = cidx({ action: { verb: 'v', resource: lr } }); for (const r of ['re:.*', 're:a*', 're:a+', 're:b*', 'a*', '*', lr, 're:' + 'a'.repeat(200)]) { const p = { verb: '*', resource: r }; pred.push([p, k, pr.predicateMatches(p, ctxsClean[k])]); } }
const WH = [undefined, [], [LEAFS[0]], [LEAFS[1]], [LEAFS[0], LEAFS[3]], [LEAFS[0], LEAFS[1]], [LEAFS[2]], [LEAFS[0], LEAFS[2]], [null], [5], 'x', {}, null, [{ all_of: [LEAFS[0], LEAFS[3]] }], [{ not: LEAFS[1] }], [{ not: LEAFS[2] }], [LEAFS[8]], [L('zzz', 'exists', { value: false })], [L('action.params.missing', 'exists', { value: false })], [L('action.params.total', 'in', { value: [38900, 1] })], [L('action.params.total', 'lt', { value: 40000 })], [L('action.params.total', 'lt', { value: 38900 })]];
for (const w of WH) for (const ci of [0, 1, 2, 5, 6, 7, 8, 9, 10]) for (const vb of ['air.book', 'x']) { const p = { verb: vb, resource: '*' }; if (w !== undefined) p.where = w; pred.push([p, ci, pr.predicateMatches(p, ctxsClean[ci])]); }
for (const p of [null, 5, 'x', true, [], [{ verb: '*' }], {}, { resource: '*' }, { verb: '*', where: undefined }, { verb: '*', resource: undefined }]) for (const ci of [0, 6, 7]) pred.push([p === undefined ? null : p, ci, pr.predicateMatches(p, ctxsClean[ci])]);
// predicate lists
const PL = [[], null, 5, 'x', {}, [{ verb: 'x' }], [{ verb: 'air.book' }], [{ verb: 'x' }, { verb: 'air.book' }], [{ verb: '*', resource: 'nope' }, { verb: '*' }], [5, { verb: '*' }], [null, { verb: '*' }], [{ verb: 'x' }, 5], [{ verb: '*', where: [LEAFS[1]] }, { verb: '*', where: [LEAFS[0]] }], [{ verb: '*', where: [LEAFS[1]] }, { verb: '*', where: [LEAFS[2]] }]];
for (const l of PL) for (const ci of [0, 1, 6, 7, 8]) preds.push([l, ci, pr.evaluatePredicates(l, ctxsClean[ci]).allowed]);
const rePred = (re, res = 'air.book') => ({ verb: res, resource: `re:${re}` });
const budgetCtx = cidx({ action: { verb: 'air.book', resource: 'abc' } });
for (const n of [1, 63, 64, 65, 66, 100]) {
  preds.push([Array.from({ length: n }, () => rePred('x')).concat([rePred('abc')]), budgetCtx, pr.evaluatePredicates(Array.from({ length: n }, () => rePred('x')).concat([rePred('abc')]), ctxsClean[budgetCtx]).allowed]);
  const l2 = Array.from({ length: n }, () => ({ verb: '*', resource: 'nope' })).concat([rePred('abc')]); preds.push([l2, budgetCtx, pr.evaluatePredicates(l2, ctxsClean[budgetCtx]).allowed]);
}
const l3 = [...Array.from({ length: 64 }, () => rePred('x')), rePred('abc')]; preds.push([l3, budgetCtx, pr.evaluatePredicates(l3, ctxsClean[budgetCtx]).allowed]);
const l4 = [rePred('('), rePred('abc')]; preds.push([l4, budgetCtx, pr.evaluatePredicates(l4, ctxsClean[budgetCtx]).allowed]);
const l5 = [rePred('.'.repeat(200)), ...Array.from({ length: 45 }, () => rePred('.'.repeat(190))), rePred('abc')]; preds.push([l5, budgetCtx, pr.evaluatePredicates(l5, ctxsClean[budgetCtx]).allowed]);
const l6 = [...Array.from({ length: 70 }, () => ({ verb: '*', resource: '*', where: [mt('b', 'action.verb')] })), { verb: '*' }]; preds.push([l6, 0, pr.evaluatePredicates(l6, ctxsClean[0]).allowed]);
const l7 = [...Array.from({ length: 30 }, () => ({ verb: '*', resource: '*', where: [mt('b', 'action.verb')] })), ...Array.from({ length: 30 }, () => rePred('x')), ...Array.from({ length: 10 }, () => ({ verb: '*', where: [mt('air\\.book', 'action.verb')] }))]; preds.push([l7, 0, pr.evaluatePredicates(l7, ctxsClean[0]).allowed]);

const data = { ctxs: ctxsClean, rp, cond, pred, preds };
const json = JSON.stringify(data);
fs.writeFileSync(out, zlib.gzipSync(Buffer.from(json), { level: 9 }));
console.log(JSON.stringify({ ctxs: ctxsClean.length, rp: rp.length, cond: cond.length, pred: pred.length, preds: preds.length, bytes: json.length }));
