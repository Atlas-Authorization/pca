// k05 oracle: rule-14 action schemas, the v1 AND v2 document shape and the parameter value domain (Java ActionSchema and
// every native port). TS reference: packages/pca/src/action-schema.ts. Extends tools/pca-audit/java-mutate/k042-actionschema
// (v1-focused, targeted) with generated variants of a fully populated v2 schema and a fully populated v1 schema (every member
// deleted, retyped to every hostile scalar, strings at their byte limits, arrays reordered / duplicated / extended), the
// collection limits (verbs, params, values, traits, effects, tags, final_traits, dismissed, floors arrays, trait_defs), the
// parameter paths, and a decl x value grid of paramValueViolation over every type and every v2 format.
// Writes tools/pca-audit/k05-oracles/out/k05-actionschema.json.gz. Deterministic.
// PORTING (fn -> Java):
//   shape(doc)             ActionSchema.shapeError(doc)                   exact string | null ("malformed schema: canonicalize: ..." -> prefix only)
//   shapeUnsigned(doc)     ActionSchema.shapeError(doc, false)            same
//   confirmation(c)        ActionSchema.confirmationShapeError(c)          exact string | null
//   floors(f)              ActionSchema.schemaFloorsError(f)               exact string | null
//   pvv(d, x)              ActionSchema.paramValueViolation(d, x)          null | {code, reason}; four reasons carry the bound in TS only
//                          (longer than N UTF-8 bytes / below min N / above max N / strings of at most N UTF-8 bytes); {$throws} -> must throw
//   format(f, s)           ActionSchema.formatCheck(f)                     "unknown" when null, else the checker's boolean on s
import * as P from '../../../packages/pca/src/action-schema.ts';
import { Oracle, variants, seed } from './lib.mjs';

const pca: any = (P as any).actionSchemaShapeError ? P : (P as any).default;
const o = new Oracle('actionschema', 'tools/pca-audit/k05-oracles/actionschema-oracle.mts', 'TS-reference oracle for rule-14 action schemas: v1/v2 shape (generated variants, limits, paths), confirmation, floors, paramValueViolation over every type and format, formatCheck.');
const b64u = (u8: Uint8Array) => Buffer.from(u8).toString('base64url');
const D32 = b64u(seed('k05-actionschema/d32'));
const S64 = b64u(new Uint8Array([...seed('k05-actionschema/s1'), ...seed('k05-actionschema/s2')]));
const s = (n: number, ch = 'a') => ch.repeat(n);
const clone = (x: any) => JSON.parse(JSON.stringify(x));

const shape = (n: string, d: unknown) => o.run('shape', n, (x: unknown) => pca.actionSchemaShapeError(x), [d]);
const shapeU = (n: string, d: unknown) => o.run('shapeUnsigned', n, (x: unknown) => pca.actionSchemaShapeError(x, { signed: false }), [d]);
const conf = (n: string, c: unknown) => o.run('confirmation', n, pca.confirmationShapeError, [c]);
const flo = (n: string, f: unknown) => o.run('floors', n, pca.schemaFloorsError, [f]);

// ---- seeds ------------------------------------------------------------------------------------------------------------
const FLOORS = { risk: 1, rev: 'reversible', blast_ppm: 10, esc: 0, caveats: ['amount_cap', 'window'], context: ['idempotency', 'session_taint_max:abc'], prules: ['money_amount_bounded'] };
const CONF = { def_digest: D32, traits_digest: D32, facts_digest: D32, final_traits: ['money.pay'], dismissed: [{ trait: 'net.send', reason: 'r' }], reviewer_kid: 'rk', ts: 0, sig: S64 };
const PARAMS_V2: any = {
  'action.params.amount': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', unit: 'usd_cents', min: 0, max: 100, required: true, accumulates_into: ['spend.usd', 'b'], issued_by_site: false, description: 'd', role: 'amount', tags: ['pci', 'pii'], provenance_min: 'tool' },
  'action.params.to': { type: 'string', semantic: 'recipient', sensitivity: 'material', format: 'email', max_len: 64, values: ['a@b.co', 'c@d.co'] },
  'action.params.acct.id': { type: 'object_ref', semantic: 'r', sensitivity: 'free', format: 'id:acct' },
  'action.params.when': { type: 'datetime', semantic: 'w', sensitivity: 'free', required: false },
  'action.params.wait': { type: 'duration', semantic: 'w', sensitivity: 'free', min: 0, max: 1000 },
  'action.params.labels': { type: 'set', semantic: 'l', sensitivity: 'free', values: ['a', 'b'], min_items: 0, max_items: 2 },
  'action.params.list': { type: 'array', semantic: 'l', sensitivity: 'free', items: 'integer', min: 0, max: 5, min_items: 0, max_items: 3, default: [], principal_neutral_default: true },
  'action.params.flag': { type: 'boolean', semantic: 'f', sensitivity: 'free', default: false },
  'action.params.day': { type: 'date', semantic: 'd', sensitivity: 'free' },
};
const VERB_V2: any = {
  verb: 'pay.send', kind: 'write', params: PARAMS_V2,
  reversibility: 'reversible', reversibility_by: { param: 'action.params.flag', map: { true: 'irreversible', false: 'rate_limited' }, default: 'reversible' },
  mcp: { tool: 't' }, openapi: { operationId: 'op' }, harm: {}, returns: {}, world: [], description: 'x',
  effects: ['pay', 'send'], traits: ['money.pay', 'net.send'], def: D32, floors: FLOORS, confirmation: CONF,
};
const READ_V2: any = { verb: 'x.read', kind: 'read', params: {}, effects: ['read'], traits: [], def: D32, floors: { risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] } };
const V2: any = {
  v: 2, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '2',
  units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 }, count: { kind: 'count' } },
  state: [], traits_digest: D32, trait_defs: [{}], pack: { ns: 'acme', version: '1', root: D32 },
  verbs: [VERB_V2, READ_V2],
  sig: { alg: 'ed25519', kid: 'k1', value: 'AA' },
};
const PARAMS_V1: any = {
  'action.params.total': { type: 'integer', semantic: 'money.amount', sensitivity: 'critical', unit: 'usd_cents', min: 0, max: 100, required: true, accumulates_into: ['spend'], issued_by_site: true, description: 'd' },
  'action.params.name': { type: 'string', semantic: 'n', sensitivity: 'free', values: ['x', 'y'], max_len: 8, default: 'x', principal_neutral_default: true },
  'action.params.tags': { type: 'set', semantic: 't', sensitivity: 'material', values: ['a', 'b'], min_items: 1, max_items: 2 },
  'action.params.ids': { type: 'array', semantic: 'i', sensitivity: 'free', items: 'string', max_items: 4 },
  'action.params.ok': { type: 'boolean', semantic: 'o', sensitivity: 'free', required: false },
};
const V1: any = {
  v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1',
  units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } }, state: [],
  verbs: [{ verb: 'a.b', kind: 'write', params: PARAMS_V1, reversibility: 'irreversible', reversibility_by: { param: 'action.params.name', map: { x: 'reversible' } }, mcp: { tool: 't' }, openapi: { operationId: 'o' }, harm: {}, effects: {}, returns: {}, world: [], description: 'x' },
    { verb: 'r.x', kind: 'read', params: {} }],
  sig: { alg: 'ed25519', kid: 'k1', value: 'AA', pq_value: 'AA' },
};
for (const [n, d] of [['v2', V2], ['v1', V1]] as const) if (pca.actionSchemaShapeError(d) !== null) throw new Error(`seed ${n} invalid: ${pca.actionSchemaShapeError(d)}`);
if (pca.confirmationShapeError(CONF) !== null || pca.schemaFloorsError(FLOORS) !== null) throw new Error('seed confirmation/floors invalid');

// ---- generated variants -----------------------------------------------------------------------------------------------
const LENS = [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 2047, 2048, 2049];
for (const [n, d] of variants(V2, { lens: LENS, depth: 7 })) await shape('v2 ' + n, d);
for (const [n, d] of variants(V1, { lens: LENS, depth: 6 })) await shape('v1 ' + n, d);
await shapeU('v2 unsigned with sig', V2);
await shapeU('v1 unsigned with sig', V1);
for (const [n, d] of [['v2', V2], ['v1', V1]] as const) {
  const u = clone(d);
  delete u.sig;
  await shapeU(n + ' unsigned', u);
  await shapeU(n + ' unsigned bad verbs', { ...u, verbs: [] });
  await shape(n + ' signed without sig', u);
}
for (const [n, c] of variants(CONF, { lens: [0, 1, 127, 128, 129, 255, 256, 257] })) await conf(n, c);
for (const [n, f] of variants(FLOORS)) await flo(n, f);
await conf('not object', []);
await flo('not object', 'x');

// multibyte strings crossing their byte limits, and lone surrogates, at every bounded string
const mb = (n: number) => s(n - 1) + 'é'; // n+1 bytes, n characters
const set = (base: any, f: (d: any) => void) => { const d = clone(base); f(d); return d; };
const STR_SITES: [string, number, (d: any, v: string) => void][] = [
  ['site', 2048, (d, v) => { d.site = v; }], ['aud', 256, (d, v) => { d.aud = v; }], ['version', 128, (d, v) => { d.version = v; }],
  ['unit kind', 64, (d, v) => { d.units.count.kind = v; }], ['unit currency', 16, (d, v) => { d.units.usd_cents.currency = v; }],
  ['pack ns', 64, (d, v) => { d.pack.ns = v; }], ['pack version', 128, (d, v) => { d.pack.version = v; }],
  ['verb', 128, (d, v) => { d.verbs[0].verb = v; }], ['verb description', 1024, (d, v) => { d.verbs[0].description = v; }],
  ['mcp tool', 128, (d, v) => { d.verbs[0].mcp.tool = v; }], ['openapi', 128, (d, v) => { d.verbs[0].openapi.operationId = v; }],
  ['semantic', 128, (d, v) => { d.verbs[0].params['action.params.amount'].semantic = v; }],
  ['param description', 1024, (d, v) => { d.verbs[0].params['action.params.amount'].description = v; }],
  ['role', 128, (d, v) => { d.verbs[0].params['action.params.amount'].role = v; }],
  ['items', 64, (d, v) => { d.verbs[0].params['action.params.list'].items = v; }],
  ['value', 256, (d, v) => { d.verbs[0].params['action.params.to'].values = [v]; }],
  ['reviewer_kid', 128, (d, v) => { d.verbs[0].confirmation.reviewer_kid = v; }],
  ['dismissed reason', 256, (d, v) => { d.verbs[0].confirmation.dismissed[0].reason = v; }],
  ['sig kid', 128, (d, v) => { d.sig.kid = v; }],
];
for (const [n, max, f] of STR_SITES) {
  await shape(`str ${n} ${max} mb`, set(V2, (d) => f(d, mb(max))));
  await shape(`str ${n} ${max} ascii`, set(V2, (d) => f(d, s(max))));
  await shape(`str ${n} ${max + 1} ascii`, set(V2, (d) => f(d, s(max + 1))));
  await shape(`str ${n} lone`, set(V2, (d) => f(d, 'a\ud800')));
  await shape(`str ${n} empty`, set(V2, (d) => f(d, '')));
}

// ---- collection limits ------------------------------------------------------------------------------------------------
const tid = (i: number) => `t.a${String(i).padStart(3, '0')}`;
const verbN = (i: number) => ({ ...clone(READ_V2), verb: `v${i}` });
for (const n of [255, 256, 257]) await shape(`verbs ${n}`, set(V2, (d) => { d.verbs = Array.from({ length: n }, (_, i) => verbN(i)); }));
const pdecl = { type: 'boolean', semantic: 's', sensitivity: 'free' };
for (const n of [63, 64, 65]) await shape(`params ${n}`, set(V2, (d) => { d.verbs[1].params = Object.fromEntries(Array.from({ length: n }, (_, i) => [`action.params.p${i}`, pdecl])); }));
for (const n of [255, 256, 257]) await shape(`values ${n}`, set(V2, (d) => { d.verbs[0].params['action.params.to'].values = Array.from({ length: n }, (_, i) => `v${i}`); }));
for (const n of [63, 64, 65]) {
  await shape(`traits ${n}`, set(V2, (d) => { d.verbs[0].traits = Array.from({ length: n }, (_, i) => tid(i)); }));
  await shape(`trait_defs ${n}`, set(V2, (d) => { d.trait_defs = Array.from({ length: n }, () => ({})); }));
  await conf(`final_traits ${n}`, { ...CONF, final_traits: Array.from({ length: n }, (_, i) => tid(i)) });
  await conf(`dismissed ${n}`, { ...CONF, dismissed: Array.from({ length: n }, (_, i) => ({ trait: tid(i), reason: 'r' })) });
  for (const k of ['caveats', 'context', 'prules']) await flo(`${k} ${n}`, { ...FLOORS, [k]: Array.from({ length: n }, () => ({ caveats: 'window', context: 'idempotency', prules: 'array_bounded' } as any)[k]) });
}
const EFF = ['create', 'delete', 'exec', 'export', 'pay', 'privilege', 'provision', 'publish', 'read', 'send', 'sign', 'update'];
await shape('effects all 12 write', set(V2, (d) => { d.verbs[0].effects = EFF; }));
await shape('effects 13', set(V2, (d) => { d.verbs[0].effects = [...EFF, 'update']; }));
await shape('effects unsorted', set(V2, (d) => { d.verbs[0].effects = ['send', 'pay']; }));
await shape('effects dup', set(V2, (d) => { d.verbs[0].effects = ['pay', 'pay']; }));
await shape('effects read on write', set(V2, (d) => { d.verbs[0].effects = ['read']; }));
await shape('effects read+send on read', set(V2, (d) => { d.verbs[1].effects = ['read', 'send']; }));
await shape('effects read read on read', set(V2, (d) => { d.verbs[1].effects = ['read', 'read']; }));
await shape('effects unknown', set(V2, (d) => { d.verbs[0].effects = ['pay', 'zz']; }));
await shape('tags all 9', set(V2, (d) => { d.verbs[0].params['action.params.amount'].tags = ['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql']; }));
await shape('tags 10', set(V2, (d) => { d.verbs[0].params['action.params.amount'].tags = ['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql', 'pii']; }));
await shape('tags dup', set(V2, (d) => { d.verbs[0].params['action.params.amount'].tags = ['pii', 'pii']; }));
for (const n of [7, 8, 9]) await shape(`accumulates ${n}`, set(V2, (d) => { d.verbs[0].params['action.params.amount'].accumulates_into = Array.from({ length: n }, (_, i) => `u${i}`); }));
for (const u of [s(64), s(65), 'A', 'a.b', 'a..b', '.a', 'a.', '', 'é']) await shape(`accumulates entry ${u.length} ${u.slice(0, 3)}`, set(V2, (d) => { d.verbs[0].params['action.params.amount'].accumulates_into = [u]; }));
for (const e of [17, 18, 19, -1]) await shape(`exponent ${e}`, set(V2, (d) => { d.units.usd_cents.exponent = e; }));
for (const id of [s(64), s(65), 'a.b', 'A', 'a-b', '']) await shape(`unit id ${id.length} ${id.slice(0, 3)}`, set(V2, (d) => { d.units[id] = { kind: 'k' }; }));
await shape('unit unknown member', set(V2, (d) => { d.units.count.zz = 1; }));
await shape('unit kind missing', set(V2, (d) => { delete d.units.count.kind; }));
for (const b of [-1, 0, 1_000_000, 1_000_001]) await flo(`blast ${b}`, { ...FLOORS, blast_ppm: b });
for (const r of [-1, 0, 3, 4]) { await flo(`risk ${r}`, { ...FLOORS, risk: r }); await flo(`esc ${r}`, { ...FLOORS, esc: r }); }
for (const c of ['session_taint_max:a', 'session_taint_max:' + s(16), 'session_taint_max:' + s(17), 'session_taint_max:', 'session_taint_max:A', 'approval_ref', 'zz'])
  await flo(`context ${c}`, { ...FLOORS, context: [c] });
for (const k of ['caveats', 'context', 'prules']) await flo(`${k} reversed`, { ...FLOORS, [k]: [...(FLOORS as any)[k]].reverse() });
await flo('caveats dup', { ...FLOORS, caveats: ['window', 'window'] });

// ---- parameter paths --------------------------------------------------------------------------------------------------
const paths = ['action.params.' + s(64), 'action.params.' + s(65), 'action.params.', 'action.params.a-b', 'action.params.a.b', 'action.params.a.b.c', 'action.params.a.b.c.d',
  'action.params.a.' + s(64), 'action.params.a.' + s(65), 'action.params.a..b', 'params.a', 'action.params.__proto__', 'action.params.constructor', 'action.params.prototype',
  'action.params.a.prototype', 'action.params.a.constructor.b', 'action.params.é', 'action.params.a.'];
for (const p of paths)
  for (const [n, base] of [['v2', V2], ['v1', V1]] as const) {
    const d = clone(base);
    d.verbs[1].params = JSON.parse(JSON.stringify({ [p]: pdecl }));
    await shape(`path ${n} ${p.length} ${p.slice(14, 30)}`, d);
  }
await shape('v2 parent and child', set(V2, (d) => { d.verbs[1].params = { 'action.params.a': pdecl, 'action.params.a.b': pdecl }; }));
await shape('v2 child then parent', set(V2, (d) => { d.verbs[1].params = { 'action.params.a.b': pdecl, 'action.params.a': pdecl }; }));
await shape('v2 sibling prefix', set(V2, (d) => { d.verbs[1].params = { 'action.params.a': pdecl, 'action.params.ab': pdecl }; }));
await shape('verb twice', set(V2, (d) => { d.verbs = [READ_V2, READ_V2]; }));

// ---- declaration rules by type (v2 and v1) ----------------------------------------------------------------------------
const TYPES = ['string', 'integer', 'boolean', 'date', 'set', 'array', 'datetime', 'duration', 'object_ref', 'zz'];
const EXTRA: [string, any][] = [
  ['values', { values: ['a'] }], ['min', { min: 1 }], ['max', { max: 1 }], ['min max', { min: 2, max: 1 }], ['min=max', { min: 1, max: 1 }],
  ['unit', { unit: 'usd_cents' }], ['unit unknown', { unit: 'zz' }], ['unit number', { unit: 1 }], ['max_len 0', { max_len: 0 }], ['max_len 1', { max_len: 1 }],
  ['max_len 1.5', { max_len: 1.5 }], ['items integer', { items: 'integer' }], ['items string', { items: 'string' }], ['items 65', { items: s(65) }],
  ['min_items 1', { min_items: 1 }], ['max_items 0', { max_items: 0 }], ['items order', { min_items: 2, max_items: 1 }], ['min_items -1', { min_items: -1 }],
  ['default null', { default: null }], ['default', { default: 1 }], ['pnd', { principal_neutral_default: true }], ['pnd+default', { principal_neutral_default: true, default: 'x' }],
  ['pnd false', { principal_neutral_default: false }], ['pnd string', { principal_neutral_default: 'true' }], ['acc', { accumulates_into: ['a'] }],
  ['format email', { format: 'email' }], ['format id', { format: 'id:x' }], ['format unknown', { format: 'zz' }], ['format number', { format: 1 }],
  ['tags', { tags: ['pii'] }], ['tags unknown', { tags: ['zz'] }], ['tags string', { tags: 'pii' }], ['provenance', { provenance_min: 'agent' }], ['provenance unknown', { provenance_min: 'zz' }],
  ['role', { role: 'r' }], ['role empty', { role: '' }], ['issued', { issued_by_site: 1 }], ['required', { required: 'yes' }], ['values empty', { values: [] }],
  ['values dup', { values: ['a', 'a'] }], ['values number', { values: [1] }], ['set+values items', { values: ['a'], items: 'integer' }],
];
for (const t of TYPES)
  for (const [n, extra] of EXTRA)
    for (const [vn, base] of [['v2', V2], ['v1', V1]] as const) {
      const d = clone(base);
      d.verbs[1].params = { 'action.params.p': { type: t, semantic: 's', sensitivity: 'free', ...(t === 'set' && !('values' in extra) ? { values: ['a'] } : {}), ...extra } };
      await shape(`decl ${vn} ${t} ${n}`, d);
    }

// ---- reversibility_by -------------------------------------------------------------------------------------------------
const RB: [string, any][] = [['not object', 'x'], ['unknown key', { param: 'action.params.flag', map: { a: 'reversible' }, zz: 1 }], ['param missing', { map: { a: 'reversible' } }],
  ['param undeclared', { param: 'action.params.zz', map: { a: 'reversible' } }], ['param number', { param: 1, map: { a: 'reversible' } }], ['map empty', { param: 'action.params.flag', map: {} }],
  ['map array', { param: 'action.params.flag', map: [] }], ['map bad class', { param: 'action.params.flag', map: { a: 'zz' } }], ['map second bad', { param: 'action.params.flag', map: { a: 'reversible', b: 'zz' } }],
  ['default bad', { param: 'action.params.flag', map: { a: 'reversible' }, default: 'zz' }], ['default ok', { param: 'action.params.flag', map: { a: 'reversible' }, default: 'irreversible' }],
  ['only param', { param: 'action.params.flag' }]];
for (const [n, r] of RB) await shape(`rb ${n}`, set(V2, (d) => { d.verbs[0].reversibility_by = r; }));
for (const [k, val] of [['mcp', { tool: 't', x: 1 }], ['mcp', {}], ['mcp', { tool: '' }], ['openapi', { operationId: 'o', x: 1 }], ['openapi', { tool: 'o' }], ['openapi', []]] as const)
  await shape(`${k} ${JSON.stringify(val)}`, set(V2, (d) => { d.verbs[0][k] = val; }));
for (const k of ['harm', 'returns', 'effects', 'world'])
  for (const val of [[], {}, 'x', null]) {
    await shape(`v1 ${k} ${JSON.stringify(val)}`, set(V1, (d) => { d.verbs[0][k] = val; }));
    if (k !== 'effects') await shape(`v2 ${k} ${JSON.stringify(val)}`, set(V2, (d) => { d.verbs[0][k] = val; }));
  }
for (const [n, pk] of [['extra', { ns: 'a', version: '1', root: D32, x: 1 }], ['missing', { ns: 'a', version: '1' }], ['root short', { ns: 'a', version: '1', root: 'AA' }],
  ['ns 65', { ns: s(65), version: '1', root: D32 }], ['version 129', { ns: 'a', version: s(129), root: D32 }], ['array', []]] as const)
  await shape(`pack ${n}`, set(V2, (d) => { d.pack = pk; }));

// ---- paramValueViolation grid -----------------------------------------------------------------------------------------
const pvv = (n: string, d: unknown, x: unknown) => o.run('pvv', n, pca.paramValueViolation, [d, x]);
const DECLS: [string, any][] = [
  ['string', { type: 'string' }], ['string len3', { type: 'string', max_len: 3 }], ['string values', { type: 'string', values: ['a', 'é'] }],
  ['string email', { type: 'string', format: 'email' }], ['string len1 uuid', { type: 'string', max_len: 1, format: 'uuid' }], ['string format num', { type: 'string', format: 5 }],
  ['string format unknown', { type: 'string', format: 'zz' }], ['string values+format', { type: 'string', values: ['a@b.co', 'x'], format: 'email' }],
  ['object_ref', { type: 'object_ref' }], ['object_ref len3', { type: 'object_ref', max_len: 3 }], ['object_ref id', { type: 'object_ref', format: 'id:acct' }],
  ['datetime', { type: 'datetime' }], ['duration', { type: 'duration' }], ['duration 5..10', { type: 'duration', min: 5, max: 10 }],
  ['integer', { type: 'integer' }], ['integer -5..5', { type: 'integer', min: -5, max: 5 }], ['integer min0', { type: 'integer', min: 0 }], ['integer max0', { type: 'integer', max: 0 }],
  ['boolean', { type: 'boolean' }], ['date', { type: 'date' }],
  ['set', { type: 'set', values: ['a', 'b', 'c'] }], ['set 1..2', { type: 'set', values: ['a', 'b', 'c'], min_items: 1, max_items: 2 }], ['set max0', { type: 'set', values: ['a'], max_items: 0 }],
  ['array', { type: 'array' }], ['array len2', { type: 'array', max_len: 2 }], ['array int', { type: 'array', items: 'integer' }], ['array int 0..3', { type: 'array', items: 'integer', min: 0, max: 3 }],
  ['array 1..2', { type: 'array', min_items: 1, max_items: 2 }], ['array min2', { type: 'array', min_items: 2 }], ['array max0', { type: 'array', max_items: 0 }],
  ['unknown', { type: 'zz' }], ['no type', {}],
];
const VALUES: unknown[] = [
  '', 'a', 'b', 'é', 'ab', 'abc', 'abcd', 'éé', 'a\ud800', '\udc00', 'a@b.co', 'x', s(1024), s(1025), mb(1024),
  0, -0, 1, -1, 3, 4, 5, 6, 10, 11, -5, -6, 1.5, 2 ** 53, 2 ** 53 - 1, -(2 ** 53 - 1), true, false, null, {},
  [], ['a'], ['a', 'a'], ['a', 'b'], ['b', 'a'], ['a', 'b', 'c'], ['d'], ['a', 1], [1], [0, 3], [4], [-1], [1, 2, 3], [1.5], [-0], ['ab', 'abc'], ['é'], ['a\ud800'], [null],
  '2024-02-29', '2023-02-29', '1900-02-29', '2000-02-29', '0000-01-01', '0001-01-01', '2024-13-01', '2024-12-31', '2024-00-10', '2024-04-31', '2024-04-30', '2024-01-00', '2024-1-01', '2024-02-30',
  '2024-02-29T23:59:59Z', '2024-02-29T24:00:00Z', '2024-02-29T23:60:00Z', '2024-02-29T23:59:60Z', '2024-02-29T23:59:59.1234Z', '2024-02-29T23:59:59.123Z', '2024-02-29T23:59:59.Z',
  '2023-02-29T00:00:00Z', '2024-01-01T00:00:00+00:00', '2024-01-01t00:00:00Z', '2024-01-01T19:00:00Z', '2024-01-01T20:00:00Z', '2024-13-01T00:00:00Z',
  'id-1:a.b', 'a b', '3fa85f64-5717-4562-b3fc-2c963f66afa6',
];
for (const [dn, d] of DECLS) for (const [i, x] of VALUES.entries()) await pvv(`${dn} #${i}`, d, x);

// ---- formats ----------------------------------------------------------------------------------------------------------
const lbl = (n: number) => s(n, 'b');
const FORMAT_VALUES: Record<string, string[]> = {
  email: ['a@b.co', 'a@b', '@b.co', 'a@.co', s(64) + '@b.co', s(65) + '@b.co', 'a@' + lbl(63) + '.co', 'a@' + lbl(64) + '.co', 'a b@c.d', 'a@b..c', 'a.b%+-_@x-y.z.w',
    s(64) + '@' + [lbl(63), lbl(63), lbl(60)].join('.'), s(64) + '@' + [lbl(63), lbl(63), lbl(61)].join('.'), s(64) + '@' + [lbl(63), lbl(63), lbl(62)].join('.'), 'a@b.c_', 'é@b.co'],
  url: ['h://x', 'https://x/y', 'ab+.-c://x', s(32, 'h') + '://x', s(33, 'h') + '://x', '1h://x', 'h://', 'h:// x', 'h://x y', 'h://x\u00a0', 'h://?x', 'h://x\u2028y', 'h://x/\u3000', 'h:/x', 'h://x\ufeff', 'h://#'],
  uri_https: ['https://x', 'http://x', 'https://', 'https:// ', 'https://x/ y', 'https://#', 'HTTPS://x', 'https://x?q=1#f', 'https://x\t'],
  uuid: ['3fa85f64-5717-4562-b3fc-2c963f66afa6', '3FA85F64-5717-4562-B3FC-2C963F66AFA6', '3fa85f64-5717-4562-b3fc-2c963f66afa', '3fa85f645717-4562-b3fc-2c963f66afa6', 'g' + '3fa85f64-5717-4562-b3fc-2c963f66afa'.slice(0)],
  iban: ['GB82WEST12345698765432', 'GB83WEST12345698765432', 'DE89370400440532013000', 'DE89370400440532013001', 'gb82WEST12345698765432', 'GB82west12345698765432', 'GB82WEST1234', 'GB8WEST12345698765432',
    'NO9386011117947', 'NO938601111794', 'MT84MALT011000012345MTLCAST001S', 'LC55HEMM000100010012001200023015', 'XX00' + s(30, '1'), 'XX00' + s(31, '1'), 'AL47212110090000000235698741', '0B82WEST12345698765432', 'GB82WEST1234569876543Z'],
  phone_e164: ['+1234567', '+123456', '+0123456', '+123456789012345', '+1234567890123456', '1234567', '+12 34567', '+١٢٣٤٥٦٧'],
  cidr: ['0.0.0.0/0', '255.255.255.255/32', '256.0.0.0/8', '1.256.0.0/8', '1.2.256.0/8', '1.2.3.256/8', '01.0.0.0/8', '1.02.0.0/8', '1.2.003.4/8', '1.2.3.04/8', '1.2.3.4/33', '1.2.3.4/032', '1.2.3.4/08',
    '1.2.3.4/8', '1.2.3.4/0', '1.2.3.4/00', '1.2.3.4', '1.2.3/8', '::/0', '::1/128', '::1/129', '::1/0128', 'fe80::/10', ':::/8', '1:2/64', '1/64', '1:2:3:4:5:6:7:8/64', '::/00', '::/1', 'a:b/01',
    '::/8x', 'a:b:c/64', 'a::b::c/64', 'g::/8', 'A:B::/16', ':/8', '::/', s(39, ':') + '/8', '1:' + s(38, '1') + '/8', '1:' + s(37, '1') + '/8', '1.2.3.4/32', '999.2.3.4/8', '255.255.255.255/33'],
  iso_country: ['US', 'us', 'USA', 'U', 'É1'],
  iso_currency: ['USD', 'US', 'usd', 'USDD'],
  semver: ['1.2.3', '0.0.0', '01.2.3', '1.02.3', '1.2.03', '1.2', '1.2.3-alpha.1+b.2', '1.2.3-', '1.2.3+', '1.2.3-a..b', '1.2.3+a.b', '10.20.30-rc-1', '1.2.3.4'],
  sha256: [s(64, 'a'), s(63, 'a'), s(65, 'a'), s(64, 'A'), s(63, 'a') + 'g'],
  'id:acct': ['a', '', s(128), s(129), 'a b', 'a/b', 'A-z._:9', 'é'],
};
const FORMATS = [...Object.keys(FORMAT_VALUES), 'id:a.b.c.d', 'id:a.b.c.d.e', 'id:', 'id:A', 'id:a_b', 'zz', '__proto__', 'toString', 'constructor', 'hasOwnProperty', 'Email', ''];
const fmt = (n: string, f: string, x: string) => o.run('format', n, (ff: string, xx: string) => { const ck = pca.formatCheck(ff); return ck === null ? 'unknown' : ck(xx); }, [f, x]);
const ALL_STRINGS = [...new Set(Object.values(FORMAT_VALUES).flat())];
for (const f of FORMATS) {
  const xs = Object.hasOwn(FORMAT_VALUES, f) ? FORMAT_VALUES[f]! : ['a', 'a@b.co'];
  for (const [i, x] of xs.entries()) {
    await fmt(`${f} #${i}`, f, x);
    await pvv(`fmt string ${f} #${i}`, { type: 'string', format: f }, x);
    await pvv(`fmt ref ${f} #${i}`, { type: 'object_ref', format: f }, x);
  }
}
// every format over every format's sample strings (cross-checks): booleans only
for (const f of Object.keys(FORMAT_VALUES)) for (const [i, x] of ALL_STRINGS.entries()) await fmt(`${f} x#${i}`, f, x);

o.write();
