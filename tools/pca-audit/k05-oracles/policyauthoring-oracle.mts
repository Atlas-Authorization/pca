// k05 oracle: forbid-wins certificate table check and linked policy templates (Java PolicyAuthoring and every native port).
// TS reference: packages/pca/src/forbid-certificate.ts (certificateConsistent) and packages/pca/src/policy-link.ts.
// Generated: every member of a template definition / slot object / reference / overlay deleted, retyped and at its limit;
// templates and overlays RE-SIGNED after the change (so the check after the signature is reached); a slot-value grid per type;
// every splice and matcher-injection rule; registries with 0..3 matching overlays and bound parameter objects; random forbid
// certificate tables (the consistent certificate and every single-field corruption of it) under several signer precedences.
// Writes tools/pca-audit/k05-oracles/out/k05-policyauthoring.json.gz. Deterministic (Ed25519).
// PORTING (fn -> Java):
//   templateDef(def)          PolicyAuthoring.templateDefError(def)        exact string | null
//   tighten(o)                PolicyAuthoring.tightenOverlayError(o)       exact string | null
//   templateRef(r)            PolicyAuthoring.templateRefError(r)          exact string | null
//   verifyTemplate(t, trusted) / verifyTighten(t, trusted)   null when {ok:true} else the reason; "(fail closed)" reasons -> any refusal
//   instantiate(def, slots)   PolicyAuthoring.instantiateTemplate          {ok:true, policy} -> policy (canonical JSON); else reason
//   resolve(ref, reg)         PolicyAuthoring.resolveLink                  {ok:true, policy, overlays} exact; else reason ("(fail closed)" -> any refusal)
//   forbid(cert, precedence)  PolicyAuthoring.forbidCertificateConsistent  out = {ok, typed}: typed (rows are objects with string
//                             id / kind / value, winner an object, shadowed an array) -> exact; untyped -> Java must be false
import * as L from '../../../packages/pca/src/policy-link.ts';
import * as F from '../../../packages/pca/src/forbid-certificate.ts';
import { b64u, hashCanonical, sha256, utf8 } from '../../../packages/pca/src/hash.ts';
import { publicKeyOf, sign } from '../../../packages/pca/src/keys.ts';
import { Oracle, variants, seed, rng, clone } from './lib.mjs';

const pl: any = (L as any).resolveLink ? L : (L as any).default;
const fc: any = (F as any).certificateConsistent ? F : (F as any).default;
const o = new Oracle('policyauthoring', 'tools/pca-audit/k05-oracles/policyauthoring-oracle.mts', 'TS-reference oracle for the forbid-wins certificate table and linked policy templates: definition / slot / reference / overlay variants (re-signed), slot grids, splice rules, registries with overlays and bound parameters, random certificate tables.');
const ORG = seed('k05-policy-org');
const OTHER = seed('k05-policy-other');
const ORGK = b64u(publicKeyOf(ORG));
const OTHERK = b64u(publicKeyOf(OTHER));
const TRUSTED = [ORGK];

const domainSig = (secret: Uint8Array, domain: string, value: unknown): string => {
  try {
    const pre = utf8(domain);
    const d = sha256(utf8(hashCanonical(value)));
    const m = new Uint8Array(pre.length + d.length);
    m.set(pre);
    m.set(d, pre.length);
    return b64u(sign(secret, m));
  } catch {
    return 'AA';
  }
};
const signT = (def: unknown, key = ORG, signer = ORGK) => ({ def, signer, sig: domainSig(key, pl.TEMPLATE_SIG_DOMAIN, def) });
const signO = (overlay: unknown, key = ORG, signer = ORGK) => ({ overlay, signer, sig: domainSig(key, pl.TIGHTEN_SIG_DOMAIN, overlay) });
const digest = (x: unknown) => { try { return hashCanonical(x); } catch { return 'undigestable'; } };

const DEF: any = {
  v: 1, kind: 'pca-policy-template', id: 'refund_tpl', version: '1.0.0',
  slots: {
    acct: { type: 'string' },
    limit: { type: 'integer', min: 1, max: 5000 },
    verbs: { type: 'set', values: ['list', 'read', 'refund'] },
    region: { type: 'string', values: ['eu', 'us'] },
  },
  body: {
    predicates: [
      { verb: { $slot: 'verbs' }, resource: { $slot: 'acct', pre: '/acct/', post: '/*' }, where: [{ field: 'amount', op: 'le', value: { $slot: 'limit' } }] },
      { verb: 'read', resource: { $slot: 'region' } },
    ],
    caveats: [{ type: 'region', value: { $slot: 'region' } }],
  },
};
const SLOTS: any = { acct: '42', limit: 100, verbs: ['read', 'refund'], region: 'eu' };
const D0 = digest(DEF);
const REF: any = { template_id: 'refund_tpl', version_digest: D0, slots: SLOTS };
const OV: any = { v: 1, kind: 'pca-template-tighten', template_id: 'refund_tpl', version_digest: D0, add_where: [{ field: 'country', op: 'eq', value: 'DE' }], add_caveats: [{ type: 'ttl', value: 60 }] };
const OV2: any = { v: 1, kind: 'pca-template-tighten', template_id: 'refund_tpl', version_digest: D0, add_where: [{ field: 'hour', op: 'lt', value: 18 }] };
const OV3: any = { v: 1, kind: 'pca-template-tighten', template_id: 'refund_tpl', version_digest: D0, add_caveats: [{ type: 'audit' }] };
const OVX: any = { ...OV, version_digest: digest({ other: 1 }) };
const REG = (x: any = {}) => ({ templates: { [D0]: signT(DEF) }, overlays: [signO(OV), signO(OVX)], trusted: TRUSTED, ...x });

const vt = (t: unknown, trusted: string[]) => { const r = pl.verifyTemplate(t, trusted); return r.ok ? null : r.reason; };
const vo = (t: unknown, trusted: string[]) => { const r = pl.verifyTighten(t, trusted); return r.ok ? null : r.reason; };
const LENS = [0, 1, 63, 64, 65, 127, 128, 129, 256, 257];

// ---- definitions ---------------------------------------------------------------------------------------------------------
for (const [n, v] of variants(DEF, { lens: LENS, depth: 6 })) {
  await o.run('templateDef', n, pl.templateDefError, [v]);
  await o.run('instantiate', 'def ' + n, pl.instantiateTemplate, [v, SLOTS]);
  await o.run('verifyTemplate', 'def ' + n, vt, [{ def: v, signer: ORGK, sig: signT(DEF).sig }, TRUSTED]);
  await o.run('verifyTemplate', 'def resigned ' + n, vt, [signT(v), TRUSTED]);
  // the re-signed variant registered under its own digest: the path past the signature check
  const d = digest(v);
  await o.run('resolve', 'def ' + n, pl.resolveLink, [{ ...REF, version_digest: d === 'undigestable' ? D0 : d }, { templates: { [d === 'undigestable' ? D0 : d]: signT(v) }, trusted: TRUSTED }]);
}
const withSlots = (k: number, f: (i: number) => any = () => ({ type: 'string' })) => {
  const slots: any = {};
  const preds: any[] = [];
  for (let i = 0; i < k; i++) { slots['s' + i] = f(i); preds.push({ verb: 'v', resource: { $slot: 's' + i, pre: '/r/' } }); }
  return { ...DEF, slots, body: { predicates: preds } };
};
for (const k of [0, 1, 31, 32, 33]) await o.run('templateDef', `${k} slots`, pl.templateDefError, [withSlots(k)]);
for (const k of [0, 1, 63, 64, 65]) {
  const def = withSlots(1, () => ({ type: 'set', values: Array.from({ length: k }, (_, i) => 'v' + i) }));
  await o.run('templateDef', `set of ${k} values`, pl.templateDefError, [def]);
}
const bodyDef = (body: any, slots: any = { a: { type: 'string' } }) => ({ ...DEF, slots, body });
const P = (x: any) => ({ predicates: [x] });
const BODIES: [string, any][] = [
  ['ok', P({ verb: 'v', resource: { $slot: 'a' } })],
  ['unused', P({ verb: 'v', resource: 'r' })],
  ['unknown member', P({ resource: { $slot: 'a', zz: 1 } })],
  ['unknown member after pre', P({ resource: { pre: 'x', $slot: 'a', yy: 1, zz: 2 } })],
  ['pre number', P({ resource: { $slot: 'a', pre: 1 } })],
  ['post null', P({ resource: { $slot: 'a', post: null } })],
  ['pre null post number', P({ resource: { $slot: 'a', pre: null, post: 2 } })],
  ['in caveats only', { predicates: [], caveats: [{ type: 't', value: { $slot: 'a' } }] }],
  ['caveats null', { predicates: [{ resource: { $slot: 'a' } }], caveats: null }],
  ['caveats object', { predicates: [{ resource: { $slot: 'a' } }], caveats: {} }],
  ['nested arrays', P({ where: [[{ value: [{ $slot: 'a' }] }]] })],
  ['slot in second predicate', { predicates: [{ verb: 'v' }, { resource: { $slot: 'a' } }] }],
];
for (const name of [null, true, false, 0, -0, 1, -1, 1.5, 2 ** 53, 1e21, 1e-7, 123e-20, '', 'b', 'é', [], [null], ['x'], ['x', 'y'], [1, null, 'z'], [[1, 2], 3], {}, { x: 1 }])
  BODIES.push([`undeclared ${Object.is(name, -0) ? '-0' : JSON.stringify(name)}`, P({ resource: { $slot: name } })]);
for (const [n, b] of BODIES) {
  await o.run('templateDef', 'body ' + n, pl.templateDefError, [bodyDef(b)]);
  await o.run('instantiate', 'body ' + n, pl.instantiateTemplate, [bodyDef(b), { a: 'x' }]);
}
// forbidden keys (own "__proto__" only survives through JSON.parse)
for (const [n, txt] of [
  ['__proto__ top', '{"predicates":[],"__proto__":{"$slot":"a"}}'],
  ['__proto__ in predicate', '{"predicates":[{"resource":{"$slot":"a"},"__proto__":1}]}'],
  ['constructor', '{"predicates":[{"constructor":{"$slot":"a"}}]}'],
  ['prototype in placeholder', '{"predicates":[{"resource":{"$slot":"a","prototype":1}}]}'],
  ['prototype deep', '{"predicates":[{"where":[{"x":{"prototype":2}}],"resource":{"$slot":"a"}}]}'],
  ['constructor after slot', '{"predicates":[{"resource":{"$slot":"a"}},{"constructor":0}]}'],
] as const) await o.run('templateDef', 'body ' + n, pl.templateDefError, [bodyDef(JSON.parse(txt))]);
// slot declarations
for (const [n, d] of [
  ['string', { type: 'string' }], ['integer', { type: 'integer' }], ['set no values', { type: 'set' }], ['set values null', { type: 'set', values: null }],
  ['set', { type: 'set', values: ['a'] }], ['string values null', { type: 'string', values: null }], ['string values', { type: 'string', values: ['a'] }],
  ['values numbers', { type: 'string', values: [1] }], ['values mixed', { type: 'set', values: ['a', 1] }], ['values object', { type: 'string', values: {} }],
  ['integer min', { type: 'integer', min: 0 }], ['integer min -0', { type: 'integer', min: -0 }], ['integer max 1.5', { type: 'integer', max: 1.5 }],
  ['integer max 2^53', { type: 'integer', max: 2 ** 53 }], ['integer max 2^53-1', { type: 'integer', max: 2 ** 53 - 1 }], ['integer min null', { type: 'integer', min: null }],
  ['integer min string', { type: 'integer', min: '1' }], ['string min junk', { type: 'string', min: 'x' }], ['set max junk', { type: 'set', values: [], max: 'x' }],
  ['type null', { type: null }], ['type number', { type: 1 }], ['type upper', { type: 'STRING' }], ['no type', {}], ['array', []], ['null', null], ['string decl', 'string'],
] as const) {
  await o.run('templateDef', 'decl ' + n, pl.templateDefError, [bodyDef(P({ resource: { $slot: 'a' } }), { a: d })]);
  await o.run('templateDef', 'decl second ' + n, pl.templateDefError, [bodyDef(P({ resource: { $slot: 'a' }, verb: { $slot: 'b' } }), { a: { type: 'string' }, b: d })]);
}
for (const n of ['a', 'z', 'a_1', 'a'.repeat(64), 'a'.repeat(65), '_a', '1a', 'A', 'a-b', 'a b', 'é', '', 'a\n'])
  await o.run('templateDef', `slot name ${JSON.stringify(n)}`, pl.templateDefError, [bodyDef(P({ resource: { $slot: n } }), { [n]: { type: 'string' } })]);

// ---- instantiation ---------------------------------------------------------------------------------------------------
for (const [n, v] of variants(SLOTS, { lens: [0, 1, 255, 256, 257], depth: 3 })) {
  await o.run('instantiate', 'slots ' + n, pl.instantiateTemplate, [DEF, v]);
  await o.run('resolve', 'slots ' + n, pl.resolveLink, [{ ...REF, slots: v }, REG()]);
}
const one = (decl: any, where: 'resource' | 'verb' | 'value' | 'pre' | 'post' | 'prepost' | 'verbarr') => {
  const ph = where === 'pre' ? { $slot: 'a', pre: '/x/' } : where === 'post' ? { $slot: 'a', post: '/y' } : where === 'prepost' ? { $slot: 'a', pre: 're', post: ':' } : { $slot: 'a' };
  const pred = where === 'verb' ? { verb: ph, resource: 'r' } : where === 'verbarr' ? { verb: ['read', ph], resource: 'r' } : where === 'value' ? { verb: 'v', where: [{ value: ph }] } : { verb: 'v', resource: ph };
  return bodyDef(P(pred), { a: decl });
};
const STR_VALS = ['', 'x', 'a'.repeat(256), 'a'.repeat(257), 'é'.repeat(256), '*', 'a*', 're:x', 're', 'xre:', ':', '\u0000', 'a\u0000b', '\ud800', 'eu', 'us', 'EU', 1, null, true, ['x'], {}];
const INT_VALS = [0, -0, 1, -1, 4, 5, 6, 10, 11, 1.5, 2 ** 53 - 1, 2 ** 53, -(2 ** 53 - 1), '5', null, true, [5]];
const SET_VALS = [[], ['a'], ['a', 'a'], ['a', 'b'], ['b', 'a'], ['a', 'z'], ['*'], ['re:x', 'a'], ['a', 1], [null], Array.from({ length: 64 }, (_, i) => 'v' + i), Array.from({ length: 65 }, (_, i) => 'v' + i), 'a', null, {}];
const DECLS: [string, any, any[]][] = [
  ['string', { type: 'string' }, STR_VALS],
  ['string closed', { type: 'string', values: ['eu', 'us', '*', 're:x'] }, STR_VALS],
  ['integer', { type: 'integer' }, INT_VALS],
  ['integer 5..10', { type: 'integer', min: 5, max: 10 }, INT_VALS],
  ['integer min 5', { type: 'integer', min: 5 }, INT_VALS],
  ['integer max 5', { type: 'integer', max: 5 }, INT_VALS],
  ['integer -0..0', { type: 'integer', min: 0, max: 0 }, INT_VALS],
  ['set closed', { type: 'set', values: ['a', 'b', '*', 're:x'] }, SET_VALS],
  ['set open values', { type: 'set', values: [...Array.from({ length: 64 }, (_, i) => 'v' + i)] }, SET_VALS],
  ['string set-ish', { type: 'set', values: Array.from({ length: 64 }, (_, i) => 'v' + i).slice(0, 3).concat(['a', 'b']) }, SET_VALS],
];
for (const [dn, decl, vals] of DECLS)
  for (const where of ['resource', 'verb', 'value', 'pre', 'post', 'prepost', 'verbarr'] as const)
    for (const val of vals) {
      const name = `${dn} @${where} ${Object.is(val, -0) ? '-0' : JSON.stringify(val).slice(0, 40)}${typeof val === 'string' ? ' #' + val.length : Array.isArray(val) ? ' #' + val.length : ''}`;
      await o.run('instantiate', name, pl.instantiateTemplate, [one(decl, where), { a: val }]);
    }
for (const [n, s] of [['missing', {}], ['extra', { a: 'x', b: 'y' }], ['extra first', { b: 'y', a: 'x' }], ['null', null], ['array', ['x']], ['string', 'x'], ['__proto__', JSON.parse('{"a":"x","__proto__":"y"}')]] as const)
  await o.run('instantiate', 'slots object ' + n, pl.instantiateTemplate, [one({ type: 'string' }, 'resource'), s]);
await o.run('instantiate', 'base', pl.instantiateTemplate, [DEF, SLOTS]);
await o.run('instantiate', 'no caveats', pl.instantiateTemplate, [bodyDef(P({ resource: { $slot: 'a' } })), { a: 'x' }]);

// ---- overlays ------------------------------------------------------------------------------------------------------------
for (const [n, v] of variants(OV, { lens: [0, 1, 64, 65], depth: 4 })) {
  await o.run('tighten', n, pl.tightenOverlayError, [v]);
  await o.run('verifyTighten', 'overlay ' + n, vo, [{ overlay: v, signer: ORGK, sig: signO(OV).sig }, TRUSTED]);
  await o.run('verifyTighten', 'overlay resigned ' + n, vo, [signO(v), TRUSTED]);
  // a re-signed overlay variant that still names the base version applies (or refuses) during resolution
  await o.run('resolve', 'overlay ' + n, pl.resolveLink, [REF, REG({ overlays: [signO(v)] })]);
}
for (const [n, v] of [['no adds', { v: 1, kind: 'pca-template-tighten', template_id: 'refund_tpl', version_digest: D0 }], ['empty adds', { ...OV, add_where: [], add_caveats: [] }],
  ['caveat type number', { ...OV, add_caveats: [{ type: 1 }] }], ['caveat array', { ...OV, add_caveats: [[]] }], ['where null', { ...OV, add_where: [null] }], ['where array', { ...OV, add_where: [[]] }],
  ['where second bad', { ...OV, add_where: [{}, 'x'] }], ['caveat second bad', { ...OV, add_caveats: [{ type: 'a' }, { type: null }] }]] as const) {
  await o.run('tighten', n, pl.tightenOverlayError, [v]);
  await o.run('resolve', 'overlay ' + n, pl.resolveLink, [REF, REG({ overlays: [signO(v)] })]);
}

// ---- signed artefacts -----------------------------------------------------------------------------------------------------
const ST = signT(DEF);
for (const [n, v] of variants(ST, { lens: [0, 1, 43, 44, 86, 87], depth: 1 })) {
  await o.run('verifyTemplate', 'envelope ' + n, vt, [v, TRUSTED]);
  await o.run('resolve', 'template envelope ' + n, pl.resolveLink, [REF, { templates: { [D0]: v }, trusted: TRUSTED }]);
}
const SO = signO(OV);
for (const [n, v] of variants(SO, { lens: [0, 1, 43, 44, 86, 87], depth: 1 })) {
  await o.run('verifyTighten', 'envelope ' + n, vo, [v, TRUSTED]);
  await o.run('resolve', 'overlay envelope ' + n, pl.resolveLink, [REF, REG({ overlays: [v] })]);
}
for (const [n, tr] of [['empty', []], ['other', [OTHERK]], ['both', [OTHERK, ORGK]], ['garbage', ['AA', ORGK.slice(1)]]] as const) {
  await o.run('verifyTemplate', 'trusted ' + n, vt, [ST, tr]);
  await o.run('verifyTighten', 'trusted ' + n, vo, [SO, tr]);
}
await o.run('verifyTemplate', 'other signer', vt, [signT(DEF, OTHER, OTHERK), [ORGK, OTHERK]]);
await o.run('verifyTemplate', 'signer mismatch', vt, [signT(DEF, OTHER, ORGK), TRUSTED]);
await o.run('verifyTighten', 'signer mismatch', vo, [signO(OV, OTHER, ORGK), TRUSTED]);
await o.run('verifyTemplate', 'tighten signature on template', vt, [{ def: DEF, signer: ORGK, sig: domainSig(ORG, pl.TIGHTEN_SIG_DOMAIN, DEF) }, TRUSTED]);
await o.run('verifyTighten', 'template signature on overlay', vo, [{ overlay: OV, signer: ORGK, sig: domainSig(ORG, pl.TEMPLATE_SIG_DOMAIN, OV) }, TRUSTED]);

// ---- references and registries ---------------------------------------------------------------------------------------------
for (const [n, v] of variants(REF, { lens: [0, 1, 127, 128, 129], depth: 1 })) {
  await o.run('templateRef', n, pl.templateRefError, [v]);
  await o.run('resolve', 'ref ' + n, pl.resolveLink, [v, REG()]);
}
const BREF: any = { template_id: 'refund_tpl', version_digest: D0, bind_params_digest: digest(SLOTS) };
for (const [n, v] of variants(BREF, { lens: [0, 1, 127, 128, 129], depth: 1 })) {
  await o.run('templateRef', 'bind ' + n, pl.templateRefError, [v]);
  await o.run('resolve', 'bind ' + n, pl.resolveLink, [v, REG({ params: { [BREF.bind_params_digest]: SLOTS } })]);
}
for (const [n, v] of [['both', { ...REF, bind_params_digest: 'x' }], ['both null', { ...REF, slots: null, bind_params_digest: null }], ['bind null', { template_id: 'refund_tpl', version_digest: D0, bind_params_digest: null }],
  ['neither', { template_id: 'refund_tpl', version_digest: D0 }], ['unknown first', { zz: 1, ...REF }], ['é digest', { ...REF, version_digest: 'é'.repeat(64) }]] as const) {
  await o.run('templateRef', n, pl.templateRefError, [v]);
}
const RV = REG({ params: { [BREF.bind_params_digest]: SLOTS } });
for (const [n, v] of variants(RV, { depth: 1 })) {
  await o.run('resolve', 'reg ' + n, pl.resolveLink, [REF, v]);
  await o.run('resolve', 'reg bind ' + n, pl.resolveLink, [BREF, v]);
}
for (const [n, tr] of [['empty', []], ['other', [OTHERK]], ['both', [OTHERK, ORGK]], ['null', null], ['string', 'x'], ['object', {}], ['with junk', [1, null, ORGK]]] as const)
  await o.run('resolve', 'trusted ' + n, pl.resolveLink, [REF, REG({ trusted: tr })]);
for (const [n, params] of [['missing', undefined], ['null', null], ['empty', {}], ['other object', { [BREF.bind_params_digest]: { ...SLOTS, acct: '43' } }], ['not object', { [BREF.bind_params_digest]: 'x' }],
  ['array', { [BREF.bind_params_digest]: ['x'] }], ['wrong slots', { [digest({ acct: '1' })]: { acct: '1' } }]] as const) {
  const reg: any = REG();
  if (params !== undefined) reg.params = params;
  await o.run('resolve', 'params ' + n, pl.resolveLink, [BREF, reg]);
  await o.run('resolve', 'params wrong-slots ref ' + n, pl.resolveLink, [{ ...BREF, bind_params_digest: digest({ acct: '1' }) }, reg]);
}
const OVLS: [string, any][] = [
  ['none', []], ['one', [signO(OV)]], ['two', [signO(OV), signO(OV2)]], ['three', [signO(OV2), signO(OVX), signO(OV3), signO(OV)]], ['other only', [signO(OVX)]],
  ['untrusted', [signO(OV), signO(OV2, OTHER, OTHERK)]], ['bad sig', [signO(OV), { ...signO(OV2), sig: signO(OV3).sig }]], ['other id', [signO({ ...OV, template_id: 'other_tpl' })]],
  ['junk entries', [null, 1, 'x', {}, { overlay: null }, { overlay: [] }, signO(OV)]], ['not array object', {}], ['null', null], ['string', 'ab'], ['number', 1],
  ['same twice', [signO(OV), signO(OV)]], ['invalid but naming', [signO({ ...OV, add_where: 'x' })]], ['digest number', [signO({ ...OV, version_digest: 1 })]],
];
for (const [n, ov] of OVLS) {
  await o.run('resolve', 'overlays ' + n, pl.resolveLink, [REF, REG({ overlays: ov })]);
  await o.run('resolve', 'overlays bind ' + n, pl.resolveLink, [BREF, REG({ overlays: ov, params: { [BREF.bind_params_digest]: SLOTS } })]);
}
// predicates with and without where, a where that is null, and a predicate list with no where at all
for (const [n, preds] of [['no where', [{ verb: 'v', resource: { $slot: 'a' } }]], ['where null', [{ verb: 'v', resource: { $slot: 'a' }, where: null }]], ['where list', [{ verb: 'v', resource: { $slot: 'a' }, where: [{ f: 1 }] }]],
  ['empty predicates', []], ['two', [{ verb: 'v', resource: { $slot: 'a' } }, { verb: 'w', where: [] }]]] as const) {
  const def = bodyDef({ predicates: preds, caveats: [{ type: 'c' }, { type: 'u', v: { $slot: 'a' } }] });
  const d = digest(def);
  const ovs = [OV, OV2, OV3].map((x) => signO({ ...x, version_digest: d }));
  for (const k of [0, 1, 2, 3])
    await o.run('resolve', `predicates ${n} ${k} overlays`, pl.resolveLink, [{ template_id: 'refund_tpl', version_digest: d, slots: { a: 'x' } }, { templates: { [d]: signT(def) }, overlays: ovs.slice(0, k), trusted: TRUSTED }]);
}
await o.run('resolve', 'base', pl.resolveLink, [REF, REG()]);
await o.run('resolve', 'digest mismatch', pl.resolveLink, [{ ...REF, version_digest: digest('x') }, { templates: { [digest('x')]: signT(DEF) }, trusted: TRUSTED }]);
await o.run('resolve', 'id mismatch', pl.resolveLink, [{ ...REF, template_id: 'other_tpl' }, REG()]);
await o.run('resolve', 'templates array', pl.resolveLink, [REF, REG({ templates: [signT(DEF)] })]);
await o.run('resolve', 'reg null', pl.resolveLink, [REF, null]);

// ---- forbid-wins certificates --------------------------------------------------------------------------------------------
const typed = (c: any) => c !== null && typeof c === 'object' && !Array.isArray(c) && c.winner !== null && typeof c.winner === 'object' && !Array.isArray(c.winner) && Array.isArray(c.shadowed) && Array.isArray(c.clauses) &&
  c.clauses.every((r: any) => r !== null && typeof r === 'object' && !Array.isArray(r) && typeof r.id === 'string' && typeof r.kind === 'string' && typeof r.value === 'string');
const forbid = (cert: unknown, precedence: string[] | null) => ({ ok: fc.certificateConsistent(cert, precedence === null ? {} : { precedence }), typed: typed(cert) });
/** The certificate the table forces (the generator's own construction; certificateConsistent is the judge). */
function forced(rows: any[], prec: string[]) {
  const rank = (r: any) => { const i = r.signer === undefined ? -1 : prec.indexOf(r.signer); return i < 0 ? prec.length : i; };
  const hit = (k: string) => rows.filter((r) => r.kind === k && r.value !== 'false');
  const forbids = hit('forbid').sort((x, y) => rank(x) - rank(y) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  const permits = hit('permit');
  const escalates = hit('escalate');
  const win = forbids[0] ?? (permits.length === 0 ? undefined : escalates[0] ?? permits[0]);
  const decision = forbids.length ? 'deny' : !permits.length ? 'deny' : escalates.length ? 'escalate' : 'allow';
  const kind = forbids.length ? 'forbid' : !permits.length ? 'none' : escalates.length ? 'escalate' : 'permit';
  return { v: 1, kind: 'forbid-wins', policy: 'p', action: 'a', decision, winner: { kind, id: win?.id ?? null }, shadowed: [...forbids, ...permits, ...escalates].filter((r) => r !== win).map((r) => r.id), clauses: rows };
}
const PRECS: (string[] | null)[] = [null, [], ['a'], ['b', 'a'], ['c', 'b', 'a'], ['z']];
const r = rng(0x9e1);
const IDS = ['a1', 'b2', 'c3', 'd4', 'e5', 'B2', 'é', 'aa', 'a', 'Z'];
for (let k = 0; k < 500; k++) {
  const n = r.int(0, 6);
  const ids = [...IDS].sort(() => r.next() - 0.5).slice(0, n);
  const rows = ids.map((id) => {
    const row: any = { id, kind: r.pick(['permit', 'forbid', 'escalate']) };
    const s = r.pick([undefined, 'a', 'b', 'c', 'z', undefined]);
    if (s !== undefined) row.signer = s;
    row.value = r.pick(['true', 'false', 'unknown']);
    return row;
  });
  const prec = r.pick(PRECS);
  const cert = forced(rows, prec ?? []);
  await o.run('forbid', `t${k} consistent`, forbid, [cert, prec]);
  const muts: [string, any][] = [
    ['decision', { ...cert, decision: r.pick(['allow', 'deny', 'escalate'].filter((d) => d !== cert.decision)) }],
    ['winner kind', { ...cert, winner: { ...cert.winner, kind: r.pick(['forbid', 'permit', 'escalate', 'none'].filter((d) => d !== cert.winner.kind)) } }],
    ['winner id', { ...cert, winner: { ...cert.winner, id: cert.winner.id === null ? (ids[0] ?? 'x') : null } }],
    ['winner id absent', { ...cert, winner: { kind: cert.winner.kind } }],
    ['shadowed reversed', { ...cert, shadowed: [...cert.shadowed].reverse() }],
    ['shadowed dropped', { ...cert, shadowed: cert.shadowed.slice(1) }],
    ['shadowed extra', { ...cert, shadowed: [...cert.shadowed, 'zz'] }],
    ['other precedence', cert],
  ];
  if (rows.length) {
    const i = r.int(0, rows.length - 1);
    const flip = (f: string, val: unknown) => ({ ...cert, clauses: rows.map((x, j) => (j === i ? { ...x, [f]: val } : x)) });
    muts.push(['row value', flip('value', r.pick(['true', 'false', 'unknown', 'TRUE', 'maybe']))], ['row kind', flip('kind', r.pick(['permit', 'forbid', 'escalate', 'allow']))],
      ['row signer', flip('signer', r.pick(['a', 'b', 'c', 1, null]))], ['row id number', flip('id', 7)], ['row kind number', flip('kind', 1)], ['row value bool', flip('value', true)]);
  }
  for (const [mn, m] of muts) await o.run('forbid', `t${k} ${mn}`, forbid, [m, mn === 'other precedence' ? r.pick(PRECS) : prec]);
}
const MAL = { v: 1, kind: 'forbid-wins', policy: 'p', action: 'a', decision: 'deny', winner: { kind: 'malformed', id: null }, shadowed: [], clauses: [] };
const BASE = forced([{ id: 'a1', kind: 'forbid', signer: 'b', value: 'true' }, { id: 'b2', kind: 'forbid', signer: 'a', value: 'unknown' }, { id: 'c3', kind: 'permit', value: 'true' }, { id: 'd4', kind: 'escalate', value: 'true' }], ['a', 'b']);
for (const [cn, c] of [['malformed', MAL], ['base', BASE]] as const)
  for (const [n, v] of variants(c, { depth: 3 })) {
    await o.run('forbid', `${cn} ${n}`, forbid, [v, ['a', 'b']]);
    if (cn === 'malformed') await o.run('forbid', `${cn} null precedence ${n}`, forbid, [v, null]);
  }
await o.run('forbid', 'malformed shadowed string', forbid, [{ ...MAL, shadowed: '' }, null]);
await o.run('forbid', 'malformed with rows', forbid, [{ ...MAL, clauses: [{ id: 'a', kind: 'permit', value: 'true' }] }, null]);

o.write();
