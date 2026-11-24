// Oracle: @atlasauth/pca-actions sync.ts and hosted.ts. Writes out/ref-actions-hosted.json.gz.
// PORTING table (documents and versions are plain JSON; pins {keys:[...]} or undefined/null)
//   syncSource(current, imported, specDigest, lock|null, now, confirmed) -> ActionSync.syncSource(..., CORE, d -> confirmed); syncText(result) -> ActionSync.syncText
//   rulesDocError(x, defs) (ns 'acme')                     -> ActionHosted.rulesDocError
//   hostedVersionDigest(v)                          -> ActionHosted.hostedVersionDigest
//   publishGate(input)                              -> ActionHosted.publishGate(input) ({current?, pack, rules?, traits?, publisherKeys, pins?, pin?})
//   viewLookup(versions, pins, verb)                -> ActionHosted.hostedView(versions, pins).lookup(verb)
//   viewProvenance(versions, pins, verb)            -> .provenance(verb) (null when unknown)
//   viewFloor(versions, pins, verb, grant, ctx)     -> .floor(verb, grant, ctx)
//   viewUndo(versions, pins, op)                    -> .undoPlan(op) (null when not undoable)
//   hostedCallContext(lookup, params)               -> ActionHosted.hostedCallContext; rateKeysOf(compiled, who) -> ActionHosted.rateKeysOf; grantFactsOf(grant) -> ActionHosted.grantFactsOf
import * as HO0 from '../../../packages/pca-actions/src/hosted.ts';
import * as SY0 from '../../../packages/pca-actions/src/sync.ts';
import * as BD0 from '../../../packages/pca-actions/src/build.ts';
import * as BR0 from '../../../packages/pca-actions/src/business-rules.ts';
import * as CF0 from '../../../packages/pca-actions/src/confirmation.ts';
import * as DG0 from '../../../packages/pca-actions/src/digest.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as TP0 from '../../../packages/pca-actions/src/templates.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const HO = un(HO0), SY = un(SY0), BD = un(BD0), BR = un(BR0), CF = un(CF0), DG = un(DG0), CT = un(CT0), TP = un(TP0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const CORE = CT.CORE_REGISTRY;
const o = new Oracle('actions-hosted', 'tools/pca-audit/oracles/actions-hosted.mts', 'TS-reference oracle for pca-actions sync and the hosted registry.');
const SK = seed('ref-actions-hosted/publisher'), SKR = seed('ref-actions-hosted/reviewer'), SKO = seed('ref-actions-hosted/other');
const kd = (sk: Uint8Array) => P.b64u(P.publicKeyOf(sk));
const PINS = { keys: [{ kid: 'rv1', pk: kd(SKR), roles: ['reviewer'] }] };
const PKEYS = [BD.packKeyOf('pub1', SK)];
const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
const res = { type: 'acme.note', id: { prefix: '', class: 'any_safe', len: [1, 128] }, scope: 'one' };
const note = (verb: string, over: any = {}) => clone({ v: 1, kind: 'pca-action-def', verb, title: 'Note', effects: ['create'], resource: res, params: { title: { type: 'string', max_len: 100 } }, reversibility: 'reversible', blast: { radius: 'one', ppm: 100000 }, compensates: 'acme.note.remove', review: { state: 'authored' }, since: '0.6.0', ...over });
const remove = (over: any = {}) => ({ v: 1, kind: 'pca-action-def', verb: 'acme.note.remove', title: 'Remove', effects: ['delete'], resource: res, params: { note: { type: 'string', max_len: 128, role: 'id.acme.note' } }, reversibility: 'irreversible', blast: { radius: 'one', ppm: 100000 }, review: { state: 'authored' }, since: '0.6.0', ...over });
const reader = (over: any = {}) => ({ v: 1, kind: 'pca-action-def', verb: 'acme.note.read', title: 'Read', effects: ['read'], resource: res, params: { note: { type: 'string', max_len: 128, role: 'id.acme.note' } }, reversibility: 'reversible', blast: { radius: 'one', ppm: 1000 }, review: { state: 'authored' }, since: '0.6.0', ...over });
const confirm = (d: any, reg: any = CORE, over: any = {}, sk = SKR) => {
  const body = { def_digest: DG.defDigest(d), traits_digest: DG.traitsDigest(reg), facts_digest: 'F'.repeat(43), final_traits: d.traits ?? [], dismissed: [], reviewer_kid: 'rv1', ts: 1_800_000_000, ...over };
  return { ...clone(d), review: { state: 'confirmed', attestation: CF.signReview(body, sk) } };
};
const CFG = (version: string, ns = 'acme') => ({ ns, version, stability: 'stable', site: 'https://acme.example', aud: 'acme-api' });
const mkpack = (defs: any[], version: string, reg: any = CORE, ns = 'acme', sk = SK) => BD.signPack(BD.buildArtifacts(defs, CFG(version, ns), reg).pack, 'pub1', sk, reg);
const gate = (i: any) => HO.publishGate(i);
const GATE = (n: string, i: any) => o.run('publishGate', n, (x: any) => HO.publishGate(x), [i]);

const A = note('acme.note.create'), R = remove(), B = reader();
const AC = confirm(A), RC = confirm(R), BC = confirm(B);
const base = { publisherKeys: PKEYS, pins: PINS };
const P1 = mkpack([AC, RC, BC], '1.0.0');
const g1 = gate({ ...base, pack: P1 });
const V1 = g1.version;
await GATE('first confirmed', { ...base, pack: P1 });
await GATE('first unconfirmed', { ...base, pack: mkpack([A, R, B], '1.0.0') });
await GATE('first no pins', { ...base, pins: undefined, pack: P1 });
await GATE('bad pack tampered', { ...base, pack: { ...P1, version: '1.0.1' } });
await GATE('bad pack wrong keys', { ...base, publisherKeys: [BD.packKeyOf('pub1', SKO)], pack: P1 });
await GATE('bad pack unsigned', { ...base, pack: BD.buildArtifacts([AC], CFG('1.0.0'), CORE).pack });
await GATE('traits not list', { ...base, pack: P1, traits: 'x' });
await GATE('traits weaken', { ...base, pack: P1, traits: [{ id: 'acme.weak', implies: ['pca.money_moving'], floor: { risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [] }, card_phrase: 'x' }] });
const next = (defs: any[], v: string, extra: any = {}) => ({ ...base, current: V1, pack: mkpack(defs, v), ...extra });
await GATE('same content newer', next([AC, RC, BC], '1.0.1'));
await GATE('not newer', next([AC, RC, BC], '1.0.0'));
await GATE('older', next([AC, RC, BC], '0.9.0'));
await GATE('older pinned', next([AC, RC, BC], '0.9.0', { pin: true }));
await GATE('other ns', { ...base, current: V1, pack: mkpack([AC, RC, BC], '2.0.0', CORE, 'other') });
const A2 = mut(A, (d) => (d.title = 'Note v2'));
await GATE('changed unconfirmed widens', next([A2, RC, BC], '1.1.0'));
await GATE('changed reconfirmed', next([confirm(A2), RC, BC], '1.1.0'));
await GATE('changed reconfirmed wrong signer', next([confirm(A2, CORE, {}, SKO), RC, BC], '1.1.0'));
await GATE('changed reconfirmed no pins', next([confirm(A2), RC, BC], '1.1.0', { pins: undefined }));
await GATE('blast widened confirmed', next([confirm(mut(A, (d) => (d.blast = { radius: 'global', ppm: 900000 }))), RC, BC], '1.1.0'));
await GATE('removed verb', next([AC, RC], '1.1.0'));
await GATE('added verb unconfirmed', next([AC, RC, BC, note('acme.note.draft', { compensates: undefined })], '1.1.0'));
await GATE('added verb confirmed', next([AC, RC, BC, confirm(reader({ verb: 'acme.note.peek' }))], '1.1.0'));
const V2dep = gate(next([AC, RC], '1.1.0')).version;
await GATE('re-added after deprecation', { ...base, current: V2dep, pack: mkpack([AC, RC, BC], '1.2.0') });
await GATE('rules bad doc', { ...base, pack: P1, rules: { v: 1, kind: 'pca-action-rules', ns: 'acme', rules: { 'acme.note.nope': { required: ['title'] } } } });
await GATE('rules bad shape', { ...base, pack: P1, rules: 5 });
await GATE('rules other ns', { ...base, pack: P1, rules: { v: 1, kind: 'pca-action-rules', ns: 'zzz', rules: {} } });
const RD = (rules: any, reviews?: any) => ({ v: 1, kind: 'pca-action-rules', ns: 'acme', rules, ...(reviews ? { reviews } : {}) });
const RB = { required: ['title'] }, RB2 = { required: ['title'], rate: [{ max: 5, per: 'hour' }] };
const gr = gate({ ...base, pack: P1, rules: RD({ 'acme.note.create': RB2 }) });
await GATE('first with rules', { ...base, pack: P1, rules: RD({ 'acme.note.create': RB2 }) });
const V1r = gr.version;
const rnext = (rules: any, reviews: any, v = '1.0.2', defs = [AC, RC, BC]) => ({ ...base, current: V1r, pack: mkpack(defs, v), rules: RD(rules, reviews) });
await GATE('rules narrowed', rnext({ 'acme.note.create': { required: ['title'], rate: [{ max: 3, per: 'hour' }] } }, undefined));
await GATE('rules widened unreviewed', rnext({ 'acme.note.create': { required: ['title'], rate: [{ max: 50, per: 'hour' }] } }, undefined));
await GATE('rules dropped unreviewed', rnext({}, undefined));
const mkRev = (verb: string, def: any, rules: any, over: any = {}, sk = SKR) => BR.signRulesReview({ verb, def_digest: DG.defDigest(def), rules_digest: BR.businessRulesDigest(verb, rules), reviewer_kid: 'rv1', ts: 1_800_000_000, ...over }, sk);
const widened = { required: ['title'], rate: [{ max: 50, per: 'hour' }] };
await GATE('rules widened reviewed', rnext({ 'acme.note.create': widened }, { 'acme.note.create': mkRev('acme.note.create', AC, widened) }));
await GATE('rules widened bad review', rnext({ 'acme.note.create': widened }, { 'acme.note.create': mkRev('acme.note.create', AC, widened, {}, SKO) }));
await GATE('rules dropped reviewed', rnext({}, { 'acme.note.create': mkRev('acme.note.create', AC, {}) }));
await GATE('rules review for unknown verb', rnext({ 'acme.note.create': RB2 }, { 'acme.note.zzz': {} }));
await GATE('rules added to unruled', { ...base, current: V1, pack: mkpack([AC, RC, BC], '1.0.3'), rules: RD({ 'acme.note.create': RB }) });
const TR = TP.STARTER_TEMPLATES[0].traits('acme');
const regT = HO.registryOfTraits(TR);
const AT = note('acme.note.create', { traits: ['acme.refund'] });
await GATE('custom traits first', { ...base, pack: mkpack([confirm(AT, regT), RC], '1.0.0', regT), traits: TR });
const VT = gate({ ...base, pack: mkpack([confirm(AT, regT), RC], '1.0.0', regT), traits: TR }).version;
await GATE('custom traits to core', { ...base, current: VT, pack: mkpack([confirm(A), RC], '1.1.0') });
await GATE('core to custom traits', { ...base, current: V1, pack: mkpack([confirm(AT, regT), RC], '1.1.0', regT), traits: TR });
await GATE('custom traits same', { ...base, current: VT, pack: mkpack([confirm(AT, regT), RC], '1.0.1', regT), traits: TR });

for (const [n, r] of [['ok', RD({ 'acme.note.create': RB })], ['empty', RD({})], ['unknown member', { ...RD({}), zz: 1 }], ['bad kind', { ...RD({}), kind: 'x' }], ['bad v', { ...RD({}), v: 2 }], ['other ns', { ...RD({}), ns: 'z' }], ['no ns', { v: 1, kind: 'pca-action-rules', rules: {} }],
  ['rules array', { ...RD({}), rules: [] }], ['reviews array', { ...RD({}), reviews: [] }], ['reviews null', { ...RD({}), reviews: null }], ['unknown verb', RD({ 'acme.zz': RB })], ['lint error', RD({ 'acme.note.create': { required: ['nope'] } })],
  ['lint warning only', RD({ 'acme.note.create': { required: ['title'], rate: [{ max: 5, per: 'hour' }, { max: 3, per: 'hour' }] } })], ['unknown review verb', RD({}, { 'acme.zz': {} })], ['not object', 5], ['null', null], ['array', []]] as [string, any][])
  await o.run('rulesDocError', n, (x: any, defs: any) => HO.rulesDocError(x, 'acme', defs), [r, [A, R, B]]);
for (const [n, v] of [['v1', V1], ['v1r', V1r], ['v2dep', V2dep]] as [string, any][]) await o.run('hostedVersionDigest', n, (x: any) => HO.hostedVersionDigest(x), [{ pack: v.pack, rules: v.rules, traits: v.traits, deprecated: v.deprecated }]);

// the verifier's view
const BROKEN = { ...V1, ns: 'brk', version: '1.0.0', traits: [{ id: 'bad', implies: ['nope'], floor: {}, card_phrase: 'x' }], pack: mkpack([confirm(note('brk.note.make', { compensates: undefined })), ], '1.0.0') };
const VIEWS: [string, any[]][] = [['v1', [V1]], ['v1r', [V1r]], ['deprecated', [V2dep]], ['custom', [VT]], ['two', [V1, VT]], ['broken', [BROKEN, V1]], ['empty', []]];
const VERBS = ['acme.note.create', 'acme.note.remove', 'acme.note.read', 'acme.note.zzz', 'brk.note.make', '', 'ACME.NOTE.CREATE'];
for (const [vn, vs] of VIEWS) for (const pins of [PINS, undefined]) for (const verb of VERBS) {
  const pn = pins ? 'pinned' : 'nopins';
  await o.run('viewLookup', `${vn} ${pn} ${verb}`, (v: any, p: any, x: string) => HO.hostedView(v, p === null ? undefined : p).lookup(x), [vs, pins ?? null, verb]);
  await o.run('viewProvenance', `${vn} ${pn} ${verb}`, (v: any, p: any, x: string) => HO.hostedView(v, p === null ? undefined : p).provenance({ verb: x }) ?? null, [vs, pins ?? null, verb]);
}
const GR: [string, any][] = [['none', { caveats: [], max_esc: 3, preauth_esc: 0 }], ['all', { caveats: ['amount_cap', 'count_cap', 'window', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap', 'bogus'], max_esc: 3, preauth_esc: 3 }],
  ['low max', { caveats: ['resource_scope'], max_esc: 0, preauth_esc: 0 }], ['bad tiers', { caveats: [], max_esc: -1, preauth_esc: 0 }], ['float tier', { caveats: [], max_esc: 2.5, preauth_esc: 0 }], ['resource', { caveats: ['resource_scope'], max_esc: 3, preauth_esc: 1 }]];
for (const [gn, g] of GR) for (const ctx of [[], ['fresh_revocation'], ['fresh_revocation', 'idempotency']]) for (const [vn, vs] of VIEWS.slice(0, 5)) for (const verb of VERBS.slice(0, 4)) {
  await o.run('viewFloor', `${vn} ${gn} ${ctx.length} ${verb}`, (v: any, p: any, x: string, gg: any, c: any) => HO.hostedView(v, p).floor(x, gg, c), [vs, PINS, verb, g, ctx]);
}
for (const [vn, vs] of VIEWS) for (const [on, op] of [['ok', { verb: 'acme.note.create', params: { title: 'x' } }], ['missing', { verb: 'acme.note.create', params: {} }], ['remove', { verb: 'acme.note.remove', params: { note: 'n' } }], ['unknown', { verb: 'zz.zz', params: {} }], ['no params', { verb: 'acme.note.create' }]] as [string, any][])
  for (const pins of [PINS, undefined]) await o.run('viewUndo', `${vn} ${pins ? 'pinned' : 'nopins'} ${on}`, (v: any, p: any, x: any) => HO.hostedView(v, p === null ? undefined : p).undo.plan(x, { operationId: 'op1' }) ?? null, [vs, pins ?? null, op]);

// call context, rate keys, grant facts
for (const [ln, l] of [['none', undefined], ['no idem', {}], ['idem', { idempotency_param: 'k' }]] as [string, any][]) for (const [pn, p] of [['undef', undefined], ['empty', {}], ['set', { k: 'x' }], ['blank', { k: '' }], ['num', { k: 5 }]] as [string, any][])
  await o.run('hostedCallContext', `${ln} ${pn}`, (a: any, b: any) => HO.hostedCallContext(a, b), [l ?? null, p ?? null]);
const RATED = BR.compileBusinessRules(A, { rate: [{ max: 5, per: 'hour' }, { max: 9, per: 'day', by: 'org' }] });
for (const [wn, w] of [['both', { principal: 'u1', org: 'o1' }], ['principal', { principal: 'u1' }], ['org', { org: 'o1' }], ['none', {}], ['empty', { principal: '', org: '' }], ['num', { principal: 5, org: 6 }]] as [string, any][]) {
  await o.run('rateKeysOf', wn, (c: any, x: any) => HO.rateKeysOf(c, x), [RATED, w]);
}
await o.run('rateKeysOf', 'no rates', (c: any, x: any) => HO.rateKeysOf(c, x), [BR.compileBusinessRules(A, { required: ['title'] }), { principal: 'u1' }]);
for (const [gn, g] of [['empty', {}], ['null', null], ['no caveats', { caveats: [] }], ['other caveat', { caveats: [{ type: 'x' }] }]] as [string, any][]) await o.run('grantFactsOf', gn, (x: any) => HO.grantFactsOf(x), [g]);

// sync
const S = (n: string, cur: any[], imp: any[], lock: any, conf = false) => o.run('syncSource', n, (c: any, i: any, l: any, cc: any) => SY.syncSource({ current: c, imported: i, specDigest: 'S'.repeat(43), ...(l ? { lock: l } : {}), now: 1_800_000_000, review: { attestationVerified: () => cc } }), [cur, imp, lock, conf]);
const lockOf = (defs: any[]) => ({ spec_digest: 'O'.repeat(43), ops: Object.fromEntries(defs.map((d) => [d.verb, DG.defDigest(d)])), synced_at: 1_700_000_000 });
const IMP = [A, R, B];
await S('first import', [], IMP, null);
await S('same with lock', IMP, IMP, lockOf(IMP));
await S('same without lock', IMP, IMP, null);
await S('reviewed kept', [AC, RC, BC], IMP, lockOf(IMP));
await S('reviewed no lock changed', [AC, RC, BC], IMP, null);
await S('source changed', [AC, RC, BC], [A2, R, B], lockOf(IMP));
await S('source changed confirmed', [AC, RC, BC], [A2, R, B], lockOf(IMP), true);
await S('source removed', [AC, RC, BC], [R, B], lockOf(IMP));
await S('source added', [AC, RC, BC], [A, R, B, reader({ verb: 'acme.note.peek' })], lockOf(IMP));
await S('hand written untouched', [AC, mut(B, (d) => (d.verb = 'acme.note.mine'))], IMP, lockOf(IMP));
await S('imported confirmed stripped', [], [AC, RC], null);
await S('lock removed all', [AC], [], lockOf(IMP));
await S('widening change', [AC], [mut(A, (d) => (d.blast = { radius: 'global', ppm: 900000 }))], lockOf([A]), true);
await S('invalid imported', [AC], [{ verb: 'acme.note.create', review: { state: 'authored' } }], lockOf([A]));
await S('no review member', [AC], [{ verb: 'acme.note.create' }], null);
const reps = [SY.syncSource({ current: [AC, RC, BC], imported: [A2, R, B, reader({ verb: 'acme.note.peek' })], specDigest: 'S'.repeat(43), lock: lockOf(IMP), now: 1 }), SY.syncSource({ current: [AC, RC, BC], imported: IMP, specDigest: 'S'.repeat(43), lock: lockOf(IMP), now: 1 }), SY.syncSource({ current: [AC], imported: [], specDigest: 'S'.repeat(43), lock: lockOf(IMP), now: 1 })];
for (const [i, r] of reps.entries()) await o.run('syncText', `r${i}`, (x: any) => SY.syncText(x), [r]);
refWrite(o, 'actions-hosted');
