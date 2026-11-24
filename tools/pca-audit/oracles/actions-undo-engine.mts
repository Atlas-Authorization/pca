// Oracle: @atlasauth/pca-actions undo.ts undoEngine (the confirmation-gated plan). Writes out/ref-actions-undo-engine.json.gz.
// PORTING table
//   undoPlan(defs[], pins, op)   -> ActionUndoEngine.undoEngine(defs, pins, null).plan(op); pins undefined/null = nothing confirmed; a null plan is JSON null
//   attested(def, pins)          -> ActionUndoEngine.attestationVerifier(pins, CORE).test(def)  (boolean)
import * as UN0 from '../../../packages/pca-actions/src/undo.ts';
import * as RV0 from '../../../packages/pca-actions/src/import/review.ts';
import * as CF0 from '../../../packages/pca-actions/src/confirmation.ts';
import * as DG0 from '../../../packages/pca-actions/src/digest.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, clone, seed } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const UN = un(UN0), RV = un(RV0), CF = un(CF0), DG = un(DG0), CT = un(CT0);
const P: any = (P0 as any).b64u ? P0 : (P0 as any).default;
const o = new Oracle('actions-undo-engine', 'tools/pca-audit/oracles/actions-undo-engine.mts', 'TS-reference oracle for the pca-actions undo engine and its attestation check.');
const SK = seed('ref-actions-undo/reviewer'), SK2 = seed('ref-actions-undo/other'), SK3 = seed('ref-actions-undo/windowed');
const kd = (sk: Uint8Array) => P.b64u(P.publicKeyOf(sk));
const PINS = { keys: [{ kid: 'rv1', pk: kd(SK), roles: ['reviewer'] }, { kid: 'rv2', pk: kd(SK2), roles: ['importer'] }, { kid: 'rv3', pk: kd(SK3), roles: ['reviewer'], not_before: 1_800_000_100, not_after: 1_800_000_200 }] };
const TD = DG.traitsDigest(CT.CORE_REGISTRY);

const mut = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
const note = (verb: string, over: any = {}) => ({
  v: 1, kind: 'pca-action-def', verb, title: 'Note', effects: ['create'], resource: { type: 'acme.note', id: { prefix: '', class: 'any_safe', len: [1, 128] }, scope: 'one' },
  params: { title: { type: 'string', max_len: 100 }, text: { type: 'string', max_len: 1000, required: false } }, reversibility: 'reversible', blast: { radius: 'one', ppm: 100000 },
  compensates: 'acme.note.remove', review: { state: 'authored' }, since: '0.6.0', ...over,
});
const remove = (over: any = {}) => ({
  v: 1, kind: 'pca-action-def', verb: 'acme.note.remove', title: 'Remove', effects: ['delete'], resource: { type: 'acme.note', id: { prefix: '', class: 'any_safe', len: [1, 128] }, scope: 'one' },
  params: { note: { type: 'string', max_len: 128, role: 'id.acme.note' } }, reversibility: 'irreversible', blast: { radius: 'one', ppm: 100000 }, review: { state: 'authored' }, since: '0.6.0', ...over,
});
const confirm = (d: any, over: any = {}, sk = SK) => {
  const body = { def_digest: DG.defDigest(d), traits_digest: TD, facts_digest: 'F'.repeat(43), final_traits: d.traits ?? [], dismissed: [], reviewer_kid: 'rv1', ts: 1_800_000_000, ...over };
  return { ...clone(d), review: { state: 'confirmed', attestation: CF.signReview(body, sk) } };
};
const A = note('acme.note.create'), R = remove();
const AC = confirm(A), RC = confirm(R);
const OPS: [string, any][] = [
  ['ok', { verb: 'acme.note.create', params: { title: 'x' } }], ['both params', { verb: 'acme.note.create', params: { title: 'x', text: 'y' } }], ['no params', { verb: 'acme.note.create' }],
  ['missing required', { verb: 'acme.note.create', params: { text: 'y' } }], ['unknown param', { verb: 'acme.note.create', params: { title: 'x', zzz: 1 } }],
  ['wrong type', { verb: 'acme.note.create', params: { title: 5 } }], ['unknown verb', { verb: 'nope.x', params: {} }], ['the comp', { verb: 'acme.note.remove', params: { note: 'n1' } }],
  ['nested params', { verb: 'acme.note.create', params: { title: { a: 1 } } }], ['alias-like', { verb: 'ACME.NOTE.CREATE', params: { title: 'x' } }],
];
const PL = (n: string, defs: any[], pins: any, op: any) => o.run('undoPlan', n, (d: any, p: any, x: any) => { const r = UN.undoEngine({ defs: d, pins: p === null ? undefined : p }).plan(x); return r === undefined ? null : r; }, [defs, pins, op]);
for (const [n, op] of OPS) {
  await PL(`ok ${n}`, [AC, RC], PINS, op);
  await PL(`no pins ${n}`, [AC, RC], null, op);
}
const TW: [string, any[]][] = [
  ['unconfirmed orig', [A, RC]], ['unconfirmed comp', [AC, R]], ['no comp def', [AC]], ['comp first', [RC, AC]], ['duplicate first wins', [AC, AC, RC]],
  ['stale orig', [{ ...AC, title: 'Changed' }, RC]],
  ['bad sig', [mut(AC, (d) => (d.review.attestation.sig = 'A'.repeat(86))), RC]],
  ['wrong signer', [confirm(A, {}, SK2), RC]],
  ['wrong role', [confirm(A, { reviewer_kid: 'rv2' }, SK2), RC]],
  ['key window ok', [confirm(A, { reviewer_kid: 'rv3', ts: 1_800_000_150 }, SK3), confirm(R, { reviewer_kid: 'rv3', ts: 1_800_000_150 }, SK3)]],
  ['key window early', [confirm(A, { reviewer_kid: 'rv3', ts: 1_800_000_050 }, SK3), RC]],
  ['key window late', [confirm(A, { reviewer_kid: 'rv3', ts: 1_800_000_250 }, SK3), RC]],
  ['unknown reviewer', [confirm(A, { reviewer_kid: 'zz' }), RC]],
  ['other traits digest', [confirm(A, { traits_digest: 'A'.repeat(43) }), RC]],
  ['bad ts', [confirm(A, { ts: 1.5 }), RC]],
  ['final traits mismatch', [confirm(A, { final_traits: ['write_data'] }), RC]],
  ['dismissed conflict', [confirm(A, { dismissed: [{ trait: 'x', reason: '' }] }), RC]],
  ['not state confirmed', [mut(AC, (d) => (d.review.state = 'unreviewed')), RC]],
  ['no attestation', [mut(AC, (d) => delete d.review.attestation), RC]],
  ['comp other resource', [AC, confirm(remove({ resource: { type: 'acme.other', id: { prefix: '', class: 'any_safe', len: [1, 128] }, scope: 'one' } }))]],
  ['comp reads only', [AC, confirm(remove({ effects: ['read'] }))]],
  ['comp extra required', [AC, confirm(remove({ params: { note: { type: 'string', max_len: 128, role: 'id.acme.note' }, reason: { type: 'string', max_len: 10 } } }))]],
  ['comp extra optional', [AC, confirm(remove({ params: { note: { type: 'string', max_len: 128, role: 'id.acme.note' }, reason: { type: 'string', max_len: 10, required: false } } }))]],
  ['comp copies title', [AC, confirm(remove({ params: { title: { type: 'string', max_len: 100 }, note: { type: 'string', max_len: 128, role: 'id.acme.note' } } }))]],
  ['comp copies text', [AC, confirm(remove({ params: { text: { type: 'string', max_len: 1000 }, note: { type: 'string', max_len: 128, role: 'id.acme.note' } } }))]],
  ['comp idem key', [AC, confirm(remove({ params: { note: { type: 'string', max_len: 128, role: 'id.acme.note' }, k: { type: 'string', max_len: 64 } }, idempotency: { mode: 'key_param', param: 'k' } }))]],
  ['comp type differs', [AC, confirm(remove({ params: { note: { type: 'string', max_len: 128, role: 'id.acme.note' }, title: { type: 'integer', min: 0, max: 5 } }}))]],
  ['orig irreversible', [confirm(note('acme.note.create', { reversibility: 'irreversible' })), RC]],
  ['orig rate limited', [confirm(note('acme.note.create', { reversibility: 'rate_limited' })), RC]],
  ['orig no reversibility', [confirm(mut(A, (d) => delete d.reversibility)), RC]],
  ['orig no compensates', [confirm(mut(A, (d) => delete d.compensates)), RC]],
  ['orig read only', [confirm(note('acme.note.create', { effects: ['read'] })), RC]],
  ['orig compensates itself', [confirm(note('acme.note.create', { compensates: 'acme.note.create' })), RC]],
  ['orig value map', [confirm(note('acme.note.create', { reversibility: { by: 'title', map: { x: 'reversible', y: 'irreversible' }, default: 'irreversible' } })), RC]],
  ['orig value default', [confirm(note('acme.note.create', { reversibility: { by: 'title', map: { y: 'irreversible' }, default: 'reversible' } })), RC]],
  ['orig value map int', [confirm(note('acme.note.create', { params: { title: { type: 'string', max_len: 100 }, n: { type: 'integer', min: 0, max: 9, required: false } }, reversibility: { by: 'n', map: { '1': 'reversible' }, default: 'irreversible' } })), RC]],
  ['orig traits', [confirm(note('acme.note.create', { traits: ['external_send'] })), RC]],
  ['orig pii', [confirm(note('acme.note.create', { params: { title: { type: 'string', max_len: 100, tags: ['pii'] } } })), RC]],
  ['orig email', [confirm(note('acme.note.create', { params: { title: { type: 'string', role: 'contact.email', format: 'email', max_len: 100 } } })), RC]],
];
for (const [n, defs] of TW) for (const [on, op] of OPS.slice(0, 5)) await PL(`${n} ${on}`, defs, PINS, op);
await PL('bad pins', [AC, RC], { keys: [{ kid: 'x' }] }, OPS[0][1]);
await PL('empty defs', [], PINS, OPS[0][1]);
// value-dependent reversibility across param values
const VM = confirm(note('acme.note.create', { reversibility: { by: 'title', map: { x: 'reversible', y: 'irreversible', true: 'reversible' }, default: 'irreversible' } }));
for (const t of ['x', 'y', 'z', '', 'true', 5, true, null, ['x'], { a: 1 }, 1.5, -0]) await PL(`value-dep ${JSON.stringify(t)}`, [VM, RC], PINS, { verb: 'acme.note.create', params: { title: t } });
// the attestation check on its own
const AT = (n: string, d: any, pins: any) => o.run('attested', n, (x: any, p: any) => RV.attestationVerifier({ pins: p, registry: CT.CORE_REGISTRY })(x) === true, [d, pins]);
await AT('ok', AC, PINS);
for (const [n, defs] of TW) await AT(n, defs[0], PINS);
await AT('no pins members', AC, { keys: [] });
await AT('extra traits digest', confirm(A, { traits_digest: 'B'.repeat(43) }), { ...PINS, traits_digests: ['B'.repeat(43)] });
refWrite(o, 'actions-undo-engine');
