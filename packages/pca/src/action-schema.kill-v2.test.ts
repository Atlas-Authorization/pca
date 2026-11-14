/**
 * Version-2 action-schema documents: every rule of the v2 shape check on its own (parameter members, the materialized
 * floors, the signed confirmation, the verb members, the document members) with the exact refusal text, plus the
 * module-level vocabularies and member sets, re-evaluated per test (vi.resetModules + dynamic import).
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u } from './hash';
import * as S from './action-schema';

async function fresh() {
  vi.resetModules();
  return import('./action-schema');
}

const D = b64u(new Uint8Array(32).fill(7));
const SIG64 = b64u(new Uint8Array(64).fill(9));
const floors = (o: Record<string, unknown> = {}) => ({ risk: 0, rev: 'reversible', blast_ppm: 0, esc: 0, caveats: [], context: [], prules: [], ...o });
const param = (o: Record<string, unknown> = {}) => ({ type: 'string', semantic: 's', sensitivity: 'free', ...o });
const verb = (o: Record<string, unknown> = {}) => ({ verb: 'a.b', kind: 'write', params: { 'action.params.x': param() }, effects: ['update'], traits: [], def: D, floors: floors(), ...o });
const doc = (o: Record<string, unknown> = {}) => ({ v: 2, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', verbs: [verb()], ...o });
const conf = (o: Record<string, unknown> = {}) => ({ def_digest: D, traits_digest: D, facts_digest: D, final_traits: [], dismissed: [], reviewer_kid: 'r1', ts: 0, sig: SIG64, ...o });
const shape = (d: unknown, m: typeof S = S) => m.actionSchemaShapeError(d, { signed: false });
const pErr = (o: Record<string, unknown>, path = 'action.params.x', m: typeof S = S) => shape(doc({ verbs: [verb({ params: { [path]: param(o) } })] }), m);
const vErr = (o: Record<string, unknown>, m: typeof S = S) => shape(doc({ verbs: [verb(o)] }), m);
const AT = "verb 'a.b': ";
const X = 'action.params.x: ';
const ids = (n: number) => Array.from({ length: n }, (_, i) => 'a.t' + String(i).padStart(2, '0'));

describe('published v2 vocabularies (fresh module)', () => {
  it('are exactly the normative lists', async () => {
    const m = await fresh();
    expect(m.PARAM_TYPES_V2).toStrictEqual(['string', 'integer', 'boolean', 'date', 'set', 'array', 'datetime', 'duration', 'object_ref']);
    expect(m.SCHEMA_V2_EFFECTS).toStrictEqual(['read', 'create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign']);
    expect(m.SCHEMA_V2_CAVEATS).toStrictEqual(['amount_cap', 'count_cap', 'window', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap']);
    expect(m.SCHEMA_V2_PRULES).toStrictEqual(['array_bounded', 'export_bounded', 'id_not_wildcard', 'money_amount_bounded', 'money_has_currency', 'pay_has_idempotency', 'recipient_param_declared', 'secret_not_logged']);
    expect(m.SCHEMA_V2_CONTEXT).toStrictEqual(['approval_ref', 'dry_run_first', 'fresh_revocation', 'idempotency', 'revocable', 'sandbox_attested']);
    expect(m.SCHEMA_V2_TAGS).toStrictEqual(['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql']);
    expect(m.SCHEMA_V2_PROVENANCE).toStrictEqual(['first_party', 'tool', 'agent']);
  });
  it('the v2 parameter path accepts 1..3 dotted segments of 1..64 word characters and nothing else', async () => {
    const { PARAM_PATH_RE_V2: re } = await fresh();
    const ok = ['action.params.a', 'action.params.ab', 'action.params.a.b', 'action.params.ab.cd', 'action.params.a.b.c', 'action.params.A_9.b_0.C', `action.params.${'a'.repeat(64)}`, `action.params.${'a'.repeat(64)}.${'b'.repeat(64)}.${'c'.repeat(64)}`];
    for (const p of ok) expect(re.test(p), p).toBe(true);
    const bad = ['action.params.', 'action.params.a.b.c.d', `action.params.${'a'.repeat(65)}`, `action.params.a.${'b'.repeat(65)}`, 'action.params.a.', 'action.params..a', 'action.params.a-b', 'action.params.a.b-c', 'action.params.a b', 'Xaction.params.a', ' action.params.a', 'action.params.a!', 'action.params.a.b!', 'action.params.a\n', 'action.params.-', 'action.params.a.-', 'action.params.a.b.-'];
    for (const p of bad) expect(re.test(p), p).toBe(false);
  });
});

describe('v2 member sets (fresh module)', () => {
  it('a fully populated v2 document is well-formed: every v2 document, verb and parameter member is known', async () => {
    const m = await fresh();
    const full = doc({
      traits_digest: D,
      trait_defs: [{}],
      pack: { ns: 'ns', version: '1', root: D },
      verbs: [verb({
        traits: ['a.x'],
        confirmation: conf(),
        params: { 'action.params.x': param({ role: 'money.amount', format: 'email', tags: ['pii'], provenance_min: 'tool' }) },
      })],
    });
    expect(shape(full, m)).toBeNull();
  });
  it('a v1 document and a v1 verb or parameter carry none of the v2 members', async () => {
    const m = await fresh();
    const v1 = { v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', verbs: [{ verb: 'a.b', kind: 'write', params: { 'action.params.x': { type: 'integer', semantic: 's', sensitivity: 'free' } } }] };
    expect(shape(v1, m)).toBeNull();
    for (const k of ['traits_digest', 'trait_defs', 'pack']) expect(shape({ ...v1, [k]: D }, m), k).toBe(`unknown member '${k}'`);
    for (const k of ['traits', 'def', 'floors', 'confirmation', 'effects2']) {
      const vv = { ...v1.verbs[0], [k]: D };
      expect(shape({ ...v1, verbs: [vv] }, m), k).toBe(`verb entry: unknown member '${k}'`);
    }
    for (const k of ['role', 'format', 'tags', 'provenance_min']) {
      const vv = { verb: 'a.b', kind: 'write', params: { 'action.params.x': { type: 'string', semantic: 's', sensitivity: 'free', [k]: 'x' } } };
      expect(shape({ ...v1, verbs: [vv] }, m), k).toBe(`verb 'a.b': action.params.x: unknown member '${k}'`);
    }
  });
  it('a v2 document names its own version for the member set: v1 documents refuse v2 members, other versions are unsupported', () => {
    expect(shape(doc({ v: 3, traits_digest: D }))).toBe("unknown member 'traits_digest'");
    expect(shape(doc({ v: 3 }))).toBe('unsupported schema version');
    expect(shape(doc({ v: 1, pack: { ns: 'n', version: '1', root: D } }))).toBe("unknown member 'pack'");
    expect(shape(doc())).toBeNull();
  });
});

describe('v2 parameter members', () => {
  it('role is a non-empty string of at most 128 bytes', () => {
    expect(pErr({ role: 'money.amount' })).toBeNull();
    expect(pErr({ role: 'r'.repeat(128) })).toBeNull();
    for (const bad of ['', 'r'.repeat(129), 5, null, ['x']]) expect(pErr({ role: bad }), String(bad)).toBe(`${AT}${X}role must be a non-empty string`);
  });
  it('format is a known format, on a string or object_ref parameter only', () => {
    const msg = `${AT}${X}format must be a known format on a string parameter`;
    expect(pErr({ format: 'email' })).toBeNull();
    expect(pErr({ format: 'id:user.account' })).toBeNull();
    expect(pErr({ type: 'object_ref', format: 'uuid' })).toBeNull();
    expect(pErr({ format: 'bogus' })).toBe(msg);
    expect(pErr({ format: 5 })).toBe(msg);
    expect(pErr({ format: ['email'] })).toBe(msg); // an array coerces to the known name 'email': still not a string
    expect(pErr({ type: 'integer', format: 'email' })).toBe(msg);
    expect(pErr({ type: 'boolean', format: 'email' })).toBe(msg);
    expect(pErr({ type: 'datetime', format: 'email' })).toBe(msg);
    expect(pErr({ type: 'object_ref', format: 'bogus' })).toBe(msg);
  });
  it('tags are distinct known tags', () => {
    const msg = `${AT}${X}tags must be distinct known tags`;
    expect(pErr({ tags: [] })).toBeNull();
    expect(pErr({ tags: ['pii', 'secret'] })).toBeNull();
    expect(pErr({ tags: [...S.SCHEMA_V2_TAGS] })).toBeNull(); // all nine: the length bound is inclusive
    expect(pErr({ tags: 'pii' })).toBe(msg);
    expect(pErr({ tags: { 0: 'pii', length: 1 } })).toBe(msg);
    expect(pErr({ tags: ['pii', 'pii'] })).toBe(msg);
    expect(pErr({ tags: ['nope'] })).toBe(msg);
    expect(pErr({ tags: ['pii', 'nope'] })).toBe(msg);
    expect(pErr({ tags: [...S.SCHEMA_V2_TAGS, 'pii'] })).toBe(msg);
    expect(pErr({ tags: [5] })).toBe(msg);
  });
  it('provenance_min is one of first_party, tool, agent', () => {
    for (const p of ['first_party', 'tool', 'agent']) expect(pErr({ provenance_min: p }), p).toBeNull();
    for (const bad of ['human', '', 5]) expect(pErr({ provenance_min: bad }), String(bad)).toBe(`${AT}${X}unknown provenance_min`);
  });
  it('a duration takes integer bounds; no other v2 type except integer does', () => {
    expect(pErr({ type: 'duration', min: 0, max: 10 })).toBeNull();
    expect(pErr({ type: 'duration', max: 5 })).toBeNull();
    expect(pErr({ type: 'duration', min: 5 })).toBeNull();
    expect(pErr({ type: 'duration', min: 6, max: 5 })).toBe(`${AT}${X}min > max`);
    expect(pErr({ type: 'duration', min: 1.5 })).toBe(`${AT}${X}min must be a safe integer on an integer parameter`);
    expect(pErr({ type: 'string', min: 1 })).toBe(`${AT}${X}min must be a safe integer on an integer parameter`);
    expect(pErr({ type: 'datetime', max: 1 })).toBe(`${AT}${X}max must be a safe integer on an integer parameter`);
    expect(pErr({ type: 'object_ref', min: 1 })).toBe(`${AT}${X}min must be a safe integer on an integer parameter`);
    expect(pErr({ type: 'integer', min: 1, max: 2 })).toBeNull();
  });
  it('the three v2 types exist in a v2 document only', async () => {
    const m = await fresh();
    for (const t of ['datetime', 'duration', 'object_ref']) {
      expect(pErr({ type: t }, 'action.params.x', m), t).toBeNull();
      const v1 = { v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', verbs: [{ verb: 'a.b', kind: 'write', params: { 'action.params.x': { type: t, semantic: 's', sensitivity: 'free' } } }] };
      expect(shape(v1, m), t).toBe(`${AT}${X}unknown type`);
    }
  });
  it('dotted parameter paths exist in v2 only and a reserved segment anywhere is refused', () => {
    expect(pErr({}, 'action.params.a.b.c')).toBeNull();
    expect(pErr({}, 'action.params.a.b.c.d')).toBe(`${AT}parameter path 'action.params.a.b.c.d' is not action.params.<name>`);
    expect(pErr({}, 'action.params.a.__proto__')).toBe(`${AT}parameter name 'action.params.a.__proto__' is reserved (__proto__ / constructor / prototype)`);
    expect(pErr({}, 'action.params.constructor.a')).toBe(`${AT}parameter name 'action.params.constructor.a' is reserved (__proto__ / constructor / prototype)`);
    expect(pErr({}, 'action.params.a.prototype.b')).toBe(`${AT}parameter name 'action.params.a.prototype.b' is reserved (__proto__ / constructor / prototype)`);
    expect(pErr({}, 'action.params.constructor')).toBe(`${AT}parameter name 'action.params.constructor' is reserved (__proto__ / constructor / prototype)`);
    expect(pErr({}, 'action.params.constructors.a')).toBeNull();
    const v1 = { v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', verbs: [{ verb: 'a.b', kind: 'write', params: { 'action.params.a.b': { type: 'string', semantic: 's', sensitivity: 'free' } } }] };
    expect(shape(v1)).toBe(`${AT}parameter path 'action.params.a.b' is not action.params.<name>`);
  });
  it('no parameter is both a value and the parent of another', () => {
    const two = (a: string, b: string) => shape(doc({ verbs: [verb({ params: { [a]: param(), [b]: param() } })] }));
    expect(two('action.params.a', 'action.params.a.b')).toBe(`${AT}parameter 'action.params.a' is both a value and the parent of 'action.params.a.b'`);
    expect(two('action.params.a.b', 'action.params.a')).toBe(`${AT}parameter 'action.params.a' is both a value and the parent of 'action.params.a.b'`);
    expect(two('action.params.a', 'action.params.a.b.c')).toBe(`${AT}parameter 'action.params.a' is both a value and the parent of 'action.params.a.b.c'`);
    expect(two('action.params.a', 'action.params.ab')).toBeNull();
    expect(two('action.params.a.b', 'action.params.a.c')).toBeNull();
    expect(two('action.params.a', 'action.params.b.a')).toBeNull();
  });
});

describe('schemaFloorsError', () => {
  it('a well-formed profile is accepted with every member present', () => {
    expect(S.schemaFloorsError(floors())).toBeNull();
    expect(S.schemaFloorsError(floors({ risk: 3, esc: 3, rev: 'irreversible', blast_ppm: 1_000_000, caveats: ['amount_cap', 'count_cap'], context: ['approval_ref', 'dry_run_first'], prules: ['array_bounded', 'export_bounded'] }))).toBeNull();
  });
  it('must be a plain object with the seven known members', () => {
    for (const bad of [null, undefined, 5, 'x', [], [floors()]]) expect(S.schemaFloorsError(bad), String(bad)).toBe('floors must be an object');
    expect(S.schemaFloorsError({ ...floors(), extra: 1 })).toBe("floors: unknown member 'extra'");
    for (const k of ['risk', 'rev', 'blast_ppm', 'esc', 'caveats', 'context', 'prules']) {
      const f: Record<string, unknown> = floors();
      delete f[k];
      expect(S.schemaFloorsError(f), k).not.toBeNull();
    }
  });
  it('risk and esc are integers in 0..3, each on its own', () => {
    const msg = 'floors.risk and floors.esc must be integers in 0..3';
    for (const ok of [0, 1, 2, 3]) {
      expect(S.schemaFloorsError(floors({ risk: ok })), `risk ${ok}`).toBeNull();
      expect(S.schemaFloorsError(floors({ esc: ok })), `esc ${ok}`).toBeNull();
    }
    for (const bad of [-1, 4, 1.5, '1', null, NaN, -0]) {
      expect(S.schemaFloorsError(floors({ risk: bad })), `risk ${String(bad)}`).toBe(msg);
      expect(S.schemaFloorsError(floors({ esc: bad })), `esc ${String(bad)}`).toBe(msg);
    }
  });
  it('rev is a reversibility class', () => {
    for (const ok of ['reversible', 'rate_limited', 'irreversible']) expect(S.schemaFloorsError(floors({ rev: ok })), ok).toBeNull();
    for (const bad of ['bogus', '', 1, undefined]) expect(S.schemaFloorsError(floors({ rev: bad })), String(bad)).toBe('floors.rev is not a reversibility class');
  });
  it('blast_ppm is an integer in 0..1000000', () => {
    const msg = 'floors.blast_ppm must be an integer in 0..1000000';
    for (const ok of [0, 1, 999_999, 1_000_000]) expect(S.schemaFloorsError(floors({ blast_ppm: ok })), String(ok)).toBeNull();
    for (const bad of [-1, 1_000_001, 0.5, '5', null]) expect(S.schemaFloorsError(floors({ blast_ppm: bad })), String(bad)).toBe(msg);
  });
  it('caveats, context and prules are sorted, distinct arrays of known entries', () => {
    for (const [name, ok, other] of [['caveats', 'amount_cap', 'array_bounded'], ['context', 'approval_ref', 'amount_cap'], ['prules', 'array_bounded', 'amount_cap']] as const) {
      const known = `floors.${name} must be an array of known entries`;
      const sorted = `floors.${name} must be sorted and distinct`;
      expect(S.schemaFloorsError(floors({ [name]: [ok] })), name).toBeNull();
      expect(S.schemaFloorsError(floors({ [name]: [other] })), `${name} cross`).toBe(known);
      expect(S.schemaFloorsError(floors({ [name]: 'x' })), `${name} string`).toBe(known);
      expect(S.schemaFloorsError(floors({ [name]: [5] })), `${name} number`).toBe(known);
      expect(S.schemaFloorsError(floors({ [name]: undefined })), `${name} missing`).toBe(known);
      expect(S.schemaFloorsError(floors({ [name]: [ok, 'nope'] })), `${name} unknown`).toBe(known);
      expect(S.schemaFloorsError(floors({ [name]: [ok, ok] })), `${name} dup`).toBe(sorted);
      expect(S.schemaFloorsError(floors({ [name]: Array.from({ length: 65 }, () => ok) })), `${name} 65`).toBe(known);
      expect(S.schemaFloorsError(floors({ [name]: Array.from({ length: 64 }, () => ok) })), `${name} 64`).toBe(sorted);
    }
    expect(S.schemaFloorsError(floors({ caveats: ['count_cap', 'amount_cap'] }))).toBe('floors.caveats must be sorted and distinct');
    expect(S.schemaFloorsError(floors({ caveats: ['amount_cap', 'count_cap', 'window'] }))).toBeNull();
    expect(S.schemaFloorsError(floors({ prules: ['export_bounded', 'array_bounded'] }))).toBe('floors.prules must be sorted and distinct');
    expect(S.schemaFloorsError(floors({ context: ['dry_run_first', 'approval_ref'] }))).toBe('floors.context must be sorted and distinct');
    expect(S.schemaFloorsError(floors({ context: ['approval_ref', 'dry_run_first', 'fresh_revocation', 'idempotency', 'revocable', 'sandbox_attested'] }))).toBeNull();
  });
  it('the context set also takes session_taint_max:<level>, exactly 1..16 lowercase letters or underscores', async () => {
    const { schemaFloorsError } = await fresh();
    const ctx = (x: string) => schemaFloorsError(floors({ context: [x] }));
    for (const ok of ['session_taint_max:low', 'session_taint_max:a', 'session_taint_max:a_b', 'session_taint_max:_', `session_taint_max:${'a'.repeat(16)}`]) expect(ctx(ok), ok).toBeNull();
    const bad = ['session_taint_max:', 'session_taint_max:Low', 'session_taint_max:l0w', `session_taint_max:${'a'.repeat(17)}`, 'xsession_taint_max:low', ' session_taint_max:low', 'session_taint_max:low!', 'session_taint_max:low x', 'session_taint_max:lo-w', 'session_taint_max'];
    for (const b of bad) expect(ctx(b), b).toBe('floors.context must be an array of known entries');
    expect(schemaFloorsError(floors({ context: ['approval_ref', 'session_taint_max:low'] }))).toBeNull();
    expect(schemaFloorsError(floors({ context: ['session_taint_max:low', 'session_taint_max:high'] }))).toBe('floors.context must be sorted and distinct');
    expect(schemaFloorsError(floors({ caveats: ['session_taint_max:low'] }))).toBe('floors.caveats must be an array of known entries');
    expect(ctx(['session_taint_max:low'] as unknown as string)).toBe('floors.context must be an array of known entries'); // an array coerces to the pattern text: still not a string
  });
});

describe('confirmationShapeError', () => {
  it('accepts a well-formed confirmation', () => {
    expect(S.confirmationShapeError(conf())).toBeNull();
    expect(S.confirmationShapeError(conf({ final_traits: ['a.x', 'b.y'], dismissed: [{ trait: 'a.x', reason: 'r' }], ts: 1_700_000_000 }))).toBeNull();
  });
  it('must be a plain object with the eight known members', () => {
    for (const bad of [null, undefined, 5, 'x', []]) expect(S.confirmationShapeError(bad), String(bad)).toBe('confirmation must be an object');
    expect(S.confirmationShapeError({ ...conf(), extra: 1 })).toBe("confirmation: unknown member 'extra'");
    for (const k of ['def_digest', 'traits_digest', 'facts_digest', 'final_traits', 'dismissed', 'reviewer_kid', 'ts', 'sig']) {
      const c: Record<string, unknown> = conf();
      delete c[k];
      expect(S.confirmationShapeError(c), k).not.toBeNull();
    }
  });
  it('each of the three digests and the signature are canonical base64url of the exact size', () => {
    const dmsg = 'confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests';
    for (const k of ['def_digest', 'traits_digest', 'facts_digest']) {
      expect(S.confirmationShapeError(conf({ [k]: b64u(new Uint8Array(31)) })), k).toBe(dmsg);
      expect(S.confirmationShapeError(conf({ [k]: b64u(new Uint8Array(33)) })), `${k} long`).toBe(dmsg);
      expect(S.confirmationShapeError(conf({ [k]: 5 })), `${k} number`).toBe(dmsg);
      expect(S.confirmationShapeError(conf({ [k]: `${D}=` })), `${k} padded`).toBe(dmsg);
    }
    const smsg = 'confirmation: sig must be a canonical base64url 64-byte signature';
    expect(S.confirmationShapeError(conf({ sig: b64u(new Uint8Array(63)) }))).toBe(smsg);
    expect(S.confirmationShapeError(conf({ sig: b64u(new Uint8Array(65)) }))).toBe(smsg);
    expect(S.confirmationShapeError(conf({ sig: 1 }))).toBe(smsg);
  });
  it('final_traits are at most 64 sorted, distinct trait ids', async () => {
    const m = await fresh();
    const ft = (x: unknown) => m.confirmationShapeError(conf({ final_traits: x }));
    expect(ft(ids(64))).toBeNull();
    expect(ft(ids(65))).toBe('confirmation: final_traits must be trait ids');
    expect(ft('a.x')).toBe('confirmation: final_traits must be trait ids');
    expect(ft({ length: 0 })).toBe('confirmation: final_traits must be trait ids');
    expect(ft([5])).toBe('confirmation: final_traits must be trait ids');
    expect(ft([['a.x']])).toBe('confirmation: final_traits must be trait ids');
    expect(ft(['Bad'])).toBe('confirmation: final_traits must be trait ids');
    expect(ft(['b.y', 'a.x'])).toBe('confirmation: final_traits must be sorted and distinct');
    expect(ft(['a.x', 'a.x'])).toBe('confirmation: final_traits must be sorted and distinct');
    expect(ft(['a.x', 'a.y', 'b.a'])).toBeNull();
    // the trait-id grammar
    const good = ['a.b', 'a_1.b_2', 'z9.a0', `a${'0'.repeat(31)}.b`, `a.b${'0'.repeat(63)}`, `a${'0'.repeat(31)}.b${'0'.repeat(63)}`, 'ab.cd_ef'];
    for (const g of good) expect(ft([g]), g).toBeNull();
    const bad = [`a${'0'.repeat(32)}.b`, `a.b${'0'.repeat(64)}`, 'A.b', 'a.B', '1a.b', 'a.1b', '_a.b', 'a._b', 'a', 'a.', '.b', 'a.b.c', ' a.b', 'a.b ', 'xA.b!', 'a-b.c', 'a.b-c', 'a.b\n', '', 'a b.c'];
    for (const b of bad) expect(ft([b]), b).toBe('confirmation: final_traits must be trait ids');
  });
  it('dismissed is at most 64 {trait, reason} entries', () => {
    const dm = (x: unknown) => S.confirmationShapeError(conf({ dismissed: x }));
    const entry = { trait: 'a.x', reason: 'r' };
    expect(dm(Array.from({ length: 64 }, () => entry))).toBeNull();
    expect(dm(Array.from({ length: 65 }, () => entry))).toBe('confirmation: dismissed must be an array');
    expect(dm('x')).toBe('confirmation: dismissed must be an array');
    expect(dm({ length: 0 })).toBe('confirmation: dismissed must be an array');
    const em = 'confirmation: dismissed entries must be {trait, reason}';
    expect(dm([5])).toBe(em);
    expect(dm([[entry]])).toBe(em);
    expect(dm([{ trait: 'a.x' }])).toBe(em);
    expect(dm([{ reason: 'r' }])).toBe(em);
    expect(dm([{ trait: 'a.x', reason: 'r', extra: 1 }])).toBe(em);
    expect(dm([{ trait: ['a.x'], reason: 'r' }])).toBe(em);
    expect(dm([{ trait: 'Bad', reason: 'r' }])).toBe(em);
    expect(dm([{ trait: 'a.x', reason: '' }])).toBe(em);
    expect(dm([{ trait: 'a.x', reason: 5 }])).toBe(em);
    expect(dm([{ trait: 'a.x', reason: 'r'.repeat(256) }])).toBeNull();
    expect(dm([{ trait: 'a.x', reason: 'r'.repeat(257) }])).toBe(em);
  });
  it('reviewer_kid is a non-empty string of at most 128 bytes and ts a non-negative safe integer', () => {
    const km = 'confirmation: reviewer_kid must be a non-empty string';
    expect(S.confirmationShapeError(conf({ reviewer_kid: 'k'.repeat(128) }))).toBeNull();
    for (const bad of ['', 'k'.repeat(129), 5, undefined]) expect(S.confirmationShapeError(conf({ reviewer_kid: bad })), String(bad)).toBe(km);
    const tm = 'confirmation: ts must be a non-negative safe integer';
    for (const ok of [0, 1, Number.MAX_SAFE_INTEGER]) expect(S.confirmationShapeError(conf({ ts: ok })), String(ok)).toBeNull();
    for (const bad of [-1, -0, 1.5, Number.MAX_SAFE_INTEGER + 1, '1', null, NaN, Infinity]) expect(S.confirmationShapeError(conf({ ts: bad })), String(bad)).toBe(tm);
  });
});

describe('v2 verb members', () => {
  it('effects are 1..12 known, sorted, distinct effects', () => {
    const em = `${AT}effects must be 1..12 known effects`;
    const sorted = ['create', 'delete', 'exec', 'export', 'pay', 'privilege', 'provision', 'publish', 'read', 'send', 'sign', 'update'];
    expect(vErr({ effects: sorted })).toBeNull(); // all twelve, kind write
    expect(vErr({ effects: ['update'] })).toBeNull();
    expect(vErr({ effects: ['create', 'update'] })).toBeNull();
    expect(vErr({ effects: [...sorted, 'update'] })).toBe(em);
    expect(vErr({ effects: [] })).toBe(em);
    expect(vErr({ effects: 'update' })).toBe(em);
    expect(vErr({ effects: {} })).toBe(em);
    expect(vErr({ effects: undefined })).toBe(em);
    expect(vErr({ effects: ['nope'] })).toBe(em);
    expect(vErr({ effects: ['update', 'nope'] })).toBe(em);
    expect(vErr({ effects: [5] })).toBe(em);
    expect(vErr({ effects: ['update', 'create'] })).toBe(`${AT}effects must be sorted and distinct`);
    expect(vErr({ effects: ['update', 'update'] })).toBe(`${AT}effects must be sorted and distinct`);
    expect(vErr({ effects: ['create', 'create', 'update'] })).toBe(`${AT}effects must be sorted and distinct`);
  });
  it('kind read holds exactly when every effect is read', () => {
    const km = `${AT}kind read must hold exactly when every effect is read`;
    expect(vErr({ kind: 'read', effects: ['read'] })).toBeNull();
    expect(vErr({ kind: 'write', effects: ['update'] })).toBeNull();
    expect(vErr({ kind: 'write', effects: ['read', 'update'] })).toBeNull();
    expect(vErr({ kind: 'read', effects: ['update'] })).toBe(km);
    expect(vErr({ kind: 'write', effects: ['read'] })).toBe(km);
    expect(vErr({ kind: 'read', effects: ['read', 'update'] })).toBe(km);
    expect(vErr({ kind: 'delete', effects: ['read'] })).toBe(`${AT}kind must be read or write`);
  });
  it('traits are at most 64 sorted, distinct trait ids', () => {
    const tm = `${AT}traits must be trait ids`;
    expect(vErr({ traits: ids(64) })).toBeNull();
    expect(vErr({ traits: ids(65) })).toBe(tm);
    expect(vErr({ traits: 'a.x' })).toBe(tm);
    expect(vErr({ traits: undefined })).toBe(tm);
    expect(vErr({ traits: [5] })).toBe(tm);
    expect(vErr({ traits: [['a.x']] })).toBe(tm);
    expect(vErr({ traits: ['Bad'] })).toBe(tm);
    expect(vErr({ traits: ['b.y', 'a.x'] })).toBe(`${AT}traits must be sorted and distinct`);
    expect(vErr({ traits: ['a.x', 'a.x'] })).toBe(`${AT}traits must be sorted and distinct`);
    expect(vErr({ traits: ['a.x', 'a.y', 'b.a'] })).toBeNull();
    const good = ['a.b', 'a_1.b_2', `a${'0'.repeat(31)}.b`, `a.b${'0'.repeat(63)}`];
    for (const g of good) expect(vErr({ traits: [g] }), g).toBeNull();
    const bad = [`a${'0'.repeat(32)}.b`, `a.b${'0'.repeat(64)}`, 'A.b', 'a.B', '1a.b', 'a.1b', 'a', 'a.', '.b', 'a.b.c', ' a.b', 'a.b ', 'a-b.c', 'a.b-c', '', 'a.b\n'];
    for (const b of bad) expect(vErr({ traits: [b] }), b).toBe(tm);
  });
  it('def is a canonical base64url SHA-256 digest', () => {
    const dm = `${AT}def must be a canonical base64url SHA-256 digest`;
    expect(vErr({ def: b64u(new Uint8Array(31)) })).toBe(dm);
    expect(vErr({ def: b64u(new Uint8Array(33)) })).toBe(dm);
    expect(vErr({ def: undefined })).toBe(dm);
    expect(vErr({ def: 5 })).toBe(dm);
  });
  it('floors are required and checked, with the verb named in the refusal', () => {
    expect(vErr({ floors: undefined })).toBe(`${AT}floors must be an object`);
    expect(vErr({ floors: floors({ risk: 9 }) })).toBe(`${AT}floors.risk and floors.esc must be integers in 0..3`);
    expect(vErr({ floors: floors({ caveats: ['nope'] }) })).toBe(`${AT}floors.caveats must be an array of known entries`);
  });
  it('a confirmation is optional but, when present, checked', () => {
    expect(vErr({})).toBeNull();
    expect(vErr({ confirmation: conf() })).toBeNull();
    expect(vErr({ confirmation: 5 })).toBe(`${AT}confirmation must be an object`);
    expect(vErr({ confirmation: null })).toBe(`${AT}confirmation must be an object`);
    expect(vErr({ confirmation: conf({ ts: -1 }) })).toBe(`${AT}confirmation: ts must be a non-negative safe integer`);
    expect(vErr({ confirmation: conf({ reviewer_kid: '' }) })).toBe(`${AT}confirmation: reviewer_kid must be a non-empty string`);
  });
  it('a v1 verb keeps its reserved effects object and has none of the v2 requirements', () => {
    const v1 = (vb: Record<string, unknown>) => shape({ v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', verbs: [{ verb: 'a.b', kind: 'write', params: { 'action.params.x': { type: 'integer', semantic: 's', sensitivity: 'free' } }, ...vb }] });
    expect(v1({})).toBeNull();
    expect(v1({ effects: { read: true } })).toBeNull();
    expect(v1({ effects: ['update'] })).toBe(`${AT}effects must be an object`);
    expect(v1({ harm: [] })).toBe(`${AT}harm must be an object`);
    expect(v1({ returns: 'x' })).toBe(`${AT}returns must be an object`);
    expect(v1({ effects: [] })).toBe(`${AT}effects must be an object`);
  });
  it('in a v2 verb harm and returns are objects and effects is the list', () => {
    expect(vErr({ harm: [] })).toBe(`${AT}harm must be an object`);
    expect(vErr({ returns: [] })).toBe(`${AT}returns must be an object`);
    expect(vErr({ harm: {}, returns: {} })).toBeNull();
    expect(vErr({ effects: {} })).toBe(`${AT}effects must be 1..12 known effects`);
  });
});

describe('v2 document members', () => {
  it('traits_digest is a canonical base64url SHA-256 digest', () => {
    expect(shape(doc({ traits_digest: D }))).toBeNull();
    const msg = 'traits_digest must be a canonical base64url SHA-256 digest';
    expect(shape(doc({ traits_digest: b64u(new Uint8Array(31)) }))).toBe(msg);
    expect(shape(doc({ traits_digest: 5 }))).toBe(msg);
    expect(shape(doc({ traits_digest: '' }))).toBe(msg);
  });
  it('trait_defs are at most 64 objects', () => {
    const msg = 'trait_defs must be an array of up to 64 objects';
    expect(shape(doc({ trait_defs: [] }))).toBeNull();
    expect(shape(doc({ trait_defs: Array.from({ length: 64 }, () => ({})) }))).toBeNull();
    expect(shape(doc({ trait_defs: Array.from({ length: 65 }, () => ({})) }))).toBe(msg);
    expect(shape(doc({ trait_defs: {} }))).toBe(msg);
    expect(shape(doc({ trait_defs: 'x' }))).toBe(msg);
    expect(shape(doc({ trait_defs: [{}, 5] }))).toBe(msg);
    expect(shape(doc({ trait_defs: [[]] }))).toBe(msg);
    expect(shape(doc({ trait_defs: [null] }))).toBe(msg);
  });
  it('pack is exactly {ns, version, root}', () => {
    const msg = 'pack must be {ns, version, root}';
    const pk = (o: Record<string, unknown> = {}) => ({ ns: 'ns', version: '1', root: D, ...o });
    expect(shape(doc({ pack: pk() }))).toBeNull();
    expect(shape(doc({ pack: { version: '1', root: D, ns: 'ns' } }))).toBeNull(); // member order is irrelevant
    expect(shape(doc({ pack: pk({ ns: 'n'.repeat(64), version: 'v'.repeat(128) }) }))).toBeNull();
    expect(shape(doc({ pack: 5 }))).toBe(msg);
    expect(shape(doc({ pack: [] }))).toBe(msg);
    expect(shape(doc({ pack: null }))).toBe(msg);
    expect(shape(doc({ pack: pk({ extra: 1 }) }))).toBe(msg);
    expect(shape(doc({ pack: { ns: 'ns', version: '1' } }))).toBe(msg);
    expect(shape(doc({ pack: { ns: 'ns', root: D, other: '1' } }))).toBe(msg);
    expect(shape(doc({ pack: pk({ ns: '' }) }))).toBe(msg);
    expect(shape(doc({ pack: pk({ ns: 'n'.repeat(65) }) }))).toBe(msg);
    expect(shape(doc({ pack: pk({ ns: 5 }) }))).toBe(msg);
    expect(shape(doc({ pack: pk({ version: '' }) }))).toBe(msg);
    expect(shape(doc({ pack: pk({ version: 'v'.repeat(129) }) }))).toBe(msg);
    expect(shape(doc({ pack: pk({ root: b64u(new Uint8Array(31)) }) }))).toBe(msg);
    expect(shape(doc({ pack: pk({ root: 5 }) }))).toBe(msg);
  });
  it('a v1 document does not check the v2 members it cannot carry', () => {
    const v1 = { v: 1, kind: 'pca-action-schema', site: 'https://s.example', aud: 's.example', version: '1', verbs: [{ verb: 'a.b', kind: 'write', params: {} }] };
    expect(shape(v1)).toBeNull();
    expect(shape({ ...v1, traits_digest: 5 })).toBe("unknown member 'traits_digest'");
  });
});
