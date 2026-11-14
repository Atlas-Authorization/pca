import { describe, expect, it } from 'vitest';
import { b64u, hashCanonical } from './hash';
import { publicKeyOf } from './keys';
import {
  READ_GRANT_DOMAIN,
  READ_RECEIPT_DOMAIN,
  checkSink,
  readChainLabels,
  readGrantDigest,
  readReceiptRef,
  redactRead,
  signReadGrant,
  validReadGrantBody,
  type ReadField,
  type ReadGrantBody,
  type ReadInput,
  type ReadReceipt,
} from './readside';
import { signBody } from './workflow';

const P = new Uint8Array(32).fill(71);
const PK = b64u(publicKeyOf(P));
const Y = new Uint8Array(32).fill(72);
const YPK = b64u(publicKeyOf(Y));
const R = new Uint8Array(32).fill(73);
const RPK = b64u(publicKeyOf(R));
const NOW = 1_800_000_000_000;
const SALT = 'a-per-read-secret-salt';

const body: ReadGrantBody = {
  v: 1, id: 'rg', principal: PK, issued_at: NOW - 1000, expires_at: NOW + 1000,
  reads: [{ verb: 'customers.get', resource_prefix: 'customers/', purposes: ['support'], modes: { pii: 'last4', fin: 'bucket:10', tok: 'token', open: 'show', hsh: 'hash' }, default_mode: 'drop' }],
  caps: {},
  sinks: { payments: { allow: ['pii'], escalate: ['fin'] }, email: { allow: [], escalate: [] } },
};
const grant = signReadGrant(P, body);
const DIGEST = readGrantDigest(body);

const rd = (o: Partial<ReadInput> = {}) =>
  redactRead({ grant, principal: PK, now: NOW, verb: 'customers.get', resource: 'customers/1', purpose: 'support', schema: { fields: {}, required: [] }, record: {}, tighten: {}, salt: SALT, counts: {}, ...o });
const deny = (code: string, counts: Record<string, number> = {}) => ({ decision: 'deny', code, view: {}, fields: {}, labels: [], counts });
const resign = (b: unknown) => ({ body: b, sig: signBody(P, READ_GRANT_DOMAIN, b) });

describe('read grant shape', () => {
  const v = (patch: Record<string, unknown>) => validReadGrantBody({ ...body, ...patch });
  const e = (patch: Record<string, unknown>) => v({ reads: [{ ...body.reads[0], ...patch }] });
  const keys = (n: number, mk: (k: string) => unknown) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${String(i).padStart(2, '0')}`, mk(`k${i}`)]));
  it('accepts the base grant and the stated boundaries', () => {
    expect(validReadGrantBody(body)).toBe(true);
    expect(v({ reads: Array.from({ length: 32 }, () => body.reads[0]) })).toBe(true);
    expect(v({ caps: keys(32, () => 1) })).toBe(true);
    expect(v({ sinks: keys(16, () => ({ allow: [], escalate: [] })) })).toBe(true);
    expect(e({ modes: keys(32, () => 'show') })).toBe(true);
    expect(e({ verb: 'v'.repeat(128), resource_prefix: 'p'.repeat(512), default_mode: 'bucket:999999999' })).toBe(true);
  });
  it('rejects a body that is not an exact object of version 1', () => {
    expect(validReadGrantBody(null)).toBe(false);
    expect(validReadGrantBody([])).toBe(false);
    expect(validReadGrantBody(Object.assign([], body))).toBe(false);
    expect(v({ extra: 1 })).toBe(false);
    expect(v({ v: 2 })).toBe(false);
    const { caps: _c, ...noCaps } = body;
    void _c;
    expect(validReadGrantBody(noCaps)).toBe(false);
  });
  it('rejects a bad id, principal or time', () => {
    for (const id of ['', 'a b', '__proto__', ['rg'], 5]) expect(v({ id })).toBe(false);
    for (const principal of ['abc', 5, null]) expect(v({ principal })).toBe(false);
    for (const t of [-1, 1.5, '5', null]) {
      expect(v({ issued_at: t })).toBe(false);
      expect(v({ expires_at: t })).toBe(false);
    }
  });
  it('rejects bad read lists, caps and sinks', () => {
    expect(v({ reads: [] })).toBe(false);
    expect(v({ reads: 'x' })).toBe(false);
    expect(v({ reads: Array.from({ length: 33 }, () => body.reads[0]) })).toBe(false);
    expect(v({ caps: [] })).toBe(false);
    expect(v({ caps: { 'Bad Key': 1 } })).toBe(false);
    expect(v({ caps: { x: -1 } })).toBe(false);
    expect(v({ caps: { x: 1.5 } })).toBe(false);
    expect(v({ caps: keys(33, () => 1) })).toBe(false);
    expect(v({ sinks: [] })).toBe(false);
    expect(v({ sinks: keys(17, () => ({ allow: [], escalate: [] })) })).toBe(false);
    expect(v({ sinks: { 'bad sink': { allow: [], escalate: [] } } })).toBe(false);
    expect(v({ sinks: { s: 5 } })).toBe(false);
    expect(v({ sinks: { s: { allow: [] } } })).toBe(false);
    expect(v({ sinks: { s: { allow: ['b', 'a'], escalate: [] } } })).toBe(false);
    expect(v({ sinks: { s: { allow: ['a'], escalate: ['a'] } } })).toBe(false);
  });
  it('rejects a bad read entry, one operand at a time', () => {
    expect(v({ reads: [5] })).toBe(false);
    expect(v({ reads: [Object.assign([], body.reads[0])] })).toBe(false);
    expect(e({ extra: 1 })).toBe(false);
    const { default_mode: _d, ...noDefault } = body.reads[0] as unknown as Record<string, unknown>;
    void _d;
    expect(v({ reads: [noDefault] })).toBe(false);
    for (const verb of ['', 'v'.repeat(129)]) expect(e({ verb })).toBe(false);
    for (const resource_prefix of ['', 'p'.repeat(513)]) expect(e({ resource_prefix })).toBe(false);
    for (const purposes of [[], ['b', 'a'], ['a', 'a'], ['bad purpose'], Array.from({ length: 17 }, (_, i) => `p${String(i).padStart(2, '0')}`), 'support']) expect(e({ purposes })).toBe(false);
    expect(e({ modes: [] })).toBe(false);
    expect(e({ modes: keys(33, () => 'show') })).toBe(false);
    expect(e({ modes: { 'Bad Key': 'show' } })).toBe(false);
    expect(e({ modes: { x: 'sh0w' } })).toBe(false);
    expect(e({ modes: { x: ['show'] } })).toBe(false);
    for (const m of ['bucket:0', 'bucket:1234567890', 'bucket:', 'xshow', 'showx', 5, ['show'], null]) expect(e({ default_mode: m })).toBe(false);
    expect(e({ default_mode: 'bucket:1' })).toBe(true);
  });
  it('signReadGrant refuses a malformed body or a body for another key', () => {
    expect(() => signReadGrant(P, { ...body, v: 2 } as never)).toThrow(RangeError);
    expect(() => signReadGrant(P, { ...body, v: 2 } as never)).toThrow('signReadGrant: malformed grant');
    expect(() => signReadGrant(Y, body)).toThrow('signReadGrant: malformed grant');
  });
});

describe('redactRead request checks', () => {
  it('refuses a malformed request with an exact bad_request refusal', () => {
    const cases: Partial<ReadInput>[] = [
      { principal: 'abc' }, { now: null as never }, { now: -1 }, { now: 1.5 },
      { verb: '' }, { verb: 'v'.repeat(129) }, { resource: '' }, { resource: `customers/${'r'.repeat(503)}` },
      { purpose: ['support'] as never }, { purpose: 'bad purpose' }, { purpose: '' },
      { salt: 'short-salt-15ch' }, { salt: Array.from({ length: 16 }, () => 'a') as never }, { salt: 5 as never },
      { schema: Object.assign([], { fields: {}, required: [] }) as never },
      { schema: null as never }, { schema: { fields: {} } as never }, { schema: { fields: {}, required: 'x' } as never },
      { schema: { fields: ['pii'], required: [] } as never, record: { '0': 'x' } },
      { schema: { fields: { ok: 'pii', 'bad key!': 'pii' }, required: [] } },
      { schema: { fields: { ok: 'pii', bad: 5 }, required: [] } as never },
      { schema: { fields: { ok: 'pii', bad: ['pii'] }, required: [] } as never },
      { schema: { fields: { ok: 'pii', bad: 'Bad Class' }, required: [] } },
      { schema: { fields: { '5': 'pii' }, required: [5] } as never, record: { '5': 'x' } },
      { schema: { fields: { a: 'pii' }, required: ['missing'] } },
      { schema: { fields: { a: 'pii' }, required: ['a', 'missing'] } },
      { record: { 'bad key': 'x' } }, { record: { a: null } as never },
      { tighten: { 'Bad Key': 'drop' } }, { tighten: { pii: 'nope' } }, { tighten: { pii: ['drop'] } as never },
      { counts: { 'Bad Key': 1 } }, { counts: { pii: -1 } }, { counts: { pii: 1.5 } }, { counts: [] as never },
    ];
    for (const c of cases) expect(rd(c), JSON.stringify(c)).toEqual(deny('bad_request'));
  });
  it('accepts a resource of exactly 512 characters', () => {
    expect(rd({ resource: `customers/${'r'.repeat(502)}` }).decision).toBe('allow');
  });
  it('a throwing request is a bad_request refusal', () => {
    expect(redactRead(null as never)).toEqual(deny('bad_request'));
  });
});

describe('redactRead grant checks', () => {
  it('names the exact refusal for each grant defect', () => {
    expect(rd({ grant: null })).toEqual(deny('bad_grant'));
    expect(rd({ grant: { ...grant, extra: 1 } })).toEqual(deny('bad_grant'));
    expect(rd({ grant: { body: { ...body, v: 2 }, sig: grant.sig } })).toEqual(deny('bad_grant'));
    expect(rd({ principal: YPK })).toEqual(deny('bad_signature'));
    // signed by the pinned principal but naming another principal in its body
    expect(rd({ grant: resign({ ...body, principal: YPK }) })).toEqual(deny('bad_signature'));
    expect(rd({ now: body.issued_at - 1 })).toEqual(deny('not_yet'));
    expect(rd({ now: body.expires_at })).toEqual(deny('expired'));
  });
  it('the validity window is [issued_at, expires_at)', () => {
    expect(rd({ now: body.issued_at }).decision).toBe('allow');
    expect(rd({ now: body.expires_at - 1 }).decision).toBe('allow');
  });
  it('refuses a request outside every read scope and keeps the caller counts', () => {
    expect(rd({ verb: 'customers.list', counts: { pii: 2 } })).toEqual(deny('no_read_scope', { pii: 2 }));
  });
});

describe('redactRead masking', () => {
  const schema = { fields: { c: 'pii', b: 'fin', a: 'open', t: 'tok', z: 'hsh' }, required: [] };
  it('orders fields and labels bytewise and masks per mode', () => {
    const r = rd({ schema, record: { z: 'zz', t: 'tt', c: '12345678', b: 1234, a: 'x' } });
    expect(r.decision).toBe('allow');
    expect(Object.keys(r.fields)).toEqual(['a', 'b', 'c', 't', 'z']);
    expect(r.labels).toEqual(['fin', 'hsh', 'open', 'pii', 'tok']);
    expect(r.view.a).toBe('x');
    expect(r.view.b).toBe(1230);
    expect(r.view.c).toBe('****5678');
    expect(r.view.z).toBe(hashCanonical({ d: 'atlas-pca/read-hash/v1', salt: SALT, c: 'hsh', v: 'zz' }));
    expect(r.view.t).toBe(`tok_${hashCanonical({ d: 'atlas-pca/read-token/v1', salt: SALT, c: 'tok', v: 'tt' }).slice(0, 22)}`);
  });
  it('a last4 value with an astral first character is not shown', () => {
    const r = rd({ schema: { fields: { c: 'pii' }, required: [] }, record: { c: '\u{10000}abcd' } });
    expect(r.fields.c).toMatchObject({ action: 'dropped', kind: null });
    expect(r.view).toEqual({});
    expect(rd({ schema: { fields: { c: 'pii' }, required: [] }, record: { c: '￿abcd' } }).view.c).toBe('****abcd');
  });
  it('a bucket mask applies to a number only', () => {
    const f = { fields: { b: 'fin' }, required: [] };
    expect(rd({ schema: f, record: { b: '55' } }).fields.b).toMatchObject({ action: 'dropped' });
    expect(rd({ schema: f, record: { b: true } }).fields.b).toMatchObject({ action: 'dropped' });
    expect(rd({ schema: f, record: { b: -5 } }).fields.b).toMatchObject({ action: 'dropped' });
    expect(rd({ schema: f, record: { b: 55 } }).view.b).toBe(50);
  });
  it('a caller can only tighten: an equal-rank bucket request does not replace the grant bucket', () => {
    const f = { fields: { b: 'fin' }, required: [] };
    expect(rd({ schema: f, record: { b: 1234 }, tighten: { fin: 'bucket:100' } }).view.b).toBe(1230);
    expect(rd({ schema: f, record: { b: 1234 }, tighten: { fin: 'hash' } }).fields.b).toMatchObject({ kind: 'hash' });
    expect(rd({ schema: f, record: { b: 1234 }, tighten: { fin: 'show' } }).view.b).toBe(1230);
  });
  it('enforces a cap only on a class that has one', () => {
    const capped = signReadGrant(P, { ...body, id: 'rg3', caps: { pii: 1 } });
    const f = { fields: { c: 'pii', d: 'pii', a: 'open' }, required: [] };
    const rec = { c: '12345678', d: '87654321', a: 'x' };
    expect(rd({ grant: capped, schema: f, record: rec })).toEqual(deny('read_cap', {}));
    expect(rd({ grant: capped, schema: f, record: { c: '12345678', a: 'x' } }).decision).toBe('allow');
    expect(rd({ schema: f, record: rec, counts: { pii: 9 } }).counts).toEqual({ pii: 11, open: 1 });
  });
  it('escalates when a required field is dropped', () => {
    const r = rd({ schema: { fields: { c: 'pii' }, required: ['c'] }, record: { c: 'ab' }, counts: { x: 1 } });
    expect(r).toEqual({ ...deny('required_dropped', { x: 1 }), decision: 'escalate' });
  });
});

// ---- receipts ---------------------------------------------------------------------------------------------------------------

type Raw = Record<string, unknown>;
const RECEIPT_KEYS = ['v', 'grant', 'verb', 'resource', 'purpose', 'seq', 'prev', 'fields', 'labels', 'issued_at', 'signer'];
const vd = (n: string) => hashCanonical({ n });
const fld = (cls: string, action: ReadField['action'] = 'masked', kind: string | null = 'hash'): ReadField => ({ class: cls, action, kind, vd: vd(cls) });
// a receipt signed by the resource server over exactly the signed keys; `o` may break any one field
const forge = (o: Raw = {}, key: Uint8Array = R): Raw => {
  const base: Raw = { v: 1, grant: DIGEST, verb: 'customers.get', resource: 'customers/1', purpose: 'support', seq: 0, prev: null, fields: { a: fld('pii') }, labels: ['pii'], issued_at: NOW, signer: RPK, ...o };
  return { ...base, sig: signBody(key, READ_RECEIPT_DOMAIN, Object.fromEntries(RECEIPT_KEYS.map((k) => [k, base[k]]))) };
};
const chain = (rs: unknown, now = NOW) => readChainLabels(rs, RPK, DIGEST, now);
const BAD0 = { code: 'bad_receipt', at: 0 };

describe('read receipt chain', () => {
  it('accepts a well-formed signed receipt and returns its labels', () => {
    expect(chain([forge()])).toEqual({ labels: ['pii'] });
    expect(chain([])).toEqual({ labels: [] });
    expect(chain([forge({ issued_at: NOW })], NOW)).toEqual({ labels: ['pii'] });
  });
  it('refuses a non-array chain and a non-object receipt', () => {
    expect(chain({})).toEqual(BAD0);
    expect(chain('abc')).toEqual(BAD0);
    expect(chain([null])).toEqual(BAD0);
    expect(chain([5])).toEqual(BAD0);
  });
  it('refuses a receipt whose top-level shape is wrong even though the signature is valid', () => {
    expect(chain([Object.assign([], forge())])).toEqual(BAD0);
    expect(chain([{ ...forge(), extra: 1 }])).toEqual(BAD0);
    const { labels: _l, ...noLabels } = forge();
    void _l;
    expect(chain([noLabels])).toEqual(BAD0);
    expect(chain([forge({ v: 2 })])).toEqual(BAD0);
  });
  it('refuses bad scalar fields', () => {
    for (const o of [{ verb: '' }, { verb: 'v'.repeat(129) }, { resource: '' }, { resource: 'r'.repeat(513) }, { purpose: ['support'] }, { purpose: 'bad purpose' }, { issued_at: '5' }, { grant: 'abc' }, { signer: 'abc' }]) {
      expect(chain([forge(o)]), JSON.stringify(o)).toEqual(BAD0);
    }
    expect(chain([forge({ verb: 'v'.repeat(128), resource: 'r'.repeat(512) })])).toEqual({ labels: ['pii'] });
  });
  it('refuses a receipt that does not match the pinned signer, grant, sequence or time', () => {
    expect(chain([forge({ signer: YPK })])).toEqual(BAD0); // signed by the resource server key but names another signer
    expect(chain([forge({ grant: vd('other-grant') })])).toEqual(BAD0);
    expect(chain([forge({ issued_at: NOW + 1 })])).toEqual(BAD0);
    expect(chain([forge({}, Y)])).toEqual(BAD0);
    expect(chain([{ ...forge(), sig: signBody(R, READ_RECEIPT_DOMAIN, { other: 1 }) }])).toEqual(BAD0);
  });
  it('checks each field record', () => {
    const f = (bad: unknown) => forge({ fields: { a: fld('pii'), b: bad } });
    const dropped = (o: Raw) => ({ ...fld('x', 'dropped', null), ...o });
    expect(chain([f(dropped({ class: ['pii'] }))])).toEqual(BAD0);
    expect(chain([f(dropped({ class: 'Bad Class' }))])).toEqual(BAD0);
    expect(chain([f(dropped({ class: 'unclassified' }))])).toEqual({ labels: ['pii'] });
    expect(chain([f({ ...fld('pii'), action: 'weird' })])).toEqual(BAD0);
    expect(chain([f({ ...fld('pii'), kind: 5 })])).toEqual(BAD0);
    expect(chain([f({ ...fld('pii'), vd: 'abc' })])).toEqual(BAD0);
    expect(chain([f({ ...fld('pii'), extra: 1 })])).toEqual(BAD0);
    expect(chain([f(Object.assign([], fld('pii')))])).toEqual(BAD0);
    expect(chain([f(5)])).toEqual(BAD0);
    expect(chain([forge({ fields: { a: fld('pii'), 'bad key!': fld('pii') } })])).toEqual(BAD0);
  });
  it('limits fields to 64 and labels to 32', () => {
    const many = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, fld('pii')]));
    expect(chain([forge({ fields: many(64) })])).toEqual({ labels: ['pii'] });
    expect(chain([forge({ fields: many(65) })])).toEqual(BAD0);
    const classes = (n: number) => Array.from({ length: n }, (_, i) => `c${String(i).padStart(2, '0')}`);
    const spread = (n: number) => forge({ fields: Object.fromEntries(classes(n).map((c) => [c, fld(c)])), labels: classes(n) });
    expect(chain([spread(32)])).toEqual({ labels: classes(32) });
    expect(chain([spread(33)])).toEqual(BAD0);
  });
  it('requires the labels to be exactly the classes of the fields that were not dropped', () => {
    const two = { fields: { a: fld('pii'), b: fld('ssn') } };
    expect(chain([forge({ ...two, labels: ['pii', 'ssn'] })])).toEqual({ labels: ['pii', 'ssn'] });
    expect(chain([forge({ ...two, labels: ['pii'] })])).toEqual(BAD0);
    expect(chain([forge({ labels: ['pii', 'zzz'] })])).toEqual(BAD0);
    expect(chain([forge({ ...two, labels: ['pii', 'zzz'] })])).toEqual(BAD0);
    expect(chain([forge({ labels: ['zzz'] })])).toEqual(BAD0);
    expect(chain([forge({ fields: { a: fld('pii'), b: fld('ssn', 'dropped', null) }, labels: ['pii', 'ssn'] })])).toEqual(BAD0);
    expect(chain([forge({ fields: { a: fld('pii'), b: fld('ssn', 'dropped', null) }, labels: ['pii'] })])).toEqual({ labels: ['pii'] });
  });
  it('links receipts by sequence and previous reference', () => {
    const first = forge();
    const second = (o: Raw = {}) => forge({ seq: 1, prev: readReceiptRef(first as unknown as ReadReceipt), fields: { a: fld('ssn') }, labels: ['ssn'], ...o });
    expect(chain([first, second()])).toEqual({ labels: ['pii', 'ssn'] });
    expect(chain([first, second({ prev: vd('elsewhere') })])).toEqual({ code: 'bad_receipt', at: 1 });
    expect(chain([first, second({ seq: 5 })])).toEqual({ code: 'bad_receipt', at: 1 });
    expect(chain([first, second({ seq: 0, prev: null })])).toEqual({ code: 'bad_receipt', at: 1 });
    expect(chain([first, { ...second(), sig: signBody(R, READ_RECEIPT_DOMAIN, { other: 1 }) }])).toEqual({ code: 'bad_receipt', at: 1 });
    expect(chain([first, second({ prev: null })])).toEqual({ code: 'bad_receipt', at: 1 });
  });
});

describe('read chain label ordering at scale', () => {
  // ten chained receipts of 32 ascending labels each: the union has 320 distinct labels, first seen in the block order given
  const label = (n: number) => `l${String(n).padStart(3, '0')}`;
  const build = (blockOrder: number[]): Raw[] => {
    const out: Raw[] = [];
    blockOrder.forEach((blk, i) => {
      const ls = Array.from({ length: 32 }, (_, j) => label(blk * 32 + j));
      out.push(forge({ seq: i, prev: i === 0 ? null : readReceiptRef(out[i - 1] as unknown as ReadReceipt), fields: Object.fromEntries(ls.map((c, j) => [`f${j}`, fld(c)])), labels: ls }));
    });
    return out;
  };
  const all = Array.from({ length: 320 }, (_, i) => label(i));
  it('returns all labels bytewise sorted whatever order the receipts arrive in', () => {
    for (const order of [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0], [3, 7, 0, 9, 5, 1, 8, 2, 6, 4], [5, 4, 3, 2, 1, 0, 6, 7, 8, 9], [0, 9, 1, 8, 2, 7, 3, 6, 4, 5]]) {
      expect(chain(build(order)), order.join()).toEqual({ labels: all });
    }
  });
});

describe('checkSink', () => {
  const sink = (o: Record<string, unknown> = {}) => checkSink({ grant, principal: PK, rsSigner: RPK, now: NOW, sink: 'payments', receipts: [forge()], ...o } as never);
  it('allows, escalates and denies by label', () => {
    expect(sink()).toEqual({ decision: 'allow', code: null, labels: ['pii'] });
    expect(sink({ receipts: [forge({ fields: { a: fld('fin') }, labels: ['fin'] })] })).toEqual({ decision: 'escalate', code: 'label_escalate', labels: ['fin'] });
    expect(sink({ receipts: [forge({ fields: { a: fld('ssn') }, labels: ['ssn'] })] })).toEqual({ decision: 'deny', code: 'label_flow', labels: ['ssn'] });
    expect(sink({ sink: 'billing' })).toEqual({ decision: 'deny', code: 'unknown_sink', labels: [] });
  });
  it('refuses a malformed request with an exact refusal', () => {
    expect(sink({ sink: ['payments'] })).toEqual({ decision: 'deny', code: 'bad_request', labels: [] });
    expect(sink({ rsSigner: 'abc' })).toEqual({ decision: 'deny', code: 'bad_request', labels: [] });
    expect(sink({ grant: null })).toEqual({ decision: 'deny', code: 'bad_grant', labels: [] });
    expect(sink({ receipts: [null] })).toEqual({ decision: 'deny', code: 'bad_receipt', labels: [] });
    expect(sink({ receipts: {} })).toEqual({ decision: 'deny', code: 'bad_receipt', labels: [] });
    expect(checkSink(null as never)).toEqual({ decision: 'deny', code: 'bad_request', labels: [] });
  });
});
