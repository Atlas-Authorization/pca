import { describe, expect, it } from 'vitest';
import { createMemoryDurableKv } from './durable-state';
import { obligationsError } from './obligations';
import {
  KvUndoStore,
  MemoryUndoStore,
  UNDO_DEFAULT_WINDOW_MS,
  UNDO_MAX_WINDOW_MS,
  UNDO_MIN_WINDOW_MS,
  UNDO_STATES,
  UndoError,
  compensationDigest,
  decodeUndoToken,
  encodeUndoToken,
  isUndoStore,
  resolveUndoWindow,
  signUndoReceipt,
  signUndoToken,
  undoReceiptChainError,
  undoReceiptDigest,
  undoTokenCheck,
  undoTransition,
  verifyUndoReceipt,
  withReceipt,
  type UndoCompensation,
  type UndoRecord,
  type UndoState,
  type UndoStore,
  type UndoTransitionEvent,
} from './undo';
import { b64u } from './hash';
import { publicKeyOf } from './keys';

const SK = new Uint8Array(32).fill(7);
const SK2 = new Uint8Array(32).fill(9);
const PK = b64u(publicKeyOf(SK));
const T0 = 1_800_000_000_000;
const END = T0 + 60_000;

const COMP: UndoCompensation = { verb: 'drafts.delete', resource: 'drafts:box1', params: { box: 'box1' }, undo_of: 'op_1', def_digest: 'D'.repeat(43), target_param: 'draft' };

function rec(over: Partial<UndoRecord> = {}): UndoRecord {
  const base: UndoRecord = {
    v: 1,
    id: 'op_1',
    aud: 'drafts-rs',
    grant_ref: 'g_1',
    holder: 'H'.repeat(43),
    principal: 'P'.repeat(43),
    action: { verb: 'drafts.create', resource: 'drafts:box1', params_digest: 'Q'.repeat(43), def_digest: 'A'.repeat(43) },
    compensation: COMP,
    compensation_digest: compensationDigest(COMP),
    render_digest: 'R'.repeat(43),
    opened_at: T0,
    window_end: END,
    converted: true,
    state: 'open',
    ver: 0,
    pcactn: 'x',
    attempt: 0,
    receipts: [],
    ...over,
  };
  return base.receipts.length ? base : withReceipt(base, { event: 'opened', note: '' }, T0, SK);
}

const VETO = { veto: { at: T0, via: 'operator' as const, by: 'ops' } };
const EVENTS: Record<string, UndoTransitionEvent> = {
  veto: { kind: 'veto', ...VETO },
  finalize: { kind: 'finalize' },
  abort: { kind: 'abort', reason: 'effect_failed' },
  effect: { kind: 'effect', result: { id: 'd_1' } },
  compensated: { kind: 'compensated', result: { ok: true } },
  compensation_failed: { kind: 'compensation_failed', reason: 'downstream 500' },
  retry: { kind: 'retry' },
};

describe('undoTransition: the full state x event table', () => {
  // [state, effect recorded?, event, now] -> outcome[:code|state]
  const table: [UndoState, boolean, string, number, string][] = [
    ['open', false, 'veto', T0, 'applied:vetoed'],
    ['open', false, 'veto', END, 'applied:vetoed'],
    ['open', false, 'veto', END + 1, 'refused:window_closed'],
    ['vetoed', false, 'veto', T0, 'replayed'],
    ['compensated', true, 'veto', T0, 'replayed'],
    ['compensation_failed', true, 'veto', T0, 'replayed'],
    ['finalized', false, 'veto', T0, 'refused:finalized'],
    ['open', false, 'finalize', END, 'refused:window_open'],
    ['open', false, 'finalize', END + 1, 'applied:finalized'],
    ['finalized', false, 'finalize', END + 1, 'replayed'],
    ['vetoed', false, 'finalize', END + 1, 'refused:vetoed'],
    ['compensated', true, 'finalize', END + 1, 'refused:vetoed'],
    ['open', false, 'abort', T0, 'applied:finalized'],
    ['vetoed', false, 'abort', T0, 'applied:finalized'],
    ['open', true, 'abort', T0, 'refused:effect_recorded'],
    ['compensated', true, 'abort', T0, 'refused:finalized'],
    ['compensation_failed', true, 'abort', T0, 'refused:finalized'],
    ['finalized', false, 'abort', T0, 'refused:finalized'],
    ['open', false, 'effect', T0, 'applied:open'],
    ['vetoed', false, 'effect', END + 5, 'applied:vetoed'],
    ['open', true, 'effect', T0, 'replayed'],
    ['finalized', false, 'effect', T0, 'refused:finalized'],
    ['vetoed', true, 'compensated', T0, 'applied:compensated'],
    ['compensation_failed', true, 'compensated', T0, 'applied:compensated'],
    ['compensated', true, 'compensated', T0, 'replayed'],
    ['open', true, 'compensated', T0, 'refused:not_vetoed'],
    ['finalized', true, 'compensated', T0, 'refused:not_vetoed'],
    ['vetoed', true, 'compensation_failed', T0, 'applied:compensation_failed'],
    ['compensation_failed', true, 'compensation_failed', T0, 'replayed'],
    ['open', true, 'compensation_failed', T0, 'refused:not_vetoed'],
    ['compensated', true, 'compensation_failed', T0, 'refused:not_vetoed'],
    ['compensation_failed', true, 'retry', T0, 'applied:vetoed'],
    ['vetoed', true, 'retry', T0, 'refused:not_failed'],
    ['open', true, 'retry', T0, 'refused:not_failed'],
    ['compensated', true, 'retry', T0, 'refused:not_failed'],
  ];
  for (const [state, eff, ev, now, want] of table) {
    it(`${state}${eff ? '+effect' : ''} --${ev}@${now === END ? 'end' : now > END ? 'after' : 'start'}--> ${want}`, () => {
      const r = rec({ state, ...(eff ? { effect: { at: T0, result: { id: 'd_1' } } } : {}) });
      const before = structuredClone(r);
      const t = undoTransition(r, EVENTS[ev]!, now);
      expect(r).toEqual(before); // pure
      const got = t.outcome === 'applied' ? `applied:${t.record.state}` : t.outcome === 'refused' ? `refused:${t.code}` : 'replayed';
      expect(got).toBe(want);
      if (t.outcome === 'applied') {
        expect(t.record.ver).toBe(r.ver + 1);
        expect(t.record.receipts).toEqual(r.receipts); // the receipt is appended by the store layer
      }
      if (t.outcome === 'replayed') expect(t.record).toBe(r);
    });
  }

  it('applied transitions write exactly their fields', () => {
    const v = undoTransition(rec(), EVENTS.veto!, T0 + 5);
    expect(v.outcome === 'applied' && [v.record.veto, v.receipt]).toEqual([{ at: T0, via: 'operator', by: 'ops' }, { event: 'vetoed', note: 'operator' }]);
    const a = undoTransition(rec(), EVENTS.abort!, T0 + 5);
    expect(a.outcome === 'applied' && [a.record.outcome, a.receipt.event]).toEqual([{ at: T0 + 5, status: 'aborted', reason: 'effect_failed' }, 'aborted']);
    const f = undoTransition(rec(), EVENTS.finalize!, END + 1);
    expect(f.outcome === 'applied' && f.record.outcome).toEqual({ at: END + 1, status: 'finalized' });
    const e = undoTransition(rec(), EVENTS.effect!, T0 + 2);
    expect(e.outcome === 'applied' && e.record.effect).toEqual({ at: T0 + 2, result: { id: 'd_1' } });
    const c = undoTransition(rec({ state: 'vetoed' }), EVENTS.compensated!, T0 + 3);
    expect(c.outcome === 'applied' && c.record.outcome).toEqual({ at: T0 + 3, status: 'compensated', result: { ok: true } });
    const x = undoTransition(rec({ state: 'vetoed' }), EVENTS.compensation_failed!, T0 + 3);
    expect(x.outcome === 'applied' && x.record.outcome).toEqual({ at: T0 + 3, status: 'compensation_failed', reason: 'downstream 500' });
    const r = undoTransition(rec({ state: 'compensation_failed', attempt: 2 }), EVENTS.retry!, T0);
    expect(r.outcome === 'applied' && [r.record.attempt, r.receipt.event]).toEqual([3, 'retried']);
    for (const attempt of [Number.NaN, 1.5, -1, '2', undefined]) {
      const bad = undoTransition({ ...rec({ state: 'compensation_failed' }), attempt } as never, EVENTS.retry!, T0);
      expect(bad).toEqual({ outcome: 'refused', code: 'invalid', reason: 'malformed record' });
    }
    const fin = rec({ state: 'finalized', outcome: { at: T0, status: 'aborted' } });
    expect(undoTransition(fin, EVENTS.abort!, T0).outcome).toBe('replayed');
  });

  it('malformed input is refused, never thrown', () => {
    const bad: [unknown, unknown, number][] = [
      [null, EVENTS.veto, T0],
      [{ ...rec(), state: 'gone' }, EVENTS.veto, T0],
      [{ ...rec(), window_end: 1.5 }, EVENTS.veto, T0],
      [{ ...rec(), ver: -0.5 }, EVENTS.veto, T0],
      [rec(), EVENTS.veto, Number.NaN],
      [rec(), { kind: 'explode' }, T0],
      [rec(), undefined, T0],
      [rec(), { kind: 'veto', veto: { at: T0, via: 'telepathy', by: 'x' } }, T0],
      [rec(), { kind: 'veto', veto: { at: 1.5, via: 'token', by: 'x' } }, T0],
      [rec(), { kind: 'veto', veto: { at: T0, via: 'token', by: '' } }, T0],
      [rec(), { kind: 'veto' }, T0],
    ];
    for (const [r, ev, now] of bad) {
      const t = undoTransition(r as UndoRecord, ev as UndoTransitionEvent, now);
      expect(t.outcome === 'refused' && t.code).toBe('invalid');
    }
  });

  it('every state is reachable and the terminal states take no further state change', () => {
    const terminal: UndoState[] = ['compensated', 'finalized'];
    for (const s of terminal) for (const ev of Object.values(EVENTS)) {
      const t = undoTransition(rec({ state: s, effect: { at: T0 } }), ev, END + 10);
      expect(t.outcome === 'applied' ? t.record.state : s).toBe(s);
    }
    expect(UNDO_STATES).toEqual(['open', 'vetoed', 'compensated', 'compensation_failed', 'finalized']);
  });
});

describe('the one-click undo token', () => {
  const r = rec();
  const tok = signUndoToken(r, SK);
  it('binds record, audience, principal, compensation, render and window end; valid through window_end inclusive', () => {
    expect(tok).toMatchObject({ v: 1, kind: 'pca-undo-token', record: r.id, aud: r.aud, principal: r.principal, compensation_digest: r.compensation_digest, render_digest: r.render_digest, exp: END, signer: PK });
    expect(undoTokenCheck(tok, PK, r, T0)).toBe('ok');
    expect(undoTokenCheck(tok, PK, r, END)).toBe('ok');
    expect(undoTokenCheck(tok, PK, r, END + 1)).toBe('expired');
    expect(undoTokenCheck(tok, PK, r, Number.NaN)).toBe('expired');
  });
  it('names the first check it fails', () => {
    expect(undoTokenCheck(tok, b64u(publicKeyOf(SK2)), r, T0)).toBe('signer');
    expect(undoTokenCheck({ ...tok, exp: END + 1 }, PK, r, T0)).toBe('signature');
    expect(undoTokenCheck({ ...tok, sig: tok.sig.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) }, PK, r, T0)).toBe('signature');
    expect(undoTokenCheck(signUndoToken({ ...r, id: 'op_2' }, SK), PK, r, T0)).toBe('record');
    for (const k of ['aud', 'principal', 'compensation_digest', 'render_digest', 'window_end'] as const) {
      const other = signUndoToken({ ...r, [k]: k === 'window_end' ? END + 1 : 'Z'.repeat(43) }, SK);
      expect([k, undoTokenCheck(other, PK, r, T0)]).toEqual([k, 'binding']);
    }
    // a record without a render digest binds ''
    const nr = rec({ render_digest: undefined });
    expect(signUndoToken(nr, SK).render_digest).toBe('');
    expect(undoTokenCheck(signUndoToken(nr, SK), PK, nr, T0)).toBe('ok');
    expect(undoTokenCheck(tok, PK, nr, T0)).toBe('binding');
  });
  it('anything not exactly a token is malformed', () => {
    for (const x of [null, 'str', [], {}, { ...tok, extra: 1 }, { ...tok, v: 2 }, { ...tok, kind: 'pca-undo-receipt' }, { ...tok, exp: '1' }, { ...tok, sig: 'short' }, { ...tok, record: '' }]) {
      expect(undoTokenCheck(x, PK, r, T0)).toBe('malformed');
    }
    const { sig: _s, ...noSig } = tok;
    expect(undoTokenCheck(noSig, PK, r, T0)).toBe('malformed');
  });
  it('encodes to a URL-safe string and back; garbage decodes to undefined', () => {
    const s = encodeUndoToken(tok);
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeUndoToken(s)).toEqual(tok);
    for (const g of ['', '!!', 'a'.repeat(5000), 42, undefined, b64u(new TextEncoder().encode('[1]'))]) expect(decodeUndoToken(g)).toBeUndefined();
  });
  it('signing needs a 32-byte key', () => {
    expect(() => signUndoToken(r, new Uint8Array(31))).toThrow(UndoError);
  });
});

describe('receipts: signed, hash-chained, bound to the record', () => {
  const opened = rec();
  const vetoed = (() => {
    const t = undoTransition(opened, EVENTS.veto!, T0 + 1);
    if (t.outcome !== 'applied') throw new Error('x');
    return withReceipt(t.record, t.receipt, T0 + 1, SK);
  })();
  it('a sound chain verifies; each receipt links to the previous one', () => {
    expect(undoReceiptChainError(vetoed, PK)).toBeNull();
    expect(vetoed.receipts.map((x) => [x.event, x.state, x.note])).toEqual([['opened', 'open', ''], ['vetoed', 'vetoed', 'operator']]);
    expect(vetoed.receipts[1]!.prev).toBe(undoReceiptDigest(vetoed.receipts[0]!));
    expect(vetoed.receipts[0]!.prev).toBe('');
  });
  it('tampering, reordering, a wrong signer, a foreign record, time going back or a state mismatch is caught', () => {
    const [a, b] = vetoed.receipts as [typeof vetoed.receipts[0], typeof vetoed.receipts[0]];
    expect(undoReceiptChainError({ ...vetoed, receipts: [] }, PK)).toBe('no receipts');
    expect(undoReceiptChainError({ ...vetoed, receipts: [a, { ...b, note: 'token' }] }, PK)).toBe('receipt 1 does not verify');
    expect(undoReceiptChainError({ ...vetoed, receipts: [b, a] }, PK)).toMatch(/does not link|first receipt/);
    expect(undoReceiptChainError(vetoed, b64u(publicKeyOf(SK2)))).toBe('receipt 0 does not verify');
    expect(undoReceiptChainError({ ...vetoed, id: 'op_9' }, PK)).toBe('receipt 0 is for another record');
    expect(undoReceiptChainError({ ...vetoed, compensation_digest: 'Z'.repeat(43) }, PK)).toBe('receipt 0 is for another record');
    expect(undoReceiptChainError({ ...vetoed, state: 'open' }, PK)).toBe('the last receipt does not state the record state');
    const back = signUndoReceipt({ record: 'op_1', event: 'vetoed', state: 'vetoed', at: T0 - 1, compensation_digest: vetoed.compensation_digest, prev: undoReceiptDigest(a), note: '' }, SK);
    expect(undoReceiptChainError({ ...vetoed, receipts: [a, back] }, PK)).toBe('receipt 1 goes back in time');
    const notOpened = signUndoReceipt({ record: 'op_1', event: 'vetoed', state: 'vetoed', at: T0, compensation_digest: vetoed.compensation_digest, prev: '', note: '' }, SK);
    expect(undoReceiptChainError({ ...vetoed, receipts: [notOpened] }, PK)).toBe('the first receipt is not opened');
    expect(undoReceiptChainError({ ...vetoed, receipts: [a, { ...b, prev: '' }] }, PK)).toBe('receipt 1 does not verify');
  });
  it('verifyUndoReceipt is strict about shape', () => {
    const a = vetoed.receipts[0]!;
    expect(verifyUndoReceipt(a, PK)).toBe(true);
    for (const x of [null, [], { ...a, extra: 1 }, { ...a, event: 'nope' }, { ...a, state: 'nope' }, { ...a, at: 1.5 }, { ...a, v: 2 }, { ...a, kind: 'pca-undo-token' }, { ...a, record: '' }]) expect(verifyUndoReceipt(x, PK)).toBe(false);
  });
});

describe('compensationDigest binds every field', () => {
  it('changes with each field; target_param absent differs from present', () => {
    const d = compensationDigest(COMP);
    const variants: UndoCompensation[] = [
      { ...COMP, verb: 'drafts.trash' },
      { ...COMP, resource: 'drafts:box2' },
      { ...COMP, params: { box: 'box2' } },
      { ...COMP, undo_of: 'op_2' },
      { ...COMP, def_digest: 'E'.repeat(43) },
      { ...COMP, target_param: 'id' },
    ];
    const { target_param: _t, ...noTarget } = COMP;
    variants.push(noTarget);
    const all = new Set([d, ...variants.map(compensationDigest)]);
    expect(all.size).toBe(variants.length + 1);
    expect(compensationDigest({ ...COMP, params: { box: 'box1' } })).toBe(d);
  });
});

describe('resolveUndoWindow', () => {
  it('clamps into [30 s, 24 h]; absent or non-finite takes the default; host bounds tighten only', () => {
    expect(resolveUndoWindow(undefined)).toBe(UNDO_DEFAULT_WINDOW_MS);
    expect(resolveUndoWindow(Number.NaN)).toBe(UNDO_DEFAULT_WINDOW_MS);
    expect(resolveUndoWindow(Infinity)).toBe(UNDO_DEFAULT_WINDOW_MS);
    expect(resolveUndoWindow(0)).toBe(UNDO_MIN_WINDOW_MS);
    expect(resolveUndoWindow(-5)).toBe(UNDO_MIN_WINDOW_MS);
    expect(resolveUndoWindow(UNDO_MIN_WINDOW_MS - 1)).toBe(UNDO_MIN_WINDOW_MS);
    expect(resolveUndoWindow(UNDO_MIN_WINDOW_MS)).toBe(UNDO_MIN_WINDOW_MS);
    expect(resolveUndoWindow(UNDO_MAX_WINDOW_MS + 1)).toBe(UNDO_MAX_WINDOW_MS);
    expect(resolveUndoWindow(90_000.7)).toBe(90_000);
    expect(resolveUndoWindow(10, { minMs: 1 })).toBe(UNDO_MIN_WINDOW_MS); // a host cannot go below the floor
    expect(resolveUndoWindow(10 ** 9, { maxMs: 10 ** 12 })).toBe(UNDO_MAX_WINDOW_MS); // nor above the ceiling
    expect(resolveUndoWindow(10 ** 8, { maxMs: 60_000 })).toBe(60_000);
    expect(resolveUndoWindow(undefined, { defaultMs: 120_000 })).toBe(120_000);
    expect(resolveUndoWindow(1, { minMs: 120_000, maxMs: 60_000 })).toBe(120_000); // max never below min
  });
});

describe('the undo_window obligation kind', () => {
  it('needs id and window_end and nothing else', () => {
    expect(obligationsError([{ kind: 'undo_window', params: { id: 'op_1', window_end: END }, due: END }])).toBeNull();
    for (const p of [{}, { id: 'op_1' }, { window_end: END }, { id: '', window_end: END }, { id: 'op_1', window_end: -1 }, { id: 'op_1', window_end: 1.5 }, { id: 'op_1', window_end: END, extra: 1 }, { id: 'x'.repeat(129), window_end: END }]) {
      expect(obligationsError([{ kind: 'undo_window', params: p }])).not.toBeNull();
    }
  });
});

const stores: [string, () => UndoStore][] = [
  ['MemoryUndoStore', () => new MemoryUndoStore()],
  ['KvUndoStore', () => new KvUndoStore(createMemoryDurableKv(), false)],
];
for (const [name, mk] of stores) {
  describe(`store contract: ${name}`, () => {
    it('create is insert-if-absent and returns the stored record otherwise', async () => {
      const s = mk();
      expect(isUndoStore(s)).toBe(true);
      expect(s.durable).toBe(false);
      expect(await s.create(rec())).toEqual({ created: true });
      const again = await s.create(rec({ window_end: END + 5 }));
      expect(again.created).toBe(false);
      expect(!again.created && again.record.window_end).toBe(END);
      expect(await s.get('missing')).toBeUndefined();
    });
    it('replace is compare-and-swap on ver; exactly one of two racing writers wins; the id cannot change', async () => {
      const s = mk();
      await s.create(rec());
      const cur = (await s.get('op_1'))!;
      const a = { ...cur, ver: 1, state: 'vetoed' as const };
      const b = { ...cur, ver: 1, state: 'finalized' as const };
      const [ra, rb] = await Promise.all([s.replace('op_1', 0, a), s.replace('op_1', 0, b)]);
      expect([ra, rb].filter(Boolean)).toHaveLength(1);
      expect(await s.replace('op_1', 0, { ...cur, ver: 2 })).toBe(false);
      expect(await s.replace('nope', 0, { ...cur, id: 'nope' })).toBe(false);
      await expect(s.replace('op_1', 1, { ...cur, id: 'op_2' })).rejects.toThrow(UndoError);
    });
    it('returns copies: mutating a read never changes the store', async () => {
      const s = mk();
      await s.create(rec());
      const r = (await s.get('op_1'))!;
      r.state = 'finalized';
      r.receipts.length = 0;
      expect((await s.get('op_1'))!.state).toBe('open');
      expect((await s.get('op_1'))!.receipts).toHaveLength(1);
    });
    it('list filters by state, window end, grant and bond, sorted by id, with a limit', async () => {
      const s = mk();
      await s.create(rec({ id: 'b', window_end: END }));
      await s.create(rec({ id: 'a', window_end: END + 10, grant_ref: 'g_2', bond_ref: 'bond' }));
      await s.create(rec({ id: 'c', state: 'vetoed' }));
      expect((await s.list({ state: 'open' })).map((r) => r.id)).toEqual(['a', 'b']);
      expect((await s.list({ state: 'open', windowEndedBy: END })).map((r) => r.id)).toEqual(['b']);
      expect((await s.list({ state: 'open', grantRef: 'g_2' })).map((r) => r.id)).toEqual(['a']);
      expect((await s.list({ state: 'open', bondRef: 'bond' })).map((r) => r.id)).toEqual(['a']);
      expect((await s.list({ state: 'open', limit: 1 })).map((r) => r.id)).toEqual(['a']);
      expect((await s.list({ state: 'vetoed' })).map((r) => r.id)).toEqual(['c']);
      expect(await s.list({ state: 'compensated' })).toEqual([]);
    });
    it('an unusable id is refused', async () => {
      const s = mk();
      await expect(s.create(rec({ id: '' }))).rejects.toThrow(UndoError);
      await expect(s.create(rec({ id: 'a\u0000b' }))).rejects.toThrow(UndoError);
    });
  });
}

describe('KvUndoStore specifics', () => {
  it('a corrupt stored record is an error, never a silent miss', async () => {
    const kv = createMemoryDurableKv();
    await kv.set('pca-undo/v1/op_1', { v: 1, id: 'op_1', state: 'exploded', ver: 0, receipts: [] });
    const s = new KvUndoStore(kv, true);
    await expect(s.get('op_1')).rejects.toMatchObject({ code: 'store_corrupt' });
  });
  it('needs a kv and an explicit durability claim', () => {
    expect(() => new KvUndoStore(undefined as never, true)).toThrow(UndoError);
    expect(() => new KvUndoStore(createMemoryDurableKv(), 'yes' as never)).toThrow(UndoError);
    expect(new KvUndoStore(createMemoryDurableKv(), true).durable).toBe(true);
  });
  it('isUndoStore rejects anything missing a method or the durability flag', () => {
    expect(isUndoStore(null)).toBe(false);
    expect(isUndoStore({ get() {}, create() {}, replace() {}, list() {} })).toBe(false);
    expect(isUndoStore({ durable: true, get() {}, create() {}, replace() {} })).toBe(false);
  });
});
