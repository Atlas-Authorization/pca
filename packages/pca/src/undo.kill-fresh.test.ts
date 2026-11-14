/**
 * undo.ts builds its published constants and its small helpers (id check, object check, token and receipt bodies, digests,
 * the query matcher, the refusal builder) at module load. A test that imports the module statically evaluates them before any
 * test runs, so these tests re-evaluate the module (vi.resetModules + dynamic import) and pin the exact observable behaviour:
 * constants, refusal codes and reasons, both sides of every boundary, and each shape check on its own.
 */
import { describe, expect, it, vi } from 'vitest';
import { createMemoryDurableKv, type DurableKv } from './durable-state';
import { b64u, canonicalBytesStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf, sign } from './keys';
import type { UndoCompensation, UndoRecord, UndoReceipt, UndoToken } from './undo';

async function fresh() {
  vi.resetModules();
  return import('./undo');
}

const SK = new Uint8Array(32).fill(7);
const PK = b64u(publicKeyOf(SK));
const T0 = 1_800_000_000_000;
const END = T0 + 60_000;
const ID_MSG = 'invalid: an undo record id is a non-empty string without control characters';
const COMP: UndoCompensation = { verb: 'drafts.delete', resource: 'drafts:box1', params: { box: 'box1' }, undo_of: 'op_1', def_digest: 'D'.repeat(43) };

const rec = (over: Partial<UndoRecord> = {}): UndoRecord => ({
  v: 1,
  id: 'op_1',
  aud: 'drafts-rs',
  grant_ref: 'g_1',
  holder: 'H'.repeat(43),
  principal: 'P'.repeat(43),
  action: { verb: 'drafts.create', resource: 'drafts:box1', params_digest: 'Q'.repeat(43), def_digest: 'A'.repeat(43) },
  compensation: COMP,
  compensation_digest: 'C'.repeat(43),
  render_digest: 'R'.repeat(43),
  opened_at: T0,
  window_end: END,
  converted: false,
  state: 'open',
  ver: 0,
  pcactn: 'x',
  attempt: 0,
  receipts: [],
  ...over,
});

const concat = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};
/** Sign any body under a domain exactly as the module does (the signing helpers refuse nothing, a forger would not either). */
const signed = <T extends Record<string, unknown>>(domain: string, body: T): T & { sig: string } => ({ ...body, sig: b64u(sign(SK, concat(utf8(domain), canonicalBytesStrict(body)))) });
const RECEIPT_DOMAIN = 'atlas-pca/undo-receipt/v1\0';
const receiptBody = (over: Record<string, unknown> = {}) => ({ v: 1, kind: 'pca-undo-receipt', record: 'op_1', event: 'opened', state: 'open', at: T0, compensation_digest: 'C'.repeat(43), prev: '', note: '', signer: PK, ...over });

async function rejection(p: Promise<unknown>): Promise<{ code?: string; message: string; name: string }> {
  try {
    await p;
  } catch (e) {
    return e as { code?: string; message: string; name: string };
  }
  throw new Error('expected a rejection');
}

describe('published constants and the error type (fresh module)', () => {
  it('domains, kinds and window bounds are the normative values', async () => {
    const u = await fresh();
    expect([u.UNDO_TOKEN_DOMAIN, u.UNDO_RECEIPT_DOMAIN, u.UNDO_COMPENSATION_DOMAIN, u.UNDO_RECEIPT_REF_DOMAIN, u.UNDO_TOKEN_KIND, u.UNDO_RECEIPT_KIND]).toEqual([
      'atlas-pca/undo-token/v1\0',
      'atlas-pca/undo-receipt/v1\0',
      'atlas-pca/undo-compensation/v1',
      'atlas-pca/undo-receipt-ref/v1',
      'pca-undo-token',
      'pca-undo-receipt',
    ]);
    expect([u.UNDO_MIN_WINDOW_MS, u.UNDO_DEFAULT_WINDOW_MS, u.UNDO_MAX_WINDOW_MS]).toEqual([30_000, 900_000, 86_400_000]);
    expect(u.resolveUndoWindow(undefined)).toBe(900_000);
    expect(u.resolveUndoWindow(10 ** 12)).toBe(86_400_000);
  });

  it('UndoError carries its code, a code-prefixed message and its own name', async () => {
    const u = await fresh();
    const e = new u.UndoError('config', 'x');
    expect([e.code, e.message, e.name, e instanceof Error]).toEqual(['config', 'config: x', 'UndoError', true]);
  });
});

describe('the undo token (fresh module)', () => {
  it('a token signed by hand under the token domain verifies; the signing key must be 32 bytes, by name', async () => {
    const u = await fresh();
    const r = rec();
    const body = { v: 1, kind: 'pca-undo-token', record: r.id, aud: r.aud, principal: r.principal, compensation_digest: r.compensation_digest, render_digest: r.render_digest, exp: END, signer: PK };
    const byHand = signed('atlas-pca/undo-token/v1\0', body);
    expect(u.signUndoToken(r, SK)).toEqual(byHand);
    expect(u.undoTokenCheck(byHand, PK, r, T0)).toBe('ok');
    const e = (() => {
      try {
        u.signUndoToken(r, new Uint8Array(31));
      } catch (x) {
        return x as { code: string; message: string };
      }
      return undefined;
    })();
    expect(e && [e.code, e.message]).toEqual(['signer_missing', 'signer_missing: the undo service key must be a 32-byte Ed25519 secret']);
  });

  it('an array or an object with an inherited member is malformed even when every member is right', async () => {
    const u = await fresh();
    const r = rec();
    const tok = u.signUndoToken(r, SK);
    expect(u.undoTokenCheck(Object.assign([], tok), PK, r, T0)).toBe('malformed');
    const { v: _v, ...noV } = tok;
    const inherited = Object.assign(Object.create({ v: 1 }) as Record<string, unknown>, noV, { extra: 'x' });
    expect(Object.keys(inherited)).toHaveLength(10);
    expect(u.undoTokenCheck(inherited, PK, r, T0)).toBe('malformed');
  });

  it('each string member is type-checked on its own, even when the signature covers the wrong type', async () => {
    const u = await fresh();
    for (const k of ['aud', 'principal', 'compensation_digest', 'render_digest'] as const) {
      const r = rec({ [k]: 5 } as unknown as Partial<UndoRecord>);
      const tok = u.signUndoToken(r, SK);
      expect([k, tok[k]]).toEqual([k, 5]);
      expect([k, u.undoTokenCheck(tok, PK, r, T0)]).toEqual([k, 'malformed']);
    }
    const r = rec();
    expect(u.undoTokenCheck({ ...u.signUndoToken(r, SK), signer: 5 }, PK, r, T0)).toBe('malformed');
  });

  it('a member that throws when read is malformed, never a throw or an undefined answer', async () => {
    const u = await fresh();
    const r = rec();
    const t: Record<string, unknown> = { ...u.signUndoToken(r, SK) };
    Object.defineProperty(t, 'v', {
      enumerable: true,
      get() {
        throw new Error('boom');
      },
    });
    expect(u.undoTokenCheck(t, PK, r, T0)).toBe('malformed');
  });

  it('encode is base64url of the strict-canonical JSON; decode admits only objects and at most 4096 characters', async () => {
    const u = await fresh();
    const tok = u.signUndoToken(rec(), SK);
    expect(u.encodeUndoToken(tok)).toBe(b64u(canonicalBytesStrict(tok)));
    for (const json of ['"abc"', 'null', '7', 'true']) expect([json, u.decodeUndoToken(b64u(utf8(json)))]).toEqual([json, undefined]);
    const at4096 = b64u(canonicalBytesStrict({ a: 'x'.repeat(3064) }));
    const at4098 = b64u(canonicalBytesStrict({ a: 'x'.repeat(3065) }));
    expect([at4096.length, at4098.length]).toEqual([4096, 4098]);
    expect(u.decodeUndoToken(at4096)).toEqual({ a: 'x'.repeat(3064) });
    expect(u.decodeUndoToken(at4098)).toBeUndefined();
  });

  it('the token digest hashes the token under its reference domain', async () => {
    const u = await fresh();
    const tok: UndoToken = u.signUndoToken(rec(), SK);
    expect(u.undoTokenDigest(tok)).toBe(hashCanonical({ d: 'atlas-pca/undo-token-ref/v1', t: tok }));
  });
});

describe('receipts (fresh module)', () => {
  it('a receipt signed by hand under the receipt domain verifies; its digest hashes it under the reference domain', async () => {
    const u = await fresh();
    const r = signed(RECEIPT_DOMAIN, receiptBody());
    expect(u.signUndoReceipt({ record: 'op_1', event: 'opened', state: 'open', at: T0, compensation_digest: 'C'.repeat(43), prev: '', note: '' }, SK)).toEqual(r);
    expect(u.verifyUndoReceipt(r, PK)).toBe(true);
    expect(u.undoReceiptDigest(r as unknown as UndoReceipt)).toBe(hashCanonical({ d: 'atlas-pca/undo-receipt-ref/v1', r }));
  });

  it('each shape rule refuses on its own, even over a valid signature of the wrong content', async () => {
    const u = await fresh();
    const bad: [string, Record<string, unknown>][] = [
      ['v', { v: 2 }],
      ['kind', { kind: 'pca-undo-token' }],
      ['compensation_digest', { compensation_digest: 5 }],
      ['prev', { prev: 5 }],
      ['note', { note: 5 }],
      ['signer', { signer: 'zz' }],
    ];
    for (const [name, over] of bad) expect([name, u.verifyUndoReceipt(signed(RECEIPT_DOMAIN, receiptBody(over)), PK)]).toEqual([name, false]);
    expect(u.verifyUndoReceipt(Object.assign([], signed(RECEIPT_DOMAIN, receiptBody())), PK)).toBe(false);
  });

  it('a member that throws when read is false, never a throw or an undefined answer', async () => {
    const u = await fresh();
    const r: Record<string, unknown> = { ...signed(RECEIPT_DOMAIN, receiptBody()) };
    Object.defineProperty(r, 'v', {
      enumerable: true,
      get() {
        throw new Error('boom');
      },
    });
    expect(u.verifyUndoReceipt(r, PK)).toBe(false);
  });
});

describe('clipUnits', () => {
  it('steps back one unit only when the cut would split a surrogate pair', async () => {
    const u = await fresh();
    const s = 'a😀b';
    expect([u.clipUnits(s, 1), u.clipUnits(s, 2), u.clipUnits(s, 3), u.clipUnits(s, 4)]).toEqual(['a', 'a', 'a😀', s]);
  });
});

describe('undoTransition: exact refusals and results (fresh module)', () => {
  const refused = (code: string, reason: string) => ({ outcome: 'refused', code, reason });
  const veto = { kind: 'veto' as const, veto: { at: T0, via: 'operator' as const, by: 'ops' } };

  it('malformed input and unknown events', async () => {
    const u = await fresh();
    expect(u.undoTransition(null as never, veto, T0)).toEqual(refused('invalid', 'malformed record'));
    expect(u.undoTransition(rec(), veto, Number.NaN)).toEqual(refused('invalid', 'now must be a safe integer'));
    expect(u.undoTransition(rec(), undefined as never, T0)).toEqual(refused('invalid', 'unknown event'));
    expect(u.undoTransition(rec(), { kind: 'veto', veto: { at: T0, via: 'operator', by: 5 as never } }, T0)).toEqual(refused('invalid', 'malformed veto'));
    // an evaluation error (here: an effect result that cannot be cloned) fails closed by name
    expect(u.undoTransition(rec(), { kind: 'effect', result: () => 1 }, T0)).toEqual(refused('invalid', 'evaluation error (fail closed)'));
  });

  it('veto, finalize and abort refusals carry their exact reasons; finalize writes the finalized receipt', async () => {
    const u = await fresh();
    expect(u.undoTransition(rec(), veto, END + 1)).toEqual(refused('window_closed', `the veto window closed at ${END}`));
    expect(u.undoTransition(rec({ state: 'vetoed' }), { kind: 'finalize' }, END + 1)).toEqual(refused('vetoed', 'a vetoed record is not finalized'));
    expect(u.undoTransition(rec(), { kind: 'finalize' }, END)).toEqual(refused('window_open', `the veto window is open until ${END}`));
    const f = u.undoTransition(rec(), { kind: 'finalize' }, END + 1);
    expect(f.outcome === 'applied' && f.receipt).toEqual({ event: 'finalized', note: '' });
    expect(u.undoTransition(rec({ state: 'compensated' }), { kind: 'abort', reason: 'r' }, T0)).toEqual(refused('finalized', 'a compensated record cannot be aborted'));
    expect(u.undoTransition(rec({ effect: { at: T0 } }), { kind: 'abort', reason: 'r' }, T0)).toEqual(refused('effect_recorded', 'the effect ran: it can only be compensated or finalized'));
    // only a FINALIZED record with an aborted outcome is an abort replay
    const a = u.undoTransition(rec({ outcome: { at: T0, status: 'aborted' } }), { kind: 'abort', reason: 'r' }, T0);
    expect(a.outcome === 'applied' && [a.record.state, a.receipt]).toEqual(['finalized', { event: 'aborted', note: 'r' }]);
  });

  it('effect and compensation replays return the stored record; an effect without a result stores no result member', async () => {
    const u = await fresh();
    const withEffect = rec({ effect: { at: T0 } });
    expect(u.undoTransition(withEffect, { kind: 'effect' }, T0)).toEqual({ outcome: 'replayed', record: withEffect });
    const done = rec({ state: 'compensated' });
    expect(u.undoTransition(done, { kind: 'compensated' }, T0)).toEqual({ outcome: 'replayed', record: done });
    const e = u.undoTransition(rec(), { kind: 'effect' }, T0 + 2);
    expect(e.outcome === 'applied' && e.record.effect).toStrictEqual({ at: T0 + 2 });
    expect(e.outcome === 'applied' && Object.keys(e.record.effect!)).toEqual(['at']);
  });

  it('compensation and retry refusals carry their exact reasons', async () => {
    const u = await fresh();
    expect(u.undoTransition(rec(), { kind: 'compensated' }, T0)).toEqual(refused('not_vetoed', 'a open record is not being compensated'));
    expect(u.undoTransition(rec(), { kind: 'compensation_failed', reason: 'x' }, T0)).toEqual(refused('not_vetoed', 'a open record is not being compensated'));
    expect(u.undoTransition(rec(), { kind: 'retry' }, T0)).toEqual(refused('not_failed', 'a open record is not retried'));
  });
});

describe('the store contract helpers (fresh module)', () => {
  it('isUndoStore needs each of get, create and replace to be functions', async () => {
    const u = await fresh();
    const f = () => undefined;
    expect(u.isUndoStore({ durable: true, get: f, create: f, replace: f, list: f })).toBe(true);
    expect(u.isUndoStore({ durable: true, create: f, replace: f, list: f })).toBe(false);
    expect(u.isUndoStore({ durable: true, get: f, replace: f, list: f })).toBe(false);
    expect(u.isUndoStore({ durable: true, get: f, create: f, list: f })).toBe(false);
  });

  it('MemoryUndoStore: an id of 256 units is accepted, 257 or a non-string is refused by name', async () => {
    const u = await fresh();
    const s = new u.MemoryUndoStore();
    expect(await s.create(rec({ id: 'x'.repeat(256) }))).toEqual({ created: true });
    for (const id of ['x'.repeat(257), ['a'], '']) {
      const e = await rejection(s.create(rec({ id: id as string })));
      expect([e.code, e.message]).toEqual(['invalid', ID_MSG]);
    }
    const e = await rejection(s.create(undefined as never));
    expect([e.code, e.message]).toEqual(['invalid', ID_MSG]);
  });

  it('MemoryUndoStore: a changed id on replace is refused by name; list filters, limits and sorts with an exact comparator', async () => {
    const u = await fresh();
    const s = new u.MemoryUndoStore();
    await s.create(rec({ id: 'b' }));
    await s.create(rec({ id: 'a' }));
    await s.create(rec({ id: 'c' }));
    await s.create(rec({ id: 'd', state: 'vetoed' }));
    const e = await rejection(s.replace('a', 0, rec({ id: 'z' })));
    expect([e.code, e.message]).toEqual(['invalid', 'invalid: replace: the record id cannot change']);
    expect((await s.list({ state: 'open', limit: 2 })).map((r) => r.id)).toEqual(['a', 'b']);
    const orig = Array.prototype.sort;
    let cmp: ((x: unknown, y: unknown) => number) | undefined;
    Array.prototype.sort = function (this: unknown[], c?: (x: unknown, y: unknown) => number) {
      if (c) cmp = c;
      return orig.call(this, c);
    } as typeof orig;
    let ids: string[] = [];
    try {
      ids = (await s.list({ state: 'open' })).map((r) => r.id);
    } finally {
      Array.prototype.sort = orig;
    }
    expect(ids).toEqual(['a', 'b', 'c']);
    const A = { id: 'a' };
    const B = { id: 'b' };
    expect([cmp!(A, B), cmp!(B, A), cmp!(A, { id: 'a' })]).toEqual([-1, 1, 0]);
  });

  it('KvUndoStore: the constructor names each missing kv method and the missing durability claim', async () => {
    const u = await fresh();
    const kv = createMemoryDurableKv();
    for (const missing of ['get', 'update', 'keys'] as const) {
      const partial: Record<string, unknown> = { ...kv };
      delete partial[missing];
      let got: unknown;
      try {
        new u.KvUndoStore(partial as unknown as DurableKv, true);
      } catch (x) {
        got = x;
      }
      expect([missing, (got as { code?: string })?.code, (got as Error)?.message]).toEqual([missing, 'store_missing', 'store_missing: KvUndoStore needs a DurableKv']);
    }
    let got: unknown;
    try {
      new u.KvUndoStore(kv, 'yes' as never);
    } catch (x) {
      got = x;
    }
    expect([(got as { code?: string })?.code, (got as Error)?.message]).toEqual(['invalid', 'invalid: say whether the kv is durable (true or false)']);
  });

  it('KvUndoStore: records live under the versioned prefix; ids, replaces and corrupt records are refused by name', async () => {
    const u = await fresh();
    const kv = createMemoryDurableKv();
    const s = new u.KvUndoStore(kv, true);
    expect(await s.create(rec())).toEqual({ created: true });
    expect(await kv.keys()).toEqual(['pca-undo/v1/op_1']);
    expect((await s.get('op_1'))!.id).toBe('op_1');
    expect(await s.get('nope')).toBeUndefined();
    const bad = await rejection(s.get(''));
    expect([bad.code, bad.message]).toEqual(['invalid', ID_MSG]);
    const moved = await rejection(s.replace('op_1', 0, rec({ id: 'op_2' })));
    expect([moved.code, moved.message]).toEqual(['invalid', 'invalid: replace: the record id cannot change']);
    await kv.set('pca-undo/v1/v2', { ...rec({ id: 'v2' }), v: 2 });
    const corrupt = await rejection(s.get('v2'));
    expect([corrupt.code, corrupt.message]).toEqual(['store_corrupt', 'store_corrupt: an undo record has the wrong shape']);
  });

  it('KvUndoStore: a kv that never runs the update replaces nothing', async () => {
    const u = await fresh();
    const kv = createMemoryDurableKv();
    const s0 = new u.KvUndoStore(kv, true);
    await s0.create(rec());
    const lazy: DurableKv = { ...kv, update: async (k: string) => kv.get(k) };
    expect(await new u.KvUndoStore(lazy, true).replace('op_1', 0, rec({ ver: 1 }))).toBe(false);
    expect((await s0.get('op_1'))!.ver).toBe(0);
  });

  it('KvUndoStore: list skips foreign keys, sorts the keys itself and stops exactly at the limit', async () => {
    const u = await fresh();
    const kv = createMemoryDurableKv();
    await kv.set('other/key', { not: 'a record' });
    const reversed: DurableKv = { ...kv, keys: async () => (await kv.keys()).reverse() };
    const s = new u.KvUndoStore(reversed, true);
    for (const id of ['a', 'b', 'c']) await s.create(rec({ id }));
    expect((await s.list({ state: 'open' })).map((r) => r.id)).toEqual(['a', 'b', 'c']);
    expect((await s.list({ state: 'open', limit: 2 })).map((r) => r.id)).toEqual(['a', 'b']);
    expect((await s.list({ state: 'open', limit: 1 })).map((r) => r.id)).toEqual(['a']);
  });
});
