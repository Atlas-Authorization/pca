/**
 * The approval-channel undo notifier (which link goes along with which notice, the reason when no channel accepted it) and the
 * hosted veto relay (base URL normalisation, the limit clamp, the request headers, each malformed answer refused by name).
 */
import { describe, expect, it } from 'vitest';
import type { ApprovalDelivery, ApprovalDispatcher, ApprovalNotifyContext } from '../approval-channels';
import { UndoError, type UndoRecord } from '../undo';
import { hostedUndoVetoRelay, undoNotifierFromDispatcher, type UndoRelayFetch } from './undo';

const T0 = 1_800_000_000_000;
const record: UndoRecord = {
  v: 1,
  id: 'op_1',
  aud: 'rs',
  grant_ref: 'g_1',
  holder: 'H'.repeat(43),
  principal: 'P'.repeat(43),
  action: { verb: 'drafts.create', resource: 'drafts:box1', params_digest: 'Q'.repeat(43), def_digest: 'A'.repeat(43) },
  compensation: { verb: 'drafts.delete', resource: 'drafts:box1', params: {}, undo_of: 'op_1', def_digest: 'D'.repeat(43) },
  compensation_digest: 'C'.repeat(43),
  opened_at: T0,
  window_end: T0 + 60_000,
  converted: false,
  state: 'open',
  ver: 0,
  pcactn: 'x',
  attempt: 0,
  receipts: [],
};

const capture = (deliveries: Partial<ApprovalDelivery>[] = [{ kind: 'webhook', delivered: true }]) => {
  const ctxs: (ApprovalNotifyContext | undefined)[] = [];
  const d: ApprovalDispatcher = {
    channels: [],
    notifyAll: async (req, ctx) => (ctxs.push(ctx), deliveries.map((x) => ({ requestId: req.id, payload: {}, kind: 'webhook', delivered: false, ...x }) as ApprovalDelivery)),
  };
  return { d, ctxs };
};

describe('undoNotifierFromDispatcher: the link', () => {
  it('only an opened notice WITH a token carries the one-click link; otherwise the inbox', async () => {
    const urls: string[] = [];
    const cfg = { undoUrl: (t: string, id: string) => (urls.push(t), `https://undo.example/${id}?t=${t}`), inboxUrl: 'https://inbox.example/' };
    const cases: [Parameters<ReturnType<typeof undoNotifierFromDispatcher>['notify']>[0], string][] = [
      [{ kind: 'opened', record, token: 'tok' }, 'https://undo.example/op_1?t=tok'],
      [{ kind: 'opened', record }, 'https://inbox.example/'],
      [{ kind: 'vetoed', record, token: 'tok' }, 'https://inbox.example/'],
    ];
    for (const [notice, link] of cases) {
      const c = capture();
      expect(await undoNotifierFromDispatcher(c.d, cfg).notify(notice)).toEqual({ delivered: true });
      expect([notice.kind, notice.token, c.ctxs]).toEqual([notice.kind, notice.token, [{ inboxUrl: link }]]);
    }
    expect(urls).toEqual(['tok']);
  });

  it('without an inbox URL a non-opened notice carries no link member at all', async () => {
    const c = capture();
    await undoNotifierFromDispatcher(c.d, { undoUrl: () => 'u' }).notify({ kind: 'vetoed', record });
    expect(c.ctxs).toHaveLength(1);
    expect(c.ctxs[0]).toStrictEqual({});
    expect('inboxUrl' in c.ctxs[0]!).toBe(false);
  });

  it('no channel at all is reported as "no enabled channel"', async () => {
    const c = capture([]);
    expect(await undoNotifierFromDispatcher(c.d, { undoUrl: () => 'u' }).notify({ kind: 'vetoed', record })).toEqual({ delivered: false, reason: 'no enabled channel' });
  });
});

describe('hostedUndoVetoRelay', () => {
  const answering = (body: unknown, ok = true, status = 200) => {
    const seen: { url: string; init: { method: string; headers: Record<string, string> } }[] = [];
    const fetch: UndoRelayFetch = async (url, init) => (seen.push({ url, init }), { ok, status, json: async () => body });
    return { fetch, seen };
  };
  async function rejection(p: Promise<unknown>): Promise<unknown> {
    try {
      await p;
    } catch (e) {
      return e;
    }
    throw new Error('expected a rejection');
  }

  it('strips every trailing slash, clamps the limit into [1, 200] and sends the bearer key with a JSON accept header', async () => {
    const want: [number | undefined, number][] = [
      [5, 5],
      [1000, 200],
      [0, 1],
      [7.9, 7],
      [undefined, 200],
    ];
    for (const [limit, sent] of want) {
      const a = answering({ data: [] });
      const relay = hostedUndoVetoRelay({ baseUrl: 'https://api.example//', secretKey: 'sk', fetch: a.fetch, ...(limit !== undefined ? { limit } : {}) });
      expect(await relay.pending()).toEqual([]);
      expect(a.seen).toEqual([{ url: `https://api.example/v1/pca/undo/vetoes?limit=${sent}`, init: { method: 'GET', headers: { authorization: 'Bearer sk', accept: 'application/json' } } }]);
    }
  });

  it('a non-2xx answer is an invalid-relay error with the status', async () => {
    const e = await rejection(hostedUndoVetoRelay({ baseUrl: 'https://api.example', secretKey: 'sk', fetch: answering({}, false, 503).fetch }).pending());
    expect(e).toBeInstanceOf(UndoError);
    expect([(e as UndoError).code, (e as UndoError).message]).toEqual(['invalid', 'invalid: the veto relay answered 503']);
  });

  it('each malformed entry is refused by name, never mapped and never a TypeError', async () => {
    const rows: unknown[] = [null, { record_id: 5, veto: { token: 't', at: 1 } }, { record_id: 'r1' }, { record_id: 'r1', veto: { at: 1 } }, { record_id: 'r1', veto: { token: 't', at: '1' } }];
    for (const row of rows) {
      const e = await rejection(hostedUndoVetoRelay({ baseUrl: 'https://api.example', secretKey: 'sk', fetch: answering({ data: [row] }).fetch }).pending());
      expect([JSON.stringify(row), e instanceof UndoError, (e as Error).message]).toEqual([JSON.stringify(row), true, 'invalid: the veto relay answered a malformed entry']);
    }
  });
});
