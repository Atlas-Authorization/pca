import { describe, expect, it } from 'vitest';
import { hashCanonical } from '@atlasauth/pca';
import type { AuthorizeResult } from '@atlasauth/pca';
import { authFixture } from './test-auth';
import { HandleTable, ReceiptLog, type Executor } from './index';

const op = { verb: 'notes.read', resource: 'notes', params: { id: 'n-7' } };
const empty = { op_id: '', verb: '', resource: '', params_digest: '' };

describe('handle receipts and executor failures', () => {
  const mk = async (exec: Executor) => {
    const f = authFixture(['notes']);
    const log = new ReceiptLog({ now: () => 5 });
    const t = new HandleTable('none', log, { 'notes.read': exec });
    const result = await f.allow(op);
    const h = t.mint(result, op);
    return { t, h, log, result: result as AuthorizeResult & { operation: { id: string } } };
  };

  it('an unknown handle is refused with an empty subject, in the receipt too', async () => {
    const log = new ReceiptLog({ now: () => 5 });
    const t = new HandleTable('none', log, {});
    expect(t.use(3)).toEqual({ ok: false, reason: 'unknown_handle' });
    expect(await t.useAsync(0)).toEqual({ ok: false, reason: 'unknown_handle' });
    expect(log.entries.map((e) => [e.kind, e.outcome, e.reason, e.subject])).toEqual([
      ['handle_use', 'refused', 'unknown_handle', empty],
      ['handle_use', 'refused', 'unknown_handle', empty],
    ]);
  });

  it('the receipt names the authorizing operation id and the params digest', async () => {
    const { t, h, log, result } = await mk(() => Uint8Array.of(1));
    t.use(h);
    expect(result.operation.id).not.toBe('');
    expect(log.entries[0]!.subject).toEqual({ op_id: result.operation.id, verb: 'notes.read', resource: 'notes', params_digest: hashCanonical(op.params) });
  });

  it('a result that carries no operation id mints a handle whose receipts have an empty op_id', async () => {
    const log = new ReceiptLog();
    const t = new HandleTable('none', log, { 'notes.read': () => Uint8Array.of(1) });
    const bare = { allow: true, operation: { verb: op.verb, resource: op.resource, params_digest: hashCanonical(op.params) } } as unknown as AuthorizeResult;
    const h = t.mint(bare, op);
    t.use(h);
    expect(log.entries[0]!.subject.op_id).toBe('');
  });

  it('a non-bytes result on the sync path is an executor_error receipted as error', async () => {
    const { t, h, log } = await mk((() => 'text') as unknown as Executor);
    expect(t.use(h)).toEqual({ ok: false, reason: 'executor_error' });
    expect(log.entries.map((e) => [e.outcome, e.reason])).toEqual([['error', 'executor_error']]);
  });

  it('a promise on the sync path is an executor_error and its rejection is handled', async () => {
    const seen: unknown[] = [];
    const on = (r: unknown) => seen.push(r);
    process.on('unhandledRejection', on);
    try {
      const { t, h, log } = await mk((() => Promise.reject(new Error('late'))) as unknown as Executor);
      expect(t.use(h)).toEqual({ ok: false, reason: 'executor_error' });
      expect(log.entries.map((e) => [e.outcome, e.reason])).toEqual([['error', 'executor_error']]);
      await new Promise((r) => setTimeout(r, 30));
      expect(seen).toEqual([]);
    } finally {
      process.off('unhandledRejection', on);
    }
  });

  it('a non-bytes resolved value on the async path is an executor_error receipted as error', async () => {
    const { t, h, log } = await mk((async () => 'text') as unknown as Executor);
    expect(await t.useAsync(h)).toEqual({ ok: false, reason: 'executor_error' });
    expect(log.entries.map((e) => [e.outcome, e.reason])).toEqual([['error', 'executor_error']]);
  });

  it('a rejecting async executor is an executor_error and the use stays spent', async () => {
    const { t, h, log } = await mk(async () => { throw new Error('x'); });
    expect(await t.useAsync(h)).toEqual({ ok: false, reason: 'executor_error' });
    expect(await t.useAsync(h)).toEqual({ ok: false, reason: 'spent' });
    expect(log.entries.map((e) => [e.outcome, e.reason])).toEqual([['error', 'executor_error'], ['refused', 'spent']]);
  });

  it('a handle that ends up with children still revokes the subtree (children are numbers only)', async () => {
    const f = authFixture(['notes']);
    const t = new HandleTable('none', new ReceiptLog(), { 'notes.read': () => Uint8Array.of(1) });
    const p = t.mint(await f.allow(op), op, { uses: 3 });
    const c = t.attenuate(p, { uses: 1 });
    t.revoke(p);
    expect(t.use(c)).toEqual({ ok: false, reason: 'spent' });
    expect(t.use(p)).toEqual({ ok: false, reason: 'spent' });
  });
});
