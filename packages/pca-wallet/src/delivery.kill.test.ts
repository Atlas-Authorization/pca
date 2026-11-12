import { afterEach, describe, expect, it, vi } from 'vitest';
import { clarificationNotice, questionText, questionTextChannel, questionWebhookChannel } from './index';

const n = clarificationNotice('s1', 'q1');

afterEach(() => vi.unstubAllGlobals());

describe('clarification notice', () => {
  it('has the exact type and carries the inbox url only when given', () => {
    expect(clarificationNotice('s1', 'q1', 'https://w.example/i')).toEqual({ type: 'pca.intent.clarification', session: 's1', question_id: 'q1', inbox_url: 'https://w.example/i' });
    expect(clarificationNotice('s1', 'q1')).toEqual({ type: 'pca.intent.clarification', session: 's1', question_id: 'q1' });
  });
});

describe('webhook channel', () => {
  it('is enabled only for a non-empty url', async () => {
    const calls: string[] = [];
    const fetch = async (url: string) => (calls.push(url), { ok: true, status: 200 });
    expect(questionWebhookChannel({}).enabled).toBe(false);
    const empty = questionWebhookChannel({ url: '', fetch });
    expect(empty.enabled).toBe(false);
    expect(await empty.notify(n)).toEqual({ kind: 'webhook', questionId: 'q1', payload: n, delivered: false, reason: 'webhook channel not configured' });
    expect(calls).toEqual([]);
    expect(questionWebhookChannel({ url: 'x', fetch }).enabled).toBe(true);
  });
  it('posts JSON with the default and custom headers and reports the status', async () => {
    const seen: { url: string; init: { method: string; headers: Record<string, string>; body: string } }[] = [];
    const fetch = async (url: string, init: { method: string; headers: Record<string, string>; body: string }) => (seen.push({ url, init }), { ok: true, status: 202 });
    const r = await questionWebhookChannel({ url: 'https://w.example/p', fetch, headers: { 'x-a': 'b' } }).notify(n);
    expect(r).toEqual({ kind: 'webhook', questionId: 'q1', payload: n, delivered: true, status: 202 });
    expect(seen).toEqual([{ url: 'https://w.example/p', init: { method: 'POST', headers: { 'content-type': 'application/json', 'x-a': 'b' }, body: JSON.stringify(n) } }]);
    await questionWebhookChannel({ url: 'https://w.example/p', fetch }).notify(n);
    expect(seen[1]!.init.headers).toEqual({ 'content-type': 'application/json' });
  });
  it('a non-ok response is an undelivered result with the status', async () => {
    const r = await questionWebhookChannel({ url: 'u', fetch: async () => ({ ok: false, status: 503 }) }).notify(n);
    expect(r).toEqual({ kind: 'webhook', questionId: 'q1', payload: n, delivered: false, status: 503, reason: 'webhook returned 503' });
  });
  it('a transport error is an undelivered result', async () => {
    const e = await questionWebhookChannel({ url: 'u', fetch: async () => { throw new Error('boom'); } }).notify(n);
    expect(e).toEqual({ kind: 'webhook', questionId: 'q1', payload: n, delivered: false, reason: 'boom' });
    const s = await questionWebhookChannel({ url: 'u', fetch: async () => { throw 'str'; } }).notify(n);
    expect(s).toEqual({ kind: 'webhook', questionId: 'q1', payload: n, delivered: false, reason: 'webhook transport error' });
  });
  it('falls back to the global fetch, passing url and init through', async () => {
    const g = vi.fn(async () => ({ ok: true, status: 201 }));
    vi.stubGlobal('fetch', g);
    const r = await questionWebhookChannel({ url: 'https://w.example/g' }).notify(n);
    expect(r).toMatchObject({ delivered: true, status: 201 });
    expect(g).toHaveBeenCalledTimes(1);
    expect(g.mock.calls[0]).toEqual(['https://w.example/g', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(n) }]);
  });
  it('without any fetch the delivery fails with a clear reason', async () => {
    vi.stubGlobal('fetch', undefined);
    const r = await questionWebhookChannel({ url: 'https://w.example/g' }).notify(n);
    expect(r).toMatchObject({ delivered: false, reason: 'no fetch available: pass a FetchLike transport' });
  });
});

describe('question text', () => {
  const q = { type: 'pca.intent.question' as const, session: 's', question_id: 'q 1', site: 'x', friction: 'tap' as const, expires_at: 1, intent_required: {} as never };
  it('falls back to "A site" for an empty name', () => {
    expect(questionText(q, ' \n ').subject).toBe('A site has a question about your request');
  });
  it('appends the question id with ? or & depending on the inbox url', () => {
    expect(questionText({ ...q, inbox_url: 'https://w.example/i' }, 'S').text).toBe('S has a question about your request\n\nOpen your wallet to answer: https://w.example/i?question=q%201');
    expect(questionText({ ...q, inbox_url: 'https://w.example/i?a=1' }, 'S').text).toBe('S has a question about your request\n\nOpen your wallet to answer: https://w.example/i?a=1&question=q%201');
  });
  it('has no link line without an inbox url', () => {
    expect(questionText(n, 'S')).toEqual({ subject: 'Your agent needs a decision about your request', text: 'Your agent needs a decision about your request\n\nOpen your wallet to answer.' });
  });
});

describe('text channels', () => {
  it('an unconfigured channel reports it by kind', async () => {
    const c = questionTextChannel('email', { siteName: 'S' });
    expect(c.kind).toBe('email');
    expect(c.enabled).toBe(false);
    expect(await c.notify(n)).toEqual({ kind: 'email', questionId: 'q1', payload: questionText(n, 'S'), delivered: false, reason: 'email channel not configured' });
  });
  it('a non-function sender is not enabled and is never called', async () => {
    const c = questionTextChannel('sms', { siteName: 'S', send: 'nope' as never });
    expect(c.enabled).toBe(false);
    expect(await c.notify(n)).toMatchObject({ delivered: false, reason: 'sms channel not configured' });
  });
  it('send success and failures', async () => {
    const sent: unknown[] = [];
    const ok = await questionTextChannel('push', { siteName: 'S', send: async (b) => (sent.push(b), {}) }).notify(n);
    expect(ok).toEqual({ kind: 'push', questionId: 'q1', payload: questionText(n, 'S'), delivered: true });
    expect(sent).toEqual([questionText(n, 'S')]);
    const e = await questionTextChannel('push', { siteName: 'S', send: async () => { throw new Error('down'); } }).notify(n);
    expect(e).toEqual({ kind: 'push', questionId: 'q1', payload: questionText(n, 'S'), delivered: false, reason: 'down' });
    const s = await questionTextChannel('sms', { siteName: 'S', send: async () => { throw 7; } }).notify(n);
    expect(s).toMatchObject({ delivered: false, reason: 'sms send error' });
  });
});
