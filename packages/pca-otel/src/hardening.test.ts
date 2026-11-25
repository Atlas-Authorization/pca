import { describe, expect, it } from 'vitest';
import { type GuardResultLike, type SpanLike, type TracerLike, instrumentGuard, pcaSpanAttributes, redactSecrets } from './index';

const JWT = 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyMSJ9.c2lnbmF0dXJlYnl0ZXM';
const KEY = 'sk_' + 'live_' + 'x'.repeat(36); // built at runtime so secret scanners don't flag the fixture
const DSN = 'postgres://app:hunter2@db.internal:5432/pca';

class Span implements SpanLike {
  attrs: Record<string, string | number | boolean> = {};
  status?: { code: number; message?: string };
  exceptions: Error[] = [];
  ended = 0;
  setAttribute(k: string, v: string | number | boolean) { this.attrs[k] = v; }
  setStatus(s: { code: number; message?: string }) { this.status = s; }
  recordException(e: unknown) { this.exceptions.push(e as Error); }
  end() { this.ended++; }
}
const tracerOf = (sp: Span): TracerLike => ({ startSpan: () => sp });

describe('redactSecrets', () => {
  it.each([
    ['a JWT', `token ${JWT} here`, 'token [redacted] here'],
    ['a bearer credential', 'Authorization: Bearer abc123.def-456_xyz', 'Authorization: [redacted]'],
    ['url userinfo', `connect ${DSN} failed`, 'connect postgres://[redacted]@db.internal:5432/pca failed'],
    ['a key=value pair', 'GET /x?api_key=abcd1234&page=2', 'GET /x?api_key=[redacted]&page=2'],
    ['a json pair', '{"password": "p@ss w0rd"}', '{"password": "[redacted]"}'],
    ['a long token', `bad key ${KEY}`, 'bad key [redacted]'],
    ['a hex digest', `sha ${'a1'.repeat(32)}`, 'sha [redacted]'],
  ])('removes %s', (_n, input, out) => {
    const got = redactSecrets(input);
    expect(got).toBe(out);
  });
  it('leaves ordinary text and short ids alone', () => {
    for (const t of ['risk too high', 'stripe.refund', 'pi_123', '/orders/42/line/1', 'step-up required for tier 3']) expect(redactSecrets(t)).toBe(t);
  });
  it('cuts long text to 256 characters', () => {
    expect(redactSecrets('word '.repeat(200))).toBe(`${'word '.repeat(200).slice(0, 256)}...`);
    expect(redactSecrets('x'.repeat(256))).toBe('x'.repeat(256).replace(/x{32,}/, '[redacted]'));
  });
});

describe('no secret reaches telemetry', () => {
  const leaky: GuardResultLike = {
    ok: false,
    status: 403,
    verdict: { allow: false, r: 0.4, reasons: [`token ${JWT} was rejected for ${DSN}`] },
    pcactn: { action: { verb: 'db.query', resource: `https://api.example/v1/items?token=${KEY}&id=7` } },
  };
  it('span attributes, status message and metrics', async () => {
    const sp = new Span();
    const counts: unknown[] = [];
    const wrapped = instrumentGuard(async () => leaky, { tracer: tracerOf(sp), meter: { createCounter: () => ({ add: (n, a) => counts.push([n, a]) }), createHistogram: () => ({ record: (n, a) => counts.push([n, a]) }) } });
    expect(await wrapped({})).toBe(leaky);
    const dump = JSON.stringify([sp.attrs, sp.status, counts]);
    for (const secret of [JWT, KEY, 'hunter2', 'eyJhbGci']) expect(dump).not.toContain(secret);
    expect(sp.attrs['pca.resource']).toBe('https://api.example/v1/items?token=[redacted]&id=7');
    expect(sp.attrs['pca.verb']).toBe('db.query');
    expect(sp.status?.code).toBe(2);
  });
  it('a recorded exception is a clean copy: no secret in message, stack or cause', async () => {
    const sp = new Span();
    const err = new Error(`could not reach ${DSN} with ${KEY}`, { cause: new Error(JWT) });
    const wrapped = instrumentGuard(async () => { throw err; }, { tracer: tracerOf(sp) });
    await expect(wrapped({})).rejects.toBe(err); // the caller still sees the original
    const rec = sp.exceptions[0] as Error & { cause?: unknown };
    expect(JSON.stringify([rec.message, rec.stack, rec.cause, sp.status])).not.toMatch(/hunter2|sk_live|eyJ/);
    expect(rec).not.toBe(err);
    expect(rec.cause).toBeUndefined();
    expect(sp.status).toEqual({ code: 2, message: rec.message });
  });
  it('a custom redactor is honoured, and a throwing one does not break the guard', async () => {
    const sp = new Span();
    await instrumentGuard(async () => leaky, { tracer: tracerOf(sp), redact: () => 'X' })({});
    expect(sp.attrs['pca.reason']).toBe('X');
    const sp2 = new Span();
    const r = await instrumentGuard(async () => leaky, { tracer: tracerOf(sp2), redact: () => { throw new Error('boom'); } })({});
    expect(r).toBe(leaky);
    expect(sp2.ended).toBe(1);
  });
});

describe('telemetry never changes the decision', () => {
  const ALLOW: GuardResultLike = { ok: true, status: 200, verdict: { allow: true, r: 0.1, requiredThreshold: { t: 1 } } };
  const broken: TracerLike = { startSpan: () => ({ setAttribute: () => { throw new Error('x'); }, setStatus: () => { throw new Error('x'); }, recordException: () => { throw new Error('x'); }, end: () => { throw new Error('x'); } }) };
  it('a tracer that throws on every call still returns the guard result', async () => {
    expect(await instrumentGuard(async () => ALLOW, { tracer: broken })({})).toBe(ALLOW);
  });
  it('a tracer whose startSpan throws still returns the guard result', async () => {
    const t: TracerLike = { startSpan: () => { throw new Error('x'); } };
    expect(await instrumentGuard(async () => ALLOW, { tracer: t })({})).toBe(ALLOW);
  });
  it('a meter that throws still returns the guard result', async () => {
    const meter = { createCounter: () => ({ add: () => { throw new Error('x'); } }), createHistogram: () => ({ record: () => { throw new Error('x'); } }) };
    expect(await instrumentGuard(async () => ALLOW, { meter })({})).toBe(ALLOW);
  });
  it('the guard failure is rethrown unchanged even when the tracer is broken', async () => {
    const boom = new Error('verifier exploded');
    await expect(instrumentGuard(async () => { throw boom; }, { tracer: broken })({})).rejects.toBe(boom);
  });
  it('the span is ended exactly once on every path', async () => {
    for (const g of [async () => ALLOW, async () => ({ ok: false }) as GuardResultLike, async () => { throw new Error('e'); }]) {
      const sp = new Span();
      await instrumentGuard(g, { tracer: tracerOf(sp) })({}).catch(() => undefined);
      expect(sp.ended).toBe(1);
    }
  });
});

describe('malformed results fail to a deny, not a crash or an allow', () => {
  it.each([[undefined], [null], [{}], [{ ok: 'yes' }], [{ ok: 1 }]])('reports %j as a deny', (r) => {
    expect(pcaSpanAttributes(r as never)['pca.decision']).toBe('deny');
  });
  it('the wrapper returns whatever the guard returned and reports a deny for it', async () => {
    const sp = new Span();
    const weird = undefined as never;
    expect(await instrumentGuard(async () => weird, { tracer: tracerOf(sp) })({})).toBeUndefined();
    expect(sp.attrs['pca.decision']).toBe('deny');
    expect(sp.status).toEqual({ code: 2 });
  });
  it('non-finite numbers are not exported', async () => {
    const sp = new Span();
    const hist: number[] = [];
    const bad: GuardResultLike = { ok: true, status: Number.NaN, verdict: { allow: true, r: Infinity, requiredThreshold: { t: Number.NaN } } };
    await instrumentGuard(async () => bad, { tracer: tracerOf(sp), meter: { createCounter: () => ({ add: () => {} }), createHistogram: () => ({ record: (n) => void hist.push(n) }) } })({});
    expect(sp.attrs).toEqual({ 'pca.decision': 'allow' });
    expect(hist).toEqual([]);
  });
  it('non-string verb, resource and reason are dropped', () => {
    expect(pcaSpanAttributes({ ok: false, verdict: { allow: false, reasons: [5 as never] }, pcactn: { action: { verb: 5 as never, resource: {} as never } } })).toEqual({ 'pca.decision': 'deny' });
  });
});
