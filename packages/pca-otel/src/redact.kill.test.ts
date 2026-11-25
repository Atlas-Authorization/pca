import { describe, expect, it } from 'vitest';
import { type GuardResultLike, type SpanLike, instrumentGuard, pcaSpanAttributes, redactSecrets } from './index';

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

describe('redactSecrets patterns', () => {
  it('a JWT needs a real first and second segment', () => {
    expect(redactSecrets('x eyJabcde.fghijk.sig y')).toBe('x [redacted] y');
    expect(redactSecrets('x eyJabcde.fghijk. y')).toBe('x [redacted] y');
  });
  it('authorization header forms', () => {
    expect(redactSecrets('{"authorization": "abcdef ghi"}')).toBe('{"authorization": [redacted]"abcdef ghi"}');
    expect(redactSecrets('authorization : value1')).toBe('authorization : [redacted]');
    expect(redactSecrets('authorization:value1')).toBe('authorization:[redacted]');
    expect(redactSecrets('authorization:   value1')).toBe('authorization:   [redacted]');
  });
  it('Bearer / Basic / Token credentials of 6+ characters, after any whitespace run', () => {
    expect(redactSecrets('Bearer  abcdefgh')).toBe('Bearer [redacted]');
    expect(redactSecrets('Bearer abcdefgh')).toBe('Bearer [redacted]');
    expect(redactSecrets('Basic dXNlcjpwYXNz')).toBe('Basic [redacted]');
    expect(redactSecrets('Bearer abcde')).toBe('Bearer abcde');
  });
  it('URL userinfo for any scheme shape', () => {
    expect(redactSecrets('x://u:p@h')).toBe('x://[redacted]@h');
    expect(redactSecrets('a1://u:p@h')).toBe('a1://[redacted]@h');
    expect(redactSecrets('postgres://app:hunter2@db')).toBe('postgres://[redacted]@db');
  });
  it('every credential name, case-insensitively, with optional quotes and spacing', () => {
    for (const n of ['token', 'secret', 'password', 'passwd', 'pwd', 'api_key', 'api-key', 'apikey', 'key', 'signature', 'sig', 'credential', 'auth', 'PASSWORD']) {
      expect(redactSecrets(`${n}=abcdefg`)).toBe(`${n}=[redacted]`);
      expect(redactSecrets(`${n}: abcdefg`)).toBe(`${n}: [redacted]`);
      expect(redactSecrets(`${n} = abcdefg`)).toBe(`${n} = [redacted]`);
    }
    expect(redactSecrets(`'password': 'a b c'`)).toBe(`'password': '[redacted]'`);
    expect(redactSecrets(`password='a b c' tail`)).toBe(`password='[redacted]' tail`);
    expect(redactSecrets(`password="a b c" tail`)).toBe(`password="[redacted]" tail`);
  });
  it('an unquoted value ends at whitespace, quote, ampersand, comma or semicolon', () => {
    expect(redactSecrets('password=abc def')).toBe('password=[redacted] def');
    expect(redactSecrets('password=abc&x=1')).toBe('password=[redacted]&x=1');
    expect(redactSecrets('password=abc,next')).toBe('password=[redacted],next');
    expect(redactSecrets('password=abc;next')).toBe('password=[redacted];next');
    expect(redactSecrets(`password=abc"next`)).toBe(`password=[redacted]"next`);
    expect(redactSecrets(`password=abc'next`)).toBe(`password=[redacted]'next`);
  });
  it('truncates only past 256 characters', () => {
    const t256 = 'ab '.repeat(86).slice(0, 256);
    expect(t256).toHaveLength(256);
    expect(redactSecrets(t256)).toBe(t256);
    const t257 = 'ab '.repeat(86).slice(0, 257);
    expect(redactSecrets(t257)).toBe(`${t257.slice(0, 256)}...`);
  });
});

describe('pcaSpanAttributes tolerates sparse results', () => {
  it('a deny without verdict reasons, and a result without an action, do not throw', () => {
    expect(pcaSpanAttributes({ ok: false, verdict: { allow: false } })).toEqual({ 'pca.decision': 'deny' });
    expect(pcaSpanAttributes({ ok: true, pcactn: {} })).toEqual({ 'pca.decision': 'allow' });
  });
  it('an allow never carries a reason, even when the verdict lists some', () => {
    expect(pcaSpanAttributes({ ok: true, verdict: { allow: true, reasons: ['why'] } })).toEqual({ 'pca.decision': 'allow' });
  });
});

describe('instrumentGuard without a tracer', () => {
  const full: GuardResultLike = { ok: false, status: 403, verdict: { allow: false, reasons: ['r'] }, pcactn: { action: { verb: 'a.b', resource: 'res' } } };
  it('never touches the redactor on a result, or on a thrown error', async () => {
    const seen: string[] = [];
    const redact = (s: string) => { seen.push(s); return s; };
    expect(await instrumentGuard(async () => full, { redact })({})).toBe(full);
    await expect(instrumentGuard(async () => { throw new Error('bad'); }, { redact })({})).rejects.toThrow('bad');
    expect(seen).toEqual([]);
  });
  it('returns an allow that has no verdict', async () => {
    const r: GuardResultLike = { ok: true };
    expect(await instrumentGuard(async () => r, { tracer: { startSpan: () => new Span() } })({})).toBe(r);
  });
});

describe('instrumentGuard records a clean exception', () => {
  const run = async (thrown: unknown) => {
    const sp = new Span();
    await expect(instrumentGuard(async () => { throw thrown; }, { tracer: { startSpan: () => sp } })({})).rejects.toBe(thrown);
    return sp;
  };
  it('keeps a word-like error name up to 64 characters and falls back to "Error" otherwise', async () => {
    expect((await run(new TypeError('x'))).exceptions[0]!.name).toBe('TypeError');
    const n64 = Object.assign(new Error('x'), { name: 'a'.repeat(64) });
    expect((await run(n64)).exceptions[0]!.name).toBe('a'.repeat(64));
    for (const name of ['a'.repeat(65), 'a b', 'ab c', ' ab', 'ab ', '', 'a-b']) {
      expect((await run(Object.assign(new Error('x'), { name }))).exceptions[0]!.name).toBe('Error');
    }
  });
  it('a non-Error throw is recorded as an Error named "Error" with the stringified value', async () => {
    const sp = await run('plain');
    expect(sp.exceptions[0]!.name).toBe('Error');
    expect(sp.exceptions[0]!.message).toBe('plain');
    expect(sp.status).toEqual({ code: 2, message: 'plain' });
    expect(sp.ended).toBe(1);
  });
});
