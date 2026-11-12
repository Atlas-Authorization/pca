import { describe, expect, it } from 'vitest';
import { scrubDeep, scrubText } from './scrub';

describe('scrubText: each rule on its own', () => {
  it('redacts a JWT including an empty or long signature, and requires 5+ chars in the first two parts', () => {
    expect(scrubText('x eyJabcde.fghij.klmnop y')).toBe('x [redacted] y');
    expect(scrubText('x eyJabcde.fghij. y')).toBe('x [redacted] y');
    expect(scrubText('x eyJabcd.fghij.klm y')).toBe('x eyJabcd.fghij.klm y');
    expect(scrubText('x eyJabcde.fghi.klm y')).toBe('x eyJabcde.fghi.klm y');
    expect(scrubText('x eyJ-----.-----.- y')).toBe('x [redacted] y');
  });

  it('redacts an authorization header value with optional quote and spacing', () => {
    expect(scrubText('authorization: v1')).toBe('authorization: [redacted]');
    expect(scrubText('Authorization": v1')).toBe('Authorization": [redacted]');
    expect(scrubText('authorization : v1')).toBe('authorization : [redacted]');
    expect(scrubText('authorization:v1')).toBe('authorization:[redacted]');
    expect(scrubText('authorization=v1 w2\nnext')).toBe('authorization=[redacted]\nnext');
  });

  it('redacts Bearer / Basic / Token credentials of 6+ chars after any whitespace run', () => {
    expect(scrubText('Bearer abcdef123')).toBe('Bearer [redacted]');
    expect(scrubText('basic   abc.def~g+h/i=')).toBe('basic [redacted]');
    expect(scrubText('Token\tabcdef')).toBe('Token [redacted]');
    expect(scrubText('Bearer abcde')).toBe('Bearer abcde');
    expect(scrubText('Bearer')).toBe('Bearer');
  });

  it('redacts URL userinfo for any scheme shape', () => {
    expect(scrubText('postgres://app:hunter2@db/pca')).toBe('postgres://[redacted]@db/pca');
    expect(scrubText('x://u:p@h')).toBe('x://[redacted]@h');
    expect(scrubText('x1://u:p@h')).toBe('x1://[redacted]@h');
    expect(scrubText('git+ssh://u:p@h')).toBe('git+ssh://[redacted]@h');
    expect(scrubText('https://host/path')).toBe('https://host/path');
  });

  it('redacts credential-named pairs', () => {
    for (const name of ['token', 'secret', 'password', 'passwd', 'pwd', 'api_key', 'api-key', 'apikey', 'key', 'signature', 'sig', 'credential', 'auth', 'sslpassword']) {
      expect(scrubText(`${name}=v1x`)).toBe(`${name}=[redacted]`);
      expect(scrubText(`${name.toUpperCase()}: v1x`)).toBe(`${name.toUpperCase()}: [redacted]`);
    }
    expect(scrubText('"password": "abc def"')).toBe('"password": [redacted]');
    expect(scrubText("'secret'='a b'")).toBe("'secret'=[redacted]");
    expect(scrubText('password : v1x')).toBe('password : [redacted]');
    expect(scrubText('token= abc')).toBe('token= [redacted]');
    expect(scrubText('token=abc&x=1')).toBe('token=[redacted]&x=1');
    expect(scrubText('key: abc def')).toBe('key: [redacted] def');
    expect(scrubText('token=abc,next;more')).toBe('token=[redacted],next;more');
    expect(scrubText('token=abcdef')).toBe('token=[redacted]');
  });

  it('redacts 40+ character token runs only', () => {
    expect(scrubText(`a ${'A'.repeat(40)} b`)).toBe('a [redacted] b');
    expect(scrubText(`a ${'_-aZ09'.repeat(7)} b`)).toBe('a [redacted] b');
    expect(scrubText(`a ${'A'.repeat(39)} b`)).toBe(`a ${'A'.repeat(39)} b`);
  });

  it('truncates past 600 characters with an ellipsis, not at exactly 600', () => {
    const t600 = 'x '.repeat(300);
    expect(scrubText(t600)).toBe(t600);
    const t601 = `${t600}x`;
    expect(scrubText(t601)).toBe(`${t600}...`);
    expect(scrubText('x '.repeat(400))).toBe(`${'x '.repeat(300)}...`);
  });
});

describe('scrubDeep', () => {
  it('scrubs strings at depth up to and including 9 levels, and walks arrays', () => {
    const secret = 'password=hunter2';
    const o9 = { s: secret };
    const o8 = { s: secret, next: o9 };
    let cur: Record<string, unknown> = o8;
    for (let i = 0; i < 8; i++) cur = { next: cur };
    const out = scrubDeep(cur) as Record<string, unknown>;
    let n: Record<string, unknown> = out;
    for (let i = 0; i < 8; i++) n = n.next as Record<string, unknown>;
    // the object at call depth 8 is still processed; the one at depth 9 is returned as is
    expect(n.s).toBe('password=[redacted]');
    expect((n.next as { s: string }).s).toBe(secret);
    expect(scrubDeep(['token=abc', { k: 'token=abc' }, 3, null])).toEqual(['token=[redacted]', { k: 'token=[redacted]' }, 3, null]);
    expect(scrubDeep(null)).toBeNull();
    expect(scrubDeep(7)).toBe(7);
  });
});
