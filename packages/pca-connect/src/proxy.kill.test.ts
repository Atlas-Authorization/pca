import { hashCanonical } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { DEFAULT_PROXY_HEADERS, checkProxyHeaders, httpExtractor, outboundRequestDigest, type ProxyRequest } from './proxy';

/** Run `fn` and describe how it refused: `<code>: <message>`, or `no error`. */
const refusal = (fn: () => unknown): string => {
  try {
    fn();
    return 'no error';
  } catch (e) {
    return `${(e as { code?: string }).code ?? (e as Error).name}: ${(e as Error).message}`;
  }
};
const refused = (m: string): string => `request_mismatch: outbound request refused: ${m}`;

const BASE = 'https://api.example/v1/items';
const JSON_H = { 'Content-Type': 'application/json' };
const FORM_H = { 'Content-Type': 'application/x-www-form-urlencoded' };

describe('httpExtractor configuration', () => {
  it('rejects a url with a query, a fragment, a placeholder in either, userinfo, or a non-https scheme', () => {
    const msg = 'httpExtractor: url must be https without query, fragment or userinfo';
    for (const url of [`${BASE}?a=1`, `${BASE}?{q}`, `${BASE}#f`, `${BASE}#{f}`, 'https://u@api.example/v1', 'https://u:p@api.example/v1', 'https://:p@api.example/v1', 'http://api.example/v1']) {
      expect(() => httpExtractor({ method: 'GET', url }), url).toThrow(new TypeError(msg));
      expect(refusal(() => httpExtractor({ method: 'GET', url })), url).toBe(`TypeError: ${msg}`);
    }
  });

  it('rejects a method that is not upper case', () => {
    expect(refusal(() => httpExtractor({ method: 'get', url: BASE }))).toBe('TypeError: httpExtractor: method must be upper case');
  });
});

describe('httpExtractor request matching', () => {
  const get = httpExtractor({ method: 'GET', url: `${BASE}/{id}`, query: ['page'] });

  it('maps a conforming request to its parameters', () => {
    expect(get({ method: 'GET', url: `${BASE}/42?page=2` })).toEqual({ id: '42', page: '2' });
    expect(get({ method: 'GET', url: `${BASE}/a%20b` })).toEqual({ id: 'a b' });
  });

  it('refuses another method with an exact message', () => {
    expect(refusal(() => get({ method: 'POST', url: `${BASE}/42` }))).toBe(refused('method POST is not GET'));
  });

  it('refuses a url that does not parse', () => {
    expect(refusal(() => get({ method: 'GET', url: 'not a url' }))).toBe(refused('the url does not parse'));
  });

  it('refuses another origin and any userinfo, each on its own', () => {
    const m = refused('the url is not on the pinned origin');
    expect(refusal(() => get({ method: 'GET', url: 'https://evil.example/v1/items/1' }))).toBe(m);
    expect(refusal(() => get({ method: 'GET', url: 'https://u@api.example/v1/items/1' }))).toBe(m);
    expect(refusal(() => get({ method: 'GET', url: 'https://:p@api.example/v1/items/1' }))).toBe(m);
    expect(refusal(() => get({ method: 'GET', url: `${BASE}/1#frag` }))).toBe(m);
  });

  it('refuses a path outside the template, even when the template has no placeholder', () => {
    const m = refused('the path does not match the pinned template');
    expect(refusal(() => get({ method: 'GET', url: 'https://api.example/v1/other/1' }))).toBe(m);
    const fixedPath = httpExtractor({ method: 'GET', url: 'https://api.example/v1.0/status' });
    expect(fixedPath({ method: 'GET', url: 'https://api.example/v1.0/status' })).toEqual({});
    expect(refusal(() => fixedPath({ method: 'GET', url: 'https://api.example/v1.0/other' }))).toBe(m);
    // literal text is matched literally: '.' is not a wildcard
    expect(refusal(() => fixedPath({ method: 'GET', url: 'https://api.example/v1x0/status' }))).toBe(m);
  });

  it('escapes regular-expression characters in the literal path', () => {
    const ex = httpExtractor({ method: 'GET', url: 'https://api.example/a+b(c)/{id}' });
    expect(ex({ method: 'GET', url: 'https://api.example/a+b(c)/7' })).toEqual({ id: '7' });
    expect(refusal(() => ex({ method: 'GET', url: 'https://api.example/aab(c)/7' }))).toBe(refused('the path does not match the pinned template'));
  });

  it('refuses a path segment that is not valid percent-encoding', () => {
    expect(refusal(() => get({ method: 'GET', url: `${BASE}/%E0%A4%A` }))).toBe(refused('a path segment is not valid percent-encoding'));
  });

  it('keeps the specific reason when a placeholder name repeats in the path', () => {
    const ex = httpExtractor({ method: 'GET', url: 'https://api.example/a/{x}/b/{x}' });
    expect(refusal(() => ex({ method: 'GET', url: 'https://api.example/a/1/b/2' }))).toBe(refused("parameter 'x' is carried twice"));
  });

  it('refuses query keys that are not allowed, and ones that repeat', () => {
    expect(refusal(() => get({ method: 'GET', url: `${BASE}/1?other=1` }))).toBe(refused("query key 'other' is not allowed"));
    expect(refusal(() => get({ method: 'GET', url: `${BASE}/1?page=1&page=2` }))).toBe(refused("query key 'page' is repeated"));
  });

  it('allows no query key at all when the spec lists none', () => {
    const none = httpExtractor({ method: 'GET', url: `${BASE}/{id}` });
    expect(refusal(() => none({ method: 'GET', url: `${BASE}/1?Stryker%20was%20here=1` }))).toBe(refused("query key 'Stryker was here' is not allowed"));
    expect(refusal(() => none({ method: 'GET', url: `${BASE}/1?a=1` }))).toBe(refused("query key 'a' is not allowed"));
  });

  it('a spec without a body refuses any body text but tolerates an empty one', () => {
    expect(get({ method: 'GET', url: `${BASE}/1`, body: '' })).toEqual({ id: '1' });
    expect(refusal(() => get({ method: 'GET', url: `${BASE}/1`, body: 'x' }))).toBe(refused('this operation carries no body'));
  });
});

describe('httpExtractor json bodies', () => {
  const post = httpExtractor({ method: 'POST', url: `${BASE}`, body: 'json', fixed: { kind: 'x', n: 1 } });
  const req = (body: unknown, headers: Record<string, string> | null = JSON_H): ProxyRequest => ({ method: 'POST', url: BASE, ...(headers ? { headers } : {}), ...(body === undefined ? {} : { body: body as string }) });

  it('maps members to parameters and consumes the fixed ones', () => {
    expect(post(req('{"kind":"x","n":1,"amount":5}'))).toEqual({ amount: 5 });
  });

  it('refuses a missing, empty or non-string body', () => {
    const m = refused('the body is missing');
    expect(refusal(() => post(req(undefined)))).toBe(m);
    expect(refusal(() => post(req('')))).toBe(m);
    expect(refusal(() => post(req(5)))).toBe(m);
  });

  it('requires the content type, ignoring parameters, case and spacing, and finding it among other headers', () => {
    const m = refused('content-type must be application/json');
    expect(refusal(() => post(req('{"kind":"x","n":1}', null)))).toBe(m);
    expect(refusal(() => post(req('{"kind":"x","n":1}', { Accept: 'application/json' })))).toBe(m);
    expect(refusal(() => post(req('{"kind":"x","n":1}', FORM_H)))).toBe(m);
    expect(post(req('{"kind":"x","n":1}', { Accept: 'text/plain', 'content-type': 'Application/JSON ; charset=utf-8' }))).toEqual({});
  });

  it('refuses a body that is not strict JSON or not an object', () => {
    expect(refusal(() => post(req('{bad')))).toBe(refused('the body is not strict JSON'));
    const open = httpExtractor({ method: 'POST', url: BASE, body: 'json' });
    const notObject = refused('the body must be a JSON object');
    for (const b of ['null', '[1]', '"s"', '5', 'true']) expect(refusal(() => open(req(b))), b).toBe(notObject);
  });

  it('refuses a fixed member with another value, and a missing fixed member', () => {
    expect(refusal(() => post(req('{"kind":"y","n":1}')))).toBe(refused("fixed member 'kind' has another value"));
    expect(refusal(() => post(req('{"kind":"x"}')))).toBe(refused('fixed member(s) n missing'));
    expect(refusal(() => post(req('{}')))).toBe(refused('fixed member(s) kind, n missing'));
  });
});

describe('httpExtractor form bodies', () => {
  const form = httpExtractor({ method: 'POST', url: BASE, body: 'form', fixed: { grant: 'g' } });
  const req = (body: string): ProxyRequest => ({ method: 'POST', url: BASE, headers: FORM_H, body });

  it('consumes fixed members and maps the rest', () => {
    expect(form(req('grant=g&a=1'))).toEqual({ a: '1' });
  });

  it('refuses a fixed member with another value, a missing one, and a repeated key', () => {
    expect(refusal(() => form(req('grant=other&a=1')))).toBe(refused("fixed member 'grant' has another value"));
    expect(refusal(() => form(req('a=1')))).toBe(refused('fixed member(s) grant missing'));
    expect(refusal(() => form(req('grant=g&a=1&a=2')))).toBe(refused("form key 'a' is repeated"));
    const two = httpExtractor({ method: 'POST', url: BASE, body: 'form', fixed: { p: '1', q: '2' } });
    expect(refusal(() => two(req('a=1')))).toBe(refused('fixed member(s) p, q missing'));
  });
});

describe('checkProxyHeaders', () => {
  it('lower-cases accepted headers and refuses the rest with exact reasons', () => {
    expect(checkProxyHeaders({ 'Content-Type': 'a', Accept: 'b' }, DEFAULT_PROXY_HEADERS)).toEqual({ 'content-type': 'a', accept: 'b' });
    expect(checkProxyHeaders(undefined, DEFAULT_PROXY_HEADERS)).toEqual({});
    expect(refusal(() => checkProxyHeaders({ Cookie: 'x' }, DEFAULT_PROXY_HEADERS))).toBe(refused("header 'Cookie' is not allowed"));
    expect(refusal(() => checkProxyHeaders({ Accept: 'a', accept: 'b' }, DEFAULT_PROXY_HEADERS))).toBe(refused("header 'accept' is repeated"));
  });

  it('refuses a header value that is not a string or carries a line break or NUL', () => {
    for (const v of ['a\r\nX: y', 'a\nb', 'a\rb', 'a\0b', 5 as unknown as string]) {
      expect(refusal(() => checkProxyHeaders({ Accept: v }, DEFAULT_PROXY_HEADERS))).toBe(refused("header 'Accept' has an invalid value"));
    }
  });
});

describe('outboundRequestDigest', () => {
  it('commits to the method, url, sent headers and body, with an absent body as null', () => {
    const h = { accept: 'a' };
    expect(outboundRequestDigest('POST', 'https://x/y', h, '{"a":1}')).toBe(hashCanonical({ d: 'atlas-pca/connect-request/v1', method: 'POST', url: 'https://x/y', headers: h, body: '{"a":1}' }));
    expect(outboundRequestDigest('GET', 'https://x/y', h, undefined)).toBe(hashCanonical({ d: 'atlas-pca/connect-request/v1', method: 'GET', url: 'https://x/y', headers: h, body: null }));
    expect(outboundRequestDigest('GET', 'https://x/y', h, undefined)).not.toBe(outboundRequestDigest('GET', 'https://x/y', h, ''));
  });
});
