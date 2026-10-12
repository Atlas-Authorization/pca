// R6-ALIAS-05 (lenient canonicalize number spellings): a string request body that carries `{ pcactn: {...} }` was read with
// native JSON.parse, so `1.0`, `1e0`, `10e-1` all collapsed to 1 and duplicate keys collapsed last-wins BEFORE the strict
// canonical form was applied: byte-distinct wire documents verified as the same signed PCActn. The strict profile applies to a
// PCActn, so a body that carries one is parsed with strictParse (header mode already was).
import { describe, expect, it } from 'vitest';
import { defaultExtract } from './require-pca';

const req = (body: unknown) => ({ headers: {}, body }) as never;

describe('requirePCA body extraction uses the strict JSON profile', () => {
  it('a canonical body is extracted', () => {
    expect(defaultExtract(req('{"pcactn":{"counter":1,"ver":2}}'))).toEqual({ counter: 1, ver: 2 });
  });
  it.each(['1.0', '1e0', '10e-1', '1E0', '0.1e1'])('a lenient number spelling (%s) is refused', (n) => {
    expect(defaultExtract(req(`{"pcactn":{"counter":${n},"ver":2}}`))).toBeNull();
  });
  it('-0 and duplicate keys are refused', () => {
    expect(defaultExtract(req('{"pcactn":{"counter":-0}}'))).toBeNull();
    expect(defaultExtract(req('{"pcactn":{"aud":"evil","aud":"rs"}}'))).toBeNull();
    expect(defaultExtract(req('{"pcactn":{"a":1},"pcactn":{"a":2}}'))).toBeNull();
  });
  it('an already-parsed object body is passed through unchanged (its spelling is gone; see the README note)', () => {
    expect(defaultExtract(req({ pcactn: { counter: 1 } }))).toEqual({ counter: 1 });
  });
});
