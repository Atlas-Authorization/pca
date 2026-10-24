// The pre-walk nesting guard of wireCanonicalizeStrict (depth > 4096 is refused with its own message, before the proved printer
// recurses): the depth cap is a DoS defence, so it is tested on a worker with a LARGE stack (see the vitest configs: stackSizeMb 256).
// Without that stack the walk would overflow the JS stack below the cap and the guard's counter would be unobservable.
import { describe, expect, it } from 'vitest';
import { wireCanonicalizeStrict } from '../src/ext-wire';

const nest = (n: number, wrap: (v: unknown) => unknown): unknown => { let v: unknown = 1; for (let i = 0; i < n; i++) v = wrap(v); return v; };
const msg = (v: unknown): string => { try { wireCanonicalizeStrict(v); return 'ok'; } catch (e) { return (e as Error).message; } };

describe('wireCanonicalizeStrict nesting guard (depth cap 4096)', () => {
  it('one level past the cap is refused by the guard itself, for arrays and for objects', () => {
    expect(msg(nest(4097, (v) => [v]))).toBe('canonicalize: nesting too deep');
    expect(msg(nest(4097, (v) => ({ a: v })))).toBe('canonicalize: nesting too deep');
    expect(msg(nest(5000, (v) => [v]))).toBe('canonicalize: nesting too deep');
  });
  it('exactly at the cap the guard does not fire (the proved printer then refuses on its own, much lower, strict-profile depth bound)', () => {
    expect(msg(nest(4096, (v) => [v]))).toBe('canonicalize: value outside the strict profile');
    expect(msg(nest(4096, (v) => ({ a: v })))).toBe('canonicalize: value outside the strict profile');
  });
  it('a document within the strict profile is canonicalised', () => {
    expect(msg(nest(10, (v) => [v]))).toBe('ok');
  });
});
