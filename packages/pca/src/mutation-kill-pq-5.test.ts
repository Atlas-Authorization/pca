/**
 * Mutation-kill tests for pq.ts (part 5): the type / presence guards of verifyWithSuite for the FN-DSA and LESS
 * suites, which pq-4 could not reach (their back ends are lazily-loaded wasm). The back ends are stubbed to accept
 * (FN-DSA through a mocked createRequire, LESS through its test loader), Ed25519 verify is stubbed to accept and the
 * strict decoder is made permissive, so each `typeof` guard is the ONLY thing standing between a malformed input and `true`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { utf8 } from './hash';

type PqMod = typeof import('./pq');
const MSG = utf8('pq-5 message');
const st = {
  edB64: (..._a: unknown[]): unknown => true,
  fn: (..._a: unknown[]): unknown => true,
  less: (..._a: unknown[]): unknown => true,
};
const LESS_SIG = 'x'.repeat(1329);
const PERMISSIVE = (s: unknown, len?: number): Uint8Array => new Uint8Array(len ?? (typeof s === 'string' ? s.length : 1329));

async function mocked(): Promise<PqMod> {
  st.edB64 = () => true;
  st.fn = () => true;
  st.less = () => true;
  vi.resetModules();
  vi.doMock('node:module', () => ({
    createRequire: () => () => ({
      verify: (...a: unknown[]) => st.fn(...a),
      sign: () => new Uint8Array(0),
      keygen: () => ({ verifyingKey: new Uint8Array(0), signingKey: new Uint8Array(0) }),
    }),
  }));
  vi.doMock('./keys', async () => ({ ...(await vi.importActual<object>('./keys')), verifyB64u: (...a: unknown[]) => st.edB64(...a) }));
  vi.doMock('./hash', async () => ({ ...(await vi.importActual<object>('./hash')), decodeB64uStrict: PERMISSIVE }));
  const P = await import('./pq');
  P.setLessBackendLoaderForTests(() => ({ keygen() {}, seedWith() {}, signDetached() {}, verify: (...a: unknown[]) => st.less(...a) }));
  return P;
}
afterEach(() => {
  vi.doUnmock('node:module');
  vi.doUnmock('./keys');
  vi.doUnmock('./hash');
  vi.resetModules();
});

const ALGS = ['fn-dsa-512', 'fn-dsa-1024', 'less-cat1', 'hybrid-ed25519-less-cat1'] as const;
describe('verifyWithSuite: FN-DSA / LESS type & presence guards stand alone (back ends stubbed to accept)', () => {
  it.each(ALGS)('%s', async (a) => {
    const P = await mocked();
    const hasEd = a.includes('ed25519');
    const hybrid = a.startsWith('hybrid');
    const less = a.includes('less');
    const pq = P.resolvePqVerifyKey('', undefined, { trustedPk: 'PQ' })!;
    const keys = { edPub: 'ED', pq };
    const ok = hybrid ? { sig: 'S', pq_sig: LESS_SIG } : { sig: less ? LESS_SIG : 'S' };
    expect(P.verifyWithSuite(a, keys, MSG, ok)).toBe(true); // the stubs accept: only the guards can refuse below
    for (const bad of [5, undefined, null, {}, ['S'], true]) expect(P.verifyWithSuite(a, keys, MSG, { ...ok, sig: bad }), `sig=${String(bad)}`).toBe(false);
    expect(P.verifyWithSuite(a, keys, MSG, {})).toBe(false);
    for (const bad of [undefined, 5, null, {}, new Uint8Array(32)]) {
      expect(P.verifyWithSuite(a, { ...keys, edPub: bad as never }, MSG, ok), `edPub=${String(bad)}`).toBe(hasEd ? false : true);
    }
    if (hybrid) {
      for (const bad of [undefined, 5, null, {}, ['Q']]) expect(P.verifyWithSuite(a, keys, MSG, { ...ok, pq_sig: bad }), `pq_sig=${String(bad)}`).toBe(false);
      st.edB64 = () => false; // each half alone failing is enough
      expect(P.verifyWithSuite(a, keys, MSG, ok)).toBe(false);
      st.edB64 = () => true;
      st.less = () => false;
      expect(P.verifyWithSuite(a, keys, MSG, ok)).toBe(false);
      st.less = () => true;
    } else {
      if (less) st.less = () => false;
      else st.fn = () => false;
      expect(P.verifyWithSuite(a, keys, MSG, ok)).toBe(false);
    }
    // an unminted PQ key is refused even with every primitive accepting
    expect(P.verifyWithSuite(a, { edPub: 'ED', pq: { b64u: 'PQ', source: 'trusted' } as never }, MSG, ok)).toBe(false);
  });
});
