/**
 * Mutation-kill tests for pq.ts (part 4).
 *
 *  (a) FRESH-IMPORT tests: the registry, constants and domain strings are evaluated when pq.ts loads. Stryker only
 *      attributes such "static" mutants to a test that (re)imports the module inside its body, so these assertions
 *      run against a freshly imported instance (vi.resetModules + dynamic import).
 *  (b) STRUCTURE tests with the cryptographic back ends stubbed to always accept (noble verify, Ed25519 verify) and
 *      the strict base64url decoder made permissive. With the primitives out of the picture, every length / type /
 *      presence guard in pq.ts is the ONLY thing standing between a malformed input and `true`, so each guard is
 *      pinned individually (the real primitives would otherwise mask a deleted guard).
 */
import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { b64u, utf8 } from './hash';

type PqMod = typeof import('./pq');
async function fresh(): Promise<PqMod> {
  vi.resetModules();
  return import('./pq');
}
afterEach(() => {
  vi.doUnmock('@noble/post-quantum/ml-dsa.js');
  vi.doUnmock('@noble/post-quantum/slh-dsa.js');
  vi.doUnmock('./keys');
  vi.doUnmock('./hash');
  vi.resetModules();
});
const sha256 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha256').update(b).digest());
const sha512 = (b: Uint8Array): Uint8Array => new Uint8Array(createHash('sha512').update(b).digest());
const cat = (...xs: Uint8Array[]): Uint8Array => Uint8Array.from(xs.flatMap((x) => Array.from(x)));
const bytesEq = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));
const MSG = utf8('pq-4 message');

// ---------------------------------------------------------------------------------------------------
// (a) fresh-import: static initialisers
// ---------------------------------------------------------------------------------------------------
describe('static initialisers (fresh module instance)', () => {
  it('byte-length constants and the default suite', async () => {
    const P = await fresh();
    expect([P.ML_DSA_65_PUBLIC_KEY_BYTES, P.ML_DSA_65_SIGNATURE_BYTES, P.ML_DSA_65_SEED_BYTES]).toEqual([1952, 3309, 32]);
    expect([P.SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, P.SLH_DSA_SHA2_128F_SECRET_KEY_BYTES, P.SLH_DSA_SHA2_128F_SIGNATURE_BYTES, P.SLH_DSA_SHA2_128F_SEED_BYTES]).toEqual([32, 64, 17088, 48]);
    expect(P.ED25519_SIGNATURE_BYTES).toBe(64);
    expect([P.ML_DSA_87_PUBLIC_KEY_BYTES, P.ML_DSA_87_SIGNATURE_BYTES, P.ML_DSA_87_SEED_BYTES]).toEqual([2592, 4627, 32]);
    expect([P.SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, P.SLH_DSA_SHA2_256S_SECRET_KEY_BYTES, P.SLH_DSA_SHA2_256S_SIGNATURE_BYTES, P.SLH_DSA_SHA2_256S_SEED_BYTES]).toEqual([64, 128, 29792, 96]);
    expect([P.FN_DSA_512_PUBLIC_KEY_BYTES, P.FN_DSA_512_SECRET_KEY_BYTES, P.FN_DSA_512_SIGNATURE_BYTES]).toEqual([897, 1345, 666]);
    expect([P.FN_DSA_1024_PUBLIC_KEY_BYTES, P.FN_DSA_1024_SECRET_KEY_BYTES, P.FN_DSA_1024_SIGNATURE_BYTES]).toEqual([1793, 2369, 1280]);
    expect(P.FN_DSA_SEED_BYTES).toBe(32);
    expect([P.LESS_CAT1_PUBLIC_KEY_BYTES, P.LESS_CAT1_SECRET_KEY_BYTES, P.LESS_CAT1_SIGNATURE_MAX_BYTES, P.LESS_CAT1_SIGNATURE_MIN_BYTES, P.LESS_CAT1_SIGNATURE_STEP_BYTES, P.LESS_SEED_BYTES]).toEqual([97484, 32, 1329, 1153, 16, 32]);
    expect(P.DEFAULT_SIG_ALG).toBe('ed25519');
    expect(P.resolveSigAlg(undefined)).toBe(P.SIG_SUITES.ed25519);
    expect(P.COMPOSITE_PREFIX).toBe('CompositeAlgorithmSignatures2025');
    expect(P.COMPOSITE_LABEL).toBe('COMPSIG-MLDSA65-Ed25519-SHA512');
    expect(P.COMPOSITE_SIGNATURE_BYTES).toBe(3373);
  });

  it('the registry is exactly the 14 documented suites, frozen', async () => {
    const P = await fresh();
    const base = { hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false };
    const E = { ...base, hasEd25519: true };
    const vl = { varLen: { min: 1153, step: 16 } };
    const expected: Record<string, unknown> = {
      ed25519: { alg: 'ed25519', sigBytes: 64, ...E, needsPqPk: false, needsPqSig: false, pqPkBytes: 0, pqSigBytes: 0 },
      'ml-dsa-65': { alg: 'ml-dsa-65', sigBytes: 3309, ...base, hasMlDsa: true, needsPqPk: true, needsPqSig: false, pqPkBytes: 1952, pqSigBytes: 0 },
      'hybrid-ed25519-ml-dsa-65': { alg: 'hybrid-ed25519-ml-dsa-65', sigBytes: 64, ...E, hasMlDsa: true, needsPqPk: true, needsPqSig: true, pqPkBytes: 1952, pqSigBytes: 3309 },
      'hybrid-nested-ed25519-ml-dsa-65': { alg: 'hybrid-nested-ed25519-ml-dsa-65', sigBytes: 64, ...E, hasMlDsa: true, needsPqPk: true, needsPqSig: true, pqPkBytes: 1952, pqSigBytes: 3309 },
      'slh-dsa-sha2-128f': { alg: 'slh-dsa-sha2-128f', sigBytes: 17088, ...base, hasSlhDsa: true, needsPqPk: true, needsPqSig: false, pqPkBytes: 32, pqSigBytes: 0 },
      'hybrid-ed25519-slh-dsa-sha2-128f': { alg: 'hybrid-ed25519-slh-dsa-sha2-128f', sigBytes: 64, ...E, hasSlhDsa: true, needsPqPk: true, needsPqSig: true, pqPkBytes: 32, pqSigBytes: 17088 },
      'ml-dsa-87': { alg: 'ml-dsa-87', sigBytes: 4627, ...base, hasMlDsa87: true, needsPqPk: true, needsPqSig: false, pqPkBytes: 2592, pqSigBytes: 0 },
      'hybrid-ed25519-ml-dsa-87': { alg: 'hybrid-ed25519-ml-dsa-87', sigBytes: 64, ...E, hasMlDsa87: true, needsPqPk: true, needsPqSig: true, pqPkBytes: 2592, pqSigBytes: 4627 },
      'slh-dsa-sha2-256s': { alg: 'slh-dsa-sha2-256s', sigBytes: 29792, ...base, hasSlhDsa256s: true, needsPqPk: true, needsPqSig: false, pqPkBytes: 64, pqSigBytes: 0 },
      'hybrid-ed25519-slh-dsa-sha2-256s': { alg: 'hybrid-ed25519-slh-dsa-sha2-256s', sigBytes: 64, ...E, hasSlhDsa256s: true, needsPqPk: true, needsPqSig: true, pqPkBytes: 64, pqSigBytes: 29792 },
      'fn-dsa-512': { alg: 'fn-dsa-512', sigBytes: 666, ...base, hasFnDsa512: true, needsPqPk: true, needsPqSig: false, pqPkBytes: 897, pqSigBytes: 0 },
      'fn-dsa-1024': { alg: 'fn-dsa-1024', sigBytes: 1280, ...base, hasFnDsa1024: true, needsPqPk: true, needsPqSig: false, pqPkBytes: 1793, pqSigBytes: 0 },
      'less-cat1': { alg: 'less-cat1', sigBytes: 1329, ...base, hasLessCat1: true, ...vl, needsPqPk: true, needsPqSig: false, pqPkBytes: 97484, pqSigBytes: 0 },
      'hybrid-ed25519-less-cat1': { alg: 'hybrid-ed25519-less-cat1', sigBytes: 64, ...E, hasLessCat1: true, ...vl, needsPqPk: true, needsPqSig: true, pqPkBytes: 97484, pqSigBytes: 1329 },
    };
    expect(Object.keys(P.SIG_SUITES).sort()).toEqual(Object.keys(expected).sort());
    for (const a of Object.keys(expected)) expect(P.SIG_SUITES[a as keyof typeof P.SIG_SUITES], a).toStrictEqual(expected[a]);
    expect(Object.isFrozen(P.SIG_SUITES)).toBe(true);
  });

  it('holderPqCommitment domain string', async () => {
    const P = await fresh();
    for (const k of ['abc', '', 'k'.repeat(40)]) {
      expect(P.holderPqCommitment(k)).toBe(b64u(sha256(cat(utf8('atlas-pca/holder-pq/v1\0'), utf8(k)))));
    }
  });

  it('PQ-binding domain string: the signed message is domain ‖ ed\\0pq\\0epoch\\0aud', async () => {
    const P = await fresh();
    const { generateKeyPair, verify } = await import('./keys');
    const ed = generateKeyPair();
    const edPub = b64u(ed.publicKey);
    const pq = b64u(new Uint8Array(32).fill(1));
    const b = P.signPqBinding(ed.secretKey, edPub, pq, 7, 'aud-x');
    const msg = cat(utf8('atlas-pca/pq-binding/v2\0'), utf8(`${edPub}\0${pq}\0${7}\0aud-x`));
    expect(verify(ed.publicKey, msg, Uint8Array.from(Buffer.from(b.sig, 'base64url')))).toBe(true);
    expect(P.pqPinFor(b, 'aud-x')).toStrictEqual({ [edPub]: pq });
  });

  it('the registered PQ public-key lengths (pin well-formedness)', async () => {
    const P = await fresh();
    for (const n of [1952, 32, 2592, 64, 897, 1793, 97484]) expect(P.isWellFormedPqPublicKey(b64u(new Uint8Array(n).fill(7))), String(n)).toBe(true);
    for (const n of [0, 1, 31, 33, 63, 65, 896, 898, 1951, 1953, 97483, 97485]) expect(P.isWellFormedPqPublicKey(b64u(new Uint8Array(n).fill(7))), String(n)).toBe(false);
  });

  it('PinnedPqKey: no public mint hook, direct construction refused, minted keys are frozen and registered', async () => {
    const P = await fresh();
    expect((P.PinnedPqKey as unknown as { mint?: unknown }).mint).toBeUndefined();
    expect(Object.getOwnPropertyNames(P.PinnedPqKey).sort()).toEqual(['length', 'name', 'prototype']);
    const Ctor = P.PinnedPqKey as unknown as new (k: string, s: string, t?: unknown) => unknown;
    expect(() => new Ctor('k', 'trusted')).toThrow(TypeError);
    expect(() => new Ctor('k', 'trusted', Symbol())).toThrow('PinnedPqKey can only be created by resolvePqVerifyKey');
    // every attempt to recover the token from the class surface fails
    for (const sym of Object.getOwnPropertySymbols(P.PinnedPqKey)) expect(() => new Ctor('k', 'trusted', sym)).toThrow(TypeError);
    const k = P.resolvePqVerifyKey('i', undefined, { trustedPk: 'T' })!;
    expect(Object.isFrozen(k)).toBe(true);
    expect(P.isPinnedPqKey(k)).toBe(true);
    expect(P.isPinnedPqKey({ ...k })).toBe(false);
    expect(P.isPinnedPqKey(Object.create(P.PinnedPqKey.prototype))).toBe(false);
    for (const v of [null, undefined, 'T', 0, true, () => 0, Symbol('x')]) expect(P.isPinnedPqKey(v)).toBe(false);
  });

  it('composite representative: prefix, label, length byte, ctx and SHA-512 prehash', async () => {
    const P = await fresh();
    const m = P.compositeRepresentative(MSG, 'ctx');
    expect(bytesEq(m, cat(utf8('CompositeAlgorithmSignatures2025'), utf8('COMPSIG-MLDSA65-Ed25519-SHA512'), Uint8Array.of(3), utf8('ctx'), sha512(MSG)))).toBe(true);
    expect(bytesEq(P.compositeRepresentative(MSG), cat(utf8('CompositeAlgorithmSignatures2025'), utf8('COMPSIG-MLDSA65-Ed25519-SHA512'), Uint8Array.of(0), sha512(MSG)))).toBe(true);
  });

  it('LESS: an instantiation failure that throws a non-Error still yields a reason (and never throws)', async () => {
    const P = await fresh();
    const b = { keygen() {}, seedWith() {}, signDetached() {}, verify: () => { throw undefined; } };
    P.setLessBackendLoaderForTests(() => b);
    expect(P.lessBackendStatus()).toStrictEqual({ available: false, reason: 'LESS wasm could not be instantiated: undefined' });
    P.setLessBackendLoaderForTests(undefined);
  });
});

// ---------------------------------------------------------------------------------------------------
// (b) structure tests with stubbed primitives
// ---------------------------------------------------------------------------------------------------
const st = {
  noble: (..._a: unknown[]): unknown => true,
  edB64: (..._a: unknown[]): unknown => true,
  edVerify: (..._a: unknown[]): unknown => true,
  decode: (s: unknown, len?: number): Uint8Array | null => new Uint8Array(len ?? (typeof s === 'string' ? s.length : 32)),
};
const defaultDecode = st.decode;
async function mocked(): Promise<PqMod> {
  st.noble = () => true;
  st.edB64 = () => true;
  st.edVerify = () => true;
  st.decode = defaultDecode;
  vi.resetModules();
  const nob = () => ({ verify: (...a: unknown[]) => st.noble(...a), sign: () => new Uint8Array(0), keygen: () => ({ secretKey: new Uint8Array(0), publicKey: new Uint8Array(0) }) });
  vi.doMock('@noble/post-quantum/ml-dsa.js', () => ({ ml_dsa65: nob(), ml_dsa87: nob() }));
  vi.doMock('@noble/post-quantum/slh-dsa.js', () => ({ slh_dsa_sha2_128f: nob(), slh_dsa_sha2_256s: nob() }));
  vi.doMock('./keys', async () => ({ ...(await vi.importActual<object>('./keys')), verifyB64u: (...a: unknown[]) => st.edB64(...a), verify: (...a: unknown[]) => st.edVerify(...a) }));
  vi.doMock('./hash', async () => ({ ...(await vi.importActual<object>('./hash')), decodeB64uStrict: (s: unknown, len?: number) => st.decode(s, len) }));
  return import('./pq');
}

describe('raw primitive wrappers: every guard stands alone', () => {
  const fams = [
    { n: 'ml-dsa-65', pk: 1952, sg: 3309, f: 'mlDsa65Verify' },
    { n: 'ml-dsa-87', pk: 2592, sg: 4627, f: 'mlDsa87Verify' },
    { n: 'slh-128f', pk: 32, sg: 17088, f: 'slhDsa128fVerify' },
    { n: 'slh-256s', pk: 64, sg: 29792, f: 'slhDsa256sVerify' },
  ] as const;
  it.each(fams)('$n', async ({ pk, sg, f }) => {
    const P = await mocked();
    const v = P[f] as (a: unknown, m: Uint8Array, s: unknown) => boolean;
    const U = (n: number) => new Uint8Array(n);
    expect(v(U(pk), MSG, U(sg))).toBe(true); // the stub accepts: only the guards can refuse below
    expect(v(U(pk - 1), MSG, U(sg))).toBe(false);
    expect(v(U(pk + 1), MSG, U(sg))).toBe(false);
    expect(v(U(pk), MSG, U(sg - 1))).toBe(false);
    expect(v(U(pk), MSG, U(sg + 1))).toBe(false);
    expect(v(U(0), MSG, U(sg))).toBe(false);
    expect(v(U(pk), MSG, U(0))).toBe(false);
    // right length but not a Uint8Array
    expect(v(Array(pk).fill(0), MSG, U(sg))).toBe(false);
    expect(v(U(pk), MSG, Array(sg).fill(0))).toBe(false);
    expect(v('x'.repeat(pk), MSG, U(sg))).toBe(false);
    expect(v(U(pk), MSG, 'x'.repeat(sg))).toBe(false);
    expect(v(null, MSG, U(sg))).toBe(false);
    expect(v(U(pk), MSG, undefined)).toBe(false);
    // a wrong-length key AND wrong-length sig together
    expect(v(U(pk - 1), MSG, U(sg - 1))).toBe(false);
    // the primitive throwing, or returning false / garbage, never escapes as true
    st.noble = () => {
      throw new Error('boom');
    };
    expect(v(U(pk), MSG, U(sg))).toBe(false);
    st.noble = () => false;
    expect(v(U(pk), MSG, U(sg))).toBe(false);
  });
  it.each([
    ['ml-dsa-65', 'mlDsa65VerifyB64u', 1952, 3309],
    ['ml-dsa-87', 'mlDsa87VerifyB64u', 2592, 4627],
    ['slh-128f', 'slhDsa128fVerifyB64u', 32, 17088],
    ['slh-256s', 'slhDsa256sVerifyB64u', 64, 29792],
    ['fn-dsa-512', 'fnDsa512VerifyB64u', 897, 666],
    ['fn-dsa-1024', 'fnDsa1024VerifyB64u', 1793, 1280],
    ['less-cat1', 'lessCat1VerifyB64u', 97484, 1329],
  ] as const)('%s b64u wrapper: a throwing decoder fails closed', async (_n, f, pk, sg) => {
    void pk;
    void sg;
    const P = await mocked();
    const v = P[f] as (a: unknown, m: Uint8Array, s: unknown) => boolean;
    st.decode = () => {
      throw new Error('decoder blew up');
    };
    expect(v('a', MSG, 'b')).toBe(false);
  });
  it('ml/slh b64u wrappers pass the DECODED key and signature to the primitive', async () => {
    const P = await mocked();
    const seen: unknown[][] = [];
    st.noble = (...a: unknown[]) => (seen.push(a), true);
    expect(P.mlDsa65VerifyB64u('k', MSG, 's')).toBe(true);
    const [pk, m, sg] = seen[0] as [Uint8Array, Uint8Array, Uint8Array];
    expect([pk.length, sg.length]).toEqual([1952, 3309]);
    expect(m).toBe(MSG);
    // an undecodable half (null) is refused even though the stub would accept
    st.decode = (s, len) => (s === 'bad' ? null : defaultDecode(s, len));
    expect(P.mlDsa65VerifyB64u('bad', MSG, 's')).toBe(false);
    expect(P.mlDsa65VerifyB64u('k', MSG, 'bad')).toBe(false);
    expect(P.slhDsa128fVerifyB64u('bad', MSG, 's')).toBe(false);
    expect(P.slhDsa256sVerifyB64u('k', MSG, 'bad')).toBe(false);
    expect(P.mlDsa87VerifyB64u('bad', MSG, 's')).toBe(false);
    expect(P.mlDsa87VerifyB64u('k', MSG, 'bad')).toBe(false);
  });
});

describe('verifyWithSuite: type / presence guards stand alone (primitives stubbed to accept)', () => {
  const ALGS = [
    'ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f',
    'ml-dsa-87', 'hybrid-ed25519-ml-dsa-87', 'slh-dsa-sha2-256s', 'hybrid-ed25519-slh-dsa-sha2-256s',
  ] as const;
  const hasEd = (a: string): boolean => a.includes('ed25519');
  const hasPq = (a: string): boolean => a !== 'ed25519';
  const hybrid = (a: string): boolean => a.startsWith('hybrid');
  it.each(ALGS)('%s', async (a) => {
    const P = await mocked();
    const pq = P.resolvePqVerifyKey('', undefined, { trustedPk: 'PQ' })!;
    const keys = { edPub: 'ED', ...(hasPq(a) ? { pq } : {}) };
    const ok = { sig: 'S', ...(hybrid(a) ? { pq_sig: 'Q' } : {}) };
    expect(P.verifyWithSuite(a, keys, MSG, ok)).toBe(true);
    // `sig` must be a string
    for (const bad of [5, undefined, null, {}, ['S'], true]) expect(P.verifyWithSuite(a, keys, MSG, { ...ok, sig: bad }), `sig=${String(bad)}`).toBe(false);
    expect(P.verifyWithSuite(a, keys, MSG, {})).toBe(false);
    expect(P.verifyWithSuite(a, keys, MSG, undefined as never)).toBe(false);
    // Ed25519-bearing suites need a string edPub; pure-PQ suites do not look at it
    for (const bad of [undefined, 5, null, {}, new Uint8Array(32)]) {
      expect(P.verifyWithSuite(a, { ...keys, edPub: bad as never }, MSG, ok), `edPub=${String(bad)}`).toBe(hasEd(a) ? false : true);
    }
    // a hybrid's pq_sig must be a string; pure suites ignore it
    if (hybrid(a)) {
      for (const bad of [undefined, 5, null, {}, ['Q']]) expect(P.verifyWithSuite(a, keys, MSG, { ...ok, pq_sig: bad }), `pq_sig=${String(bad)}`).toBe(false);
      // each half alone failing is enough
      st.edB64 = () => false;
      expect(P.verifyWithSuite(a, keys, MSG, ok)).toBe(false);
      st.edB64 = () => true;
      st.noble = () => false;
      expect(P.verifyWithSuite(a, keys, MSG, ok)).toBe(false);
      st.noble = () => true;
    }
    // a PQ key that was not minted here is refused for every PQ suite, even with all primitives accepting
    if (hasPq(a)) {
      expect(P.verifyWithSuite(a, { edPub: 'ED', pq: { b64u: 'PQ', source: 'trusted' } as never }, MSG, ok)).toBe(false);
    }
  });
  it('nested hybrid: a classical sig that does not decode to 64 bytes denies without throwing', async () => {
    const P = await mocked();
    const pq = P.resolvePqVerifyKey('', undefined, { trustedPk: 'PQ' })!;
    st.decode = (s, len) => (s === 'NULL' ? null : defaultDecode(s, len));
    expect(() => P.verifyWithSuite('hybrid-nested-ed25519-ml-dsa-65', { edPub: 'ED', pq }, MSG, { sig: 'NULL', pq_sig: 'Q' })).not.toThrow();
    expect(P.verifyWithSuite('hybrid-nested-ed25519-ml-dsa-65', { edPub: 'ED', pq }, MSG, { sig: 'NULL', pq_sig: 'Q' })).toBe(false);
    expect(P.verifyWithSuite('hybrid-nested-ed25519-ml-dsa-65', { edPub: 'ED', pq }, MSG, { sig: 'S', pq_sig: 'Q' })).toBe(true);
  });
  it('nested hybrid: the PQ primitive is handed msg ‖ the decoded classical signature', async () => {
    const P = await mocked();
    const pq = P.resolvePqVerifyKey('', undefined, { trustedPk: 'PQ' })!;
    const seen: Uint8Array[] = [];
    st.noble = (_pk: unknown, m: unknown) => (seen.push(m as Uint8Array), true);
    P.verifyWithSuite('hybrid-nested-ed25519-ml-dsa-65', { edPub: 'ED', pq }, MSG, { sig: 'S', pq_sig: 'Q' });
    expect(seen.length).toBe(1);
    expect(seen[0]!.length).toBe(MSG.length + 64);
    expect(bytesEq(seen[0]!.slice(0, MSG.length), MSG)).toBe(true);
    seen.length = 0;
    P.verifyWithSuite('hybrid-ed25519-ml-dsa-65', { edPub: 'ED', pq }, MSG, { sig: 'S', pq_sig: 'Q' });
    expect(seen[0]).toBe(MSG);
  });
});

describe('pin / binding guards stand alone (decoder permissive, signature check stubbed to accept)', () => {
  const PQ32 = 'q'.repeat(32); // permissive decode => 32 bytes => a registered PQ key length
  const good = (over: Record<string, unknown> = {}) => ({ ed: 'ed', pq: PQ32, epoch: 1, aud: 'aud', sig: 'sig', ...over });
  it('isWellFormedPqPublicKey requires a string', async () => {
    const P = await mocked();
    expect(P.isWellFormedPqPublicKey(PQ32)).toBe(true);
    for (const v of [5, null, undefined, {}, [], true, Symbol.for('x')]) expect(P.isWellFormedPqPublicKey(v), String(typeof v)).toBe(false);
  });
  it('pqPinFor: each field type is checked on its own', async () => {
    const P = await mocked();
    expect(P.pqPinFor(good() as never, 'aud')).toStrictEqual({ ed: PQ32 });
    for (const k of ['ed', 'pq', 'sig'] as const) {
      for (const bad of [undefined, null, 5, {}, ['x']]) {
        expect(P.pqPinFor(good({ [k]: bad }) as never, 'aud'), `${k}=${String(bad)}`).toBeNull();
      }
    }
    for (const bad of [null, undefined, 0, '', false]) expect(P.pqPinFor(bad as never, 'aud')).toBeNull();
  });
  it('pqPinFor: audience must be a non-empty string equal to the binding\'s', async () => {
    const P = await mocked();
    expect(P.pqPinFor(good({ aud: '' }) as never, '')).toBeNull();
    expect(P.pqPinFor(good({ aud: 5 }) as never, 5 as never)).toBeNull();
    expect(P.pqPinFor(good({ aud: undefined }) as never, undefined as never)).toBeNull();
    expect(P.pqPinFor(good({ aud: null }) as never, null as never)).toBeNull();
    expect(P.pqPinFor(good() as never, 'other')).toBeNull();
    expect(P.pqPinFor(good() as never, 'aud ')).toBeNull();
    expect(P.pqPinFor(good() as never, 'aud')).not.toBeNull();
  });
  it('pqPinFor: epoch gate, well-formed-key gate and signature gate are independent', async () => {
    const P = await mocked();
    for (const e of [0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', null, undefined]) expect(P.pqPinFor(good({ epoch: e }) as never, 'aud'), String(e)).toBeNull();
    for (const e of [1, 2, Number.MAX_SAFE_INTEGER]) expect(P.pqPinFor(good({ epoch: e }) as never, 'aud'), String(e)).not.toBeNull();
    expect(P.pqPinFor(good({ pq: 'q'.repeat(31) }) as never, 'aud')).toBeNull();
    st.edB64 = () => false;
    expect(P.pqPinFor(good() as never, 'aud')).toBeNull();
    st.edB64 = () => 1; // only literal acceptance counts? (truthy is what verifyB64u returns: boolean) => still passes the `!` test
    expect(P.pqPinFor(good() as never, 'aud')).not.toBeNull();
  });
  it('pqPinFor never throws: a throwing signature verifier, or a hostile binding, is a plain null', async () => {
    const P = await mocked();
    st.edB64 = () => {
      throw new Error('verify trap');
    };
    expect(P.pqPinFor(good() as never, 'aud')).toBeNull();
    st.edB64 = () => true;
    const hostile = new Proxy({}, { get: () => { throw new Error('getter trap'); } });
    expect(() => P.pqPinFor(hostile as never, 'aud')).not.toThrow();
    expect(P.pqPinFor(hostile as never, 'aud')).toBeNull();
  });
  it('the verify call receives (binding.ed, message, binding.sig)', async () => {
    const P = await mocked();
    const seen: unknown[][] = [];
    st.edB64 = (...a: unknown[]) => (seen.push(a), true);
    P.pqPinFor(good() as never, 'aud');
    expect(seen.length).toBe(1);
    expect(seen[0]![0]).toBe('ed');
    expect(seen[0]![2]).toBe('sig');
    const msg = seen[0]![1] as Uint8Array;
    expect(bytesEq(msg, cat(utf8('atlas-pca/pq-binding/v2\0'), utf8(`ed\0${PQ32}\x001\0aud`)))).toBe(true);
  });
});

describe('compositeVerify guards stand alone (component verifiers stubbed to accept)', () => {
  it('only a Uint8Array of exactly 3373 bytes is considered', async () => {
    const P = await mocked();
    const pub = { ed25519Pub: new Uint8Array(32), mlDsaPub: new Uint8Array(1952), message: MSG };
    expect(P.compositeVerify({ ...pub, signature: new Uint8Array(3373) })).toBe(true);
    for (const n of [0, 1, 64, 3308, 3309, 3372, 3374, 3375, 6746]) expect(P.compositeVerify({ ...pub, signature: new Uint8Array(n) }), String(n)).toBe(false);
    expect(P.compositeVerify({ ...pub, signature: Array(3373).fill(0) as never })).toBe(false);
    expect(P.compositeVerify({ ...pub, signature: 'x'.repeat(3373) as never })).toBe(false);
    expect(P.compositeVerify({ ...pub, signature: undefined as never })).toBe(false);
  });
  it('splits at byte 3309 and needs BOTH component verifiers', async () => {
    const P = await mocked();
    const pub = { ed25519Pub: new Uint8Array(32), mlDsaPub: new Uint8Array(1952), message: MSG };
    const sig = new Uint8Array(3373);
    sig.fill(1, 0, 3309);
    sig.fill(2, 3309);
    const lens: number[] = [];
    st.noble = (_pk: unknown, _m: unknown, s: unknown) => (lens.push((s as Uint8Array).length, (s as Uint8Array)[0]!), true);
    st.edVerify = (_pk: unknown, _m: unknown, s: unknown) => (lens.push((s as Uint8Array).length, (s as Uint8Array)[0]!), true);
    expect(P.compositeVerify({ ...pub, signature: sig })).toBe(true);
    expect(lens).toEqual([3309, 1, 64, 2]);
    st.noble = () => false;
    st.edVerify = () => true;
    expect(P.compositeVerify({ ...pub, signature: sig })).toBe(false);
    st.noble = () => true;
    st.edVerify = () => false;
    expect(P.compositeVerify({ ...pub, signature: sig })).toBe(false);
    st.edVerify = () => {
      throw new Error('x');
    };
    expect(P.compositeVerify({ ...pub, signature: sig })).toBe(false);
  });
});
