/**
 * Mutation-kill tests for pq.ts (part 1): the registry, primitive wrappers, the sign/verify suite seam and the
 * artifact helpers. Parts 2 and 3 (mutation-kill-pq-2/-3) cover the PinnedPqKey choke point, bindings, wire
 * validation, composite and the lazily-loaded backends.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { b64u, unb64u, utf8 } from './hash';
import { generateKeyPair, sign as edSign } from './keys';
import {
  DEFAULT_SIG_ALG,
  ED25519_SIGNATURE_BYTES,
  FN_DSA_1024_PUBLIC_KEY_BYTES,
  FN_DSA_1024_SECRET_KEY_BYTES,
  FN_DSA_1024_SIGNATURE_BYTES,
  FN_DSA_512_PUBLIC_KEY_BYTES,
  FN_DSA_512_SECRET_KEY_BYTES,
  FN_DSA_512_SIGNATURE_BYTES,
  FN_DSA_SEED_BYTES,
  LESS_CAT1_PUBLIC_KEY_BYTES,
  LESS_CAT1_SECRET_KEY_BYTES,
  LESS_CAT1_SIGNATURE_MAX_BYTES,
  LESS_CAT1_SIGNATURE_MIN_BYTES,
  LESS_CAT1_SIGNATURE_STEP_BYTES,
  LESS_SEED_BYTES,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SEED_BYTES,
  ML_DSA_65_SIGNATURE_BYTES,
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SEED_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  SIG_SUITES,
  SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES,
  SLH_DSA_SHA2_128F_SECRET_KEY_BYTES,
  SLH_DSA_SHA2_128F_SEED_BYTES,
  SLH_DSA_SHA2_128F_SIGNATURE_BYTES,
  SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES,
  SLH_DSA_SHA2_256S_SECRET_KEY_BYTES,
  SLH_DSA_SHA2_256S_SEED_BYTES,
  SLH_DSA_SHA2_256S_SIGNATURE_BYTES,
  type FnDsaSuiteKey,
  type MlDsaKeyPair,
  type SigAlg,
  type SlhDsaKeyPair,
  type SuiteSecretKeys,
  bindSuiteFields,
  encodeFnDsaPublicKey,
  encodeMlDsa87PublicKey,
  encodeMlDsaPublicKey,
  encodeSlhDsa256sPublicKey,
  encodeSlhDsaPublicKey,
  fnDsa1024Keygen,
  fnDsa1024Sign,
  fnDsa1024Verify,
  fnDsa1024VerifyB64u,
  fnDsa512Keygen,
  fnDsa512Sign,
  fnDsa512Verify,
  fnDsa512VerifyB64u,
  isFnDsaBackendActive,
  isKnownSigAlg,
  mlDsa65Keygen,
  mlDsa65Sign,
  mlDsa65Verify,
  mlDsa65VerifyB64u,
  mlDsa87Keygen,
  mlDsa87Sign,
  mlDsa87Verify,
  mlDsa87VerifyB64u,
  resolvePqVerifyKey,
  resolveSigAlg,
  signSuiteArtifact,
  signWithSuite,
  slhDsa128fKeygen,
  slhDsa128fSign,
  slhDsa128fVerify,
  slhDsa128fVerifyB64u,
  slhDsa256sKeygen,
  slhDsa256sVerify,
  slhDsa256sVerifyB64u,
  suiteKeysOf,
  suitePqPublicKey,
  verifyLeafSuite,
  verifyWithSuite,
  lessCat1Keygen,
  isLessBackendActive,
} from './pq';

const MSG = utf8('mutation-kill pq message');
const OTHER = utf8('mutation-kill pq message!');
const seedOf = (n: number, len: number): Uint8Array => new Uint8Array(len).fill(n);
const flipB64 = (s: string, at = 0): string => {
  const b = unb64u(s);
  b[at] = (b[at] ?? 0) ^ 1;
  return b64u(b);
};
function thrown(fn: () => unknown): Error {
  try {
    fn();
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a throw');
}
const pinned = (pk: string) => resolvePqVerifyKey('', undefined, { trustedPk: pk })!;
const bytesEq = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));

// ---- key material ---------------------------------------------------------------------------------
const ED = generateKeyPair();
const ED2 = generateKeyPair();
let ML: MlDsaKeyPair;
let ML2: MlDsaKeyPair;
let ML87: MlDsaKeyPair;
let SLH: SlhDsaKeyPair;
let SLH2: SlhDsaKeyPair;
let SLH256: SlhDsaKeyPair;
let FN512: FnDsaSuiteKey;
let FN1024: FnDsaSuiteKey;
let LESS: { publicKey: Uint8Array; secretKey: Uint8Array; signSeed: Uint8Array };
let KEYS: SuiteSecretKeys;
const ALL_ALGS = Object.keys(SIG_SUITES) as SigAlg[];
const SIGS: Record<string, { sig: string; pq_sig?: string }> = {};
// SLH-DSA-256s signing costs ~4.5 s; its two deterministic signatures (over MSG and OTHER) are pre-computed fixtures,
// and a dedicated test below signs for real and compares to them.
const FX = JSON.parse(readFileSync(join(__dirname, 'mutation-kill-pq.fixtures.json'), 'utf8')) as { msg: string; other: string };
const isSlh256 = (a: string): boolean => a.endsWith('slh-dsa-sha2-256s');
/** signWithSuite, but the SLH-DSA-256s primitive comes from the fixture for MSG / OTHER. */
function signCached(a: SigAlg, m: Uint8Array): { sig: string; pq_sig?: string } {
  if (!isSlh256(a)) return signWithSuite(a, KEYS, m);
  const prim = m === MSG ? FX.msg : m === OTHER ? FX.other : undefined;
  if (prim === undefined) throw new Error('signCached: only MSG/OTHER');
  return a === 'slh-dsa-sha2-256s' ? { sig: prim } : { sig: b64u(edSign(ED.secretKey, m)), pq_sig: prim };
}
const PQPK: Record<string, string | undefined> = {};

beforeAll(() => {
  ML = mlDsa65Keygen(seedOf(1, 32));
  ML2 = mlDsa65Keygen(seedOf(2, 32));
  ML87 = mlDsa87Keygen(seedOf(3, 32));
  SLH = slhDsa128fKeygen(seedOf(4, 48));
  SLH2 = slhDsa128fKeygen(seedOf(5, 48));
  SLH256 = slhDsa256sKeygen(seedOf(6, 96));
  const f5 = fnDsa512Keygen(seedOf(7, 32));
  FN512 = { ...f5, signSeed: seedOf(8, 32) };
  const f10 = fnDsa1024Keygen(seedOf(9, 32));
  FN1024 = { ...f10, signSeed: seedOf(10, 32) };
  const l = lessCat1Keygen(seedOf(11, LESS_SEED_BYTES));
  LESS = { ...l, signSeed: seedOf(12, LESS_SEED_BYTES) };
  KEYS = { edSecret: ED.secretKey, mlDsa: ML, slhDsa: SLH, mlDsa87: ML87, slhDsa256s: SLH256, fnDsa512: FN512, fnDsa1024: FN1024, lessCat1: LESS };
  for (const a of ALL_ALGS) {
    SIGS[a] = signCached(a, MSG);
    PQPK[a] = suitePqPublicKey(a, KEYS);
  }
}, 600_000);

// ---- constants & registry -------------------------------------------------------------------------
describe('pq constants', () => {
  it('byte-length constants are the standard sizes', () => {
    expect([ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, ML_DSA_65_SEED_BYTES]).toEqual([1952, 3309, 32]);
    expect([SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_128F_SECRET_KEY_BYTES, SLH_DSA_SHA2_128F_SIGNATURE_BYTES, SLH_DSA_SHA2_128F_SEED_BYTES]).toEqual([32, 64, 17088, 48]);
    expect(ED25519_SIGNATURE_BYTES).toBe(64);
    expect([ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES, ML_DSA_87_SEED_BYTES]).toEqual([2592, 4627, 32]);
    expect([SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHA2_256S_SECRET_KEY_BYTES, SLH_DSA_SHA2_256S_SIGNATURE_BYTES, SLH_DSA_SHA2_256S_SEED_BYTES]).toEqual([64, 128, 29792, 96]);
    expect([FN_DSA_512_PUBLIC_KEY_BYTES, FN_DSA_512_SECRET_KEY_BYTES, FN_DSA_512_SIGNATURE_BYTES]).toEqual([897, 1345, 666]);
    expect([FN_DSA_1024_PUBLIC_KEY_BYTES, FN_DSA_1024_SECRET_KEY_BYTES, FN_DSA_1024_SIGNATURE_BYTES]).toEqual([1793, 2369, 1280]);
    expect(FN_DSA_SEED_BYTES).toBe(32);
    expect([LESS_CAT1_PUBLIC_KEY_BYTES, LESS_CAT1_SECRET_KEY_BYTES, LESS_CAT1_SIGNATURE_MAX_BYTES, LESS_CAT1_SIGNATURE_MIN_BYTES, LESS_CAT1_SIGNATURE_STEP_BYTES, LESS_SEED_BYTES]).toEqual([97484, 32, 1329, 1153, 16, 32]);
    expect(DEFAULT_SIG_ALG).toBe('ed25519');
  });
});

describe('SIG_SUITES registry is exact and frozen', () => {
  const base = { hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: false, hasSlhDsa256s: false };
  const E = { ...base, hasEd25519: true };
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
    'less-cat1': { alg: 'less-cat1', sigBytes: 1329, ...base, hasLessCat1: true, varLen: { min: 1153, step: 16 }, needsPqPk: true, needsPqSig: false, pqPkBytes: 97484, pqSigBytes: 0 },
    'hybrid-ed25519-less-cat1': { alg: 'hybrid-ed25519-less-cat1', sigBytes: 64, ...E, hasLessCat1: true, varLen: { min: 1153, step: 16 }, needsPqPk: true, needsPqSig: true, pqPkBytes: 97484, pqSigBytes: 1329 },
  };
  it('has exactly the 14 documented suites, field for field', () => {
    expect(Object.keys(SIG_SUITES).sort()).toEqual(Object.keys(expected).sort());
    for (const a of Object.keys(expected)) expect(SIG_SUITES[a as SigAlg], a).toStrictEqual(expected[a]);
  });
  it('is frozen', () => {
    expect(Object.isFrozen(SIG_SUITES)).toBe(true);
  });
  it('isKnownSigAlg: own registry keys only', () => {
    for (const a of ALL_ALGS) expect(isKnownSigAlg(a)).toBe(true);
    for (const bad of ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'ED25519', '', 'ml-dsa', 5, null, undefined, {}, ['ed25519']]) {
      expect(isKnownSigAlg(bad), String(bad)).toBe(false);
    }
  });
  it('resolveSigAlg: undefined => default suite; known => that suite; else null', () => {
    expect(resolveSigAlg(undefined)).toBe(SIG_SUITES.ed25519);
    for (const a of ALL_ALGS) expect(resolveSigAlg(a)).toBe(SIG_SUITES[a]);
    for (const bad of [null, '', 'toString', 'nope', 0, false, {}, 'ED25519']) expect(resolveSigAlg(bad), String(bad)).toBeNull();
  });
});

// ---- primitive wrappers ---------------------------------------------------------------------------
type Prim = {
  name: string;
  pkLen: number;
  sigLen: number;
  pk: () => Uint8Array;
  sig: () => Uint8Array;
  other: () => Uint8Array;
  verify: (pk: Uint8Array, m: Uint8Array, s: Uint8Array) => boolean;
  verifyB: (pk: unknown, m: Uint8Array, s: unknown) => boolean;
};
const prims: Prim[] = [
  { name: 'ml-dsa-65', pkLen: 1952, sigLen: 3309, pk: () => ML.publicKey, sig: () => mlDsa65Sign(ML.secretKey, MSG), other: () => ML2.publicKey, verify: mlDsa65Verify, verifyB: mlDsa65VerifyB64u },
  { name: 'ml-dsa-87', pkLen: 2592, sigLen: 4627, pk: () => ML87.publicKey, sig: () => mlDsa87Sign(ML87.secretKey, MSG), other: () => mlDsa87Keygen(seedOf(30, 32)).publicKey, verify: mlDsa87Verify, verifyB: mlDsa87VerifyB64u },
  { name: 'slh-128f', pkLen: 32, sigLen: 17088, pk: () => SLH.publicKey, sig: () => slhDsa128fSign(SLH.secretKey, MSG), other: () => SLH2.publicKey, verify: slhDsa128fVerify, verifyB: slhDsa128fVerifyB64u },
  { name: 'slh-256s', pkLen: 64, sigLen: 29792, pk: () => SLH256.publicKey, sig: () => unb64u(FX.msg), other: () => slhDsa256sKeygen(seedOf(31, 96)).publicKey, verify: slhDsa256sVerify, verifyB: slhDsa256sVerifyB64u },
  { name: 'fn-dsa-512', pkLen: 897, sigLen: 666, pk: () => FN512.verifyingKey, sig: () => fnDsa512Sign(FN512.signingKey, MSG, FN512.signSeed), other: () => fnDsa512Keygen(seedOf(32, 32)).verifyingKey, verify: fnDsa512Verify, verifyB: fnDsa512VerifyB64u },
  { name: 'fn-dsa-1024', pkLen: 1793, sigLen: 1280, pk: () => FN1024.verifyingKey, sig: () => fnDsa1024Sign(FN1024.signingKey, MSG, FN1024.signSeed), other: () => fnDsa1024Keygen(seedOf(33, 32)).verifyingKey, verify: fnDsa1024Verify, verifyB: fnDsa1024VerifyB64u },
];
describe.each(prims.map((p) => [p.name, p] as const))('primitive wrapper %s', (_n, p) => {
  let pk: Uint8Array;
  let sig: Uint8Array;
  beforeAll(() => {
    pk = p.pk();
    sig = p.sig();
  }, 300_000);
  it('has the registered key and signature lengths', () => {
    expect(pk.length).toBe(p.pkLen);
    expect(sig.length).toBe(p.sigLen);
  });
  it('raw verify: accepts the valid triple; rejects wrong message, wrong key, bit-flipped sig', () => {
    expect(p.verify(pk, MSG, sig)).toBe(true);
    expect(p.verify(pk, OTHER, sig)).toBe(false);
    expect(p.verify(p.other(), MSG, sig)).toBe(false);
    const bad = Uint8Array.from(sig);
    bad[5] = bad[5]! ^ 1;
    expect(p.verify(pk, MSG, bad)).toBe(false);
  });
  it('raw verify: every length mismatch is refused independently (never throws)', () => {
    const pkPlus = new Uint8Array(p.pkLen + 1);
    pkPlus.set(pk);
    const sigPlus = new Uint8Array(p.sigLen + 1);
    sigPlus.set(sig);
    expect(p.verify(pk.subarray(0, p.pkLen - 1), MSG, sig)).toBe(false);
    expect(p.verify(pkPlus, MSG, sig)).toBe(false);
    expect(p.verify(pk, MSG, sig.subarray(0, p.sigLen - 1))).toBe(false);
    expect(p.verify(pk, MSG, sigPlus)).toBe(false);
    expect(p.verify(new Uint8Array(0), MSG, sig)).toBe(false);
    expect(p.verify(pk, MSG, new Uint8Array(0))).toBe(false);
  });
  it('raw verify: non-Uint8Array inputs are refused', () => {
    expect(p.verify(Array.from(pk) as unknown as Uint8Array, MSG, sig)).toBe(false);
    expect(p.verify(pk, MSG, Array.from(sig) as unknown as Uint8Array)).toBe(false);
    expect(p.verify(null as unknown as Uint8Array, MSG, sig)).toBe(false);
    expect(p.verify(pk, MSG, undefined as unknown as Uint8Array)).toBe(false);
  });
  it('b64u verify: valid accepted; each half independently validated; bad inputs refused', () => {
    const pk64 = b64u(pk);
    const sg64 = b64u(sig);
    expect(p.verifyB(pk64, MSG, sg64)).toBe(true);
    expect(p.verifyB(pk64, OTHER, sg64)).toBe(false);
    expect(p.verifyB(pk64, MSG, flipB64(sg64, 7))).toBe(false);
    expect(p.verifyB(b64u(p.other()), MSG, sg64)).toBe(false);
    // valid pk but undecodable sig, and vice versa
    expect(p.verifyB(pk64, MSG, '!!')).toBe(false);
    expect(p.verifyB(pk64, MSG, undefined)).toBe(false);
    expect(p.verifyB(pk64, MSG, 5)).toBe(false);
    expect(p.verifyB('!!', MSG, sg64)).toBe(false);
    expect(p.verifyB(undefined, MSG, sg64)).toBe(false);
    expect(p.verifyB(pk64, MSG, '')).toBe(false);
    expect(p.verifyB('', MSG, sg64)).toBe(false);
    // wrong decoded lengths
    expect(p.verifyB(b64u(pk.subarray(1)), MSG, sg64)).toBe(false);
    expect(p.verifyB(pk64, MSG, b64u(sig.subarray(1)))).toBe(false);
    // non-canonical (padded) encodings are refused
    expect(p.verifyB(pk64 + '=', MSG, sg64)).toBe(false);
    expect(p.verifyB(pk64, MSG, sg64 + '=')).toBe(false);
  });
});

describe('primitive keygen/sign are the noble / wasm primitives (deterministic)', () => {
  it('ml-dsa keygen+sign reproducible and seed-dependent', () => {
    expect(bytesEq(mlDsa65Keygen(seedOf(1, 32)).publicKey, ML.publicKey)).toBe(true);
    expect(bytesEq(mlDsa65Keygen(seedOf(2, 32)).publicKey, ML.publicKey)).toBe(false);
    expect(bytesEq(mlDsa65Sign(ML.secretKey, MSG), mlDsa65Sign(ML.secretKey, MSG))).toBe(true);
    expect(bytesEq(mlDsa87Keygen(seedOf(3, 32)).publicKey, ML87.publicKey)).toBe(true);
    expect(bytesEq(slhDsa128fKeygen(seedOf(4, 48)).publicKey, SLH.publicKey)).toBe(true);
    expect(bytesEq(slhDsa256sKeygen(seedOf(6, 96)).publicKey, SLH256.publicKey)).toBe(true);
  });
  it('fn-dsa keygen uses the right variant (key sizes) and signs with the supplied seed', () => {
    expect(isFnDsaBackendActive()).toBe(true);
    expect(FN512.verifyingKey.length).toBe(897);
    expect(FN512.signingKey.length).toBe(1345);
    expect(FN1024.verifyingKey.length).toBe(1793);
    expect(FN1024.signingKey.length).toBe(2369);
    expect(bytesEq(fnDsa512Sign(FN512.signingKey, MSG, FN512.signSeed), fnDsa512Sign(FN512.signingKey, MSG, FN512.signSeed))).toBe(true);
    expect(bytesEq(fnDsa512Sign(FN512.signingKey, MSG, FN512.signSeed), fnDsa512Sign(FN512.signingKey, MSG, seedOf(99, 32)))).toBe(false);
    expect(fnDsa512Sign(FN512.signingKey, MSG, FN512.signSeed).length).toBe(666);
    expect(fnDsa1024Sign(FN1024.signingKey, MSG, FN1024.signSeed).length).toBe(1280);
    // a 512 signature never verifies under the 1024 verifier and vice versa (length gate)
    expect(fnDsa1024Verify(FN1024.verifyingKey, MSG, fnDsa512Sign(FN512.signingKey, MSG, FN512.signSeed))).toBe(false);
  });
  it('encode*PublicKey are b64u of the key bytes', () => {
    expect(encodeMlDsaPublicKey(ML.publicKey)).toBe(b64u(ML.publicKey));
    expect(encodeMlDsa87PublicKey(ML87.publicKey)).toBe(b64u(ML87.publicKey));
    expect(encodeSlhDsaPublicKey(SLH.publicKey)).toBe(b64u(SLH.publicKey));
    expect(encodeSlhDsa256sPublicKey(SLH256.publicKey)).toBe(b64u(SLH256.publicKey));
    expect(encodeFnDsaPublicKey(FN512.verifyingKey)).toBe(b64u(FN512.verifyingKey));
  });
});

// ---- signWithSuite --------------------------------------------------------------------------------
describe('signWithSuite', () => {
  const edSig = (m: Uint8Array) => b64u(edSign(ED.secretKey, m));
  it('ed25519 (explicit and implicit) is byte-identical to the classical signature and has no pq_sig', () => {
    expect(signWithSuite('ed25519', { edSecret: ED.secretKey }, MSG)).toStrictEqual({ sig: edSig(MSG) });
    expect(signWithSuite(undefined, { edSecret: ED.secretKey }, MSG)).toStrictEqual({ sig: edSig(MSG) });
  });
  it('every suite signs the documented primitive(s) over the documented message', () => {
    expect(SIGS['ml-dsa-65']).toStrictEqual({ sig: b64u(mlDsa65Sign(ML.secretKey, MSG)) });
    expect(SIGS['hybrid-ed25519-ml-dsa-65']).toStrictEqual({ sig: edSig(MSG), pq_sig: b64u(mlDsa65Sign(ML.secretKey, MSG)) });
    const nestedMsg = new Uint8Array(MSG.length + 64);
    nestedMsg.set(MSG);
    nestedMsg.set(edSign(ED.secretKey, MSG), MSG.length);
    expect(SIGS['hybrid-nested-ed25519-ml-dsa-65']).toStrictEqual({ sig: edSig(MSG), pq_sig: b64u(mlDsa65Sign(ML.secretKey, nestedMsg)) });
    expect(SIGS['hybrid-nested-ed25519-ml-dsa-65']!.pq_sig).not.toBe(SIGS['hybrid-ed25519-ml-dsa-65']!.pq_sig);
    expect(SIGS['slh-dsa-sha2-128f']).toStrictEqual({ sig: b64u(slhDsa128fSign(SLH.secretKey, MSG)) });
    expect(SIGS['hybrid-ed25519-slh-dsa-sha2-128f']).toStrictEqual({ sig: edSig(MSG), pq_sig: b64u(slhDsa128fSign(SLH.secretKey, MSG)) });
    expect(SIGS['ml-dsa-87']).toStrictEqual({ sig: b64u(mlDsa87Sign(ML87.secretKey, MSG)) });
    expect(SIGS['hybrid-ed25519-ml-dsa-87']).toStrictEqual({ sig: edSig(MSG), pq_sig: b64u(mlDsa87Sign(ML87.secretKey, MSG)) });
    expect(SIGS['slh-dsa-sha2-256s']).toStrictEqual({ sig: FX.msg });
    expect(SIGS['hybrid-ed25519-slh-dsa-sha2-256s']).toStrictEqual({ sig: edSig(MSG), pq_sig: FX.msg });
    expect(SIGS['fn-dsa-512']).toStrictEqual({ sig: b64u(fnDsa512Sign(FN512.signingKey, MSG, FN512.signSeed)) });
    expect(SIGS['fn-dsa-1024']).toStrictEqual({ sig: b64u(fnDsa1024Sign(FN1024.signingKey, MSG, FN1024.signSeed)) });
    // sig lengths match the registry (decoded)
    for (const a of ALL_ALGS) {
      const s = SIG_SUITES[a];
      if (a === 'less-cat1') continue;
      expect(unb64u(SIGS[a]!.sig).length, a).toBe(s.sigBytes);
      if (s.needsPqSig && a !== 'hybrid-ed25519-less-cat1') expect(unb64u(SIGS[a]!.pq_sig!).length, a).toBe(s.pqSigBytes);
      else expect(SIGS[a]!.pq_sig === undefined || a === 'hybrid-ed25519-less-cat1', a).toBe(true);
    }
  });
  it('slh-dsa-sha2-256s signs for real and matches the precomputed fixture (both suites)', () => {
    expect(signWithSuite('slh-dsa-sha2-256s', KEYS, MSG)).toStrictEqual({ sig: FX.msg });
    expect(signWithSuite('hybrid-ed25519-slh-dsa-sha2-256s', KEYS, OTHER)).toStrictEqual({ sig: edSig(OTHER), pq_sig: FX.other });
  }, 60_000);
  it('less suites: pure carries the LESS sig in `sig`; hybrid carries ed25519 in `sig` and LESS in `pq_sig`', () => {
    expect(isLessBackendActive()).toBe(true);
    expect(Object.keys(SIGS['less-cat1']!)).toEqual(['sig']);
    expect(unb64u(SIGS['less-cat1']!.sig).length).toBeGreaterThanOrEqual(1153);
    expect(unb64u(SIGS['hybrid-ed25519-less-cat1']!.sig).length).toBe(64);
    expect(unb64u(SIGS['hybrid-ed25519-less-cat1']!.pq_sig!).length).toBeGreaterThanOrEqual(1153);
    expect(SIGS['hybrid-ed25519-less-cat1']!.sig).toBe(edSig(MSG));
  });
  it('unknown alg throws RangeError with the exact message', () => {
    for (const bad of ['nope', null, 5, '']) {
      const e = thrown(() => signWithSuite(bad, KEYS, MSG));
      expect(e).toBeInstanceOf(RangeError);
      expect(e.message).toBe(`signWithSuite: unknown signature alg '${String(bad)}'`);
    }
  });
  it('a suite with an Ed25519 half requires edSecret (TypeError, exact message) — and only those do', () => {
    for (const a of ALL_ALGS.filter((x) => SIG_SUITES[x].hasEd25519)) {
      const e = thrown(() => signWithSuite(a, { ...KEYS, edSecret: undefined }, MSG));
      expect(e, a).toBeInstanceOf(TypeError);
      expect(e.message).toBe(`signWithSuite: '${a}' requires edSecret`);
      expect(thrown(() => signWithSuite(a, { ...KEYS, edSecret: 'x' as unknown as Uint8Array }, MSG)).message).toBe(`signWithSuite: '${a}' requires edSecret`);
    }
    // pure PQ suites never need edSecret
    for (const a of ALL_ALGS.filter((x) => !SIG_SUITES[x].hasEd25519 && !isSlh256(x))) {
      expect(() => signWithSuite(a, { ...KEYS, edSecret: undefined }, MSG), a).not.toThrow();
    }
  });
  it('each PQ family requires ITS key material (exact message), and ignores the other families', () => {
    const slot: Record<string, [keyof SuiteSecretKeys, string]> = {
      'ml-dsa-65': ['mlDsa', 'mlDsa key material'],
      'hybrid-ed25519-ml-dsa-65': ['mlDsa', 'mlDsa key material'],
      'hybrid-nested-ed25519-ml-dsa-65': ['mlDsa', 'mlDsa key material'],
      'slh-dsa-sha2-128f': ['slhDsa', 'slhDsa key material'],
      'hybrid-ed25519-slh-dsa-sha2-128f': ['slhDsa', 'slhDsa key material'],
      'ml-dsa-87': ['mlDsa87', 'mlDsa87 key material'],
      'hybrid-ed25519-ml-dsa-87': ['mlDsa87', 'mlDsa87 key material'],
      'slh-dsa-sha2-256s': ['slhDsa256s', 'slhDsa256s key material'],
      'hybrid-ed25519-slh-dsa-sha2-256s': ['slhDsa256s', 'slhDsa256s key material'],
      'fn-dsa-512': ['fnDsa512', 'fnDsa512 key material (signingKey + signSeed)'],
      'fn-dsa-1024': ['fnDsa1024', 'fnDsa1024 key material (signingKey + signSeed)'],
      'less-cat1': ['lessCat1', 'lessCat1 key material (secretKey + signSeed)'],
      'hybrid-ed25519-less-cat1': ['lessCat1', 'lessCat1 key material (secretKey + signSeed)'],
    };
    for (const [a, [k, what]] of Object.entries(slot)) {
      const want = `signWithSuite: '${a}' requires ${what}`;
      const missing = thrown(() => signWithSuite(a, { ...KEYS, [k]: undefined }, MSG));
      expect(missing, a).toBeInstanceOf(TypeError);
      expect(missing.message).toBe(want);
      // present-but-wrong-typed secret
      const secretField = k === 'fnDsa512' || k === 'fnDsa1024' ? 'signingKey' : 'secretKey';
      const wrong = thrown(() => signWithSuite(a, { ...KEYS, [k]: { ...(KEYS[k] as object), [secretField]: 'nope' } }, MSG));
      expect(wrong.message, a).toBe(want);
      // the OTHER families are irrelevant
      const only: SuiteSecretKeys = { edSecret: ED.secretKey, [k]: KEYS[k] };
      if (!isSlh256(a)) expect(() => signWithSuite(a, only, MSG), a).not.toThrow();
    }
    for (const [a, k] of [['fn-dsa-512', 'fnDsa512'], ['fn-dsa-1024', 'fnDsa1024'], ['less-cat1', 'lessCat1'], ['hybrid-ed25519-less-cat1', 'lessCat1']] as const) {
      const noSeed = { ...(KEYS[k] as object), signSeed: undefined };
      expect(thrown(() => signWithSuite(a, { ...KEYS, [k]: noSeed }, MSG)).message, a).toMatch(/requires/);
    }
  });
  it('ed25519 does not demand any PQ material', () => {
    expect(() => signWithSuite('ed25519', { edSecret: ED.secretKey }, MSG)).not.toThrow();
  });
});

// ---- verifyWithSuite ------------------------------------------------------------------------------
describe('verifyWithSuite: fail-closed per suite', () => {
  const keysFor = (a: SigAlg, pk = PQPK[a]) => ({ edPub: ED.publicKey, ...(pk !== undefined ? { pq: pinned(pk) } : {}) });
  const edPubB64 = () => b64u(ED.publicKey);
  const K = (a: SigAlg, pk = PQPK[a]) => ({ edPub: edPubB64(), ...(pk !== undefined ? { pq: pinned(pk) } : {}) });
  void keysFor;

  it('accepts every genuine signature, and refuses a changed message', () => {
    for (const a of ALL_ALGS) {
      expect(verifyWithSuite(a, K(a), MSG, SIGS[a]!), a).toBe(true);
      expect(verifyWithSuite(a, K(a), OTHER, SIGS[a]!), a).toBe(false);
    }
  });
  it('refuses a flipped primary signature and a flipped pq_sig', () => {
    for (const a of ALL_ALGS) {
      const s = SIGS[a]!;
      expect(verifyWithSuite(a, K(a), MSG, { ...s, sig: flipB64(s.sig, 3) }), a).toBe(false);
      if (s.pq_sig !== undefined) expect(verifyWithSuite(a, K(a), MSG, { ...s, pq_sig: flipB64(s.pq_sig, 3) }), a).toBe(false);
    }
  });
  it('refuses a missing / non-string signature component', () => {
    for (const a of ALL_ALGS) {
      const s = SIGS[a]!;
      expect(verifyWithSuite(a, K(a), MSG, { ...s, sig: undefined }), a).toBe(false);
      expect(verifyWithSuite(a, K(a), MSG, { ...s, sig: 5 }), a).toBe(false);
      expect(verifyWithSuite(a, K(a), MSG, { ...s, sig: null }), a).toBe(false);
      expect(verifyWithSuite(a, K(a), MSG, {}), a).toBe(false);
      expect(verifyWithSuite(a, K(a), MSG, undefined as never), a).toBe(false);
      if (s.pq_sig !== undefined) {
        expect(verifyWithSuite(a, K(a), MSG, { sig: s.sig }), a).toBe(false);
        expect(verifyWithSuite(a, K(a), MSG, { sig: s.sig, pq_sig: 5 }), a).toBe(false);
        expect(verifyWithSuite(a, K(a), MSG, { sig: s.sig, pq_sig: null }), a).toBe(false);
      }
    }
  });
  it('hybrid needs BOTH halves: swapping in a wrong ed25519 key, or a wrong PQ key, fails alone', () => {
    for (const a of ALL_ALGS.filter((x) => SIG_SUITES[x].hasEd25519 && SIG_SUITES[x].needsPqSig)) {
      const s = SIGS[a]!;
      expect(verifyWithSuite(a, { ...K(a), edPub: b64u(ED2.publicKey) }, MSG, s), a).toBe(false); // ed bad, pq good
      // pq bad (another valid-length PQ key), ed good
      const otherPk = a.includes('ml-dsa-65') ? encodeMlDsaPublicKey(ML2.publicKey) : a.includes('slh-dsa-sha2-128f') ? encodeSlhDsaPublicKey(SLH2.publicKey) : a.includes('ml-dsa-87') ? encodeMlDsa87PublicKey(mlDsa87Keygen(seedOf(40, 32)).publicKey) : a.includes('slh-dsa-sha2-256s') ? encodeSlhDsa256sPublicKey(slhDsa256sKeygen(seedOf(41, 96)).publicKey) : undefined;
      if (otherPk !== undefined) expect(verifyWithSuite(a, K(a, otherPk), MSG, s), a).toBe(false);
      // ed good, pq_sig from a different message
      const wrongPqSig = signCached(a, OTHER).pq_sig;
      expect(verifyWithSuite(a, K(a), MSG, { sig: s.sig, pq_sig: wrongPqSig }), a).toBe(false);
      // pq good, ed sig from another message
      const wrongEdSig = signCached(a, OTHER).sig;
      expect(verifyWithSuite(a, K(a), MSG, { sig: wrongEdSig, pq_sig: s.pq_sig }), a).toBe(false);
    }
  });
  it('an Ed25519-bearing suite refuses a missing / non-string edPub', () => {
    for (const a of ALL_ALGS.filter((x) => SIG_SUITES[x].hasEd25519)) {
      const pq = PQPK[a] !== undefined ? { pq: pinned(PQPK[a]!) } : {};
      expect(verifyWithSuite(a, { ...pq }, MSG, SIGS[a]!), a).toBe(false);
      expect(verifyWithSuite(a, { edPub: 5 as unknown as string, ...pq }, MSG, SIGS[a]!), a).toBe(false);
      expect(verifyWithSuite(a, { edPub: ED.publicKey as unknown as string, ...pq }, MSG, SIGS[a]!), a).toBe(false);
    }
  });
  it('a pure-PQ suite does not need or look at edPub', () => {
    for (const a of ALL_ALGS.filter((x) => !SIG_SUITES[x].hasEd25519)) {
      expect(verifyWithSuite(a, { pq: pinned(PQPK[a]!) }, MSG, SIGS[a]!), a).toBe(true);
      expect(verifyWithSuite(a, { edPub: 'garbage', pq: pinned(PQPK[a]!) }, MSG, SIGS[a]!), a).toBe(true);
    }
  });
  it('a PQ suite refuses when the pinned PQ key is missing, forged, bare, or for another key', () => {
    for (const a of ALL_ALGS.filter((x) => SIG_SUITES[x].needsPqPk)) {
      const s = SIGS[a]!;
      const base = { edPub: edPubB64() };
      expect(verifyWithSuite(a, base, MSG, s), `${a} no pq`).toBe(false);
      expect(verifyWithSuite(a, { ...base, pq: { b64u: PQPK[a]!, source: 'trusted' } as never }, MSG, s), `${a} structural forgery`).toBe(false);
      expect(verifyWithSuite(a, { ...base, pq: PQPK[a] as never }, MSG, s), `${a} bare string`).toBe(false);
      expect(verifyWithSuite(a, { ...base, pq: null as never }, MSG, s), `${a} null pq`).toBe(false);
      expect(verifyWithSuite(a, { ...base, pq: Object.create(Object.getPrototypeOf(pinned(PQPK[a]!))) as never }, MSG, s), `${a} proto forgery`).toBe(false);
      expect(verifyWithSuite(a, { ...base, pq: { ...pinned(PQPK[a]!) } as never }, MSG, s), `${a} spread copy`).toBe(false);
    }
  });
  it('a forged pq object is refused EVEN for ed25519 (the choke point is checked before dispatch)', () => {
    expect(verifyWithSuite('ed25519', { edPub: edPubB64(), pq: { b64u: 'x', source: 'trusted' } as never }, MSG, SIGS.ed25519!)).toBe(false);
    expect(verifyWithSuite('ed25519', { edPub: edPubB64(), pq: 'x' as never }, MSG, SIGS.ed25519!)).toBe(false);
    expect(verifyWithSuite('ed25519', { edPub: edPubB64(), pq: null as never }, MSG, SIGS.ed25519!)).toBe(false);
    // ...whereas a genuine minted key (or none) is fine for ed25519
    expect(verifyWithSuite('ed25519', { edPub: edPubB64(), pq: pinned(PQPK['ml-dsa-65']!) }, MSG, SIGS.ed25519!)).toBe(true);
    expect(verifyWithSuite('ed25519', { edPub: edPubB64() }, MSG, SIGS.ed25519!)).toBe(true);
    expect(verifyWithSuite(undefined, { edPub: edPubB64() }, MSG, SIGS.ed25519!)).toBe(true);
  });
  it('unknown alg => false; undefined keys never throw', () => {
    for (const bad of ['nope', null, 5, '', 'toString']) expect(verifyWithSuite(bad, K('ed25519'), MSG, SIGS.ed25519!), String(bad)).toBe(false);
    for (const a of ALL_ALGS.filter((x) => !SIG_SUITES[x].hasEd25519)) {
      expect(verifyWithSuite(a, undefined as never, MSG, SIGS[a]!), a).toBe(false);
    }
    expect(verifyWithSuite('ml-dsa-65', null as never, MSG, SIGS['ml-dsa-65']!)).toBe(false);
  });
  it('suite confusion: a signature never verifies under another PQ family or a different suite name', () => {
    const pure = ALL_ALGS.filter((x) => SIG_SUITES[x].needsPqPk && !SIG_SUITES[x].hasEd25519 && x !== 'less-cat1');
    for (const a of pure) for (const b of pure) {
      if (a === b) continue;
      expect(verifyWithSuite(b, K(b, PQPK[a]), MSG, SIGS[a]!), `${a} under ${b}`).toBe(false);
    }
    // ed25519 signature under a hybrid with that same sig but no pq_sig
    expect(verifyWithSuite('hybrid-ed25519-ml-dsa-65', K('hybrid-ed25519-ml-dsa-65'), MSG, { sig: SIGS.ed25519!.sig })).toBe(false);
  });
  it('nested hybrid: the PQ half is bound to the exact ed25519 sig bytes (and differs from plain hybrid)', () => {
    const nested = 'hybrid-nested-ed25519-ml-dsa-65';
    const plain = 'hybrid-ed25519-ml-dsa-65';
    const kN = K(nested);
    // plain-hybrid pq_sig is over msg only: rejected by nested; nested pq_sig rejected by plain
    expect(verifyWithSuite(nested, kN, MSG, SIGS[plain]!)).toBe(false);
    expect(verifyWithSuite(plain, K(plain), MSG, SIGS[nested]!)).toBe(false);
    // an undecodable / wrong-length `sig` must not throw: it is a plain refusal
    for (const badSig of ['AAAA', '!!', '', b64u(new Uint8Array(63)), b64u(new Uint8Array(65))]) {
      expect(() => verifyWithSuite(nested, kN, MSG, { sig: badSig, pq_sig: SIGS[nested]!.pq_sig }), badSig).not.toThrow();
      expect(verifyWithSuite(nested, kN, MSG, { sig: badSig, pq_sig: SIGS[nested]!.pq_sig }), badSig).toBe(false);
    }
    expect(verifyWithSuite(nested, kN, MSG, { sig: 5, pq_sig: SIGS[nested]!.pq_sig })).toBe(false);
    expect(verifyWithSuite(nested, kN, MSG, undefined as never)).toBe(false);
    // a mauled-but-still-valid-looking ed sig changes the nested message
    expect(verifyWithSuite(nested, kN, MSG, { sig: flipB64(SIGS[nested]!.sig, 63), pq_sig: SIGS[nested]!.pq_sig })).toBe(false);
  });
  it('hybrid suites with an absent signature object never throw', () => {
    for (const a of ALL_ALGS.filter((x) => SIG_SUITES[x].needsPqSig)) {
      expect(() => verifyWithSuite(a, K(a), MSG, undefined as never), a).not.toThrow();
      expect(verifyWithSuite(a, K(a), MSG, undefined as never), a).toBe(false);
    }
  });
});

// ---- verifyLeafSuite ------------------------------------------------------------------------------
describe('verifyLeafSuite routes holder / pq / sig / pqSig into the seam', () => {
  it('ed25519: holder is the verifying key; wrong holder / message refused', () => {
    const i = { alg: undefined, holder: b64u(ED.publicKey), message: MSG, sig: SIGS.ed25519!.sig };
    expect(verifyLeafSuite(i)).toBe(true);
    expect(verifyLeafSuite({ ...i, holder: b64u(ED2.publicKey) })).toBe(false);
    expect(verifyLeafSuite({ ...i, message: OTHER })).toBe(false);
    expect(verifyLeafSuite({ ...i, alg: 'ed25519' })).toBe(true);
    expect(verifyLeafSuite({ ...i, alg: 'bogus' })).toBe(false);
  });
  it('pure PQ and hybrid: pq key + sig + pqSig mapped correctly', () => {
    const pure = { alg: 'ml-dsa-65', holder: 'ignored', pq: pinned(PQPK['ml-dsa-65']!), message: MSG, sig: SIGS['ml-dsa-65']!.sig };
    expect(verifyLeafSuite(pure)).toBe(true);
    expect(verifyLeafSuite({ ...pure, pq: undefined })).toBe(false);
    const hy = { alg: 'hybrid-ed25519-ml-dsa-65', holder: b64u(ED.publicKey), pq: pinned(PQPK['hybrid-ed25519-ml-dsa-65']!), message: MSG, sig: SIGS['hybrid-ed25519-ml-dsa-65']!.sig, pqSig: SIGS['hybrid-ed25519-ml-dsa-65']!.pq_sig };
    expect(verifyLeafSuite(hy)).toBe(true);
    expect(verifyLeafSuite({ ...hy, pqSig: undefined })).toBe(false);
    expect(verifyLeafSuite({ ...hy, pq: undefined })).toBe(false);
    expect(verifyLeafSuite({ ...hy, holder: b64u(ED2.publicKey) })).toBe(false);
    expect(verifyLeafSuite({ ...hy, pq: { b64u: PQPK['hybrid-ed25519-ml-dsa-65']!, source: 'trusted' } as never })).toBe(false);
  });
});

// ---- suite artifact helpers ------------------------------------------------------------------------
describe('suitePqPublicKey', () => {
  it('returns the suite-selected public key, whatever other material is also supplied', () => {
    expect(suitePqPublicKey('ml-dsa-65', KEYS)).toBe(b64u(ML.publicKey));
    expect(suitePqPublicKey('hybrid-ed25519-ml-dsa-65', KEYS)).toBe(b64u(ML.publicKey));
    expect(suitePqPublicKey('hybrid-nested-ed25519-ml-dsa-65', KEYS)).toBe(b64u(ML.publicKey));
    expect(suitePqPublicKey('slh-dsa-sha2-128f', KEYS)).toBe(b64u(SLH.publicKey));
    expect(suitePqPublicKey('hybrid-ed25519-slh-dsa-sha2-128f', KEYS)).toBe(b64u(SLH.publicKey));
    expect(suitePqPublicKey('ml-dsa-87', KEYS)).toBe(b64u(ML87.publicKey));
    expect(suitePqPublicKey('hybrid-ed25519-ml-dsa-87', KEYS)).toBe(b64u(ML87.publicKey));
    expect(suitePqPublicKey('slh-dsa-sha2-256s', KEYS)).toBe(b64u(SLH256.publicKey));
    expect(suitePqPublicKey('hybrid-ed25519-slh-dsa-sha2-256s', KEYS)).toBe(b64u(SLH256.publicKey));
    expect(suitePqPublicKey('fn-dsa-512', KEYS)).toBe(b64u(FN512.verifyingKey));
    expect(suitePqPublicKey('fn-dsa-1024', KEYS)).toBe(b64u(FN1024.verifyingKey));
    expect(suitePqPublicKey('less-cat1', KEYS)).toBe(b64u(LESS.publicKey));
    expect(suitePqPublicKey('hybrid-ed25519-less-cat1', KEYS)).toBe(b64u(LESS.publicKey));
  });
  it('only the suite\'s own family is consulted (single-family key sets)', () => {
    const fams: Array<[SigAlg, keyof SuiteSecretKeys]> = [
      ['ml-dsa-65', 'mlDsa'], ['slh-dsa-sha2-128f', 'slhDsa'], ['ml-dsa-87', 'mlDsa87'], ['slh-dsa-sha2-256s', 'slhDsa256s'],
      ['fn-dsa-512', 'fnDsa512'], ['fn-dsa-1024', 'fnDsa1024'], ['less-cat1', 'lessCat1'],
    ];
    for (const [alg, slot] of fams) {
      // the right family alone => key; every OTHER family alone => undefined
      expect(suitePqPublicKey(alg, { [slot]: KEYS[slot] }), alg).toBe(suitePqPublicKey(alg, KEYS));
      for (const [, otherSlot] of fams) {
        if (otherSlot === slot) continue;
        expect(suitePqPublicKey(alg, { [otherSlot]: KEYS[otherSlot] }), `${alg} with only ${otherSlot}`).toBeUndefined();
      }
    }
  });
  it('undefined for ed25519, unknown alg, absent keys', () => {
    expect(suitePqPublicKey('ed25519', KEYS)).toBeUndefined();
    expect(suitePqPublicKey(undefined, KEYS)).toBeUndefined();
    expect(suitePqPublicKey('nope', KEYS)).toBeUndefined();
    expect(suitePqPublicKey('ml-dsa-65', undefined)).toBeUndefined();
    expect(suitePqPublicKey('ml-dsa-65', {})).toBeUndefined();
  });
});

describe('signSuiteArtifact', () => {
  it('ed25519 (explicit or default): ONLY { sig } — no alg / pq keys at all', () => {
    for (const a of ['ed25519', undefined]) {
      const r = signSuiteArtifact(a, KEYS, MSG);
      expect(r).toStrictEqual({ sig: SIGS.ed25519!.sig });
      expect(Object.keys(r)).toEqual(['sig']);
    }
  });
  it.each(ALL_ALGS.filter((x) => x !== 'ed25519'))('%s returns { sig, alg, pq_pk, pq_sig? } with the signer\'s own pk', (a) => {
    const r = signSuiteArtifact(a, KEYS, MSG);
    const expected = isSlh256(a) ? signCached(a, MSG) : SIGS[a]!;
    expect(r.sig, a).toBe(expected.sig);
    expect(r.alg, a).toBe(a);
    expect(r.pq_pk, a).toBe(PQPK[a]);
    if (expected.pq_sig !== undefined) expect(r.pq_sig, a).toBe(expected.pq_sig);
    else expect('pq_sig' in r, a).toBe(false);
  }, 60_000);
  it('propagates the signer\'s throw on unknown alg / missing key material', () => {
    expect(thrown(() => signSuiteArtifact('nope', KEYS, MSG))).toBeInstanceOf(RangeError);
    expect(thrown(() => signSuiteArtifact('ml-dsa-65', { edSecret: ED.secretKey }, MSG))).toBeInstanceOf(TypeError);
  });
});

describe('suiteKeysOf', () => {
  it('drops alg, keeps PQ material, adds edSecret (which wins)', () => {
    const k = suiteKeysOf(ED.secretKey, { alg: 'ml-dsa-65', mlDsa: ML });
    expect(k).toStrictEqual({ mlDsa: ML, edSecret: ED.secretKey });
    expect('alg' in k).toBe(false);
    const forced = suiteKeysOf(ED.secretKey, { mlDsa: ML, edSecret: ED2.secretKey } as never);
    expect(forced.edSecret).toBe(ED.secretKey);
    expect(suiteKeysOf(ED.secretKey, undefined)).toStrictEqual({ edSecret: ED.secretKey });
  });
});

describe('bindSuiteFields', () => {
  const base = { a: 1, b: 'x' };
  it('default / ed25519 / unknown alg: returns the SAME object (byte-identical body)', () => {
    expect(bindSuiteFields(base, undefined, 'pk')).toBe(base);
    expect(bindSuiteFields(base, 'ed25519', 'pk')).toBe(base);
    expect(bindSuiteFields(base, 'nope', 'pk')).toBe(base);
    expect(bindSuiteFields(base, 5, 'pk')).toBe(base);
  });
  it('a PQ suite returns a COPY with alg and pq_pk bound; base is untouched', () => {
    for (const a of ALL_ALGS.filter((x) => x !== 'ed25519')) {
      const r = bindSuiteFields(base, a, 'PK');
      expect(r, a).not.toBe(base);
      expect(r, a).toStrictEqual({ a: 1, b: 'x', alg: a, pq_pk: 'PK' });
    }
    expect(base).toStrictEqual({ a: 1, b: 'x' });
    // `pq_sig` is never bound
    expect('pq_sig' in bindSuiteFields(base, 'hybrid-ed25519-ml-dsa-65', 'PK')).toBe(false);
  });
  it('pq_pk is bound as given even when undefined (key present), overriding a base pq_pk', () => {
    const r = bindSuiteFields({ pq_pk: 'old' } as { pq_pk?: string }, 'ml-dsa-65', undefined);
    expect('pq_pk' in r).toBe(true);
    expect(r.pq_pk).toBeUndefined();
    expect(bindSuiteFields({ alg: 'ed25519' } as object, 'ml-dsa-65', 'k')).toMatchObject({ alg: 'ml-dsa-65' });
  });
});
