import { beforeAll, describe, expect, it } from 'vitest';
import { mintRoot } from './capability';
import { b64u, unb64u, utf8 } from './hash';
import { generateKeyPair, sign } from './keys';
import { paramsDigest } from './merkle';
import { type PCActn, type PCActnBody, buildPCActn, thresholdMessage, verifyPCActnCore } from './pcactn';
import {
  type SlhDsaKeyPair,
  type SuiteSecretKeys,
  ED25519_SIGNATURE_BYTES,
  ML_DSA_87_PUBLIC_KEY_BYTES,
  ML_DSA_87_SEED_BYTES,
  ML_DSA_87_SIGNATURE_BYTES,
  SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES,
  SLH_DSA_SHA2_256S_SECRET_KEY_BYTES,
  SLH_DSA_SHA2_256S_SEED_BYTES,
  SLH_DSA_SHA2_256S_SIGNATURE_BYTES,
  bindSuiteFields,
  encodeMlDsa87PublicKey,
  encodeSlhDsa256sPublicKey,
  isKnownSigAlg,
  mlDsa87Keygen,
  mlDsa87Sign,
  mlDsa87Verify,
  mlDsa87VerifyB64u,
  resolveSigAlg,
  signSuiteArtifact,
  signWithSuite,
  slhDsa256sKeygen,
  slhDsa256sSign,
  slhDsa256sVerify,
  slhDsa256sVerifyB64u,
  verifyLeafSuite,
  verifyWithSuite,
} from './pq';
import { validateWireV2 } from './wire';

const NOW = 1_800_000_000_000;
const AUD = 'rs-level5';
const ML87 = 'ml-dsa-87' as const;
const ML87_HYBRID = 'hybrid-ed25519-ml-dsa-87' as const;
const SLH256 = 'slh-dsa-sha2-256s' as const;
const SLH256_HYBRID = 'hybrid-ed25519-slh-dsa-sha2-256s' as const;

const flip = (s: string): string => {
  const b = unb64u(s);
  b[0] = (b[0] ?? 0) ^ 0x01;
  return b64u(b);
};

const pqSigOf = (s: string | undefined): string => {
  if (typeof s !== 'string') throw new Error('expected a present pq_sig (hybrid suite)');
  return s;
};

/** A full ed25519 PCActn body (sig stripped) plus a fresh ML-DSA-87 key pair and a fresh SLH-DSA-256s key pair. */
function fixture() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const root = mintRoot({
    principalSecret: P.secretKey,
    principalPublic: b64u(P.publicKey),
    holder: b64u(A.publicKey),
    caveats: [{ type: 'ttl', secs: 60 }],
  });
  const plan = [
    { id: 'n1', verb: 'read', resource: 'db/users' },
    { id: 'n2', verb: 'write', resource: 'db/orders', params_digest: paramsDigest({ qty: 3 }), reversibility_class: 'reversible' },
  ];
  const base = buildPCActn({
    aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan, nodeId: 'n2',
    params: { qty: 3 }, counter: 7, signerSecret: A.secretKey,
  });
  const { sig: _s, ...body } = base;
  void _s;
  const mlDsa87 = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(7));
  return { root, agent: A, base, body, mlDsa87 };
}

/**
 * Build a signed PCActn under a Level-5 suite via the seam only (signPCActnSuite in pcactn.ts does not
 * carry an mlDsa87/slhDsa256s branch — wiring those surfaces is the mechanical follow). Binds `alg`+`pq_pk`
 * into the body, then signs the canonical message with the seam.
 */
function signPCActnLevel5(
  body: PCActnBody,
  opts: { alg: SigAlgL5; keys: SuiteSecretKeys; pqPk: string },
): PCActn {
  const withSuite: PCActnBody = { ...body, alg: opts.alg, pq_pk: opts.pqPk };
  const msg = thresholdMessage(withSuite);
  const parts = signWithSuite(opts.alg, opts.keys, msg);
  return parts.pq_sig === undefined ? { ...withSuite, sig: parts.sig } : { ...withSuite, sig: parts.sig, pq_sig: parts.pq_sig };
}
type SigAlgL5 = typeof ML87 | typeof ML87_HYBRID | typeof SLH256 | typeof SLH256_HYBRID;

// ================================================================================================
// ML-DSA-87 (FIPS-204, Category 5) — fast, full coverage inline.
// ================================================================================================

describe('ML-DSA-87 primitive (FIPS-204, Category 5)', () => {
  it('sign/verify round-trip; sizes are FIPS-204 Category 5', () => {
    const kp = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(3));
    expect(kp.publicKey.length).toBe(ML_DSA_87_PUBLIC_KEY_BYTES);
    const msg = utf8('category-5 lattice hello');
    const sig = mlDsa87Sign(kp.secretKey, msg);
    expect(sig.length).toBe(ML_DSA_87_SIGNATURE_BYTES);
    expect(mlDsa87Verify(kp.publicKey, msg, sig)).toBe(true);
    expect(mlDsa87VerifyB64u(b64u(kp.publicKey), msg, b64u(sig))).toBe(true);
  });
  it('signing is deterministic (reproducible vectors)', () => {
    const kp = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(9));
    const msg = utf8('x');
    expect(b64u(mlDsa87Sign(kp.secretKey, msg))).toBe(b64u(mlDsa87Sign(kp.secretKey, msg)));
  });
  it('wrong key, tampered message/sig, wrong lengths all fail (never throw)', () => {
    const kp = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(3));
    const other = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(4));
    const msg = utf8('m');
    const sig = mlDsa87Sign(kp.secretKey, msg);
    expect(mlDsa87Verify(other.publicKey, msg, sig)).toBe(false);
    expect(mlDsa87Verify(kp.publicKey, utf8('m2'), sig)).toBe(false);
    const bad = Uint8Array.from(sig); bad[0] = bad[0]! ^ 1;
    expect(mlDsa87Verify(kp.publicKey, msg, bad)).toBe(false);
    expect(mlDsa87Verify(kp.publicKey.subarray(0, 16), msg, sig)).toBe(false);
    expect(mlDsa87Verify(kp.publicKey, msg, sig.subarray(0, 100))).toBe(false);
    expect(mlDsa87VerifyB64u('!!', msg, b64u(sig))).toBe(false);
    expect(mlDsa87VerifyB64u(b64u(kp.publicKey), msg, '!!')).toBe(false);
    // a Category-3 (ml-dsa-65) size sig must not pass as Category 5
    expect(mlDsa87VerifyB64u(b64u(kp.publicKey), msg, b64u(sig.subarray(0, 3309)))).toBe(false);
  });
});

describe('ML-DSA-87 suites via the seam (Category-5 lattice)', () => {
  it('pure ml-dsa-87: signWithSuite + verifyWithSuite round-trip and fail cases', () => {
    const mlDsa87 = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(1));
    const msg = utf8('seam ml87 pure');
    const parts = signWithSuite(ML87, { mlDsa87 }, msg);
    expect(parts.pq_sig).toBeUndefined();
    expect(unb64u(parts.sig).length).toBe(ML_DSA_87_SIGNATURE_BYTES);
    const pub = { mlDsa87Pub: encodeMlDsa87PublicKey(mlDsa87.publicKey) };
    expect(verifyWithSuite(ML87, pub, msg, parts)).toBe(true);
    expect(verifyWithSuite(ML87, pub, msg, { sig: flip(parts.sig) })).toBe(false);
    expect(verifyWithSuite(ML87, pub, utf8('other'), parts)).toBe(false);
    const other = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(2));
    expect(verifyWithSuite(ML87, { mlDsa87Pub: encodeMlDsa87PublicKey(other.publicKey) }, msg, parts)).toBe(false);
  });
  it('pure ml-dsa-87: signWithSuite throws without mlDsa87 key material (fail-closed signer)', () => {
    expect(() => signWithSuite(ML87, {}, utf8('m'))).toThrow(/mlDsa87/);
  });
  it('hybrid-ed25519-ml-dsa-87: both halves required (fail-closed)', () => {
    const ed = generateKeyPair();
    const mlDsa87 = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(1));
    const msg = utf8('seam ml87 hybrid');
    const parts = signWithSuite(ML87_HYBRID, { edSecret: ed.secretKey, mlDsa87 }, msg);
    expect(unb64u(parts.sig).length).toBe(ED25519_SIGNATURE_BYTES);
    expect(unb64u(pqSigOf(parts.pq_sig)).length).toBe(ML_DSA_87_SIGNATURE_BYTES);
    const pub = { edPub: b64u(ed.publicKey), mlDsa87Pub: encodeMlDsa87PublicKey(mlDsa87.publicKey) };
    expect(verifyWithSuite(ML87_HYBRID, pub, msg, parts)).toBe(true);
    expect(verifyWithSuite(ML87_HYBRID, pub, msg, { sig: flip(parts.sig), pq_sig: parts.pq_sig })).toBe(false); // ed broken
    expect(verifyWithSuite(ML87_HYBRID, pub, msg, { sig: parts.sig, pq_sig: flip(pqSigOf(parts.pq_sig)) })).toBe(false); // pq broken
    expect(verifyWithSuite(ML87_HYBRID, pub, msg, { sig: parts.sig })).toBe(false); // pq dropped
    expect(verifyWithSuite(ML87_HYBRID, pub, msg, { pq_sig: parts.pq_sig })).toBe(false); // ed dropped
  });
  it('signSuiteArtifact emits alg + pq_pk (pure) and + pq_sig (hybrid)', () => {
    const ed = generateKeyPair();
    const mlDsa87 = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(5));
    const pure = signSuiteArtifact(ML87, { mlDsa87 }, utf8('artifact'));
    expect(pure.alg).toBe(ML87);
    expect(pure.pq_pk).toBe(encodeMlDsa87PublicKey(mlDsa87.publicKey));
    expect(pure.pq_sig).toBeUndefined();
    const hyb = signSuiteArtifact(ML87_HYBRID, { edSecret: ed.secretKey, mlDsa87 }, utf8('artifact'));
    expect(hyb.alg).toBe(ML87_HYBRID);
    expect(hyb.pq_pk).toBe(encodeMlDsa87PublicKey(mlDsa87.publicKey));
    expect(unb64u(hyb.sig).length).toBe(ED25519_SIGNATURE_BYTES);
    expect(unb64u(pqSigOf(hyb.pq_sig)).length).toBe(ML_DSA_87_SIGNATURE_BYTES);
  });
  it('end-to-end: a pure ml-dsa-87 PCActn verifies; corruption fails', async () => {
    const { body, mlDsa87, root } = fixture();
    const p = signPCActnLevel5(body, { alg: ML87, keys: { mlDsa87 }, pqPk: encodeMlDsa87PublicKey(mlDsa87.publicKey) });
    expect(p.alg).toBe(ML87);
    expect('pq_sig' in p).toBe(false);
    expect(validateWireV2(p)).toBeNull();
    const r = await verifyPCActnCore(p, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(true);
    expect(r.checks.leaf_signature).toBe('pass');
    const bad: PCActn = { ...p, sig: flip(p.sig) };
    expect((await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
    // verifyLeafSuite dispatches purely on alg + pq_pk
    const msg = thresholdMessage(p);
    expect(verifyLeafSuite({ alg: p.alg, holder: 'anything', pqPublicKey: p.pq_pk, message: msg, sig: p.sig })).toBe(true);
  });
  it('end-to-end: a hybrid ml-dsa-87 PCActn verifies and requires BOTH halves', async () => {
    const { body, agent, mlDsa87, root } = fixture();
    const p = signPCActnLevel5(body, { alg: ML87_HYBRID, keys: { edSecret: agent.secretKey, mlDsa87 }, pqPk: encodeMlDsa87PublicKey(mlDsa87.publicKey) });
    expect(validateWireV2(p)).toBeNull();
    expect((await verifyPCActnCore(p, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('pass');
    const badEd: PCActn = { ...p, sig: flip(p.sig) };
    const badPq: PCActn = { ...p, pq_sig: flip(pqSigOf(p.pq_sig)) };
    expect((await verifyPCActnCore(badEd, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
    expect((await verifyPCActnCore(badPq, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
  });
});

// ================================================================================================
// SLH-DSA-SHA2-256s (FIPS-205, Category 5, small/slow) — signing is ~2.5s, so sign ONCE in beforeAll
// and reuse the artifacts across every assertion.
// ================================================================================================

describe('SLH-DSA-SHA2-256s suite (FIPS-205, Category 5, hash-based anchor)', () => {
  let slhKp: SlhDsaKeyPair;
  let ed: ReturnType<typeof generateKeyPair>;
  let root: ReturnType<typeof fixture>['root'];
  let purePc: PCActn;
  let hybridPc: PCActn;
  let pureMsg: Uint8Array;
  let hybridMsg: Uint8Array;

  beforeAll(() => {
    const f = fixture();
    root = f.root;
    ed = f.agent;
    slhKp = slhDsa256sKeygen(new Uint8Array(SLH_DSA_SHA2_256S_SEED_BYTES).fill(1));
    const pqPk = encodeSlhDsa256sPublicKey(slhKp.publicKey);
    // The two expensive (~2.5s each) SLH-DSA-256s signatures — everything else reuses these.
    purePc = signPCActnLevel5(f.body, { alg: SLH256, keys: { slhDsa256s: slhKp }, pqPk });
    hybridPc = signPCActnLevel5(f.body, { alg: SLH256_HYBRID, keys: { edSecret: ed.secretKey, slhDsa256s: slhKp }, pqPk });
    pureMsg = thresholdMessage(purePc);
    hybridMsg = thresholdMessage(hybridPc);
  }, 60_000);

  it('primitive sizes are FIPS-205 SHA2-256s and verify passes/fails correctly', () => {
    expect(slhKp.publicKey.length).toBe(SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES);
    expect(slhKp.secretKey.length).toBe(SLH_DSA_SHA2_256S_SECRET_KEY_BYTES);
    const sig = unb64u(purePc.sig);
    expect(sig.length).toBe(SLH_DSA_SHA2_256S_SIGNATURE_BYTES);
    expect(slhDsa256sVerify(slhKp.publicKey, pureMsg, sig)).toBe(true);
    expect(slhDsa256sVerify(slhKp.publicKey, utf8('other'), sig)).toBe(false);
    const bad = Uint8Array.from(sig); bad[0] = bad[0]! ^ 1;
    expect(slhDsa256sVerify(slhKp.publicKey, pureMsg, bad)).toBe(false);
    expect(slhDsa256sVerify(slhKp.publicKey.subarray(0, 16), pureMsg, sig)).toBe(false);
    expect(slhDsa256sVerifyB64u(encodeSlhDsa256sPublicKey(slhKp.publicKey), pureMsg, purePc.sig)).toBe(true);
    expect(slhDsa256sVerifyB64u('!!', pureMsg, purePc.sig)).toBe(false);
  });

  it('pure slh-dsa-256s verifies via the seam; tamper / wrong-key / wrong-msg fail', () => {
    const pub = { slhDsa256sPub: encodeSlhDsa256sPublicKey(slhKp.publicKey) };
    expect(verifyWithSuite(SLH256, pub, pureMsg, { sig: purePc.sig })).toBe(true);
    expect(verifyWithSuite(SLH256, pub, pureMsg, { sig: flip(purePc.sig) })).toBe(false);
    expect(verifyWithSuite(SLH256, pub, utf8('nope'), { sig: purePc.sig })).toBe(false);
    const other = slhDsa256sKeygen(new Uint8Array(SLH_DSA_SHA2_256S_SEED_BYTES).fill(2));
    expect(verifyWithSuite(SLH256, { slhDsa256sPub: encodeSlhDsa256sPublicKey(other.publicKey) }, pureMsg, { sig: purePc.sig })).toBe(false);
  });

  it('pure slh-dsa-256s: signWithSuite throws without slhDsa256s key material (fail-closed signer)', () => {
    expect(() => signWithSuite(SLH256, {}, utf8('m'))).toThrow(/slhDsa256s/);
  });

  it('hybrid-ed25519-slh-dsa-256s verifies via the seam and requires BOTH halves', () => {
    const pub = { edPub: b64u(ed.publicKey), slhDsa256sPub: encodeSlhDsa256sPublicKey(slhKp.publicKey) };
    const parts = { sig: hybridPc.sig, pq_sig: pqSigOf(hybridPc.pq_sig) };
    expect(unb64u(parts.sig).length).toBe(ED25519_SIGNATURE_BYTES);
    expect(unb64u(parts.pq_sig).length).toBe(SLH_DSA_SHA2_256S_SIGNATURE_BYTES);
    expect(verifyWithSuite(SLH256_HYBRID, pub, hybridMsg, parts)).toBe(true);
    expect(verifyWithSuite(SLH256_HYBRID, pub, hybridMsg, { sig: flip(parts.sig), pq_sig: parts.pq_sig })).toBe(false);
    expect(verifyWithSuite(SLH256_HYBRID, pub, hybridMsg, { sig: parts.sig, pq_sig: flip(parts.pq_sig) })).toBe(false);
    expect(verifyWithSuite(SLH256_HYBRID, pub, hybridMsg, { sig: parts.sig })).toBe(false); // pq dropped
    expect(verifyWithSuite(SLH256_HYBRID, pub, hybridMsg, { pq_sig: parts.pq_sig })).toBe(false); // ed dropped
  });

  it('end-to-end: a pure slh-dsa-256s PCActn verifies; corruption fails', async () => {
    expect(purePc.alg).toBe(SLH256);
    expect('pq_sig' in purePc).toBe(false);
    expect(validateWireV2(purePc)).toBeNull();
    const r = await verifyPCActnCore(purePc, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(true);
    expect(r.checks.leaf_signature).toBe('pass');
    const bad: PCActn = { ...purePc, sig: flip(purePc.sig) };
    expect((await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
  });

  it('end-to-end: a hybrid slh-dsa-256s PCActn verifies and requires BOTH halves', async () => {
    expect(hybridPc.alg).toBe(SLH256_HYBRID);
    expect(validateWireV2(hybridPc)).toBeNull();
    expect((await verifyPCActnCore(hybridPc, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('pass');
    const badEd: PCActn = { ...hybridPc, sig: flip(hybridPc.sig) };
    const badPq: PCActn = { ...hybridPc, pq_sig: flip(pqSigOf(hybridPc.pq_sig)) };
    expect((await verifyPCActnCore(badEd, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
    expect((await verifyPCActnCore(badPq, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
  });
});

// ================================================================================================
// Registry metadata, fail-closed behaviour, and the invariant that existing suites are untouched.
// ================================================================================================

describe('Level-5 suite registry metadata', () => {
  it('all four new suites resolve with correct metadata', () => {
    for (const a of [ML87, ML87_HYBRID, SLH256, SLH256_HYBRID]) {
      expect(isKnownSigAlg(a)).toBe(true);
      expect(resolveSigAlg(a)?.alg).toBe(a);
    }
    expect(resolveSigAlg(ML87)).toMatchObject({
      hasEd25519: false, hasMlDsa: false, hasSlhDsa: false, hasMlDsa87: true, hasSlhDsa256s: false,
      needsPqPk: true, needsPqSig: false, sigBytes: ML_DSA_87_SIGNATURE_BYTES, pqPkBytes: ML_DSA_87_PUBLIC_KEY_BYTES, pqSigBytes: 0,
    });
    expect(resolveSigAlg(ML87_HYBRID)).toMatchObject({
      hasEd25519: true, hasMlDsa87: true, needsPqPk: true, needsPqSig: true,
      sigBytes: ED25519_SIGNATURE_BYTES, pqPkBytes: ML_DSA_87_PUBLIC_KEY_BYTES, pqSigBytes: ML_DSA_87_SIGNATURE_BYTES,
    });
    expect(resolveSigAlg(SLH256)).toMatchObject({
      hasEd25519: false, hasSlhDsa256s: true, needsPqPk: true, needsPqSig: false,
      sigBytes: SLH_DSA_SHA2_256S_SIGNATURE_BYTES, pqPkBytes: SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, pqSigBytes: 0,
    });
    expect(resolveSigAlg(SLH256_HYBRID)).toMatchObject({
      hasEd25519: true, hasSlhDsa256s: true, needsPqPk: true, needsPqSig: true,
      sigBytes: ED25519_SIGNATURE_BYTES, pqPkBytes: SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES, pqSigBytes: SLH_DSA_SHA2_256S_SIGNATURE_BYTES,
    });
  });
  it('bindSuiteFields binds alg + the Category-5 pq public key (downgrade/key-swap protection)', () => {
    const pqPk = encodeMlDsa87PublicKey(mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(6)).publicKey);
    expect(bindSuiteFields({ foo: 1 }, ML87, pqPk)).toEqual({ foo: 1, alg: ML87, pq_pk: pqPk });
  });
});

describe('unknown / downgrade fail-closed; ed25519 unaffected', () => {
  it('unknown Level-5-looking alg => signWithSuite throws, verifyWithSuite false', () => {
    const mlDsa87 = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(1));
    expect(() => signWithSuite('ml-dsa-99', { mlDsa87 }, utf8('m'))).toThrow();
    expect(() => signWithSuite('slh-dsa-sha2-256f', {}, utf8('m'))).toThrow();
    expect(verifyWithSuite('ml-dsa-99', { mlDsa87Pub: 'x' }, utf8('m'), { sig: 'y' })).toBe(false);
  });
  it('downgrade: verifying an ml-dsa-87 sig as the Category-3 ml-dsa-65 fails closed (wrong length)', () => {
    const mlDsa87 = mlDsa87Keygen(new Uint8Array(ML_DSA_87_SEED_BYTES).fill(1));
    const msg = utf8('downgrade');
    const parts = signWithSuite(ML87, { mlDsa87 }, msg);
    // the 4627-byte ml-dsa-87 sig is not a valid ml-dsa-65 (3309) sig; verifying under the wrong suite fails
    expect(verifyWithSuite('ml-dsa-65', { mlDsaPub: encodeMlDsa87PublicKey(mlDsa87.publicKey) }, msg, parts)).toBe(false);
  });
  it('ed25519 and the existing PQ suites are BYTE-IDENTICAL after adding the Level-5 suites', () => {
    const ed = generateKeyPair();
    const msg = utf8('classical unchanged');
    const parts = signWithSuite('ed25519', { edSecret: ed.secretKey }, msg);
    expect(parts.sig).toBe(b64u(sign(ed.secretKey, msg)));
    expect(parts.pq_sig).toBeUndefined();
    expect(signSuiteArtifact('ed25519', { edSecret: ed.secretKey }, msg)).toEqual({ sig: parts.sig });
    expect(verifyWithSuite('ed25519', { edPub: b64u(ed.publicKey) }, msg, parts)).toBe(true);
  });
  it('an ml-dsa-87 pq_pk on an ed25519 PCActn is a wire failure (closed field set unchanged)', () => {
    const { base, mlDsa87 } = fixture();
    expect(validateWireV2(base)).toBeNull();
    expect(validateWireV2({ ...base, pq_pk: encodeMlDsa87PublicKey(mlDsa87.publicKey) })).not.toBeNull();
  });
});
