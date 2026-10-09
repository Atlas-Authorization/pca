import { describe, expect, it } from 'vitest';
import { mintRoot } from './capability';
import { b64u, unb64u, utf8 } from './hash';
import { generateKeyPair, sign } from './keys';
import { paramsDigest } from './merkle';
import {
  type PCActn,
  type PCActnBody,
  buildPCActn,
  signPCActn,
  signPCActnSuite,
  thresholdMessage,
  verifyPCActnCore,
} from './pcactn';
import {
  type SlhDsaKeyPair,
  SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES,
  SLH_DSA_SHA2_128F_SECRET_KEY_BYTES,
  SLH_DSA_SHA2_128F_SIGNATURE_BYTES,
  SLH_DSA_SHA2_128F_SEED_BYTES,
  ED25519_SIGNATURE_BYTES,
  bindSuiteFields,
  encodeSlhDsaPublicKey,
  isKnownSigAlg,
  resolveSigAlg,
  signSuiteArtifact,
  signWithSuite,
  slhDsa128fKeygen,
  slhDsa128fSign,
  slhDsa128fVerify,
  slhDsa128fVerifyB64u,
  verifyLeafSuite,
  verifyWithSuite,
} from './pq';
import { validateWireV2 } from './wire';

const NOW = 1_800_000_000_000;
const AUD = 'rs-slhdsa';
const PURE = 'slh-dsa-sha2-128f' as const;
const HYBRID = 'hybrid-ed25519-slh-dsa-sha2-128f' as const;

const flip = (s: string): string => {
  const b = unb64u(s);
  b[0] = (b[0] ?? 0) ^ 0x01;
  return b64u(b);
};

/** Assert a hybrid suite's `pq_sig` is present and return it as a string (no non-null assertion needed). */
const pqSigOf = (s: string | undefined): string => {
  if (typeof s !== 'string') throw new Error('expected a present pq_sig (hybrid suite)');
  return s;
};

/** A full ed25519 PCActn plus a fresh SLH-DSA key pair, mirroring pq.test.ts's fixture. */
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
  const slhDsa = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(7));
  return { root, agent: A, base, body, slhDsa };
}

/**
 * Build a signed PCActn under an SLH-DSA suite using ONLY the seam exports (signPCActnSuite in pcactn.ts
 * does not yet carry an slhDsa branch — that is the mechanical follow). This reproduces exactly what the
 * seam does: bind `alg`+`pq_pk` into the body, then sign the canonical message with SLH-DSA (and, for
 * hybrid, Ed25519 over the SAME message).
 */
function signPCActnSlh(body: PCActnBody, opts: { alg: typeof PURE | typeof HYBRID; slhDsa: SlhDsaKeyPair; edLeafSecret?: Uint8Array }): PCActn {
  const withSuite: PCActnBody = { ...body, alg: opts.alg, pq_pk: encodeSlhDsaPublicKey(opts.slhDsa.publicKey) };
  const msg = thresholdMessage(withSuite);
  if (opts.alg === PURE) {
    return { ...withSuite, sig: b64u(slhDsa128fSign(opts.slhDsa.secretKey, msg)) };
  }
  if (!opts.edLeafSecret) throw new Error('hybrid needs edLeafSecret');
  return { ...withSuite, sig: b64u(sign(opts.edLeafSecret, msg)), pq_sig: b64u(slhDsa128fSign(opts.slhDsa.secretKey, msg)) };
}

describe('SLH-DSA-SHA2-128f primitive (FIPS-205 / SPHINCS+)', () => {
  it('sign/verify roundtrip; sizes are FIPS-205 SHA2-128f', () => {
    const kp = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(3));
    expect(kp.publicKey.length).toBe(SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES);
    expect(kp.secretKey.length).toBe(SLH_DSA_SHA2_128F_SECRET_KEY_BYTES);
    const msg = utf8('hash-based post-quantum hello');
    const sig = slhDsa128fSign(kp.secretKey, msg);
    expect(sig.length).toBe(SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
    expect(slhDsa128fVerify(kp.publicKey, msg, sig)).toBe(true);
    expect(slhDsa128fVerifyB64u(b64u(kp.publicKey), msg, b64u(sig))).toBe(true);
  });
  it('signing is deterministic (reproducible vectors)', () => {
    const kp = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(9));
    const msg = utf8('x');
    expect(b64u(slhDsa128fSign(kp.secretKey, msg))).toBe(b64u(slhDsa128fSign(kp.secretKey, msg)));
  });
  it('wrong key, tampered message/sig, wrong lengths all fail (never throw)', () => {
    const kp = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(3));
    const other = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(4));
    const msg = utf8('m');
    const sig = slhDsa128fSign(kp.secretKey, msg);
    expect(slhDsa128fVerify(other.publicKey, msg, sig)).toBe(false);
    expect(slhDsa128fVerify(kp.publicKey, utf8('m2'), sig)).toBe(false);
    const bad = Uint8Array.from(sig); bad[0] = bad[0]! ^ 1;
    expect(slhDsa128fVerify(kp.publicKey, msg, bad)).toBe(false);
    expect(slhDsa128fVerify(kp.publicKey.subarray(0, 16), msg, sig)).toBe(false);
    expect(slhDsa128fVerify(kp.publicKey, msg, sig.subarray(0, 100))).toBe(false);
    expect(slhDsa128fVerifyB64u('!!', msg, b64u(sig))).toBe(false);
    expect(slhDsa128fVerifyB64u(b64u(kp.publicKey), msg, '!!')).toBe(false);
  });
});

describe('SLH-DSA suite registry (assumption-diverse, hash-based)', () => {
  it('both new suites resolve; metadata is correct', () => {
    for (const a of [PURE, HYBRID]) {
      expect(isKnownSigAlg(a)).toBe(true);
      expect(resolveSigAlg(a)?.alg).toBe(a);
    }
    expect(resolveSigAlg(PURE)).toMatchObject({
      hasEd25519: false, hasMlDsa: false, hasSlhDsa: true, needsPqPk: true, needsPqSig: false,
      sigBytes: SLH_DSA_SHA2_128F_SIGNATURE_BYTES, pqPkBytes: SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, pqSigBytes: 0,
    });
    expect(resolveSigAlg(HYBRID)).toMatchObject({
      hasEd25519: true, hasMlDsa: false, hasSlhDsa: true, needsPqPk: true, needsPqSig: true,
      sigBytes: ED25519_SIGNATURE_BYTES, pqPkBytes: SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES, pqSigBytes: SLH_DSA_SHA2_128F_SIGNATURE_BYTES,
    });
  });
});

describe('pure slh-dsa-sha2-128f via the seam', () => {
  it('signWithSuite + verifyWithSuite round-trip', () => {
    const slhDsa = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(1));
    const msg = utf8('seam pure');
    const parts = signWithSuite(PURE, { slhDsa }, msg);
    expect(parts.pq_sig).toBeUndefined();
    expect(unb64u(parts.sig).length).toBe(SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
    const pub = { slhDsaPub: encodeSlhDsaPublicKey(slhDsa.publicKey) };
    expect(verifyWithSuite(PURE, pub, msg, parts)).toBe(true);
    // tampered sig / wrong message / wrong key all fail
    expect(verifyWithSuite(PURE, pub, msg, { sig: flip(parts.sig) })).toBe(false);
    expect(verifyWithSuite(PURE, pub, utf8('other'), parts)).toBe(false);
    const other = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(2));
    expect(verifyWithSuite(PURE, { slhDsaPub: encodeSlhDsaPublicKey(other.publicKey) }, msg, parts)).toBe(false);
  });
  it('signWithSuite throws without slhDsa key material (fail-closed signer)', () => {
    expect(() => signWithSuite(PURE, {}, utf8('m'))).toThrow(/slhDsa/);
  });
  it('signSuiteArtifact emits alg + pq_pk, no pq_sig', () => {
    const slhDsa = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(5));
    const art = signSuiteArtifact(PURE, { slhDsa }, utf8('artifact'));
    expect(art.alg).toBe(PURE);
    expect(art.pq_pk).toBe(encodeSlhDsaPublicKey(slhDsa.publicKey));
    expect(art.pq_sig).toBeUndefined();
    expect(unb64u(art.sig).length).toBe(SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
  });
  it('bindSuiteFields binds alg + the SLH-DSA public key (downgrade/key-swap protection)', () => {
    const pqPk = encodeSlhDsaPublicKey(slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(6)).publicKey);
    const bound = bindSuiteFields({ foo: 1 }, PURE, pqPk);
    expect(bound).toEqual({ foo: 1, alg: PURE, pq_pk: pqPk });
  });
});

describe('hybrid-ed25519-slh-dsa-sha2-128f via the seam (BOTH required, fail-closed)', () => {
  it('round-trip: both halves verify', () => {
    const ed = generateKeyPair();
    const slhDsa = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(1));
    const msg = utf8('seam hybrid');
    const parts = signWithSuite(HYBRID, { edSecret: ed.secretKey, slhDsa }, msg);
    expect(unb64u(parts.sig).length).toBe(ED25519_SIGNATURE_BYTES);
    expect(unb64u(pqSigOf(parts.pq_sig)).length).toBe(SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
    const pub = { edPub: b64u(ed.publicKey), slhDsaPub: encodeSlhDsaPublicKey(slhDsa.publicKey) };
    expect(verifyWithSuite(HYBRID, pub, msg, parts)).toBe(true);
  });
  it('corrupt/drop EITHER half => fail', () => {
    const ed = generateKeyPair();
    const slhDsa = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(1));
    const msg = utf8('seam hybrid both');
    const parts = signWithSuite(HYBRID, { edSecret: ed.secretKey, slhDsa }, msg);
    const pub = { edPub: b64u(ed.publicKey), slhDsaPub: encodeSlhDsaPublicKey(slhDsa.publicKey) };
    expect(verifyWithSuite(HYBRID, pub, msg, { sig: flip(parts.sig), pq_sig: parts.pq_sig })).toBe(false); // ed broken
    expect(verifyWithSuite(HYBRID, pub, msg, { sig: parts.sig, pq_sig: flip(pqSigOf(parts.pq_sig)) })).toBe(false); // slh broken
    expect(verifyWithSuite(HYBRID, pub, msg, { sig: parts.sig })).toBe(false); // slh dropped
    expect(verifyWithSuite(HYBRID, pub, msg, { pq_sig: parts.pq_sig })).toBe(false); // ed dropped
  });
  it('signSuiteArtifact emits alg + pq_pk + pq_sig', () => {
    const ed = generateKeyPair();
    const slhDsa = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(5));
    const art = signSuiteArtifact(HYBRID, { edSecret: ed.secretKey, slhDsa }, utf8('artifact'));
    expect(art.alg).toBe(HYBRID);
    expect(art.pq_pk).toBe(encodeSlhDsaPublicKey(slhDsa.publicKey));
    expect(unb64u(art.sig).length).toBe(ED25519_SIGNATURE_BYTES);
    expect(unb64u(pqSigOf(art.pq_sig)).length).toBe(SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
  });
});

describe('unknown-suite + downgrade fail-closed (seam level)', () => {
  it('unknown alg => signWithSuite throws, verifyWithSuite false', () => {
    const slhDsa = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(1));
    expect(() => signWithSuite('slh-dsa-sha2-999', { slhDsa }, utf8('m'))).toThrow();
    expect(verifyWithSuite('slh-dsa-sha2-999', { slhDsaPub: 'x' }, utf8('m'), { sig: 'y' })).toBe(false);
  });
  it('downgrade (verify a slh-dsa sig as ed25519) fails closed', () => {
    const slhDsa = slhDsa128fKeygen(new Uint8Array(SLH_DSA_SHA2_128F_SEED_BYTES).fill(1));
    const msg = utf8('downgrade');
    const parts = signWithSuite(PURE, { slhDsa }, msg);
    // the SLH-DSA sig is not a valid 64-byte Ed25519 sig under any edPub
    expect(verifyWithSuite('ed25519', { edPub: encodeSlhDsaPublicKey(slhDsa.publicKey) }, msg, parts)).toBe(false);
  });
});

describe('ed25519 / existing suites UNAFFECTED by adding SLH-DSA', () => {
  it('signWithSuite ed25519 is BYTE-IDENTICAL to the classical sign, no pq parts', () => {
    const ed = generateKeyPair();
    const msg = utf8('classical');
    const parts = signWithSuite('ed25519', { edSecret: ed.secretKey }, msg);
    expect(parts.sig).toBe(b64u(sign(ed.secretKey, msg)));
    expect(parts.pq_sig).toBeUndefined();
    expect(signSuiteArtifact('ed25519', { edSecret: ed.secretKey }, msg)).toEqual({ sig: parts.sig });
  });
  it('an ed25519 PCActn still validates on the wire and its leaf still verifies', () => {
    const { base, root } = fixture();
    expect(validateWireV2(base)).toBeNull();
    const msg = thresholdMessage(base);
    expect(verifyLeafSuite({ alg: undefined, holder: root.holder, message: msg, sig: base.sig })).toBe(true);
    expect(verifyLeafSuite({ alg: undefined, holder: root.holder, message: msg, sig: flip(base.sig) })).toBe(false);
  });
  it('ed25519 with a stray SLH-DSA pq_pk / pq_sig => wire fail (closed field set unchanged)', () => {
    const { base, slhDsa } = fixture();
    expect(validateWireV2({ ...base, pq_pk: encodeSlhDsaPublicKey(slhDsa.publicKey) })).not.toBeNull();
    expect(validateWireV2({ ...base, pq_sig: b64u(slhDsa128fSign(slhDsa.secretKey, utf8('x'))) })).not.toBeNull();
  });
});

describe('end-to-end leaf: pure slh-dsa PCActn through verifyPCActnCore', () => {
  it('a valid pure slh-dsa PCActn is allowed; a corrupted one fails', async () => {
    const { body, slhDsa, root } = fixture();
    const p = signPCActnSlh(body, { alg: PURE, slhDsa });
    expect(p.alg).toBe(PURE);
    expect('pq_sig' in p).toBe(false);
    expect(validateWireV2(p)).toBeNull();
    const r = await verifyPCActnCore(p, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(true);
    expect(r.checks.leaf_signature).toBe('pass');

    const bad: PCActn = { ...p, sig: flip(p.sig) };
    const r2 = await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r2.checks.leaf_signature).toBe('fail');
  });
  it('verifyLeafSuite dispatches purely on alg for the pure slh-dsa leaf', () => {
    const { body, slhDsa, root } = fixture();
    const p = signPCActnSlh(body, { alg: PURE, slhDsa });
    const msg = thresholdMessage(p);
    // holder (ed25519) is irrelevant for a pure PQ suite; dispatch is on alg + pq_pk only
    expect(verifyLeafSuite({ alg: p.alg, holder: root.holder, pqPublicKey: p.pq_pk, message: msg, sig: p.sig })).toBe(true);
    expect(verifyLeafSuite({ alg: p.alg, holder: 'anything', pqPublicKey: p.pq_pk, message: msg, sig: p.sig })).toBe(true);
    expect(verifyLeafSuite({ alg: p.alg, holder: root.holder, pqPublicKey: p.pq_pk, message: msg, sig: flip(p.sig) })).toBe(false);
  });
  it('downgrade: stripping alg from a pure slh-dsa PCActn => wire fail (claims ed25519, sig/pq_pk mismatch)', async () => {
    const { body, slhDsa, root } = fixture();
    const p = signPCActnSlh(body, { alg: PURE, slhDsa });
    // `alg` is optional, so removing it leaves a (still well-typed) PCActn that now claims ed25519.
    const { alg: _droppedAlg, ...stripped } = p;
    void _droppedAlg;
    expect(validateWireV2(stripped)).not.toBeNull(); // ed25519 forbids pq_pk and wants a 64-byte sig
    const r = await verifyPCActnCore(stripped, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
    expect(Object.keys(r.checks)).toEqual(['wire']); // wire failure is terminal
  });
});

describe('end-to-end leaf: hybrid-ed25519-slh-dsa PCActn through verifyPCActnCore', () => {
  it('a valid hybrid PCActn is allowed end-to-end', async () => {
    const { body, agent, slhDsa, root } = fixture();
    const p = signPCActnSlh(body, { alg: HYBRID, slhDsa, edLeafSecret: agent.secretKey });
    expect(p.alg).toBe(HYBRID);
    expect(validateWireV2(p)).toBeNull();
    const r = await verifyPCActnCore(p, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(true);
    expect(r.checks.leaf_signature).toBe('pass');
  });
  it('valid Ed25519 but INVALID SLH-DSA => fail (both required)', async () => {
    const { body, agent, slhDsa, root } = fixture();
    const p = signPCActnSlh(body, { alg: HYBRID, slhDsa, edLeafSecret: agent.secretKey });
    const bad: PCActn = { ...p, pq_sig: flip(pqSigOf(p.pq_sig)) };
    expect(validateWireV2(bad)).toBeNull(); // still well-formed; the failure is cryptographic
    const r = await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(false);
    expect(r.checks.leaf_signature).toBe('fail');
  });
  it('INVALID Ed25519 but valid SLH-DSA => fail (both required)', async () => {
    const { body, agent, slhDsa, root } = fixture();
    const p = signPCActnSlh(body, { alg: HYBRID, slhDsa, edLeafSecret: agent.secretKey });
    const bad: PCActn = { ...p, sig: flip(p.sig) };
    const r = await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(false);
    expect(r.checks.leaf_signature).toBe('fail');
  });
  it('DROPPING the SLH-DSA component => wire fail (pq_sig required for hybrid)', async () => {
    const { body, agent, slhDsa, root } = fixture();
    const p = signPCActnSlh(body, { alg: HYBRID, slhDsa, edLeafSecret: agent.secretKey });
    // `pq_sig` is optional, so removing it leaves a well-typed PCActn that is now wire-invalid for a hybrid.
    const { pq_sig: _droppedPq, ...dropped } = p;
    void _droppedPq;
    expect(validateWireV2(dropped)).not.toBeNull();
    const r = await verifyPCActnCore(dropped, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
    expect(Object.keys(r.checks)).toEqual(['wire']); // wire failure is terminal
  });
});

describe('leaf signer signPCActnSuite — SLH-DSA (real signer, not the test helper)', () => {
  it('pure slh-dsa: signs + verifies end-to-end and matches the hand-rolled seam output', async () => {
    const { root, body, slhDsa } = fixture();
    const signed = signPCActnSuite(body, { alg: PURE, slhDsa });
    expect(signed.alg).toBe(PURE);
    expect(unb64u(signed.sig).length).toBe(SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
    expect(signed.pq_sig).toBeUndefined();
    // byte-identical to the seam helper (deterministic SLH-DSA over the same canonical message)
    expect(signed).toEqual(signPCActnSlh(body, { alg: PURE, slhDsa }));
    const r = await verifyPCActnCore(signed, { grant: root, nowEpoch: NOW, audience: AUD });
    expect(r.checks.leaf_signature).toBe('pass');
    const bad = { ...signed, sig: flip(signed.sig) };
    expect((await verifyPCActnCore(bad, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
  });

  it('hybrid ed25519+slh-dsa: both halves present, verifies, and requires BOTH', async () => {
    const { root, agent, body, slhDsa } = fixture();
    const signed = signPCActnSuite(body, { alg: HYBRID, slhDsa, edLeafSecret: agent.secretKey });
    expect(signed.alg).toBe(HYBRID);
    expect(unb64u(signed.sig).length).toBe(ED25519_SIGNATURE_BYTES);
    expect(unb64u(pqSigOf(signed.pq_sig)).length).toBe(SLH_DSA_SHA2_128F_SIGNATURE_BYTES);
    expect(signed).toEqual(signPCActnSlh(body, { alg: HYBRID, slhDsa, edLeafSecret: agent.secretKey }));
    expect((await verifyPCActnCore(signed, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('pass');
    // corrupt either half ⇒ leaf fails (hybrid needs both)
    const badEd = { ...signed, sig: flip(signed.sig) };
    const badPq = { ...signed, pq_sig: flip(pqSigOf(signed.pq_sig)) };
    expect((await verifyPCActnCore(badEd, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
    expect((await verifyPCActnCore(badPq, { grant: root, nowEpoch: NOW, audience: AUD })).checks.leaf_signature).toBe('fail');
  });

  it('fails closed when slhDsa key material is missing', () => {
    const { body } = fixture();
    expect(() => signPCActnSuite(body, { alg: PURE })).toThrow(/requires slhDsa/);
    expect(() => signPCActnSuite(body, { alg: HYBRID, slhDsa: fixture().slhDsa })).toThrow(/edLeafSecret/);
  });
})
