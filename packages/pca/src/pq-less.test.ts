/**
 * LESS (code-based, NIST additional-signature Round 2 CANDIDATE) in the PCA signature-suite registry:
 * `less-cat1` (pure) and `hybrid-ed25519-less-cat1`. The backend (@atlasauth/pca-less-wasm) is OPTIONAL and
 * lazily loaded; these tests cover the real roundtrip, tampering of each hybrid half, the absent-backend
 * fail-closed path, and suite-confusion negatives.
 */
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { type Capability, mintRoot, delegate, verifyChain } from './capability';
import { b64u, unb64u, utf8 } from './hash';
import { generateKeyPair, sign } from './keys';
import { paramsDigest } from './merkle';
import { type PCActn, buildPCActn, signPCActnSuite, thresholdMessage, verifyPCActnCore } from './pcactn';
import {
  LESS_CAT1_PUBLIC_KEY_BYTES,
  LESS_CAT1_SIGNATURE_MAX_BYTES,
  LESS_CAT1_SIGNATURE_MIN_BYTES,
  LESS_SEED_BYTES,
  type LessSuiteKey,
  type SigAlg,
  bindSuiteFields,
  encodeLessPublicKey,
  isKnownSigAlg,
  isLessBackendActive,
  lessBackendStatus,
  lessCat1Keygen,
  lessCat1Sign,
  lessCat1Verify,
  lessCat1VerifyB64u,
  mlDsa65Keygen,
  resolveSigAlg,
  setLessBackendLoaderForTests,
  signSuiteArtifact,
  signWithSuite,
  validateSignatureWire,
  verifyLeafSuite,
  verifyWithSuite,
} from './pq';
import { validateWireV2 } from './wire';

const PURE = 'less-cat1' as const;
const HYBRID = 'hybrid-ed25519-less-cat1' as const;
const MSG = utf8('less suite dispatch test message');
const NOW = 1_800_000_000_000;
const AUD = 'rs-less';
const seed = (n: number): Uint8Array => new Uint8Array(LESS_SEED_BYTES).fill(n);
const flip = (s: string, at = 0): string => {
  const b = unb64u(s);
  b[at] = (b[at] ?? 0) ^ 0x01;
  return b64u(b);
};

let K: LessSuiteKey; // the LESS signer
let K2: LessSuiteKey; // an unrelated LESS signer
const ED = generateKeyPair();

beforeAll(() => {
  const a = lessCat1Keygen(seed(1));
  K = { ...a, signSeed: seed(2) };
  const b = lessCat1Keygen(seed(3));
  K2 = { ...b, signSeed: seed(4) };
}, 60_000);

afterEach(() => setLessBackendLoaderForTests(undefined));

describe('LESS backend + registry metadata', () => {
  it('the optional pca-less-wasm backend is resolvable in the workspace', () => {
    expect(isLessBackendActive()).toBe(true);
    expect(lessBackendStatus()).toEqual({ available: true });
  });
  it('both suites resolve with the real sizes (variable-length LESS signature)', () => {
    for (const a of [PURE, HYBRID]) {
      expect(isKnownSigAlg(a)).toBe(true);
      expect(resolveSigAlg(a)?.hasLessCat1).toBe(true);
      expect(resolveSigAlg(a)?.pqPkBytes).toBe(97484);
    }
    expect(resolveSigAlg(PURE)).toMatchObject({ hasEd25519: false, needsPqPk: true, needsPqSig: false, sigBytes: 1329, varLen: { min: 1153, step: 16 } });
    expect(resolveSigAlg(HYBRID)).toMatchObject({ hasEd25519: true, needsPqPk: true, needsPqSig: true, sigBytes: 64, pqSigBytes: 1329 });
    expect(K.publicKey.length).toBe(LESS_CAT1_PUBLIC_KEY_BYTES);
    expect(K.secretKey.length).toBe(32);
  });
  it('keygen and signing are deterministic under a seed; signature length is on the 16-byte grid', () => {
    expect(Buffer.from(lessCat1Keygen(seed(1)).publicKey).equals(Buffer.from(K.publicKey))).toBe(true);
    const s1 = lessCat1Sign(K.secretKey, MSG, seed(9));
    const s2 = lessCat1Sign(K.secretKey, MSG, seed(9));
    expect(Buffer.from(s1).equals(Buffer.from(s2))).toBe(true);
    expect(s1.length).toBeGreaterThanOrEqual(LESS_CAT1_SIGNATURE_MIN_BYTES);
    expect(s1.length).toBeLessThanOrEqual(LESS_CAT1_SIGNATURE_MAX_BYTES);
    expect((LESS_CAT1_SIGNATURE_MAX_BYTES - s1.length) % 16).toBe(0);
    expect(lessCat1Verify(K.publicKey, MSG, s1)).toBe(true);
    expect(lessCat1VerifyB64u(b64u(K.publicKey), MSG, b64u(s1))).toBe(true);
  });
  it('primitive negatives never throw: wrong key/message, bad lengths, bit flips, garbage', () => {
    const s = lessCat1Sign(K.secretKey, MSG, seed(9));
    expect(lessCat1Verify(K2.publicKey, MSG, s)).toBe(false);
    expect(lessCat1Verify(K.publicKey, utf8('other'), s)).toBe(false);
    expect(lessCat1Verify(K.publicKey.subarray(1), MSG, s)).toBe(false);
    expect(lessCat1Verify(K.publicKey, MSG, s.subarray(0, s.length - 1))).toBe(false);
    expect(lessCat1Verify(K.publicKey, MSG, s.subarray(0, s.length - 16))).toBe(false);
    expect(lessCat1Verify(K.publicKey, MSG, new Uint8Array(LESS_CAT1_SIGNATURE_MAX_BYTES))).toBe(false);
    for (const i of [0, 40, 700, s.length - 2, s.length - 1]) {
      const bad = Uint8Array.from(s);
      bad[i] = bad[i]! ^ 1;
      expect(lessCat1Verify(K.publicKey, MSG, bad), `flip@${i}`).toBe(false);
    }
    expect(lessCat1VerifyB64u('!!', MSG, b64u(s))).toBe(false);
    expect(lessCat1VerifyB64u(b64u(K.publicKey), MSG, '!!')).toBe(false);
    expect(lessCat1VerifyB64u(undefined, MSG, undefined)).toBe(false);
  }, 120_000);
});

describe('suite seam roundtrip (signWithSuite / verifyWithSuite / signSuiteArtifact / bindSuiteFields)', () => {
  it('pure less-cat1 signs and verifies; artifact fields carry alg + pq_pk', () => {
    const parts = signWithSuite(PURE, { lessCat1: K }, MSG);
    expect(parts.pq_sig).toBeUndefined();
    expect(verifyWithSuite(PURE, { lessCat1Pub: encodeLessPublicKey(K.publicKey) }, MSG, parts)).toBe(true);
    const art = signSuiteArtifact(PURE, { lessCat1: K }, MSG);
    expect(art).toMatchObject({ alg: PURE, pq_pk: encodeLessPublicKey(K.publicKey) });
    expect(bindSuiteFields({ x: 1 }, PURE, art.pq_pk)).toEqual({ x: 1, alg: PURE, pq_pk: art.pq_pk });
    expect(verifyWithSuite(PURE, { lessCat1Pub: art.pq_pk }, utf8('other'), art)).toBe(false);
  }, 60_000);

  it('hybrid requires BOTH halves: tamper each, drop each, wrong keys', () => {
    const art = signSuiteArtifact(HYBRID, { edSecret: ED.secretKey, lessCat1: K }, MSG);
    const keys = { edPub: b64u(ED.publicKey), lessCat1Pub: art.pq_pk };
    expect(art.sig.length).toBe(86); // 64-byte ed25519
    expect(verifyWithSuite(HYBRID, keys, MSG, art)).toBe(true);
    expect(verifyWithSuite(HYBRID, keys, MSG, { sig: flip(art.sig), pq_sig: art.pq_sig })).toBe(false); // ed half
    expect(verifyWithSuite(HYBRID, keys, MSG, { sig: art.sig, pq_sig: flip(art.pq_sig!, 100) })).toBe(false); // LESS half
    expect(verifyWithSuite(HYBRID, keys, MSG, { sig: art.sig })).toBe(false);
    expect(verifyWithSuite(HYBRID, keys, MSG, { pq_sig: art.pq_sig })).toBe(false);
    expect(verifyWithSuite(HYBRID, { ...keys, edPub: b64u(generateKeyPair().publicKey) }, MSG, art)).toBe(false);
    expect(verifyWithSuite(HYBRID, { ...keys, lessCat1Pub: encodeLessPublicKey(K2.publicKey) }, MSG, art)).toBe(false);
    expect(verifyWithSuite(HYBRID, { ...keys, lessCat1Pub: undefined }, MSG, art)).toBe(false);
  }, 120_000);

  it('signers fail loudly on missing key material', () => {
    expect(() => signWithSuite(PURE, {}, MSG)).toThrow(TypeError);
    expect(() => signWithSuite(HYBRID, { lessCat1: K }, MSG)).toThrow(/edSecret/);
    expect(() => signWithSuite(HYBRID, { edSecret: ED.secretKey }, MSG)).toThrow(/lessCat1/);
    expect(() => lessCat1Keygen(new Uint8Array(5))).toThrow(RangeError);
  });
});

describe('wire validation (variable-length LESS signature)', () => {
  const art = () => signSuiteArtifact(PURE, { lessCat1: K }, MSG);
  const hyb = () => signSuiteArtifact(HYBRID, { edSecret: ED.secretKey, lessCat1: K }, MSG);
  it('well-formed pure and hybrid artifacts validate', () => {
    expect(validateSignatureWire({ ...art() })).toBeNull();
    expect(validateSignatureWire({ ...hyb() })).toBeNull();
  });
  it('rejects stray / missing / mis-sized components', () => {
    const a = art();
    const h = hyb();
    expect(validateSignatureWire({ ...a, pq_sig: a.sig })).not.toBeNull(); // pure forbids pq_sig
    expect(validateSignatureWire({ alg: PURE, sig: a.sig })).not.toBeNull(); // missing pq_pk
    expect(validateSignatureWire({ ...a, pq_pk: b64u(K.publicKey.subarray(1)) })).not.toBeNull();
    const raw = unb64u(a.sig);
    expect(validateSignatureWire({ ...a, sig: b64u(raw.subarray(0, raw.length - 1)) })).not.toBeNull(); // off-grid
    expect(validateSignatureWire({ ...a, sig: b64u(new Uint8Array(LESS_CAT1_SIGNATURE_MIN_BYTES - 16)) })).not.toBeNull(); // too short
    expect(validateSignatureWire({ ...a, sig: b64u(new Uint8Array(LESS_CAT1_SIGNATURE_MAX_BYTES + 16)) })).not.toBeNull(); // too long
    expect(validateSignatureWire({ ...a, sig: b64u(new Uint8Array(LESS_CAT1_SIGNATURE_MIN_BYTES)) + '=' })).not.toBeNull(); // non-canonical
    const { pq_sig, ...noPq } = h;
    void pq_sig;
    expect(validateSignatureWire({ ...noPq })).not.toBeNull(); // hybrid needs pq_sig
    expect(validateSignatureWire({ ...h, sig: h.pq_sig })).not.toBeNull(); // ed half must be 64 bytes
  });
});

// -- a real PCActn ---------------------------------------------------------------------------------
function pcactnFixture() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const root = mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(A.publicKey), caveats: [{ type: 'ttl', secs: 60 }] });
  const plan = [
    { id: 'n1', verb: 'read', resource: 'db/users' },
    { id: 'n2', verb: 'write', resource: 'db/orders', params_digest: paramsDigest({ qty: 3 }), reversibility_class: 'reversible' },
  ];
  const base = buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan, nodeId: 'n2', params: { qty: 3 }, counter: 7, signerSecret: A.secretKey });
  const { sig: _s, ...body } = base;
  void _s;
  return { root, agent: A, body };
}
const ctx = (root: Capability) => ({ grant: root, nowEpoch: NOW, audience: AUD });

describe('a real PCActn signed with the LESS suites, end to end through verifyPCActnCore', () => {
  it('pure less-cat1: allowed; corrupted sig fails; stripped alg is a wire failure', async () => {
    const { body, root } = pcactnFixture();
    const p = signPCActnSuite(body, { alg: PURE, lessCat1: K });
    expect(p.alg).toBe(PURE);
    expect('pq_sig' in p).toBe(false);
    expect(validateWireV2(p)).toBeNull();
    const r = await verifyPCActnCore(p, ctx(root));
    expect(r.allow).toBe(true);
    expect(r.checks.leaf_signature).toBe('pass');
    const r2 = await verifyPCActnCore({ ...p, sig: flip(p.sig, 50) }, ctx(root));
    expect(r2.checks.leaf_signature).toBe('fail');
    const { alg: _a, ...stripped } = p;
    void _a;
    const r3 = await verifyPCActnCore(stripped as PCActn, ctx(root));
    expect(r3.allow).toBe(false);
    expect(r3.checks.wire).toBe('fail');
  }, 120_000);

  it('hybrid: allowed; each half tampered => fail; dropped pq_sig => wire failure', async () => {
    const { body, root, agent } = pcactnFixture();
    const p = signPCActnSuite(body, { alg: HYBRID, edLeafSecret: agent.secretKey, lessCat1: K });
    expect(p.alg).toBe(HYBRID);
    expect(validateWireV2(p)).toBeNull();
    const ok = await verifyPCActnCore(p, ctx(root));
    expect(ok.allow).toBe(true);
    expect(ok.checks.leaf_signature).toBe('pass');
    const edBad = await verifyPCActnCore({ ...p, sig: flip(p.sig) }, ctx(root));
    expect(edBad.allow).toBe(false);
    expect(edBad.checks.leaf_signature).toBe('fail');
    const lessBad = await verifyPCActnCore({ ...p, pq_sig: flip(p.pq_sig!, 200) }, ctx(root));
    expect(lessBad.allow).toBe(false);
    expect(lessBad.checks.leaf_signature).toBe('fail');
    const { pq_sig: _q, ...dropped } = p;
    void _q;
    const r = await verifyPCActnCore(dropped as PCActn, ctx(root));
    expect(r.allow).toBe(false);
    expect(r.checks.wire).toBe('fail');
  }, 180_000);

  it('verifyLeafSuite dispatches on alg; a swapped pq_pk (key substitution) fails', () => {
    const { body, root, agent } = pcactnFixture();
    const p = signPCActnSuite(body, { alg: HYBRID, edLeafSecret: agent.secretKey, lessCat1: K });
    const msg = thresholdMessage(p);
    expect(verifyLeafSuite({ alg: p.alg, holder: root.holder, pqPublicKey: p.pq_pk, message: msg, sig: p.sig, pqSig: p.pq_sig })).toBe(true);
    expect(verifyLeafSuite({ alg: p.alg, holder: root.holder, pqPublicKey: encodeLessPublicKey(K2.publicKey), message: msg, sig: p.sig, pqSig: p.pq_sig })).toBe(false);
  }, 60_000);
});

describe('a capability chain whose hops are signed with LESS', () => {
  it('hybrid root (principal) + pure-LESS delegation verify; tampering any part fails', () => {
    const P = generateKeyPair();
    const A = generateKeyPair();
    const B = generateKeyPair();
    const root = mintRoot({
      principalSecret: P.secretKey,
      principalPublic: b64u(P.publicKey),
      holder: b64u(A.publicKey),
      caveats: [{ type: 'ttl', secs: 60 }],
      suite: { alg: HYBRID, lessCat1: K },
    });
    expect(root.alg).toBe(HYBRID);
    const hop = delegate(root, b64u(B.publicKey), [{ type: 'ttl', secs: 30 }], A.secretKey, { alg: PURE, lessCat1: K2 });
    expect(hop.alg).toBe(PURE);
    expect(verifyChain([root, hop]).ok).toBe(true);
    expect(verifyChain([{ ...root, pq_sig: flip(root.pq_sig!, 10) }, hop]).ok).toBe(false);
    expect(verifyChain([{ ...root, sig: flip(root.sig) }, hop]).ok).toBe(false);
    expect(verifyChain([root, { ...hop, sig: flip(hop.sig, 99) }]).ok).toBe(false);
    expect(verifyChain([root, { ...hop, pq_pk: encodeLessPublicKey(K.publicKey) }]).ok).toBe(false); // key swap
  }, 180_000);
});

describe('the optional backend is ABSENT or BROKEN: LESS suites are unsupported and fail closed', () => {
  it('missing package: status carries a clear reason; verify denies; signing throws; other suites unaffected', async () => {
    const { body, root, agent } = pcactnFixture();
    const p = signPCActnSuite(body, { alg: HYBRID, edLeafSecret: agent.secretKey, lessCat1: K });
    const art = signSuiteArtifact(PURE, { lessCat1: K }, MSG);
    const h = signSuiteArtifact(HYBRID, { edSecret: ED.secretKey, lessCat1: K }, MSG);
    const validSig = lessCat1Sign(K.secretKey, MSG, seed(9));
    expect(lessCat1Verify(K.publicKey, MSG, validSig)).toBe(true);
    const lessRoot = mintRoot({ principalSecret: ED.secretKey, principalPublic: b64u(ED.publicKey), holder: 'h', caveats: [], suite: { alg: PURE, lessCat1: K } });
    expect(verifyChain([lessRoot]).ok).toBe(true);

    setLessBackendLoaderForTests(() => {
      throw new Error("Cannot find module '@atlasauth/pca-less-wasm'");
    });
    expect(isLessBackendActive()).toBe(false);
    const st = lessBackendStatus();
    expect(st.available).toBe(false);
    expect(st.reason).toMatch(/not installed|failed to load|unusable/);
    // a perfectly valid artifact is DENIED, never accepted
    expect(verifyWithSuite(PURE, { lessCat1Pub: art.pq_pk }, MSG, art)).toBe(false);
    expect(lessCat1Verify(K.publicKey, MSG, validSig)).toBe(false); // genuinely valid, still denied
    const r = await verifyPCActnCore(p, ctx(root));
    expect(r.allow).toBe(false);
    expect(r.checks.leaf_signature).toBe('fail');
    expect(verifyChain([lessRoot]).ok).toBe(false); // a valid LESS-signed hop is denied while the backend is absent
    // sign / keygen refuse rather than silently no-op
    expect(() => lessCat1Keygen(seed(1))).toThrow(/unsupported/);
    expect(() => signWithSuite(PURE, { lessCat1: K }, MSG)).toThrow(/unsupported/);
    // classical + other PQ suites are untouched
    const ed = signWithSuite('ed25519', { edSecret: ED.secretKey }, MSG);
    expect(verifyWithSuite('ed25519', { edPub: b64u(ED.publicKey) }, MSG, ed)).toBe(true);
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(5));
    const mlArt = signSuiteArtifact('ml-dsa-65', { mlDsa: ml }, MSG);
    expect(verifyWithSuite('ml-dsa-65', { mlDsaPub: mlArt.pq_pk }, MSG, mlArt)).toBe(true);
    // and the hybrid with a VALID ed25519 half still denies when LESS is unavailable
    expect(verifyWithSuite(HYBRID, { edPub: b64u(ED.publicKey), lessCat1Pub: h.pq_pk }, MSG, h)).toBe(false);

    setLessBackendLoaderForTests(undefined);
    expect(isLessBackendActive()).toBe(true);
    expect(verifyWithSuite(PURE, { lessCat1Pub: art.pq_pk }, MSG, art)).toBe(true); // recovers
  }, 180_000);

  it('installed-but-unusable module (wasm cannot instantiate / wrong API) is also unsupported', () => {
    setLessBackendLoaderForTests(() => ({ keygen() { throw new Error('x'); }, seedWith() {}, signDetached() { return new Uint8Array(0); }, verify() { throw new Error('WebAssembly.instantiate failed'); } }));
    expect(isLessBackendActive()).toBe(false);
    expect(lessBackendStatus().reason).toMatch(/could not be instantiated/);
    setLessBackendLoaderForTests(() => ({}));
    expect(lessBackendStatus().reason).toMatch(/unusable/);
    setLessBackendLoaderForTests(() => ({ keygen() { return { publicKey: K.publicKey, secretKey: K.secretKey }; }, seedWith() {}, signDetached() { return new Uint8Array(0); }, verify() { return true; } }));
    // a backend that "verifies" everything is only as good as the backend; length gating still precedes it
    expect(lessCat1Verify(K.publicKey, MSG, new Uint8Array(10))).toBe(false);
  });
});

describe('suite-confusion negatives (alg is signed into the body; components are not interchangeable)', () => {
  it('a LESS signature/key presented under ml-dsa / ed25519 / fn-dsa algs (and vice versa) never verifies', () => {
    const less = signSuiteArtifact(PURE, { lessCat1: K }, MSG);
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(8));
    const mlArt = signSuiteArtifact('ml-dsa-65', { mlDsa: ml }, MSG);
    for (const alg of ['ml-dsa-65', 'ml-dsa-87', 'slh-dsa-sha2-128f', 'slh-dsa-sha2-256s', 'fn-dsa-512', 'fn-dsa-1024'] as SigAlg[]) {
      const pk = less.pq_pk;
      expect(verifyWithSuite(alg, { mlDsaPub: pk, mlDsa87Pub: pk, slhDsaPub: pk, slhDsa256sPub: pk, fnDsa512Pub: pk, fnDsa1024Pub: pk }, MSG, { sig: less.sig }), alg).toBe(false);
    }
    expect(verifyWithSuite('ed25519', { edPub: b64u(ED.publicKey) }, MSG, { sig: less.sig })).toBe(false);
    expect(verifyWithSuite(PURE, { lessCat1Pub: mlArt.pq_pk }, MSG, { sig: mlArt.sig })).toBe(false); // ml-dsa under less
    const edSig = signWithSuite('ed25519', { edSecret: ED.secretKey }, MSG);
    expect(verifyWithSuite(PURE, { lessCat1Pub: less.pq_pk }, MSG, edSig)).toBe(false);
    expect(verifyWithSuite(HYBRID, { edPub: b64u(ED.publicKey), lessCat1Pub: less.pq_pk }, MSG, { sig: edSig.sig, pq_sig: mlArt.sig })).toBe(false);
  }, 120_000);

  it('rewriting `alg` on a signed PCActn / capability (hybrid-less <-> hybrid-ml-dsa, less <-> ed25519) is rejected', async () => {
    const { body, root, agent } = pcactnFixture();
    const p = signPCActnSuite(body, { alg: HYBRID, edLeafSecret: agent.secretKey, lessCat1: K });
    for (const alg of ['hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'hybrid-ed25519-slh-dsa-sha2-128f', 'ed25519', 'less-cat1'] as SigAlg[]) {
      const forged = { ...p, alg } as PCActn;
      const r = await verifyPCActnCore(forged, ctx(root));
      expect(r.allow, alg).toBe(false);
    }
    const hop = mintRoot({ principalSecret: ED.secretKey, principalPublic: b64u(ED.publicKey), holder: 'h', caveats: [], suite: { alg: PURE, lessCat1: K } });
    expect(verifyChain([hop]).ok).toBe(true);
    expect(verifyChain([{ ...hop, alg: 'ml-dsa-65' }]).ok).toBe(false);
    expect(verifyChain([{ ...hop, alg: HYBRID }]).ok).toBe(false);
    const { alg: _x, pq_pk: _y, ...stripped } = hop;
    void _x; void _y;
    expect(verifyChain([stripped as Capability]).ok).toBe(false);
  }, 180_000);
});
