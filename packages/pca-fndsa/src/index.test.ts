import { afterEach, describe, expect, it } from 'vitest';
import {
  attenuate,
  b64u,
  commitPlan,
  conditionsDigest,
  delegate,
  encodeKey,
  generateKeyPair,
  mintRoot,
  paramsDigest,
  type PCActnBody,
} from '@atlasauth/pca';
import {
  FN_DSA_1024_PUBLIC_KEY_BYTES,
  FN_DSA_1024_SIGNATURE_BYTES,
  FN_DSA_512_PUBLIC_KEY_BYTES,
  FN_DSA_512_SIGNATURE_BYTES,
  FN_DSA_SUITES,
  type FalconBackend,
  type FnDsaArtifactFields,
  NO_FN_DSA_BACKEND_MESSAGE,
  fndsaSign,
  fndsaVerify,
  mockKeypair,
  registerTestBackend,
  resetFalconBackend,
  resolveFnDsaAlg,
  setFalconBackend,
  signPcaWithFndsa,
  verifyPcaFndsa,
} from './index';

afterEach(() => resetFalconBackend());

const u = (s: string): Uint8Array => new TextEncoder().encode(s);

// ---- a real PCActn leaf (body) to sign under FN-DSA -------------------------------------------
const NOW = 1_800_000_000_000;
function buildLeafBody(): PCActnBody {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const S = generateKeyPair();
  const grant = mintRoot({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    caveats: [{ type: 'ttl', secs: 60 }],
  });
  const c1 = attenuate(grant, [{ type: 'x' }], A.secretKey);
  const sub = delegate(c1, encodeKey(S.publicKey), [], A.secretKey);
  const node = { id: 'n1', verb: 'revoke_session', resource: 'sess/1', params_digest: paramsDigest({ a: 1 }), reversibility_class: 'R1', pre: { a: 1 } };
  const plan = commitPlan([node]);
  return {
    ver: 2,
    action: { verb: node.verb, resource: node.resource, params_digest: node.params_digest, reversibility_class: node.reversibility_class },
    grant_ref: grant.id,
    cap_chain: [grant, c1, sub],
    plan: { root: plan.root, inclusion_proof: plan.proofFor(node.id), node_id: node.id, conditions_digest: conditionsDigest(node.pre, undefined) },
    attestation: { quote_digest: 'q', epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
    provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: [] },
    freshness: { beacon_ref: 'b', epoch: 1, accumulator_witness: 'w' },
    counter: 7,
    risk_claim: { r: 0.1, inputs: {} },
    aud: 'rs-1',
    iat: NOW,
    exp: NOW + 60_000,
  };
}

describe('suite registry + sizes', () => {
  it('registers fn-dsa-512 / fn-dsa-1024 with FIPS-206 byte sizes', () => {
    expect(FN_DSA_512_PUBLIC_KEY_BYTES).toBe(897);
    expect(FN_DSA_512_SIGNATURE_BYTES).toBe(666);
    expect(FN_DSA_1024_PUBLIC_KEY_BYTES).toBe(1793);
    expect(FN_DSA_1024_SIGNATURE_BYTES).toBe(1280);
    expect(FN_DSA_SUITES['fn-dsa-512'].sigBytes).toBe(666);
    expect(FN_DSA_SUITES['fn-dsa-512'].pqPkBytes).toBe(897);
    expect(FN_DSA_SUITES['hybrid-ed25519-fn-dsa-1024'].sigBytes).toBe(64); // ed25519 in `sig`
    expect(FN_DSA_SUITES['hybrid-ed25519-fn-dsa-1024'].pqSigBytes).toBe(1280);
  });
});

describe('fndsaSign / fndsaVerify (raw primitive via MOCK backend — wiring only, not Falcon)', () => {
  it('round-trips for fn-dsa-512', () => {
    registerTestBackend();
    const kp = mockKeypair('fn-dsa-512');
    const msg = u('hello falcon 512');
    const sig = fndsaSign('fn-dsa-512', kp.sk, msg);
    expect(sig.length).toBe(666);
    expect(fndsaVerify('fn-dsa-512', kp.pk, msg, sig)).toBe(true);
  });

  it('round-trips for fn-dsa-1024', () => {
    registerTestBackend();
    const kp = mockKeypair('fn-dsa-1024');
    const msg = u('hello falcon 1024');
    const sig = fndsaSign('fn-dsa-1024', kp.sk, msg);
    expect(sig.length).toBe(1280);
    expect(fndsaVerify('fn-dsa-1024', kp.pk, msg, sig)).toBe(true);
  });

  it('a tampered message or signature fails', () => {
    registerTestBackend();
    const kp = mockKeypair('fn-dsa-512');
    const msg = u('authentic');
    const sig = fndsaSign('fn-dsa-512', kp.sk, msg);
    expect(fndsaVerify('fn-dsa-512', kp.pk, u('tampered'), sig)).toBe(false);
    const badSig = sig.slice();
    badSig[0] = (badSig[0] ?? 0) ^ 0xff;
    expect(fndsaVerify('fn-dsa-512', kp.pk, msg, badSig)).toBe(false);
  });
});

describe('length guard runs BEFORE the backend', () => {
  it('rejects a wrong-length public key without calling the backend', () => {
    // A tripwire backend throws if ever reached; a length-rejected input must return false, not throw.
    const tripwire: FalconBackend = { verify: () => { throw new Error('backend must not be reached'); } };
    setFalconBackend(tripwire);
    const shortPk = new Uint8Array(896); // one byte short of 897
    const sig = new Uint8Array(666);
    expect(fndsaVerify('fn-dsa-512', shortPk, u('m'), sig)).toBe(false);
  });

  it('rejects a wrong-length signature without calling the backend', () => {
    const tripwire: FalconBackend = { verify: () => { throw new Error('backend must not be reached'); } };
    setFalconBackend(tripwire);
    const pk = new Uint8Array(897);
    const shortSig = new Uint8Array(665); // one byte short of 666
    expect(fndsaVerify('fn-dsa-512', pk, u('m'), shortSig)).toBe(false);
  });
});

describe('default (unregistered) backend fails loud', () => {
  it('fndsaVerify throws the clear error once lengths pass', () => {
    resetFalconBackend();
    const pk = new Uint8Array(897);
    const sig = new Uint8Array(666);
    expect(() => fndsaVerify('fn-dsa-512', pk, u('m'), sig)).toThrow(NO_FN_DSA_BACKEND_MESSAGE);
  });

  it('fndsaSign throws the clear error', () => {
    resetFalconBackend();
    expect(() => fndsaSign('fn-dsa-512', new Uint8Array([1, 2, 3]), u('m'))).toThrow(NO_FN_DSA_BACKEND_MESSAGE);
  });
});

describe('signPcaWithFndsa / verifyPcaFndsa — a real PCActn leaf, MOCK backend (plumbing only; see real-backend.test.ts for the real wasm)', () => {
  for (const alg of ['fn-dsa-512', 'fn-dsa-1024'] as const) {
    it(`round-trips ${alg}`, () => {
      registerTestBackend();
      const leaf = buildLeafBody();
      const kp = mockKeypair(FN_DSA_SUITES[alg].variant);
      const fields = signPcaWithFndsa({ alg, leaf, fnDsa: kp });
      expect(fields.alg).toBe(alg);
      expect(fields.pq_pk).toBe(b64u(kp.pk));
      expect(fields.pq_sig).toBeUndefined();
      expect(verifyPcaFndsa({ alg: fields.alg, leaf, pq_pk: fields.pq_pk, sig: fields.sig })).toBe(true);
    });
  }

  it('a tampered action fails (thresholdMessage changes)', () => {
    registerTestBackend();
    const leaf = buildLeafBody();
    const kp = mockKeypair('fn-dsa-512');
    const fields = signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp });
    const tampered: PCActnBody = { ...leaf, action: { ...leaf.action, resource: 'sess/ALL' } };
    expect(verifyPcaFndsa({ alg: fields.alg, leaf: tampered, pq_pk: fields.pq_pk, sig: fields.sig })).toBe(false);
  });

  it('a tampered signature fails', () => {
    registerTestBackend();
    const leaf = buildLeafBody();
    const kp = mockKeypair('fn-dsa-512');
    const fields = signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp });
    const badSigBytes = (FN_DSA_SUITES['fn-dsa-512'].sigBytes);
    const flipped = new Uint8Array(badSigBytes); // all-zero sig of correct length
    expect(verifyPcaFndsa({ alg: fields.alg, leaf, pq_pk: fields.pq_pk, sig: b64u(flipped) })).toBe(false);
  });

  it('a swapped pq_pk fails (downgrade/key-swap binding)', () => {
    registerTestBackend();
    const leaf = buildLeafBody();
    const kp = mockKeypair('fn-dsa-512', 'A');
    const other = mockKeypair('fn-dsa-512', 'B');
    const fields = signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp });
    // Present someone else's key: both the binding suffix AND the verification key no longer match.
    expect(verifyPcaFndsa({ alg: fields.alg, leaf, pq_pk: b64u(other.pk), sig: fields.sig })).toBe(false);
  });

  it('a wrong-length pq_pk is rejected before the backend', () => {
    const tripwire: FalconBackend = { verify: () => { throw new Error('backend must not be reached'); } };
    setFalconBackend(tripwire);
    const leaf = buildLeafBody();
    const shortPk = b64u(new Uint8Array(896));
    expect(verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk: shortPk, sig: b64u(new Uint8Array(666)) })).toBe(false);
  });

  it('an unknown alg fails closed', () => {
    registerTestBackend();
    const leaf = buildLeafBody();
    expect(verifyPcaFndsa({ alg: 'fn-dsa-9000', leaf, pq_pk: 'x', sig: 'y' })).toBe(false);
  });
});

describe('hybrid ed25519 + fn-dsa requires BOTH (MOCK backend plumbing)', () => {
  function signHybrid(): { leaf: PCActnBody; holder: string; fields: FnDsaArtifactFields } {
    registerTestBackend();
    const leaf = buildLeafBody();
    const ed = generateKeyPair();
    const kp = mockKeypair('fn-dsa-512');
    const fields = signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, fnDsa: kp, edSecret: ed.secretKey });
    return { leaf, holder: encodeKey(ed.publicKey), fields };
  }

  it('verifies when both halves are valid', () => {
    const { leaf, holder, fields } = signHybrid();
    expect(fields.pq_sig).toBeDefined();
    expect(verifyPcaFndsa({ alg: fields.alg, leaf, holder, pq_pk: fields.pq_pk, sig: fields.sig, pq_sig: fields.pq_sig })).toBe(true);
  });

  it('fails if the ed25519 half is wrong (wrong holder)', () => {
    const { leaf, fields } = signHybrid();
    const wrongHolder = encodeKey(generateKeyPair().publicKey);
    expect(verifyPcaFndsa({ alg: fields.alg, leaf, holder: wrongHolder, pq_pk: fields.pq_pk, sig: fields.sig, pq_sig: fields.pq_sig })).toBe(false);
  });

  it('fails if the fn-dsa half is missing', () => {
    const { leaf, holder, fields } = signHybrid();
    expect(verifyPcaFndsa({ alg: fields.alg, leaf, holder, pq_pk: fields.pq_pk, sig: fields.sig })).toBe(false);
  });

  it('fails if the fn-dsa half is tampered', () => {
    const { leaf, holder, fields } = signHybrid();
    const badPq = b64u(new Uint8Array(666));
    expect(verifyPcaFndsa({ alg: fields.alg, leaf, holder, pq_pk: fields.pq_pk, sig: fields.sig, pq_sig: badPq })).toBe(false);
  });

  it('signing a hybrid suite without edSecret throws', () => {
    registerTestBackend();
    const leaf = buildLeafBody();
    const kp = mockKeypair('fn-dsa-512');
    expect(() => signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, fnDsa: kp })).toThrow(/requires edSecret/);
  });
});

// ---- audit-readiness: the fail-closed table of the README, one exact outcome per row -----------------
describe('fail-closed table: malformed wire input is rejected before the backend and never throws', () => {
  const tripwire: FalconBackend = { verify: () => { throw new Error('backend must not be reached'); } };
  const pkOk = b64u(new Uint8Array(FN_DSA_512_PUBLIC_KEY_BYTES));
  const sigOk = b64u(new Uint8Array(FN_DSA_512_SIGNATURE_BYTES));

  it('non-canonical base64url (padding, standard alphabet, whitespace, trailing junk) in pq_pk or sig -> false', () => {
    setFalconBackend(tripwire);
    const leaf = buildLeafBody();
    const bad = (x: string) => [x + '=', x.replace(/./, '+'), ' ' + x, x + '!'];
    for (const pk of bad(pkOk)) expect(verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk: pk, sig: sigOk })).toBe(false);
    for (const sig of bad(sigOk)) expect(verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk: pkOk, sig })).toBe(false);
  });

  it('wrong type for alg, pq_pk, sig, pq_sig or holder -> false', () => {
    setFalconBackend(tripwire);
    const leaf = buildLeafBody();
    for (const v of [undefined, null, 5, {}, []]) {
      expect(verifyPcaFndsa({ alg: v, leaf, pq_pk: pkOk, sig: sigOk })).toBe(false);
      expect(verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk: v, sig: sigOk })).toBe(false);
      expect(verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk: pkOk, sig: v })).toBe(false);
      expect(verifyPcaFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, holder: v, pq_pk: pkOk, sig: b64u(new Uint8Array(64)), pq_sig: sigOk })).toBe(false);
      expect(verifyPcaFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, holder: encodeKey(generateKeyPair().publicKey), pq_pk: pkOk, sig: b64u(new Uint8Array(64)), pq_sig: v })).toBe(false);
    }
  });

  it('hybrid with a short Ed25519 half or a short FN-DSA half -> false, backend not reached', () => {
    setFalconBackend(tripwire);
    const leaf = buildLeafBody();
    const holder = encodeKey(generateKeyPair().publicKey);
    expect(verifyPcaFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, holder, pq_pk: pkOk, sig: b64u(new Uint8Array(63)), pq_sig: sigOk })).toBe(false);
    expect(verifyPcaFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, holder, pq_pk: pkOk, sig: b64u(new Uint8Array(64)), pq_sig: b64u(new Uint8Array(665)) })).toBe(false);
  });

  it('a 512 signature or key under a 1024 suite (and the reverse) -> false', () => {
    setFalconBackend(tripwire);
    const leaf = buildLeafBody();
    expect(verifyPcaFndsa({ alg: 'fn-dsa-1024', leaf, pq_pk: pkOk, sig: sigOk })).toBe(false);
    expect(verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk: b64u(new Uint8Array(FN_DSA_1024_PUBLIC_KEY_BYTES)), sig: b64u(new Uint8Array(FN_DSA_1024_SIGNATURE_BYTES)) })).toBe(false);
  });

  it('suite names that are inherited object keys do not resolve', () => {
    for (const k of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'FN-DSA-512', ' fn-dsa-512']) {
      expect(resolveFnDsaAlg(k)).toBeNull();
    }
  });

  it('raw primitive: unknown variant or non-bytes -> false (verify) or a typed throw (sign), never a backend call', () => {
    setFalconBackend(tripwire);
    const pk = new Uint8Array(FN_DSA_512_PUBLIC_KEY_BYTES);
    const sig = new Uint8Array(FN_DSA_512_SIGNATURE_BYTES);
    expect(fndsaVerify('fn-dsa-256' as never, pk, u('m'), sig)).toBe(false);
    expect(fndsaVerify('fn-dsa-512', Array.from(pk) as never, u('m'), sig)).toBe(false);
    expect(fndsaVerify('fn-dsa-512', pk, 'm' as never, sig)).toBe(false);
    expect(() => fndsaSign('fn-dsa-256' as never, new Uint8Array(4), u('m'))).toThrow(RangeError);
    expect(() => fndsaSign('fn-dsa-512', new Uint8Array(0), u('m'))).toThrow(TypeError);
    expect(() => fndsaSign('fn-dsa-512', new Uint8Array(4), 'm' as never)).toThrow(TypeError);
  });
});

describe('fail-closed table: backend faults', () => {
  it('no backend registered -> verification and signing throw the "no FN-DSA backend" error (loud, never true)', () => {
    const leaf = buildLeafBody();
    const pq_pk = b64u(new Uint8Array(FN_DSA_512_PUBLIC_KEY_BYTES));
    const sig = b64u(new Uint8Array(FN_DSA_512_SIGNATURE_BYTES));
    expect(() => verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk, sig })).toThrow(NO_FN_DSA_BACKEND_MESSAGE);
    expect(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: mockKeypair('fn-dsa-512') })).toThrow(NO_FN_DSA_BACKEND_MESSAGE);
  });

  it('verify-only backend -> signing throws; a backend returning a short or non-byte signature -> signing throws', () => {
    const leaf = buildLeafBody();
    const kp = mockKeypair('fn-dsa-512');
    setFalconBackend({ verify: () => true });
    expect(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp })).toThrow(/verify-only/);
    setFalconBackend({ verify: () => true, sign: () => new Uint8Array(665) });
    expect(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp })).toThrow(/expected padded 666 bytes/);
    setFalconBackend({ verify: () => true, sign: () => 'sig' as never });
    expect(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp })).toThrow(/non-byte signature/);
  });

  it('signing with a key of the wrong length for the suite, or an empty secret -> typed throw', () => {
    registerTestBackend();
    const leaf = buildLeafBody();
    expect(() => signPcaWithFndsa({ alg: 'fn-dsa-1024', leaf, fnDsa: mockKeypair('fn-dsa-512') })).toThrow(/1793-byte FN-DSA public key/);
    expect(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: { pk: mockKeypair('fn-dsa-512').pk, sk: new Uint8Array(0) } })).toThrow(/secret-key material/);
    expect(() => signPcaWithFndsa({ alg: 'nope' as never, leaf, fnDsa: mockKeypair('fn-dsa-512') })).toThrow(RangeError);
  });

  it('a backend that returns false is a rejection', () => {
    registerTestBackend();
    const leaf = buildLeafBody();
    const kp = mockKeypair('fn-dsa-512');
    const f = signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp });
    expect(verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk: f.pq_pk, sig: f.sig })).toBe(true);
    setFalconBackend({ verify: () => false });
    expect(verifyPcaFndsa({ alg: 'fn-dsa-512', leaf, pq_pk: f.pq_pk, sig: f.sig })).toBe(false);
  });
});
