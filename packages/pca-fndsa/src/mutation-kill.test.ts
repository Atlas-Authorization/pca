/** Mutation-kill tests for pca-fndsa: every guard, message, byte layout and mock-backend branch. */
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
  sha256,
  thresholdMessage,
  type PCActnBody,
} from '@atlasauth/pca';
import {
  FN_DSA_LEAF_DOMAIN,
  FN_DSA_SUITES,
  type FalconBackend,
  NO_FN_DSA_BACKEND_MESSAGE,
  fndsaLeafMessage,
  fndsaSign,
  fndsaVerify,
  getFalconBackend,
  hashKat,
  isFnDsaVariant,
  isKnownFnDsaAlg,
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
const cat = (...p: Uint8Array[]): Uint8Array => {
  const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0));
  let off = 0;
  for (const x of p) { o.set(x, off); off += x.length; }
  return o;
};
const be32 = (n: number): Uint8Array => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const SK_TAG = u('atlas-pca/fn-dsa/mock-sk/v1\0');

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


/** A spy backend: counts verify calls and returns a fixed verdict. */
function spy(verdict = true, over: Partial<FalconBackend> = {}) {
  const calls: unknown[][] = [];
  const be: FalconBackend = { verify: (...a) => { calls.push(a); return verdict; }, ...over };
  setFalconBackend(be);
  return { calls, be };
}
const rejects = (f: () => unknown, ctor: new (...a: never[]) => Error, msg: string | RegExp) => {
  let err: unknown;
  try { f(); } catch (e) { err = e; }
  expect(err).toBeInstanceOf(ctor);
  expect((err as Error).constructor).toBe(ctor);
  if (typeof msg === 'string') expect((err as Error).message).toBe(msg); else expect((err as Error).message).toMatch(msg);
};

describe('registry predicates', () => {
  it('isKnownFnDsaAlg / resolveFnDsaAlg accept only real string keys', () => {
    expect(isKnownFnDsaAlg('fn-dsa-512')).toBe(true);
    expect(isKnownFnDsaAlg('hybrid-ed25519-fn-dsa-1024')).toBe(true);
    expect(isKnownFnDsaAlg('toString')).toBe(false);
    expect(isKnownFnDsaAlg(512)).toBe(false);
    // a non-string that coerces to a registered name must NOT be accepted
    const sneaky = { toString: () => 'fn-dsa-512' };
    expect(isKnownFnDsaAlg(sneaky)).toBe(false);
    expect(resolveFnDsaAlg(sneaky)).toBeNull();
    expect(resolveFnDsaAlg('nope')).toBeNull();
    expect(resolveFnDsaAlg('fn-dsa-1024')).toBe(FN_DSA_SUITES['fn-dsa-1024']);
  });
  it('isFnDsaVariant accepts exactly the two pure variants', () => {
    expect(isFnDsaVariant('fn-dsa-512')).toBe(true);
    expect(isFnDsaVariant('fn-dsa-1024')).toBe(true);
    expect(isFnDsaVariant('hybrid-ed25519-fn-dsa-512')).toBe(false);
    expect(isFnDsaVariant('x')).toBe(false);
    expect(isFnDsaVariant(undefined)).toBe(false);
  });
  it('FN_DSA_SUITES is frozen with exact per-suite fields', () => {
    expect(Object.isFrozen(FN_DSA_SUITES)).toBe(true);
    expect(FN_DSA_SUITES['fn-dsa-1024']).toEqual({ alg: 'fn-dsa-1024', variant: 'fn-dsa-1024', hasEd25519: false, sigBytes: 1280, needsPqPk: true, pqPkBytes: 1793, needsPqSig: false, pqSigBytes: 0, fnSigBytes: 1280 });
    expect(FN_DSA_SUITES['hybrid-ed25519-fn-dsa-512']).toEqual({ alg: 'hybrid-ed25519-fn-dsa-512', variant: 'fn-dsa-512', hasEd25519: true, sigBytes: 64, needsPqPk: true, pqPkBytes: 897, needsPqSig: true, pqSigBytes: 666, fnSigBytes: 666 });
  });
});

describe('backend seam', () => {
  it('default backend throws the exact message from every entry; get/set/reset round-trip', () => {
    const d = getFalconBackend();
    expect(Object.isFrozen(d)).toBe(true);
    for (const f of [() => d.verify(new Uint8Array(), new Uint8Array(), new Uint8Array()), () => d.sign!(new Uint8Array(), new Uint8Array()), () => d.keygen!()]) rejects(f, Error, NO_FN_DSA_BACKEND_MESSAGE);
    const mine: FalconBackend = { verify: () => true };
    setFalconBackend(mine);
    expect(getFalconBackend()).toBe(mine);
    resetFalconBackend();
    expect(getFalconBackend()).toBe(d);
  });
});

describe('fndsaSign guards', () => {
  const sk = new Uint8Array([1, 2, 3]);
  const m = new Uint8Array([9]);
  it('unknown variant -> RangeError (before touching the backend)', () => {
    const s = spy(true, { sign: () => { throw new Error('should not be called'); } });
    rejects(() => fndsaSign('fn-dsa-256' as never, sk, m), RangeError, "fndsaSign: unknown FN-DSA variant 'fn-dsa-256'");
    expect(s.calls.length).toBe(0);
  });
  it('secret key must be a non-empty Uint8Array', () => {
    spy(true, { sign: () => new Uint8Array(666) });
    const msg = 'fndsaSign: secret key must be a non-empty Uint8Array';
    rejects(() => fndsaSign('fn-dsa-512', new Uint8Array(0), m), TypeError, msg);
    rejects(() => fndsaSign('fn-dsa-512', [1, 2] as never, m), TypeError, msg);
    rejects(() => fndsaSign('fn-dsa-512', 'abc' as never, m), TypeError, msg);
    expect(fndsaSign('fn-dsa-512', sk, m).length).toBe(666);
  });
  it('message must be a Uint8Array', () => {
    spy(true, { sign: () => new Uint8Array(666) });
    rejects(() => fndsaSign('fn-dsa-512', sk, [1] as never), TypeError, 'fndsaSign: message must be a Uint8Array');
    expect(fndsaSign('fn-dsa-512', sk, new Uint8Array(0)).length).toBe(666);
  });
  it('verify-only backend -> clear error', () => {
    spy(true);
    rejects(() => fndsaSign('fn-dsa-512', sk, m), Error, 'fndsaSign: FN-DSA backend is verify-only (no sign())');
  });
  it('backend signature must be a Uint8Array of the padded length (messages name the problem)', () => {
    let out: unknown;
    spy(true, { sign: () => out as Uint8Array });
    out = new Uint8Array(665);
    rejects(() => fndsaSign('fn-dsa-512', sk, m), Error, "fndsaSign: FN-DSA backend returned a 665 signature; expected padded 666 bytes for 'fn-dsa-512'");
    out = new Uint8Array(667);
    rejects(() => fndsaSign('fn-dsa-512', sk, m), Error, /returned a 667 signature/);
    out = new Uint8Array(666); // 512-length from a 1024 call
    rejects(() => fndsaSign('fn-dsa-1024', sk, m), Error, "fndsaSign: FN-DSA backend returned a 666 signature; expected padded 1280 bytes for 'fn-dsa-1024'");
    out = new Array(666).fill(0);
    rejects(() => fndsaSign('fn-dsa-512', sk, m), Error, "fndsaSign: FN-DSA backend returned a non-byte signature; expected padded 666 bytes for 'fn-dsa-512'");
    out = new Uint8Array(666).fill(5);
    const r = fndsaSign('fn-dsa-512', sk, m);
    expect(r).toBe(out);
  });
  it('passes sk and msg to the backend unchanged', () => {
    let seen: Uint8Array[] = [];
    spy(true, { sign: (a, b) => { seen = [a, b]; return new Uint8Array(1280); } });
    fndsaSign('fn-dsa-1024', sk, m);
    expect(seen[0]).toBe(sk);
    expect(seen[1]).toBe(m);
  });
});

describe('fndsaVerify guards', () => {
  const pk5 = new Uint8Array(897), sg5 = new Uint8Array(666), msg = new Uint8Array([1]);
  it('bad variant / pk / sig / msg => false and the backend is never called', () => {
    const s = spy(true);
    expect(fndsaVerify('x' as never, pk5, msg, sg5)).toBe(false);
    expect(fndsaVerify('fn-dsa-512', new Uint8Array(896), msg, sg5)).toBe(false);
    expect(fndsaVerify('fn-dsa-512', new Array(897).fill(0) as never, msg, sg5)).toBe(false);
    expect(fndsaVerify('fn-dsa-512', pk5, msg, new Uint8Array(665))).toBe(false);
    expect(fndsaVerify('fn-dsa-512', pk5, msg, new Array(666).fill(0) as never)).toBe(false);
    expect(fndsaVerify('fn-dsa-512', pk5, 'str' as never, sg5)).toBe(false);
    expect(fndsaVerify('fn-dsa-512', new Uint8Array(1793), msg, sg5)).toBe(false); // 1024 key under 512
    expect(fndsaVerify('fn-dsa-1024', pk5, msg, new Uint8Array(1280))).toBe(false);
    expect(s.calls.length).toBe(0);
  });
  it('valid shapes reach the backend with the same objects and return its verdict', () => {
    const s = spy(true);
    expect(fndsaVerify('fn-dsa-512', pk5, msg, sg5)).toBe(true);
    expect(s.calls[0]).toEqual([pk5, msg, sg5]);
    expect(s.calls[0]![1]).toBe(msg);
    spy(false);
    expect(fndsaVerify('fn-dsa-512', pk5, msg, sg5)).toBe(false);
    expect(fndsaVerify('fn-dsa-1024', new Uint8Array(1793), msg, new Uint8Array(1280))).toBe(false);
    spy(true);
    expect(fndsaVerify('fn-dsa-1024', new Uint8Array(1793), msg, new Uint8Array(1280))).toBe(true);
  });
  it('backend exceptions are not swallowed', () => {
    setFalconBackend({ verify: () => { throw new Error('boom'); } });
    rejects(() => fndsaVerify('fn-dsa-512', pk5, msg, sg5), Error, 'boom');
  });
});

describe('fndsaLeafMessage byte layout', () => {
  it('is thresholdMessage || domain || alg || 0x00 || pq_pk, exactly', () => {
    const leaf = buildLeafBody();
    const got = fndsaLeafMessage(leaf, 'hybrid-ed25519-fn-dsa-512', 'PKPK');
    const want = cat(thresholdMessage(leaf), u(FN_DSA_LEAF_DOMAIN), u('hybrid-ed25519-fn-dsa-512'), new Uint8Array([0]), u('PKPK'));
    expect(Array.from(got)).toEqual(Array.from(want));
    expect(FN_DSA_LEAF_DOMAIN).toBe('atlas-pca/fn-dsa/leaf/v1\0');
  });
});

describe('signPcaWithFndsa guards + output', () => {
  const leaf = buildLeafBody();
  const ed = generateKeyPair();
  it('rejects unknown alg, bad key shapes, with exact messages', () => {
    registerTestBackend();
    const kp = mockKeypair('fn-dsa-512');
    rejects(() => signPcaWithFndsa({ alg: 'fn-dsa-9' as never, leaf, fnDsa: kp }), RangeError, "signPcaWithFndsa: unknown FN-DSA alg 'fn-dsa-9'");
    const pkMsg = "signPcaWithFndsa: 'fn-dsa-512' requires a 897-byte FN-DSA public key";
    rejects(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: undefined as never }), TypeError, pkMsg);
    rejects(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: { pk: new Uint8Array(896), sk: kp.sk } }), TypeError, pkMsg);
    rejects(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: { pk: new Array(897).fill(0) as never, sk: kp.sk } }), TypeError, pkMsg);
    rejects(() => signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-1024', leaf, fnDsa: kp, edSecret: ed.secretKey }), TypeError, "signPcaWithFndsa: 'hybrid-ed25519-fn-dsa-1024' requires a 1793-byte FN-DSA public key");
    const skMsg = "signPcaWithFndsa: 'fn-dsa-512' requires FN-DSA secret-key material";
    rejects(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: { pk: kp.pk, sk: new Uint8Array(0) } }), TypeError, skMsg);
    rejects(() => signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: { pk: kp.pk, sk: [1, 2, 3] as never } }), TypeError, skMsg);
    rejects(() => signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, fnDsa: kp }), TypeError, "signPcaWithFndsa: 'hybrid-ed25519-fn-dsa-512' requires edSecret (Ed25519 leaf-holder secret key)");
    rejects(() => signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, fnDsa: kp, edSecret: 'x' as never }), TypeError, /requires edSecret/);
  });
  it('pure suite output has no pq_sig; sig is the backend signature over the leaf message', () => {
    registerTestBackend();
    const kp = mockKeypair('fn-dsa-1024', 'k');
    const out = signPcaWithFndsa({ alg: 'fn-dsa-1024', leaf, fnDsa: kp, edSecret: ed.secretKey });
    expect(Object.keys(out).sort()).toEqual(['alg', 'pq_pk', 'sig']);
    expect(out.alg).toBe('fn-dsa-1024');
    expect(out.pq_pk).toBe(b64u(kp.pk));
    const msg = fndsaLeafMessage(leaf, 'fn-dsa-1024', out.pq_pk);
    expect(out.sig).toBe(b64u(fndsaSign('fn-dsa-1024', kp.sk, msg)));
  });
  it('hybrid output: Ed25519 sig in sig, FN-DSA sig in pq_sig, both over the same message', () => {
    registerTestBackend();
    const kp = mockKeypair('fn-dsa-512', 'h');
    const out = signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, fnDsa: kp, edSecret: ed.secretKey });
    expect(Object.keys(out).sort()).toEqual(['alg', 'pq_pk', 'pq_sig', 'sig']);
    const msg = fndsaLeafMessage(leaf, 'hybrid-ed25519-fn-dsa-512', out.pq_pk);
    expect(out.pq_sig).toBe(b64u(fndsaSign('fn-dsa-512', kp.sk, msg)));
    expect(out.sig.length).toBe(86);
    expect(verifyPcaFndsa({ ...out, leaf, holder: encodeKey(ed.publicKey) })).toBe(true);
  });
});

describe('verifyPcaFndsa short-circuits', () => {
  const leaf = buildLeafBody();
  const ed = generateKeyPair();
  const holder = encodeKey(ed.publicKey);
  it('pure: unknown alg / bad pq_pk / bad sig never reach the backend', () => {
    const be = registerTestBackend();
    const kp = mockKeypair('fn-dsa-512');
    const good = signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp });
    expect(verifyPcaFndsa({ ...good, leaf })).toBe(true);
    let n = 0;
    const real = be.verify;
    setFalconBackend({ ...be, verify: (...a) => { n++; return real(...a); } });
    expect(verifyPcaFndsa({ ...good, leaf, alg: 'nope' })).toBe(false);
    expect(verifyPcaFndsa({ ...good, leaf, alg: 'hybrid-ed25519-fn-dsa-512' })).toBe(false);
    expect(verifyPcaFndsa({ ...good, leaf, pq_pk: 5 })).toBe(false);
    expect(verifyPcaFndsa({ ...good, leaf, pq_pk: good.pq_pk.slice(1) })).toBe(false);
    expect(verifyPcaFndsa({ ...good, leaf, sig: undefined })).toBe(false);
    expect(verifyPcaFndsa({ ...good, leaf, sig: good.sig.slice(1) })).toBe(false);
    expect(verifyPcaFndsa({ ...good, leaf, sig: 7 })).toBe(false);
    expect(n).toBe(0);
    expect(verifyPcaFndsa({ ...good, leaf })).toBe(true);
    expect(n).toBe(1);
  });
  it('pure: a different alg label or pq_pk changes the signed bytes (binding)', () => {
    registerTestBackend();
    const kp = mockKeypair('fn-dsa-512');
    const good = signPcaWithFndsa({ alg: 'fn-dsa-512', leaf, fnDsa: kp });
    const kp2 = mockKeypair('fn-dsa-512', 'other');
    expect(verifyPcaFndsa({ ...good, leaf, pq_pk: b64u(kp2.pk) })).toBe(false);
    const leaf2 = { ...leaf, counter: 8 };
    expect(verifyPcaFndsa({ ...good, leaf: leaf2 })).toBe(false);
  });
  it('hybrid: every early-out happens before the FN-DSA backend; both halves required', () => {
    const be = registerTestBackend();
    const kp = mockKeypair('fn-dsa-512');
    const good = signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, fnDsa: kp, edSecret: ed.secretKey });
    const base = { ...good, leaf, holder };
    expect(verifyPcaFndsa(base)).toBe(true);
    let n = 0;
    const real = be.verify;
    setFalconBackend({ ...be, verify: (...a) => { n++; return real(...a); } });
    expect(verifyPcaFndsa({ ...base, holder: undefined })).toBe(false);
    expect(verifyPcaFndsa({ ...base, holder: 5 })).toBe(false);
    expect(verifyPcaFndsa({ ...base, sig: undefined })).toBe(false);
    expect(verifyPcaFndsa({ ...base, sig: good.sig.slice(2) })).toBe(false); // wrong ed length
    expect(verifyPcaFndsa({ ...base, pq_sig: undefined })).toBe(false);
    expect(verifyPcaFndsa({ ...base, pq_sig: good.pq_sig!.slice(2) })).toBe(false);
    expect(verifyPcaFndsa({ ...base, pq_sig: 3 })).toBe(false);
    expect(n).toBe(0);
    // each half individually broken
    const other = generateKeyPair();
    expect(verifyPcaFndsa({ ...base, holder: encodeKey(other.publicKey) })).toBe(false);
    expect(n).toBe(1);
    const sigSwapped = signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, fnDsa: mockKeypair('fn-dsa-512', 'z'), edSecret: ed.secretKey });
    expect(verifyPcaFndsa({ ...base, pq_sig: sigSwapped.pq_sig })).toBe(false);
    expect(verifyPcaFndsa({ ...base, pq_sig: b64u(new Uint8Array(666)) })).toBe(false);
    expect(verifyPcaFndsa(base)).toBe(true);
  });
  it('hybrid-1024 uses 1280-byte pq_sig and 64-byte ed sig', () => {
    registerTestBackend();
    const kp = mockKeypair('fn-dsa-1024');
    const good = signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-1024', leaf, fnDsa: kp, edSecret: ed.secretKey });
    expect(verifyPcaFndsa({ ...good, leaf, holder })).toBe(true);
    expect(verifyPcaFndsa({ ...good, leaf, holder, pq_sig: b64u(new Uint8Array(666)) })).toBe(false);
  });
});

describe('hashKat', () => {
  it('is SHA-256 counter mode (big-endian counter), truncating the last block', () => {
    const seed = u('seed');
    for (const len of [0, 1, 31, 32, 33, 64, 100, 666]) {
      const blocks: Uint8Array[] = [];
      for (let i = 0; i * 32 < len; i++) blocks.push(sha256(cat(seed, be32(i))));
      const want = cat(...blocks).subarray(0, len);
      expect(Array.from(hashKat(seed, len))).toEqual(Array.from(want));
    }
  });
});

describe('mock backend', () => {
  it('mockKeypair: sizes, default seed, string vs bytes seeds, unknown variant, sk layout', () => {
    const a = mockKeypair('fn-dsa-512');
    expect(a.pk.length).toBe(897);
    expect(Array.from(mockKeypair('fn-dsa-512', 'default').pk)).toEqual(Array.from(a.pk));
    expect(Array.from(a.pk)).toEqual(Array.from(hashKat(u('fn-dsa-512/default'), 897)));
    expect(Array.from(a.sk)).toEqual(Array.from(cat(SK_TAG, a.pk)));
    const bs = new Uint8Array([1, 2, 3]);
    expect(Array.from(mockKeypair('fn-dsa-1024', bs).pk)).toEqual(Array.from(hashKat(cat(u('fn-dsa-1024/'), bs), 1793)));
    expect(Array.from(mockKeypair('fn-dsa-1024', bs).pk)).not.toEqual(Array.from(mockKeypair('fn-dsa-1024', '1,2,3').pk));
    rejects(() => mockKeypair('nope' as never), RangeError, "mockKeypair: unknown FN-DSA variant 'nope'");
  });
  it('sign is the domain-separated hashKat of (pk,msg); verify accepts exactly that', () => {
    const be = registerTestBackend();
    const kp = mockKeypair('fn-dsa-512');
    const msg = u('hello');
    const want = hashKat(cat(u('fn-dsa/mock-sig/v1\0'), kp.pk, msg), 666);
    const got = be.sign!(kp.sk, msg);
    expect(Array.from(got)).toEqual(Array.from(want));
    expect(be.verify(kp.pk, msg, got)).toBe(true);
    expect(be.verify(kp.pk, u('hellO'), got)).toBe(false);
    const kp2 = mockKeypair('fn-dsa-1024');
    expect(be.sign!(kp2.sk, msg).length).toBe(1280);
    expect(be.verify(kp2.pk, msg, be.sign!(kp2.sk, msg))).toBe(true);
    expect(be.verify(kp2.pk, msg, got)).toBe(false);
  });
  it('verify requires an exact-length match (a prefix of the right signature fails)', () => {
    const be = registerTestBackend();
    const kp = mockKeypair('fn-dsa-512');
    const sig = be.sign!(kp.sk, u('m'));
    expect(be.verify(kp.pk, u('m'), sig.subarray(0, 665))).toBe(false);
    const longer = cat(sig, new Uint8Array([0]));
    expect(be.verify(kp.pk, u('m'), longer)).toBe(false);
  });
  it('keys of an unknown length: verify false, sign throws', () => {
    const be = registerTestBackend();
    expect(be.verify(new Uint8Array(10), u('m'), new Uint8Array(666))).toBe(false);
    rejects(() => be.sign!(cat(SK_TAG, new Uint8Array(10)), u('m')), Error, 'mock FN-DSA backend: public key length matches no FN-DSA variant');
    // a 1793-byte key is the 1024 variant, any other non-897 length is not
    rejects(() => be.sign!(cat(SK_TAG, new Uint8Array(1000)), u('m')), Error, 'mock FN-DSA backend: public key length matches no FN-DSA variant');
  });
  it('sign rejects a secret key not minted by mockKeypair', () => {
    const be = registerTestBackend();
    const msg = 'mock FN-DSA backend: secret key was not minted by mockKeypair()';
    rejects(() => be.sign!(new Uint8Array(0), u('m')), Error, msg);
    rejects(() => be.sign!(SK_TAG, u('m')), Error, msg); // tag only: no pk bytes
    rejects(() => be.sign!(new Uint8Array(SK_TAG.length + 897).fill(1), u('m')), Error, msg);
    const bad = cat(SK_TAG, mockKeypair('fn-dsa-512').pk);
    bad[SK_TAG.length - 1]! ^= 1;
    rejects(() => be.sign!(bad, u('m')), Error, msg);
  });
  it('explicit vectors take precedence, only for their exact (pk,msg)', () => {
    const kp = mockKeypair('fn-dsa-512');
    const custom = new Uint8Array(666).fill(7);
    const be = registerTestBackend([{ pk: kp.pk, msg: u('A'), sig: custom }]);
    expect(be.sign!(kp.sk, u('A'))).toBe(custom);
    expect(be.verify(kp.pk, u('A'), custom)).toBe(true);
    const derivedB = hashKat(cat(u('fn-dsa/mock-sig/v1\0'), kp.pk, u('B')), 666);
    expect(Array.from(be.sign!(kp.sk, u('B')))).toEqual(Array.from(derivedB));
    expect(be.verify(kp.pk, u('B'), custom)).toBe(false);
    expect(be.verify(kp.pk, u('B'), derivedB)).toBe(true);
    // the vector is keyed by pk AND msg
    const kp2 = mockKeypair('fn-dsa-512', 'o');
    expect(be.verify(kp2.pk, u('A'), custom)).toBe(false);
    expect(be.verify(kp.pk, u('A'), derivedB)).toBe(false);
    // no vectors argument: nothing is overridden
    const plain = registerTestBackend();
    expect(plain.verify(kp.pk, u('A'), custom)).toBe(false);
  });
  it('registerTestBackend installs and returns the backend; keygen is a fn-dsa-512 mock keypair', () => {
    const be = registerTestBackend();
    expect(getFalconBackend()).toBe(be);
    const k = be.keygen!();
    expect(k.pk.length).toBe(897);
    expect(Array.from(k.pk)).toEqual(Array.from(mockKeypair('fn-dsa-512').pk));
  });
});
