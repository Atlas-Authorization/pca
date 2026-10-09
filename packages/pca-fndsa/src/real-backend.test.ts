/**
 * The same PCA integration paths as index.test.ts, but through the REAL FN-DSA backend
 * (`@atlasauth/pca-fndsa-wasm`: the `fn-dsa` crate compiled to WebAssembly) instead of the mock.
 * The mock in index.test.ts is kept only for wiring/negative-plumbing checks.
 *
 * The wasm package is imported from its built output (`pnpm --filter @atlasauth/pca-fndsa-wasm build`)
 * so this package needs no runtime dependency on it.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
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
import { keygen as wasmKeygen, sign as wasmSign, verify as wasmVerify, type FnDsaVariant } from '../../pca-fndsa-wasm/dist/index';
import {
  FN_DSA_SUITES,
  type FalconBackend,
  type FalconKeyPair,
  fndsaSign,
  fndsaVerify,
  resetFalconBackend,
  setFalconBackend,
  signPcaWithFndsa,
  verifyPcaFndsa,
} from './index';

const u = (s: string): Uint8Array => new TextEncoder().encode(s);
const SEED_LEN = 32;
let counter = 0;
/** Deterministic, distinct seeds per call (test-only). */
function seed(): Uint8Array {
  counter += 1;
  const out = new Uint8Array(SEED_LEN);
  new DataView(out.buffer).setUint32(0, counter);
  out[SEED_LEN - 1] = 0x5a;
  return out;
}
function variantFromPk(pk: Uint8Array): FnDsaVariant {
  if (pk.length === 897) return 'fn-dsa-512';
  if (pk.length === 1793) return 'fn-dsa-1024';
  throw new Error(`unexpected public-key length ${pk.length}`);
}
function variantFromSk(sk: Uint8Array): FnDsaVariant {
  if (sk.length === 1345) return 'fn-dsa-512';
  if (sk.length === 2369) return 'fn-dsa-1024';
  throw new Error(`unexpected secret-key length ${sk.length}`);
}
const realBackend: FalconBackend = {
  verify: (pk, msg, sig) => wasmVerify(variantFromPk(pk), pk, msg, sig),
  sign: (sk, msg) => wasmSign(variantFromSk(sk), sk, msg, seed()),
  keygen: () => {
    const k = wasmKeygen('fn-dsa-512', seed());
    return { pk: k.verifyingKey, sk: k.signingKey };
  },
};
function realKeypair(variant: FnDsaVariant): FalconKeyPair {
  const k = wasmKeygen(variant, seed());
  return { pk: k.verifyingKey, sk: k.signingKey };
}

beforeEach(() => setFalconBackend(realBackend));
afterEach(() => resetFalconBackend());

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

const VARIANTS: FnDsaVariant[] = ['fn-dsa-512', 'fn-dsa-1024'];

describe('REAL wasm backend: fndsaSign / fndsaVerify', () => {
  for (const variant of VARIANTS) {
    const sigBytes = FN_DSA_SUITES[variant].sigBytes;
    it(`${variant}: genuine round-trip; wrong message, flipped signature bit and foreign key are rejected`, () => {
      const kp = realKeypair(variant);
      const other = realKeypair(variant);
      const msg = u(`real falcon ${variant}`);
      const sig = fndsaSign(variant, kp.sk, msg);
      expect(sig.length).toBe(sigBytes);
      expect(fndsaVerify(variant, kp.pk, msg, sig)).toBe(true);
      expect(fndsaVerify(variant, kp.pk, u('other'), sig)).toBe(false);
      const bad = sig.slice();
      bad[Math.floor(bad.length / 2)] = (bad[Math.floor(bad.length / 2)] ?? 0) ^ 0x01;
      expect(fndsaVerify(variant, kp.pk, msg, bad)).toBe(false);
      expect(fndsaVerify(variant, other.pk, msg, sig)).toBe(false);
    });
  }

  it('a mock-style forged signature (hash-derived bytes of the right length) is NOT accepted by the real backend', () => {
    const kp = realKeypair('fn-dsa-512');
    const forged = new Uint8Array(666).fill(0x39);
    expect(fndsaVerify('fn-dsa-512', kp.pk, u('m'), forged)).toBe(false);
  });
});

describe('REAL wasm backend: PCActn leaf signing', () => {
  for (const alg of ['fn-dsa-512', 'fn-dsa-1024'] as const) {
    it(`${alg}: round-trips; tampered action, swapped key and zeroed signature fail`, () => {
      const leaf = buildLeafBody();
      const kp = realKeypair(FN_DSA_SUITES[alg].variant);
      const other = realKeypair(FN_DSA_SUITES[alg].variant);
      const f = signPcaWithFndsa({ alg, leaf, fnDsa: kp });
      expect(verifyPcaFndsa({ alg: f.alg, leaf, pq_pk: f.pq_pk, sig: f.sig })).toBe(true);
      const tampered: PCActnBody = { ...leaf, action: { ...leaf.action, resource: 'sess/ALL' } };
      expect(verifyPcaFndsa({ alg: f.alg, leaf: tampered, pq_pk: f.pq_pk, sig: f.sig })).toBe(false);
      expect(verifyPcaFndsa({ alg: f.alg, leaf, pq_pk: b64u(other.pk), sig: f.sig })).toBe(false);
      expect(verifyPcaFndsa({ alg: f.alg, leaf, pq_pk: f.pq_pk, sig: b64u(new Uint8Array(FN_DSA_SUITES[alg].sigBytes)) })).toBe(false);
    });
  }

  it('hybrid ed25519 + fn-dsa-512 requires BOTH halves with real signatures', () => {
    const leaf = buildLeafBody();
    const ed = generateKeyPair();
    const kp = realKeypair('fn-dsa-512');
    const f = signPcaWithFndsa({ alg: 'hybrid-ed25519-fn-dsa-512', leaf, fnDsa: kp, edSecret: ed.secretKey });
    const holder = encodeKey(ed.publicKey);
    expect(verifyPcaFndsa({ alg: f.alg, leaf, holder, pq_pk: f.pq_pk, sig: f.sig, pq_sig: f.pq_sig })).toBe(true);
    // wrong classical half
    expect(verifyPcaFndsa({ alg: f.alg, leaf, holder: encodeKey(generateKeyPair().publicKey), pq_pk: f.pq_pk, sig: f.sig, pq_sig: f.pq_sig })).toBe(false);
    // missing / forged lattice half
    expect(verifyPcaFndsa({ alg: f.alg, leaf, holder, pq_pk: f.pq_pk, sig: f.sig })).toBe(false);
    expect(verifyPcaFndsa({ alg: f.alg, leaf, holder, pq_pk: f.pq_pk, sig: f.sig, pq_sig: b64u(new Uint8Array(666)) })).toBe(false);
  });
});
