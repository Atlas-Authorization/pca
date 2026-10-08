import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u, unb64u, utf8 } from './hash';
import {
  FN_DSA_1024_PUBLIC_KEY_BYTES,
  FN_DSA_1024_SIGNATURE_BYTES,
  FN_DSA_512_PUBLIC_KEY_BYTES,
  FN_DSA_512_SIGNATURE_BYTES,
  type SigAlg,
  type SuitePublicKeys,
  type SuiteSecretKeys,
  fnDsa1024Keygen,
  fnDsa1024Sign,
  fnDsa1024Verify,
  fnDsa512Keygen,
  fnDsa512Sign,
  fnDsa512Verify,
  fnDsa512VerifyB64u,
  isFnDsaBackendActive,
  isKnownSigAlg,
  resolveSigAlg,
  signSuiteArtifact,
  signWithSuite,
  validateSignatureWire,
  verifyLeafSuite,
  verifyWithSuite,
} from './pq';

const MSG = utf8('fn-dsa suite dispatch test message');
const SEED = (label: string): Uint8Array => {
  const s = new Uint8Array(32);
  for (let i = 0; i < label.length && i < 32; i++) s[i] = label.charCodeAt(i);
  return s;
};
const flip = (s: string): string => {
  const b = unb64u(s);
  b[0] = b[0]! ^ 0x01;
  return b64u(b);
};
const drop = (s: string): string => {
  const b = unb64u(s);
  return b64u(b.slice(0, b.length - 1));
};

describe('FN-DSA backend is available in the workspace', () => {
  it('the pca-fndsa-wasm binding loads (else every FN-DSA suite fails closed)', () => {
    expect(isFnDsaBackendActive()).toBe(true);
  });
});

describe('FN-DSA suites are registered (fail-closed registry)', () => {
  it('fn-dsa-512 / fn-dsa-1024 resolve as pure-PQ non-hybrid suites with the FIPS-206 sizes', () => {
    for (const alg of ['fn-dsa-512', 'fn-dsa-1024'] as const) {
      expect(isKnownSigAlg(alg)).toBe(true);
      const suite = resolveSigAlg(alg);
      expect(suite?.alg).toBe(alg);
      expect(suite?.needsPqPk).toBe(true);
      expect(suite?.needsPqSig).toBe(false); // pure PQ: no separate pq_sig
      expect(suite?.hasEd25519).toBe(false);
    }
    expect(resolveSigAlg('fn-dsa-512')?.sigBytes).toBe(FN_DSA_512_SIGNATURE_BYTES);
    expect(resolveSigAlg('fn-dsa-512')?.pqPkBytes).toBe(FN_DSA_512_PUBLIC_KEY_BYTES);
    expect(resolveSigAlg('fn-dsa-1024')?.sigBytes).toBe(FN_DSA_1024_SIGNATURE_BYTES);
    expect(resolveSigAlg('fn-dsa-1024')?.pqPkBytes).toBe(FN_DSA_1024_PUBLIC_KEY_BYTES);
  });
  it("a near-miss alg 'falcon-512' is NOT known (fail-closed)", () => {
    expect(isKnownSigAlg('falcon-512')).toBe(false);
    expect(resolveSigAlg('falcon-512')).toBeNull();
  });
});

describe('FN-DSA primitive wrappers (via the wasm binding)', () => {
  it('fn-dsa-512 keygen/sign/verify roundtrip; FIPS-206 sizes', () => {
    const kp = fnDsa512Keygen(SEED('kg-512'));
    expect(kp.verifyingKey.length).toBe(FN_DSA_512_PUBLIC_KEY_BYTES);
    const sig = fnDsa512Sign(kp.signingKey, MSG, SEED('sign-512'));
    expect(sig.length).toBe(FN_DSA_512_SIGNATURE_BYTES);
    expect(fnDsa512Verify(kp.verifyingKey, MSG, sig)).toBe(true);
    expect(fnDsa512VerifyB64u(b64u(kp.verifyingKey), MSG, b64u(sig))).toBe(true);
  });
  it('fn-dsa-1024 keygen/sign/verify roundtrip; FIPS-206 sizes', () => {
    const kp = fnDsa1024Keygen(SEED('kg-1024'));
    expect(kp.verifyingKey.length).toBe(FN_DSA_1024_PUBLIC_KEY_BYTES);
    const sig = fnDsa1024Sign(kp.signingKey, MSG, SEED('sign-1024'));
    expect(sig.length).toBe(FN_DSA_1024_SIGNATURE_BYTES);
    expect(fnDsa1024Verify(kp.verifyingKey, MSG, sig)).toBe(true);
  });
  it('wrong key, tampered message/sig, wrong lengths all fail (never throw)', () => {
    const kp = fnDsa512Keygen(SEED('kg-512'));
    const other = fnDsa512Keygen(SEED('kg-512-other'));
    const sig = fnDsa512Sign(kp.signingKey, MSG, SEED('sign-512'));
    expect(fnDsa512Verify(other.verifyingKey, MSG, sig)).toBe(false);
    expect(fnDsa512Verify(kp.verifyingKey, utf8('other message'), sig)).toBe(false);
    const bad = Uint8Array.from(sig); bad[0] = bad[0]! ^ 1;
    expect(fnDsa512Verify(kp.verifyingKey, MSG, bad)).toBe(false);
    expect(fnDsa512Verify(kp.verifyingKey.subarray(0, 100), MSG, sig)).toBe(false); // wrong-size key
    expect(fnDsa512Verify(kp.verifyingKey, MSG, sig.subarray(0, 100))).toBe(false); // wrong-size sig
    expect(fnDsa512VerifyB64u('!!not-b64u', MSG, b64u(sig))).toBe(false);
  });
});

interface VariantCfg {
  readonly alg: SigAlg;
  readonly keygen: (seed: Uint8Array) => { verifyingKey: Uint8Array; signingKey: Uint8Array };
  readonly secretKeys: (kp: { verifyingKey: Uint8Array; signingKey: Uint8Array }, seed: Uint8Array) => SuiteSecretKeys;
  readonly pubKeys: (pk: string) => SuitePublicKeys;
}

const VARIANTS: readonly VariantCfg[] = [
  {
    alg: 'fn-dsa-512',
    keygen: fnDsa512Keygen,
    secretKeys: (kp, signSeed) => ({ fnDsa512: { verifyingKey: kp.verifyingKey, signingKey: kp.signingKey, signSeed } }),
    pubKeys: (pk) => ({ fnDsa512Pub: pk }),
  },
  {
    alg: 'fn-dsa-1024',
    keygen: fnDsa1024Keygen,
    secretKeys: (kp, signSeed) => ({ fnDsa1024: { verifyingKey: kp.verifyingKey, signingKey: kp.signingKey, signSeed } }),
    pubKeys: (pk) => ({ fnDsa1024Pub: pk }),
  },
];

describe('FN-DSA suite dispatch (signWithSuite / verifyWithSuite — a real wasm signature)', () => {
  for (const cfg of VARIANTS) {
    const { alg } = cfg;

    it(`${alg}: signWithSuite produces a sig that verifyWithSuite accepts; tamper => deny`, () => {
      const kp = cfg.keygen(SEED(`disp-${alg}`));
      const parts = signWithSuite(alg, cfg.secretKeys(kp, SEED(`sseed-${alg}`)), MSG);
      expect('pq_sig' in parts).toBe(false); // pure PQ

      const pub = cfg.pubKeys(b64u(kp.verifyingKey));
      expect(verifyWithSuite(alg, pub, MSG, { sig: parts.sig })).toBe(true);
      // tamper the signature => deny
      expect(verifyWithSuite(alg, pub, MSG, { sig: flip(parts.sig) })).toBe(false);
      // wrong message => deny
      expect(verifyWithSuite(alg, pub, utf8('different'), { sig: parts.sig })).toBe(false);
      // missing public key => deny (fail-closed)
      expect(verifyWithSuite(alg, {}, MSG, { sig: parts.sig })).toBe(false);
    });

    it(`${alg}: signSuiteArtifact carries alg + pq_pk (the verifying key) and no pq_sig`, () => {
      const kp = cfg.keygen(SEED(`art-${alg}`));
      const art = signSuiteArtifact(alg, cfg.secretKeys(kp, SEED(`aseed-${alg}`)), MSG);
      expect(art.alg).toBe(alg);
      expect(art.pq_pk).toBe(b64u(kp.verifyingKey));
      expect('pq_sig' in art).toBe(false);
      expect(validateSignatureWire({ alg: art.alg, sig: art.sig, pq_pk: art.pq_pk })).toBeNull();
      // verifyLeafSuite (the PCActn leaf seam) accepts it with pq_pk fed as the PQ key.
      expect(verifyLeafSuite({ alg, holder: 'unused-for-pure-pq', pqPublicKey: art.pq_pk, message: MSG, sig: art.sig })).toBe(true);
    });

    it(`${alg}: signWithSuite throws fail-closed when the key material is missing`, () => {
      expect(() => signWithSuite(alg, {}, MSG)).toThrow();
    });
  }
});

describe('FN-DSA wire validation (per-suite, fail-closed)', () => {
  it('a well-formed fn-dsa-512 object validates; stray pq_sig / wrong sizes / unknown alg are rejected', () => {
    const kp = fnDsa512Keygen(SEED('wire-512'));
    const sig = b64u(fnDsa512Sign(kp.signingKey, MSG, SEED('wire-sign-512')));
    const pq_pk = b64u(kp.verifyingKey);
    expect(validateSignatureWire({ alg: 'fn-dsa-512', sig, pq_pk })).toBeNull();
    // pq_pk REQUIRED for a pure PQ suite.
    expect(validateSignatureWire({ alg: 'fn-dsa-512', sig })).not.toBeNull();
    // pq_sig FORBIDDEN on a non-hybrid suite.
    expect(validateSignatureWire({ alg: 'fn-dsa-512', sig, pq_pk, pq_sig: sig })).not.toBeNull();
    // wrong sig / pq_pk sizes.
    expect(validateSignatureWire({ alg: 'fn-dsa-512', sig: drop(sig), pq_pk })).not.toBeNull();
    expect(validateSignatureWire({ alg: 'fn-dsa-512', sig, pq_pk: drop(pq_pk) })).not.toBeNull();
    // unknown alg.
    expect(validateSignatureWire({ alg: 'falcon-512', sig, pq_pk })).not.toBeNull();
  });
});

// ---- conformance corpus (the committed golden/adversarial vectors must re-verify) ----------------

interface FnDsaVector {
  name: string;
  class: 'positive' | 'negative';
  description: string;
  alg: string;
  message: string;
  pq_pk?: string;
  sig: string;
  pq_sig?: string;
  expect: { verify: boolean; wire_ok: boolean; allow: boolean };
}

describe('FN-DSA conformance corpus', () => {
  const corpus = JSON.parse(
    readFileSync(join(__dirname, '..', 'conformance', 'fndsa-vectors.json'), 'utf8'),
  ) as { format: number; suite: string; vectors: FnDsaVector[] };

  it('is the fn-dsa falcon FIPS-206 suite with >= 10 vectors', () => {
    expect(corpus.format).toBe(1);
    expect(corpus.suite).toBe('fn-dsa-falcon-fips206');
    expect(corpus.vectors.length).toBeGreaterThanOrEqual(10);
  });

  for (const v of corpus.vectors) {
    it(v.name, () => {
      const msg = unb64u(v.message);
      // (1) wire shape per the committed object.
      const wireObj: Record<string, unknown> = { alg: v.alg, sig: v.sig };
      if (v.pq_pk !== undefined) wireObj.pq_pk = v.pq_pk;
      if (v.pq_sig !== undefined) wireObj.pq_sig = v.pq_sig;
      const wireOk = validateSignatureWire(wireObj) === null;
      // (2) suite dispatch (the leaf seam) over the message.
      const verify = verifyLeafSuite({
        alg: v.alg as SigAlg,
        holder: 'unused-for-pure-pq',
        pqPublicKey: v.pq_pk,
        message: msg,
        sig: v.sig,
      });
      expect(wireOk).toBe(v.expect.wire_ok);
      expect(verify).toBe(v.expect.verify);
      const allow = wireOk && verify;
      expect(allow).toBe(v.expect.allow);
      expect(allow).toBe(v.class === 'positive');
    });
  }
});
