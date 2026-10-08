import { beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_RISK_POLICY, type PCActn, type RiskInputs } from '@atlasauth/pca';
import {
  DEFAULT_SCALE,
  RISK_DIM,
  type EvalKeys,
  type FheKeyset,
  decryptVerdict,
  encryptRiskInputs,
  encryptedRiskClaim,
  evalEncryptedRiskClaim,
  evalRiskGate,
  fheRiskPolicy,
  keygen,
  plaintextVerdict,
  quantizeRiskInputs,
  riskInputsFromPCActn,
  transformedInputs,
  weightVector,
} from './index';

// node-seal compiles WASM and generates Galois keys on first use — give generous timeouts.
const TIMEOUT = 60_000;

/** Build a RiskInputs whose transformed vector is exactly `[d,1-rev,bl,taint,1-conf,age]`. */
function inputsFor(transformed: [number, number, number, number, number, number]): RiskInputs {
  const [d, oneMinusRev, bl, taint, oneMinusConf, age] = transformed;
  return {
    semanticDistance: d,
    reversibility: 1 - oneMinusRev,
    blastRadius: bl,
    taint,
    confidence: 1 - oneMinusConf,
    age,
  };
}

/** Hand-computed Σ weightsScaled·round(x·S) — the integer the FHE path must reproduce. */
function expectedRiskRaw(inputs: RiskInputs, scale = DEFAULT_SCALE): number {
  const w = weightVector(DEFAULT_RISK_POLICY.weights).map((v) => Math.round(v * scale));
  const x = quantizeRiskInputs(inputs, scale);
  return w.reduce((acc, wi, i) => acc + wi * (x[i] ?? 0), 0);
}

describe('@atlasauth/pca-fhe risk gate under homomorphic encryption', () => {
  let keys: FheKeyset;
  let evalKeys: EvalKeys;

  beforeAll(async () => {
    keys = await keygen();
    evalKeys = {
      publicKey: keys.publicKey,
      relinKeys: keys.relinKeys,
      galoisKeys: keys.galoisKeys,
    };
  }, TIMEOUT);

  it('fixed-point helpers mirror risk.ts (transform + weight clamp)', () => {
    expect(weightVector(DEFAULT_RISK_POLICY.weights)).toEqual([0.25, 0.2, 0.2, 0.2, 0.1, 0.05]);
    // reversibility/confidence are inverted; non-finite fails closed to the worst case.
    const t = transformedInputs(inputsFor([0.8, 0.5, 0.3, 0.9, 0.4, 0.2]));
    expect(t).toEqual([0.8, 0.5, 0.3, 0.9, 0.4, 0.2]);
    const worst = transformedInputs({
      semanticDistance: Number.NaN,
      reversibility: Number.NaN,
      blastRadius: Number.NaN,
      taint: Number.NaN,
      confidence: Number.NaN,
      age: Number.NaN,
    });
    expect(worst).toEqual([1, 1, 1, 1, 1, 1]); // all terms at their risk-maximizing value
  });

  it(
    'reproduces the plaintext riskRaw and ADMITS a low-risk action (slack >= 0)',
    async () => {
      const inputs = inputsFor([0.1, 0.1, 0.1, 0.1, 0.1, 0.1]); // r = 0.1
      const budget = 0.6;
      const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, budget);
      const encInputs = await encryptRiskInputs(keys.publicKey, quantizeRiskInputs(inputs));
      const gate = await evalRiskGate(evalKeys, encInputs, policy);
      const verdict = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);

      expect(verdict.rScaled).toBe(expectedRiskRaw(inputs)); // 100000
      expect(verdict.rScaled / (DEFAULT_SCALE * DEFAULT_SCALE)).toBeCloseTo(0.1, 9);
      expect(verdict.admit).toBe(true);
      expect(verdict.slack).toBe(Math.round(budget * 1e6) - expectedRiskRaw(inputs)); // 500000

      const ref = plaintextVerdict(inputs, DEFAULT_RISK_POLICY, budget);
      expect(verdict.rScaled / 1e6).toBeCloseTo(ref.r, 9);
      expect(verdict.admit).toBe(ref.admit);
    },
    TIMEOUT,
  );

  it(
    'reproduces the plaintext riskRaw and DENIES a high-risk action (slack < 0)',
    async () => {
      const inputs = inputsFor([0.9, 0.9, 0.9, 0.9, 0.9, 0.9]); // r = 0.9
      const budget = 0.2;
      const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, budget);
      const encInputs = await encryptRiskInputs(keys.publicKey, quantizeRiskInputs(inputs));
      const gate = await evalRiskGate(evalKeys, encInputs, policy);
      const verdict = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);

      expect(verdict.rScaled).toBe(expectedRiskRaw(inputs)); // 900000
      expect(verdict.slack).toBe(Math.round(budget * 1e6) - 900000); // -700000
      expect(verdict.slack).toBeLessThan(0);
      expect(verdict.admit).toBe(false);

      const ref = plaintextVerdict(inputs, DEFAULT_RISK_POLICY, budget);
      expect(verdict.rScaled / 1e6).toBeCloseTo(ref.r, 9);
      expect(verdict.admit).toBe(ref.admit);
    },
    TIMEOUT,
  );

  it(
    'matches risk.ts riskScore/admit across a spread of mixed inputs and budgets',
    async () => {
      const cases: Array<{ t: [number, number, number, number, number, number]; budget: number }> = [
        { t: [0.8, 0.5, 0.3, 0.9, 0.4, 0.2], budget: 0.6 }, // r = 0.59
        { t: [0.5, 0.5, 0.5, 0.5, 0.5, 0.5], budget: 0.5 }, // r = 0.5, slack = 0 -> admit
        { t: [0.0, 0.0, 0.0, 0.0, 0.0, 0.0], budget: 0.0 }, // r = 0, slack = 0 -> admit
        { t: [1.0, 1.0, 1.0, 1.0, 1.0, 1.0], budget: 0.99 }, // r = 1, deny
      ];
      for (const c of cases) {
        const inputs = inputsFor(c.t);
        const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, c.budget);
        const encInputs = await encryptRiskInputs(keys.publicKey, quantizeRiskInputs(inputs));
        const gate = await evalRiskGate(evalKeys, encInputs, policy);
        const verdict = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
        const ref = plaintextVerdict(inputs, DEFAULT_RISK_POLICY, c.budget);

        expect(verdict.rScaled).toBe(expectedRiskRaw(inputs));
        expect(verdict.rScaled / 1e6).toBeCloseTo(ref.r, 9);
        expect(verdict.admit).toBe(ref.admit);
      }
    },
    TIMEOUT,
  );

  it('the evaluator holds NO secret key — it cannot decrypt by construction', () => {
    // EvalKeys is the only material the evaluator receives.
    expect(Object.keys(evalKeys).sort()).toEqual(['galoisKeys', 'publicKey', 'relinKeys']);
    expect(Object.keys(evalKeys)).not.toContain('secretKey');
    // evalRiskGate's signature accepts EvalKeys; there is no code path in it that builds a Decryptor.
    // (decryptVerdict, the only decrypting function, demands the secret key as its first argument.)
  });

  it(
    'a WRONG secret key does not recover the correct verdict',
    async () => {
      const inputs = inputsFor([0.1, 0.1, 0.1, 0.1, 0.1, 0.1]);
      const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
      const encInputs = await encryptRiskInputs(keys.publicKey, quantizeRiskInputs(inputs));
      const gate = await evalRiskGate(evalKeys, encInputs, policy);

      const wrong = await keygen();
      const verdict = await decryptVerdict(wrong.secretKey, gate.encRiskRaw, gate.encSlack, policy);
      // The real rScaled is 100000; a wrong key yields garbage mod t, overwhelmingly not that value.
      expect(verdict.rScaled).not.toBe(expectedRiskRaw(inputs));
    },
    TIMEOUT,
  );

  it(
    'a TAMPERED ciphertext does not yield the correct verdict',
    async () => {
      const inputs = inputsFor([0.1, 0.1, 0.1, 0.1, 0.1, 0.1]);
      const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, 0.6);
      const encInputs = await encryptRiskInputs(keys.publicKey, quantizeRiskInputs(inputs));

      // Corrupt the serialized ciphertext mid-stream.
      const mid = Math.floor(encInputs.length / 2);
      const flip = encInputs[mid] === 'A' ? 'B' : 'A';
      const tampered = encInputs.slice(0, mid) + flip + encInputs.slice(mid + 1);

      let correct = false;
      try {
        const gate = await evalRiskGate(evalKeys, tampered, policy);
        const verdict = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
        correct = verdict.rScaled === expectedRiskRaw(inputs);
      } catch {
        correct = false; // rejected on load/eval — also an acceptable failure mode
      }
      expect(correct).toBe(false);
    },
    TIMEOUT,
  );

  it(
    'PCA layer: an agent submits an encrypted risk claim the evaluator processes blind',
    async () => {
      const inputs = inputsFor([0.8, 0.5, 0.3, 0.9, 0.4, 0.2]); // r = 0.59
      const budget = 0.6;
      const actn = makePCActn(inputs);
      const policy = fheRiskPolicy(DEFAULT_RISK_POLICY, budget);

      // Agent side: build the encrypted claim from the signed action.
      const claim = await encryptedRiskClaim({ actn, publicKey: keys.publicKey, policy });
      expect(claim.binding.aud).toBe(actn.aud);
      expect(claim.binding.actionRef).toBe(actn.action.params_digest);
      expect(claim.binding.counter).toBe(actn.counter);
      expect(riskInputsFromPCActn(actn)).toEqual(inputs);

      // Evaluator side: run the gate over the claim with only the eval keys.
      const gate = await evalEncryptedRiskClaim(evalKeys, claim);

      // Key holder: open the verdict and cross-check against plaintext risk.ts.
      const verdict = await decryptVerdict(keys.secretKey, gate.encRiskRaw, gate.encSlack, policy);
      const ref = plaintextVerdict(inputs, DEFAULT_RISK_POLICY, budget);
      expect(verdict.rScaled).toBe(590000);
      expect(verdict.rScaled / 1e6).toBeCloseTo(ref.r, 9);
      expect(verdict.admit).toBe(ref.admit);
    },
    TIMEOUT,
  );

  it('fheRiskPolicy rejects a scale that would overflow the plain modulus', () => {
    // scale 1e6 -> budgetScaled = budget*1e12, far beyond SIGNED_BOUND.
    expect(() => fheRiskPolicy(DEFAULT_RISK_POLICY, 1, 1_000_000)).toThrow(/overflow/);
  });

  it('encryptRiskInputs rejects a wrong-length or negative input vector', async () => {
    await expect(encryptRiskInputs(keys.publicKey, [1, 2, 3])).rejects.toThrow(
      new RegExp(`length ${RISK_DIM}`),
    );
    await expect(
      encryptRiskInputs(keys.publicKey, [0, 0, 0, 0, 0, -1]),
    ).rejects.toThrow(/non-negative integer/);
  });
});

/** A minimal PCActn carrying plaintext risk inputs (only the fields this package reads are meaningful). */
function makePCActn(inputs: RiskInputs): PCActn {
  return {
    ver: 2,
    action: {
      verb: 'delete',
      resource: 'db://records/42',
      params_digest: 'params-digest-abc',
      reversibility_class: 'hard',
    },
    grant_ref: 'grant-1',
    cap_chain: [],
    plan: { root: 'root', inclusion_proof: { index: 0, size: 1, path: [] }, node_id: 'n1' },
    attestation: {
      quote_digest: 'q',
      epoch: 1,
      model_id: 'm',
      measurement: 'x',
      operator: 'op',
    },
    provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: [] },
    freshness: { beacon_ref: 'b', epoch: 1, accumulator_witness: 'w' },
    counter: 7,
    risk_claim: {
      r: 0.59,
      inputs: {
        semanticDistance: inputs.semanticDistance,
        reversibility: inputs.reversibility,
        blastRadius: inputs.blastRadius,
        taint: inputs.taint,
        confidence: inputs.confidence,
        age: inputs.age,
      },
    },
    aud: 'ins_test',
    iat: 1_700_000_000_000,
    exp: 1_700_000_600_000,
    nonce: 'nonce-xyz',
    sig: 'sig',
  };
}
