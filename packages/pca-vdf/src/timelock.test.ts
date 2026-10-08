import { describe, expect, it } from 'vitest';
import {
  type PCActn,
  attenuate,
  commitPlan,
  conditionsDigest,
  delegate,
  encodeKey,
  generateKeyPair,
  mintRoot,
  paramsDigest,
  pcactnDigest,
  signPCActn,
} from '@atlasauth/pca';
import {
  calibrateSteps,
  deriveTimelockInput,
  proveTimelockElapsed,
  requireTimelock,
  verifyTimelock,
} from './timelock';
import { DEFAULT_MODULUS, setup } from './vdf';

const N = DEFAULT_MODULUS;

// --- build two real, well-formed PCActns that differ only in their action -------------------
const NOW = 1_800_000_000_000;
function buildPCActns(): { A: PCActn; B: PCActn } {
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
  const nodes = [
    { id: 'n1', verb: 'wire_transfer', resource: 'acct/treasury', params_digest: paramsDigest({ amount: 5_000_000 }), reversibility_class: 'R3', pre: { ok: 1 } },
    { id: 'n2', verb: 'wire_transfer', resource: 'acct/treasury', params_digest: paramsDigest({ amount: 42 }), reversibility_class: 'R3', pre: { ok: 1 } },
  ];
  const plan = commitPlan(nodes);
  const mk = (idx: 0 | 1): PCActn => {
    const n = nodes[idx]!;
    return signPCActn(
      {
        ver: 2,
        action: { verb: n.verb, resource: n.resource, params_digest: n.params_digest, reversibility_class: n.reversibility_class },
        grant_ref: grant.id,
        cap_chain: [grant, c1, sub],
        plan: { root: plan.root, inclusion_proof: plan.proofFor(n.id), node_id: n.id, conditions_digest: conditionsDigest(n.pre, undefined) },
        attestation: { quote_digest: 'q', epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
        provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: [] },
        freshness: { beacon_ref: 'b', epoch: 1, accumulator_witness: 'w' },
        counter: 1,
        risk_claim: { r: 0.1, inputs: {} },
        aud: 'rs-1',
        iat: NOW,
        exp: NOW + 60_000,
      },
      S.secretKey,
    );
  };
  return { A: mk(0), B: mk(1) };
}

describe('deriveTimelockInput — binds x to the action', () => {
  it('is deterministic, in [2, N), and differs per action', () => {
    const xa = deriveTimelockInput('transfer:A', N);
    expect(deriveTimelockInput('transfer:A', N)).toBe(xa);
    expect(xa >= 2n && xa < N).toBe(true);
    expect(deriveTimelockInput('transfer:B', N)).not.toBe(xa);
  });
  it('uses pcactnDigest for a PCActn and matches the string-digest path', () => {
    const { A } = buildPCActns();
    expect(deriveTimelockInput(A, N)).toBe(deriveTimelockInput(pcactnDigest(A), N));
  });
  it('rejects a bad modulus', () => {
    expect(() => deriveTimelockInput('x', 3n)).toThrow();
  });
});

describe('requireTimelock', () => {
  it('derives the requirement for an action', () => {
    const req = requireTimelock('delete-prod-db', { steps: 500, N });
    expect(req.kind).toBe('vdf-timelock');
    expect(req.steps).toBe(500);
    expect(req.N).toBe(N);
    expect(req.actionDigest).toBe('delete-prod-db');
    expect(req.x).toBe(deriveTimelockInput('delete-prod-db', N));
  });
  it('rejects a non-positive / non-integer step count', () => {
    expect(() => requireTimelock('a', { steps: 0, N })).toThrow();
    expect(() => requireTimelock('a', { steps: 1.5, N })).toThrow();
  });
});

describe('prove then verify — the timelock round-trip', () => {
  it('a valid proof for the required (action, steps, N) releases the action', () => {
    const action = 'rotate-root-key';
    const steps = 400;
    const proof = proveTimelockElapsed(action, steps, N);
    expect(proof.steps).toBe(steps);
    expect(verifyTimelock(action, proof, { steps, N })).toBe(true);
  });

  it('works end-to-end on a real PCActn', () => {
    const { A } = buildPCActns();
    const steps = 300;
    const proof = proveTimelockElapsed(A, steps, N);
    expect(verifyTimelock(A, proof, { steps, N })).toBe(true);
  });
});

describe('verifyTimelock — fails closed on every mismatch', () => {
  it('REJECTS a proof for the wrong step count (a shorter delay cannot pass)', () => {
    const action = 'irreversible';
    const proof = proveTimelockElapsed(action, 300, N);
    expect(verifyTimelock(action, proof, { steps: 299, N })).toBe(false);
    expect(verifyTimelock(action, proof, { steps: 301, N })).toBe(false);
  });

  it('REJECTS a tampered y / pi', () => {
    const action = 'irreversible';
    const steps = 250;
    const proof = proveTimelockElapsed(action, steps, N);
    expect(verifyTimelock(action, { ...proof, y: proof.y + 1n }, { steps, N })).toBe(false);
    expect(verifyTimelock(action, { ...proof, pi: proof.pi + 1n }, { steps, N })).toBe(false);
  });

  it('BINDING: a proof for action A does not verify for action B', () => {
    const steps = 300;
    const proofA = proveTimelockElapsed('transfer:A', steps, N);
    expect(verifyTimelock('transfer:A', proofA, { steps, N })).toBe(true);
    expect(verifyTimelock('transfer:B', proofA, { steps, N })).toBe(false);
  });

  it('BINDING on real PCActns: proof for PCActn A does not release PCActn B', () => {
    const { A, B } = buildPCActns();
    const steps = 300;
    const proofA = proveTimelockElapsed(A, steps, N);
    expect(verifyTimelock(A, proofA, { steps, N })).toBe(true);
    expect(verifyTimelock(B, proofA, { steps, N })).toBe(false);
  });

  it('a timelock on a setup()-generated modulus still round-trips', () => {
    const s = setup({ bits: 256 });
    const proof = proveTimelockElapsed('gen-mod-action', 200, s.N);
    expect(verifyTimelock('gen-mod-action', proof, { steps: 200, N: s.N })).toBe(true);
    expect(verifyTimelock('other-action', proof, { steps: 200, N: s.N })).toBe(false);
  });
});

describe('calibrateSteps — steps ≈ wall-clock (operator helper)', () => {
  it('maps a measured squaring rate + adversary margin to a step count', () => {
    // Deterministic fake clock: t0 = 0 ms, end = 1000 ms for the sampled loop.
    const times = [0, 1000];
    let i = 0;
    const now = () => times[Math.min(i++, times.length - 1)]!;
    const r = calibrateSteps({ N, desiredSeconds: 2, sampleSquarings: 1000, adversaryAdvantage: 10, now });
    expect(r.measuredSquaringsPerSecond).toBeCloseTo(1000, 6); // 1000 squarings / 1 s
    expect(r.assumedAdversarySquaringsPerSecond).toBeCloseTo(10000, 6);
    expect(r.steps).toBe(20000); // 10000/s * 2 s
  });
  it('rejects nonsensical parameters', () => {
    expect(() => calibrateSteps({ N, desiredSeconds: 0 })).toThrow();
    expect(() => calibrateSteps({ N, desiredSeconds: 1, adversaryAdvantage: 0.5 })).toThrow();
    expect(() => calibrateSteps({ N: 3n, desiredSeconds: 1 })).toThrow();
  });
});
