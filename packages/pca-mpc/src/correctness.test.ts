import { describe, expect, it } from 'vitest';
import {
  type DecideInput,
  DEFAULT_RISK_POLICY,
  encodeKey,
  generateKeyPair,
  mintGrant,
  type RiskPolicy,
} from '@atlasauth/pca';
import { composeClear } from './compose';
import { evaluateParty, type DecisionVector, type PartyPolicy } from './party';
import { composeSecure } from './runner';

/** Deterministic LCG so the "many random combinations" are reproducible. */
function lcg(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

function randomVector(rnd: () => number, Q: number): DecisionVector {
  return {
    allow: rnd() < 0.5 ? 0 : 1,
    t: (1 + Math.floor(rnd() * 3)) as 1 | 2 | 3,
    rQuant: Math.floor(rnd() * (Q + 1)),
  };
}

describe('MPC composition correctness == cleartext composition', () => {
  it('matches composeClear over many random party-policy combinations', () => {
    const rnd = lcg(0xc0ffee);
    const Q = 16; // small domain keeps the heavy random loop fast; equivalence holds for any Q
    let runs = 0;
    for (let iter = 0; iter < 300; iter++) {
      const n = 1 + Math.floor(rnd() * 4); // 1..4 parties
      const vectors = Array.from({ length: n }, () => randomVector(rnd, Q));
      const expected = composeClear(vectors);
      const got = composeSecure(vectors, { Q, seed: BigInt(iter + 1) });
      expect(got.composed).toEqual(expected);
      runs++;
    }
    expect(runs).toBe(300);
  });

  it('matches at full Q=100 for the canonical 3-party (user/org/regulator) shapes', () => {
    const Q = 100;
    const vectors: DecisionVector[] = [
      { allow: 1, t: 1, rQuant: 12 }, // user: happy to proceed, low risk
      { allow: 1, t: 2, rQuant: 55 }, // org: wants a stronger proof, medium risk
      { allow: 1, t: 1, rQuant: 30 }, // regulator: fine, low-ish risk
    ];
    const got = composeSecure(vectors, { Q, seed: 7n });
    expect(got.composed).toEqual(composeClear(vectors));
    // meet semantics: allow AND => 1; t MAX => 2; r MAX => 55
    expect(got.composed).toEqual({ allow: 1, t: 2, rQuant: 55 });
  });

  it('performs exactly (N-1)*(1 + T_M + Q) Beaver multiplications', () => {
    const Q = 16;
    const vectors = Array.from({ length: 3 }, (_, i) => ({ allow: 1, t: 1, rQuant: i }) as DecisionVector);
    const got = composeSecure(vectors, { Q, seed: 1n });
    expect(got.multiplications).toBe((3 - 1) * (1 + 3 + Q));
  });

  it('is deterministic for a fixed seed (same transcript and output)', () => {
    const vectors: DecisionVector[] = [
      { allow: 1, t: 2, rQuant: 5 },
      { allow: 0, t: 3, rQuant: 9 },
    ];
    const a = composeSecure(vectors, { Q: 16, seed: 42n });
    const b = composeSecure(vectors, { Q: 16, seed: 42n });
    expect(a.composed).toEqual(b.composed);
    expect(a.opened).toEqual(b.opened);
  });
});

describe('reuses @atlasauth/pca decide() for per-party evaluation', () => {
  const principal = generateKeyPair();
  const agentKp = generateKeyPair();
  const pub = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);

  function makeParty(
    id: string,
    opts: { policy?: RiskPolicy; risk?: DecideInput['risk']; verb?: string } = {},
  ): PartyPolicy {
    const { grant } = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: pub(principal),
      holder: pub(agentKp),
      goal: 'wire funds',
      envelope: {
        predicates: [{ verb: opts.verb ?? '*', resource: '*' }],
        caveats: [],
        agent_binding: {},
        risk_policy: opts.policy ?? DEFAULT_RISK_POLICY,
      },
    });
    const decideInput: DecideInput = {
      grant,
      action: { action: { verb: 'wire', resource: 'acct:1', params: {} } },
      risk: opts.risk ?? { semanticDistance: 0.1, reversibility: 1, blastRadius: 0.1, taint: 0, confidence: 1, age: 0 },
      budget: { B: 1, tau: 0 },
      now: 1000,
    };
    return { id, decideInput };
  }

  it('composes three real PCA Policy-VM decisions under MPC == cleartext of their decision vectors', () => {
    const Q = 100;
    const parties: PartyPolicy[] = [
      makeParty('user'),
      // org: a heavier risk policy and a higher-risk input => higher r and threshold
      makeParty('org', {
        policy: { ...DEFAULT_RISK_POLICY, theta1: 0.05, theta2: 0.1 },
        risk: { semanticDistance: 0.6, reversibility: 0.5, blastRadius: 0.6, taint: 0.4, confidence: 0.6, age: 0.3 },
      }),
      makeParty('regulator'),
    ];
    const vectors = parties.map((p) => evaluateParty(p, Q));
    const got = composeSecure(vectors, { Q, seed: 99n });
    expect(got.composed).toEqual(composeClear(vectors));
  });

  it('one party whose predicate denies the verb => composed deny', () => {
    const Q = 100;
    const parties: PartyPolicy[] = [
      makeParty('user'),
      makeParty('org'),
      // regulator only permits "read", so "wire" is not admitted => allow 0
      makeParty('regulator', { verb: 'read' }),
    ];
    const vectors = parties.map((p) => evaluateParty(p, Q));
    expect(vectors[2]!.allow).toBe(0);
    const got = composeSecure(vectors, { Q, seed: 3n });
    expect(got.composed.allow).toBe(0);
    expect(got.composed).toEqual(composeClear(vectors));
  });
});
