/**
 * Adversarial / audit-style tests for @atlasauth/pca-pq-threshold (complements the hybrid round-trips and
 * the ML-DSA vectors; does not repeat them): action binding, quorum accounting (duplicates, foreign keys,
 * malformed entries), downgrade claims, canonical-encoding strictness, work bounds, the experimental
 * additive-sharing toy, property tests and bounded fuzzing.
 * Fuzz seconds per group: `AUDIT_FUZZ_SECONDS` (default 3).
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  DEFAULT_RISK_POLICY,
  type PCActn,
  type PlanNode,
  attenuate,
  b64u,
  buildPCActn,
  encodeKey,
  generateKeyPair,
  mintGrant,
  mlDsa65Keygen,
  mlDsa65Sign,
  thresholdMessage,
} from '@atlasauth/pca';
import { type FrostParticipantShare, frostTrustedDealerKeygen } from '@atlasauth/pca/ext/frost';
import {
  MAX_PQ_SIGNER_ENTRIES,
  createHybridThresholdVerifier,
  experimental,
  foldHybridStepUp,
  hybridThresholdSign,
  verifyHybridStepUp,
  verifyHybridThreshold,
  type HybridThresholdArtifact,
  type SignedGroupDescriptor,
  issueGroupDescriptor,
} from './index';

const NOW = Date.now();
const FUZZ_MS = Number(process.env.AUDIT_FUZZ_SECONDS ?? '3') * 1000;
const fuzzOpts = { numRuns: 1_000_000, interruptAfterTimeLimit: FUZZ_MS, markInterruptAsFailure: false } as const;
const seed = (n: number) => new Uint8Array(32).fill(n & 0xff);
const pq = Array.from({ length: 4 }, (_, i) => mlDsa65Keygen(seed(i + 1)));
const pqPks = pq.map((k) => k.publicKey);

function loop(counter = 1): { grant: ReturnType<typeof mintGrant>['grant']; pcactn: PCActn } {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const { grant } = mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const c1 = attenuate(grant, [{ type: 'task' }], A.secretKey);
  const nodes: PlanNode[] = [{ id: 'n1', verb: 'wire_transfer', resource: 'ledger', reversibility_class: 'R3' }];
  const pcactn = buildPCActn({ aud: 'aud', now: NOW, grant, chain: [grant, c1], plan: nodes, nodeId: 'n1', counter, signerSecret: A.secretKey, riskClaim: { r: 0.9, inputs: {} } });
  return { grant, pcactn };
}

const AUTH = generateKeyPair();
const authorities = [AUTH.publicKey];

function group(t: number, n: number): { gk: Uint8Array; quorum: FrostParticipantShare[]; desc: SignedGroupDescriptor } {
  const kg = frostTrustedDealerKeygen(t, n);
  const desc = issueGroupDescriptor({ authoritySecretKey: AUTH.secretKey, groupPublicKey: kg.groupPublicKey, t, participants: kg.participantShares });
  return { gk: kg.groupPublicKey, quorum: kg.participantShares.slice(0, t), desc };
}

const { pcactn: actionA, grant } = loop(1);
const actionB = loop(2).pcactn;
const fg = group(2, 3);
const artifact = hybridThresholdSign(actionA, { frost: { groupPublicKey: fg.gk, quorum: fg.quorum, t: 2 }, pqSigners: [{ keyPair: pq[0]! }, { keyPair: pq[1]! }], pqT: 2 });
const opts = { groupKey: fg.gk, pqPublicKeys: pqPks, t: 2, pqT: 2, groupDescriptor: fg.desc, trustedAuthorities: authorities };
const withPq = (signers: Array<{ pk: string; sig: string }>): HybridThresholdArtifact => ({ ...artifact, pq: { ...artifact.pq, signers } });
const good0 = artifact.pq.signers[0]!;
const good1 = artifact.pq.signers[1]!;

describe('action binding and quorum accounting', () => {
  it('baseline verifies; the same artifact does not verify for a different action (counter) or an altered digest', () => {
    expect(verifyHybridThreshold(actionA, artifact, opts).ok).toBe(true);
    expect(verifyHybridThreshold(actionB, artifact, opts).ok).toBe(false);
    expect(verifyHybridThreshold(actionB, artifact, opts).frost).toBe(false);
    expect(verifyHybridThreshold(actionB, artifact, opts).pq.count).toBe(0);
  });

  it('PQ quorum: one key repeated N times counts once; an unregistered key, a foreign-action signature and a swapped signature count zero', () => {
    const dup = verifyHybridThreshold(actionA, withPq([good0, good0, good0, good0]), opts);
    expect(dup.pq.count).toBe(1);
    expect(dup.ok).toBe(false);
    const outsider = mlDsa65Keygen(seed(99));
    const forged = { pk: b64u(outsider.publicKey), sig: b64u(mlDsa65Sign(outsider.secretKey, thresholdMessage(actionA))) };
    expect(verifyHybridThreshold(actionA, withPq([good0, forged]), opts).pq.count).toBe(1);
    const otherAction = { pk: good1.pk, sig: b64u(mlDsa65Sign(pq[1]!.secretKey, thresholdMessage(actionB))) };
    expect(verifyHybridThreshold(actionA, withPq([good0, otherAction]), opts).pq.count).toBe(1);
    expect(verifyHybridThreshold(actionA, withPq([good0, { pk: good1.pk, sig: good0.sig }]), opts).pq.count).toBe(1);
  });

  it('malformed entries and pool members are ignored, never counted and never thrown on', () => {
    const junk: unknown[] = [null, undefined, 5, 'x', [], {}, { pk: 1, sig: 2 }, { pk: good0.pk }, { sig: good0.sig }, { pk: good0.pk, sig: good0.sig + '=' }, { pk: good0.pk, sig: '' }, { pk: good0.pk + 'A', sig: good0.sig }];
    const v = verifyHybridThreshold(actionA, withPq([...(junk as never[]), good0, good1]), opts);
    expect(v.pq.count).toBe(2);
    expect(v.ok).toBe(true);
    // a pool padded with garbage / non-canonical keys does not admit anyone
    const poolJunk = verifyHybridThreshold(actionA, artifact, { ...opts, pqPublicKeys: ['x', '', good0.pk + '=', new Uint8Array(3) as never, 7 as never, ...pqPks.slice(0, 1)] });
    expect(poolJunk.pq.count).toBe(1);
    expect(poolJunk.ok).toBe(false);
  });

  it('pqT is the VERIFIER\'s value: the artifact\'s own pqT claim is ignored, and 0 / negative / NaN / fractional pqT fail closed', () => {
    const lying = { ...artifact, pq: { ...artifact.pq, pqT: 1 } } as HybridThresholdArtifact;
    expect(verifyHybridThreshold(actionA, withPq([good0]).pq && { ...lying, pq: { ...lying.pq, signers: [good0] } }, opts).ok).toBe(false);
    for (const bad of [0, -1, Number.NaN, 1.5, Infinity]) expect(verifyHybridThreshold(actionA, artifact, { ...opts, pqT: bad }).ok).toBe(false);
    expect(verifyHybridThreshold(actionA, artifact, { ...opts, pqT: 3 }).ok).toBe(false);
  });

  it('FROST: wrong group key, non-canonical key string, bad t, tampered / truncated / non-string signature all fail closed with a reason', () => {
    const other = group(2, 3);
    expect(verifyHybridThreshold(actionA, artifact, { ...opts, groupKey: other.gk }).frost).toBe(false);
    expect(verifyHybridThreshold(actionA, artifact, { ...opts, groupKey: b64u(fg.gk) + '=' }).reason).toMatch(/canonical/);
    expect(verifyHybridThreshold(actionA, artifact, { ...opts, groupKey: new Uint8Array(31) }).frost).toBe(false);
    for (const t of [0, -1, Number.NaN, 1.5]) expect(verifyHybridThreshold(actionA, artifact, { ...opts, t }).frost).toBe(false);
    const sigBytes = Buffer.from(artifact.frost.sig, 'base64url');
    sigBytes[0] = (sigBytes[0] ?? 0) ^ 1;
    for (const sig of [b64u(sigBytes), artifact.frost.sig.slice(0, -4), '', 5, null]) {
      expect(verifyHybridThreshold(actionA, { ...artifact, frost: { ...artifact.frost, sig: sig as string } }, opts).frost).toBe(false);
    }
    for (const frost of [undefined, null, 5, {}, { ...artifact.frost, alg: 'x' }]) {
      expect(verifyHybridThreshold(actionA, { ...artifact, frost } as never, opts).frost).toBe(false);
    }
    for (const pqb of [undefined, null, 5, {}, { alg: 'x', signers: [] }, { alg: artifact.pq.alg, signers: 'x' }]) {
      expect(verifyHybridThreshold(actionA, { ...artifact, pq: pqb } as never, opts).ok).toBe(false);
    }
  });

  it('DOWNGRADE: a lower declared FROST t is refused; and a HIGHER declared t no longer helps an attacker (the dealt threshold is attested by the signed group descriptor)', () => {
    expect(verifyHybridThreshold(actionA, { ...artifact, frost: { ...artifact.frost, t: 1 } }, opts).frost).toBe(false);
    const one = group(1, 3);
    const solo = hybridThresholdSign(actionA, { frost: { groupPublicKey: one.gk, quorum: one.quorum, t: 1 }, pqSigners: [{ keyPair: pq[0]! }], pqT: 1 });
    const relabelled = { ...solo, frost: { ...solo.frost, t: 2 } };
    // CLOSED (was a documented residual): the dealt threshold is attested by the signed group descriptor, so a
    // 1-of-3 group key presented as 2-of-3 is refused even though the aggregate itself is a valid Ed25519 signature.
    const v = verifyHybridThreshold(actionA, relabelled, { groupKey: one.gk, pqPublicKeys: pqPks, t: 2, pqT: 1, groupDescriptor: one.desc, trustedAuthorities: authorities });
    expect(v.frost).toBe(false);
    expect(v.reason).toMatch(/set up as 1-of-3 but 2 is required/);
  });

  it('signing fails closed on a short quorum, no PQ signers, an invalid group key and a non-positive t', () => {
    expect(() => hybridThresholdSign(actionA, { frost: { groupPublicKey: fg.gk, quorum: fg.quorum.slice(0, 1), t: 2 }, pqSigners: [{ keyPair: pq[0]! }] })).toThrow(RangeError);
    expect(() => hybridThresholdSign(actionA, { frost: { groupPublicKey: fg.gk, quorum: fg.quorum, t: 2 }, pqSigners: [] })).toThrow(RangeError);
    expect(() => hybridThresholdSign(actionA, { frost: { groupPublicKey: new Uint8Array(31), quorum: fg.quorum, t: 2 }, pqSigners: [{ keyPair: pq[0]! }] })).toThrow(RangeError);
    expect(() => hybridThresholdSign(actionA, { frost: { groupPublicKey: 'x', quorum: fg.quorum, t: 2 }, pqSigners: [{ keyPair: pq[0]! }] })).toThrow(RangeError);
    for (const t of [0, -1, 1.5, Number.NaN]) expect(() => hybridThresholdSign(actionA, { frost: { groupPublicKey: fg.gk, quorum: fg.quorum, t }, pqSigners: [{ keyPair: pq[0]! }] })).toThrow(RangeError);
  });
});

describe('step-up folding: the two halves cannot be mixed across actions', () => {
  const stepUp = foldHybridStepUp(actionA, artifact);
  const vopts = { grant, groupKey: fg.gk, pqPublicKeys: pqPks, t: 2, pqT: 2, groupDescriptor: fg.desc, trustedAuthorities: authorities, audience: 'aud', nowEpoch: NOW };

  it('baseline allow; a PQ block from another action, an empty block or a missing FROST share is denied', async () => {
    expect((await verifyHybridStepUp(stepUp, vopts)).allow).toBe(true);
    const artB = hybridThresholdSign(actionB, { frost: { groupPublicKey: fg.gk, quorum: fg.quorum, t: 2 }, pqSigners: [{ keyPair: pq[0]! }, { keyPair: pq[1]! }], pqT: 2 });
    expect((await verifyHybridStepUp({ ...stepUp, pq: artB.pq }, vopts)).allow).toBe(false);
    expect((await verifyHybridStepUp({ ...stepUp, pq: { ...stepUp.pq, signers: [] } }, vopts)).allow).toBe(false);
    expect((await verifyHybridStepUp({ pcactn: actionA, pq: stepUp.pq }, vopts)).allow).toBe(false);
    // FROST half from another action
    const crossed = foldHybridStepUp(actionA, { ...artifact, frost: artB.frost });
    expect((await verifyHybridStepUp(crossed, vopts)).allow).toBe(false);
  });

  it('the threshold hook is enforced and reports a precise reason for each missing half', () => {
    const hook = createHybridThresholdVerifier({ groupKey: fg.gk, pqPublicKeys: pqPks, t: 2, pqT: 2, pqBlock: artifact.pq, groupDescriptor: fg.desc, trustedAuthorities: authorities });
    const ctx = { pcactn: stepUp.pcactn } as never;
    expect(hook(ctx)).toEqual({ enforced: true, ok: true });
    const none = hook({ pcactn: actionA } as never);
    expect(none).toMatchObject({ enforced: true, ok: false });
    const noGroup = createHybridThresholdVerifier({ groupKey: 'x', pqPublicKeys: pqPks, t: 2, pqT: 2, pqBlock: artifact.pq, groupDescriptor: fg.desc, trustedAuthorities: authorities });
    expect(noGroup(ctx)).toMatchObject({ enforced: true, ok: false });
  });
});

describe('work bound', () => {
  it('a block stuffed with thousands of invalid co-signatures is processed in bounded time (entries beyond the cap are ignored)', () => {
    const stuffed = Array.from({ length: 5000 }, () => ({ pk: good0.pk, sig: good1.sig }));
    const t0 = performance.now();
    const v = verifyHybridThreshold(actionA, withPq(stuffed), opts);
    expect(performance.now() - t0).toBeLessThan(5000);
    expect(v.ok).toBe(false);
    expect(MAX_PQ_SIGNER_ENTRIES).toBeGreaterThanOrEqual(pq.length);
  });
});

describe('experimental additive-sharing toy: gated, and refuses ambiguous input', () => {
  const ok = { iUnderstandThisIsNotProduction: true } as const;
  const key = [1n, 2n, 3n, 4n];

  it('every entry point refuses to run without the explicit opt-in (including truthy-but-not-true values)', () => {
    for (const optIn of [undefined, null, {}, { iUnderstandThisIsNotProduction: false }, { iUnderstandThisIsNotProduction: 'true' }, { iUnderstandThisIsNotProduction: 1 }]) {
      expect(() => experimental.additiveShareLatticeKey(key, 3, optIn as never)).toThrow(/NOT PRODUCTION/);
      expect(() => experimental.reconstructLatticeKey([], optIn as never)).toThrow(/NOT PRODUCTION/);
    }
  });

  it('round-trips with all shares; any proper subset reconstructs a WRONG key (n-of-n, documented); a duplicated share index is refused; absurd n is refused', () => {
    const shares = experimental.additiveShareLatticeKey(key, 4, ok);
    expect(experimental.reconstructLatticeKey(shares, ok)).toEqual(key);
    expect(experimental.reconstructLatticeKey(shares.slice(0, 3), ok)).not.toEqual(key);
    expect(() => experimental.reconstructLatticeKey([shares[0]!, shares[0]!, shares[1]!, shares[2]!], ok)).toThrow(/duplicate/);
    expect(() => experimental.reconstructLatticeKey([], ok)).toThrow(RangeError);
    for (const n of [0, -1, 1.5, 1025, 2 ** 31]) expect(() => experimental.additiveShareLatticeKey(key, n, ok)).toThrow(RangeError);
    expect(() => experimental.additiveShareLatticeKey([1n], 2, ok)).toThrow(RangeError);
  });

  it('property: n-of-n reconstruction is exact for any key and any n, and no single share equals the key', () => {
    fc.assert(
      fc.property(fc.array(fc.bigInt({ min: 0n, max: 8380416n }), { minLength: 4, maxLength: 4 }), fc.integer({ min: 2, max: 8 }), (k, n) => {
        const shares = experimental.additiveShareLatticeKey(k, n, ok);
        return JSON.stringify(experimental.reconstructLatticeKey(shares, ok).map(String)) === JSON.stringify(k.map(String)) && shares.every((s) => JSON.stringify(s.coeffs.map(String)) !== JSON.stringify(k.map(String)));
      }),
      { numRuns: 100 },
    );
  });

  it('a constant sampler (RNG failure) is not detected by the toy: all but the last share are the constant (documented: toy only)', () => {
    const shares = experimental.additiveShareLatticeKey(key, 3, ok, undefined, () => 5n);
    expect(shares[0]!.coeffs).toEqual([5n, 5n, 5n, 5n]);
    expect(experimental.reconstructLatticeKey(shares, ok)).toEqual(key);
  });
});

describe('bounded fuzzing of every verify entry', () => {
  it('verifyHybridThreshold never throws on arbitrary artifacts / options and accepts only the genuine artifact', () => {
    fc.assert(
      fc.property(fc.anything(), fc.anything(), (a, o) => {
        let r;
        expect(() => {
          r = verifyHybridThreshold(actionA, a as never, o as never);
        }).not.toThrow();
        return (r as unknown as { ok: boolean }).ok === false;
      }),
      fuzzOpts,
    );
  });

  it('mutations of the genuine artifact (fields and signatures) are never accepted', () => {
    const fields = ['digest', 'frost', 'pq'] as const;
    fc.assert(
      fc.property(fc.constantFrom(...fields), fc.anything(), fc.nat({ max: 1 }), fc.nat({ max: 400 }), (f, v, which, bit) => {
        const m = JSON.parse(JSON.stringify(artifact)) as { -readonly [K in keyof HybridThresholdArtifact]: HybridThresholdArtifact[K] } & Record<string, unknown>;
        if (which === 0) m[f] = v as never;
        else {
          const s = m.pq.signers[0] as { sig: string };
          const bytes = Buffer.from(s.sig, 'base64url');
          bytes[bit % bytes.length] = (bytes[bit % bytes.length] ?? 0) ^ (1 << (bit % 8));
          s.sig = bytes.toString('base64url');
        }
        const r = verifyHybridThreshold(actionA, m, opts);
        // `digest` is informational (the verifier recomputes the message), so replacing only it may stay ok.
        if (which === 0 && f === 'digest') return true;
        return r.ok === false;
      }),
      fuzzOpts,
    );
    // direct check: a flipped ML-DSA signature bit must lose that co-signer
    const bytes = Buffer.from(good0.sig, 'base64url');
    bytes[10] = (bytes[10] ?? 0) ^ 1;
    expect(verifyHybridThreshold(actionA, withPq([{ pk: good0.pk, sig: bytes.toString('base64url') }, good1]), opts).pq.count).toBe(1);
  });

  it('verifyHybridStepUp and createHybridThresholdVerifier survive arbitrary shapes (reject, never throw an untyped error)', async () => {
    const t0 = Date.now();
    let n = 0;
    while (Date.now() - t0 < FUZZ_MS) {
      const [a, b] = fc.sample(fc.tuple(fc.anything(), fc.anything()), 1)[0] as [unknown, unknown];
      n++;
      try {
        const r = await verifyHybridStepUp(a as never, b as never);
        expect(r.allow).toBe(false);
      } catch (e) {
        expect(e instanceof Error).toBe(true);
      }
      try {
        const hook = createHybridThresholdVerifier(b as never);
        hook(a as never);
      } catch (e) {
        expect(e instanceof Error).toBe(true);
      }
    }
    expect(n).toBeGreaterThan(0);
  });
});
