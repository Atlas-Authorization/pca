import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import {
  TransparencyLedger,
  signTreeHead,
  verifyHeadConsistency,
  verifyTreeHead,
} from './ledger';
import {
  AttestedStateSource,
  InMemoryStateSource,
  ProgressTracker,
  type Goal,
  type StateAttestation,
  anchorTrajectoryHead,
  attestedStateVerifier,
  commitGoal,
  trajectoryAnchorCommit,
  trajectoryHead,
  verifyProgressStep,
  verifyStateAttestation,
  verifyTrajectoryAnchor,
} from './progress';

const G = generateKeyPair();
const Gpub = encodeKey(G.publicKey);
const SRC = generateKeyPair();

const goal: Goal = { objective: { target: [0] }, potential: 'l1-feature-v1', metric: 'l1', epsilon: 1, explorationBudget: 0 };
const { commitment } = commitGoal(goal);

// ---- A2g: anchor the trajectory head into the transparency ledger ----------------------------
describe('A2g: anchorTrajectoryHead', () => {
  it('appends the current head as a verifiable commitment', () => {
    const t = new ProgressTracker(goal, commitment, { x: [2] });
    expect(t.step({ x: [1] }, 'act1').ok).toBe(true);
    expect(t.step({ x: [0] }, 'act2').ok).toBe(true);
    const tl = new TransparencyLedger('traj');
    const anchor = anchorTrajectoryHead(tl, t.steps, { salt: 's' });
    expect(anchor.head).toBe(trajectoryHead(t.steps));
    expect(anchor.commit).toBe(trajectoryAnchorCommit('s', anchor.head));
    expect(verifyTrajectoryAnchor(anchor.commit, anchor.salt, anchor.head)).toBe(true);
    expect(verifyTrajectoryAnchor(anchor.commit, anchor.salt, 'genesis')).toBe(false); // wrong head
    expect(tl.verifyInclusion(tl.head().root, tl.inclusionProof(anchor.index), anchor.commit)).toBe(true);
  });

  it('makes a ROLLBACK externally detectable via a pinned, signed STH chain', () => {
    const t = new ProgressTracker(goal, commitment, { x: [2] });
    t.step({ x: [1] }, 'act1');
    const tl = new TransparencyLedger('traj');
    anchorTrajectoryHead(tl, t.steps, { salt: 's1' }); // head after 1 step
    const sth1 = signTreeHead(G.secretKey, { instance_id: 'i', principal: 'traj', size: tl.size, root: tl.head().root, prev_root: '', timestamp: 1 });

    t.step({ x: [0] }, 'act2');
    anchorTrajectoryHead(tl, t.steps, { salt: 's2' }); // head after 2 steps
    const sth2 = signTreeHead(G.secretKey, { instance_id: 'i', principal: 'traj', size: tl.size, root: tl.head().root, prev_root: sth1.root, timestamp: 2 });

    expect(verifyTreeHead(sth2, Gpub)).toBe(true);
    expect(verifyHeadConsistency(sth1, sth2, tl.consistencyProof(1, 2), Gpub)).toBe(true);

    // a rolled-back log that dropped the later head cannot reproduce the pinned STH2 root
    const rolled = TransparencyLedger.fromEntries([tl.entry(0)], 'traj');
    expect(rolled.head().root).not.toBe(sth2.root);
    expect(rolled.head().root).toBe(sth1.root);
  });

  it('trajectoryAnchorCommit refuses empty salt/head', () => {
    expect(() => trajectoryAnchorCommit('', 'h')).toThrow();
    expect(() => trajectoryAnchorCommit('s', '')).toThrow();
  });
});

// ---- A2k: a production-grade ATTESTED StateSource --------------------------------------------
describe('A2k: AttestedStateSource + attestedStateVerifier', () => {
  async function runGood() {
    const t = new ProgressTracker(goal, commitment, { x: [2] });
    let world: unknown = { x: [1] };
    const src = new AttestedStateSource({ id: 'rs-1', signerSecret: SRC.secretKey, observeState: () => world });
    const r1 = await t.stepObserved(src, 'act1');
    expect(r1.ok).toBe(true);
    world = { x: [0] };
    const r2 = await t.stepObserved(src, 'act2');
    expect(r2.ok).toBe(true);
    return { t, src };
  }

  it('signs observations; a trusted-key verifier accepts every attested step', async () => {
    const { t, src } = await runGood();
    const verifier = attestedStateVerifier({ trustedKeys: { 'rs-1': src.publicKey }, attestations: src.attestations });
    for (const step of t.steps) {
      const vr = verifyProgressStep(goal, commitment, step, { trustedStateSources: ['rs-1'], attestation: verifier });
      expect(vr.ok).toBe(true);
    }
    // the attestation itself verifies and is bound to the exact transition
    const att = src.attestations[0]!;
    expect(verifyStateAttestation(att, src.publicKey)).toBe(true);
    expect(att.source).toBe('rs-1');
    expect(att.state_digest).toBe(t.steps[0]!.after_digest);
  });

  it('a self-reported InMemoryStateSource step is rejected by the allowlist', async () => {
    const t = new ProgressTracker(goal, commitment, { x: [2] });
    const inmem = new InMemoryStateSource({ x: [1] }, 'in-memory');
    const r = await t.stepObserved(inmem, 'act1');
    expect(r.ok).toBe(true);
    const vr = verifyProgressStep(goal, commitment, t.steps[0]!, { trustedStateSources: ['rs-1'] });
    expect(vr).toEqual({ ok: false, reason: 'untrusted-state-source' });
  });

  it('a TAMPERED attestation signature fails closed', async () => {
    const { t, src } = await runGood();
    const good = src.attestations[0]!;
    expect(verifyStateAttestation(good, src.publicKey)).toBe(true);
    const tampered: StateAttestation = { ...good, sig: b64u(new Uint8Array(64)) }; // valid length, wrong bytes
    expect(verifyStateAttestation(tampered, src.publicKey)).toBe(false);
    // and a verifier fed the tampered attestation rejects the step (evidence_digest no longer matches)
    const verifier = attestedStateVerifier({ trustedKeys: { 'rs-1': src.publicKey }, attestations: [tampered] });
    const vr = verifyProgressStep(goal, commitment, t.steps[0]!, { trustedStateSources: ['rs-1'], attestation: verifier });
    expect(vr).toEqual({ ok: false, reason: 'attestation-failed' });
  });

  it('a wrong trusted key, a missing attestation, and an untrusted source all fail closed', async () => {
    const { t, src } = await runGood();
    const other = generateKeyPair();
    expect(verifyStateAttestation(src.attestations[0]!, encodeKey(other.publicKey))).toBe(false);

    const missing = attestedStateVerifier({ trustedKeys: { 'rs-1': src.publicKey }, attestations: [] });
    expect(verifyProgressStep(goal, commitment, t.steps[0]!, { trustedStateSources: ['rs-1'], attestation: missing }).ok).toBe(false);

    const untrusted = attestedStateVerifier({ trustedKeys: {}, attestations: src.attestations });
    expect(verifyProgressStep(goal, commitment, t.steps[0]!, { trustedStateSources: ['rs-1'], attestation: untrusted }).ok).toBe(false);
  });

  it('rejects malformed construction (fail closed)', () => {
    expect(() => new AttestedStateSource({ id: '', signerSecret: SRC.secretKey, observeState: () => ({}) })).toThrow();
    expect(() => new AttestedStateSource({ id: 'x', signerSecret: 'nope' as unknown as Uint8Array, observeState: () => ({}) })).toThrow();
  });
});
