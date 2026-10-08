import { describe, expect, it } from 'vitest';
import { attenuate, mintRoot } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { commitPlan, conditionsDigest } from './merkle';
import { type PCActn, signPCActn } from './pcactn';
import {
  TransparencyLedger,
  detectEquivocation,
  entryCommit,
  verifyOpening,
  verifyWitnessedHead,
  signTreeHead,
  verifyTreeHead,
  verifyHeadConsistency,
  cosignTreeHead,
  verifyWitnessCosignature,
  verifyWitnessCosignatures,
  STH_DOMAIN,
  STH_WITNESS_DOMAIN,
  ledgerRootOf,
  type SignedTreeHead,
  type WitnessCosignature,
} from './ledger';

const S = generateKeyPair();
const P = generateKeyPair();
const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(S.publicKey), caveats: [] });
const leaf = attenuate(grant, [], S.secretKey);
function act(n: number): PCActn {
  const plan = commitPlan([{ id: 'n', verb: 'read', resource: `r/${n}`, params_digest: 'p', reversibility_class: 'R0' }]);
  return signPCActn(
    {
      ver: 2,
      action: { verb: 'read', resource: `r/${n}`, params_digest: 'p', reversibility_class: 'R0' },
      grant_ref: 'g',
      cap_chain: [grant, leaf],
      plan: { root: plan.root, inclusion_proof: plan.proofFor('n'), node_id: 'n', conditions_digest: conditionsDigest(undefined, undefined) },
      attestation: { quote_digest: 'q', epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
      provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: [] },
      freshness: { beacon_ref: 'b', epoch: 1, accumulator_witness: 'w' },
      counter: n,
      risk_claim: { r: 0.1, inputs: {} },
      aud: 'rs',
      iat: 1_800_000_000_000,
      exp: 1_800_000_600_000,
    },
    S.secretKey,
  );
}
const fill = (n: number, l = new TransparencyLedger('p1')) => {
  for (let i = 0; i < n; i++) l.append(act(i), { salt: `s${i}` });
  return l;
};

describe('ledger', () => {
  it('is deterministic given salts; commit = H(salt, digest)', () => {
    expect(fill(5).head()).toEqual(fill(5).head());
    const l = fill(1);
    expect(l.entry(0).commit).toBe(entryCommit('s0', act(0)));
    expect(verifyOpening(l.entry(0).commit, l.entry(0).opening!)).toBe(true);
    expect(verifyOpening(l.entry(0).commit, { salt: 'x', pcactn: act(0) })).toBe(false);
  });
  it('random salts by default differ', () => {
    const l = new TransparencyLedger();
    expect(l.append(act(0)).commit).not.toBe(l.append(act(0)).commit);
  });
  it('empty head and append/inclusion for every size', () => {
    expect(new TransparencyLedger().head().size).toBe(0);
    for (let n = 1; n <= 13; n++) {
      const l = fill(n);
      const { root } = l.head();
      for (let i = 0; i < n; i++) {
        expect(l.verifyInclusion(root, l.inclusionProof(i), l.entry(i).commit)).toBe(true);
      }
      expect(l.verifyInclusion(root, l.inclusionProof(0), 'forged')).toBe(false);
    }
  });
  it('consistency proofs verify for all (old,new) pairs; forged fail', () => {
    const l = fill(14);
    for (let n = 0; n <= 14; n++) {
      for (let m = 0; m <= n; m++) {
        const p = l.consistencyProof(m, n);
        expect(l.verifyConsistency(l.rootAt(m), l.rootAt(n), p)).toBe(true);
      }
    }
    const p = l.consistencyProof(5, 12);
    expect(l.verifyConsistency(l.rootAt(5), l.rootAt(11), p)).toBe(false);
    expect(l.verifyConsistency(l.rootAt(4), l.rootAt(12), p)).toBe(false);
    expect(l.verifyConsistency(l.rootAt(5), l.rootAt(12), { ...p, path: [...p.path.slice(1)] })).toBe(false);
    const bad = { ...p, path: p.path.map((h, i) => (i === 0 ? l.rootAt(1) : h)) };
    expect(l.verifyConsistency(l.rootAt(5), l.rootAt(12), bad)).toBe(false);
  });
  it('a rewritten history is not consistent with the old head', () => {
    const honest = fill(8);
    const oldRoot = honest.rootAt(4);
    const forged = TransparencyLedger.fromEntries(honest.commits().map((c, i) => ({ commit: i === 2 ? 'evil' : c })));
    expect(forged.verifyConsistency(oldRoot, forged.head().root, forged.consistencyProof(4, 8))).toBe(false);
  });
  it('tampering an entry breaks the root and the stored opening audit', () => {
    const l = fill(6);
    const root = l.head().root;
    const entries = l.commits().map((commit, i) => ({ commit: i === 3 ? 'tampered' : commit }));
    expect(TransparencyLedger.fromEntries(entries).head().root).not.toBe(root);
    const t = TransparencyLedger.fromEntries(
      l.commits().map((_, i) => ({ commit: l.entry(i).commit, opening: i === 1 ? { salt: 'x', pcactn: act(1) } : l.entry(i).opening })),
    );
    expect(t.auditOpenings()).toEqual([1]);
    expect(t.head().root).toBe(root); // commits untouched
  });
  it('shred drops the opening but keeps every proof valid', () => {
    const l = fill(9);
    const before = l.head();
    const inc = l.inclusionProof(4);
    const cons = l.consistencyProof(3, 9);
    const commit = l.entry(4).commit;
    expect(l.shred(4)).toBe(true);
    expect(l.shred(4)).toBe(false);
    expect(l.entry(4).opening).toBeUndefined();
    expect(l.entry(4).commit).toBe(commit);
    expect(l.head()).toEqual(before);
    expect(l.verifyInclusion(before.root, inc, commit)).toBe(true);
    expect(l.verifyInclusion(before.root, l.inclusionProof(4), commit)).toBe(true);
    expect(l.verifyConsistency(l.rootAt(3), before.root, cons)).toBe(true);
    // growth after shredding stays consistent
    l.append(act(99));
    expect(l.verifyConsistency(before.root, l.head().root, l.consistencyProof(9, 10))).toBe(true);
    expect(l.auditOpenings()).toEqual([]);
  });
  it('witnessed heads verify, reject wrong key/tamper, and expose equivocation', () => {
    const W = generateKeyPair();
    const a = fill(4);
    const wh = a.witnessHead(W.secretKey);
    const pub = encodeKey(W.publicKey);
    expect(verifyWitnessedHead(wh, pub)).toBe(true);
    expect(verifyWitnessedHead(wh, encodeKey(generateKeyPair().publicKey))).toBe(false);
    expect(verifyWitnessedHead({ ...wh, size: 5 }, pub)).toBe(false);
    const fork = TransparencyLedger.fromEntries(a.commits().map((c, i) => ({ commit: i === 3 ? 'fork' : c })), 'p1');
    expect(detectEquivocation(wh, fork.witnessHead(W.secretKey), pub)).toBe(true);
    expect(detectEquivocation(wh, wh, pub)).toBe(false);
  });
  it('range errors', () => {
    const l = fill(3);
    expect(() => l.inclusionProof(3)).toThrow();
    expect(() => l.consistencyProof(4, 3)).toThrow();
    expect(() => l.shred(9)).toThrow();
  });
});

describe('signed tree heads (STH)', () => {
  const G = generateKeyPair();
  const gPub = encodeKey(G.publicKey);
  const headOf = (l: TransparencyLedger, size: number, prev = '') =>
    signTreeHead(G.secretKey, { instance_id: 'ins1', principal: 'p1', size, root: l.rootAt(size), prev_root: prev, timestamp: 1000 + size });

  it('signs, verifies, and is bound to the pinned guardian key + every field', () => {
    const l = fill(4);
    const h = headOf(l, 4, l.rootAt(3));
    expect(verifyTreeHead(h, gPub)).toBe(true);
    expect(verifyTreeHead(h, encodeKey(generateKeyPair().publicKey))).toBe(false);
    for (const t of [{ size: 5 }, { root: l.rootAt(3) }, { prev_root: 'x' }, { timestamp: 1 }, { principal: 'p2' }, { instance_id: 'ins2' }]) {
      expect(verifyTreeHead({ ...h, ...t }, gPub)).toBe(false);
    }
  });

  it('uses a domain distinct from the witness head (no cross-protocol signature reuse)', () => {
    expect(STH_DOMAIN).not.toBe('atlas-pca/ledger-head/v1\0');
    const l = fill(3);
    const w = l.witnessHead(G.secretKey);
    // a witness-head signature is not a valid STH signature over the same size/root
    expect(verifyTreeHead({ instance_id: '', principal: w.principal, size: w.size, root: w.root, prev_root: '', timestamp: 0, guardian: gPub, sig: w.sig }, gPub)).toBe(false);
  });

  it('pin-and-check: consistent between two appends; forged / truncated / forked heads are rejected', () => {
    const l = fill(3);
    const h3 = headOf(l, 3);
    for (let i = 3; i < 7; i++) l.append(act(i), { salt: `s${i}` });
    const h7 = headOf(l, 7, l.rootAt(6));
    const proof = l.consistencyProof(3, 7);
    expect(verifyHeadConsistency(h3, h7, proof, gPub)).toBe(true);
    // truncated: a head claiming a smaller log than the pin
    expect(verifyHeadConsistency(h7, h3, l.consistencyProof(3, 3), gPub)).toBe(false);
    // forked history: different content at the same sizes (even validly signed by the guardian) has no valid proof
    const fork = fill(3, new TransparencyLedger('p1'));
    const forkAll = TransparencyLedger.fromEntries([...fork.commits().slice(0, 2), 'evil', ...l.commits().slice(3, 7)].map((commit) => ({ commit })), 'p1');
    const hFork = headOf(forkAll, 7);
    expect(verifyHeadConsistency(h3, hFork, forkAll.consistencyProof(3, 7), gPub)).toBe(false);
    // forged signature
    expect(verifyHeadConsistency(h3, { ...h7, sig: h3.sig }, proof, gPub)).toBe(false);
    // tampered proof
    expect(verifyHeadConsistency(h3, h7, { ...proof, path: proof.path.slice(1) }, gPub)).toBe(false);
    // mismatched sizes in the proof
    expect(verifyHeadConsistency(h3, h7, { ...proof, oldSize: 2 }, gPub)).toBe(false);
    // roots match the library helper
    expect(h7.root).toBe(ledgerRootOf(l.commits()));
  });

  it('enforces the SIGNED prev_root hash-chain for consecutive heads (prev_root is no longer decorative)', () => {
    const l = fill(7);
    const h6 = headOf(l, 6, l.rootAt(5));
    const h7 = headOf(l, 7, l.rootAt(6)); // correct chain: prev_root === h6.root
    const proof = l.consistencyProof(6, 7);
    // Sanity: the correct chain links prev_root -> the predecessor's root.
    expect(h7.prev_root).toBe(h6.root);
    expect(verifyHeadConsistency(h6, h7, proof, gPub)).toBe(true);

    // A newer STH carrying a WRONG prev_root is rejected EVEN THOUGH it is validly guardian-signed AND the
    // Merkle consistency proof itself is valid — the hash chain and the proof must agree.
    const brokenChain = headOf(l, 7, l.rootAt(3)); // genuinely signed, but prev_root != h6.root
    expect(verifyTreeHead(brokenChain, gPub)).toBe(true); // the guardian really signed this head
    expect(l.verifyConsistency(l.rootAt(6), l.rootAt(7), proof)).toBe(true); // the consistency proof is valid
    expect(verifyHeadConsistency(h6, brokenChain, proof, gPub)).toBe(false); // but the chain link is broken

    // Even an EMPTY prev_root on a consecutive head is rejected (a forged proof cannot paper over it).
    const emptyPrev = headOf(l, 7, '');
    expect(verifyTreeHead(emptyPrev, gPub)).toBe(true);
    expect(verifyHeadConsistency(h6, emptyPrev, proof, gPub)).toBe(false);

    // A non-adjacent (skip-ahead) pin still verifies via the consistency proof alone: prev_root there
    // links to an intermediate STH we never pinned, so it is not asserted against older.root.
    const h3 = headOf(l, 3, l.rootAt(2));
    expect(h7.prev_root).not.toBe(h3.root); // the chain link genuinely differs across the skip
    expect(verifyHeadConsistency(h3, h7, l.consistencyProof(3, 7), gPub)).toBe(true);
  });
});

describe('STH external witness cosignatures (C2SP anti-equivocation)', () => {
  const G = generateKeyPair();
  const gPub = encodeKey(G.publicKey);
  const W1 = generateKeyPair();
  const W2 = generateKeyPair();
  const W3 = generateKeyPair();
  const k1 = encodeKey(W1.publicKey);
  const k2 = encodeKey(W2.publicKey);
  const k3 = encodeKey(W3.publicKey);
  const headOf = (l: TransparencyLedger, size: number, prev = '') =>
    signTreeHead(G.secretKey, { instance_id: 'ins1', principal: 'p1', size, root: l.rootAt(size), prev_root: prev, timestamp: 1000 + size });
  const withW = (h: SignedTreeHead, ws: WitnessCosignature[]): SignedTreeHead => ({ ...h, witnesses: ws });

  it('uses a domain distinct from the STH and legacy witness-head domains', () => {
    expect(STH_WITNESS_DOMAIN).not.toBe(STH_DOMAIN);
    expect(STH_WITNESS_DOMAIN).not.toBe('atlas-pca/ledger-head/v1\0');
  });

  it('a cosignature verifies against the witness key and is bound to the exact (size, root)', () => {
    const l = fill(4);
    const h = headOf(l, 4, l.rootAt(3));
    const c = cosignTreeHead(h, W1.secretKey);
    expect(c.key).toBe(k1);
    expect(verifyWitnessCosignature(h, c, k1)).toBe(true);
    // the cosignature is NOT a guardian signature and does not re-use its bytes
    expect(c.sig).not.toBe(h.sig);
    // verified only against the cosigning witness' own key
    expect(verifyWitnessCosignature(h, c, k2)).toBe(false);
    expect(verifyWitnessCosignature(h, { ...c, key: k2 }, k2)).toBe(false);
    // a cosignature for a DIFFERENT (size, root) does not verify against this head
    const cForSize3 = cosignTreeHead(headOf(l, 3, l.rootAt(2)), W1.secretKey);
    expect(verifyWitnessCosignature(h, cForSize3, k1)).toBe(false);
    expect(verifyWitnessCosignature({ ...h, size: 5 }, c, k1)).toBe(false);
    expect(verifyWitnessCosignature({ ...h, root: l.rootAt(3) }, c, k1)).toBe(false);
    expect(verifyWitnessCosignature({ ...h, prev_root: 'x' }, c, k1)).toBe(false);
    // a tampered signature is rejected
    expect(verifyWitnessCosignature(h, { ...c, sig: cForSize3.sig }, k1)).toBe(false);
  });

  it('k-of-n: threshold met ⇒ ok; k−1 ⇒ fail; duplicate counted once; unknown ignored; tampered rejected', () => {
    const l = fill(5);
    const h = headOf(l, 5, l.rootAt(4));
    const c1 = cosignTreeHead(h, W1.secretKey);
    const c2 = cosignTreeHead(h, W2.secretKey);
    const policy = { witnessKeys: [k1, k2, k3], threshold: 2 };

    // two DISTINCT trusted cosignatures meet the threshold
    expect(verifyWitnessCosignatures(withW(h, [c1, c2]), policy)).toBe(true);
    // k−1 (one short) fails
    expect(verifyWitnessCosignatures(withW(h, [c1]), policy)).toBe(false);
    // a DUPLICATE trusted key counts once -> still only one distinct witness -> fail
    expect(verifyWitnessCosignatures(withW(h, [c1, { ...c1 }]), policy)).toBe(false);
    // an UNKNOWN witness is ignored: unknown + one trusted -> one distinct -> fail
    const unknown = cosignTreeHead(h, generateKeyPair().secretKey);
    expect(verifyWitnessCosignatures(withW(h, [unknown, c1]), policy)).toBe(false);
    // ...but the unknown never blocks a genuine quorum
    expect(verifyWitnessCosignatures(withW(h, [unknown, c1, c2]), policy)).toBe(true);
    // a TAMPERED cosignature for a trusted key does not count -> quorum falls short -> fail
    const tampered: WitnessCosignature = { key: k2, sig: cosignTreeHead(headOf(l, 4, l.rootAt(3)), W2.secretKey).sig };
    expect(verifyWitnessCosignature(h, tampered, k2)).toBe(false);
    expect(verifyWitnessCosignatures(withW(h, [c1, tampered]), policy)).toBe(false);
    // three distinct trusted cosignatures also clear a threshold of 2 (and of 3)
    const c3 = cosignTreeHead(h, W3.secretKey);
    expect(verifyWitnessCosignatures(withW(h, [c1, c2, c3]), policy)).toBe(true);
    expect(verifyWitnessCosignatures(withW(h, [c1, c2, c3]), { ...policy, threshold: 3 })).toBe(true);
    expect(verifyWitnessCosignatures(withW(h, [c1, c2]), { ...policy, threshold: 3 })).toBe(false);

    // degenerate policies are fail-closed except the vacuous threshold 0
    expect(verifyWitnessCosignatures(h, { witnessKeys: [k1], threshold: 0 })).toBe(true);
    expect(verifyWitnessCosignatures(h, policy)).toBe(false); // no witnesses[] at all
    expect(verifyWitnessCosignatures(withW(h, [c1, c2]), { witnessKeys: [], threshold: 1 })).toBe(false);
    expect(verifyWitnessCosignatures(withW(h, [c1, c2]), { witnessKeys: [k1, k2], threshold: -1 })).toBe(false);
  });

  it('an STH with no witnesses still verifies and the guardian-signed bytes are byte-identical to before', () => {
    const l = fill(4);
    const h = headOf(l, 4, l.rootAt(3));
    expect(h.witnesses).toBeUndefined();
    expect('witnesses' in h).toBe(false);
    expect(verifyTreeHead(h, gPub)).toBe(true);

    // re-signing the identical statement is byte-identical (Ed25519 is deterministic; witnesses never leak into signing)
    const resigned = signTreeHead(G.secretKey, {
      instance_id: 'ins1',
      principal: 'p1',
      size: 4,
      root: l.rootAt(4),
      prev_root: l.rootAt(3),
      timestamp: 1004,
    });
    expect(resigned).toEqual(h);

    // attaching cosignatures changes NO signed field and the guardian check still passes
    const cosigned = withW(h, [cosignTreeHead(h, W1.secretKey), cosignTreeHead(h, W2.secretKey)]);
    expect(cosigned.sig).toBe(h.sig);
    const { witnesses: _w, ...signed } = cosigned;
    expect(signed).toEqual(h);
    expect(verifyTreeHead(cosigned, gPub)).toBe(true);
  });

  it('requireWitnessThreshold gates verifyTreeHead and verifyHeadConsistency (opt-in only)', () => {
    const l = fill(5);
    const policy = { witnessKeys: [k1, k2], threshold: 2 };
    const h5 = headOf(l, 5, l.rootAt(4));
    const h2 = headOf(l, 2, l.rootAt(1));
    const cosign = (h: SignedTreeHead) => withW(h, [cosignTreeHead(h, W1.secretKey), cosignTreeHead(h, W2.secretKey)]);
    const proof = l.consistencyProof(2, 5);

    // no requirement: a witness-less head verifies exactly as today (backward compat)
    expect(verifyTreeHead(h5, gPub)).toBe(true);
    expect(verifyHeadConsistency(h2, h5, proof, gPub)).toBe(true);
    // requirement supplied but head carries no quorum -> refused
    expect(verifyTreeHead(h5, gPub, policy)).toBe(false);
    expect(verifyHeadConsistency(h2, h5, proof, gPub, policy)).toBe(false);
    // cosigned to quorum -> accepted
    expect(verifyTreeHead(cosign(h5), gPub, policy)).toBe(true);
    expect(verifyHeadConsistency(cosign(h2), cosign(h5), proof, gPub, policy)).toBe(true);
    // BOTH heads must meet the threshold: older cosigned, newer not -> refused
    expect(verifyHeadConsistency(cosign(h2), h5, proof, gPub, policy)).toBe(false);
    expect(verifyHeadConsistency(h2, cosign(h5), proof, gPub, policy)).toBe(false);
  });

  it('split view: two conflicting roots at the same size cannot both gather an honest-witness threshold', () => {
    const l = fill(4);
    const hA = headOf(l, 4, l.rootAt(3));
    // the operator equivocates: a fork of the SAME size, SAME guardian, DIFFERENT root
    const fork = TransparencyLedger.fromEntries(l.commits().map((c, i) => ({ commit: i === 2 ? 'evil' : c })), 'p1');
    const hB = signTreeHead(G.secretKey, { instance_id: 'ins1', principal: 'p1', size: 4, root: fork.rootAt(4), prev_root: fork.rootAt(3), timestamp: 1004 });
    expect(hA.root).not.toBe(hB.root);
    expect(verifyTreeHead(hA, gPub)).toBe(true); // both are genuinely guardian-signed
    expect(verifyTreeHead(hB, gPub)).toBe(true);

    // honest witnesses cosign the FIRST root they see at a given size and refuse a second, conflicting root
    const honest = [W1, W2, W3];
    const seen = new Map<string, string>();
    const cosignHonest = (W: ReturnType<typeof generateKeyPair>, h: SignedTreeHead): WitnessCosignature | null => {
      const key = encodeKey(W.publicKey);
      const prior = seen.get(`${h.size}:${key}`);
      if (prior !== undefined && prior !== h.root) return null; // refuse to equivocate
      seen.set(`${h.size}:${key}`, h.root);
      return cosignTreeHead(h, W.secretKey);
    };
    const isC = (c: WitnessCosignature | null): c is WitnessCosignature => c !== null;
    const aCosigs = honest.map((W) => cosignHonest(W, hA)).filter(isC);
    const bCosigs = honest.map((W) => cosignHonest(W, hB)).filter(isC); // every honest witness now refuses
    expect(aCosigs.length).toBe(3);
    expect(bCosigs.length).toBe(0);

    const policy = { witnessKeys: [k1, k2, k3], threshold: 2 };
    expect(verifyWitnessCosignatures(withW(hA, aCosigs), policy)).toBe(true);
    expect(verifyWitnessCosignatures(withW(hB, bCosigs), policy)).toBe(false);
    // replaying hA's cosignatures onto hB does not help: they are bound to hA's root and do not verify for hB
    expect(verifyWitnessCosignatures(withW(hB, aCosigs), policy)).toBe(false);
  });
});
