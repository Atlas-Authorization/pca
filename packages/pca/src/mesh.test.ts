import { describe, expect, it } from 'vitest';
import { type Capability, type Caveat, capHash, delegate, mintRoot } from './capability';
import { b64u, canonicalBytes, hashCanonical, unb64u, utf8 } from './hash';
import { encodeKey, publicKeyOf, sign } from './keys';
import { debitConsolidated } from './risk';
import {
  anchorCrossReference,
  allocateSub,
  assembleMeshProof,
  buildMeshExample,
  checkHeadAdvance,
  type CosignedHead,
  createFederatedBudget,
  type CrossReference,
  crossReferenceCommit,
  demonstrateForkRejection,
  type FederatedBudgetState,
  federatedSafetyBound,
  keyRevocationId,
  type MeshAction,
  MeshDomain,
  type MeshExample,
  type MeshHead,
  type MeshProof,
  MeshWitness,
  meshActionDigest,
  meshProofSize,
  revocationLatencyBound,
  spendFederated,
  translateCapability,
  type TranslatedCapability,
  translatedEffectiveAuthority,
  verifyCrossReference,
  verifyMeshProof,
  verifyTranslatedCapability,
} from './mesh';

const pub = (s: Uint8Array) => encodeKey(publicKeyOf(s));

/** A validly SIGNED hop built by a malicious holder (bypasses delegate's append-only helper). */
function forgeHop(parent: Capability, holder: string, caveats: Capability['caveats'], signer: Uint8Array): Capability {
  const body = { issuer: parent.holder, holder, caveats, parent: capHash(parent) };
  const digest = hashCanonical(body);
  const p = utf8('atlas-pca/cap/v1\0');
  const d = unb64u(digest);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return { id: digest, issuer: body.issuer, holder, caveats, parent: body.parent, body_digest: digest, sig: b64u(sign(signer, m)) };
}

/** Rebuild the example's proof from (possibly replaced) evidence. */
function rebuild(ex: MeshExample, evidence = ex.evidence, action = ex.proof.action): MeshProof {
  return assembleMeshProof({ chain: ex.chain, hops: evidence, action, leafSecret: ex.keys.leaf });
}

describe('mesh: valid cross-domain chain', () => {
  it('verifies a 4-hop, 3-org chain offline and roots in the human', () => {
    const ex = buildMeshExample();
    const v = verifyMeshProof(ex.proof, ex.trust);
    expect(v).toMatchObject({ ok: true, root_principal: pub(ex.keys.human), leaf: pub(ex.keys.leaf) });
    expect(v.trace).toHaveLength(4);
    expect(v.trace.map((h) => h.domain)).toEqual([ex.domains.A.id, ex.domains.A.id, ex.domains.B.id, ex.domains.C.id]);
    expect(v.trace.map((h) => h.crosses_boundary)).toEqual([false, true, true, false]);
    expect(v.trace.map((h) => h.effective.maxAmount)).toEqual([500, 100, 100, 50]);
    expect(v.trace[3]!.effective.actions).toEqual(['payments.refund']);
    expect(v.trace[0]!.issuer).toBe(pub(ex.keys.human));
  });

  it('shares ONE head across the two hops issued in org A', () => {
    const ex = buildMeshExample();
    expect(ex.proof.heads).toHaveLength(3);
    expect(ex.proof.hops[0]!.head).toBe(ex.proof.hops[1]!.head);
  });

  it('rejects a different expected human', () => {
    const ex = buildMeshExample();
    const v = verifyMeshProof(ex.proof, { ...ex.trust, humanPrincipal: pub(ex.keys.tool) });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/root issuer/);
  });

  it('rejects an action outside the leaf ceiling / scope / audience / expiry', () => {
    const ex = buildMeshExample();
    const mk = (a: Partial<MeshProof['action']>) => rebuild(ex, ex.evidence, { ...ex.proof.action, ...a });
    expect(verifyMeshProof(mk({ amount: 60 }), ex.trust).reason).toMatch(/amount/);
    const { amount: _drop, ...noAmount } = ex.proof.action;
    expect(verifyMeshProof(rebuild(ex, ex.evidence, noAmount), ex.trust).reason).toMatch(/amount/);
    expect(verifyMeshProof(mk({ type: 'orders.read' }), ex.trust).reason).toMatch(/scope/);
    expect(verifyMeshProof(mk({ resource: '/orders/43/x' }), ex.trust).reason).toMatch(/prefix/);
    expect(verifyMeshProof(mk({ service_domain: ex.domains.A.id }), ex.trust).reason).toMatch(/audience/);
    // expired capability (heads would be stale first, so widen the freshness window)
    const late = { ...ex.trust, now: ex.trust.now + 2 * 3_600_000, maxHeadAgeMs: 10 * 3_600_000 };
    expect(verifyMeshProof(mk({ at: late.now }), late).reason).toMatch(/expired/);
  });

  it('rejects an action not signed by the tip holder', () => {
    const ex = buildMeshExample();
    const bad = assembleMeshProof({ chain: ex.chain, hops: ex.evidence, action: ex.proof.action, leafSecret: ex.keys.tool });
    expect(verifyMeshProof(bad, ex.trust).reason).toMatch(/tip holder/);
  });
});

describe('mesh: attenuation violations', () => {
  const widen = (ex: MeshExample, caveats: (c1: Capability) => Capability['caveats']) => {
    const [root, c1] = ex.chain;
    const wide = forgeHop(c1!, pub(ex.keys.service), caveats(c1!), ex.keys.tool);
    ex.domains.B.record(wide);
    const hB = ex.domains.B.publishHead(ex.witnesses, ex.trust.now - 500);
    const evidence = [ex.evidence[0]!, ex.evidence[1]!, ex.domains.B.evidence(wide, hB, ex.bindings.tool)];
    return assembleMeshProof({ chain: [root!, c1!, wide], hops: evidence, action: ex.proof.action, leafSecret: ex.keys.service });
  };

  it('rejects a hop that drops a parent caveat (widening)', () => {
    const ex = buildMeshExample();
    const v = verifyMeshProof(widen(ex, (c1) => [c1.caveats[0]!]), ex.trust);
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/drops parent caveat/);
  });

  it('rejects a hop that edits a parent caveat to a larger ceiling', () => {
    const ex = buildMeshExample();
    const p = widen(ex, (c1) => c1.caveats.map((c) => (c.type === 'max_amount' ? { ...c, max: 10_000 } : c)));
    expect(verifyMeshProof(p, ex.trust).reason).toMatch(/altered or reordered/);
  });

  it('rejects an unknown caveat type (fail closed)', () => {
    const ex = buildMeshExample();
    expect(verifyMeshProof(widen(ex, (c1) => [...c1.caveats, { type: 'mystery' }]), ex.trust).reason).toMatch(/unknown caveat/);
  });
});

describe('mesh: k-of-n witness threshold + cross-org anchors (no central authority)', () => {
  it('rejects when the source domain head lacks enough trusted witness cosignatures', () => {
    const ex = buildMeshExample();
    const v = verifyMeshProof(ex.proof, { ...ex.trust, witnesses: [ex.trust.witnesses[0]!, pub(new Uint8Array(32).fill(7))] });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/source-domain anchor: head has 1\/2/);
    expect(v.hop).toBe(0);
  });

  it('enforces the threshold exactly: k-1 fails, k passes, 3-of-3 passes with all cosigs', () => {
    const ex = buildMeshExample();
    expect(verifyMeshProof(ex.proof, { ...ex.trust, threshold: 3 }).ok).toBe(true);
    const only1 = structuredClone(ex.proof);
    for (const h of only1.heads) h.cosigs = h.cosigs.slice(0, 1);
    expect(verifyMeshProof(only1, { ...ex.trust, threshold: 1 }).ok).toBe(true);
    expect(verifyMeshProof(only1, { ...ex.trust, threshold: 2 }).reason).toMatch(/1\/2/);
  });

  it('does not count one witness twice (duplicate cosignatures)', () => {
    const ex = buildMeshExample();
    const p = structuredClone(ex.proof);
    for (const h of p.heads) h.cosigs = [h.cosigs[0]!, h.cosigs[0]!, h.cosigs[0]!];
    expect(verifyMeshProof(p, ex.trust).reason).toMatch(/1\/2/);
  });

  it('rejects a head cosigned only by unpinned (attacker) witnesses', () => {
    const ex = buildMeshExample();
    const rogue = [new MeshWitness(new Uint8Array(32).fill(1)), new MeshWitness(new Uint8Array(32).fill(2))];
    const evil = new MeshDomain('evil-B', new Uint8Array(32).fill(9));
    const c2 = ex.chain[2]!;
    evil.record(c2);
    const h = evil.publishHead(rogue, ex.trust.now - 100);
    const evidence = [...ex.evidence];
    evidence[2] = evil.evidence(c2, h, evil.enroll(c2.issuer, 'tool-agent'));
    const v = verifyMeshProof(rebuild(ex, evidence), ex.trust);
    expect(v.reason).toMatch(/source-domain anchor/);
    expect(v.hop).toBe(2);
  });

  it('rejects a tampered head or a head presented for another domain', () => {
    const ex = buildMeshExample();
    const p = structuredClone(ex.proof);
    p.heads[p.hops[2]!.head]!.head.size += 1;
    expect(verifyMeshProof(p, ex.trust).reason).toMatch(/source-domain anchor: head not signed/);
    const p2 = structuredClone(ex.proof);
    p2.heads[p2.hops[2]!.head] = ex.heads.A;
    expect(verifyMeshProof(p2, ex.trust).reason).toMatch(/different domain/);
  });

  it('rejects a hop that was never logged by its issuing domain', () => {
    const ex = buildMeshExample();
    const p = structuredClone(ex.proof);
    p.hops[1]!.inclusion = ex.proof.hops[0]!.inclusion;
    expect(verifyMeshProof(p, ex.trust).reason).toMatch(/not included/);
  });

  it('rejects a domain not allowed by policy', () => {
    const ex = buildMeshExample();
    expect(verifyMeshProof(ex.proof, { ...ex.trust, allowedDomains: [ex.domains.A.id, ex.domains.C.id] }).reason).toMatch(/not allowed/);
  });

  it('rejects an issuer key not vouched for by the issuing domain', () => {
    const ex = buildMeshExample();
    const p = structuredClone(ex.proof);
    p.hops[2]!.binding = { ...p.hops[2]!.binding!, agent: pub(ex.keys.service) };
    expect(verifyMeshProof(p, ex.trust).reason).toMatch(/binding/);
    delete p.hops[2]!.binding;
    expect(verifyMeshProof(p, ex.trust).reason).toMatch(/binding/);
  });

  it('rejects an unreferenced extra head and a missing head table entry', () => {
    const ex = buildMeshExample();
    const extra = structuredClone(ex.proof);
    extra.heads.push(ex.heads.A0);
    expect(verifyMeshProof(extra, ex.trust).reason).toMatch(/head/);
    const missing = structuredClone(ex.proof);
    missing.heads.pop();
    expect(verifyMeshProof(missing, ex.trust).ok).toBe(false);
  });
});

describe('mesh: witness verifies REAL RFC 9162 consistency between successive heads', () => {
  it('cosigns an honest extension (1 -> 2 in the example, every witness)', () => {
    const ex = buildMeshExample();
    for (const w of ex.witnesses) expect(w.lastSeen(ex.domains.A.id)).toMatchObject({ size: 2 });
    expect(checkHeadAdvance(ex.heads.A0.head, ex.heads.A.head, ex.domains.A.consistencyProof(1, 2))).toBeUndefined();
  });

  it('the demonstrated fork (rewritten history, grown PAST the prior size) is rejected via the consistency proof', () => {
    const d = demonstrateForkRejection();
    expect(d).toMatchObject({ honest_extension_cosigned: true, fork_larger_than_prior: true, size_only_check_would_accept: true, fork_rejected: true });
    expect(d.fork_reason).toMatch(/not consistent/);
  });

  it('rejects an inconsistent fork even with a well-formed but wrong proof path', () => {
    const k = new Uint8Array(32).fill(4);
    const ex = buildMeshExample();
    const w = new MeshWitness(new Uint8Array(32).fill(3));
    const honest = new MeshDomain('X', k);
    honest.record(ex.chain[0]!);
    honest.record(ex.chain[1]!);
    honest.publishHead([w], 100);
    const fork = new MeshDomain('X', k);
    fork.record(ex.chain[2]!);
    fork.record(ex.chain[1]!);
    fork.record(ex.chain[0]!);
    expect(() => fork.publishHead([w], 200)).toThrow(/not consistent/);
    // the witness state is untouched by the refusal
    expect(w.lastSeen(honest.id)).toMatchObject({ size: 2, timestamp: 100 });
  });

  it('refuses a larger head with no / mismatched / garbage consistency proof', () => {
    const ex = buildMeshExample();
    const w = new MeshWitness(new Uint8Array(32).fill(3));
    const d = new MeshDomain('X', new Uint8Array(32).fill(4));
    d.record(ex.chain[0]!);
    d.publishHead([w], 100);
    d.record(ex.chain[1]!);
    const ch = d.publishHead([new MeshWitness(new Uint8Array(32).fill(5))], 200); // fresh witness: TOFU
    const rev_ids: string[] = [];
    expect(() => w.cosign({ head: ch, rev_ids })).toThrow(/consistency proof required/);
    expect(() => w.cosign({ head: ch, rev_ids, consistency: { oldSize: 1, newSize: 2, path: ['AAAA'] } })).toThrow(/not consistent/);
    expect(() => w.cosign({ head: ch, rev_ids, consistency: { oldSize: 0, newSize: 2, path: [] } })).toThrow(/consistency proof required/);
    expect(() => w.cosign({ head: ch, rev_ids, consistency: { oldSize: 1, newSize: 2, path: 7 as never } })).toThrow();
    expect(w.cosign({ head: ch, rev_ids, consistency: d.consistencyProof(1, 2) }).witness).toBe(w.id);
  });

  it('refuses equivocation (same size, different log) and rollback', () => {
    const w = new MeshWitness(new Uint8Array(32).fill(3));
    const d = new MeshDomain('X', new Uint8Array(32).fill(4));
    const ex = buildMeshExample();
    d.record(ex.chain[0]!);
    d.publishHead([w], 100);
    const fork = new MeshDomain('X', new Uint8Array(32).fill(4));
    fork.record(ex.chain[1]!);
    expect(() => fork.publishHead([w], 200)).toThrow(/equivocation/);
    const empty = new MeshDomain('X', new Uint8Array(32).fill(4));
    expect(() => empty.publishHead([w], 300)).toThrow(/rolls back/);
  });

  it('refuses a revocation list that does not match, drops a prior revocation, or equivocates', () => {
    const w = new MeshWitness(new Uint8Array(32).fill(3));
    const k = new Uint8Array(32).fill(4);
    const ex = buildMeshExample();
    const d = new MeshDomain('X', k);
    d.record(ex.chain[0]!);
    d.revoke('x');
    const h1 = d.publishHead([w], 100);
    expect(() => w.cosign({ head: h1, rev_ids: [] })).toThrow(/revocation list does not match/);
    const swap = new MeshDomain('X', k); // same log, revokes y instead of x (same size)
    swap.record(ex.chain[0]!);
    swap.revoke('y');
    expect(() => swap.publishHead([w], 200)).toThrow(/equivocation \(revocation set\)/);
    const drop = new MeshDomain('X', k); // bigger revocation set that no longer contains x
    drop.record(ex.chain[0]!);
    drop.revoke('y');
    drop.revoke('z');
    expect(() => drop.publishHead([w], 300)).toThrow(/drops a previously cosigned revocation/);
  });

  it('refuses a regressing timestamp, a forged domain signature and future-dated heads (with a clock)', () => {
    const ex = buildMeshExample();
    const w = new MeshWitness(new Uint8Array(32).fill(3), { clock: () => 1_000, maxClockSkewMs: 100 });
    const d = new MeshDomain('X', new Uint8Array(32).fill(4));
    d.record(ex.chain[0]!);
    expect(() => d.publishHead([w], 5_000)).toThrow(/future/);
    d.publishHead([w], 1_000);
    expect(() => d.publishHead([w], 900)).toThrow(/timestamp regresses/);
    const ch = d.publishHead([w], 1_050); // heartbeat: same log, newer timestamp
    const forged: CosignedHead = { ...ch, head: { ...ch.head, timestamp: 1_060 } };
    expect(() => w.cosign({ head: forged, rev_ids: [] })).toThrow(/not signed by its domain/);
  });

  it('persists and restores witness memory; refuses corrupt state', () => {
    const ex = buildMeshExample();
    const w = ex.witnesses[0]!;
    const w2 = new MeshWitness(seed(1));
    w2.importState(w.exportState());
    expect(w2.lastSeen(ex.domains.A.id)).toEqual(w.lastSeen(ex.domains.A.id));
    expect(() => w2.importState({ seen: [{ head: ex.heads.A.head, rev_ids: ['bogus'] }] })).toThrow(/malformed state/);
    expect(() => w2.importState({ seen: [{ head: null as never, rev_ids: [] }] })).toThrow(/malformed state/);
  });

  it('a publisher may tolerate refusing witnesses down to a threshold', () => {
    const ex = buildMeshExample();
    const good = new MeshWitness(seed(11));
    const poisoned = new MeshWitness(seed(12));
    const d = new MeshDomain('X', seed(13));
    d.record(ex.chain[0]!);
    d.publishHead([poisoned], 100);
    const f = new MeshDomain('X', seed(13));
    f.record(ex.chain[1]!);
    expect(() => f.publishHead([good, poisoned], 200)).toThrow(/equivocation/);
    const ch = f.publishHead([good, poisoned], 200, { threshold: 1 });
    expect(ch.cosigs).toHaveLength(1);
    expect(() => f.publishHead([poisoned], 300, { threshold: 1 })).toThrow(/equivocation/);
  });

  it('checkHeadAdvance is total on garbage', () => {
    expect(checkHeadAdvance(null as never, null as never)).toMatch(/malformed/);
    const h = buildMeshExample().heads.A.head;
    expect(checkHeadAdvance(h, { ...h, domain: 'other' })).toMatch(/different domain/);
    expect(checkHeadAdvance(h, { ...h, size: 5, root: 'x' }, { oldSize: 2, newSize: 5, path: [1 as never] })).toMatch(/consistency proof required/);
    expect(checkHeadAdvance(h, { ...h, size: 5, root: 'x' }, { oldSize: 2, newSize: 5, path: ['AAAA'] })).toMatch(/not consistent/);
  });
});

function seed(n: number): Uint8Array {
  return new Uint8Array(32).fill(n);
}

describe('mesh: verifier pins (consistency from the pin)', () => {
  it('accepts a larger head only with a verified consistency proof from the pin', () => {
    const ex = buildMeshExample();
    const trust = { ...ex.trust, pinnedHeads: { [ex.domains.A.id]: ex.heads.A0.head } };
    expect(verifyMeshProof(ex.proof, trust).reason).toMatch(/consistency proof required.*pinned/);
    const pp = ex.domains.A.pinProof(ex.heads.A0.head, ex.heads.A);
    const ok = assembleMeshProof({ chain: ex.chain, hops: ex.evidence, action: ex.proof.action, leafSecret: ex.keys.leaf, pinProofs: [pp] });
    expect(verifyMeshProof(ok, trust).ok).toBe(true);
    const wrong = assembleMeshProof({
      chain: ex.chain,
      hops: ex.evidence,
      action: ex.proof.action,
      leafSecret: ex.keys.leaf,
      pinProofs: [{ domain: pp.domain, proof: { ...pp.proof, path: ['AAAA'] } }],
    });
    expect(verifyMeshProof(wrong, trust).reason).toMatch(/not consistent/);
  });

  it('rejects a pin that the presented head forks from', () => {
    const ex = buildMeshExample();
    const forked: MeshHead = { ...ex.heads.A0.head, root: b64u(new Uint8Array(32).fill(1)) };
    const pp = ex.domains.A.pinProof(ex.heads.A0.head, ex.heads.A);
    const p = assembleMeshProof({ chain: ex.chain, hops: ex.evidence, action: ex.proof.action, leafSecret: ex.keys.leaf, pinProofs: [pp] });
    expect(verifyMeshProof(p, { ...ex.trust, pinnedHeads: { [ex.domains.A.id]: forked } }).reason).toMatch(/not consistent/);
  });

  it('a prototype-polluting domain name cannot crash or bypass pin lookup', () => {
    const ex = buildMeshExample();
    const pins = JSON.parse('{"__proto__": {"domain":"x"}}') as Record<string, MeshHead>;
    expect(() => verifyMeshProof(ex.proof, { ...ex.trust, pinnedHeads: pins })).not.toThrow();
    expect(verifyMeshProof(ex.proof, { ...ex.trust, pinnedHeads: pins }).ok).toBe(true);
  });
});

describe('mesh: freshness windows (deterministic)', () => {
  it('rejects a stale head, at the exact boundary +1 ms', () => {
    const ex = buildMeshExample();
    const age = 1_000; // heads are timestamped now-1000 (A: now-1000, A0 unused)
    expect(verifyMeshProof(ex.proof, { ...ex.trust, now: ex.trust.now - 1_000 + 300_000 }).ok).toBe(true);
    expect(verifyMeshProof(ex.proof, { ...ex.trust, now: ex.trust.now - 1_000 + 300_001 }).reason).toMatch(/stale/);
    expect(age).toBe(1_000);
    expect(verifyMeshProof(ex.proof, { ...ex.trust, now: ex.trust.now + 10 * 60_000 }).reason).toMatch(/stale/);
  });

  it('the freshness window is tunable', () => {
    const ex = buildMeshExample();
    const t = { ...ex.trust, maxHeadAgeMs: 10_000 };
    expect(verifyMeshProof(ex.proof, { ...t, now: ex.trust.now + 9_000 }).ok).toBe(true);
    expect(verifyMeshProof(ex.proof, { ...t, now: ex.trust.now + 9_001 }).reason).toMatch(/stale/);
  });

  it('rejects future-dated heads beyond the skew allowance and accepts within it', () => {
    const ex = buildMeshExample();
    expect(verifyMeshProof(ex.proof, { ...ex.trust, now: ex.trust.now - 61_001 }).reason).toMatch(/future/);
    expect(verifyMeshProof(ex.proof, { ...ex.trust, now: ex.trust.now - 1_500, maxClockSkewMs: 2_000 }).ok).toBe(true);
    expect(verifyMeshProof(ex.proof, { ...ex.trust, now: ex.trust.now - 2_500, maxClockSkewMs: 1_000 }).reason).toMatch(/future/);
  });

  it('rejects future-dated and (optionally) stale actions', () => {
    const ex = buildMeshExample();
    const future = rebuild(ex, ex.evidence, { ...ex.proof.action, at: ex.trust.now + 120_000 });
    expect(verifyMeshProof(future, ex.trust).reason).toMatch(/action timestamp is in the future/);
    const old = rebuild(ex, ex.evidence, { ...ex.proof.action, at: ex.trust.now - 50_000 });
    expect(verifyMeshProof(old, ex.trust).ok).toBe(true);
    expect(verifyMeshProof(old, { ...ex.trust, maxActionAgeMs: 10_000 }).reason).toMatch(/action is stale/);
  });
});

describe('mesh: revocation propagation + latency model', () => {
  it('a mid-chain revocation in another org invalidates the leaf (pinned verifier: immediately)', () => {
    const ex = buildMeshExample();
    const mid = ex.chain[2]!;
    ex.domains.B.revoke(mid.id);
    const hB2 = ex.domains.B.publishHead(ex.witnesses, ex.trust.now - 100);
    expect(() => ex.domains.B.evidence(mid, hB2, ex.bindings.tool)).toThrow(/revoked/);
    // an unpinned verifier still accepts the pre-revocation proof...
    expect(verifyMeshProof(ex.proof, ex.trust).ok).toBe(true);
    // ...a verifier that pinned B's newer head rejects it at once
    const v = verifyMeshProof(ex.proof, { ...ex.trust, pinnedHeads: { [ex.domains.B.id]: hB2.head } });
    expect(v.ok).toBe(false);
    expect(v.reason).toMatch(/rolls back.*pinned/);
    expect(v.hop).toBe(2);
    // splicing the new head with the old non-membership proofs fails
    const p = structuredClone(ex.proof);
    p.heads[p.hops[2]!.head] = hB2;
    expect(verifyMeshProof(p, ex.trust).ok).toBe(false);
  });

  it('unpinned verifier: the stale pre-revocation proof dies within the stated bound', () => {
    const ex = buildMeshExample();
    const r = ex.trust.now; // revocation made now; B's head (timestamp r-1000) cannot contain it
    ex.domains.B.revoke(ex.chain[2]!.id);
    const bound = revocationLatencyBound({ maxHeadAgeMs: 300_000, maxClockSkewMs: 0, headIntervalMs: 60_000 });
    expect(bound).toEqual({ published_ms: 60_000, unpinned_ms: 300_000, pinned_ms: 300_000, honest_provers_viable: true });
    const t = { ...ex.trust, maxClockSkewMs: 0 };
    expect(verifyMeshProof(ex.proof, { ...t, now: r + 1_000 }).ok).toBe(true); // inside the window: still accepted
    expect(verifyMeshProof(ex.proof, { ...t, now: r + bound.unpinned_ms }).reason).toMatch(/stale/); // at the bound: dead
  });

  it('pinning verifier: bound is the pin refresh interval', () => {
    const b = revocationLatencyBound({ maxHeadAgeMs: 300_000, maxClockSkewMs: 5_000, headIntervalMs: 30_000, pinRefreshMs: 20_000 });
    expect(b).toMatchObject({ unpinned_ms: 305_000, pinned_ms: 20_000, published_ms: 30_000, honest_provers_viable: true });
    expect(revocationLatencyBound({ maxHeadAgeMs: 10_000, headIntervalMs: 10_000 }).honest_provers_viable).toBe(false);
    expect(revocationLatencyBound({ maxHeadAgeMs: NaN, headIntervalMs: 1 })).toMatchObject({ unpinned_ms: Infinity, honest_provers_viable: false });
    expect(revocationLatencyBound(null as never).honest_provers_viable).toBe(false);
  });

  it('a tighter head age tightens the bound', () => {
    const ex = buildMeshExample();
    ex.domains.B.revoke(ex.chain[2]!.id);
    const t = { ...ex.trust, maxHeadAgeMs: 5_000, maxClockSkewMs: 0 };
    const bound = revocationLatencyBound({ maxHeadAgeMs: 5_000, headIntervalMs: 1_000 });
    expect(verifyMeshProof(ex.proof, { ...t, now: ex.trust.now + bound.unpinned_ms }).reason).toMatch(/stale/);
  });

  it('revoking the human root (hop 0) kills every descendant', () => {
    const ex = buildMeshExample();
    ex.domains.A.revoke(ex.chain[0]!.id);
    const hA2 = ex.domains.A.publishHead(ex.witnesses, ex.trust.now - 100);
    expect(() => ex.domains.A.evidence(ex.chain[0]!, hA2)).toThrow(/revoked/);
    const pp = ex.domains.A.pinProof(ex.heads.A.head, hA2);
    expect(verifyMeshProof(ex.proof, { ...ex.trust, pinnedHeads: { [ex.domains.A.id]: hA2.head } }).ok).toBe(false);
    expect(pp.proof.oldSize).toBe(2);
  });

  it('revoking an agent key (not a cap) also invalidates what it issued', () => {
    const ex = buildMeshExample();
    ex.domains.B.revoke(keyRevocationId(pub(ex.keys.tool)));
    const hB2 = ex.domains.B.publishHead(ex.witnesses, ex.trust.now - 100);
    expect(() => ex.domains.B.evidence(ex.chain[2]!, hB2, ex.bindings.tool)).toThrow(/revoked/);
  });

  it('an unrelated revocation does not affect the chain; non-empty revocation sets verify via compact leaves', () => {
    const ex = buildMeshExample();
    for (const id of ['some-other-cap', 'aaa', 'zzz', 'key:other']) ex.domains.B.revoke(id);
    const hB2 = ex.domains.B.publishHead(ex.witnesses, ex.trust.now - 100);
    const evidence = [...ex.evidence];
    evidence[2] = ex.domains.B.evidence(ex.chain[2]!, hB2, ex.bindings.tool);
    const p = rebuild(ex, evidence);
    expect(p.rev_leaves.length).toBeGreaterThan(0);
    expect(verifyMeshProof(p, { ...ex.trust, pinnedHeads: { [ex.domains.B.id]: hB2.head } }).ok).toBe(true);
    // a revocation proof pointing at the wrong leaf is refused
    const bad = structuredClone(p);
    bad.hops[2]!.revocation.cap = { size: 4, lo: 0, hi: 0 };
    expect(verifyMeshProof(bad, ex.trust).ok).toBe(false);
  });
});

describe('mesh: proof size', () => {
  it('compaction beats the per-hop layout and heads scale with domains, not hops', () => {
    const ex = buildMeshExample();
    const s = meshProofSize(ex.proof);
    expect(s.total_bytes).toBeLessThan(s.uncompacted_bytes);
    expect(s.heads_bytes + s.rev_leaves_bytes + s.hops_bytes + s.chain_bytes).toBeLessThanOrEqual(s.total_bytes);
    // 4 hops, 3 heads (not 4)
    expect(ex.proof.heads).toHaveLength(3);
    console.info('mesh proof size', JSON.stringify(s));
  });

  it('deep same-domain chains carry a single head regardless of depth', () => {
    const ex = buildMeshExample();
    const D = new MeshDomain('deep', seed(21));
    const keys = Array.from({ length: 10 }, (_, i) => seed(30 + i));
    const root = ex.chain[0]!;
    // human -> k0 -> k1 ... all issued/logged in D (hop 0 reuses the example human root, logged in D)
    const caps: Capability[] = [root];
    const hk = ex.keys.orchestrator;
    let prev = root;
    let signer = hk;
    D.record(root);
    for (let i = 0; i < 6; i++) {
      const next = forgeHopNarrow(prev, pub(keys[i]!), signer);
      D.record(next);
      caps.push(next);
      prev = next;
      signer = keys[i]!;
    }
    const h = D.publishHead(ex.witnesses, ex.trust.now - 100);
    const evidence = caps.map((c, i) => D.evidence(c, h, i === 0 ? undefined : D.enroll(c.issuer, 'agent')));
    const p = assembleMeshProof({
      chain: caps,
      hops: evidence,
      action: { ...ex.proof.action, service_domain: ex.domains.C.id },
      leafSecret: signer,
    });
    expect(p.heads).toHaveLength(1);
    const v = verifyMeshProof(p, ex.trust);
    expect(v.reason).toBeUndefined();
    expect(v.ok).toBe(true);
    expect(v.trace.every((t) => t.crosses_boundary === false || t.hop === 6)).toBe(true);
  });
});

function forgeHopNarrow(parent: Capability, holder: string, signer: Uint8Array): Capability {
  // a legitimate (append-only) attenuation: parent's caveats + one more
  const caveats = [...parent.caveats, { type: 'max_hops', n: 40 }];
  return forgeHop(parent, holder, caveats, signer);
}

describe('mesh: fail closed on malformed input (verifyMeshProof is total)', () => {
  const mutations: [string, (p: any) => void][] = [
    ['chain removed', (p) => delete p.chain],
    ['chain empty', (p) => (p.chain = [])],
    ['heads null', (p) => (p.heads = null)],
    ['rev_leaves string', (p) => (p.rev_leaves = 'x')],
    ['hops empty', (p) => (p.hops = [])],
    ['hop null', (p) => (p.hops[0] = null)],
    ['hop head index out of range', (p) => (p.hops[0].head = 99)],
    ['hop head index negative', (p) => (p.hops[0].head = -1)],
    ['hop head index float', (p) => (p.hops[0].head = 0.5)],
    ['hop domain number', (p) => (p.hops[0].domain = 5)],
    ['hop revocation null', (p) => (p.hops[1].revocation = null)],
    ['nm index out of range', (p) => (p.hops[2].revocation.cap = { size: 0, lo: 50 })],
    ['nm size negative', (p) => (p.hops[2].revocation.cap = { size: -1 })],
    ['nm size lying (non-empty claimed)', (p) => (p.hops[2].revocation.issuer_key = { size: 3 })],
    ['inclusion null', (p) => (p.hops[0].inclusion = null)],
    ['inclusion path huge', (p) => (p.hops[0].inclusion.path = new Array(500).fill({ side: 'L', hash: 'AA' }))],
    ['head null', (p) => (p.heads[0] = null)],
    ['head cosigs null', (p) => (p.heads[0].cosigs = null)],
    ['head cosig entry null', (p) => (p.heads[0].cosigs = [null, 7])],
    ['head cosigs flood', (p) => (p.heads[0].cosigs = new Array(1000).fill(p.heads[0].cosigs[0]))],
    ['head sig number', (p) => (p.heads[0].sig = 5)],
    ['head size negative', (p) => (p.heads[0].head.size = -1)],
    ['head size NaN', (p) => (p.heads[0].head.size = NaN)],
    ['head root empty with size>0', (p) => (p.heads[0].head.root = '')],
    ['head timestamp string', (p) => (p.heads[0].head.timestamp = 'x')],
    ['head domain missing', (p) => delete p.heads[0].head.domain],
    ['binding null', (p) => (p.hops[1].binding = null)],
    ['binding role number', (p) => (p.hops[1].binding.role = 5)],
    ['action null', (p) => (p.action = null)],
    ['action amount NaN', (p) => (p.action.amount = NaN)],
    ['action amount string', (p) => (p.action.amount = '1')],
    ['action nonce number', (p) => (p.action.nonce = 1)],
    ['action at Infinity', (p) => (p.action.at = Infinity)],
    ['action_sig number', (p) => (p.action_sig = 5)],
    ['pin_proofs not array', (p) => (p.pin_proofs = {})],
    ['pin_proofs bad entry', (p) => (p.pin_proofs = [{ domain: 1 }])],
    ['chain element null', (p) => (p.chain[1] = null)],
    ['chain element wrong shape', (p) => (p.chain[2] = { id: 1 })],
    ['caveats not array', (p) => (p.chain[1].caveats = 'x')],
  ];
  for (const [name, mut] of mutations) {
    it(`rejects: ${name}`, () => {
      const ex = buildMeshExample();
      const p = structuredClone(ex.proof) as any;
      mut(p);
      let v: ReturnType<typeof verifyMeshProof> | undefined;
      expect(() => (v = verifyMeshProof(p, ex.trust))).not.toThrow();
      expect(v!.ok).toBe(false);
      expect(typeof v!.reason).toBe('string');
    });
  }

  it('rejects non-object proofs and every bad trust configuration', () => {
    const ex = buildMeshExample();
    for (const bad of [null, undefined, 1, 'x', [], true]) expect(verifyMeshProof(bad as never, ex.trust).ok).toBe(false);
    const cfg: Partial<typeof ex.trust>[] = [
      { threshold: 0 },
      { threshold: 4 },
      { threshold: 1.5 },
      { threshold: NaN },
      { now: NaN },
      { witnesses: 'x' as never },
      { witnesses: [] },
      { maxHeadAgeMs: -1 },
      { maxHeadAgeMs: NaN },
      { maxClockSkewMs: -5 },
      { maxActionAgeMs: Infinity },
      { maxChainLength: 0 },
      { allowedDomains: 'a' as never },
      { pinnedHeads: [] as never },
      { humanPrincipal: 5 as never },
    ];
    for (const c of cfg) {
      const v = verifyMeshProof(ex.proof, { ...ex.trust, ...c });
      expect(v.ok, JSON.stringify(c)).toBe(false);
      expect(v.reason).toMatch(/invalid trust/);
    }
    expect(verifyMeshProof(ex.proof, null as never).ok).toBe(false);
    expect(verifyMeshProof(ex.proof, { ...ex.trust, maxChainLength: 3 }).reason).toMatch(/chain length/);
  });

  it('never throws under deterministic structural fuzzing, and every rejection has a reason', () => {
    const ex = buildMeshExample();
    let s = 12345;
    const rnd = () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const junk = [null, undefined, 0, -1, 1.5, NaN, '', 'x', [], {}, true, [null], { a: 1 }, 1e308];
    const paths = (o: unknown, pre: (string | number)[] = [], out: (string | number)[][] = []) => {
      if (o && typeof o === 'object') {
        for (const k of Object.keys(o)) {
          out.push([...pre, k]);
          paths((o as any)[k], [...pre, k], out);
        }
      }
      return out;
    };
    const all = paths(ex.proof);
    let rejected = 0;
    for (let i = 0; i < 400; i++) {
      const p = structuredClone(ex.proof) as any;
      const path = all[Math.floor(rnd() * all.length)]!;
      let o = p;
      for (const k of path.slice(0, -1)) o = o[k];
      o[path[path.length - 1]!] = junk[Math.floor(rnd() * junk.length)];
      const v = verifyMeshProof(p, ex.trust);
      if (!v.ok) {
        rejected++;
        expect(typeof v.reason).toBe('string');
      }
    }
    expect(rejected).toBeGreaterThan(300);
  });
});

describe('mesh: determinism', () => {
  it('same inputs give identical proofs and verdicts', () => {
    const a = buildMeshExample();
    const b = buildMeshExample();
    expect(JSON.stringify(a.proof)).toBe(JSON.stringify(b.proof));
    const va = verifyMeshProof(a.proof, a.trust);
    expect(JSON.stringify(va)).toBe(JSON.stringify(verifyMeshProof(b.proof, b.trust)));
    expect(JSON.stringify(va)).toBe(JSON.stringify(verifyMeshProof(a.proof, a.trust)));
    expect(JSON.stringify(demonstrateForkRejection())).toBe(JSON.stringify(demonstrateForkRejection()));
  });
});

// =============================================================================================
// A2A FEDERATION (paradigm B5, multi-agent half)
// =============================================================================================

/** Sign a translated-capability body exactly as the library does (for FORGED translations in tests). */
function signXcap(secret: Uint8Array, body: unknown): string {
  const p = utf8('atlas-pca/mesh-xcap/v1\0');
  const b = canonicalBytes(body);
  const m = new Uint8Array(p.length + b.length);
  m.set(p);
  m.set(b, p.length);
  return b64u(sign(secret, m));
}

/** Re-sign a translated capability with a replaced caveat array (a malicious bridge forging). */
function forgeTranslation(tc: TranslatedCapability, caveats: Caveat[], bridgeSecret: Uint8Array): TranslatedCapability {
  const body = { v: 'atlas-pca/mesh-xcap/v1', from: tc.fromGuardian, to: tc.toGuardian, source_tip: tc.source_tip, caveats, issued_at: tc.issued_at };
  return { ...tc, caveats, sig: signXcap(bridgeSecret, body) };
}

/** A worked federation setup: a 2-hop chain rooted in Guardian A, translated into Guardian B. */
function buildFederation(now = 1_800_000_000_000) {
  const human = seed(100);
  const agent = seed(101); // the agent that acts across the boundary (holder of the chain tip)
  const bAgent = seed(102);
  const guardianA = pub(seed(110));
  const guardianBSecret = seed(111); // B is the bridging party (B narrows + signs)
  const guardianB = pub(guardianBSecret);
  const root = mintRoot({
    principalSecret: human,
    principalPublic: pub(human),
    holder: pub(agent),
    caveats: [
      { type: 'scope', actions: ['payments.refund', 'payments.read', 'orders.read'] },
      { type: 'resource', prefix: '/orders/' },
      { type: 'max_amount', max: 500 },
      { type: 'expires', at: now + 3_600_000 },
    ],
  });
  const c1 = delegate(root, pub(bAgent), [{ type: 'scope', actions: ['payments.refund', 'payments.read'] }, { type: 'max_amount', max: 100 }], agent);
  const chain = [root, c1];
  const additionalCaveats: Caveat[] = [{ type: 'max_amount', max: 50 }, { type: 'audience', domains: [guardianB] }];
  const tc = translateCapability(chain, { fromGuardian: guardianA, toGuardian: guardianB, additionalCaveats, bridgeSecret: guardianBSecret, issued_at: now });
  return { now, human, agent, bAgent, guardianA, guardianB, guardianBSecret, root, c1, chain, additionalCaveats, tc };
}

describe('federation: cross-domain capability translation (monotone, append-only, bridge-signed)', () => {
  it('translates a chain rooted in Guardian A into a capability valid in Guardian B', () => {
    const f = buildFederation();
    const v = verifyTranslatedCapability(f.tc, { fromGuardian: f.guardianA, toGuardian: f.guardianB, bridge: f.guardianB, rootIssuer: pub(f.human) });
    expect(v.ok).toBe(true);
    expect(v).toMatchObject({ from: f.guardianA, to: f.guardianB, bridge: f.guardianB });
  });

  it('is MONOTONE: the translated effective authority narrows the source tip authority', () => {
    const f = buildFederation();
    const srcTip = f.chain[f.chain.length - 1]!;
    const srcEff = translatedEffectiveAuthority({ ...f.tc, caveats: srcTip.caveats } as TranslatedCapability);
    const tEff = translatedEffectiveAuthority(f.tc);
    expect('error' in srcEff).toBe(false);
    expect('error' in tEff).toBe(false);
    if ('error' in srcEff || 'error' in tEff) throw new Error('unexpected');
    // narrowed: ceiling dropped from 100 -> 50, audience added, scope preserved/narrowed
    expect(srcEff.maxAmount).toBe(100);
    expect(tEff.maxAmount).toBe(50);
    expect(tEff.maxAmount! <= srcEff.maxAmount!).toBe(true);
    expect(tEff.audience).toEqual([f.guardianB]);
    expect(srcEff.audience).toBeUndefined();
  });

  it('the translated caveats are an APPEND-ONLY extension of the source tip caveats', () => {
    const f = buildFederation();
    const srcTip = f.chain[f.chain.length - 1]!;
    expect(f.tc.caveats.slice(0, srcTip.caveats.length)).toEqual(srcTip.caveats);
    expect(f.tc.caveats.length).toBe(srcTip.caveats.length + f.additionalCaveats.length);
  });

  it('REJECTS a translation that drops a source caveat (widening)', () => {
    const f = buildFederation();
    const srcTip = f.chain[f.chain.length - 1]!;
    const dropped = srcTip.caveats.slice(1); // drop the leading scope caveat
    const forged = forgeTranslation(f.tc, dropped, f.guardianBSecret);
    expect(verifyTranslatedCapability(forged).reason).toMatch(/drops a source caveat/);
  });

  it('REJECTS a translation that loosens (edits) a source caveat to a larger ceiling', () => {
    const f = buildFederation();
    const srcTip = f.chain[f.chain.length - 1]!;
    const loosened = srcTip.caveats.map((c) => (c.type === 'max_amount' ? { ...c, max: 1_000_000 } : c));
    const forged = forgeTranslation(f.tc, loosened, f.guardianBSecret);
    expect(verifyTranslatedCapability(forged).reason).toMatch(/altered or reordered/);
  });

  it('REJECTS an unknown caveat type in the translation (fail closed)', () => {
    const f = buildFederation();
    const chain = f.chain;
    const tc = translateCapability(chain, {
      fromGuardian: f.guardianA,
      toGuardian: f.guardianB,
      additionalCaveats: [{ type: 'mystery', wat: 1 }],
      bridgeSecret: f.guardianBSecret,
      issued_at: f.now,
    });
    expect(verifyTranslatedCapability(tc).reason).toMatch(/unknown caveat/);
  });

  it('REJECTS a bad bridge signature, a wrong bridge/guardian pin, and a non-crossing translation', () => {
    const f = buildFederation();
    // forged body not signed by the declared bridge key
    const badSig = { ...f.tc, sig: signXcap(seed(9), { v: 'atlas-pca/mesh-xcap/v1', from: f.tc.fromGuardian, to: f.tc.toGuardian, source_tip: f.tc.source_tip, caveats: f.tc.caveats, issued_at: f.tc.issued_at }) };
    expect(verifyTranslatedCapability(badSig).reason).toMatch(/not signed by the declared bridge/);
    expect(verifyTranslatedCapability(f.tc, { bridge: pub(seed(77)) }).reason).toMatch(/bridge key mismatch/);
    expect(verifyTranslatedCapability(f.tc, { fromGuardian: pub(seed(78)) }).reason).toMatch(/source guardian mismatch/);
    expect(verifyTranslatedCapability(f.tc, { toGuardian: pub(seed(79)) }).reason).toMatch(/target guardian mismatch/);
    expect(verifyTranslatedCapability({ ...f.tc, fromGuardian: f.tc.toGuardian }).reason).toMatch(/cross a domain boundary/);
  });

  it('REJECTS a tampered source_tip and an invalid / wrongly-rooted source chain', () => {
    const f = buildFederation();
    expect(verifyTranslatedCapability({ ...f.tc, source_tip: capHash(f.root) }).reason).toMatch(/source_tip/);
    expect(verifyTranslatedCapability(f.tc, { rootIssuer: pub(seed(5)) }).reason).toMatch(/source chain/);
    const brokenChain = { ...f.tc, source: [f.root, { ...f.c1, sig: f.root.sig }] as Capability[] };
    expect(verifyTranslatedCapability(brokenChain).ok).toBe(false);
  });

  it('optionally enforces the translated expiry', () => {
    const f = buildFederation();
    expect(verifyTranslatedCapability(f.tc, { now: f.now }).ok).toBe(true);
    expect(verifyTranslatedCapability(f.tc, { now: f.now + 2 * 3_600_000 }).reason).toMatch(/expired/);
  });

  it('is deterministic and TOTAL (never throws) on malformed input', () => {
    const a = buildFederation();
    const b = buildFederation();
    expect(JSON.stringify(a.tc)).toBe(JSON.stringify(b.tc));
    expect(JSON.stringify(verifyTranslatedCapability(a.tc))).toBe(JSON.stringify(verifyTranslatedCapability(b.tc)));
    for (const bad of [null, undefined, 1, 'x', [], {}, { source: 5 }, { ...a.tc, caveats: 'x' }, { ...a.tc, source: [null] }]) {
      let v: ReturnType<typeof verifyTranslatedCapability> | undefined;
      expect(() => (v = verifyTranslatedCapability(bad as never))).not.toThrow();
      expect(v!.ok).toBe(false);
      expect(typeof v!.reason).toBe('string');
    }
  });
});

describe('federation: consolidated cross-domain budget (the budget tree spans domains)', () => {
  const build = (B0: number, kappa = 1, bMax = B0) => {
    const r = createFederatedBudget({ rootId: 'root', rootDomain: 'A', B0, kappa, bMax });
    if (!r.ok) throw new Error(r.reason);
    return r.state;
  };
  const alloc = (s: FederatedBudgetState, id: string, domain: string, parent: string, a: number) => {
    const r = allocateSub(s, { id, domain, parent, alloc: a });
    if (!r.ok) throw new Error(r.reason);
    return r.state;
  };
  const freason = (r: ReturnType<typeof spendFederated>): string | undefined => (r.ok ? undefined : r.reason);

  it('allocates B_sub <= parent remaining; a larger allocation is refused', () => {
    const s = build(100);
    expect(allocateSub(s, { id: 'x', domain: 'B', parent: 'root', alloc: 150 }).ok).toBe(false);
    expect(allocateSub(s, { id: 'x', domain: 'B', parent: 'root', alloc: 80 }).ok).toBe(true);
    expect(allocateSub(s, { id: 'x', domain: 'B', parent: 'nope', alloc: 1 }).ok).toBe(false);
    const s2 = alloc(s, 'x', 'B', 'root', 80);
    expect(freason(allocateSub(s2, { id: 'x', domain: 'B', parent: 'root', alloc: 1 }))).toMatch(/already exists/);
  });

  it('debiting a leaf debits every ancestor up to the root (across 3 domains)', () => {
    let s = build(100);
    s = alloc(s, 'mid', 'B', 'root', 80);
    s = alloc(s, 'leaf', 'C', 'mid', 60);
    const r = spendFederated(s, 'leaf', 30);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.state.nodes.root!.B).toBe(70);
    expect(r.state.nodes.mid!.B).toBe(50);
    expect(r.state.nodes.leaf!.B).toBe(30);
  });

  it('a spend is atomic and fail-closed: if the root cannot cover it, nothing changes', () => {
    let s = build(40);
    s = alloc(s, 'mid', 'B', 'root', 40);
    s = alloc(s, 'leaf', 'C', 'mid', 40); // ceiling 40 but root only has 40
    const r1 = spendFederated(s, 'leaf', 30);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    // root is now 10; a further 20 is refused by the root even though the leaf ceiling (10 left) ... root gates
    const r2 = spendFederated(r1.state, 'leaf', 20);
    expect(r2.ok).toBe(false);
    expect(freason(r2)).toMatch(/insufficient/);
    // malformed spends are refused
    expect(spendFederated(s, 'leaf', -1).ok).toBe(false);
    expect(spendFederated(s, 'leaf', NaN).ok).toBe(false);
    expect(freason(spendFederated(s, 'ghost', 1))).toMatch(/unknown node/);
  });

  it('for a direct child of the root, spendFederated IS debitConsolidated(root, node, c)', () => {
    let s = build(100);
    s = alloc(s, 'leaf', 'B', 'root', 70);
    const c = 25;
    const r = spendFederated(s, 'leaf', c);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const dc = debitConsolidated({ B: 100, tau: 0 }, { B: 70, tau: 0 }, c);
    expect(dc.ok).toBe(true);
    if (!dc.ok) return;
    expect(r.state.nodes.root!.B).toBe(dc.parent.B);
    expect(r.state.nodes.leaf!.B).toBe(dc.sub.B);
  });

  it('federatedSafetyBound = bMax/kappa, and 0 on a malformed policy', () => {
    expect(federatedSafetyBound({ bMax: 10, kappa: 2 })).toBe(5);
    expect(federatedSafetyBound({ bMax: 1, kappa: 1 })).toBe(1);
    expect(federatedSafetyBound({ bMax: NaN as never, kappa: 1 })).toBe(0);
    expect(federatedSafetyBound(null as never)).toBe(0);
  });

  it('PROPERTY: a swarm across 2-3 domains can never collectively exceed root Bmax/kappa', () => {
    let st = 987654321;
    const rnd = () => (st = (st * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const ri = (n: number) => Math.floor(rnd() * n);
    const domains = ['A', 'B', 'C'];
    for (let trial = 0; trial < 500; trial++) {
      const kappa = [1, 2, 4][ri(3)]!;
      const bMax = 100 + ri(900);
      const B0 = ri(bMax + 1);
      let s = createFederatedBudget({ rootId: 'n0', rootDomain: 'A', B0, kappa, bMax });
      expect(s.ok).toBe(true);
      if (!s.ok) continue;
      let state = s.state;
      const ids = ['n0'];
      // random delegation tree (2-6 nodes), spanning up to 3 domains
      const extra = 1 + ri(5);
      for (let i = 1; i <= extra; i++) {
        const parent = ids[ri(ids.length)]!;
        const parentB = state.nodes[parent]!.B;
        const a = ri(parentB + 1); // 0..parent remaining -> always valid
        const res = allocateSub(state, { id: `n${i}`, domain: domains[ri(3)]!, parent, alloc: a });
        if (res.ok) {
          state = res.state;
          ids.push(`n${i}`);
        }
      }
      // random spends anywhere in the tree
      let totalSpent = 0;
      for (let k = 0; k < 20; k++) {
        const node = ids[ri(ids.length)]!;
        const c = ri(60);
        const res = spendFederated(state, node, c);
        if (res.ok) {
          state = res.state;
          totalSpent += c;
        }
      }
      // the root tracks the sum of every debit anywhere in the DAG
      expect(state.nodes.n0!.B).toBe(B0 - totalSpent);
      // collective spend never exceeds the root's granted budget...
      expect(totalSpent).toBeLessThanOrEqual(B0);
      // ...hence Sigma r = Sigma c / kappa <= bMax/kappa = the federated safety bound
      expect(totalSpent / kappa).toBeLessThanOrEqual(federatedSafetyBound({ bMax, kappa }) + 1e-9);
      // every node's remaining budget stays non-negative
      for (const id of ids) expect(state.nodes[id]!.B).toBeGreaterThanOrEqual(0);
    }
  });

  it('fail-closed on a malformed budget state', () => {
    expect(spendFederated(null as never, 'x', 1).ok).toBe(false);
    expect(allocateSub(null as never, { id: 'x', domain: 'd', parent: 'p', alloc: 1 }).ok).toBe(false);
    expect(createFederatedBudget({ rootId: 'r', rootDomain: 'A', B0: 10, kappa: 0, bMax: 10 }).ok).toBe(false);
    expect(freason(createFederatedBudget({ rootId: 'r', rootDomain: 'A', B0: 20, kappa: 1, bMax: 10 }))).toMatch(/exceeds bMax/);
  });
});

describe('federation: mutual-transparency cross-reference commitment', () => {
  const action = (): MeshAction => ({ type: 'payments.refund', resource: '/orders/42', amount: 25, service_domain: pub(seed(201)), nonce: 'n1', at: 123 });
  const build = () => {
    const A = seed(200);
    const B = seed(201);
    const x: CrossReference = { action_digest: meshActionDigest(action()), fromGuardian: pub(A), toGuardian: pub(B), nonce: 'xr-1', at: 1_000 };
    const commit = crossReferenceCommit(x);
    return { A, B, x, commit, anchors: { from: anchorCrossReference(A, commit, 5), to: anchorCrossReference(B, commit, 9) } };
  };

  it('binds the same action digest in both domains and verifies', () => {
    const { x, commit, anchors } = build();
    const v = verifyCrossReference(x, anchors);
    expect(v.ok).toBe(true);
    expect(v.commit).toBe(commit);
  });

  it('REJECTS a mismatched link: an anchor committing a DIFFERENT action', () => {
    const { A, B, x } = build();
    const other: CrossReference = { ...x, action_digest: meshActionDigest({ ...action(), amount: 9999 }) };
    const otherCommit = crossReferenceCommit(other);
    const anchors = { from: anchorCrossReference(A, crossReferenceCommit(x), 5), to: anchorCrossReference(B, otherCommit, 9) };
    expect(verifyCrossReference(x, anchors).reason).toMatch(/target anchor commits a different action/);
    const anchors2 = { from: anchorCrossReference(A, otherCommit, 5), to: anchorCrossReference(B, crossReferenceCommit(x), 9) };
    expect(verifyCrossReference(x, anchors2).reason).toMatch(/source anchor commits a different action/);
  });

  it('REJECTS a wrong-domain anchor, a tampered commit, and a broken signature', () => {
    const { A, B, x, commit, anchors } = build();
    const wrongDomain = { ...anchors, from: anchorCrossReference(seed(202), commit, 5) };
    expect(verifyCrossReference(x, wrongDomain).reason).toMatch(/source anchor domain/);
    const tampered = { ...anchors, to: { ...anchors.to, commit: 'AAAA' } };
    expect(verifyCrossReference(x, tampered).reason).toMatch(/target anchor commits a different action/);
    const badSig = { ...anchors, from: { ...anchors.from, seq: 999 } }; // signature was over seq 5
    expect(verifyCrossReference(x, badSig).reason).toMatch(/source anchor signature invalid/);
    void A;
    void B;
  });

  it('REJECTS a cross-reference that does not span two distinct domains', () => {
    const { A, x } = build();
    const same: CrossReference = { ...x, toGuardian: x.fromGuardian };
    const commit = crossReferenceCommit(same);
    const anchors = { from: anchorCrossReference(A, commit, 1), to: anchorCrossReference(A, commit, 2) };
    expect(verifyCrossReference(same, anchors).reason).toMatch(/two distinct domains/);
  });

  it('meshActionDigest and crossReferenceCommit are deterministic; verify is TOTAL on garbage', () => {
    const { x, anchors } = build();
    expect(meshActionDigest(action())).toBe(meshActionDigest(action()));
    expect(crossReferenceCommit(x)).toBe(crossReferenceCommit(x));
    for (const bad of [null, undefined, 1, 'x', [], {}, { from: null }]) {
      let v: ReturnType<typeof verifyCrossReference> | undefined;
      expect(() => (v = verifyCrossReference(bad as never, bad as never))).not.toThrow();
      expect(v!.ok).toBe(false);
      expect(typeof v!.reason).toBe('string');
    }
    expect(verifyCrossReference(x, { from: anchors.from, to: null as never }).ok).toBe(false);
  });
});
