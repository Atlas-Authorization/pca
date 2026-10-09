import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type CapabilityChain,
  type KeyPair,
  attenuate,
  buildPCActn,
  budgetAllocCaveat,
  delegate,
  encodeKey,
  generateKeyPair,
  mintRoot,
  verifyChain,
  verifyPCActnCore,
} from '@atlasauth/pca';
import {
  type RevocationRecord,
  compromisedKeyFlow,
  revokeAndReissueSubtree,
  rotateAgentKey,
  rotatePrincipalKey,
} from './index';

const AUD = 'inst_test';

/** Type-safe access to a capability at an index (no casts, no non-null assertions). */
function cap(x: Capability | undefined): Capability {
  if (x === undefined) throw new Error('expected a capability');
  return x;
}
const leafOf = (chain: CapabilityChain): Capability => cap(chain[chain.length - 1]);

/** Canonical agent chain: principal P -> agent A (root), then A's self-attenuated leaf. */
function agentChain() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const root = mintRoot({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    caveats: [{ type: 'ttl', secs: 3600 }],
  });
  const leaf = attenuate(root, [{ type: 'resource', prefix: '/acct' }], A.secretKey);
  return { P, A, root, leaf, chain: [root, leaf] as CapabilityChain };
}

/**
 * Deeper chain with a sub-agent B (and sub-sub-agent C), carrying monotone budget allocations so the
 * re-issue "never widens" assertion is meaningful:
 *   root(P->A, ttl) -> c1(A, alloc 10) -> c2(B, alloc 4) -> c3(C, alloc 2).
 */
function subAgentChain() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const B = generateKeyPair();
  const C = generateKeyPair();
  const root = mintRoot({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    caveats: [{ type: 'ttl', secs: 3600 }],
  });
  const c1 = delegate(root, encodeKey(A.publicKey), [budgetAllocCaveat(10)], A.secretKey);
  const c2 = delegate(c1, encodeKey(B.publicKey), [budgetAllocCaveat(4)], A.secretKey);
  const c3 = delegate(c2, encodeKey(C.publicKey), [budgetAllocCaveat(2)], B.secretKey);
  return { P, A, B, C, root, c1, c2, c3, chain: [root, c1, c2, c3] as CapabilityChain };
}

/** The verifier's check map when `signerSecret` signs a real PCActn over `chain`. */
async function leafSignatureChecks(chain: CapabilityChain, signerSecret: Uint8Array) {
  const grant = cap(chain[0]);
  const plan = [{ id: 'n1', verb: 'read', resource: '/acct' }];
  const actn = buildPCActn({ grant, chain, plan, nodeId: 'n1', counter: 0, signerSecret, aud: AUD });
  const res = await verifyPCActnCore(actn, { grant, audience: AUD });
  return res.checks;
}

describe('rotateAgentKey', () => {
  it('re-issues the leaf to the new holder; verifies under the new key, not the old', async () => {
    const { P, A, chain, leaf } = agentChain();
    const A2 = generateKeyPair();

    const { chain: nc, revocation } = rotateAgentKey(chain, {
      oldHolderSecret: A.secretKey,
      newKeyPair: A2,
      now: 1234,
    });

    expect(verifyChain(nc, encodeKey(P.publicKey))).toEqual({ ok: true });
    const newLeaf = leafOf(nc);
    expect(newLeaf.holder).toBe(encodeKey(A2.publicKey));
    expect(newLeaf.holder).not.toBe(encodeKey(A.publicKey));

    // A PCActn signed by the NEW key verifies at the leaf; the OLD key no longer does.
    const withNew = await leafSignatureChecks(nc, A2.secretKey);
    expect(withNew.cap_chain).toBe('pass');
    expect(withNew.leaf_signature).toBe('pass');
    const withOld = await leafSignatureChecks(nc, A.secretKey);
    expect(withOld.leaf_signature).toBe('fail');

    // Revocation record names the OLD holder.
    const rec: RevocationRecord = revocation;
    expect(rec.holder).toBe(encodeKey(A.publicKey));
    expect(rec.capId).toBe(leaf.id);
    expect(rec.revokedAt).toBe(1234);
  });

  it('preserves the leaf caveats exactly (no widening)', () => {
    const { A, chain, leaf } = agentChain();
    const { chain: nc } = rotateAgentKey(chain, { oldHolderSecret: A.secretKey, newKeyPair: generateKeyPair() });
    expect(leafOf(nc).caveats).toEqual(leaf.caveats);
  });

  it('rotates a sub-agent leaf: parent re-signs to the new holder', async () => {
    const { P, A, B, chain } = subAgentChain();
    const threeHop: CapabilityChain = chain.slice(0, 3); // [root, c1(A), c2(B)] — B is the leaf holder
    const B2 = generateKeyPair();
    const { chain: nc, revocation } = rotateAgentKey(threeHop, { oldHolderSecret: A.secretKey, newKeyPair: B2, now: 7 });

    expect(verifyChain(nc, encodeKey(P.publicKey))).toEqual({ ok: true });
    expect(leafOf(nc).holder).toBe(encodeKey(B2.publicKey));
    expect(revocation.holder).toBe(encodeKey(B.publicKey)); // old sub-agent holder
    const withNew = await leafSignatureChecks(nc, B2.secretKey);
    expect(withNew.leaf_signature).toBe('pass');
  });

  it('throws when the secret is not the leaf issuer, and on a root-only chain', () => {
    const { chain } = agentChain();
    expect(() =>
      rotateAgentKey(chain, { oldHolderSecret: generateKeyPair().secretKey, newKeyPair: generateKeyPair() }),
    ).toThrow(/not the leaf's issuer/);
    const rootOnly: CapabilityChain = [cap(chain[0])];
    expect(() =>
      rotateAgentKey(rootOnly, { oldHolderSecret: generateKeyPair().secretKey, newKeyPair: generateKeyPair() }),
    ).toThrow(/root-only chain/);
  });
});

describe('rotatePrincipalKey', () => {
  it('re-roots under a new principal: verifies against the new principal, not the old', async () => {
    const { P, A, chain, root, leaf } = agentChain();
    const P2 = generateKeyPair();

    const { chain: nc, revocation } = rotatePrincipalKey({
      chain,
      oldPrincipalSecret: P.secretKey,
      newPrincipalKeyPair: P2,
      holderSecrets: [A.secretKey],
      now: 50,
    });

    expect(verifyChain(nc, encodeKey(P2.publicKey))).toEqual({ ok: true });
    expect(verifyChain(nc, encodeKey(P.publicKey)).ok).toBe(false); // not rooted at the old principal
    const newRoot = cap(nc[0]);
    expect(newRoot.issuer).toBe(encodeKey(P2.publicKey));
    expect(newRoot.holder).toBe(encodeKey(A.publicKey)); // holder preserved

    // Authority preserved: leaf caveats unchanged; the agent key still signs valid PCActns.
    expect(leafOf(nc).caveats).toEqual(leaf.caveats);
    const checks = await leafSignatureChecks(nc, A.secretKey);
    expect(checks.cap_chain).toBe('pass');
    expect(checks.leaf_signature).toBe('pass');

    // Revocation names the old root / principal; covers the whole old chain.
    expect(revocation.issuer).toBe(encodeKey(P.publicKey));
    expect(revocation.capId).toBe(root.id);
    expect(revocation.subtreeRoot).toBe(root.id);
    expect(revocation.capIds).toEqual(chain.map((c) => c.id));
    expect(revocation.revokedAt).toBe(50);
  });

  it('re-roots a root-only chain from oldRoot alone', () => {
    const { P, root } = agentChain();
    const P2 = generateKeyPair();
    const { chain: nc } = rotatePrincipalKey({ oldRoot: root, oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: P2 });
    expect(nc).toHaveLength(1);
    expect(verifyChain(nc, encodeKey(P2.publicKey))).toEqual({ ok: true });
    expect(verifyChain(nc, encodeKey(P.publicKey)).ok).toBe(false);
  });

  it('re-roots a deep chain preserving monotone budget allocations', () => {
    const { P, A, B, chain, c3 } = subAgentChain();
    const P2 = generateKeyPair();
    const { chain: nc } = rotatePrincipalKey({
      chain,
      oldPrincipalSecret: P.secretKey,
      newPrincipalKeyPair: P2,
      holderSecrets: [A.secretKey, A.secretKey, B.secretKey], // issuer of c1=A, c2=A, c3=B
    });
    expect(verifyChain(nc, encodeKey(P2.publicKey))).toEqual({ ok: true });
    expect(leafOf(nc).caveats).toEqual(c3.caveats);
  });

  it('throws on a bad principal secret or wrong holderSecret count', () => {
    const { P, A, chain } = agentChain();
    expect(() =>
      rotatePrincipalKey({
        chain,
        oldPrincipalSecret: generateKeyPair().secretKey,
        newPrincipalKeyPair: generateKeyPair(),
        holderSecrets: [A.secretKey],
      }),
    ).toThrow(/not the root's issuer/);
    expect(() =>
      rotatePrincipalKey({ chain, oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: generateKeyPair(), holderSecrets: [] }),
    ).toThrow(/expected 1 holderSecrets/);
  });
});

describe('revokeAndReissueSubtree', () => {
  it('revokes the compromised subtree and re-issues from the nearest safe ancestor to a new key', () => {
    const { P, A, B, C, chain, c2, c3 } = subAgentChain();
    const B2 = generateKeyPair();

    const { chain: reissued, revocation } = revokeAndReissueSubtree(chain, encodeKey(B.publicKey), {
      newKeyPair: B2,
      ancestorSecret: A.secretKey, // c1's holder = nearest safe ancestor
      now: 77,
    });

    // Re-issued chain verifies under the original principal.
    expect(verifyChain(reissued, encodeKey(P.publicKey))).toEqual({ ok: true });
    // The compromised subtree (B, C) collapsed into ONE new hop bound to the new key.
    expect(reissued).toHaveLength(3); // [root, c1, newHop]
    const newLeaf = leafOf(reissued);
    expect(newLeaf.holder).toBe(encodeKey(B2.publicKey));
    expect(newLeaf.holder).not.toBe(encodeKey(B.publicKey));
    expect(newLeaf.holder).not.toBe(encodeKey(C.publicKey));

    // Authority preserved, NEVER widened: the re-issued leaf carries exactly the old deepest leaf's
    // caveats (budget alloc stays 2 — not the ancestor's 10). verifyChain rejects any widening.
    expect(newLeaf.caveats).toEqual(c3.caveats);

    // Revocation record for the whole compromised subtree.
    expect(revocation.subtreeRoot).toBe(c2.id);
    expect(revocation.holder).toBe(encodeKey(B.publicKey));
    expect(revocation.capIds).toEqual([c2.id, c3.id]);
    expect(revocation.revokedAt).toBe(77);
  });

  it('throws for an unknown holder and for the root holder', () => {
    const { A, chain } = subAgentChain();
    expect(() =>
      revokeAndReissueSubtree(chain, encodeKey(generateKeyPair().publicKey), {
        newKeyPair: generateKeyPair(),
        ancestorSecret: A.secretKey,
      }),
    ).toThrow(/not in the chain/);
    // Root holder is the agent A; compromising it has no safe delegation ancestor.
    expect(() =>
      revokeAndReissueSubtree(chain, encodeKey(A.publicKey), { newKeyPair: generateKeyPair(), ancestorSecret: A.secretKey }),
    ).toThrow(/root holder/);
  });

  it('rejects a wrong ancestor secret', () => {
    const { B, chain } = subAgentChain();
    expect(() =>
      revokeAndReissueSubtree(chain, encodeKey(B.publicKey), {
        newKeyPair: generateKeyPair(),
        ancestorSecret: generateKeyPair().secretKey,
      }),
    ).toThrow(/not the safe ancestor's holder/);
  });
});

describe('compromisedKeyFlow', () => {
  it('returns one revocation per compromised-subtree cap plus a verifying reissued chain', () => {
    const { P, A, B, chain, c2, c3 } = subAgentChain();
    const B2 = generateKeyPair();

    const { revocations, reissued } = compromisedKeyFlow(chain, encodeKey(B.publicKey), {
      newKeyPair: B2,
      ancestorSecret: A.secretKey,
      now: 9,
    });

    expect(revocations.map((r) => r.capId)).toEqual([c2.id, c3.id]); // B and its descendant C
    expect(revocations.every((r) => r.revokedAt === 9)).toBe(true);
    expect(verifyChain(reissued, encodeKey(P.publicKey))).toEqual({ ok: true });
    expect(leafOf(reissued).holder).toBe(encodeKey(B2.publicKey));
    // Never widens: re-issued leaf authority equals the old narrowest leaf.
    expect(leafOf(reissued).caveats).toEqual(c3.caveats);
  });
});

// Keep the KeyPair type import load-bearing.
const _kp: KeyPair = generateKeyPair();
void _kp;
