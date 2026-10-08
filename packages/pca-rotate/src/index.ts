/**
 * `@atlasauth/pca-rotate` — key rotation + subtree revocation for Proof-Carrying Authority.
 *
 * This is the KEY-LIFECYCLE boundary for PCA capability chains. A PCA chain binds authority to keys:
 * the root is signed by the PRINCIPAL and bound to an agent HOLDER key, and every delegation hop is
 * signed by its parent's holder and bound to the next holder. When a key is rotated — or a key is
 * COMPROMISED — the authority it carried must be re-issued under a fresh key and the old key named in
 * a revocation record a registry can act on.
 *
 * Everything here re-issues chains with the REAL core builders (`mintRoot` / `delegate` from
 * `@atlasauth/pca`): nothing re-implements signing or hashing. Attenuation is preserved by
 * construction — every re-issued hop carries exactly the caveats the hop it replaces carried (the
 * parent's full prefix plus the same appended caveats), so a re-issue can NEVER widen authority, and
 * carried budget allocations stay monotone (a widening would be rejected by `verifyChain`).
 *
 * Each function returns the new chain/capabilities together with a {@link RevocationRecord} for the
 * old key or subtree, in a shape a revocation registry can consume directly.
 */

import {
  type Capability,
  type CapabilityChain,
  type Caveat,
  type KeyPair,
  delegate,
  encodeKey,
  mintRoot,
  publicKeyOf,
} from '@atlasauth/pca';

/**
 * A record naming a key / capability / subtree as revoked, for a revocation registry (compatible with
 * the sorted-set root in `@atlasauth/pca`'s `RevocationSet`: feed `capId` — or every id in `capIds` —
 * into `revoke()`). Only `reason` and `revokedAt` are always present; the identifying fields are set to
 * whatever the rotation knows (a single cap, a holder key, an issuer key, and/or a subtree root).
 */
export interface RevocationRecord {
  /** The capability id (content address) being revoked — the subtree root for a subtree revocation. */
  capId?: string;
  /** The b64u holder key whose authority is revoked (the rotated-out / compromised agent key). */
  holder?: string;
  /** The b64u issuer key that signed the revoked capability (e.g. the old principal, on a re-root). */
  issuer?: string;
  /** The capability id at the top of a revoked subtree (every descendant is revoked with it). */
  subtreeRoot?: string;
  /** Every capability id this record covers (a single cap, or an entire revoked subtree root→leaf). */
  capIds?: string[];
  /** Human-readable reason. */
  reason: string;
  /** Epoch-ms timestamp the revocation was recorded. */
  revokedAt: number;
}

/** The result of a rotation / re-issue: the new chain plus the revocation record for the old key(s). */
export interface RotationResult {
  /** The re-issued chain — accepted by `verifyChain` under the (possibly new) root issuer. */
  chain: CapabilityChain;
  /** The revocation record for the key / subtree that was rotated out. */
  revocation: RevocationRecord;
}

// ---- internal helpers -----------------------------------------------------------------------------

/** b64u public key for a secret key. */
function pub(secret: Uint8Array): string {
  if (!(secret instanceof Uint8Array)) throw new TypeError('expected a Uint8Array secret key');
  return encodeKey(publicKeyOf(secret));
}

/** A capability at `i`, or a precise error ( `noUncheckedIndexedAccess`-safe, no `!`). */
function at(chain: CapabilityChain, i: number, ctx: string): Capability {
  const c = chain[i];
  if (c === undefined) throw new RangeError(`${ctx}: no capability at index ${i} (chain length ${chain.length})`);
  return c;
}

/**
 * The caveats a child appended beyond its parent. Caveats are append-only (the core's `delegate` builds
 * `child.caveats = [...parent.caveats, ...added]` and `verifyChain` enforces the parent is an exact
 * prefix), so re-delegating with exactly this slice reproduces the child's cumulative authority — never
 * wider, never narrower.
 */
function appendedCaveats(parent: Capability, child: Capability): Caveat[] {
  if (!Array.isArray(child.caveats) || !Array.isArray(parent.caveats)) {
    throw new TypeError('malformed capability: caveats must be arrays');
  }
  if (child.caveats.length < parent.caveats.length) {
    throw new Error('malformed chain: a child carries fewer caveats than its parent (not an attenuation)');
  }
  return child.caveats.slice(parent.caveats.length);
}

function requireNonEmpty(chain: CapabilityChain, ctx: string): void {
  if (!Array.isArray(chain) || chain.length === 0) throw new Error(`${ctx}: empty chain`);
}

// ---- agent (leaf holder) key rotation ------------------------------------------------------------

/**
 * Rotate the AGENT (leaf holder) key: the leaf's parent re-signs the leaf delegation, re-binding it to
 * `newKeyPair`'s public key while preserving the leaf's exact caveats. The returned chain is accepted by
 * `verifyChain` and a PCActn now verifies under the NEW holder key (and no longer under the old one).
 *
 * `oldHolderSecret` is the secret that RE-SIGNS the leaf hop — i.e. the leaf's issuer, which is the
 * parent's holder key. In the canonical agent chain (a root delegated to the agent, then the agent's own
 * self-attenuated leaf) that issuer IS the agent's current key, so this is literally the old holder's
 * secret. For a sub-agent leaf it is the delegating parent's secret. The call throws if the secret does
 * not match the leaf's issuer (the only key whose signature `verifyChain` will accept for that hop).
 *
 * A root-only chain has no leaf delegation to re-issue; rotate the root holder via
 * {@link rotatePrincipalKey} (or add a delegation) instead.
 */
export function rotateAgentKey(
  chain: CapabilityChain,
  opts: { oldHolderSecret: Uint8Array; newKeyPair: KeyPair; reason?: string; now?: number },
): RotationResult {
  requireNonEmpty(chain, 'rotateAgentKey');
  if (chain.length < 2) {
    throw new Error('rotateAgentKey: a root-only chain has no leaf delegation to re-issue; use rotatePrincipalKey');
  }
  const parent = at(chain, chain.length - 2, 'rotateAgentKey');
  const leaf = at(chain, chain.length - 1, 'rotateAgentKey');

  const signerPub = pub(opts.oldHolderSecret);
  if (signerPub !== leaf.issuer) {
    throw new Error(
      `rotateAgentKey: oldHolderSecret (pub ${signerPub}) is not the leaf's issuer ${leaf.issuer}; ` +
        'the leaf is re-signed by its parent holder (the leaf issuer)',
    );
  }

  const newHolder = encodeKey(opts.newKeyPair.publicKey);
  const newLeaf = delegate(parent, newHolder, appendedCaveats(parent, leaf), opts.oldHolderSecret);
  const newChain: CapabilityChain = [...chain.slice(0, chain.length - 1), newLeaf];

  return {
    chain: newChain,
    revocation: {
      capId: leaf.id,
      holder: leaf.holder,
      issuer: leaf.issuer,
      capIds: [leaf.id],
      reason: opts.reason ?? 'agent key rotated',
      revokedAt: opts.now ?? Date.now(),
    },
  };
}

// ---- principal (root) key rotation / re-root ------------------------------------------------------

/**
 * Rotate the PRINCIPAL (root) key by RE-ROOTING: mint a fresh root under `newPrincipalKeyPair`, bound to
 * the same agent holder and the same root caveats, then re-issue every downstream hop onto the new root
 * (holders are unchanged, so every hop is re-signed by the same issuer secret it had before — supply
 * those in `holderSecrets`, chain order, one per non-root hop). The returned chain is accepted by
 * `verifyChain` under the NEW principal and rejected under the old one.
 *
 * Pass the full `chain` (recommended) or, for a root-only chain, just `oldRoot`. `oldPrincipalSecret`
 * must be the current root's issuer (the old principal); it is the authority being rotated out and is
 * named in the revocation record (the entire old chain is revoked with the old root).
 */
export function rotatePrincipalKey(args: {
  /** The full current chain (chain[0] is the root). Omit and pass `oldRoot` for a root-only chain. */
  chain?: CapabilityChain;
  /** The current root, for a root-only chain (ignored when `chain` is given). */
  oldRoot?: Capability;
  /** The old principal secret — must equal the current root's issuer. */
  oldPrincipalSecret: Uint8Array;
  /** The replacement principal key pair; the new root is signed by (and rooted at) its public key. */
  newPrincipalKeyPair: KeyPair;
  /** Signer secrets for the non-root hops, in chain order: each is that hop's issuer secret (unchanged by re-rooting). */
  holderSecrets?: Uint8Array[];
  reason?: string;
  now?: number;
}): RotationResult {
  const chain: CapabilityChain = args.chain ?? (args.oldRoot ? [args.oldRoot] : []);
  requireNonEmpty(chain, 'rotatePrincipalKey');
  const oldRoot = at(chain, 0, 'rotatePrincipalKey');
  if (oldRoot.parent !== undefined) throw new Error('rotatePrincipalKey: chain[0] is not a root (it has a parent)');

  const oldPrincipalPub = pub(args.oldPrincipalSecret);
  if (oldPrincipalPub !== oldRoot.issuer) {
    throw new Error(
      `rotatePrincipalKey: oldPrincipalSecret (pub ${oldPrincipalPub}) is not the root's issuer ${oldRoot.issuer}`,
    );
  }

  const holderSecrets = args.holderSecrets ?? [];
  if (holderSecrets.length !== chain.length - 1) {
    throw new Error(
      `rotatePrincipalKey: expected ${chain.length - 1} holderSecrets (one per non-root hop), got ${holderSecrets.length}`,
    );
  }

  const newPrincipalPub = encodeKey(args.newPrincipalKeyPair.publicKey);
  const newRoot = mintRoot({
    principalSecret: args.newPrincipalKeyPair.secretKey,
    principalPublic: newPrincipalPub,
    holder: oldRoot.holder,
    caveats: oldRoot.caveats,
  });

  const newChain: CapabilityChain = [newRoot];
  for (let i = 1; i < chain.length; i++) {
    const oldParent = at(chain, i - 1, 'rotatePrincipalKey');
    const oldChild = at(chain, i, 'rotatePrincipalKey');
    const signer = holderSecrets[i - 1];
    if (signer === undefined) throw new RangeError(`rotatePrincipalKey: missing holderSecret for hop ${i}`);
    const signerPub = pub(signer);
    if (signerPub !== oldChild.issuer) {
      throw new Error(
        `rotatePrincipalKey: holderSecret for hop ${i} (pub ${signerPub}) is not that hop's issuer ${oldChild.issuer}`,
      );
    }
    const newParent = at(newChain, i - 1, 'rotatePrincipalKey');
    newChain.push(delegate(newParent, oldChild.holder, appendedCaveats(oldParent, oldChild), signer));
  }

  return {
    chain: newChain,
    revocation: {
      capId: oldRoot.id,
      issuer: oldRoot.issuer,
      holder: oldRoot.holder,
      subtreeRoot: oldRoot.id,
      capIds: chain.map((c) => c.id),
      reason: args.reason ?? 'principal key rotated (re-root)',
      revokedAt: args.now ?? Date.now(),
    },
  };
}

// ---- compromised-subtree revoke + re-issue -------------------------------------------------------

/** First index whose holder is `holder`, or -1. The shallowest such hop is where the compromise enters. */
function indexOfHolder(chain: CapabilityChain, holder: string): number {
  for (let i = 0; i < chain.length; i++) {
    if (at(chain, i, 'revokeAndReissueSubtree').holder === holder) return i;
  }
  return -1;
}

/**
 * Treat `compromisedHolder` as COMPROMISED: revoke the hop it first holds and every descendant (its whole
 * delegation subtree), and re-issue a fresh chain from the nearest SAFE ancestor (the hop just above the
 * compromised one) down to a brand-new key.
 *
 * The re-issue collapses the entire compromised subtree into one new delegation from the safe ancestor to
 * `newKeyPair`, carrying the caveats of the subtree's deepest (narrowest) leaf — so the re-issued
 * authority equals the old leaf's and is never wider. `ancestorSecret` must be the safe ancestor's holder
 * secret (the key that signs the new delegation); it is the first UNCOMPROMISED key up the chain, so the
 * caller legitimately holds it. Throws if `compromisedHolder` is not in the chain, or is the root holder
 * (there is no delegation ancestor to re-issue from — rotate the root with {@link rotatePrincipalKey}).
 */
export function revokeAndReissueSubtree(
  chain: CapabilityChain,
  compromisedHolder: string,
  opts: { newKeyPair: KeyPair; ancestorSecret: Uint8Array; reason?: string; now?: number },
): RotationResult {
  requireNonEmpty(chain, 'revokeAndReissueSubtree');
  const idx = indexOfHolder(chain, compromisedHolder);
  if (idx < 0) throw new Error(`revokeAndReissueSubtree: holder ${compromisedHolder} is not in the chain`);
  if (idx === 0) {
    throw new Error(
      'revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); ' +
        'rotate the root with rotatePrincipalKey',
    );
  }

  const ancestor = at(chain, idx - 1, 'revokeAndReissueSubtree');
  const subtreeRoot = at(chain, idx, 'revokeAndReissueSubtree');
  const leaf = at(chain, chain.length - 1, 'revokeAndReissueSubtree');

  const ancestorPub = pub(opts.ancestorSecret);
  if (ancestorPub !== ancestor.holder) {
    throw new Error(
      `revokeAndReissueSubtree: ancestorSecret (pub ${ancestorPub}) is not the safe ancestor's holder ${ancestor.holder}`,
    );
  }

  const newHolder = encodeKey(opts.newKeyPair.publicKey);
  // Re-delegate from the safe ancestor straight to the new key, carrying the deepest leaf's appended
  // caveats so the re-issued authority equals the old narrowest leaf's (never widened).
  const newHop = delegate(ancestor, newHolder, appendedCaveats(ancestor, leaf), opts.ancestorSecret);
  const reissued: CapabilityChain = [...chain.slice(0, idx), newHop];

  const revokedIds = chain.slice(idx).map((c) => c.id);
  return {
    chain: reissued,
    revocation: {
      capId: subtreeRoot.id,
      holder: compromisedHolder,
      issuer: subtreeRoot.issuer,
      subtreeRoot: subtreeRoot.id,
      capIds: revokedIds,
      reason: opts.reason ?? 'delegation subtree compromised',
      revokedAt: opts.now ?? Date.now(),
    },
  };
}

/**
 * Convenience over {@link revokeAndReissueSubtree}: handle a compromised key end-to-end, returning one
 * revocation record PER capability in the compromised subtree (root→leaf, so a registry can revoke each
 * id) plus the re-issued chain from the nearest safe ancestor.
 */
export function compromisedKeyFlow(
  chain: CapabilityChain,
  compromisedHolder: string,
  opts: { newKeyPair: KeyPair; ancestorSecret: Uint8Array; reason?: string; now?: number },
): { revocations: RevocationRecord[]; reissued: CapabilityChain } {
  requireNonEmpty(chain, 'compromisedKeyFlow');
  const idx = indexOfHolder(chain, compromisedHolder);
  if (idx < 0) throw new Error(`compromisedKeyFlow: holder ${compromisedHolder} is not in the chain`);

  const { chain: reissued } = revokeAndReissueSubtree(chain, compromisedHolder, opts);

  const subtreeRoot = at(chain, idx, 'compromisedKeyFlow');
  const revokedAt = opts.now ?? Date.now();
  const reason = opts.reason ?? 'delegation subtree compromised';
  const revocations: RevocationRecord[] = chain.slice(idx).map((c) => ({
    capId: c.id,
    holder: c.holder,
    issuer: c.issuer,
    subtreeRoot: subtreeRoot.id,
    capIds: [c.id],
    reason,
    revokedAt,
  }));

  return { revocations, reissued };
}
