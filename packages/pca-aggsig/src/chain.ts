import {
  type Caveat,
  type ChainResult,
  b64u,
  canonicalBytes,
  hashCanonical,
  unb64u,
  utf8,
} from '@atlasauth/pca';
import { aggregate, aggregateVerify, publicKeyOf, sign as signBls } from './bls';

/**
 * A BLS-suite attenuable capability chain — the compact alternative to the core PCA chain's N
 * separate Ed25519 hop signatures.
 *
 * The chain's STRUCTURE is identical to `@atlasauth/pca`'s Ed25519 `Capability`: each hop signs the
 * canonical body `{ issuer, holder, caveats, parent }`, caveats are append-only (a child's array
 * starts with the parent's exact prefix), holders bind to the next issuer, and parents are
 * hash-linked. The ONLY difference is the signature: every hop is signed with the BLS12-381 PoP
 * scheme (keys in G1, signatures in G2) instead of Ed25519.
 *
 * The payoff is {@link aggregateChainSignatures}: an M-hop chain's M per-hop signatures collapse into
 * ONE 96-byte aggregate, and {@link verifyAggregatedChain} checks ALL M hops with a single
 * pairing-product AggregateVerify instead of M separate verifications. Each hop signs a DISTINCT body
 * (the parent hash-link alone differs per depth), so the distinct-message AggregateVerify applies.
 */

/** Domain separator for a BLS capability hop — distinct from the core chain's `atlas-pca/cap/v1`. */
const CAP_BLS_DOMAIN = 'atlas-pca/cap-bls/v1\0';

/** The signature suite tag carried on every BLS hop. */
export const BLS_SUITE = 'bls12-381-pop' as const;

export interface BlsCapability {
  /** Content address of the signed body (== `body_digest`). */
  id: string;
  /** b64u BLS12-381 G1 public key that signed this hop. Root: the principal; child: the parent's holder. */
  issuer: string;
  /** b64u BLS12-381 G1 public key this capability is bound to (cnf). */
  holder: string;
  caveats: Caveat[];
  /** {@link capHash} of the parent capability; absent on the root. */
  parent?: string;
  body_digest: string;
  /** b64u BLS12-381 G2 signature over the domain-separated hop body. */
  sig: string;
  suite: typeof BLS_SUITE;
}

export type BlsCapabilityChain = BlsCapability[];

/** Longest delegation chain accepted (bounds verification cost; mirrors the core chain's limit). */
export const MAX_CHAIN_DEPTH = 16;

interface HopBody {
  issuer: string;
  holder: string;
  caveats: Caveat[];
  parent: string | null;
}

function bodyOf(c: { issuer: string; holder: string; caveats: Caveat[]; parent?: string }): HopBody {
  return { issuer: c.issuer, holder: c.holder, caveats: c.caveats, parent: c.parent ?? null };
}

/** The exact bytes a hop signs: the domain separator followed by the raw body digest. */
function sigMessage(bodyDigest: string): Uint8Array {
  const d = unb64u(bodyDigest);
  const p = utf8(CAP_BLS_DOMAIN);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return m;
}

/** Hash of a full capability (signature included); used as the child's `parent` link. */
export function capHash(c: BlsCapability): string {
  return hashCanonical(c);
}

function cloneCaveats(cs: readonly Caveat[]): Caveat[] {
  const parsed: unknown = JSON.parse(new TextDecoder().decode(canonicalBytes(cs)));
  return parsed as Caveat[];
}

function seal(body: { issuer: string; holder: string; caveats: Caveat[]; parent?: string }, signerSecret: Uint8Array): BlsCapability {
  const body_digest = hashCanonical(bodyOf(body));
  const sig = b64u(signBls(signerSecret, sigMessage(body_digest)));
  const cap: BlsCapability = {
    id: body_digest,
    issuer: body.issuer,
    holder: body.holder,
    caveats: body.caveats,
    body_digest,
    sig,
    suite: BLS_SUITE,
  };
  if (body.parent !== undefined) cap.parent = body.parent;
  return cap;
}

/** b64u BLS G1 public key for a secret scalar — the identity a chain is rooted at / delegated to. */
export function blsPublicKey(secretKey: Uint8Array): string {
  return b64u(publicKeyOf(secretKey));
}

/** Mint a root capability, signed by the principal (root issuer). */
export function mintBlsRoot(args: {
  principalSecret: Uint8Array;
  /** b64u BLS G1 principal key. */
  principalPublic: string;
  /** b64u BLS G1 holder key. */
  holder: string;
  caveats: Caveat[];
}): BlsCapability {
  return seal({ issuer: args.principalPublic, holder: args.holder, caveats: cloneCaveats(args.caveats) }, args.principalSecret);
}

/** Child with the SAME holder; caveats = parent.caveats ++ added. Signed by the parent's holder. */
export function blsAttenuate(parent: BlsCapability, addedCaveats: Caveat[], signerSecret: Uint8Array): BlsCapability {
  return blsDelegate(parent, parent.holder, addedCaveats, signerSecret);
}

/** Like {@link blsAttenuate}, but rebinds `holder` to a new sub-agent key. */
export function blsDelegate(parent: BlsCapability, toHolder: string, addedCaveats: Caveat[], signerSecret: Uint8Array): BlsCapability {
  return seal(
    {
      issuer: parent.holder,
      holder: toHolder,
      caveats: [...cloneCaveats(parent.caveats), ...cloneCaveats(addedCaveats)],
      parent: capHash(parent),
    },
    signerSecret,
  );
}

function wellTyped(c: unknown): c is BlsCapability {
  if (c === null || typeof c !== 'object') return false;
  const x = c as Record<string, unknown>;
  return (
    typeof x.id === 'string' &&
    typeof x.issuer === 'string' &&
    typeof x.holder === 'string' &&
    typeof x.body_digest === 'string' &&
    typeof x.sig === 'string' &&
    x.suite === BLS_SUITE &&
    (x.parent === undefined || typeof x.parent === 'string') &&
    Array.isArray(x.caveats) &&
    x.caveats.every((cv) => cv !== null && typeof cv === 'object' && !Array.isArray(cv) && typeof (cv as Caveat).type === 'string')
  );
}

/**
 * Collapse every per-hop BLS signature in `chain` into ONE 96-byte aggregate. The chain's hop bodies
 * are not re-derived here — only the signatures are summed; {@link verifyAggregatedChain} re-derives
 * and checks them. Throws on an empty chain or a hop whose `sig` is not valid b64u.
 */
export function aggregateChainSignatures(chain: BlsCapabilityChain): Uint8Array {
  if (!Array.isArray(chain) || chain.length === 0) throw new RangeError('aggregateChainSignatures: empty chain');
  return aggregate(chain.map((c) => unb64u(c.sig)));
}

/**
 * Verify an ENTIRE BLS capability chain against one aggregate signature.
 *
 * Does all the structural checks the core `verifyChain` does — depth bound, well-typedness, root has
 * no parent, optional expected root principal, parent hash-links, holder→issuer continuity, and
 * append-only caveat prefixes — then verifies all M hop signatures at once with a single
 * distinct-message AggregateVerify over each hop's (issuer key, signed body) pair. Never throws.
 */
export function verifyAggregatedChain(chain: BlsCapabilityChain, aggSig: Uint8Array, expectedRootPrincipal?: string): ChainResult {
  if (!Array.isArray(chain) || chain.length === 0) return { ok: false, reason: 'empty chain' };
  if (chain.length > MAX_CHAIN_DEPTH) return { ok: false, reason: `chain too long (max ${MAX_CHAIN_DEPTH} hops)` };
  for (let i = 0; i < chain.length; i++) {
    if (!wellTyped(chain[i])) return { ok: false, reason: `hop ${i}: malformed capability` };
  }

  const pks: Uint8Array[] = [];
  const msgs: Uint8Array[] = [];

  const root = chain[0];
  if (root === undefined) return { ok: false, reason: 'empty chain' };
  if (root.parent !== undefined) return { ok: false, reason: 'hop 0: root must not have a parent' };
  if (expectedRootPrincipal !== undefined && root.issuer !== expectedRootPrincipal) {
    return { ok: false, reason: 'hop 0: root issuer is not the expected principal' };
  }

  for (let i = 0; i < chain.length; i++) {
    const c = chain[i];
    if (c === undefined) return { ok: false, reason: `hop ${i}: missing` };
    let digest: string;
    try {
      digest = hashCanonical(bodyOf(c));
    } catch {
      return { ok: false, reason: `hop ${i}: malformed body` };
    }
    if (digest !== c.body_digest || c.id !== c.body_digest) return { ok: false, reason: `hop ${i}: body digest mismatch` };

    let pk: Uint8Array;
    try {
      pk = unb64u(c.issuer);
    } catch {
      return { ok: false, reason: `hop ${i}: malformed issuer key` };
    }

    if (i > 0) {
      const parent = chain[i - 1];
      if (parent === undefined) return { ok: false, reason: `hop ${i}: missing parent` };
      if (c.parent !== capHash(parent)) return { ok: false, reason: `hop ${i}: broken parent link` };
      if (c.issuer !== parent.holder) return { ok: false, reason: `hop ${i}: issuer is not the parent's bound holder` };
      if (c.caveats.length < parent.caveats.length) return { ok: false, reason: `hop ${i}: drops parent caveat(s)` };
      for (let j = 0; j < parent.caveats.length; j++) {
        if (hashCanonical(c.caveats[j]) !== hashCanonical(parent.caveats[j])) {
          return { ok: false, reason: `hop ${i}: caveat ${j} altered or reordered` };
        }
      }
    }

    pks.push(pk);
    msgs.push(sigMessage(c.body_digest));
  }

  if (!aggregateVerify(pks, msgs, aggSig)) {
    return { ok: false, reason: 'aggregate signature does not verify over all hops' };
  }
  return { ok: true };
}
