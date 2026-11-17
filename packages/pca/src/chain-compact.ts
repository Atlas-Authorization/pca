import { type Capability, type CapabilityChain, type ChainPolicy, MAX_CHAIN_DEPTH, capHash, verifyChain } from './capability';
import { type ChainView, chainView } from './caveat-lang';
import { merkleRoot } from './merkle';
import { closedMembers, isPlainObject, isSafeInt } from './intent-artifacts';

/**
 * CHAIN COMPACTION (track K1, item 2): a long delegation chain folds into one handle, a Merkle root over the ordered hop hashes, plus
 * the leaf hop. The verifier that has already verified the full chain once remembers it under that root; later presentations carry
 * only `{depth, hops_root, leaf}`.
 *
 *  - The root commits to the order and the number of hops: a different chain, an inserted, dropped or reordered hop has another root.
 *  - Nothing is trusted from the presentation. A compact chain is accepted only when the verifier's OWN memo holds an entry for
 *    `hops_root` that its own `verifyChain` produced ({@link ChainMemo.rememberVerified} runs the verification itself, so an
 *    unverified chain cannot be remembered), the depth equals the memoized depth, and the presented leaf hashes to the memoized last hop.
 *  - What a compact chain gives the caveat language is a {@link ChainView}: hop count, per-hop hash and caveat-list length, and the
 *    leaf. `evaluateK1`, `verifyNarrow`, `boundCaveats` and `dischargeRequests` accept it in place of the full chain and decide
 *    identically (the shared k1_eval vectors are replayed through it).
 *
 * Scope: this is the verifier-side fold. The PCActn wire still carries `cap_chain` (the verified core reads it); a compact PCActn member
 * is a wire change to the proved core and is not part of this track.
 */

export const CHAIN_HOP_DOMAIN = 'atlas-pca/chain-hop/v1';
/** A memo entry lives at most this long (the chain's caveats may expire sooner; the verifier still evaluates them every time). */
export const CHAIN_MEMO_MAX_TTL_MS = 3_600_000;
export const CHAIN_MEMO_DEFAULT_MAX_ENTRIES = 10_000;

/** The Merkle leaf of one hop: its content hash under a domain tag. */
export const hopLeaf = (hop: Capability): { d: string; hop: string } => ({ d: CHAIN_HOP_DOMAIN, hop: capHash(hop) });

/** The handle of a chain: Merkle root over the ordered hop leaves. */
export function hopsRoot(chain: CapabilityChain): string {
  return merkleRoot(chain.map(hopLeaf));
}

export interface CompactChain {
  v: 1;
  kind: 'pca-chain-compact';
  /** Number of hops, 1..MAX_CHAIN_DEPTH. */
  depth: number;
  hops_root: string;
  /** The last hop, in full. */
  leaf: Capability;
}

/** Fold a chain. Throws on an empty or over-deep chain. Does not verify it (the memo does). */
export function compactChain(chain: CapabilityChain): CompactChain {
  if (!Array.isArray(chain) || chain.length === 0 || chain.length > MAX_CHAIN_DEPTH) throw new Error('compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops');
  return { v: 1, kind: 'pca-chain-compact', depth: chain.length, hops_root: hopsRoot(chain), leaf: chain[chain.length - 1]! };
}

export function compactChainShapeError(c: unknown): string | null {
  if (!isPlainObject(c)) return 'not an object';
  const e = closedMembers(c, ['v', 'kind', 'depth', 'hops_root', 'leaf'], [], 'compact chain');
  if (e) return e;
  if (c.v !== 1 || c.kind !== 'pca-chain-compact') return 'not a pca-chain-compact v1';
  if (!(isSafeInt(c.depth) && c.depth >= 1 && c.depth <= MAX_CHAIN_DEPTH)) return `depth must be 1..${MAX_CHAIN_DEPTH}`;
  if (typeof c.hops_root !== 'string' || c.hops_root.length !== 43) return 'hops_root must be a 43 character digest';
  if (!isPlainObject(c.leaf)) return 'leaf must be a capability';
  return null;
}

export interface ChainMemoEntry {
  depth: number;
  hops_root: string;
  /** capHash of every hop, root first. */
  hashes: readonly string[];
  /** Length of every hop's (cumulative) caveat list. */
  counts: readonly number[];
  expires_at: number;
}

export type ResolveVerdict = { ok: true; view: ChainView } | { ok: false; reason: string };

export class ChainMemo {
  private readonly entries = new Map<string, ChainMemoEntry>();
  constructor(private readonly opts: { maxEntries?: number; ttlMs?: number } = {}) {}

  get size(): number {
    return this.entries.size;
  }

  /**
   * Verify `chain` (rooted at `expectedRootIssuer`) with the full verifier and remember it. Throws when the chain does not verify or
   * the memo is full of live entries (fail closed: a full memo never evicts a live entry, so one tenant cannot push another out).
   * Returns the compact form a holder presents.
   */
  rememberVerified(chain: CapabilityChain, expectedRootIssuer: string, now: number, policy?: ChainPolicy): CompactChain {
    if (!isSafeInt(now)) throw new Error('rememberVerified: the clock is not a safe integer');
    const v = verifyChain(chain, expectedRootIssuer, policy);
    if (!v.ok) throw new Error(`rememberVerified: the chain does not verify: ${v.reason ?? 'invalid'}`);
    const compact = compactChain(chain);
    const ttl = Math.min(this.opts.ttlMs ?? CHAIN_MEMO_MAX_TTL_MS, CHAIN_MEMO_MAX_TTL_MS);
    this.prune(now);
    if (!this.entries.has(compact.hops_root) && this.entries.size >= (this.opts.maxEntries ?? CHAIN_MEMO_DEFAULT_MAX_ENTRIES)) throw new Error('rememberVerified: the memo is full of live entries');
    this.entries.set(compact.hops_root, {
      depth: chain.length,
      hops_root: compact.hops_root,
      hashes: chain.map((h) => capHash(h)),
      counts: chain.map((h) => h.caveats.length),
      expires_at: now + ttl,
    });
    return compact;
  }

  /** Drop entries whose time is up. */
  prune(now: number): void {
    for (const [k, e] of this.entries) if (e.expires_at < now) this.entries.delete(k);
  }

  /** Forget a chain (e.g. when it is revoked). */
  forget(hopsRootValue: string): boolean {
    return this.entries.delete(hopsRootValue);
  }

  /** Resolve a presented compact chain against the memo. Total. */
  resolve(compact: unknown, now: number): ResolveVerdict {
    try {
      if (!isSafeInt(now)) return { ok: false, reason: 'the verifier clock is not a safe integer (fail closed)' };
      const e = compactChainShapeError(compact);
      if (e) return { ok: false, reason: `malformed compact chain: ${e}` };
      const c = compact as CompactChain;
      const m = this.entries.get(c.hops_root);
      if (!m) return { ok: false, reason: 'the chain is not in this verifier memo (present the full chain)' };
      if (m.expires_at < now) {
        this.entries.delete(c.hops_root);
        return { ok: false, reason: 'the memoized chain has expired (present the full chain)' };
      }
      if (m.depth !== c.depth) return { ok: false, reason: 'the depth differs from the memoized chain' };
      if (capHash(c.leaf) !== m.hashes[m.depth - 1]) return { ok: false, reason: 'the leaf is not the memoized last hop' };
      if (!Array.isArray(c.leaf.caveats) || c.leaf.caveats.length !== m.counts[m.depth - 1]) return { ok: false, reason: 'the leaf caveats differ from the memoized chain' };
      return { ok: true, view: { n: m.depth, leaf: c.leaf, hash: (i) => m.hashes[i]!, count: (i) => m.counts[i]! } };
    } catch (err) {
      return { ok: false, reason: `compact chain error (fail closed): ${err instanceof Error ? err.message : 'unknown'}` };
    }
  }
}

/** The view of a full chain, for symmetry with {@link ChainMemo.resolve} (both feed the caveat language). */
export const viewOfChain = (grant: Capability, chain: CapabilityChain): ChainView => chainView(grant, chain);
