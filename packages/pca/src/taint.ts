import type { ResourceGraph } from './objective-risk';

/**
 * L4 information-flow taint (spec §6 L4, the "untrusted-lineage" risk dimension).
 *
 * Replaces the conservative constant stub (`serverObservedTaint === undefined`, which pinned taint to the
 * worst case 1 for every action, so the dimension never discriminated) with a REAL computed signal.
 *
 * SAFETY PRINCIPLE (the whole point). Agent-declared provenance is UNTRUSTED. Taint may only be LOWERED
 * below the worst case (1) for inputs the SERVER can INDEPENDENTLY verify as trusted. The agent chooses WHICH
 * refs to declare, but it never chooses their LABEL: every declared ref is re-classified here from facts the
 * server holds (a trusted-input registry it populated, or its own committed resource graph). A ref the agent
 * merely *claims* is "trusted" but that the server cannot vouch for is treated as `agent` (worst), so a claim
 * can never forge low taint. The result is combined downstream as `max(computed, agentClaim)` (see
 * `deriveRisk`), so the agent's own `taint_level` can still only RAISE the number.
 *
 * Pure and deterministic: no time, no randomness, no I/O. Malformed/absent provenance and any internal error
 * fail CLOSED to taint 1.
 *
 * KNOWN BOUNDARY (documented, not a bug). The lineage this reads is agent-DECLARED: a compromised agent that
 * UNDER-declares its dirty inputs could look cleaner than it is. That is why going below 1 requires POSITIVE,
 * server-verifiable evidence for EVERY declared ref and a non-empty declared set, the default is fail-closed 1,
 * and the number is a `max` floor the agent can only raise — never a value the agent hands us.
 */

// ---- label lattice -----------------------------------------------------------------------
//
// A total-order join-semilattice of trust levels, least-trusted last:
//
//     trusted  ⊏  first_party  ⊏  tool:<id>  ⊏  web  ⊏  agent:<id>
//
// `join` = least-upper-bound = the higher-ranked label (worse lineage wins). The `tool`/`agent` ids are
// explanatory metadata; when two labels of the SAME rank but DIFFERENT id are joined they collapse to the
// rank's generic representative (id dropped), which keeps join idempotent, commutative and associative.

export const TAINT_LEVELS = ['trusted', 'first_party', 'tool', 'web', 'agent'] as const;
export type TaintLevel = (typeof TAINT_LEVELS)[number];

export type TaintLabel =
  | { kind: 'trusted' }
  | { kind: 'first_party' }
  | { kind: 'tool'; id?: string }
  | { kind: 'web' }
  | { kind: 'agent'; id?: string };

const RANK: Record<TaintLevel, number> = { trusted: 0, first_party: 1, tool: 2, web: 3, agent: 4 };
const MAX_RANK = TAINT_LEVELS.length - 1; // 4

/** Bottom of the lattice: the most-trusted label (identity element of `join`). */
export const BOTTOM: TaintLabel = { kind: 'trusted' };
/** Top of the lattice: the least-trusted label (fail-closed / worst case). */
export const TOP: TaintLabel = { kind: 'agent' };

export const labelRank = (l: TaintLabel): number => RANK[l.kind];

/** Normalized taint value of a label in [0,1]: trusted→0, first_party→0.25, tool→0.5, web→0.75, agent→1. */
export const taintValue = (l: TaintLabel): number => labelRank(l) / MAX_RANK;

const labelId = (l: TaintLabel): string | undefined => ('id' in l ? l.id : undefined);

/** Least-upper-bound of two labels. Commutative, associative, idempotent; `BOTTOM` is the identity. */
export function joinLabel(a: TaintLabel, b: TaintLabel): TaintLabel {
  const ra = labelRank(a);
  const rb = labelRank(b);
  if (ra > rb) return a;
  if (rb > ra) return b;
  // Equal rank ⇒ same kind. Keep the id only when both agree; otherwise collapse to the generic representative.
  const ida = labelId(a);
  const idb = labelId(b);
  if (ida === idb) return a;
  return { kind: a.kind } as TaintLabel;
}

/**
 * Join over a list of labels. The EMPTY lineage joins to `TOP` (worst): "no verifiable trusted input" is not
 * the same as "trusted", so it must fail closed. Non-empty is a seedless fold (order-independent by the
 * semilattice laws), which is what makes {@link computeTaint} deterministic regardless of ref order.
 */
export function joinLabels(labels: readonly TaintLabel[]): TaintLabel {
  if (labels.length === 0) return { ...TOP };
  return labels.reduce((acc, l) => joinLabel(acc, l));
}

// ---- trusted-input registry --------------------------------------------------------------
//
// The server records inputs it can VOUCH for, keyed by a content digest. An input ref counts as trusted ONLY
// because the SERVER put it here (a verified principal utterance, a first-party resource snapshot, a known
// tool's attested output), NEVER because the agent said so. The registry is populated from server-side
// evidence; nothing an agent sends reaches it.

export interface TrustedInputRegistry {
  /** The label the SERVER independently vouches for this content digest, or `undefined` if it vouches for none. */
  lookup(digest: string): TaintLabel | undefined;
}

const freezeLabel = (l: TaintLabel): TaintLabel => ({ ...l });

export class InMemoryTrustedInputRegistry implements TrustedInputRegistry {
  private readonly m = new Map<string, TaintLabel>();

  /** Server-only: record that `digest` is an input the server independently verified at `label`. */
  record(digest: string, label: TaintLabel): this {
    if (typeof digest === 'string' && digest.length > 0 && RANK[label?.kind] !== undefined) {
      this.m.set(digest, freezeLabel(label));
    }
    return this;
  }
  /** A verified principal utterance / fully trusted first-party input (lattice bottom). */
  recordTrusted(digest: string): this {
    return this.record(digest, { kind: 'trusted' });
  }
  /** A server-owned first-party resource the server can check. */
  recordFirstParty(digest: string): this {
    return this.record(digest, { kind: 'first_party' });
  }
  /** The attested output of a known tool. */
  recordTool(digest: string, id: string): this {
    return this.record(digest, { kind: 'tool', id });
  }
  /** Content the server itself fetched from / observed on the open web. */
  recordWeb(digest: string): this {
    return this.record(digest, { kind: 'web' });
  }

  lookup(digest: string): TaintLabel | undefined {
    const l = this.m.get(digest);
    return l ? freezeLabel(l) : undefined;
  }
  get size(): number {
    return this.m.size;
  }
}

/** The empty registry: vouches for nothing (every ref falls through to the resource graph / worst case). */
export const EMPTY_REGISTRY: TrustedInputRegistry = { lookup: () => undefined };

// ---- classification + composition --------------------------------------------------------

export interface TaintContext {
  /** Digests the SERVER independently verified as trusted inputs. */
  registry: TrustedInputRegistry;
  /**
   * The committed, operator-controlled resource graph (objective-risk). A ref naming one of its nodes is a
   * first-party input the server can check against its own records — "a signed first-party source". READ-ONLY
   * (only `node(id)` is called); the graph is never mutated. Operator-controlled, so it is server-authoritative
   * even without the grant's objective-risk commitment (the agent cannot add a node to it).
   */
  resourceGraph?: Pick<ResourceGraph, 'node'>;
}

/**
 * Independently classify ONE declared provenance ref. The agent's own label is never read:
 *   1. server-vouched in the registry  → the REGISTERED label (trusted / first_party / tool / web / ...)
 *   2. else names a resource-graph node → `first_party` (a first-party source the server can check)
 *   3. else unverifiable                → `agent` (worst): the agent merely asserted it.
 * A non-string / empty ref is malformed → `agent`.
 */
export function classifyRef(ref: unknown, ctx: TaintContext): TaintLabel {
  if (typeof ref !== 'string' || ref.length === 0) return { kind: 'agent' };
  const vouched = ctx.registry.lookup(ref);
  if (vouched && RANK[vouched.kind] !== undefined) return vouched;
  try {
    if (ctx.resourceGraph?.node(ref)) return { kind: 'first_party' };
  } catch {
    /* fall through to worst case */
  }
  return { kind: 'agent', id: ref.length <= 128 ? ref : undefined };
}

/** Minimal provenance shape read here; everything else on the PCActn provenance is ignored. */
export interface TaintProvenance {
  causal_hash?: unknown;
  taint_level?: unknown;
  trusted_refs?: unknown;
}

export interface TaintRefClassification {
  ref: string;
  label: TaintLabel;
}

export interface TaintResult {
  /** Normalized join over the declared lineage in [0,1]; exactly 1 when fail-closed. */
  taint: number;
  /** The join (LUB) label the value came from. */
  label: TaintLabel;
  /** Per-ref independent classification (audit / explanation). */
  refs: TaintRefClassification[];
  /** `false` iff the provenance was absent/malformed (then taint is the fail-closed 1). */
  valid: boolean;
  reason?: string;
}

/**
 * Compute the information-flow taint for a PCActn's provenance.
 *
 * `taint = taintValue(join over the independently-classified declared input refs)`. All-trusted verified
 * lineage → 0; any unverifiable/web/agent ref → high (up to 1); an empty lineage → 1 (no trusted evidence).
 * Fail-closed: a missing context, absent/malformed provenance, a non-array `trusted_refs`, or any non-string
 * ref all return `{ taint: 1, valid: false }`. Never throws.
 */
export function computeTaint(provenance: unknown, ctx: TaintContext): TaintResult {
  const fail = (reason: string): TaintResult => ({ taint: 1, label: { ...TOP }, refs: [], valid: false, reason });
  if (!ctx || !ctx.registry || typeof ctx.registry.lookup !== 'function') return fail('taint: no trusted-input registry');
  if (provenance === null || typeof provenance !== 'object' || Array.isArray(provenance)) {
    return fail('taint: provenance is absent or malformed');
  }
  const refsRaw = (provenance as TaintProvenance).trusted_refs;
  if (refsRaw !== undefined && !Array.isArray(refsRaw)) return fail('taint: trusted_refs must be an array');
  const list = Array.isArray(refsRaw) ? refsRaw : [];
  if (list.some((r) => typeof r !== 'string' || r.length === 0)) return fail('taint: trusted_refs must be non-empty strings');
  const refs: TaintRefClassification[] = (list as string[]).map((ref) => ({ ref, label: classifyRef(ref, ctx) }));
  const label = joinLabels(refs.map((r) => r.label));
  return { taint: taintValue(label), label, refs, valid: true };
}
