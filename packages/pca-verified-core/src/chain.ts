import { Chain, bn, fromOpt, num, seq, wrapRes, type Res, some, none, D } from './bridge';

/** Maximum delegation chain length (hops) accepted by the verified walk. Proved: longer chains are always TooLong. */
export const MAX_CHAIN_DEPTH: number = num(Chain.__default.MaxDepth);

/**
 * Pre-evaluated facts about one hop. Every closure is a PURE function of the artifact: the glue computes it with the
 * trusted primitives (hashing, suite policy, signature verification) and the verified core decides order,
 * first-failure, depth and attenuation. Closures are only called when the core needs them (lazily, in order).
 */
export interface ChainHop<M, C> {
  wellTyped: boolean;
  hasParent: boolean;
  /** hop 0 only: the root issuer is the expected principal (or none is expected). */
  rootIssuerOk: boolean;
  /** this hop's caveat list (opaque elements; compared with `ceq`). */
  caveats: readonly C[];
  /** hops >= 1: `hop.parent === capHash(parent)`. */
  parentLinkOk: () => boolean;
  /** hops >= 1: `hop.issuer === parent.holder`. */
  issuerIsParentHolder: () => boolean;
  /** suite policy (allowedSuites) result. */
  suite: () => Res<M>;
  /** F-2 holder_pq binding result (hops >= 1). */
  pq: () => Res<M>;
  /** body digest + signature result. */
  sig: () => Res<M>;
}

export type ChainError<M> =
  | { kind: 'empty' }
  | { kind: 'too-long' }
  | { kind: 'malformed'; hop: number }
  | { kind: 'root-has-parent' }
  | { kind: 'root-issuer' }
  | { kind: 'suite' | 'pq' | 'sig'; hop: number; m: M }
  | { kind: 'parent-link' | 'issuer-not-holder' | 'drops'; hop: number }
  | { kind: 'altered'; hop: number; caveat: number }
  | { kind: 'alloc'; m: M };

export type ChainDecision<M> = { ok: true } | { ok: false; error: ChainError<M> };

/**
 * Verified chain walk (formal/dafny/Chain.dfy: VerifyChain). `hopAt(i)` builds the facts of hop i on demand; only the
 * first MAX_CHAIN_DEPTH+1 hops are ever materialised, so an absurdly long chain costs O(1) before it is rejected.
 * `ceq(a, b)` is caveat equality (b must be the parent's element), `alloc()` the budget_alloc monotonicity result.
 */
export function decideChain<M, C>(
  length: number,
  hopAt: (i: number) => ChainHop<M, C>,
  ceq: (child: C, parent: C) => boolean,
  alloc: () => Res<M>,
): ChainDecision<M> {
  const n = Math.min(length, MAX_CHAIN_DEPTH + 1);
  const hops: unknown[] = [];
  for (let i = 0; i < n; i++) {
    const h = hopAt(i);
    hops.push(
      Chain.Hop.create_Hop(
        h.wellTyped,
        h.hasParent,
        h.rootIssuerOk,
        seq(h.caveats),
        h.parentLinkOk,
        h.issuerIsParentHolder,
        wrapRes(h.suite),
        wrapRes(h.pq),
        wrapRes(h.sig),
      ),
    );
  }
  const r = Chain.__default.VerifyChain(seq(hops), ceq, wrapRes(alloc));
  if (r.is_ChainOk) return { ok: true };
  const e = r.dtor_e;
  const error = ((): ChainError<M> => {
    if (e.is_Empty) return { kind: 'empty' };
    if (e.is_TooLong) return { kind: 'too-long' };
    if (e.is_Malformed) return { kind: 'malformed', hop: num(e.dtor_hop) };
    if (e.is_RootHasParent) return { kind: 'root-has-parent' };
    if (e.is_RootIssuer) return { kind: 'root-issuer' };
    if (e.is_SuiteErr) return { kind: 'suite', hop: num(e.dtor_hop), m: e.dtor_m as M };
    if (e.is_PqErr) return { kind: 'pq', hop: num(e.dtor_hop), m: e.dtor_m as M };
    if (e.is_SigErr) return { kind: 'sig', hop: num(e.dtor_hop), m: e.dtor_m as M };
    if (e.is_ParentLink) return { kind: 'parent-link', hop: num(e.dtor_hop) };
    if (e.is_IssuerNotHolder) return { kind: 'issuer-not-holder', hop: num(e.dtor_hop) };
    if (e.is_Drops) return { kind: 'drops', hop: num(e.dtor_hop) };
    if (e.is_Altered) return { kind: 'altered', hop: num(e.dtor_hop), caveat: num(e.dtor_j) };
    return { kind: 'alloc', m: e.dtor_m as M };
  })();
  return { ok: false, error };
}

// re-exported for the unit tests / docs
export { bn, fromOpt, some, none, D };
