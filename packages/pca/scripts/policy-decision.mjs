// The policy layer's reference evaluation of one `policy_decision` vector (conformance/policy-vectors.json), shared by
// gen-conformance-policy.mjs (writes `expect`), the TS conformance test (src/conformance-layers.test.ts, recomputes it from
// source) and the cross-language gate's TS driver (packages/pca-conformance/adversarial/ref-driver.ts, kind `policy`).
//
// A vector is { grant, chain, context } with context = { now, delegation_depth, blast_radius?, reversibility_class?,
// recent_action_times?, action: { verb, resource, params } } (the `primitives.caveat_eval` context, so the same input
// drives both results below). Two results, no reason text:
//
//   caveats   { allow, failed }       evaluate_caveats(policy_caveats(grant, chain), context): the caveat projection every
//                                      native SDK implements today (root caveats outside the envelope + the hops' appended
//                                      caveats, agent-native evaluator; unknown types unsatisfied).
//   decision  { allow, reasons, failed: { envelope, root, delegated } }
//                                      the whole policy decision of `decide()` (envelope predicates, envelope caveats, root
//                                      caveats, delegated caveats, chain shape) with risk and budget held neutral, as
//                                      ordered reason CODES (REASON_CODES) and the unsatisfied caveat types per group.
//
// `pca` is the reference module (dist or src); nothing here decides anything itself: the codes are read off `decide()`'s
// reasons and every group's failed list is cross-checked against an independent evaluation of the same group (a mismatch
// throws, so the reference cannot silently drift from this projection).

/** Reason codes, in the order `decide()` reports them. */
export const REASON_CODES = [
  'envelope_missing', // the grant carries no valid envelope caveat (nothing else is evaluated)
  'predicates_unsatisfied', // no envelope predicate permits the action
  'chain_malformed', // the delegation chain is empty or malformed
  'envelope_caveats_unsatisfied', // a caveat inside the envelope is unsatisfied
  'root_caveats_unsatisfied', // a caveat on the root grant outside the envelope is unsatisfied
  'delegated_caveats_unsatisfied', // a caveat a delegation hop appended is unsatisfied
];

/** Risk inputs and budget that never deny: the policy layer is judged without the risk / budget layer. */
export const NEUTRAL_RISK = Object.freeze({ semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 });
const neutralBudget = (now) => ({ B: 1e9, tau: now });

const has = (o, k) => o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);

/** The stock caveat context of a vector (the caveat_eval contract). */
function caveatContext(context) {
  return {
    now: context.now,
    delegationDepth: context.delegation_depth,
    blastRadius: has(context, 'blast_radius') ? context.blast_radius : undefined,
    reversibilityClass: has(context, 'reversibility_class') ? context.reversibility_class : undefined,
    recentActionTimes: has(context, 'recent_action_times') ? context.recent_action_times : undefined,
  };
}

/** `evaluate_caveats(policy_caveats(grant, chain), context)`. */
export function caveatProjection(pca, v) {
  const r = pca.evaluateAgentCaveats(pca.policyCaveats(v.grant, v.chain), caveatContext(v.context), { action: v.context.action });
  return { allow: r.ok, failed: r.failed };
}

/** The policy decision of `decide()` as reason codes + failed types per group. */
export function policyDecision(pca, v) {
  const { grant, chain, context } = v;
  const cctx = caveatContext(context);
  const action = { action: context.action };
  const d = pca.decide({
    grant,
    chain,
    action,
    now: context.now,
    risk: { ...NEUTRAL_RISK },
    budget: neutralBudget(context.now),
    // every key explicit: an absent context member stays absent (decide() would otherwise default the blast radius from
    // the risk inputs and the class from the action)
    caveatContext: { blastRadius: cctx.blastRadius, reversibilityClass: cctx.reversibilityClass, recentActionTimes: cctx.recentActionTimes },
  });
  const reasons = [];
  const failed = { envelope: [], root: [], delegated: [] };
  const env = pca.readEnvelope(grant);
  const groups = [
    ['caveat(s) not satisfied: ', 'envelope_caveats_unsatisfied', 'envelope', () => env.caveats],
    ['root caveat(s) not satisfied: ', 'root_caveats_unsatisfied', 'root', () => pca.rootCaveats(grant)],
    ['delegated caveat(s) not satisfied: ', 'delegated_caveats_unsatisfied', 'delegated', () => (Array.isArray(chain) && chain.length ? chain[chain.length - 1].caveats.slice(grant.caveats.length) : [])],
  ];
  for (const text of d.reasons) {
    if (text === 'grant carries no valid envelope') { reasons.push('envelope_missing'); continue; }
    if (text === 'delegation chain is empty or malformed') { reasons.push('chain_malformed'); continue; }
    const g = groups.find(([prefix]) => text.startsWith(prefix));
    if (g) {
      const [prefix, code, key, list] = g;
      // decide() takes the depth from the chain (none without one), never from the context
      const own = pca.evaluateAgentCaveats(list(), { ...cctx, delegationDepth: Array.isArray(chain) && chain.length ? chain.length - 1 : undefined }, action);
      if (own.ok || prefix + own.failed.join(', ') !== text) throw new Error(`policy-decision: decide() reported "${text}" but the ${key} caveats evaluate to ${JSON.stringify(own)}`);
      reasons.push(code);
      failed[key] = own.failed;
      continue;
    }
    if (/^(risk|trust budget|capability chain unverified|invalid decision time|policy evaluation error)/.test(text)) {
      throw new Error(`policy-decision: decide() denied outside the policy layer: ${text}`);
    }
    // the only other reason decide() emits is the predicate step's (first, and only when the predicates refuse)
    const pr = env ? pca.evaluatePredicates(env.predicates, action) : { allowed: true };
    if (pr.allowed || reasons.length) throw new Error(`policy-decision: unexpected decide() reason "${text}"`);
    reasons.push('predicates_unsatisfied');
  }
  const allow = d.releaseGuardianShare === true;
  if (allow !== (reasons.length === 0)) throw new Error(`policy-decision: release=${allow} but reasons ${JSON.stringify(d.reasons)}`);
  return { allow, reasons, failed };
}

/** Both results, in the vector's `expect` shape. */
export function evaluatePolicyVector(pca, v) {
  return { decision: policyDecision(pca, v), caveats: caveatProjection(pca, v) };
}
