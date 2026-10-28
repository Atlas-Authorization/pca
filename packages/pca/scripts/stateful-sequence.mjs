// The stateful layer's reference execution of one sequence (conformance/stateful-vectors.json), shared by
// gen-conformance-stateful.mjs (writes each step's `expect`), the TS conformance test (src/conformance-layers.test.ts,
// recomputes it from source with both store kinds) and the cross-language gate (scripts/pca-conformance-all.mjs).
//
// A sequence is run against ONE fresh store, in order. Its `setup` is the resource server's own state:
//   { audience, grants: [grant...] (resolved by grant_ref), plan_nodes (the principal-authorized plan),
//     risk (RS-supplied risk inputs), initial_budget? (the trust budget every holder stream starts with), revoked: [id...] }
// Steps:
//   { op: 'present', pcactn, params, now, expect: { allow, failed: [check...] } }   one authorization at time `now`
//   { op: 'revoke', id }                                                            add a capability id to the revoked set
// A step's result is { allow, failed } with `failed` the names of the checks that FAILED, sorted (no reason text). The
// reference is `requirePCA` (state keyed by audience, grant and holder) with the default required checks (counter, revocation, plan_root_authorized, audience,
// validity, grant_ref_bound), a revocation hook over the revoked set, and the store passed in (default: the atomic
// in-memory store).

const sortStr = (a) => [...a].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));

/** Run `seq` with the reference module `pca`; returns one result per step ({ allow, failed } for present, null for revoke). */
export async function runSequence(pca, seq, { store = pca.atomicMemoryPcaStore() } = {}) {
  const { setup } = seq;
  const grants = new Map(setup.grants.map((g) => [g.id, g]));
  const revoked = new Set(setup.revoked ?? []);
  let step = null;
  // seed every holder stream the sequence touches with the initial trust budget (the RS's budget store, before any action)
  if (setup.initial_budget) {
    const keys = new Set();
    for (const s of seq.steps) {
      if (s.op !== 'present') continue;
      const leaf = s.pcactn?.cap_chain?.[s.pcactn.cap_chain.length - 1];
      if (grants.has(s.pcactn?.grant_ref) && leaf?.holder) keys.add(pca.pcaStateKey(s.pcactn.grant_ref, leaf.holder, undefined, setup.audience));
    }
    for (const k of keys) await store.put(k, { budget: { ...setup.initial_budget } });
  }
  const guard = pca.requirePCA({
    audience: setup.audience,
    resolveGrant: async (ref) => grants.get(ref) ?? null,
    budgetStore: store,
    insecureAllowUnboundOperation: true, // the vectors fix the proof and the server's params; operation binding has its own tests
    now: () => step.now,
    hooks: {
      revocation: (ctx) => {
        const hit = (ctx.pcactn?.cap_chain ?? []).map((c) => c?.id).find((id) => revoked.has(id));
        return hit ? { enforced: true, ok: false, reason: `revoked: ${hit}` } : { enforced: true, ok: true };
      },
    },
    context: () => ({ plan: setup.plan_nodes, planAuthorized: true, params: step.params, risk: { ...setup.risk } }),
  });
  const out = [];
  for (const s of seq.steps) {
    if (s.op === 'revoke') { revoked.add(s.id); out.push(null); continue; }
    if (s.op !== 'present') throw new Error(`unknown step op ${s.op}`);
    step = s;
    const r = await guard({ headers: {}, body: { pcactn: JSON.stringify(s.pcactn) } });
    const failed = sortStr(Object.entries(r.verdict.checks).filter(([, v]) => v === 'fail').map(([k]) => k));
    out.push({ allow: r.ok === true, failed });
  }
  return out;
}
