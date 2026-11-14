/**
 * THE FACADE  --  the three-line version of the PCA loop.
 *
 * `examples/pca-loop.ts` shows every primitive by hand. This shows the way almost everyone should
 * actually use PCA: `agent({...})` compiles a human-level intent into the signed grant + policy +
 * trust budget for you, and `.act()` hands you a proof-carrying action to attach to each tool call.
 * A guard wraps a tool so this happens automatically.
 *
 * Run:   pnpm --filter @atlasauth/pca exec tsx examples/agent-facade.ts
 *
 * Only the real exported API is used. The resource-server verification is the SAME full server verifier
 * (`verifyPCActn`, with the default-deny profile) a real RS runs behind `requirePCA`: the grant the RS holds,
 * the grant's predicates and limits, the authorized plan, revocation, budget and the server-derived threshold.
 * A well-formed, signed proof alone authorizes nothing.
 */
import {
  agent,
  generateKeyPair,
  guard,
  PCA_HEADER,
  DEFAULT_REQUIRED_CHECKS,
  verifyPCActn,
  merkleRoot,
  planNodeLeaf,
  decodePCActn,
  type PCActn,
  type PcaVerdict,
  type PlanNode,
} from '../src/index';

async function main() {
  // The principal (the human) — the longest-lived key; it roots + signs the grant.
  const principal = generateKeyPair();

  // One call compiles intent → predicates + caveats + risk budget + a signed Root Intent Grant.
  const a = agent({
    principal,
    goal: 'reconcile October refunds for unhappy customers',
    permissions: { stripe: ['refund'], gmail: ['send'] },
    limits: { refund: '$500/day' },
    aud: 'ins_acme', // the resource server / Atlas instance these actions are for
  });

  console.log('grant holder (agent) key:', a.principalPublic.slice(0, 12), '…');
  console.log('budget model:', a.policy.budgetModel, '| κ:', a.policy.riskPolicy.kappa, '| bMax:', a.policy.riskPolicy.bMax);
  console.log('autonomy bound (max autonomous spend between human co-signs): $' + a.autonomyBound);

  // The resource server's decision: the full verifier under the grant the RS holds (never one the request carries).
  const rsVerify = (p: PCActn, params: Record<string, unknown>): Promise<PcaVerdict> => {
    const now = Date.now();
    const plan: PlanNode[] = [{ id: p.plan.node_id, verb: p.action.verb, resource: p.action.resource, params_digest: p.action.params_digest, reversibility_class: p.action.reversibility_class }];
    return verifyPCActn(p, { insecureSkipPlanRootCheck: true,
      grant: a.grant,
      audience: 'ins_acme',
      allowedSuites: ['ed25519'],
      now,
      hooks: { revocation: () => ({ enforced: true, ok: true }) }, // your revocation list
      // here the principal has authorized every one-node plan the agent proposes; a real RS keeps its own list
      context: { params, plan, planAuthorized: merkleRoot(plan.map(planNodeLeaf)) === p.plan.root, budget: { B: a.policy.riskPolicy.bMax, tau: now, asOf: now } },
      require: [...DEFAULT_REQUIRED_CHECKS],
    });
  };

  // --- a tool call, guarded. Each invocation silently produces a PCActn. -------------------------
  const issueRefund = guard<{ amount: number; currency: string; charge: string }, { status: string }>(
    a,
    { verb: 'stripe.refund', resource: (p) => `charge:${p.charge}` },
    async (params, pca) => {
      // In a real client this is your fetch/SDK call; the proof rides in a header the RS reads.
      console.log(`\n→ dispatching stripe.refund $${params.amount} with header ${PCA_HEADER}=<${pca.encoded.length}B PCActn>`);
      // Here we play the resource server and verify offline with the full verifier, as requirePCA() would.
      const res = await rsVerify(pca.pcactn, params);
      console.log('   RS verify:', JSON.stringify(res.checks));
      if (!res.allow) throw new Error('RS rejected: ' + res.reasons.join('; '));
      return { status: 'refunded' };
    },
  );

  // Within the $500 cap → auto (t=1), verifies, dispatched.
  const ok = await issueRefund({ amount: 42, currency: 'usd', charge: 'ch_abc' }, { counter: 1 });
  console.log('   result:', ok);

  // Over the cap → the local dry-run fast-fails BEFORE any dispatch (PcaDenied).
  try {
    await issueRefund({ amount: 5_000, currency: 'usd', charge: 'ch_big' }, { counter: 2 });
  } catch (e) {
    console.log('\n✗ over-cap refund rejected locally:', (e as Error).message);
  }

  // A sub-agent: delegate one attenuated hop to a worker key; it signs its own actions.
  const worker = a.subAgent();
  const mail = { to: 'cust@example.com', body: 'Your refund is on its way.' };
  const sent = worker.act('gmail.send', 'msg:thread-1', mail, { counter: 1 });
  const subRes = await rsVerify(sent.pcactn, mail);
  console.log('\nsub-agent gmail.send verify:', subRes.allow ? 'ALLOW' : 'DENY', JSON.stringify(subRes.checks));

  // A compromised agent signs an action the grant never allowed: the proof is valid, the verifier still denies.
  const rogue = a.act('github.delete_repo', 'repo:prod', {}, { counter: 3 });
  const rogueRes = await rsVerify(rogue.pcactn, {});
  console.log('\nout-of-scope github.delete_repo:', rogueRes.allow ? 'ALLOW (BUG)' : 'DENY', '|', rogueRes.reasons.find((r) => /no predicate permits/.test(r)) ?? rogueRes.reasons[0]);
  if (rogueRes.allow) throw new Error('out-of-scope action was allowed');
  console.log('decoded verb:', decodePCActn(sent.encoded).action.verb, '| chain depth:', sent.pcactn.cap_chain.length);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
