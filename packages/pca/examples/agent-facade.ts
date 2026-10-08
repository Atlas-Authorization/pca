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
 * Only the real exported API is used. The resource-server verification at the end is the SAME
 * offline verifier (`verifyPCActnCore`) a real RS runs behind `requirePCA`.
 */
import {
  agent,
  generateKeyPair,
  guard,
  PCA_HEADER,
  verifyPCActnCore,
  decodePCActn,
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

  // --- a tool call, guarded. Each invocation silently produces a PCActn. -------------------------
  const issueRefund = guard<{ amount: number; currency: string; charge: string }, { status: string }>(
    a,
    { verb: 'stripe.refund', resource: (p) => `charge:${p.charge}` },
    async (params, pca) => {
      // In a real client this is your fetch/SDK call; the proof rides in a header the RS reads.
      console.log(`\n→ dispatching stripe.refund $${params.amount} with header ${PCA_HEADER}=<${pca.encoded.length}B PCActn>`);
      // Here we play the resource server and verify offline, exactly as requirePCA() would.
      const res = await verifyPCActnCore(pca.pcactn, { grant: a.grant, audience: 'ins_acme', nowEpoch: pca.pcactn.iat });
      console.log('   RS verify:', JSON.stringify(res.checks));
      if (!res.allow) throw new Error('RS rejected: ' + res.reason);
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
  const sent = worker.act('gmail.send', 'msg:thread-1', { to: 'cust@example.com', body: 'Your refund is on its way.' }, { counter: 1 });
  const subRes = await verifyPCActnCore(sent.pcactn, { grant: a.grant, audience: 'ins_acme', nowEpoch: sent.pcactn.iat });
  console.log('\nsub-agent gmail.send verify:', JSON.stringify(subRes.checks));
  console.log('decoded verb:', decodePCActn(sent.encoded).action.verb, '| chain depth:', sent.pcactn.cap_chain.length);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
