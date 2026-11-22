/**
 * Delegate to a sub-agent. The parent agent may refund up to $500; it hands a sub-agent a narrower authority (refunds
 * up to $100). The sub-agent's proofs chain back through the parent to the person, and every hop can only narrow:
 * there is no call that widens a grant, so the sub-agent cannot exceed its parent no matter what it signs.
 *
 * The server side is `protect()`: it fills in the grant lookup, replay store, revocation and risk, in one call.
 *
 * Run it:  npm start      (exits nonzero if any outcome is not the expected one)
 */

import { agent, explainRefusal, generateKeyPair, protect, requireAuthorized } from '@atlasauth/pca';

const AUD = 'ins_delegation';

const parent = agent({
  principal: generateKeyPair(), // the person
  goal: 'refund customers for broken orders',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: AUD,
});
// The person's own request, recorded by the agent harness (provenance by default: a sensitive action must derive from it).
parent.provenance?.principal('Refund customers for broken orders: ch_0 $120, ch_1 $60, ch_2 $400, ch_9 $10.');
// One extra hop, narrower: refunds of at most $100. (Also available: expiry, call counts, tool schemas.)
const sub = parent.subAgent({ addedCaveats: [{ type: 'max_spend', usd: 100 }] });

// The server: trusts the person's grant (from its own list, never from the request) and names the operation each route runs.
const server = protect({
  audience: AUD,
  grants: [parent.grant],
  operation: (req) => {
    const b = req.body as { charge: string; params: Record<string, unknown> };
    return { verb: 'stripe.refund', resource: `charge:${b.charge}`, params: b.params };
  },
});
const guard = requireAuthorized(server.options);

async function refund(who: 'parent' | 'sub', charge: string, amount: number): Promise<string> {
  const params = { amount, currency: 'usd' };
  const { encoded, provenance } = (who === 'parent' ? parent : sub).act('stripe.refund', `charge:${charge}`, params);
  const r = await guard({ headers: {}, body: { pcactn: encoded, pca_provenance: provenance, charge, params } });
  if (r.ok) return 'ALLOWED';
  const reason = r.verdict.reasons.find((x) => !x.includes('risk input')) ?? 'denied';
  return `DENIED (${reason}) -> ${explainRefusal(reason).fix}`;
}

// Amounts stay within a quarter of the $500 cap: the refund is irreversible, so a larger one is a human step-up by design.
const cases = [
  { label: 'parent refunds $120 (more than the sub-agent may)', who: 'parent', amount: 120, expect: 'ALLOWED' },
  { label: 'sub-agent refunds $60', who: 'sub', amount: 60, expect: 'ALLOWED' },
  { label: 'sub-agent refunds $400 (parent could, the sub-agent was narrowed)', who: 'sub', amount: 400, expect: 'DENIED' },
] as const;

let ok = true;
for (const [i, c] of cases.entries()) {
  const out = await refund(c.who, `ch_${i}`, c.amount);
  const good = out.startsWith(c.expect);
  if (!good) ok = false;
  console.log(`${good ? 'ok  ' : 'FAIL'} ${c.label.padEnd(66)} -> ${out}`);
}

server.revoke(parent.grant.id); // the person withdraws the grant: the parent and every sub-agent under it stop at once
const after = await refund('sub', 'ch_9', 10);
const good = after.startsWith('DENIED');
if (!good) ok = false;
console.log(`${good ? 'ok  ' : 'FAIL'} ${'after revoking the grant, the sub-agent refunds $10'.padEnd(66)} -> ${after}`);

console.log(ok ? '\nAll outcomes as expected.' : '\nAn outcome was not as expected.');
process.exit(ok ? 0 : 1);
