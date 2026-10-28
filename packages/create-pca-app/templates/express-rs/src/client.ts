/**
 * Client for the PCA resource server. Mints an agent, then calls POST /refund four times:
 *   1. with two VALID, in-scope proof-carrying actions   -> the server allows both (HTTP 200); the server prices
 *      each refund from its amount, so the first does not spend the whole trust budget
 *   2. with a TAMPERED proof                              -> the server denies it (HTTP 403)
 *   3. with a validly SIGNED action OUTSIDE the grant     -> the server denies it (HTTP 403): the agent's
 *      own key can sign anything, but the grant only says `stripe.refund`, and the server's verifier
 *      enforces the grant's scope and limits
 *
 * Start the server first (`npm start`), then run this (`npm run client`).
 */

import { agent, decodePCActn, generateKeyPair } from '@atlasauth/pca';
import { authorizePlan, registerGrant } from './store.js';

const AUDIENCE = 'ins_quickstart';
const ENDPOINT = 'http://localhost:8787/refund';

let failures = 0;

async function call(label: string, action: string, charge: string, params: Record<string, unknown>, expectAllowed: boolean): Promise<void> {
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'PCA-Action': action,
    },
    body: JSON.stringify({ charge, params }),
  });
  const body: unknown = await res.json();
  const asExpected = res.ok === expectAllowed;
  if (!asExpected) failures++;
  console.log(`\n${asExpected ? 'ok  ' : 'FAIL'} ${label} -> HTTP ${res.status}`);
  console.log(JSON.stringify(body, null, 2));
}

async function main(): Promise<void> {
  // The principal roots the grant; the agent (holder) signs each action.
  const principal = generateKeyPair();
  const a = agent({
    principal,
    goal: 'reconcile October refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUDIENCE,
  });
  // The principal registers the grant with the server OUT-OF-BAND (here: a file in the server's grant
  // store; in production your admin flow or database). The request never carries the grant: the server
  // trusts only what it loaded from its own store.
  registerGrant(a.grant);

  // 1. A valid, in-policy action. The principal authorizes its plan root with the server, out-of-band.
  const params = { amount: 42, currency: 'usd' };
  const { pcactn, encoded } = a.act('stripe.refund', 'charge:ch_123', params, { counter: 1 });
  authorizePlan(a.grant.id, pcactn.plan.root);
  await call('VALID proof', encoded, 'ch_123', params, true);

  // 1b. A second valid refund. The server debited only 42 of the $500 budget for the first one.
  const params2 = { amount: 100, currency: 'usd' };
  const second = a.act('stripe.refund', 'charge:ch_124', params2, { counter: 2 });
  authorizePlan(a.grant.id, second.pcactn.plan.root);
  await call('VALID proof (second refund)', second.encoded, 'ch_124', params2, true);

  // 2. Tamper with the signed action — redirect the refund. The holder signature + plan-inclusion
  //    proof cover `action`, so the server detects it offline and denies (and the route names the charge it will refund).
  const tampered = decodePCActn(encoded);
  tampered.action.resource = 'charge:ch_ATTACKER';
  await call('TAMPERED proof', JSON.stringify(tampered), 'ch_123', params, false);

  // 3. A compromised (or prompt-injected) agent signs an action its grant never allowed. The proof is
  //    perfectly well-formed and signed by the agent's real key; the server still denies it, because the
  //    decision is the grant's scope ("no predicate permits stripe.delete_customer") and the operation this route runs
  //    (it executes stripe.refund, so a proof for any other operation is refused), not the signature.
  const rogue = a.act('stripe.delete_customer', 'cus_ALL', {}, { counter: 3 });
  await call('OUT-OF-SCOPE action (stripe.delete_customer)', rogue.encoded, 'ch_123', {}, false);

  if (failures > 0) {
    console.error(`\n${failures} outcome(s) were not the expected ones.`);
    process.exitCode = 1;
  } else {
    console.log('\nAll outcomes as expected.');
  }
}

main().catch((err: unknown) => {
  console.error(err);
  console.error('\nIs the server running? Start it with `npm start` in another terminal.');
  process.exit(1);
});
