/**
 * An agent that may pay up to $200 a day on its own, must ask a person for a charge over $50, and is refused
 * anything else. One mandate (a signed grant) holds the terms; every charge is decided against it.
 *
 *   auto      charge is on the merchant list, in the right currency, at most $50, and the day's $200 is not used up
 *   step_up   a person must co-sign: the charge is over $50, or the autonomous $200 is used up
 *   deny      wrong merchant, wrong currency, or over the $200 hard ceiling per charge
 *
 * Amounts are whole dollars here (the mandate requires integers); use cents in production.
 *
 * Run it:  npm start      (exits nonzero if any outcome is not the expected one)
 */

import { encodeKey, generateKeyPair } from '@atlasauth/pca';
import { applyHumanCosign, authorizeCharge, buildPaymentMandate, settleCharge, type Charge } from '@atlasauth/pca-payments';

const principal = generateKeyPair(); // the person who owns the money; in production their passkey-backed key
const agentKey = generateKeyPair(); // the agent's own key

let mandate = buildPaymentMandate({
  principalSecret: principal.secretKey,
  principalPublic: encodeKey(principal.publicKey),
  agentPublic: encodeKey(agentKey.publicKey),
  merchants: ['openai', 'aws'], // only these
  currency: 'USD',
  perTransactionCap: 200, // hard ceiling on one charge
  autoApproveThreshold: 50, // at or under this the agent pays alone
  cumulativeCap: 200, // total the agent may spend alone before a person must refill it
  periodMs: 24 * 3_600_000, // the mandate lasts a day
});

const now = Date.now();
const charge = (merchant: string, amount: number, over: Partial<Charge> = {}): Charge => ({ merchant, amount, currency: 'USD', now, ...over });

const steps: Array<{ label: string; charge: Charge; expect: 'auto' | 'step_up' | 'deny'; cosign?: boolean }> = [
  { label: 'openai $20', charge: charge('openai', 20), expect: 'auto' },
  { label: 'aws $30', charge: charge('aws', 30), expect: 'auto' },
  { label: 'openai $50 (to the threshold)', charge: charge('openai', 50), expect: 'auto' },
  { label: 'aws $120 (over $50: ask a person)', charge: charge('aws', 120), expect: 'step_up' },
  { label: 'aws $250 (over the $200 ceiling)', charge: charge('aws', 250), expect: 'deny' },
  { label: 'sketchy-co $10 (not on the list)', charge: charge('sketchy-co', 10), expect: 'deny' },
  { label: 'openai $10 EUR (wrong currency)', charge: charge('openai', 10, { currency: 'EUR' }), expect: 'deny' },
  { label: 'aws $50', charge: charge('aws', 50), expect: 'auto' },
  { label: 'openai $50 (this uses the last of the $200)', charge: charge('openai', 50), expect: 'auto' },
  { label: 'openai $50 (autonomous $200 is used up)', charge: charge('openai', 50), expect: 'step_up' },
  { label: 'after a person refills the budget: aws $50', charge: charge('aws', 50), expect: 'auto', cosign: true },
];

let ok = true;
for (const s of steps) {
  if (s.cosign) mandate = applyHumanCosign(mandate, now, { full: true }); // the only way the budget goes up
  const d = authorizeCharge(mandate, s.charge, mandate.grant); // decided against the grant, never against the agent's claim
  mandate = settleCharge(mandate, d); // thread the new budget into the next charge
  const good = d.outcome === s.expect;
  if (!good) ok = false;
  console.log(`${good ? 'ok  ' : 'FAIL'} ${s.label.padEnd(46)} -> ${d.outcome.toUpperCase().padEnd(7)} left $${mandate.budget.B}${d.outcome === 'auto' ? '' : `  (${d.reasons[0] ?? ''})`}`);
}
console.log(ok ? '\nAll outcomes as expected.' : '\nAn outcome was not as expected.');
process.exit(ok ? 0 : 1);
