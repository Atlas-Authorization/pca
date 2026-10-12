/**
 * Generate the PCA-bound AP2 purchase that the independent implementations then verify.
 *
 *   ./node_modules/.bin/tsc -p tsconfig.json --noEmit false --outDir dist/xc
 *   AP2_FIXTURES=$PWD/fixtures node crosscheck/generate.cjs
 *
 * Output: fixtures/crosscheck/mine.json (tokens, public keys, expected results). Private keys are
 * generated per run and never written.
 */
const { writeFileSync } = require('node:fs');
const { resolve } = require('node:path');
const kit = require('../dist/xc/testkit.js');
const ap2 = require('../dist/xc/index.js');

const s = kit.makeScenario();
const openHash = ap2.sdHashOf(ap2.parseSdJwtHop(s.openCheckout));

// Probe 1: the agent presents fewer units than the open mandate requires (needs 2, carts 1).
function probeUnderQuantity() {
  const payload = {
    id: 'chk_under', merchant: kit.MERCHANT, status: 'ready_for_complete', currency: 'USD',
    line_items: [{ id: 'li_1', item: { id: 'sku-1', title: 'Widget', price: 2000 }, quantity: 1, totals: [{ type: 'subtotal', amount: 2000 }] }],
    totals: [{ type: 'subtotal', amount: 2000 }, { type: 'total', amount: 2000 }], links: [],
  };
  const jwt = ap2.signJwtEs256({ header: { kid: 'merchant-key-1' }, payload, privateKey: s.merchantKey.privateKey });
  const token = ap2.presentClosedCheckout({ open: s.openCheckout, agentKey: s.agent, checkoutJwt: jwt, aud: s.aud.checkout, nonce: s.nonces.checkout, iat: kit.NOW_S + 5 });
  return { token, checkout_jwt: jwt, description: 'open mandate requires quantity 2 of an acceptable item; the checkout carries 1' };
}

// Probe 2: the agent redacts every acceptable_items disclosure, then checks out an item the user never allowed.
function probeWithheldItems() {
  const hop = ap2.parseSdJwtHop(s.openCheckout);
  const kept = hop.disclosures.filter((d) => {
    const v = JSON.parse(Buffer.from(d, 'base64url').toString());
    return !(v.length === 2 && v[1] && typeof v[1] === 'object' && String(v[1].id).startsWith('sku-'));
  });
  const open = ap2.hopSdJwt({ jwt: hop.jwt, disclosures: kept });
  const payload = {
    id: 'chk_evil', merchant: kit.MERCHANT, status: 'ready_for_complete', currency: 'USD',
    line_items: [{ id: 'li_1', item: { id: 'forbidden-sku', title: 'Not allowed', price: 2000 }, quantity: 2, totals: [{ type: 'subtotal', amount: 4000 }] }],
    totals: [{ type: 'subtotal', amount: 4000 }, { type: 'total', amount: 4000 }], links: [],
  };
  const jwt = ap2.signJwtEs256({ header: { kid: 'merchant-key-1' }, payload, privateKey: s.merchantKey.privateKey });
  const token = ap2.presentClosedCheckout({ open, agentKey: s.agent, checkoutJwt: jwt, aud: s.aud.checkout, nonce: s.nonces.checkout, iat: kit.NOW_S + 5 });
  return { token, checkout_jwt: jwt, description: 'every acceptable_items disclosure withheld before the closed hop signs sd_hash; the cart holds an item that was never allowed' };
}

// Control for probe 2: the same forbidden item over the INTACT open mandate (a correct verifier refuses it).
function probeForbiddenIntact() {
  const payload = {
    id: 'chk_evil', merchant: kit.MERCHANT, status: 'ready_for_complete', currency: 'USD',
    line_items: [{ id: 'li_1', item: { id: 'forbidden-sku', title: 'Not allowed', price: 2000 }, quantity: 2, totals: [{ type: 'subtotal', amount: 4000 }] }],
    totals: [{ type: 'subtotal', amount: 4000 }, { type: 'total', amount: 4000 }], links: [],
  };
  const jwt = ap2.signJwtEs256({ header: { kid: 'merchant-key-1' }, payload, privateKey: s.merchantKey.privateKey });
  const token = ap2.presentClosedCheckout({ open: s.openCheckout, agentKey: s.agent, checkoutJwt: jwt, aud: s.aud.checkout, nonce: s.nonces.checkout, iat: kit.NOW_S + 5 });
  return { token, checkout_jwt: jwt, description: 'control: the same forbidden item over the intact open mandate' };
}

const keys = [s.issuer.publicJwk, s.merchantKey.publicJwk, s.agent.publicJwk, ...Array.from({ length: 5 }, () => ap2.generateAp2KeyPair().publicJwk)];
const out = {
  generator: 'crosscheck/generate.cjs (pca-ap2)',
  ap2_commit: ap2.AP2_COMMIT,
  now: kit.NOW_S + 60,
  keys: { issuer: s.issuer.publicJwk, merchant: s.merchantKey.publicJwk, agent: s.agent.publicJwk },
  checkout: { token: s.checkoutChain, aud: s.aud.checkout, nonce: s.nonces.checkout, checkout_jwt: s.checkoutJwt, open_hash: openHash },
  payment: { token: s.paymentChain, aud: s.aud.payment, nonce: s.nonces.payment, open_token: s.openPayment },
  transaction_id: s.transactionId,
  amount_minor: s.amountMinor,
  pca: { principal_public: Buffer.from(s.principal.publicKey).toString('base64url'), audience: s.pcaAudience },
  probes: { under_quantity: probeUnderQuantity(), withheld_acceptable_items: probeWithheldItems(), forbidden_item_intact: probeForbiddenIntact() },
  thumbprints: keys.map((k) => ({ jwk: { kty: k.kty, crv: k.crv, x: k.x, y: k.y }, jkt: ap2.jwkThumbprint(k) })),
};
const target = resolve(__dirname, '..', 'fixtures', 'crosscheck', 'mine.json');
writeFileSync(target, JSON.stringify(out, null, 1) + '\n');
console.log('wrote', target);
