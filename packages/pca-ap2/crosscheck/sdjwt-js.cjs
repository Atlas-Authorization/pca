/**
 * Cross-check pca-ap2 against the independent `@sd-jwt/*` JavaScript libraries.
 *
 * Setup:  npm i --prefix "$SDJWT_LIB" @sd-jwt/core@0.22.0 @sd-jwt/crypto-nodejs@0.19.0
 * Run:    SDJWT_LIB=/path/to/dir node crosscheck/sdjwt-js.cjs        (after crosscheck/generate.cjs)
 * Output: fixtures/crosscheck/sdjwt-js.json
 *
 * Direction 1: every hop of the purchase made by pca-ap2, and of the six official documentation tokens, is decoded
 *              by @sd-jwt/core; hops whose signing key is known are VERIFIED by it (signature + digests).
 * Direction 2: @sd-jwt/core ISSUES an AP2-shaped purchase (open mandates, closed KB-SD-JWT hops); pca-ap2's test-suite
 *              verifies it end to end.
 */
const { createRequire } = require('node:module');
const { readFileSync, writeFileSync } = require('node:fs');
const { createHash, generateKeyPairSync } = require('node:crypto');
const { resolve } = require('node:path');

const lib = process.env.SDJWT_LIB;
if (!lib) throw new Error('set SDJWT_LIB');
const req = createRequire(resolve(lib, 'x.js'));
const { SDJwtInstance } = req('@sd-jwt/core');
const { ES256, digest, generateSalt } = req('@sd-jwt/crypto-nodejs');
const ver = (n) => JSON.parse(readFileSync(resolve(lib, 'node_modules', n, 'package.json'), 'utf8')).version;
const fixtures = resolve(__dirname, '..', 'fixtures');
const mine = JSON.parse(readFileSync(resolve(fixtures, 'crosscheck', 'mine.json'), 'utf8'));
const docTokens = JSON.parse(readFileSync(resolve(fixtures, 'ap2-doc-encoded-tokens.json'), 'utf8'));

const sha256 = (s) => createHash('sha256').update(s, 'ascii').digest('base64url');
const hops = (token) => token.split('~~').map((h, i, a) => (i === a.length - 1 ? h : `${h}~`));
const b64u = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

async function instance(publicJwk) {
  return new SDJwtInstance({
    hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt, signAlg: 'ES256',
    ...(publicJwk ? { verifier: await ES256.getVerifier(publicJwk) } : {}),
  });
}

async function inspect(source, token, keysByIndex, currentDate) {
  const out = [];
  const parts = hops(token);
  for (let i = 0; i < parts.length; i++) {
    const key = keysByIndex[i];
    const inst = await instance(key);
    const claims = await inst.getClaims(parts[i]);
    let verified = null;
    if (key) {
      const r = await inst.verify(parts[i], { currentDate });
      verified = { ok: true, header: r.header };
    }
    out.push({ source, index: i, claims, verified });
  }
  return out;
}

(async () => {
  const result = { generator: `@sd-jwt/core ${ver('@sd-jwt/core')} + @sd-jwt/crypto-nodejs ${ver('@sd-jwt/crypto-nodejs')} (independent implementation)`, mine: [], docs: [] };

  // ---- direction 1: mine
  const k = mine.keys;
  result.mine.push(...(await inspect('checkout', mine.checkout.token, [k.issuer, k.agent], mine.now)));
  result.mine.push(...(await inspect('payment', mine.payment.token, [k.issuer, k.agent], mine.now)));

  // ---- direction 1: the official documentation tokens. The closed hop is verified under the open mandate's own cnf.jwk.
  const docOpen = await (await instance()).getClaims(hops(docTokens[0].token)[0]);
  const docAgent = docOpen.delegate_payload[0].cnf.jwk; // the agent key every documented purchase delegates to
  for (const t of docTokens) {
    const ps = hops(t.token);
    const keys = ps.length === 2 ? [undefined, docAgent] : /^Closed/.test(t.heading) ? [docAgent] : [];
    result.docs.push(...(await inspect(t.heading, t.token, keys, 1777342400)));
  }

  // ---- direction 2: @sd-jwt/core issues an AP2-shaped purchase
  const gen = () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return { pub: publicKey.export({ format: 'jwk' }), priv: privateKey.export({ format: 'jwk' }) };
  };
  const issuerK = gen(), agentK = gen(), merchantK = gen();
  const NOW = mine.now;
  const IAT = NOW - 30, EXP = IAT + 3600;
  const merchant = { id: 'merchant_1', name: 'Demo Merchant', website: 'https://demo-merchant.example' };
  const cnf = { jwk: { crv: 'P-256', kty: 'EC', x: agentK.pub.x, y: agentK.pub.y } };
  const issuer = async (priv, _kid) => new SDJwtInstance({ hasher: digest, hashAlg: 'sha-256', saltGenerator: generateSalt, signAlg: 'ES256', signer: await ES256.getSigner(priv) });
  const rootInst = await issuer(issuerK.priv);
  const agentInst = await issuer(agentK.priv);
  const frameMandate = { delegate_payload: { _sd: [0] } };

  const openCheckoutMandate = {
    vct: 'mandate.checkout.open.1', cnf, iat: IAT, exp: EXP,
    constraints: [
      { type: 'checkout.line_items', items: [{ id: 'line_1', acceptable_items: [{ id: 'sku-1', title: 'Widget' }], quantity: 2 }] },
      { type: 'checkout.allowed_merchants', allowed: [merchant] },
    ],
  };
  const openCheckout = await rootInst.issue({ delegate_payload: [openCheckoutMandate] }, frameMandate, { header: { kid: 'agent-provider-key-1', typ: 'dc+sd-jwt' } });
  const openCheckoutHash = sha256(openCheckout);

  const co = {
    id: 'chk_js_0001', merchant, status: 'ready_for_complete', currency: 'USD',
    line_items: [{ id: 'li_1', item: { id: 'sku-1', title: 'Widget', price: 2000 }, quantity: 2, totals: [{ type: 'subtotal', amount: 4000 }] }],
    totals: [{ type: 'subtotal', amount: 4000 }, { type: 'total', amount: 4000 }], links: [],
  };
  const signingInput = `${b64u({ alg: 'ES256', typ: 'JWT', kid: 'merchant-key-1' })}.${b64u(co)}`;
  const checkoutJwt = `${signingInput}.${await (await ES256.getSigner(merchantK.priv))(signingInput)}`;
  const checkoutHash = sha256(checkoutJwt);

  // closed hops: claims iat/aud/nonce/sd_hash next to delegate_payload; the checkout_jwt property is itself selectively disclosable
  const closedCheckout = await agentInst.issue(
    { delegate_payload: [{ vct: 'mandate.checkout.1', checkout_jwt: checkoutJwt, checkout_hash: checkoutHash }], iat: NOW - 20, aud: 'merchant', nonce: 'js-nonce-checkout', sd_hash: sha256(openCheckout) },
    { delegate_payload: { _sd: [0], 0: { _sd: ['checkout_jwt'] } } },
    { header: { typ: 'kb+sd-jwt' } },
  );

  const openPaymentMandate = {
    vct: 'mandate.payment.open.1', cnf, iat: IAT, exp: EXP,
    constraints: [
      { type: 'payment.amount_range', currency: 'USD', min: 0, max: 50000 },
      { type: 'payment.allowed_payees', allowed: [merchant] },
      { type: 'payment.reference', conditional_transaction_id: openCheckoutHash },
      { type: 'payment.budget', currency: 'USD', max: 1000 },
      { type: 'payment.agent_recurrence', frequency: 'ON_DEMAND', max_occurrences: 5 },
    ],
  };
  const openPayment = await rootInst.issue({ delegate_payload: [openPaymentMandate] }, frameMandate, { header: { kid: 'agent-provider-key-1', typ: 'dc+sd-jwt' } });
  const closedPayment = await agentInst.issue(
    {
      delegate_payload: [{ vct: 'mandate.payment.1', transaction_id: checkoutHash, payee: merchant, payment_amount: { amount: 4000, currency: 'USD' }, payment_instrument: { id: 'card_4242', type: 'card', description: 'Card 4242' } }],
      iat: NOW - 10, aud: 'credential-provider', nonce: 'js-nonce-payment', sd_hash: sha256(openPayment),
    },
    frameMandate,
    { header: { typ: 'kb+sd-jwt' } },
  );
  const join = (open, closed) => `${open.slice(0, -1)}~~${closed}`;
  result.issued_by_sdjwt_js = {
    now: NOW,
    keys: { issuer: { kty: 'EC', crv: 'P-256', x: issuerK.pub.x, y: issuerK.pub.y, kid: 'agent-provider-key-1' }, merchant: { kty: 'EC', crv: 'P-256', x: merchantK.pub.x, y: merchantK.pub.y, kid: 'merchant-key-1' }, agent: cnf.jwk },
    checkout: { token: join(openCheckout, closedCheckout), aud: 'merchant', nonce: 'js-nonce-checkout', checkout_jwt: checkoutJwt, open_hash: openCheckoutHash },
    payment: { token: join(openPayment, closedPayment), aud: 'credential-provider', nonce: 'js-nonce-payment' },
    transaction_id: checkoutHash, amount_minor: 4000,
  };
  writeFileSync(resolve(fixtures, 'crosscheck', 'sdjwt-js.json'), JSON.stringify(result, null, 1) + '\n');
  console.log('wrote fixtures/crosscheck/sdjwt-js.json:', result.mine.length, 'hops of mine,', result.docs.length, 'documentation hops;', result.mine.filter((h) => h.verified).length, 'verified by @sd-jwt/core (mine),', result.docs.filter((h) => h.verified).length, '(docs)');
})().catch((e) => { console.error(e); process.exit(1); });
