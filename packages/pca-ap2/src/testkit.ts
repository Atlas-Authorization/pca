/** Shared helpers for the test-suite (excluded from the build). */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import type { ValidateFunction } from 'ajv/dist/2020';
import { assembleThreshold, createThresholdVerifier, encodeKey, generateKeyPair, signShare, thresholdMessage, type Signer } from '@atlasauth/pca';
import { buildPaymentMandate, type PaymentMandate as PcaPaymentMandate } from '@atlasauth/pca-payments';
import {
  buildPcaPaymentBinding,
  generateAp2KeyPair,
  openCheckoutMandateFromPca,
  openPaymentMandateFromPca,
  parseSdJwtHop,
  presentClosedCheckout,
  presentClosedPayment,
  sdHashOf,
  signJwtEs256,
  type Ap2KeyPair,
  type JsonObject,
  type Merchant,
} from './index';

export const FIX = process.env.AP2_FIXTURES ?? join(__dirname, '..', 'fixtures');
export const readText = (rel: string): string => readFileSync(join(FIX, rel), 'utf8');
export const readJson = <T>(rel: string): T => JSON.parse(readText(rel)) as T;

export interface Provenance {
  ap2Commit: string;
  x402Commit: string;
  files: { file: string; sha256: string; kind: string; source: string | string[] }[];
}
export const PROV = readJson<Provenance>('PROVENANCE.json');
export const sha256hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex');

export const SCHEMA_ID = {
  payment: 'https://ap2-protocol.org/schemas/payment_mandate.json',
  openPayment: 'https://ap2-protocol.org/schemas/payment_mandate_open.json',
  checkout: 'https://ap2-protocol.org/schemas/checkout_mandate.json',
  openCheckout: 'https://ap2-protocol.org/schemas/open_checkout_mandate',
} as const;

const ajv = new Ajv2020({ strict: false, allErrors: true });
for (const f of PROV.files.filter((x) => x.file.startsWith('ap2-schemas/'))) ajv.addSchema(readJson<object>(f.file));
export const schema = (id: string): ValidateFunction => {
  const v = ajv.getSchema(id);
  if (!v) throw new Error(`schema ${id} not loaded`);
  return v;
};

/** Deterministic salts so token bytes are reproducible within a run. */
export function counterSalt(): () => string {
  let n = 0;
  return () => Buffer.from(`salt-${String(++n).padStart(12, '0')}`).toString('base64url');
}

export const NOW_S = 1_800_000_000;
export const NOW_MS = NOW_S * 1000;
export const MERCHANT: Merchant = { id: 'merchant_1', name: 'Demo Merchant', website: 'https://demo-merchant.example' };

export interface Scenario {
  principal: ReturnType<typeof generateKeyPair>;
  agentEd: ReturnType<typeof generateKeyPair>;
  pca: PcaPaymentMandate;
  issuer: Ap2KeyPair;
  agent: Ap2KeyPair;
  merchantKey: Ap2KeyPair;
  openCheckout: string;
  openPayment: string;
  checkoutJwt: string;
  checkoutChain: string;
  paymentChain: string;
  transactionId: string;
  amountMinor: number;
  nonces: { checkout: string; payment: string };
  aud: { checkout: string; payment: string };
  pcaAudience: string;
  signerSet: Signer[];
  guardian: ReturnType<typeof generateKeyPair>;
}

export interface ScenarioOptions {
  amountMinor?: number;
  quantity?: number;
  unitPrice?: number;
  cumulativeCap?: number;
  perTransactionCap?: number;
  /** Attach a guardian + principal co-sign (needed for a charge above the auto-approve threshold). */
  cosign?: boolean;
  /** Extra / overriding `buildPaymentMandate` params (an `undefined` value removes the default). */
  mandateOver?: Record<string, unknown>;
  /** Explicit expiry (epoch seconds) of the open mandates. */
  exp?: number;
  /** MCC category of the charge. */
  category?: string;
  /** Further merchant descriptors (for terms naming more than one merchant). */
  extraMerchants?: Merchant[];
}

/** A complete PCA-bound purchase: open checkout+payment mandates, merchant checkout, closed mandates. */
export function makeScenario(o: ScenarioOptions = {}): Scenario {
  const principal = generateKeyPair();
  const agentEd = generateKeyPair();
  const issuer = generateAp2KeyPair('agent-provider-key-1');
  const agent = generateAp2KeyPair();
  const merchantKey = generateAp2KeyPair('merchant-key-1');
  const pub = (k: { publicKey: Uint8Array }): string => encodeKey(k.publicKey);
  const pca = buildPaymentMandate({
    principalSecret: principal.secretKey,
    principalPublic: pub(principal),
    agentPublic: pub(agentEd),
    merchants: [MERCHANT.id],
    currency: 'USD',
    perTransactionCap: o.perTransactionCap ?? 500,
    autoApproveThreshold: 50,
    cumulativeCap: o.cumulativeCap ?? 1000,
    periodMs: 24 * 3_600_000,
    maxTransactionsPerPeriod: 5,
    now: NOW_MS,
    ...(o.mandateOver as object),
  });
  const salt = counterSalt();
  const quantity = o.quantity ?? 2;
  const unitPrice = o.unitPrice ?? 2000;
  const total = o.amountMinor ?? quantity * unitPrice;
  const nonces = { checkout: 'nonce-checkout-0001', payment: 'nonce-payment-0001' };
  const aud = { checkout: 'merchant', payment: 'credential-provider' };

  const openCheckout = openCheckoutMandateFromPca(pca, {
    issuer: { privateKey: issuer.privateKey, kid: 'agent-provider-key-1' },
    agentJwk: agent.publicJwk,
    merchants: [MERCHANT, ...(o.extraMerchants ?? [])],
    iat: NOW_S,
    ...(o.exp !== undefined ? { exp: o.exp } : {}),
    salt,
    lineItems: [{ id: 'line_1', acceptable_items: [{ id: 'sku-1', title: 'Widget' }, { id: 'sku-2', title: 'Widget Pro' }], quantity }],
  });
  const checkoutPayload: JsonObject = {
    id: 'chk_0001',
    merchant: MERCHANT as unknown as JsonObject,
    status: 'ready_for_complete',
    currency: 'USD',
    line_items: [{ id: 'li_1', item: { id: 'sku-1', title: 'Widget', price: unitPrice }, quantity, totals: [{ type: 'subtotal', amount: quantity * unitPrice }] }],
    totals: [{ type: 'subtotal', amount: quantity * unitPrice }, { type: 'total', amount: total }],
    links: [{ type: 'terms', url: 'https://demo-merchant.example/terms' }],
  };
  const checkoutJwt = signJwtEs256({ header: { kid: 'merchant-key-1' }, payload: checkoutPayload, privateKey: merchantKey.privateKey });
  const checkoutChain = presentClosedCheckout({ open: openCheckout, agentKey: agent, checkoutJwt, aud: aud.checkout, nonce: nonces.checkout, iat: NOW_S + 5, salt });
  const closedCheckoutHash = checkoutChainHash(checkoutChain);
  const openPayment = openPaymentMandateFromPca(pca, {
    issuer: { privateKey: issuer.privateKey, kid: 'agent-provider-key-1' },
    agentJwk: agent.publicJwk,
    merchants: [MERCHANT, ...(o.extraMerchants ?? [])],
    iat: NOW_S,
    ...(o.exp !== undefined ? { exp: o.exp } : {}),
    salt,
    checkoutReference: sdHashOf(parseSdJwtHop(openCheckout)),
  });
  const pcaAudience = 'https://pca.example/instance/1';
  const guardian = generateKeyPair();
  const signerSet: Signer[] = [
    { role: 'agent', publicKey: pub(agentEd) },
    { role: 'guardian', publicKey: pub(guardian) },
    { role: 'principal', publicKey: pub(principal) },
  ];
  const instrument = { id: 'card_4242', type: 'card', description: 'Card 4242' };
  const paymentChain = presentClosedPayment({
    open: openPayment,
    agentKey: agent,
    aud: aud.payment,
    nonce: nonces.payment,
    iat: NOW_S + 10,
    transactionId: closedCheckoutHash,
    payee: MERCHANT,
    paymentAmount: { amount: total, currency: 'USD' },
    paymentInstrument: instrument,
    salt,
    pca: buildPcaPaymentBinding({
      mandate: pca,
      open: openPayment,
      agentJwk: agent.publicJwk,
      agentSecret: agentEd.secretKey,
      audience: pcaAudience,
      counter: 1,
      transactionId: closedCheckoutHash,
      payee: MERCHANT,
      amount: { amount: total, currency: 'USD' },
      instrumentId: instrument.id,
      ...(o.category !== undefined ? { category: o.category } : {}),
      now: NOW_MS + 10_000,
      ...(o.cosign
        ? {
            cosign: (pcactn) => {
              const bind = { signerSet, t: 3 };
              const msg = thresholdMessage(pcactn);
              return assembleThreshold([signShare('guardian', guardian.secretKey, msg, bind), signShare('principal', principal.secretKey, msg, bind)]);
            },
          }
        : {}),
    }),
  });
  return { principal, agentEd, pca, issuer, agent, merchantKey, openCheckout, openPayment, checkoutJwt, checkoutChain, paymentChain, transactionId: closedCheckoutHash, amountMinor: total, nonces, aud, pcaAudience, signerSet, guardian };
}

/** The `checkout_hash` disclosed in a closed checkout chain's last hop. */
function checkoutChainHash(chain: string): string {
  const last = chain.split('~~').pop() as string;
  const hop = parseSdJwtHop(last);
  for (const d of hop.disclosures) {
    const arr = JSON.parse(Buffer.from(d, 'base64url').toString('utf8')) as unknown[];
    const v = arr[1];
    if (arr.length === 2 && typeof v === 'object' && v !== null && 'checkout_hash' in v) return String((v as { checkout_hash: string }).checkout_hash);
  }
  throw new Error('no checkout_hash');
}

import {
  verifyPurchase,
  type P256Jwk,
  type VerifyPurchaseOptions,
} from './index';

/** Verification options matching a scenario (the verifier knows the issuer + merchant keys, its audiences and nonces). */
export function purchaseOptions(s: Scenario, over: Partial<VerifyPurchaseOptions> = {}): VerifyPurchaseOptions {
  const issuerKey: P256Jwk = s.issuer.publicJwk;
  const merchantKey: P256Jwk = s.merchantKey.publicJwk;
  return {
    resolveIssuerKey: (h) => (h.kid === 'agent-provider-key-1' ? issuerKey : undefined),
    resolveMerchantKey: (h) => (h.kid === 'merchant-key-1' ? merchantKey : undefined),
    checkout: { expectedAudience: s.aud.checkout, expectedNonce: s.nonces.checkout },
    payment: { expectedAudience: s.aud.payment, expectedNonce: s.nonces.payment },
    now: NOW_S + 60,
    context: { totalAmount: 0, totalUses: 0 },
    ...over,
  };
}

export const verifyScenario = (s: Scenario, over: Partial<VerifyPurchaseOptions> = {}, tokens?: { checkout?: string; payment?: string }) =>
  verifyPurchase(tokens?.checkout ?? s.checkoutChain, tokens?.payment ?? s.paymentChain, purchaseOptions(s, over));

export { createThresholdVerifier };
