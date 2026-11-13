import { openApiPack } from '../lib/factory';

// Reviewed Stripe rules (the trait review of the money-moving surface). Applied to the derived verb; first match wins.
// pay: money leaves, enters or is committed on the platform or a connected account. All irreversible and idempotency-keyed.
const PAY = /^stripe\.(refunds\.create|charges\.(create|capture)|payouts\.(create|reverse)|transfers\.(create|reversals\.create)|topups\.create|payment_intents\.(create|confirm|capture|increment_authorization|apply_customer_balance)|invoices\.(pay|finalize)|subscriptions\.(create|migrate)|credit_notes\.create|application_fees\.refunds\.create|treasury\.(outbound_payments|outbound_transfers|inbound_transfers|credit_reversals|debit_reversals)\.create|terminal\.readers\.(process_payment_intent|refund_payment)|issuing\.authorizations\.approve|customers\.balance_transactions\.create|billing\.credit_grants\.create|climate\.orders\.create)$/;
// privilege: who may receive funds or act for an account
const PRIV = /^stripe\.(accounts\.(create|update|reject|unreject)|accounts\.(external_accounts|persons)\.(create|update)|accounts\.login_links\.create|account_links\.create|account_sessions\.create)$/;
const PRIV_DELETE = /^stripe\.accounts\.(delete|external_accounts\.delete|persons\.delete)$/;
const PROVISION = /^stripe\.(webhook_endpoints\.create|apple_pay\.domains\.create|terminal\.readers\.create)$/;

export default openApiPack({
  name: 'stripe',
  ns: 'stripe',
  redistribution: 'permitted',
  licence_notes: 'Stripe publishes its OpenAPI description under the MIT licence. Operation names, parameter names/types/bounds and short operation summaries are carried; the trait review is ours.',
  config_file: __filename,
  oa: () => ({ naming: 'path', exclude: /^\/v1\/test_helpers\//, flatten: true }),
  build: () => ({
    ns: 'stripe',
    vendorTitles: true,
    rules: [
      { re: PAY, on: 'verb', patch: { effects: ['pay'], rev: 'irreversible', scope: 'one' } },
      { re: PRIV, on: 'verb', patch: { effects: ['privilege'], rev: 'rate_limited' } },
      { re: PRIV_DELETE, on: 'verb', patch: { effects: ['delete', 'privilege'], rev: 'irreversible' } },
      { re: PROVISION, on: 'verb', patch: { effects: ['provision'], rev: 'rate_limited' } },
      { re: /^stripe\.quotes\.accept$/, on: 'verb', patch: { effects: ['sign'], rev: 'irreversible' } },
      { re: /^stripe\.disputes\.close$/, on: 'verb', patch: { effects: ['update'], rev: 'irreversible' } },
      { re: /^stripe\.invoices\.send$/, on: 'verb', patch: { effects: ['send'], rev: 'irreversible' } },
      { re: /^stripe\.subscription_schedules\.release$/, on: 'verb', patch: { effects: ['update'], rev: 'rate_limited' } },
    ],
  }),
});
