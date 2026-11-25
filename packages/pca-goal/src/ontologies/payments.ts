import { domainVerbs } from '@atlasauth/pca-actions';
import type { IntentOntology } from '../ontology';
import { and, ban, both, cmp, countCap, exact, grant, related, sumCap, UNITS_MONEY } from './dsl';

const VERBS = domainVerbs('payments');
export const payments: IntentOntology = {
  id: 'atlas.payments', version: 1, domain: 'payments',
  types: [{ id: 'customer', id_prefix: 'cus_' }, { id: 'charge', id_prefix: 'ch_' }, { id: 'payout', id_prefix: 'po_' }, { id: 'subscription', id_prefix: 'sub_' }, { id: 'account', id_prefix: 'acct_' }],
  units: { ...UNITS_MONEY, count: { kind: 'count' } },
  relations: [{ id: 'charges_of', from: 'customer', to: 'charge' }, { id: 'subscriptions_of', from: 'customer', to: 'subscription' }],
  // derived from the action definitions (@atlasauth/pca-actions): the effect class, parameter kinds and aliases are not written here
  verbs: VERBS.verbs,
  aliases: VERBS.aliases,
  templates: [
    {
      id: 'refund_duplicate', title: 'Refund one duplicate charge', phrases: ['duplicate charge', 'refund the duplicate', 'refund this charge', 'refund charge'],
      slots: [
        { name: 'customer', kind: 'id', of: 'customer', mandatory: true },
        { name: 'charge', kind: 'id', of: 'charge', mandatory: true },
        { name: 'max_amount', kind: 'money', ccy: 'USD', mandatory: true, max: 5_000_000 },
      ],
      grants: [grant('refund-one', 'refund', both(exact('charge'), related('charges_of', 'customer')), cmp('lte', 'amount', 'max_amount'))],
      prohibits: ban('transfer', 'payout', 'charge_customer'), bounds: [countCap('one-refund', 'all', 1)],
      example: { customer: 'cus_1', charge: 'ch_1', max_amount: { ccy: 'USD', minor: 4000 } },
    },
    {
      id: 'refund_customer_charges', title: 'Refund charges of one customer within limits', phrases: ['refund charges of', 'refund any charge', 'refunds for customer', 'refund customer'],
      slots: [
        { name: 'customer', kind: 'id', of: 'customer', mandatory: true },
        { name: 'max_per', kind: 'money', ccy: 'USD', mandatory: true, cue: ['each', 'per', 'single'], max: 5_000_000 },
        { name: 'max_total', kind: 'money', ccy: 'USD', mandatory: true, cue: ['total', 'overall', 'combined', 'in all'], max: 20_000_000 },
        { name: 'max_count', kind: 'count', mandatory: false, default: { n: 5 }, cue: ['up to', 'at most', 'no more than', 'max'], max: 100 },
      ],
      grants: [grant('refund-any', 'refund', related('charges_of', 'customer'), cmp('lte', 'amount', 'max_per'))],
      prohibits: ban('transfer', 'payout', 'charge_customer'),
      bounds: [sumCap('total', 'all', 'amount', 'USD', 'max_total'), countCap('count', 'all', 0, 'max_count')],
      example: { customer: 'cus_1', max_per: { ccy: 'USD', minor: 2000 }, max_total: { ccy: 'USD', minor: 10000 }, max_count: { n: 5 } },
    },
    {
      id: 'read_customer_charges', title: 'Read the charges of one customer', phrases: ['read the charges', 'look at the charges', 'view the charges', 'review charges'],
      slots: [{ name: 'customer', kind: 'id', of: 'customer', mandatory: true }],
      grants: [grant('read', 'read_charge', related('charges_of', 'customer'))],
      prohibits: ban('refund', 'charge_customer', 'transfer', 'payout', 'cancel_subscription'), bounds: [],
      example: { customer: 'cus_1' },
    },
    {
      id: 'cancel_one_subscription', title: 'Cancel one subscription', phrases: ['cancel subscription', 'cancel the subscription', 'cancel plan'],
      slots: [{ name: 'subscription', kind: 'id', of: 'subscription', mandatory: true }],
      grants: [grant('cancel', 'cancel_subscription', exact('subscription'))],
      prohibits: ban('refund', 'transfer', 'payout', 'charge_customer'), bounds: [countCap('once', 'all', 1)],
      example: { subscription: 'sub_1' },
    },
  ],
};
void and;
