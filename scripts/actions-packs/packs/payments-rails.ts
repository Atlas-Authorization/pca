// payments-rails - money movement over the common rails: ACH, SEPA, instant payments, wires, card-network operations and
// PayPal/Adyen-style processors. Hand written from public standards facts (NACHA, EPC, ISO 20022 message families) and
// general processor concepts; every money-moving action is irreversible, idempotency-keyed and priced from its amount.
import { P, def, handPack, type H } from '../lib/hand';

const RAILS: { ns: string; name: string; ccy: string; payee: string; exp?: number }[] = [
  { ns: 'ach', name: 'ACH', ccy: 'USD', payee: 'Receiving account' },
  { ns: 'sepa', name: 'SEPA', ccy: 'EUR', payee: 'Beneficiary IBAN' },
  { ns: 'rtp', name: 'instant payment (RTP/FedNow)', ccy: 'USD', payee: 'Receiving account' },
  { ns: 'wire', name: 'wire', ccy: 'USD', payee: 'Beneficiary account' },
  { ns: 'swift', name: 'SWIFT', ccy: 'USD', payee: 'Beneficiary account' },
  { ns: 'faster_payments', name: 'Faster Payments', ccy: 'GBP', payee: 'Beneficiary account' },
  { ns: 'pix', name: 'Pix', ccy: 'BRL', payee: 'Pix key' },
  { ns: 'upi', name: 'UPI', ccy: 'INR', payee: 'Virtual payment address' },
];

const out: H[] = [];
for (const r of RAILS) {
  const pay = (n: string, title: string, desc: string, extra: H['params'] = {}): H => ({
    verb: `${r.ns}.${n}`, title, description: desc, effects: ['pay'], rev: 'irreversible', idem: 'key',
    res: [`${r.ns}.payment`, 'set'],
    params: { amount: P.money(100_000_000_00, 'currency'), currency: P.ccy(), payee: P.payee(), memo: P.opt(P.str(140)), ...extra },
  });
  out.push(
    pay('send_payment', `Send a ${r.name} payment`, `Sends money to a ${r.payee.toLowerCase()} over ${r.name}; settlement cannot be recalled by the sender.`),
    pay('send_batch', `Send a ${r.name} batch`, `Submits many ${r.name} credits in one file; the amount is the batch total.`, { items: P.arr('string', 10_000) }),
    { verb: `${r.ns}.get_payment`, title: `Read a ${r.name} payment`, description: 'Status and details of one payment.', effects: ['read'], res: [`${r.ns}.payment`, 'one'], params: { payment: P.id(`${r.ns}.payment`) } },
    { verb: `${r.ns}.list_payments`, title: `List ${r.name} payments`, description: 'Payments in a window.', effects: ['read'], traits: ['pca.financial_data_read'], res: [`${r.ns}.payment`, 'set'], params: { since: P.opt(P.dt()), limit: P.limit(1000) } },
    { verb: `${r.ns}.cancel_payment`, title: `Cancel a pending ${r.name} payment`, description: 'Cancels a payment that has not settled; refused once it has.', effects: ['update'], rev: 'irreversible', res: [`${r.ns}.payment`, 'one'], params: { payment: P.id(`${r.ns}.payment`) } },
    { verb: `${r.ns}.add_beneficiary`, title: `Add a ${r.name} beneficiary`, description: 'Registers a new destination that later payments can use.', effects: ['create', 'privilege'], rev: 'rate_limited', res: [`${r.ns}.beneficiary`, 'set'], params: { payee: P.payee(), name: P.str(140, { role: 'person.name', tags: ['pii'] }) } },
    { verb: `${r.ns}.remove_beneficiary`, title: `Remove a ${r.name} beneficiary`, description: 'Removes a saved destination.', effects: ['delete'], rev: 'rate_limited', res: [`${r.ns}.beneficiary`, 'one'], params: { beneficiary: P.id(`${r.ns}.beneficiary`) } },
  );
}
// pull-side and reversals
out.push(
  { verb: 'ach.debit_account', title: 'Pull funds by ACH debit', description: 'Debits another party account under their authorisation.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['ach.payment', 'set'], params: { amount: P.money(), currency: P.ccy(), payer: { ...P.payee(), role: 'party.payer' }, authorisation: P.id('ach.authorization') } },
  { verb: 'ach.return_entry', title: 'Return an ACH entry', description: 'Returns a received entry with a return reason code.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['ach.payment', 'one'], params: { amount: P.money(), currency: P.ccy(), payment: P.id('ach.payment'), reason: P.str(8) } },
  { verb: 'ach.stop_payment', title: 'Place an ACH stop payment', description: 'Stops future debits from an originator.', effects: ['update'], rev: 'rate_limited', res: ['ach.payment', 'set'], params: { originator: P.str(140) } },
  { verb: 'sepa.direct_debit_collect', title: 'Collect a SEPA direct debit', description: 'Debits a payer under a mandate.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['sepa.payment', 'set'], params: { amount: P.money(), currency: P.ccy(), payer: { ...P.payee(), role: 'party.payer' }, mandate: P.id('sepa.mandate') } },
  { verb: 'sepa.refund_collection', title: 'Refund a SEPA direct debit', description: 'Returns money debited under a mandate.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['sepa.payment', 'one'], params: { amount: P.money(), currency: P.ccy(), payment: P.id('sepa.payment'), payee: P.payee() } },
  { verb: 'sepa.create_mandate', title: 'Create a SEPA mandate', description: 'Records authorisation to debit an account.', effects: ['create', 'sign'], rev: 'irreversible', res: ['sepa.mandate', 'set'], params: { debtor: P.payee({ role: 'party.payer' }), creditor_id: P.str(35) } },
  { verb: 'sepa.revoke_mandate', title: 'Revoke a SEPA mandate', description: 'Withdraws a debit authorisation.', effects: ['delete'], rev: 'rate_limited', res: ['sepa.mandate', 'one'], params: { mandate: P.id('sepa.mandate') } },
  { verb: 'wire.recall', title: 'Request a wire recall', description: 'Asks the receiving bank to return a sent wire; not guaranteed.', effects: ['update'], rev: 'irreversible', res: ['wire.payment', 'one'], params: { payment: P.id('wire.payment'), reason: P.str(140) } },
  { verb: 'wire.set_standing_instruction', title: 'Set a standing wire instruction', description: 'Creates a recurring wire.', effects: ['create', 'pay'], rev: 'irreversible', idem: 'key', traits: ['pca.scheduled'], res: ['wire.payment', 'set'], params: { amount: P.money(), currency: P.ccy(), payee: P.payee(), schedule: P.str(128) } },
  // card networks
  { verb: 'cardnet.refund', title: 'Refund a card transaction', description: 'Returns funds to the cardholder.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['cardnet.transaction', 'one'], params: { amount: P.money(), currency: P.ccy(), transaction: P.id('cardnet.transaction') } },
  { verb: 'cardnet.capture', title: 'Capture an authorised card payment', description: 'Settles an authorisation and moves the money.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['cardnet.transaction', 'one'], params: { amount: P.money(), currency: P.ccy(), transaction: P.id('cardnet.transaction') } },
  { verb: 'cardnet.void', title: 'Void a card authorisation', description: 'Releases a hold before capture.', effects: ['update'], rev: 'irreversible', res: ['cardnet.transaction', 'one'], params: { transaction: P.id('cardnet.transaction') } },
  { verb: 'cardnet.authorize', title: 'Authorise a card payment', description: 'Places a hold on a card.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['cardnet.transaction', 'set'], params: { amount: P.money(), currency: P.ccy(), card_token: P.secret({ role: 'credential.token', tags: ['pci', 'secret'] }), payee: P.payee({ required: false }) } },
  { verb: 'cardnet.chargeback_respond', title: 'Respond to a chargeback', description: 'Submits evidence contesting a chargeback.', effects: ['update', 'sign'], rev: 'irreversible', res: ['cardnet.chargeback', 'one'], params: { chargeback: P.id('cardnet.chargeback'), evidence: P.obj() } },
  { verb: 'cardnet.chargeback_accept', title: 'Accept a chargeback', description: 'Concedes a dispute and forfeits the funds.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: ['cardnet.chargeback', 'one'], params: { amount: P.money(), currency: P.ccy(), chargeback: P.id('cardnet.chargeback') } },
  { verb: 'cardnet.tokenize', title: 'Tokenise a card', description: 'Exchanges card details for a reusable token.', effects: ['create'], rev: 'reversible', traits: ['pca.credential_access'], res: ['cardnet.token', 'set'], params: { pan: P.secret({ tags: ['pci', 'secret'], max_len: 19 }), expiry: P.str(7) } },
  { verb: 'cardnet.detokenize', title: 'Reveal a card number', description: 'Returns the primary account number behind a token.', effects: ['read'], traits: ['pca.credential_access', 'pca.regulated_data'], res: ['cardnet.token', 'one'], params: { token: P.id('cardnet.token') } },
  { verb: 'cardnet.list_transactions', title: 'List card transactions', description: 'Transactions in a window.', effects: ['read'], traits: ['pca.financial_data_read'], res: ['cardnet.transaction', 'set'], params: { since: P.opt(P.dt()), limit: P.limit(1000) } },
  // PayPal / Adyen style processors
  ...['paypal', 'adyen'].flatMap((ns): H[] => [
    { verb: `${ns}.create_order`, title: `Create a ${ns} order`, description: 'Creates a payment order for the buyer to approve.', effects: ['create'], rev: 'reversible', res: [`${ns}.order`, 'set'], params: { amount: P.int(1, 100_000_000_00), currency: P.ccy() } },
    { verb: `${ns}.capture_order`, title: `Capture a ${ns} order`, description: 'Collects an approved order.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: [`${ns}.order`, 'one'], params: { amount: P.money(), currency: P.ccy(), order: P.id(`${ns}.order`) } },
    { verb: `${ns}.refund_payment`, title: `Refund a ${ns} payment`, description: 'Returns money to the buyer.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: [`${ns}.payment`, 'one'], params: { amount: P.money(), currency: P.ccy(), payment: P.id(`${ns}.payment`) } },
    { verb: `${ns}.payout`, title: `Send a ${ns} payout`, description: 'Pays a recipient out of the merchant balance.', effects: ['pay'], rev: 'irreversible', idem: 'key', res: [`${ns}.payout`, 'set'], params: { amount: P.money(), currency: P.ccy(), payee: P.payee() } },
    { verb: `${ns}.get_balance`, title: `Read the ${ns} balance`, description: 'Available and pending balance.', effects: ['read'], traits: ['pca.financial_data_read'], res: [`${ns}.account`, 'set'], params: {} },
    { verb: `${ns}.list_payments`, title: `List ${ns} payments`, description: 'Payments in a window.', effects: ['read'], traits: ['pca.financial_data_read'], res: [`${ns}.payment`, 'set'], params: { since: P.opt(P.dt()), limit: P.limit(1000) } },
    { verb: `${ns}.create_subscription`, title: `Start a ${ns} subscription`, description: 'Creates recurring billing.', effects: ['create', 'pay'], rev: 'irreversible', idem: 'key', traits: ['pca.scheduled'], res: [`${ns}.subscription`, 'set'], params: { amount: P.money(), currency: P.ccy(), plan: P.str(128), payer: P.payee({ role: 'party.payer' }) } },
    { verb: `${ns}.cancel_subscription`, title: `Cancel a ${ns} subscription`, description: 'Stops recurring billing.', effects: ['delete'], rev: 'rate_limited', res: [`${ns}.subscription`, 'one'], params: { subscription: P.id(`${ns}.subscription`) } },
    { verb: `${ns}.add_webhook`, title: `Register a ${ns} webhook`, description: 'Sends payment events to a URL.', effects: ['provision'], rev: 'rate_limited', res: [`${ns}.webhook`, 'set'], params: { url: P.url() } },
  ]),
);

export default handPack({
  name: 'payments-rails',
  licence_notes: 'Written in-house from public standards facts (NACHA operating rules overview, EPC SEPA scheme names, ISO 20022 message families, card-network dispute concepts) and general payment-processor concepts; no third-party text or schema is carried.',
  config_file: __filename,
  sourceUri: 'in-repo:scripts/actions-packs/packs/payments-rails.ts',
  defs: out.map(def),
});
