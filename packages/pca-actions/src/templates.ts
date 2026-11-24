// templates.ts - starter packs a platform can begin from ("start from a template" in the dashboard, `pca actions init --template`):
// typical actions of five business types in the authoring YAML form, with custom traits and business rules (and their examples).
// Every action is an AUTHORED draft (review state `authored`): a template never confirms anything, so until a reviewer of the
// platform signs each action it is treated as the most dangerous case. The namespace is the platform's choice: verbs, resource
// types and custom trait ids are all derived from it.

import { ActionKitError, type TraitId } from './def';
import { CORE_REGISTRY } from './core-traits';
import { extendRegistry, floorOf, join, profile, type Profile, type TraitDef } from './traits';

export type StarterTemplateId = 'ecommerce' | 'fintech' | 'healthcare' | 'saas_admin' | 'devtools';

export interface StarterTemplate {
  id: StarterTemplateId;
  /** Short name for a template picker. */
  title: string;
  /** One or two plain sentences: what the pack covers and which safeguards it starts with. */
  description: string;
  /** The default namespace (the first segment of every verb). */
  ns: string;
  /** The pack's custom traits under namespace `ns` (ids `<ns>.<name>`). */
  traits(ns: string): TraitDef[];
  /** The authoring YAML (`loadActionsText`) under namespace `ns`, with `rules:` blocks and their examples. */
  yaml(ns: string): string;
}

const NS_RE = /^[a-z][a-z0-9_]{0,31}$/;

/** The namespace is interpolated into YAML and trait ids: only a plain lowercase identifier, never the reserved `pca`. */
function checkNs(ns: string): string {
  if (typeof ns !== 'string' || !NS_RE.test(ns)) throw new ActionKitError('bad_ns', 'ns must be a lowercase identifier (a-z, 0-9, _; up to 32 characters)');
  if (ns === 'pca') throw new ActionKitError('bad_ns', "the namespace 'pca' is reserved for core traits");
  return ns;
}

/** Escalation tiers (traits.ts ESC_TIERS): confirm 1, cosign 2. */
const CONFIRM = 1;
const COSIGN = 2;

/** A custom trait whose floor is its own highlights joined with the floors of what it implies, so it can only extend them. */
function trait(id: TraitId, implies: TraitId[], own: Partial<Profile>, card_phrase: string, implied: readonly TraitDef[] = []): TraitDef {
  const reg = implied.length > 0 ? extendRegistry(CORE_REGISTRY, implied) : CORE_REGISTRY;
  return { id, implies, floor: join(floorOf(reg, implies), profile(own)), card_phrase };
}

// ---- e-commerce ------------------------------------------------------------------------------------------------------------------

const ecommerceTraits = (ns: string): TraitDef[] => [
  trait(`${checkNs(ns)}.refund`, ['pca.money_moving'], { caveats: ['resource_scope'], context: ['fresh_revocation'] }, 'gives money back to a customer'),
];

const ecommerceYaml = (n: string): string => {
  const ns = checkNs(n);
  return `# Starter pack: online store. Drafts only: every action needs a reviewer's confirmation before it counts.
ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.order.get
    title: Look up an order
    description: Reads one order with its items, totals and delivery status.
    effects: [read]
    resource: ${ns}.order:ord_*
    params:
      order: id:${ns}.order

  - verb: ${ns}.order.refund
    title: Refund an order
    description: Returns money to the customer for all or part of an order. Refunds above a small amount need a support lead's approval.
    effects: [pay]
    traits: [${ns}.refund]
    resource: ${ns}.order:ord_*
    params:
      order: id:${ns}.order
      amount: money(@currency, max=10000000)
      currency: ccy
      reason: text(500)?
    examples:
      - params: {order: ord_A1B2C3D4, amount: 2500, currency: USD, reason: Damaged in transit, idempotency_key: k_12345678}
        expect: escalate
      - params: {order: ord_A1B2C3D4, amount: 20000000, currency: USD, idempotency_key: k_12345678}
        expect: deny
    rules:
      amount: {max: {USD: "500.00", EUR: "450.00", GBP: "400.00"}}
      approval: {above: {USD: "100.00", EUR: "90.00", GBP: "80.00"}, approvers: 1, group: support_leads}
      rate:
        - {max: 20, per: hour, by: principal}
        - {max: 200, per: day, by: org}
      required: [reason]
      examples:
        - {params: {order: ord_A1B2C3D4, amount: 2500, currency: USD, reason: Damaged in transit}, expect: allow}
        - {params: {order: ord_A1B2C3D4, amount: 9500, currency: EUR, reason: Damaged in transit}, expect: escalate}
        - {params: {order: ord_A1B2C3D4, amount: 25000, currency: USD, reason: Damaged in transit}, expect: escalate}
        - {params: {order: ord_A1B2C3D4, amount: 60000, currency: USD, reason: Damaged in transit}, expect: deny}
        - {params: {order: ord_A1B2C3D4, amount: 2500, currency: JPY, reason: Damaged in transit}, expect: deny}
        - {params: {order: ord_A1B2C3D4, amount: 2500, currency: USD}, expect: deny}
        - {params: {order: ord_A1B2C3D4, amount: 2500, currency: USD, reason: Damaged in transit}, recent: {"0": 20}, expect: deny}

  - verb: ${ns}.order.cancel
    title: Cancel an order
    description: Cancels an order that has not shipped yet. A shopper's assistant may only cancel that shopper's own orders.
    effects: [update]
    resource: ${ns}.order:ord_*
    params:
      order: id:${ns}.order
      customer: id:${ns}.customer
    rules:
      scope:
        - {param: customer, caller: customer_id}
      rate:
        - {max: 5, per: day, by: principal}
      examples:
        - {params: {order: ord_A1B2C3D4, customer: cus_A1B2C3D4}, caller: {customer_id: cus_A1B2C3D4}, expect: allow}
        - {params: {order: ord_A1B2C3D4, customer: cus_A1B2C3D4}, caller: {customer_id: cus_Z9Y8X7W6}, expect: deny}
        - {params: {order: ord_A1B2C3D4, customer: cus_A1B2C3D4}, expect: deny}
        - {params: {order: ord_A1B2C3D4, customer: cus_A1B2C3D4}, caller: {customer_id: cus_A1B2C3D4}, recent: {"0": 5}, expect: deny}

  - verb: ${ns}.customer.notify
    title: Email a customer
    description: Sends a service email (an order update or a delivery notice) to a customer.
    effects: [send]
    resource: ${ns}.customer:cus_*
    params:
      customer: id:${ns}.customer
      to: email
      subject: message(150)
      body: message(2000)
    rules:
      rate:
        - {max: 100, per: hour, by: principal}
        - {max: 1000, per: day, by: org}
      examples:
        - {params: {customer: cus_A1B2C3D4, to: jo@example.com, subject: Your order shipped, body: It arrives on Friday}, expect: allow}
        - {params: {customer: cus_A1B2C3D4, to: jo@example.com, subject: Your order shipped, body: It arrives on Friday}, recent: {"1": 1000}, expect: deny}

  - verb: ${ns}.discount_code.create
    title: Create a discount code
    description: Creates a percentage discount code for checkout. Undo by deleting the code.
    effects: [create]
    resource: ${ns}.discount_code
    params:
      code: text(32)
      percent_off: int(1..90)
      expires_at: datetime
    reversibility: reversible
    compensates: ${ns}.discount_code.delete
    rules:
      rate:
        - {max: 10, per: day, by: org}
      examples:
        - {params: {code: SPRING10, percent_off: 10, expires_at: "2026-04-01T00:00:00Z"}, expect: allow}
        - {params: {code: SPRING10, percent_off: 10, expires_at: "2026-04-01T00:00:00Z"}, recent: {"0": 10}, expect: deny}

  - verb: ${ns}.discount_code.delete
    title: Delete a discount code
    description: Deletes a discount code so it can no longer be used at checkout.
    effects: [delete]
    resource: ${ns}.discount_code:dc_*
    params:
      discount_code: id:${ns}.discount_code
    examples:
      - params: {discount_code: dc_A1B2C3D4}
        expect: escalate

  - verb: ${ns}.product.update_price
    title: Change a product price
    description: Sets the list price of one product in one currency. Outside store office hours the change needs approval.
    effects: [update]
    resource: ${ns}.product:prd_*
    params:
      product: id:${ns}.product
      price: money(@currency, max=100000000)
      currency: ccy
    rules:
      amount: {max: {USD: "10000.00", EUR: "9000.00"}}
      hours: {days: [mon, tue, wed, thu, fri], from: "08:00", to: "20:00", tz: Europe/London}
      examples:
        - {params: {product: prd_A1B2C3D4, price: 1999, currency: USD}, expect: allow}
        - {params: {product: prd_A1B2C3D4, price: 1999, currency: USD}, at: "2026-01-10T12:00:00Z", expect: escalate}
        - {params: {product: prd_A1B2C3D4, price: 2000000, currency: USD}, expect: deny}

  - verb: ${ns}.customer.export
    title: Export the customer list
    description: Exports up to 10000 customer records as a file. Always needs approval from the data protection group.
    effects: [export]
    traits: [pca.pii_access]
    resource: ${ns}.customer
    params:
      limit: count(10000)
      file_format: enum(csv|json)
    rules:
      approval: {always: true, approvers: 1, group: data_protection}
      rate:
        - {max: 2, per: day, by: org}
      examples:
        - {params: {limit: 100, file_format: csv}, expect: escalate}
        - {params: {limit: 100, file_format: csv}, recent: {"0": 2}, expect: deny}
`;
};

// ---- fintech / payments ----------------------------------------------------------------------------------------------------------

const fintechTraits = (ns: string): TraitDef[] => [
  trait(`${checkNs(ns)}.funds_movement`, ['pca.money_moving'], { rev: 'irreversible', esc: COSIGN, caveats: ['approval_ref', 'recipient_scope'], context: ['fresh_revocation'] }, 'moves customer funds out of an account'),
];

const fintechYaml = (n: string): string => {
  const ns = checkNs(n);
  return `# Starter pack: payments and accounts. Drafts only: every action needs a reviewer's confirmation before it counts.
ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.account.get_balance
    title: Read an account balance
    description: Reads the available and pending balance of one account. Only the account holder's own account.
    effects: [read]
    resource: ${ns}.account:acct_*
    params:
      account: id:${ns}.account
    rules:
      scope:
        - {param: account, caller: account_id}
      examples:
        - {params: {account: acct_A1B2C3D4}, caller: {account_id: acct_A1B2C3D4}, expect: allow}
        - {params: {account: acct_A1B2C3D4}, caller: {account_id: acct_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.transaction.list
    title: List account transactions
    description: Lists recent transactions of one account, newest first. Only the account holder's own account.
    effects: [read]
    resource: ${ns}.account:acct_*
    params:
      account: id:${ns}.account
      limit: count(500)
      from_date: date?
    rules:
      scope:
        - {param: account, caller: account_id}
      rate:
        - {max: 120, per: hour, by: principal}
      examples:
        - {params: {account: acct_A1B2C3D4, limit: 50}, caller: {account_id: acct_A1B2C3D4}, expect: allow}
        - {params: {account: acct_A1B2C3D4, limit: 50}, caller: {account_id: acct_A1B2C3D4}, recent: {"0": 120}, expect: deny}

  - verb: ${ns}.payout.create
    title: Send a payout
    description: Pays money out of an account to a saved beneficiary. Payouts run on business days during New York hours, and large ones need two treasury approvers.
    effects: [pay]
    traits: [${ns}.funds_movement]
    resource: ${ns}.account:acct_*
    params:
      account: id:${ns}.account
      beneficiary: {type: string, role: party.payee, max_len: 64, provenance_min: first_party}
      amount: money(@currency, max=100000000)
      currency: ccy
      memo: text(140)?
    examples:
      - params: {account: acct_A1B2C3D4, beneficiary: ben_A1B2C3D4, amount: 120000, currency: USD, idempotency_key: k_12345678}
        expect: escalate
      - params: {account: acct_A1B2C3D4, beneficiary: ben_A1B2C3D4, amount: 200000000, currency: USD, idempotency_key: k_12345678}
        expect: deny
    rules:
      amount: {max: {USD: "25000.00", EUR: "20000.00"}}
      approval: {above: {USD: "5000.00", EUR: "4000.00"}, approvers: 2, group: treasury}
      scope:
        - {param: account, caller: account_id}
      rate:
        - {max: 10, per: hour, by: principal}
        - {max: 50, per: day, by: principal}
      hours: {days: [mon, tue, wed, thu, fri], from: "09:00", to: "17:00", tz: America/New_York, outside: deny}
      examples:
        - {params: {account: acct_A1B2C3D4, amount: 120000, currency: USD}, caller: {account_id: acct_A1B2C3D4}, expect: allow}
        - {params: {account: acct_A1B2C3D4, amount: 50000, currency: EUR}, caller: {account_id: acct_A1B2C3D4}, expect: allow}
        - {params: {account: acct_A1B2C3D4, amount: 750000, currency: USD}, caller: {account_id: acct_A1B2C3D4}, expect: escalate}
        - {params: {account: acct_A1B2C3D4, amount: 3000000, currency: USD}, caller: {account_id: acct_A1B2C3D4}, expect: deny}
        - {params: {account: acct_A1B2C3D4, amount: 120000, currency: GBP}, caller: {account_id: acct_A1B2C3D4}, expect: deny}
        - {params: {account: acct_A1B2C3D4, amount: 120000, currency: USD}, caller: {account_id: acct_Z9Y8X7W6}, expect: deny}
        - {params: {account: acct_A1B2C3D4, amount: 120000, currency: USD}, caller: {account_id: acct_A1B2C3D4}, at: "2026-01-07T23:00:00Z", expect: deny}
        - {params: {account: acct_A1B2C3D4, amount: 120000, currency: USD}, caller: {account_id: acct_A1B2C3D4}, recent: {"0": 10}, expect: deny}

  - verb: ${ns}.card.freeze
    title: Freeze a card
    description: Blocks new payments on a card. Undo by unfreezing it.
    effects: [update]
    resource: ${ns}.card:card_*
    params:
      card: id:${ns}.card
      reason: enum(lost|stolen|suspected_fraud|customer_request)
    reversibility: reversible
    compensates: ${ns}.card.unfreeze

  - verb: ${ns}.card.unfreeze
    title: Unfreeze a card
    description: Allows payments on a frozen card again. Always needs a fraud team approval.
    effects: [update]
    resource: ${ns}.card:card_*
    params:
      card: id:${ns}.card
    rules:
      approval: {always: true, approvers: 1, group: fraud_ops}
      examples:
        - {params: {card: card_A1B2C3D4}, expect: escalate}

  - verb: ${ns}.beneficiary.add
    title: Add a payout beneficiary
    description: Saves a new bank account that payouts can be sent to. Only on the caller's own account, and always with a treasury approval.
    effects: [create]
    resource: ${ns}.account:acct_*
    params:
      account: id:${ns}.account
      name: {type: string, role: person.name, max_len: 140, tags: [pii]}
      iban: {type: string, format: iban, max_len: 34, tags: [pci]}
    rules:
      scope:
        - {param: account, caller: account_id}
      approval: {always: true, approvers: 1, group: treasury}
      examples:
        - {params: {account: acct_A1B2C3D4, name: Jo Smith, iban: GB33BUKB20201555555555}, caller: {account_id: acct_A1B2C3D4}, expect: escalate}
        - {params: {account: acct_A1B2C3D4, name: Jo Smith, iban: GB33BUKB20201555555555}, caller: {account_id: acct_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.statement.send
    title: Email an account statement
    description: Emails the monthly statement of an account to the account holder's own address.
    effects: [send]
    resource: ${ns}.account:acct_*
    params:
      account: id:${ns}.account
      to: email
      month: date
    rules:
      scope:
        - {param: account, caller: account_id}
        - {param: to, caller: email}
      examples:
        - {params: {account: acct_A1B2C3D4, to: jo@example.com, month: "2026-01-01"}, caller: {account_id: acct_A1B2C3D4, email: jo@example.com}, expect: allow}
        - {params: {account: acct_A1B2C3D4, to: someone@example.net, month: "2026-01-01"}, caller: {account_id: acct_A1B2C3D4, email: jo@example.com}, expect: deny}
`;
};

// ---- healthcare ------------------------------------------------------------------------------------------------------------------

const healthcareTraits = (ns: string): TraitDef[] => {
  const access = trait(`${checkNs(ns)}.health_record_access`, ['pca.regulated_data', 'pca.pii_access'], { risk: 2, esc: CONFIRM, caveats: ['resource_scope'], context: ['fresh_revocation'] }, 'reads or sends protected health information');
  const change = trait(`${ns}.health_record_change`, [access.id], { risk: 3, esc: COSIGN, caveats: ['approval_ref'] }, 'changes a patient record', [access]);
  return [access, change];
};

const healthcareYaml = (n: string): string => {
  const ns = checkNs(n);
  return `# Starter pack: clinic and patient records. Drafts only: every action needs a reviewer's confirmation before it counts.
ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.patient.get
    title: Read a patient record
    description: Reads one patient's chart summary. Every read states its purpose (treatment, payment or operations) for the access log.
    effects: [read]
    traits: [${ns}.health_record_access]
    resource: ${ns}.patient:pat_*
    params:
      patient: id:${ns}.patient
      purpose: enum(treatment|payment|operations)?
    rules:
      required: [purpose]
      rate:
        - {max: 50, per: hour, by: principal}
        - {max: 500, per: day, by: org}
      examples:
        - {params: {patient: pat_A1B2C3D4, purpose: treatment}, expect: allow}
        - {params: {patient: pat_A1B2C3D4}, expect: deny}
        - {params: {patient: pat_A1B2C3D4, purpose: treatment}, recent: {"0": 50}, expect: deny}

  - verb: ${ns}.patient.export_records
    title: Export a patient's records
    description: Exports the full record of one patient, for a transfer of care or the patient's own access request. Always needs the privacy office's approval.
    effects: [export]
    traits: [${ns}.health_record_access]
    resource: ${ns}.patient:pat_*
    params:
      patient: id:${ns}.patient
      file_format: enum(pdf|fhir_json)
    rules:
      approval: {always: true, approvers: 1, group: privacy_office}
      examples:
        - {params: {patient: pat_A1B2C3D4, file_format: pdf}, expect: escalate}

  - verb: ${ns}.note.add
    title: Add a clinical note
    description: Adds a note to a patient's chart in the name of the clinician who wrote it.
    effects: [create]
    traits: [${ns}.health_record_change]
    resource: ${ns}.patient:pat_*
    params:
      patient: id:${ns}.patient
      author: id:${ns}.clinician
      text: {type: string, max_len: 4000, tags: [phi]}
    rules:
      scope:
        - {param: author, caller: clinician_id}
      rate:
        - {max: 60, per: hour, by: principal}
      examples:
        - {params: {patient: pat_A1B2C3D4, author: cln_A1B2C3D4, text: Follow up in two weeks}, caller: {clinician_id: cln_A1B2C3D4}, expect: allow}
        - {params: {patient: pat_A1B2C3D4, author: cln_A1B2C3D4, text: Follow up in two weeks}, caller: {clinician_id: cln_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.prescription.create
    title: Write a prescription
    description: Creates a prescription for a patient in the name of the prescribing clinician. Outside clinic hours it needs approval.
    effects: [create]
    traits: [${ns}.health_record_change]
    resource: ${ns}.patient:pat_*
    params:
      patient: id:${ns}.patient
      prescriber: id:${ns}.clinician
      medication: {type: string, max_len: 200, tags: [phi]}
      quantity: int(1..365)
    rules:
      scope:
        - {param: prescriber, caller: clinician_id}
      hours: {days: [mon, tue, wed, thu, fri, sat], from: "07:00", to: "19:00", tz: America/Chicago}
      examples:
        - {params: {patient: pat_A1B2C3D4, prescriber: cln_A1B2C3D4, medication: Amoxicillin 500 mg, quantity: 21}, caller: {clinician_id: cln_A1B2C3D4}, expect: allow}
        - {params: {patient: pat_A1B2C3D4, prescriber: cln_A1B2C3D4, medication: Amoxicillin 500 mg, quantity: 21}, caller: {clinician_id: cln_Z9Y8X7W6}, expect: deny}
        - {params: {patient: pat_A1B2C3D4, prescriber: cln_A1B2C3D4, medication: Amoxicillin 500 mg, quantity: 21}, caller: {clinician_id: cln_A1B2C3D4}, at: "2026-01-11T15:00:00Z", expect: escalate}
        - {params: {patient: pat_A1B2C3D4, prescriber: cln_A1B2C3D4, medication: Amoxicillin 500 mg, quantity: 21}, caller: {clinician_id: cln_A1B2C3D4}, at: "2026-01-08T02:00:00Z", expect: escalate}

  - verb: ${ns}.appointment.book
    title: Book an appointment
    description: Books an appointment for a patient with a clinician. A patient's assistant may only book for that patient. Undo by cancelling it.
    effects: [create]
    resource: ${ns}.appointment
    params:
      patient: id:${ns}.patient
      clinician: id:${ns}.clinician
      starts_at: datetime
    reversibility: reversible
    compensates: ${ns}.appointment.cancel
    rules:
      scope:
        - {param: patient, caller: patient_id}
      rate:
        - {max: 5, per: day, by: principal}
      examples:
        - {params: {patient: pat_A1B2C3D4, clinician: cln_A1B2C3D4, starts_at: "2026-02-03T09:30:00Z"}, caller: {patient_id: pat_A1B2C3D4}, expect: allow}
        - {params: {patient: pat_A1B2C3D4, clinician: cln_A1B2C3D4, starts_at: "2026-02-03T09:30:00Z"}, caller: {patient_id: pat_Z9Y8X7W6}, expect: deny}
        - {params: {patient: pat_A1B2C3D4, clinician: cln_A1B2C3D4, starts_at: "2026-02-03T09:30:00Z"}, caller: {patient_id: pat_A1B2C3D4}, recent: {"0": 5}, expect: deny}

  - verb: ${ns}.appointment.cancel
    title: Cancel an appointment
    description: Cancels a booked appointment and frees the slot.
    effects: [update]
    resource: ${ns}.appointment:apt_*
    params:
      appointment: id:${ns}.appointment
      reason: enum(patient_request|clinician_unavailable|rescheduled)?

  - verb: ${ns}.patient.message
    title: Message a patient
    description: Sends a secure message to a patient at an address of the clinic's patient portal domain.
    effects: [send]
    traits: [${ns}.health_record_access]
    resource: ${ns}.patient:pat_*
    params:
      patient: id:${ns}.patient
      to: email
      subject: message(150)
      body: {type: string, role: text.message, max_len: 4000, tags: [free_text_outbound, phi]}
    rules:
      recipients: {param: to, domains: [example.org]}   # replace with your patient portal domain
      rate:
        - {max: 30, per: hour, by: principal}
      examples:
        - {params: {patient: pat_A1B2C3D4, to: jo@example.org, subject: Your results, body: Your results are ready in the portal}, expect: allow}
        - {params: {patient: pat_A1B2C3D4, to: jo@example.net, subject: Your results, body: Your results are ready in the portal}, expect: deny}
        - {params: {patient: pat_A1B2C3D4, subject: Your results, body: Your results are ready in the portal}, expect: deny}
`;
};

// ---- SaaS administration ---------------------------------------------------------------------------------------------------------

const saasAdminTraits = (ns: string): TraitDef[] => [
  trait(`${checkNs(ns)}.tenant_admin`, ['pca.privilege_change'], { context: ['fresh_revocation'] }, 'administers who can use a customer tenant'),
];

const saasAdminYaml = (n: string): string => {
  const ns = checkNs(n);
  return `# Starter pack: SaaS tenant administration. Drafts only: every action needs a reviewer's confirmation before it counts.
ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.user.list
    title: List a tenant's users
    description: Lists the users of one tenant with their roles. Only the caller's own tenant.
    effects: [read]
    resource: ${ns}.tenant:ten_*
    params:
      tenant: id:${ns}.tenant
      limit: count(500)
    rules:
      scope:
        - {param: tenant, caller: tenant_id}
      examples:
        - {params: {tenant: ten_A1B2C3D4, limit: 50}, caller: {tenant_id: ten_A1B2C3D4}, expect: allow}
        - {params: {tenant: ten_A1B2C3D4, limit: 50}, caller: {tenant_id: ten_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.user.invite
    title: Invite a user
    description: Emails an invitation to join a tenant with the given role. Invitations may only go to approved company domains and addresses.
    effects: [create, send]
    resource: ${ns}.tenant:ten_*
    params:
      tenant: id:${ns}.tenant
      email: email
      role: enum(member|billing|admin)
    rules:
      scope:
        - {param: tenant, caller: tenant_id}
      recipients: {param: email, domains: [example.com], addresses: [contractor@example.net]}   # replace with your own
      rate:
        - {max: 20, per: hour, by: principal}
        - {max: 200, per: day, by: org}
      examples:
        - {params: {tenant: ten_A1B2C3D4, email: jo@example.com, role: member}, caller: {tenant_id: ten_A1B2C3D4}, expect: allow}
        - {params: {tenant: ten_A1B2C3D4, email: contractor@example.net, role: member}, caller: {tenant_id: ten_A1B2C3D4}, expect: allow}
        - {params: {tenant: ten_A1B2C3D4, email: someone@example.net, role: member}, caller: {tenant_id: ten_A1B2C3D4}, expect: deny}
        - {params: {tenant: ten_A1B2C3D4, email: jo@example.com, role: member}, caller: {tenant_id: ten_A1B2C3D4}, recent: {"1": 200}, expect: deny}

  - verb: ${ns}.user.change_role
    title: Change a user's role
    description: Changes the role of a user in a tenant. Always needs two tenant owners to approve.
    effects: [privilege]
    traits: [${ns}.tenant_admin]
    resource: ${ns}.user:usr_*
    params:
      user: id:${ns}.user
      tenant: id:${ns}.tenant
      role: enum(member|billing|admin|owner)
    examples:
      - params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4, role: admin}
        expect: escalate
    rules:
      scope:
        - {param: tenant, caller: tenant_id}
      approval: {always: true, approvers: 2, group: tenant_owners}
      examples:
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4, role: admin}, caller: {tenant_id: ten_A1B2C3D4}, expect: escalate}
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4, role: admin}, caller: {tenant_id: ten_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.user.suspend
    title: Suspend a user
    description: Signs a user out and blocks sign-in until reinstated. Undo by reinstating the user. A reason is required.
    effects: [privilege]
    traits: [${ns}.tenant_admin]
    resource: ${ns}.user:usr_*
    params:
      user: id:${ns}.user
      tenant: id:${ns}.tenant
      reason: text(500)?
    reversibility: reversible
    compensates: ${ns}.user.reinstate
    examples:
      - params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4, reason: Left the company}
        expect: escalate
    rules:
      scope:
        - {param: tenant, caller: tenant_id}
      required: [reason]
      examples:
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4, reason: Left the company}, caller: {tenant_id: ten_A1B2C3D4}, expect: allow}
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4}, caller: {tenant_id: ten_A1B2C3D4}, expect: deny}
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4, reason: Left the company}, caller: {tenant_id: ten_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.user.reinstate
    title: Reinstate a user
    description: Lets a suspended user sign in again. Always needs a tenant owner's approval.
    effects: [privilege]
    traits: [${ns}.tenant_admin]
    resource: ${ns}.user:usr_*
    params:
      user: id:${ns}.user
      tenant: id:${ns}.tenant
    examples:
      - params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4}
        expect: escalate
    rules:
      scope:
        - {param: tenant, caller: tenant_id}
      approval: {always: true, approvers: 1, group: tenant_owners}
      examples:
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4}, caller: {tenant_id: ten_A1B2C3D4}, expect: escalate}
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4}, caller: {tenant_id: ten_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.user.delete
    title: Delete a user
    description: Permanently deletes a user and their data from a tenant. Always needs two tenant owners to approve.
    effects: [delete]
    resource: ${ns}.user:usr_*
    params:
      user: id:${ns}.user
      tenant: id:${ns}.tenant
    examples:
      - params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4}
        expect: escalate
    rules:
      scope:
        - {param: tenant, caller: tenant_id}
      approval: {always: true, approvers: 2, group: tenant_owners}
      examples:
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4}, caller: {tenant_id: ten_A1B2C3D4}, expect: escalate}
        - {params: {user: usr_A1B2C3D4, tenant: ten_A1B2C3D4}, caller: {tenant_id: ten_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.api_key.revoke
    title: Revoke an API key
    description: Revokes one API key of a tenant so it stops working at once.
    effects: [delete]
    resource: ${ns}.api_key:key_*
    params:
      api_key: id:${ns}.api_key
      tenant: id:${ns}.tenant
    examples:
      - params: {api_key: key_A1B2C3D4, tenant: ten_A1B2C3D4}
        expect: escalate
    rules:
      scope:
        - {param: tenant, caller: tenant_id}
      examples:
        - {params: {api_key: key_A1B2C3D4, tenant: ten_A1B2C3D4}, caller: {tenant_id: ten_A1B2C3D4}, expect: allow}
        - {params: {api_key: key_A1B2C3D4, tenant: ten_A1B2C3D4}, caller: {tenant_id: ten_Z9Y8X7W6}, expect: deny}

  - verb: ${ns}.audit_log.export
    title: Export the audit log
    description: Exports the audit log of one tenant for a date range.
    effects: [export]
    resource: ${ns}.tenant:ten_*
    params:
      tenant: id:${ns}.tenant
      start_date: date
      end_date: date
    rules:
      scope:
        - {param: tenant, caller: tenant_id}
      rate:
        - {max: 5, per: day, by: org}
      examples:
        - {params: {tenant: ten_A1B2C3D4, start_date: "2026-01-01", end_date: "2026-01-31"}, caller: {tenant_id: ten_A1B2C3D4}, expect: allow}
        - {params: {tenant: ten_A1B2C3D4, start_date: "2026-01-01", end_date: "2026-01-31"}, caller: {tenant_id: ten_A1B2C3D4}, recent: {"0": 5}, expect: deny}
`;
};

// ---- developer tools / infrastructure -----------------------------------------------------------------------------------------

const devtoolsTraits = (ns: string): TraitDef[] => [
  trait(`${checkNs(ns)}.production_change`, ['pca.infra_mutation'], { risk: 3, esc: COSIGN, caveats: ['approval_ref'], context: ['fresh_revocation'] }, 'changes a production system'),
];

const devtoolsYaml = (n: string): string => {
  const ns = checkNs(n);
  return `# Starter pack: deployments and infrastructure. Drafts only: every action needs a reviewer's confirmation before it counts.
ns: ${ns}
since: 0.1.0
actions:
  - verb: ${ns}.deployment.list
    title: List recent deployments
    description: Lists the recent deployments of one service with their versions and status.
    effects: [read]
    resource: ${ns}.service:svc_*
    params:
      service: id:${ns}.service
      limit: count(100)

  - verb: ${ns}.service.deploy
    title: Deploy a service version
    description: Deploys a released version of a service. Deploys run Monday to Thursday in Berlin office hours; at other times they need approval.
    effects: [exec]
    traits: [${ns}.production_change]
    resource: ${ns}.service:svc_*
    params:
      service: id:${ns}.service
      version: {type: string, format: semver, max_len: 64}
      environment: enum(staging|production)
    rules:
      hours: {days: [mon, tue, wed, thu], from: "09:00", to: "17:00", tz: Europe/Berlin}
      rate:
        - {max: 3, per: hour, by: principal}
        - {max: 20, per: day, by: org}
      examples:
        - {params: {service: svc_A1B2C3D4, version: 1.4.2, environment: production}, expect: allow}
        - {params: {service: svc_A1B2C3D4, version: 1.4.2, environment: production}, at: "2026-01-09T10:00:00Z", expect: escalate}
        - {params: {service: svc_A1B2C3D4, version: 1.4.2, environment: production}, recent: {"0": 3}, expect: deny}

  - verb: ${ns}.service.rollback
    title: Roll back a service
    description: Returns a service to an earlier released version.
    effects: [update]
    traits: [${ns}.production_change]
    resource: ${ns}.service:svc_*
    params:
      service: id:${ns}.service
      version: {type: string, format: semver, max_len: 64}
    rules:
      rate:
        - {max: 5, per: hour, by: principal}
      examples:
        - {params: {service: svc_A1B2C3D4, version: 1.4.1}, expect: allow}
        - {params: {service: svc_A1B2C3D4, version: 1.4.1}, recent: {"0": 5}, expect: deny}

  - verb: ${ns}.service.scale
    title: Scale a service
    description: Sets the number of running replicas of a service (0 to 50).
    effects: [update]
    traits: [${ns}.production_change]
    resource: ${ns}.service:svc_*
    params:
      service: id:${ns}.service
      replicas: int(0..50)

  - verb: ${ns}.secret.rotate
    title: Rotate a secret
    description: Replaces a stored secret with a newly generated value and restarts what uses it. Always needs two on-call approvers.
    effects: [update]
    traits: [${ns}.production_change]
    resource: ${ns}.secret:sec_*
    params:
      secret: id:${ns}.secret
    rules:
      approval: {always: true, approvers: 2, group: platform_oncall}
      examples:
        - {params: {secret: sec_A1B2C3D4}, expect: escalate}

  - verb: ${ns}.environment.create
    title: Create a preview environment
    description: Creates a short-lived preview environment of a service from a branch. Undo by deleting the environment.
    effects: [create]
    resource: ${ns}.environment
    params:
      service: id:${ns}.service
      branch: text(100)
    reversibility: reversible
    compensates: ${ns}.environment.delete
    rules:
      rate:
        - {max: 10, per: day, by: principal}
      examples:
        - {params: {service: svc_A1B2C3D4, branch: feature/new-checkout}, expect: allow}
        - {params: {service: svc_A1B2C3D4, branch: feature/new-checkout}, recent: {"0": 10}, expect: deny}

  - verb: ${ns}.environment.delete
    title: Delete a preview environment
    description: Deletes a preview environment and everything running in it.
    effects: [delete]
    resource: ${ns}.environment:env_*
    params:
      environment: id:${ns}.environment
    examples:
      - params: {environment: env_A1B2C3D4}
        expect: escalate

  - verb: ${ns}.production_access.grant
    title: Grant temporary production access
    description: Gives a person access to a production service for up to 8 hours. Always needs an on-call approval and a reason.
    effects: [privilege]
    resource: ${ns}.service:svc_*
    params:
      service: id:${ns}.service
      user: id:${ns}.user
      duration: duration(28800000)
      reason: text(500)?
    examples:
      - params: {service: svc_A1B2C3D4, user: usr_A1B2C3D4, duration: 3600000, reason: Investigate incident 4521}
        expect: escalate
    rules:
      approval: {always: true, approvers: 1, group: platform_oncall}
      required: [reason]
      examples:
        - {params: {service: svc_A1B2C3D4, user: usr_A1B2C3D4, duration: 3600000, reason: Investigate incident 4521}, expect: escalate}
        - {params: {service: svc_A1B2C3D4, user: usr_A1B2C3D4, duration: 3600000}, expect: deny}
`;
};

// ---- the catalog ------------------------------------------------------------------------------------------------------------------

const TEMPLATES: StarterTemplate[] = [
  {
    id: 'ecommerce',
    title: 'Online store',
    description: 'Orders, refunds, discount codes, prices and customer emails. Refunds have per-currency ceilings and need approval above a small amount; shoppers can only cancel their own orders.',
    ns: 'shop',
    traits: ecommerceTraits,
    yaml: ecommerceYaml,
  },
  {
    id: 'fintech',
    title: 'Payments and accounts',
    description: 'Balances, transactions, payouts, cards, beneficiaries and statements. Payouts are capped per currency, limited to business hours and the account holder\'s own account, and large ones need two approvers.',
    ns: 'pay',
    traits: fintechTraits,
    yaml: fintechYaml,
  },
  {
    id: 'healthcare',
    title: 'Clinic and patient records',
    description: 'Patient records, clinical notes, prescriptions, appointments and patient messages. Record reads state a purpose, prescriptions follow clinic hours, and messages only go to the patient portal.',
    ns: 'clinic',
    traits: healthcareTraits,
    yaml: healthcareYaml,
  },
  {
    id: 'saas_admin',
    title: 'SaaS tenant administration',
    description: 'Users, roles, invitations, API keys and audit logs of a customer tenant. Every action stays inside the caller\'s own tenant; role changes and deletions need tenant owners to approve.',
    ns: 'admin',
    traits: saasAdminTraits,
    yaml: saasAdminYaml,
  },
  {
    id: 'devtools',
    title: 'Deployments and infrastructure',
    description: 'Deploys, rollbacks, scaling, secrets, preview environments and temporary production access. Deploys follow office hours and rate limits; secret rotation and production access need on-call approval.',
    ns: 'infra',
    traits: devtoolsTraits,
    yaml: devtoolsYaml,
  },
];

export const STARTER_TEMPLATES: readonly StarterTemplate[] = Object.freeze(TEMPLATES);

/** The starter template with this id, or undefined. */
export function starterTemplate(id: string): StarterTemplate | undefined {
  return STARTER_TEMPLATES.find((t) => t.id === id);
}
