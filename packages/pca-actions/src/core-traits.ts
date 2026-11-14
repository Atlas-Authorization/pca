// core-traits.ts - the 22 core traits (spec section 3.2), the effect/role/tag -> trait implication tables, and the
// role sensitivity floors. This table is DATA with its own digest (traitsDigest in ./digest); changing a floor is a
// reviewed registry change (raising = narrow, lowering = widen and blocked in CI).

import type { Effect, TraitId } from './def';
import { buildRegistry, join, profile, type Profile, type Registry, type TraitDef } from './traits';

type Own = Partial<Profile>;

/** Tier numbers: auto 0, confirm 1, cosign 2, stepup 3. */
const CONFIRM = 1;
const COSIGN = 2;
const STEPUP = 3;

// [id, implies, own floor, card phrase]
const TABLE: ReadonlyArray<readonly [string, readonly string[], Own, string]> = [
  ['money_moving', [], { risk: 3, rev: 'rate_limited', blast_ppm: 700_000, esc: COSIGN, caveats: ['amount_cap', 'count_cap', 'window'], context: ['idempotency'], prules: ['money_has_currency', 'money_amount_bounded', 'pay_has_idempotency'] }, 'moves money'],
  ['destructive', [], { risk: 2, rev: 'rate_limited', esc: CONFIRM, caveats: ['resource_scope'], prules: ['id_not_wildcard'] }, 'deletes or destroys data'],
  ['irreversible', [], { risk: 2, rev: 'irreversible', esc: CONFIRM, context: ['fresh_revocation'] }, 'cannot be undone'],
  ['external_communication', [], { risk: 2, rev: 'irreversible', caveats: ['recipient_scope', 'rate_cap'], prules: ['recipient_param_declared'] }, 'sends to people outside your organisation'],
  ['data_export', [], { risk: 2, caveats: ['resource_scope', 'count_cap'], prules: ['export_bounded'] }, 'exports data'],
  ['privilege_change', [], { risk: 3, esc: STEPUP, caveats: ['resource_scope', 'short_expiry'] }, 'changes who can do what'],
  ['code_execution', [], { risk: 3, rev: 'irreversible', esc: COSIGN, caveats: ['resource_scope'], context: ['sandbox_attested'] }, 'runs code or commands'],
  ['credential_access', [], { risk: 3, esc: STEPUP, prules: ['secret_not_logged'] }, 'reads or handles credentials'],
  ['bulk', [], { risk: 2, caveats: ['count_cap'], prules: ['array_bounded'] }, 'acts on many items at once'],
  ['pii_access', [], { risk: 1, caveats: ['resource_scope'] }, 'touches personal data'],
  ['public_exposure', [], { risk: 2, rev: 'irreversible', esc: CONFIRM }, 'makes content public'],
  ['persistence', [], { risk: 2, caveats: ['short_expiry'], context: ['revocable'] }, 'creates standing access or infrastructure'],
  ['infra_mutation', [], { risk: 2, rev: 'rate_limited', caveats: ['resource_scope'] }, 'changes infrastructure'],
  ['cost_incurring', [], { risk: 1, caveats: ['amount_cap'] }, 'incurs cost'],
  ['legal_binding', [], { risk: 3, rev: 'irreversible', esc: STEPUP }, 'legally or cryptographically binds you'],
  ['impersonation', ['external_communication'], { risk: 2, esc: CONFIRM }, 'acts as a person'],
  ['network_egress', [], { risk: 1, caveats: ['recipient_scope'] }, 'reaches out to the network'],
  ['financial_data_read', [], { risk: 1, caveats: ['resource_scope'] }, 'reads financial data'],
  ['regulated_data', [], { risk: 2, esc: CONFIRM }, 'handles regulated data'],
  ['scheduled', [], { risk: 2, caveats: ['short_expiry', 'count_cap'] }, 'runs later or repeatedly'],
  ['unreviewed', [], { risk: 3, rev: 'irreversible', blast_ppm: 1_000_000, esc: COSIGN, caveats: ['approval_ref', 'resource_scope'], context: ['dry_run_first'] }, 'has not been reviewed yet'],
  ['agent_spawning', [], { risk: 2, caveats: ['count_cap'] }, 'starts another agent'],
];

/** `pca.<name>` for every core trait, in table order. */
export const CORE_TRAIT_IDS: readonly TraitId[] = TABLE.map(([n]) => `pca.${n}`);

function buildCoreDefs(): TraitDef[] {
  const floors = new Map<string, Profile>();
  const defs: TraitDef[] = [];
  for (const [name, implies, own, phrase] of TABLE) {
    const id = `pca.${name}`;
    const imp = implies.map((n) => `pca.${n}`);
    // floor = own highlights joined with the implied floors, so T5 (floor >= floors of implies) holds by construction
    const floor = imp.reduce((acc, u) => join(acc, floors.get(u)!), profile(own));
    floors.set(id, floor);
    defs.push({ id, implies: imp, floor, card_phrase: phrase });
  }
  return defs;
}

/** The core trait definitions (frozen data). */
export const CORE_TRAIT_DEFS: readonly TraitDef[] = Object.freeze(buildCoreDefs());

/** The core registry. Cached: it is immutable. */
export const CORE_REGISTRY: Registry = buildRegistry(CORE_TRAIT_DEFS as TraitDef[], { core: true });

// ---- the implication tables (monotone: more effects/roles/tags, more traits) ---------------------------------------------

export const EFFECT_TRAITS: Readonly<Record<Effect, readonly TraitId[]>> = Object.freeze({
  read: [],
  create: [],
  update: [],
  delete: ['pca.destructive'],
  send: ['pca.external_communication'],
  pay: ['pca.money_moving'],
  exec: ['pca.code_execution'],
  privilege: ['pca.privilege_change'],
  export: ['pca.data_export'],
  publish: ['pca.public_exposure'],
  provision: ['pca.persistence', 'pca.scheduled'],
  sign: ['pca.legal_binding'],
});

/** Param tag -> traits. */
export const TAG_TRAITS: Readonly<Record<string, readonly TraitId[]>> = Object.freeze({
  pii: ['pca.pii_access'],
  phi: ['pca.pii_access', 'pca.regulated_data'],
  pci: ['pca.regulated_data'],
  secret: ['pca.credential_access'],
  credential: ['pca.credential_access'],
});

/** Role -> traits (prefix `credential.` and `url.target` handled in effective.ts; this lists the exact roles). */
export const ROLE_TRAITS: Readonly<Record<string, readonly TraitId[]>> = Object.freeze({
  'credential.secret': ['pca.credential_access'],
  'credential.token': ['pca.credential_access'],
  'credential.key': ['pca.credential_access'],
  'url.target': ['pca.network_egress'],
});

/** Sensitivity floor per core role (the old wallet floor is the `material` special case). */
export const ROLE_SENSITIVITY_FLOOR: Readonly<Record<string, 'material' | 'critical'>> = Object.freeze({
  'money.amount': 'critical', 'money.currency': 'material', 'money.fee': 'material',
  'party.payee': 'critical', 'party.payer': 'material',
  'contact.email': 'material', 'contact.phone': 'material', 'contact.address': 'material',
  'person.name': 'material', 'person.dob': 'material', 'person.national_id': 'critical',
  'credential.secret': 'critical', 'credential.token': 'critical', 'credential.key': 'critical',
  'code.command': 'critical', 'query.sql': 'critical',
  'text.message': 'material',
});

/** Param tag -> sensitivity floor. */
export const TAG_SENSITIVITY_FLOOR: Readonly<Record<string, 'material' | 'critical'>> = Object.freeze({
  pii: 'material', phi: 'material', pci: 'material', secret: 'critical', credential: 'critical',
  free_text_outbound: 'material', code: 'material', path: 'material', sql: 'material',
});
