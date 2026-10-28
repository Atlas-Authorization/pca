import { FRICTIONS, type Friction } from '@atlasauth/pca/ext/intent';
import { type Reversibility } from '@atlasauth/pca/ext/research';

const isFriction = (x: unknown): x is Friction => typeof x === 'string' && (FRICTIONS as readonly string[]).includes(x);

/**
 * SITE ACCESS TIERS 0–4 (docs/specs/pca-intent-layer-v2.md §3.15). What a site needs before it lets an AI agent in,
 * instead of blocking it, depends on the action: reading needs an accountable agent, writing needs an intent binding,
 * paying or doing something irreversible needs a bounded residual risk, just-in-time consent and an evidence bundle.
 *
 * The §3.15 table is encoded below as data ({@link TIER_TABLE}), so documentation, presets and the guard read the same
 * source. Tier requirements are NOT a chain in every column: Tier 1 is an HTTP message signature (Web Bot Auth),
 * Tier 2 is a PCActn under a principal-rooted grant (it does not need Tier 1's signature), and Tiers 3 and 4 each extend
 * the tier below them ("Tier 2 + …", "Tier 3 + …").
 */

export type AccessTier = 0 | 1 | 2 | 3 | 4;
export const ACCESS_TIERS: readonly AccessTier[] = [0, 1, 2, 3, 4];

export function isAccessTier(x: unknown): x is AccessTier {
  return typeof x === 'number' && (ACCESS_TIERS as readonly number[]).includes(x);
}

/** The action classes the §3.15 table names in its "allowed actions (default)" column. */
export type ActionClass =
  | 'public_page'
  | 'public_catalog_read'
  | 'own_data_read'
  | 'reversible_write'
  | 'rate_limited_write'
  | 'payment_under_cap'
  | 'irreversible_with_jit'
  | 'high_value'
  | 'refund';

export interface TierSpec {
  tier: AccessTier;
  name: 'anonymous' | 'identified' | 'accountable' | 'intent-bound' | 'dispute-grade';
  /** What the agent proves. */
  agentProves: string;
  /** What the site checks. */
  siteChecks: string;
  /** What the site can relax for an agent at this tier. */
  siteMayRelax: string;
  /** The action classes allowed at this tier by default (cumulative: a tier allows everything below it). */
  allows: readonly ActionClass[];
}

export const TIER_TABLE: readonly TierSpec[] = [
  {
    tier: 0,
    name: 'anonymous',
    agentProves: 'nothing',
    siteChecks: "today's bot defenses",
    siteMayRelax: 'nothing',
    allows: ['public_page'],
  },
  {
    tier: 1,
    name: 'identified',
    agentProves: 'an HTTP message signature from a known agent key (RFC 9421, web-bot-auth profile via pca-webbotauth)',
    siteChecks: 'signature, key directory',
    siteMayRelax: 'CAPTCHAs and fingerprinting for this key; rate limits per key rather than per IP',
    allows: ['public_page', 'public_catalog_read'],
  },
  {
    tier: 2,
    name: 'accountable',
    agentProves: 'a PCActn under a principal-rooted grant, plus revocation',
    siteChecks: 'requirePCA (chain, aud, counter, revocation epoch)',
    siteMayRelax: 'per-principal rate limits; abuse leads to key revocation, not IP bans',
    allows: ['public_page', 'public_catalog_read', 'own_data_read', 'reversible_write'],
  },
  {
    tier: 3,
    name: 'intent-bound',
    agentProves: 'Tier 2 + envelope.intent + intent_session (schema digest, session, accumulators)',
    siteChecks: 'schema conformance, layers, accumulators, residual risk <= the site ceiling, lazy elicitation',
    siteMayRelax: "step-up: the site's own 3-D Secure or OTP challenge can be skipped when the principal answered at device tier",
    allows: ['public_page', 'public_catalog_read', 'own_data_read', 'reversible_write', 'rate_limited_write', 'payment_under_cap', 'irreversible_with_jit'],
  },
  {
    tier: 4,
    name: 'dispute-grade',
    agentProves: 'Tier 3 + evidence bundle anchored + bond for optimistic actions',
    siteChecks: 'bundle verifies; bond posted',
    siteMayRelax: 'instant fulfilment for reversible actions under bond',
    allows: ['public_page', 'public_catalog_read', 'own_data_read', 'reversible_write', 'rate_limited_write', 'payment_under_cap', 'irreversible_with_jit', 'high_value', 'refund'],
  },
];

/** The lowest tier whose default allowance contains an action class. */
export function minimumTierFor(cls: ActionClass): AccessTier {
  for (const t of TIER_TABLE) if (t.allows.includes(cls)) return t.tier;
  return 4;
}

// ---- per-verb rules (the §5 `tiers` member) -------------------------------------------------------------------

export interface RateRule {
  max: number;
  per_secs: number;
  /** Whose rate: the agent key (Tier 1 keyid / leaf holder) or the principal (grant issuer). */
  key: 'agent' | 'principal';
}

export type JitRequirement = Friction | 'none';

export interface TierRule {
  tier: AccessTier;
  rate?: RateRule;
  /** JIT consent tier required per reversibility (Tier 3+). */
  jit?: { irreversible?: JitRequirement; reversible?: JitRequirement };
  /** Cap on the session total for this verb (enforced by the V3 accumulator check, through the intent port). */
  max_total_cents?: number;
  /** Tier 4: the minimum bond that must be posted. */
  bond_min_cents?: number;
}

const RULE_KEYS = ['tier', 'rate', 'jit', 'max_total_cents', 'bond_min_cents'];
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isNat = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;

/** Validate one per-verb rule. Unknown members are a configuration error (§5): throws. */
export function parseTierRule(v: unknown, where = 'tier rule'): TierRule {
  if (!isObj(v)) throw new TypeError(`${where}: must be an object`);
  for (const k of Object.keys(v)) if (!RULE_KEYS.includes(k)) throw new TypeError(`${where}: unknown member "${k}"`);
  if (!isAccessTier(v.tier)) throw new TypeError(`${where}: tier must be 0..4`);
  const out: TierRule = { tier: v.tier };
  if (v.rate !== undefined) {
    const r = v.rate;
    if (!isObj(r)) throw new TypeError(`${where}.rate: must be an object`);
    for (const k of Object.keys(r)) if (!['max', 'per_secs', 'key'].includes(k)) throw new TypeError(`${where}.rate: unknown member "${k}"`);
    if (!isNat(r.max) || r.max < 1) throw new TypeError(`${where}.rate.max must be a positive integer`);
    if (!isNat(r.per_secs) || r.per_secs < 1) throw new TypeError(`${where}.rate.per_secs must be a positive integer`);
    const key = r.key ?? 'agent';
    if (key !== 'agent' && key !== 'principal') throw new TypeError(`${where}.rate.key must be agent or principal`);
    out.rate = { max: r.max, per_secs: r.per_secs, key };
  }
  if (v.jit !== undefined) {
    const j = v.jit;
    if (!isObj(j)) throw new TypeError(`${where}.jit: must be an object`);
    for (const k of Object.keys(j)) if (k !== 'irreversible' && k !== 'reversible') throw new TypeError(`${where}.jit: unknown member "${k}"`);
    const ok = (x: unknown) => x === undefined || x === 'none' || isFriction(x);
    if (!ok(j.irreversible) || !ok(j.reversible)) throw new TypeError(`${where}.jit: each entry must be none, tap, hold, typed or device`);
    if (v.tier < 3 && ((j.irreversible ?? 'none') !== 'none' || (j.reversible ?? 'none') !== 'none')) throw new TypeError(`${where}: JIT consent needs Tier 3 or above`);
    out.jit = {
      ...(j.irreversible !== undefined ? { irreversible: j.irreversible as JitRequirement } : {}),
      ...(j.reversible !== undefined ? { reversible: j.reversible as JitRequirement } : {}),
    };
  }
  if (v.max_total_cents !== undefined) {
    if (!isNat(v.max_total_cents)) throw new TypeError(`${where}.max_total_cents must be a non-negative integer`);
    if (v.tier < 3) throw new TypeError(`${where}: max_total_cents needs Tier 3 or above (it is an accumulator cap)`);
    out.max_total_cents = v.max_total_cents;
  }
  if (v.bond_min_cents !== undefined) {
    if (!isNat(v.bond_min_cents)) throw new TypeError(`${where}.bond_min_cents must be a non-negative integer`);
    if (v.tier !== 4) throw new TypeError(`${where}: bond_min_cents is a Tier 4 member`);
    out.bond_min_cents = v.bond_min_cents;
  }
  return out;
}

/** Presets: drop-in per-verb rules. Tier 3 and 4 default to typed JIT consent for irreversible actions (§5). */
export const tier0: Readonly<TierRule> = Object.freeze({ tier: 0 });
export const tier1: Readonly<TierRule> = Object.freeze({ tier: 1 });
export const tier2: Readonly<TierRule> = Object.freeze({ tier: 2 });
export const tier3: Readonly<TierRule> = Object.freeze({ tier: 3, jit: Object.freeze({ irreversible: 'typed', reversible: 'none' }) as TierRule['jit'] });
export const tier4: Readonly<TierRule> = Object.freeze({ tier: 4, jit: Object.freeze({ irreversible: 'typed', reversible: 'none' }) as TierRule['jit'], bond_min_cents: 0 });
export const TIER_PRESETS: readonly Readonly<TierRule>[] = [tier0, tier1, tier2, tier3, tier4];

/** A preset with overrides, validated. */
export function preset(tier: AccessTier, overrides: Partial<TierRule> = {}): TierRule {
  const base = TIER_PRESETS[tier]!;
  return parseTierRule(JSON.parse(JSON.stringify({ ...base, ...overrides })) as unknown);
}

/** Hints a site gives about a verb when it has no explicit rule (from its action schema). */
export interface ActionHints {
  kind?: 'read' | 'write';
  /** Reads of public catalogue data (no principal data). */
  public?: boolean;
  /** Moves money. */
  payment?: boolean;
  refund?: boolean;
  /** Above the site's high-value threshold. */
  highValue?: boolean;
  /** The site wants instant (optimistic) fulfilment under bond. */
  bond?: boolean;
}

/**
 * The default required tier of a verb (§3.15 "allowed actions" column, read right to left): an explicit per-verb rule
 * wins; otherwise refunds, high-value and bonded actions are Tier 4; payments, rate-limited and irreversible actions
 * Tier 3; public reads Tier 1; own-data reads and reversible writes Tier 2. An action with no reversibility and no
 * hints is treated as irreversible (fail closed: Tier 3).
 */
export function requiredTierFor(verb: string, reversibility: Reversibility | undefined, policy?: { tiers?: Record<string, TierRule> }, hints: ActionHints = {}): AccessTier {
  const explicit = policy?.tiers?.[verb];
  if (explicit) return explicit.tier;
  if (hints.refund || hints.highValue || hints.bond) return 4;
  if (hints.payment || reversibility === 'irreversible' || reversibility === 'rate_limited') return 3;
  if (hints.kind === 'read' && hints.public) return reversibility === undefined || reversibility === 'reversible' ? 1 : 3;
  if (reversibility === undefined && hints.kind === undefined) return 3;
  return 2;
}

// ---- the tier a request proves -----------------------------------------------------------------------------------

/** What a request has PROVEN (each flag is set only by a passed verification step). */
export interface PresentedFacts {
  /** A valid RFC 9421 web-bot-auth signature from a key in the site's directory. */
  webBotAuth: boolean;
  /** A PCActn verified by requirePCA (chain, aud, counter, revocation). */
  pca: boolean;
  /** envelope.intent + intent_session passed the intent checks (V3 port). */
  intent: boolean;
  /** An evidence record was stored for the action. */
  evidence: boolean;
  /** A bond of the required size is posted. */
  bond: boolean;
}

export const NO_FACTS: Readonly<PresentedFacts> = Object.freeze({ webBotAuth: false, pca: false, intent: false, evidence: false, bond: false });

/** Does a request with these facts meet `tier`'s proof requirement (§3.15 "the agent proves" column)? */
export function meetsTier(f: PresentedFacts, tier: AccessTier): boolean {
  switch (tier) {
    case 0: return true;
    case 1: return f.webBotAuth;
    case 2: return f.pca;
    case 3: return f.pca && f.intent;
    case 4: return f.pca && f.intent && f.evidence && f.bond;
  }
}

/**
 * The highest tier a request proves. MONOTONE: proving more never lowers the tier. Tier 2 does not need a Tier 1
 * signature (the PCActn identifies the agent), so a PCActn-only request is Tier 2 while a signature-only one is Tier 1.
 */
export function classifyPresentedTier(f: PresentedFacts): AccessTier {
  let best: AccessTier = 0;
  for (const t of ACCESS_TIERS) if (meetsTier(f, t)) best = t;
  return best;
}
