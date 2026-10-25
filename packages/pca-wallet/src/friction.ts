import type { Reversibility } from '@atlasauth/pca';
import { frictionRank, FRICTION_ORDER, maxFriction, type FrictionTier } from './wire';

/**
 * FRICTION SCALED BY HARM (§2.5, §3.4 item 4). The tier of a question is a pure function of the cell's value-dependent
 * reversibility, its expected harm E[h | c], the provenance of its values and the sensitivity of the parameters it
 * widens, raised to the site's minimum for the verb. The default rule is the spec table:
 *
 *   tap     reversible and E[h|c] < h_tap
 *   hold    rate_limited, or E[h|c] ≥ h_tap                       (press and hold, ≥ 2 s dwell)
 *   typed   irreversible, or provenance ∈ {web, agent} on a critical parameter
 *   device  critical and irreversible, or E[h|c] ≥ h_device       (WebAuthn with user verification)
 *
 * "critical" here means the cell widens a critical IDENTITY parameter (a payee, a passenger, a credential: a
 * categorical parameter of a `party.*`, `person.*` or `credential.*` semantic type) beyond the values the principal
 * already confirmed. A critical AMOUNT is covered by E[h|c] and the irreversible rule; that is what makes the §4
 * walkthrough a typed question ("type the total") rather than a security-key ceremony.
 *
 * A dimension filled from a single oracle (`single_source`, §3.6) raises the tier by one step ("doubles the friction
 * tier" in the spec; one step up is this implementation's reading, capped at device).
 */

/** PCA's taint lattice (`taint.ts`), as provenance levels: trusted < first_party < tool < web < agent. */
export type ProvenanceLevel = 'trusted' | 'first_party' | 'tool' | 'web' | 'agent';
export const PROVENANCE_ORDER: readonly ProvenanceLevel[] = ['trusted', 'first_party', 'tool', 'web', 'agent'];

export function isProvenanceLevel(x: unknown): x is ProvenanceLevel {
  return typeof x === 'string' && (PROVENANCE_ORDER as readonly string[]).includes(x);
}

/** The highest (least trusted) level of a set; `agent` for an empty or unknown set (fail closed). */
export function worstProvenance(levels: readonly string[]): ProvenanceLevel {
  let best = -1;
  for (const l of levels) {
    if (!isProvenanceLevel(l)) return 'agent';
    best = Math.max(best, PROVENANCE_ORDER.indexOf(l));
  }
  return best < 0 ? 'agent' : PROVENANCE_ORDER[best]!;
}

export type Sensitivity = 'free' | 'material' | 'critical';

export interface FrictionThresholds {
  /** E[h|c] at and above which a question is at least hold tier. */
  hTap: number;
  /** E[h|c] at and above which a question is device tier. */
  hDevice: number;
}

/** Defaults on the scale of pca-intent's DEFAULT_HARM (irreversible 10, amounts scale as 1 + x/100). */
export const DEFAULT_FRICTION_THRESHOLDS: FrictionThresholds = { hTap: 5, hDevice: 100_000 };

export interface ParamProvenance {
  path: string;
  sensitivity: Sensitivity;
  /** The provenance levels the cell admits for this parameter (its `prov:` coordinate). */
  levels: readonly string[];
}

export interface FrictionInputs {
  reversibility: Reversibility;
  expectedHarm: number;
  provenance?: readonly ParamProvenance[];
  /** The cell widens a critical identity parameter beyond its confirmed values. */
  widensCriticalIdentity?: boolean;
  /** Admission depends on a single-source world dimension (§3.6). */
  singleSource?: boolean;
  /** The site's minimum tier for this verb (§5 `tiers.<verb>.jit`), or the tier the site put in intent_required. */
  siteMin?: FrictionTier;
}

/** Why a tier was chosen: the rule names, for the card and for evidence. */
export interface FrictionDecision {
  tier: FrictionTier;
  rules: string[];
}

const TAINTED: readonly ProvenanceLevel[] = ['web', 'agent'];

export function frictionFor(inp: FrictionInputs, th: FrictionThresholds = DEFAULT_FRICTION_THRESHOLDS): FrictionDecision {
  if (!(Number.isFinite(inp.expectedHarm) && inp.expectedHarm >= 0)) return { tier: 'device', rules: ['harm-unknown'] };
  const rules: string[] = [];
  let tier: FrictionTier = 'tap';
  const raise = (t: FrictionTier, why: string) => {
    if (frictionRank(t) >= frictionRank(tier)) rules.push(why);
    tier = maxFriction(tier, t);
  };
  if (inp.reversibility === 'rate_limited') raise('hold', 'rate-limited');
  if (inp.expectedHarm >= th.hTap) raise('hold', 'harm>=h_tap');
  if (inp.reversibility === 'irreversible') raise('typed', 'irreversible');
  const taintedCritical = (inp.provenance ?? []).some((p) => p.sensitivity === 'critical' && TAINTED.includes(worstProvenance(p.levels)));
  if (taintedCritical) raise('typed', 'tainted-critical');
  if (inp.widensCriticalIdentity && inp.reversibility === 'irreversible') raise('device', 'critical-irreversible');
  if (inp.expectedHarm >= th.hDevice) raise('device', 'harm>=h_device');
  if (inp.singleSource) {
    const up = FRICTION_ORDER[Math.min(FRICTION_ORDER.length - 1, frictionRank(tier) + 1)]!;
    raise(up, 'single-source');
  }
  if (inp.siteMin !== undefined) raise(inp.siteMin, 'site-minimum');
  return { tier, rules };
}

/** Does an answer given at tier `given` satisfy a requirement of tier `required`? */
export function satisfiesTier(given: FrictionTier, required: FrictionTier): boolean {
  return frictionRank(given) >= frictionRank(required);
}
