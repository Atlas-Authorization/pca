/**
 * Server-side risk inputs from the connector action catalog.
 *
 * The verifier prices every risk input the server does not supply at the worst case, so a server that supplies none
 * sends every non-money tool to a co-sign. `catalogRisk` returns the inputs a server can vouch for from its own data:
 * the catalog's reversibility class and blast radius for the verb, and for a money-moving verb the blast radius
 * `amount / kappa` from the operation's (verified) amount and the grant's signed risk policy. It never reads anything
 * the agent claims. Pass it as `requirePCA` / `authorize`'s `risk` option, or merge it into `context().risk`.
 */

import { DEFAULT_CATALOG, type Catalog } from './catalog';
import type { Capability } from './capability';
import { readEnvelope } from './envelope';
import type { RiskInputs } from './risk';

/** Reversibility score per class (1 = fully reversible), the scale the hosted adjudicator uses. */
export const CATALOG_REVERSIBILITY_SCORE: Readonly<Record<string, number>> = Object.freeze({ reversible: 1, rate_limited: 0.4, costly: 0.4, irreversible: 0 });

export interface CatalogRiskOptions {
  /** Catalog to read (default: the built-in catalog). */
  catalog?: Catalog;
  /**
   * Server-observed taint of the operation's inputs in [0, 1] (e.g. from `computeTaint` over its own registry). Absent:
   * taint is not supplied, so the verifier prices it at the worst case (1).
   */
  taint?: number;
}

const unit = (x: number): number => Math.min(1, Math.max(0, x));

/**
 * Risk inputs for `verb` with `params`, from the catalog and the grant. An unknown verb returns `{}` (every input is
 * then priced at the worst case). A money-moving verb whose amount is missing or not a finite number >= 0, or whose
 * grant has no positive `kappa`, gets blast radius 1.
 */
export function catalogRisk(verb: string, params: Record<string, unknown> | undefined, grant: Capability, opts: CatalogRiskOptions = {}): Partial<RiskInputs> {
  const spec = (opts.catalog ?? DEFAULT_CATALOG).get(verb);
  if (!spec) return {};
  const reversibility = Object.prototype.hasOwnProperty.call(CATALOG_REVERSIBILITY_SCORE, spec.reversibility) ? CATALOG_REVERSIBILITY_SCORE[spec.reversibility]! : 0;
  let blastRadius = unit(spec.blastRadius);
  if (spec.amountField !== undefined) {
    const amount = params && Object.prototype.hasOwnProperty.call(params, spec.amountField) ? params[spec.amountField] : undefined;
    const kappa = readEnvelope(grant)?.risk_policy.kappa;
    blastRadius = typeof amount === 'number' && Number.isFinite(amount) && amount >= 0 && typeof kappa === 'number' && kappa > 0 ? unit(amount / kappa) : 1;
  }
  const taint = typeof opts.taint === 'number' && Number.isFinite(opts.taint) ? { taint: unit(opts.taint) } : {};
  return { reversibility, blastRadius, confidence: 1, ...taint };
}
