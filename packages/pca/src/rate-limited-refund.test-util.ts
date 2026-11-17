// Test fixture: a catalog whose `stripe.refund` is the pre-0.5 `rate_limited` money action. The built-in refund is `irreversible`
// now (one definition: a refund is a new payment), so tests that exercise the within-cap auto-approve path of a money limit,
// where nothing granted is irreversible, run against this override.
import { BUILTIN_ACTIONS, buildCatalog, defineAction } from './catalog';

export const RATE_LIMITED_REFUND_CATALOG = buildCatalog([
  ...BUILTIN_ACTIONS,
  defineAction({ connector: 'stripe', action: 'refund', reversibility: 'rate_limited', blastRadius: 0.9, amountField: 'amount', description: 'Refund a charge (hard to undo; rate-limit).' }),
]);
