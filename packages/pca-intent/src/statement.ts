import { type SignerSuiteOpts } from '@atlasauth/pca';
import {
  type IntentStatement as CoreIntentStatement,
  type IntentVerdict,
  type IntentVerifyOptions,
  type SignedIntentStatement as CoreSignedIntentStatement,
  signIntentStatement,
  verifyIntentStatement,
} from '@atlasauth/pca/ext/intent';
import type { IntentSlots } from './slots';

/**
 * INTENT CAPTURE AND COMMITMENT (spec §4.1).
 *
 * An intent statement is the principal's own words (`text`) plus the structured reading of them (`slots`),
 * with provenance pointers to where they came from (a conversation turn, a ticket), signed by the principal.
 * `intentRef` is its content address. The grant binds to it, so the chain
 *     conversation / ticket  ->  intent statement  ->  grant  ->  PCActn
 * is hash-linked end to end.
 *
 * The artifact, its suite-agile signature (Ed25519, ML-DSA-65, hybrid, ...), `intentRef`, the goal binding
 * (`intentGoal` / `parseIntentGoal`) and the signed `envelope.intent` PCActn slot live in the core
 * (`@atlasauth/pca`, intent.ts + intent-binding.ts) so the server and every verifier share one definition. This
 * module types the slots with the Intent Layer's `IntentSlots` vocabulary.
 */
export {
  INTENT_GOAL_PREFIX,
  INTENT_REF_DOMAIN,
  INTENT_SIG_DOMAIN,
  intentGoal,
  intentRef,
  parseIntentGoal,
  type IntentSource,
} from '@atlasauth/pca/ext/intent';

export type IntentStatement = CoreIntentStatement<IntentSlots>;
export type SignedIntentStatement = CoreSignedIntentStatement<IntentSlots>;

/** Sign a statement as its principal (Ed25519 by default; pass `suite` for ML-DSA-65 / hybrid / ...). */
export function signIntent(s: Omit<IntentStatement, 'principal'> & { principal?: string }, principalSecret: Uint8Array, suite?: SignerSuiteOpts): SignedIntentStatement {
  return signIntentStatement<IntentSlots>(s, principalSecret, suite);
}

/** Verify a signed statement (shape, principal, suite signature; PQ keys must be pinned via `pqPins`). */
export function verifyIntent(s: SignedIntentStatement, opts?: IntentVerifyOptions): IntentVerdict {
  return verifyIntentStatement(s, opts);
}
