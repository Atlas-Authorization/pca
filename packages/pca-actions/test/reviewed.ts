// reviewed.ts - test support: the TEST reviewer key (fixed label, deterministic), the pins that name it, and helpers that turn a def
// into a CONFIRMED one by really signing it (so the tests exercise the same attestation path production uses). "Treated as confirmed
// in tests" means exactly this: a signature by the test key, never a bypass flag.
import { b64u, publicKeyOf, sha256, utf8 } from '@atlasauth/pca';
import { CORE_REGISTRY, attestationVerifier, confirmDef, effective, type ActionDef, type Effective, type PinnedKey, type Registry, type ReviewOpts, type ReviewerPins } from '../src';

export const TEST_REVIEWER = { kid: 'test-reviewer', secret: sha256(utf8('atlas-pca-tests/test-reviewer-key')) };
export const TEST_REVIEWER_KEY: PinnedKey = { kid: TEST_REVIEWER.kid, pk: b64u(publicKeyOf(TEST_REVIEWER.secret)), roles: ['reviewer'] };
export const TEST_PINS: ReviewerPins = { keys: [TEST_REVIEWER_KEY] };
export const TEST_TS = 1_700_000_000;

/** The review options under which a def signed by the test reviewer counts as confirmed. */
export const testReview = (reg: Registry = CORE_REGISTRY): ReviewOpts => ({ attestationVerified: attestationVerifier({ pins: TEST_PINS, registry: reg }) });

/** Really sign a def with the test reviewer key (final traits = the def's own declared traits). */
export const confirmed = (d0: ActionDef, reg: Registry = CORE_REGISTRY): ActionDef => {
  const d = JSON.parse(JSON.stringify(d0)) as ActionDef; // drops `undefined` members, which are not JSON
  // 'pca.unreviewed' is the review marker: a def that declares it cannot be signed as it stands
  const finalTraits = (d.traits ?? []).filter((t) => t !== 'pca.unreviewed');
  delete d.traits; // `...d` would otherwise keep 'pca.unreviewed' when nothing else is declared, and the reviewer would be shown it as undismissed
  return confirmDef({ ...d, ...(finalTraits.length > 0 ? { traits: finalTraits } : {}) }, { registry: reg, reviewer: TEST_REVIEWER, pins: TEST_PINS, finalTraits, ts: TEST_TS });
};

/** effective() of the def as signed by the test reviewer. */
export const eff = (d: ActionDef, reg: Registry = CORE_REGISTRY): Effective => effective(confirmed(d, reg), reg, testReview(reg));

/** The reviewed (hint) view in the shape of {@link Effective}: for tests of the algebra itself, not of the confirmation. */
export const hinted = (d: ActionDef, reg: Registry = CORE_REGISTRY): Effective => {
  const e = effective(d, reg);
  return { ...e, ...e.hint, confirmed: true };
};
