// reviewed.ts - test support: the core pack signed by a TEST reviewer key, so selector tests run over CONFIRMED defs (an unsigned def
// is unconfirmed, i.e. the top of the registry, and a class allow never covers it). Deterministic; the key exists only here.
import { b64u, publicKeyOf, sha256, utf8 } from '@atlasauth/pca';
import { CORE_PACK_DEFS, CORE_REGISTRY, attestationVerifier, confirmDef, type ActionDef, type ReviewOpts, type ReviewerPins } from '@atlasauth/pca-actions';

const SECRET = sha256(utf8('atlas-pca-tests/goal-test-reviewer-key'));
const KID = 'goal-test-reviewer';
export const TEST_PINS: ReviewerPins = { keys: [{ kid: KID, pk: b64u(publicKeyOf(SECRET)), roles: ['reviewer'] }] };
export const REVIEW: ReviewOpts = { attestationVerified: attestationVerifier({ pins: TEST_PINS, registry: CORE_REGISTRY }) };
const sign = (d: ActionDef): ActionDef => {
  const o = JSON.parse(JSON.stringify(d)) as ActionDef;
  return confirmDef(o, { registry: CORE_REGISTRY, reviewer: { kid: KID, secret: SECRET }, pins: TEST_PINS, finalTraits: [...(o.traits ?? [])], ts: 1_700_000_000 });
};
/** The core pack with every def signed by the test reviewer. */
export const REVIEWED_PACK: readonly ActionDef[] = CORE_PACK_DEFS.map(sign);
export const reviewed = (d: ActionDef): ActionDef => sign(d);
