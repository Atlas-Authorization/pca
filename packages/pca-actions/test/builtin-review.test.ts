// The built-in definitions are confirmed only by the release attestation (scripts/sign-builtins.ts). Without it they are unconfirmed.
import { describe, expect, it } from 'vitest';
import { BUILTIN_DEFS, CORE_REGISTRY, attestationVerifier, builtinReleaseCtx, builtinReviewOpts, effective, releasedBuiltinDefs, signBuiltins, topTraits } from '../src';
import { TEST_PINS, TEST_REVIEWER, TEST_TS } from './reviewed';

describe('built-in release attestation', () => {
  it('a build without the release step has no pinned release key, no attestation, and every built-in is unconfirmed (the top)', () => {
    expect(builtinReleaseCtx()).toBeNull();
    expect(builtinReviewOpts()).toEqual({});
    for (const d of releasedBuiltinDefs()) {
      const e = effective(d, CORE_REGISTRY, builtinReviewOpts());
      expect(e.confirmed, d.verb).toBe(false);
      expect(e.traits, d.verb).toEqual(topTraits(CORE_REGISTRY));
    }
  });
  it('the release step signs every built-in; under the pinned release key each is confirmed with exactly its reviewed traits', () => {
    const signed = signBuiltins({ kid: TEST_REVIEWER.kid, secret: TEST_REVIEWER.secret, ts: TEST_TS });
    expect(signed).toHaveLength(BUILTIN_DEFS.length);
    const ok = attestationVerifier({ pins: TEST_PINS, registry: CORE_REGISTRY });
    for (const d of signed) {
      expect(ok(d), d.verb).toBe(true);
      const e = effective(d, CORE_REGISTRY, { attestationVerified: ok });
      expect(e.confirmed).toBe(true);
      expect(e.traits.length).toBeLessThan(topTraits(CORE_REGISTRY).length);
      // an edit after release invalidates it
      expect(ok({ ...d, title: `${d.title} (edited)` }), d.verb).toBe(false);
    }
    // a key that is not the pinned release key does not confirm them
    expect(attestationVerifier({ pins: { keys: [] }, registry: CORE_REGISTRY })(signed[0]!)).toBe(false);
  });
});
