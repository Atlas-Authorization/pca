// The release attestation plumbing with a release present: pins, attached attestations, verifier and signed traits.
import { afterEach, describe, expect, it } from 'vitest';
import { BUILTIN_DEFS, CORE_REGISTRY, attestationVerifier, builtinReleaseCtx, builtinReviewOpts, effective, releasedBuiltinDefs, signBuiltins } from '../src';
import { BUILTIN_RELEASE } from '../src/builtin-release.generated';
import { TEST_PINS, TEST_REVIEWER, TEST_TS } from './reviewed';

const saved = { pins: BUILTIN_RELEASE.pins, attestations: BUILTIN_RELEASE.attestations };
afterEach(() => { BUILTIN_RELEASE.pins = saved.pins; BUILTIN_RELEASE.attestations = saved.attestations; });

const sign = () => signBuiltins({ kid: TEST_REVIEWER.kid, secret: TEST_REVIEWER.secret, ts: TEST_TS });

describe('built-in release with a pinned key', () => {
  it('builtinReleaseCtx carries the pins and the registry given', () => {
    BUILTIN_RELEASE.pins = TEST_PINS;
    expect(builtinReleaseCtx()).toEqual({ pins: TEST_PINS, registry: CORE_REGISTRY });
    const reg = { ...CORE_REGISTRY };
    expect(builtinReleaseCtx(reg)!.registry).toBe(reg);
    expect(builtinReleaseCtx(reg)!.pins).toBe(TEST_PINS);
  });

  it('releasedBuiltinDefs attaches the attestation of a verb and leaves the others untouched', () => {
    const signed = sign();
    const att = signed[0]!.review.attestation!;
    BUILTIN_RELEASE.attestations = { [BUILTIN_DEFS[0]!.verb]: att };
    const out = releasedBuiltinDefs();
    expect(out).toHaveLength(BUILTIN_DEFS.length);
    expect(out[0]).toEqual({ ...BUILTIN_DEFS[0], review: { ...BUILTIN_DEFS[0]!.review, state: 'confirmed', attestation: att } });
    expect(out[0]!.review.state).toBe('confirmed');
    for (let i = 1; i < out.length; i++) expect(out[i]).toBe(BUILTIN_DEFS[i]);
  });

  it('builtinReviewOpts verifies a def signed by the pinned release key and nothing else', () => {
    BUILTIN_RELEASE.pins = TEST_PINS;
    const opts = builtinReviewOpts();
    expect(Object.keys(opts)).toEqual(['attestationVerified']);
    const signed = sign()[0]!;
    expect(opts.attestationVerified!(signed)).toBe(true);
    expect(opts.attestationVerified!(BUILTIN_DEFS[0]!)).toBe(false);
    expect(effective(signed, CORE_REGISTRY, opts).confirmed).toBe(true);
    expect(attestationVerifier({ pins: TEST_PINS, registry: CORE_REGISTRY })(signed)).toBe(true);
  });

  it('signBuiltins signs a def with the traits it declares', () => {
    const d = { ...BUILTIN_DEFS[0]!, traits: ['pca.data_export', 'pca.pii_access'] };
    const [s] = signBuiltins({ kid: TEST_REVIEWER.kid, secret: TEST_REVIEWER.secret, ts: TEST_TS, defs: [d] });
    expect(s!.traits).toEqual(['pca.data_export', 'pca.pii_access']);
    expect(s!.review.attestation!.final_traits).toEqual(['pca.data_export', 'pca.pii_access']);
  });
});
