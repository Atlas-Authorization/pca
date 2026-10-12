import { describe, expect, it } from 'vitest';
import { MAX_CHAIN_DEPTH } from '../../pca/src/capability';
import { PCACTN_MAX_LIFETIME_MS, PCACTN_MAX_SKEW_MS } from '../../pca/src/pcactn';
import { MAX_CHAIN_DEPTH as VERIFIED_MAX_CHAIN_DEPTH, PCACTN_MAX_LIFETIME_MS_VERIFIED, PCACTN_MAX_SKEW_MS_VERIFIED, validityDecision } from '../src';

/** The Dafny sources hard-code the protocol limits; if the TypeScript constants ever change this fails until the proofs are re-stated. */
describe('protocol constants are identical in the proved core and the TypeScript verifier', () => {
  it('chain depth, lifetime and skew', () => {
    expect(VERIFIED_MAX_CHAIN_DEPTH).toBe(MAX_CHAIN_DEPTH);
    expect(PCACTN_MAX_LIFETIME_MS_VERIFIED).toBe(PCACTN_MAX_LIFETIME_MS);
    expect(PCACTN_MAX_SKEW_MS_VERIFIED).toBe(PCACTN_MAX_SKEW_MS);
  });
  it('the window boundaries sit exactly on those limits', () => {
    const iat = 1_000_000;
    expect(validityDecision(true, iat, iat + PCACTN_MAX_LIFETIME_MS, iat)).toBe('pass');
    expect(validityDecision(true, iat, iat + PCACTN_MAX_LIFETIME_MS + 1, iat)).toBe('too-long');
    expect(validityDecision(true, iat, iat + 10, iat - PCACTN_MAX_SKEW_MS)).toBe('pass');
    expect(validityDecision(true, iat, iat + 10, iat - PCACTN_MAX_SKEW_MS - 1)).toBe('future');
    expect(validityDecision(true, iat, iat + 10, iat + 10)).toBe('pass');
    expect(validityDecision(true, iat, iat + 10, iat + 11)).toBe('expired');
  });
});
