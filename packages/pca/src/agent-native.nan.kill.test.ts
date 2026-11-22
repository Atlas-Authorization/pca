import { describe, expect, it } from 'vitest';
import { envelopePermits, type AuthorityEnvelope } from './agent-native';

// A hand-built, otherwise permissive envelope: no scope restriction, nothing unsatisfiable.
const env = (hints: AuthorityEnvelope['remainingBudgetHints']): AuthorityEnvelope =>
  ({ ok: true, hasEnvelope: true, scopes: null, verbs: null, resources: null, opaqueResourceConstraints: [], tools: null, toolSchemas: [], unsatisfiable: [], caveats: [], remainingBudgetHints: hints }) as AuthorityEnvelope;

describe('a non-finite hint never admits (agent-native envelope)', () => {
  it('the permissive envelope permits a finite clock', () => {
    expect(envelopePermits(env({ expiresAt: 5_000, notBefore: 1_000 }), 'read', '/x', 2_000)).toBe(true);
  });
  // old checks `now >= expiresAt`, `now < notBefore`, `depth < 0` are all false when a side is NaN, so the envelope permitted
  it('a NaN expiresAt or notBefore refuses', () => {
    expect(envelopePermits(env({ expiresAt: Number.NaN }), 'read', '/x', 2_000)).toBe(false);
    expect(envelopePermits(env({ notBefore: Number.NaN }), 'read', '/x', 2_000)).toBe(false);
  });
  it('a NaN remaining delegation depth refuses', () => {
    expect(envelopePermits(env({ delegationDepthRemaining: Number.NaN }), 'read', '/x')).toBe(false);
  });
  it('a non-finite clock refuses', () => {
    for (const now of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) expect(envelopePermits(env({}), 'read', '/x', now)).toBe(false);
  });
});

describe('an infinite hint never admits (agent-native envelope)', () => {
  // old checks admitted -Infinity notBefore (now >= -Inf) and +Infinity expiresAt / remaining depth
  it('an infinite expiresAt or notBefore refuses', () => {
    for (const v of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      expect(envelopePermits(env({ expiresAt: v }), 'read', '/x', 2_000)).toBe(false);
      expect(envelopePermits(env({ notBefore: v }), 'read', '/x', 2_000)).toBe(false);
    }
  });
  it('an infinite remaining delegation depth refuses', () => {
    for (const v of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) expect(envelopePermits(env({ delegationDepthRemaining: v }), 'read', '/x')).toBe(false);
  });
  // old `spend > NaN` was false, so a NaN spend ceiling admitted
  it('a NaN spend ceiling refuses', () => {
    expect(envelopePermits(env({ maxSpendUsd: Number.NaN }), 'read', '/x', undefined, { amount: 1 })).toBe(false);
  });
});
