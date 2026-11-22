import type { CapabilityChain } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import { grantedOAuthScopes, isOAuthScopeCaveat, oauthScopeCaveat } from './authority';

const chainOf = (...caveats: unknown[]): CapabilityChain => [{ caveats }] as unknown as CapabilityChain;

describe('isOAuthScopeCaveat', () => {
  it('accepts only a well-formed oauth_scope caveat', () => {
    expect(isOAuthScopeCaveat({ type: 'oauth_scope', provider: 'g', scopes: ['a'] })).toBe(true);
    expect(isOAuthScopeCaveat({ type: 'oauth_scope', provider: 'g', scopes: [] })).toBe(true);
    expect(isOAuthScopeCaveat(oauthScopeCaveat('g', ['a', 'a', 'b']))).toBe(true);
  });

  it('rejects non-objects without throwing', () => {
    expect(isOAuthScopeCaveat(null)).toBe(false);
    expect(isOAuthScopeCaveat(undefined)).toBe(false);
    expect(isOAuthScopeCaveat('oauth_scope')).toBe(false);
    expect(isOAuthScopeCaveat(7)).toBe(false);
  });

  it('rejects objects missing a field, and each wrongly typed field on its own', () => {
    expect(isOAuthScopeCaveat({})).toBe(false);
    expect(isOAuthScopeCaveat({ type: 'oauth_scope' })).toBe(false);
    expect(isOAuthScopeCaveat({ type: 'oauth_scope', provider: 'g' })).toBe(false);
    expect(isOAuthScopeCaveat({ provider: 'g', scopes: [] })).toBe(false);
    expect(isOAuthScopeCaveat({ type: 'oauth_scope', scopes: [] })).toBe(false);
    expect(isOAuthScopeCaveat({ type: 'other', provider: 'g', scopes: ['a'] })).toBe(false);
    expect(isOAuthScopeCaveat({ type: 'oauth_scope', provider: 5, scopes: ['a'] })).toBe(false);
    expect(isOAuthScopeCaveat({ type: 'oauth_scope', provider: 'g', scopes: 'abc' })).toBe(false);
    expect(isOAuthScopeCaveat({ type: 'oauth_scope', provider: 'g', scopes: [1] })).toBe(false);
    expect(isOAuthScopeCaveat({ type: 'oauth_scope', provider: 'g', scopes: ['a', 1] })).toBe(false);
  });
});

describe('grantedOAuthScopes edge cases', () => {
  const cv = (provider: string, scopes: string[]) => ({ type: 'oauth_scope', provider, scopes });

  it('refuses anything that is not a non-empty array chain', () => {
    const arrayLike = { length: 1, 0: { caveats: [cv('g', ['a'])] } } as unknown as CapabilityChain;
    expect(grantedOAuthScopes(arrayLike, 'g')).toBeNull();
    expect(grantedOAuthScopes([], 'g')).toBeNull();
    expect(grantedOAuthScopes(undefined as unknown as CapabilityChain, 'g')).toBeNull();
  });

  it('refuses a chain whose leaf is missing or has no caveat list', () => {
    expect(grantedOAuthScopes([undefined] as unknown as CapabilityChain, 'g')).toBeNull();
    expect(grantedOAuthScopes([{}] as unknown as CapabilityChain, 'g')).toBeNull();
    expect(grantedOAuthScopes([{ caveats: 'x' }] as unknown as CapabilityChain, 'g')).toBeNull();
  });

  it('reads the leaf, ignores other providers and malformed caveats', () => {
    const chain = [{ caveats: [cv('g', ['root'])] }, { caveats: [cv('s', ['x']), { type: 'oauth_scope', provider: 'g', scopes: [1] }, cv('g', ['a', 'b'])] }] as unknown as CapabilityChain;
    expect([...(grantedOAuthScopes(chain, 'g') ?? [])].sort()).toEqual(['a', 'b']);
  });

  it('intersects every caveat for the provider, whatever the order', () => {
    const wideThenNarrow = grantedOAuthScopes(chainOf(cv('g', ['read', 'write']), cv('g', ['read'])), 'g');
    expect([...(wideThenNarrow ?? [])]).toEqual(['read']);
    const narrowThenWide = grantedOAuthScopes(chainOf(cv('g', ['read']), cv('g', ['read', 'write'])), 'g');
    expect([...(narrowThenWide ?? [])]).toEqual(['read']);
    const disjoint = grantedOAuthScopes(chainOf(cv('g', ['a']), cv('g', ['b'])), 'g');
    expect(disjoint).toEqual(new Set());
  });
});
