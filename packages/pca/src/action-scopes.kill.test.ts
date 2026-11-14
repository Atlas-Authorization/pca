import { describe, expect, it } from 'vitest';
import { deriveActionScopes, type ScopeAction } from './action-scopes';

const act = (over: Partial<ScopeAction> = {}): ScopeAction => ({
  verb: 'acme.thing.do', def_digest: 'D'.repeat(43), confirmed: true, upstream: { provider: 'acme', scopes_min: ['b', 'a'] }, ...over,
});
const refuse = (code: string) => ({ ok: false, code });

describe('deriveActionScopes', () => {
  it('refuses a missing or non-object action', () => {
    expect(deriveActionScopes(undefined)).toEqual(refuse('unknown_action'));
    expect(deriveActionScopes(null as unknown as ScopeAction)).toEqual(refuse('unknown_action'));
    expect(deriveActionScopes('x' as unknown as ScopeAction)).toEqual(refuse('unknown_action'));
    expect(deriveActionScopes(7 as unknown as ScopeAction)).toEqual(refuse('unknown_action'));
  });
  it('requires confirmed to be exactly true', () => {
    expect(deriveActionScopes(act({ confirmed: false }))).toEqual(refuse('unconfirmed'));
    expect(deriveActionScopes(act({ confirmed: 'yes' as unknown as boolean }))).toEqual(refuse('unconfirmed'));
    expect(deriveActionScopes(act({ confirmed: undefined as unknown as boolean }))).toEqual(refuse('unconfirmed'));
  });
  it('pins the provider only when one is given', () => {
    expect(deriveActionScopes(act(), { provider: 'other' })).toEqual(refuse('provider_mismatch'));
    expect(deriveActionScopes(act({ upstream: undefined as unknown as ScopeAction['upstream'] }), { provider: 'acme' })).toEqual(refuse('provider_mismatch'));
    expect(deriveActionScopes(act(), { provider: 'acme' })).toEqual({ ok: true, scopes: ['a', 'b'], provider: 'acme', def_digest: 'D'.repeat(43) });
    expect(deriveActionScopes(act({ upstream: { provider: 'zzz', scopes_min: ['a'] } }))).toEqual({ ok: true, scopes: ['a'], provider: 'zzz', def_digest: 'D'.repeat(43) });
    expect(deriveActionScopes(act(), {})).toMatchObject({ ok: true });
  });
  it('refuses an absent, non-array or empty scope list', () => {
    const noUp = act({ upstream: undefined as unknown as ScopeAction['upstream'] });
    expect(deriveActionScopes(noUp)).toEqual(refuse('no_scopes'));
    expect(deriveActionScopes(act({ upstream: { provider: 'acme', scopes_min: [] } }))).toEqual(refuse('no_scopes'));
    expect(deriveActionScopes(act({ upstream: { provider: 'acme', scopes_min: 'a' as unknown as string[] } }))).toEqual(refuse('no_scopes'));
    expect(deriveActionScopes(act({ upstream: { provider: 'acme' } as unknown as ScopeAction['upstream'] }))).toEqual(refuse('no_scopes'));
    expect(deriveActionScopes(act({ upstream: { provider: 'acme', scopes_min: ['a'] } }))).toMatchObject({ ok: true });
  });
  it('refuses any malformed scope, checking every element', () => {
    const bad = (scopes_min: unknown[]) => deriveActionScopes(act({ upstream: { provider: 'acme', scopes_min: scopes_min as string[] } }));
    expect(bad(['ok', 'has space'])).toEqual(refuse('bad_scope'));
    expect(bad(['has space', 'ok'])).toEqual(refuse('bad_scope'));
    expect(bad(['ok', 'q"uote'])).toEqual(refuse('bad_scope'));
    expect(bad(['ok', 'back\\slash'])).toEqual(refuse('bad_scope'));
    expect(bad(['ok', ''])).toEqual(refuse('bad_scope'));
    expect(bad(['ok', 5])).toEqual(refuse('bad_scope'));
    expect(bad(['ok', null])).toEqual(refuse('bad_scope'));
    expect(bad(['x'.repeat(256)])).toMatchObject({ ok: true });
    expect(bad(['ok', 'x'.repeat(257)])).toEqual(refuse('bad_scope'));
    expect(bad(['x'.repeat(255), 'x'.repeat(256)])).toMatchObject({ ok: true });
  });
  it('de-duplicates and sorts the scopes', () => {
    const r = deriveActionScopes(act({ upstream: { provider: 'acme', scopes_min: ['c', 'a', 'b', 'a'] } }));
    expect(r).toEqual({ ok: true, scopes: ['a', 'b', 'c'], provider: 'acme', def_digest: 'D'.repeat(43) });
  });
  it('requires every derived scope inside the grant', () => {
    const a = act({ upstream: { provider: 'acme', scopes_min: ['a', 'b'] } });
    expect(deriveActionScopes(a, { granted: ['a'] })).toEqual(refuse('exceeds_grant'));
    expect(deriveActionScopes(a, { granted: ['b'] })).toEqual(refuse('exceeds_grant'));
    expect(deriveActionScopes(a, { granted: [] })).toEqual(refuse('exceeds_grant'));
    expect(deriveActionScopes(a, { granted: ['a', 'b', 'c'] })).toEqual({ ok: true, scopes: ['a', 'b'], provider: 'acme', def_digest: 'D'.repeat(43) });
    expect(deriveActionScopes(a)).toMatchObject({ ok: true });
  });
});
