import { describe, expect, it } from 'vitest';
import { validateManifest } from './index';

const base = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: 'p',
  displayName: 'P',
  authorizeUrl: 'https://a.example/auth',
  tokenUrl: 'https://a.example/token',
  scopesAvailable: ['a', 'b'],
  defaultScopes: ['a'],
  refresh: { mode: 'refresh_token' },
  tokenPlacement: 'bearer',
  ...over,
});
const issues = (over: Record<string, unknown>): string[] => {
  const v = validateManifest(base(over));
  return v.ok ? [] : v.issues;
};

describe('manifest URL and map checks', () => {
  it('a string map with one non-string value is refused', () => {
    expect(issues({ authParams: { a: 'x', b: 5 } })).toEqual(['authParams must be a string→string map']);
    expect(issues({ authParams: { a: 'x', b: 'y' } })).toEqual([]);
  });
  it('the scheme must be spelled https:// exactly', () => {
    for (const u of ['HTTPS://a.example/auth', 'https:a.example/auth']) {
      expect(issues({ authorizeUrl: u }), u).toContain('authorizeUrl must be an https:// URL');
      expect(issues({ tokenUrl: u }), u).toContain('tokenUrl must be an https:// URL');
    }
  });
  it('a placeholder is checked as the label it will become, whatever its length', () => {
    // {ab} becomes a final label "0x", a number-like host that is refused; left unreplaced it would pass
    expect(issues({ authorizeUrl: 'https://a.0{ab}/x' })).toContain('authorizeUrl must be an https:// URL');
    // a placeholder before @ becomes user info, which is refused
    expect(issues({ authorizeUrl: 'https://{u}@a.example/x' })).toContain('authorizeUrl must be an https:// URL');
    expect(issues({ tokenUrl: 'https://{u}@a.example/x' })).toContain('tokenUrl must be an https:// URL');
  });
});
