/**
 * r14 static-mutant kills for intent-revocation.ts (group g2): the namespaced id prefix and the id / scope builders are
 * module-level bindings evaluated at load, so each check re-evaluates the module (vi.resetModules + dynamic import).
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./intent-revocation');
}

describe('intent-revocation ids and scopes (fresh module)', () => {
  it('the prefix and every id / scope builder give the normative strings', async () => {
    const r = await fresh();
    expect({
      prefix: r.INTENT_REVOCATION_PREFIX,
      session: r.sessionRevocationId('S1'),
      map: r.mapRevocationId('M1'),
      delta: r.deltaRevocationId('D1'),
      profile: r.profileRevocationId('travel', 3),
      sessionScope: r.sessionRevocationScope('S1'),
      profileScope: r.profileRevocationScope('travel'),
    }).toEqual({
      prefix: 'pca-intent:',
      session: 'pca-intent:session:S1',
      map: 'pca-intent:map:M1',
      delta: 'pca-intent:delta:D1',
      profile: 'pca-intent:profile:travel@3',
      sessionScope: 'pca-intent-session:S1',
      profileScope: 'pca-intent-profile:travel',
    });
  });
});
