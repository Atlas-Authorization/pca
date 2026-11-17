/**
 * protect(): the revocation hook it installs consults the caller's isRevoked source; only an explicit `true` revokes.
 */
import { describe, expect, it } from 'vitest';
import type { Capability } from '../capability';
import { protect } from './protect';

const GRANT = { id: 'g1' } as unknown as Capability;
const hookOf = (isRevoked?: (g: Capability) => boolean | Promise<boolean>) => {
  const p = protect({ audience: 'rs', operation: () => ({ verb: 'v', resource: 'r', params: {} }), grants: [GRANT], ...(isRevoked ? { isRevoked } : {}) });
  return { p, hook: p.options.hooks!.revocation as unknown as (c: { grant: Capability }) => Promise<{ enforced: boolean; ok: boolean }> };
};

describe('protect: the revocation hook', () => {
  it('isRevoked true refuses; false or absent allows; revoke() refuses regardless', async () => {
    expect(await hookOf(() => true).hook({ grant: GRANT })).toEqual({ enforced: true, ok: false });
    expect(await hookOf(async () => true).hook({ grant: GRANT })).toEqual({ enforced: true, ok: false });
    expect(await hookOf(() => false).hook({ grant: GRANT })).toEqual({ enforced: true, ok: true });
    expect(await hookOf().hook({ grant: GRANT })).toEqual({ enforced: true, ok: true });
    const h = hookOf(() => false);
    h.p.revoke('g1');
    expect(await h.hook({ grant: GRANT })).toEqual({ enforced: true, ok: false });
  });
});
