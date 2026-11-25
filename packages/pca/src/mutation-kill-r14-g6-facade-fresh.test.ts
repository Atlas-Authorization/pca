/**
 * r14 g6: facade.ts compilePolicy's rate-caveat rule, on a freshly evaluated module: only a COUNT limit with a period becomes
 * the grant-wide rate caveat; a dollar limit with a period contributes only the expiry window.
 */
import { describe, expect, it, vi } from 'vitest';

async function fresh() {
  vi.resetModules();
  return import('./facade');
}
const DAY = 86_400_000;

describe('facade rate caveat (fresh module)', () => {
  it('a $/period limit adds an expiry but no rate caveat; a count/period limit adds both', async () => {
    const f = await fresh();
    expect(f.compilePolicy({ permissions: { stripe: ['refund'] }, limits: { refund: '$5/day' }, now: 0 }).caveats).toEqual([
      { type: 'reversibility_max', class: 'irreversible' },
      { type: 'expires', at: DAY },
    ]);
    expect(f.compilePolicy({ permissions: { gmail: ['send'] }, limits: { send: '5/day' }, now: 0 }).caveats).toEqual([
      { type: 'reversibility_max', class: 'irreversible' },
      { type: 'expires', at: DAY },
      { type: 'rate', max: 5, per_secs: 86_400 },
    ]);
    expect(f.compilePolicy({ permissions: { gmail: ['send'] }, limits: { send: '5' }, now: 0 }).caveats).toEqual([{ type: 'reversibility_max', class: 'irreversible' }]);
  });
});
