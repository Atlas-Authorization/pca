import { describe, expect, it } from 'vitest';
import { InteractionServer } from './interaction';

const mk = (clock: { t: number }, ttlSec?: number) =>
  new InteractionServer({ grantEndpoint: 'https://as.example/gnap', supports: ['redirect'], redirectUri: (id) => `https://as.example/i/${id}`, now: () => clock.t, ...(ttlSec !== undefined ? { ttlSec } : {}) });
const BAD = [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];

describe('an interaction never stays live under a non-finite clock or ttl', () => {
  // pre-fix: `now() > expiresAt` was false for NaN and for -Infinity, so an approval or continuation went through
  it.each(BAD)('approve with a clock of %s', (bad) => {
    const clock = { t: 1000 };
    const s = mk(clock);
    const { interaction } = s.start({ start: ['redirect'] } as never);
    clock.t = bad;
    expect(() => s.approve(interaction.id)).toThrow(/expired/);
  });
  // pre-fix: an infinite ttl made `now() > expiresAt` false forever
  it('an infinite ttl never reads as live', () => {
    const s = mk({ t: 1000 }, Number.POSITIVE_INFINITY);
    const { interaction } = s.start({ start: ['redirect'] } as never);
    expect(() => s.approve(interaction.id)).toThrow(/expired/);
  });
});
