/**
 * R4-12 instrumentation: log every (row x, tweak) pair that reaches the OT-extension hash across several independent
 * channels (sessions), several rounds each, and a dealer-free offline run, then look for a repeated (x, tweak) pair
 * (a hash call that would be an exact repeat) and for a repeated x (any tweak).
 */
import { describe, expect, it, vi } from 'vitest';

const log: Array<{ x: string; j: number; role: number; tw: string }> = [];
let callNo = 0;

vi.mock('./otx', async (orig) => {
  const real = await orig<typeof import('./otx')>();
  return {
    ...real,
    tmmoCrh: (rows: Uint32Array, n: number, ...rest: unknown[]) => {
      const t = rest[0] as { offset: number; domain: Uint32Array } | undefined;
      // Order inside one extension round is fixed: sender h0, sender h1, then the receiver's finish (role 0,1,2).
      const role = callNo++ % 3;
      for (let j = 0; j < n; j++) {
        log.push({ role, tw: `${t ? t.offset : 0}+${j}@${t ? Array.from(t.domain).join('.') : '0'}`, x: Array.from(rows.subarray(4 * j, 4 * j + 4), (w) => w.toString(16).padStart(8, '0')).join(''), j });
      }
      return (real.tmmoCrh as (...a: unknown[]) => Uint32Array)(rows, n, ...rest);
    },
  };
});

import { OtChannel } from './ot';
import { makeNoDealerOffline } from './mascot';

describe('R4-12 tweak/input collision scan', () => {
  it('no repeated (x, tweak) pair and no repeated x across sessions, rounds and a dealer-free run', { timeout: 600_000 }, async () => {
    for (let s = 0; s < 4; s++) {
      const ch = new OtChannel();
      for (const m of [1, 7, 64, 200, 64, 5]) {
        const bits = Array.from({ length: m }, (_, i) => (i * 7 + s) & 1);
        const m0 = Array.from({ length: m }, (_, i) => BigInt(i + 1));
        const m1 = Array.from({ length: m }, (_, i) => BigInt(1000 + i));
        ch.extend(bits, m0, m1);
      }
    }
    const off = makeNoDealerOffline(3, 77n);
    off.genAuthTriples(4);
    const seenXT = new Set<string>();
    const seenX = new Map<string, number>();
    let repeatXT = 0;
    // The receiver's t_j equals the sender's q_j (b_j = 0) or q_j ^ s (b_j = 1) BY DESIGN (that is the OT), so the
    // receiver role is compared against the sender role separately; the security-relevant scan is over the sender's
    // hash inputs (roles 0 and 1), where equal inputs would be a real repeat.
    const sender = log.filter((e) => e.role < 2);
    const recvRows = log.filter((e) => e.role === 2);
    const senderSet = new Set(sender.map((e) => `${e.x}|${e.j}`));
    expect(recvRows.every((e) => senderSet.has(`${e.x}|${e.j}`))).toBe(true);
    for (const e of sender) {
      const k = `${e.x}|${e.j}`;
      if (seenXT.has(k)) repeatXT++;
      seenXT.add(k);
      seenX.set(e.x, (seenX.get(e.x) ?? 0) + 1);
    }
    const repeatX = [...seenX.values()].filter((c) => c > 1).length;
    console.log(`R4-12: sender hash inputs=${sender.length} receiver=${recvRows.length} distinct(x,tweak)=${seenXT.size} repeated(x,tweak)=${repeatXT} distinct x=${seenX.size} x with >1 use=${repeatX}`);
    // Tweaks: within one role, no two hash calls of the whole run (all channels, all rounds) may share a (tweak, role)
    // slot: sender h0, sender h1 and the receiver each see every channel-global row index exactly once. Before R4-12
    // the tweak restarted at 0 every round, so this failed.
    for (const role of [0, 1, 2]) {
      const tws = log.filter((e) => e.role === role).map((e) => e.tw);
      expect(new Set(tws).size).toBe(tws.length);
    }
    expect(log.length).toBeGreaterThan(500);
    expect(repeatXT).toBe(0);
    expect(repeatX).toBe(0);
  });
});
