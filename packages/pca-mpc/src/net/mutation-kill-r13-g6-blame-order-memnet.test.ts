/**
 * In-process kill for the blame-round deferral in protocol.ts (mesh.setDeferAborts(true)): three parties and a dealer on
 * the in-memory mesh, party 0 forges its MAC share. The test forces the order that made the real-network test flaky: party
 * 0's abort reaches party 1 BEFORE party 2's blame data (held back, then delivered just before party 2's own abort, as an
 * in-order link would), and party 1 must still name party 0 first-hand.
 */
import { describe, expect, it } from 'vitest';
import type { DecisionVector } from '../party';
import { MemNet } from './memnet';
import { type PartyResult, runDealer, runParty } from './protocol';
import { NetAbort } from './wire';

type Inbox = { inbox: Map<number, { items: Array<{ rd: string; d: unknown; size: number }> }>; wake(): void };
const V: DecisionVector[] = [
  { allow: 1, t: 1, rQuant: 1 },
  { allow: 1, t: 2, rQuant: 0 },
  { allow: 0, t: 1, rQuant: 2 },
];

describe('blame round under a forced message order (in-memory mesh)', () => {
  it("party 1 sees the cheater's abort before party 2's blame data and still names party 0 (mac-check)", async () => {
    let held21: unknown;
    let held12: unknown;
    const net = new MemNet([0, 1, 2, 3], 'sess', 20_000, (from, to, rd, d) => {
      if (rd === 'blame' && from === 2 && to === 1) {
        held21 = d; // party 2 -> party 1 blame data is delayed
        return undefined;
      }
      if (rd === 'blame' && from === 1 && to === 2) {
        held12 = d; // party 2 cannot finish before party 0 has aborted
        return undefined;
      }
      return d;
    });
    const deliver = (to: number, from: number, d: unknown): void => {
      const m = net.mesh(to) as unknown as Inbox;
      m.inbox.get(from)!.items.push({ rd: 'blame', d, size: 1 });
      m.wake();
    };
    // party 0 (the cheater) aborts: only then does party 2 get party 1's blame data
    const m0 = net.mesh(0);
    const fail0 = m0.fail.bind(m0);
    m0.fail = (e, skip) => {
      fail0(e, skip);
      if (held12 !== undefined) deliver(2, 1, held12);
    };
    // party 2 aborts: its delayed blame data reaches party 1 first (in-order link), then its abort
    const m2 = net.mesh(2);
    const fail2 = m2.fail.bind(m2);
    m2.fail = (e, skip) => {
      if (held21 !== undefined) deliver(1, 2, held21);
      fail2(e, skip);
    };
    const run = (i: number) =>
      runParty({ id: i, n: 3, Q: 2, input: V[i]!, mesh: net.mesh(i) as unknown as never, offline: 'trusted-dealer', insecureTrustedDealer: true, sessionId: 'sess', ...(i === 0 ? { behavior: { kind: 'mac-lie', round: 'mul1' }, unsafeTestHooks: true } : {}) }).then(
        (r: PartyResult) => ({ ok: true as const, r }),
        (e: unknown) => ({ ok: false as const, e }),
      );
    const dealer = runDealer({ insecureTrustedDealer: true, n: 3, Q: 2, mesh: net.mesh(3) as unknown as never, seed: 7n }).catch(() => undefined);
    const [, , o1, o2] = await Promise.all([dealer, run(0), run(1), run(2)]);
    expect(held21).toBeDefined();
    expect(held12).toBeDefined();
    const e1 = o1.ok ? null : (o1.e as NetAbort);
    expect([e1 instanceof NetAbort, e1?.kind, e1?.blamed]).toEqual([true, 'mac-check', 0]);
    expect(e1?.message).toContain("party 0's MAC share (key 0) does not match its pairwise tag");
    const e2 = o2.ok ? null : (o2.e as NetAbort);
    expect([e2?.kind, e2?.blamed]).toEqual(['mac-check', 0]);
  }, 60_000);
});
