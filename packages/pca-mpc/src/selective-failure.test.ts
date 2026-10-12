/* eslint-disable @typescript-eslint/no-explicit-any -- the test patches private members of the offline phase to play the attacker */
/**
 * RT-04 regression: selective failure in the no-dealer (OT) triple generation.
 *
 * The attack (proof-of-concept from the red-team round, not published): party 1 is a corrupt OT SENDER toward the honest
 * party 0 and corrupts chosen message pairs of the first triple product; the run aborts iff the honest receiver's
 * choice bits hit the corrupted pairs. With plain binary choice bits that is "bit k of the honest share a_0", and when the
 * run does not abort the public Beaver opening d = x - a gives the honest input bit. The corrupt party also fixes its own
 * share a_1 = 0, so a = a_0.
 *
 * With the privacy-amplified choice bits (enc.ts, statSec = 64) the abort depends on uniform bits b, not on the share, so
 * the attacker's recovery rate over many runs must be chance. The LEGACY encoding (statSec: 0) is the positive control:
 * the same harness must recover the bit essentially always, which shows the statistic has power.
 */
import { describe, expect, it } from 'vitest';
import { NoDealerOffline, OfflineCheatingAbort } from './mascot';
import { encValue, makeGadget, plainShare } from './enc';
import { MacCheckAbort, SpdzEngine, subAuth } from './spdz';
import { FieldRng, PRIME } from './field';

type Predicate = 'bit' | 'xor';
interface Trial {
  aborted: boolean;
  shareBit: number;
  guess?: number;
  truth: number;
  blamed?: readonly number[];
}

function trial(honestBit: number, seed: bigint, statSec: number, predicate: Predicate): Trial {
  const off: any = new NoDealerOffline(2, seed, { statSec, unsafeStatSec: statSec < 40 });
  let armed = false; // set just before genAuthTriple: the first extension round of the 0 -> 1 link carries the first product
  let tripleOnce = true;
  let shareBit = -1; // ground truth, used only for scoring: bit 0 of the honest share a_0 of the attacked (first) product
  const origChannel = off.channel.bind(off);
  off.channel = (i: number, j: number) => {
    const ch = origChannel(i, j);
    if (!ch.__patched) {
      const ext = ch.extend.bind(ch);
      ch.extend = (choice: number[], m0: bigint[], m1: bigint[]) => {
        if (armed && tripleOnce && i === 0 && j === 1) {
          tripleOnce = false;
          m1 = m1.slice();
          const M = (1n << 64n) - 1n;
          m1[0] = (m1[0]! + 1n) & M; // 'bit': abort iff chosen bit 0 is 1
          if (predicate === 'xor') m1[1] = (m1[1]! - 1n) & M; // 'xor': abort iff b_0 != b_1
        }
        return ext(choice, m0, m1);
      };
      ch.__patched = true;
    }
    return ch;
  };
  // the corrupt party fixes its OWN triple share a_1 = 0 (all-zero choice bits), so a = a_0 exactly
  const origSample = off.sampleShare.bind(off);
  let seen = false;
  off.sampleShare = (party: number) => {
    if (party === 1) return { value: 0n, bits: new Array(off.gadget.length).fill(0) };
    const e = origSample(party);
    if (armed && !seen) {
      seen = true;
      shareBit = Number(e.value & 1n);
    }
    return e;
  };
  const x = off.authInput(BigInt(honestBit), 0);
  let triple;
  armed = true;
  try {
    triple = off.genAuthTriple();
  } catch (e) {
    if (e instanceof MacCheckAbort) return { aborted: true, shareBit, truth: honestBit, blamed: (e as OfflineCheatingAbort).blamed };
    throw e;
  }
  const engine = new SpdzEngine(off.macContext, []);
  const d = engine.open(subAuth(x, triple.a), 'd'); // PUBLIC Beaver opening d = x - a_0
  // the attacker's best guess assuming "no abort => bit0(a_0) = 0": x = d + a (mod p, p odd) => bit0(x) = bit0(d) xor 1
  return { aborted: false, shareBit, guess: Number((d & 1n) ^ 1n), truth: honestBit };
}

function campaign(runs: number, statSec: number, predicate: Predicate) {
  let aborts = 0;
  let abortsWithShareBit1 = 0;
  let correct = 0;
  let guesses = 0;
  let namedSender = 0;
  for (let t = 0; t < runs; t++) {
    const r = trial(t & 1, BigInt(7000 + t * 13), statSec, predicate);
    if (r.aborted) {
      aborts++;
      if (r.shareBit === 1) abortsWithShareBit1++;
      if (r.blamed?.length === 1 && r.blamed[0] === 1) namedSender++;
    } else {
      guesses++;
      if (r.guess === r.truth) correct++;
    }
  }
  return { aborts, abortsWithShareBit1, guesses, correct, namedSender };
}

describe('RT-04: selective failure in no-dealer triple generation', () => {
  const RUNS = 200;

  it('positive control: with LEGACY plain choice bits the attack recovers the honest bit on every non-aborting run', () => {
    const r = campaign(40, 0, 'bit');
    expect(r.guesses).toBeGreaterThan(5);
    expect(r.correct).toBe(r.guesses); // 100% - the attack works
    expect(r.abortsWithShareBit1).toBe(r.aborts); // every abort coincides with share bit 0 == 1
  }, 120_000);

  for (const [predicate, runs] of [['bit', RUNS], ['xor', 100]] as const) {
    it(`privacy-amplified choice bits: the attacker's recovery rate over ${runs} runs is chance (predicate '${predicate}')`, () => {
      const r = campaign(runs, 64, predicate);
      // the run aborts about half of the time (the predicate still fires) ...
      expect(r.aborts).toBeGreaterThan(runs / 4);
      expect(r.guesses).toBeGreaterThan(runs / 4);
      // ... but the non-abort event carries no information on the honest input bit: success rate within 3.5 sigma of 1/2
      const rate = r.correct / r.guesses;
      const sigma = 0.5 / Math.sqrt(r.guesses);
      expect(Math.abs(rate - 0.5)).toBeLessThan(3.5 * sigma);
      // ... and the abort no longer tells the attacker the honest share bit (legacy: 100%)
      const abortCorr = r.abortsWithShareBit1 / r.aborts;
      expect(Math.abs(abortCorr - 0.5)).toBeLessThan(3.5 * (0.5 / Math.sqrt(r.aborts)));
      // attribution still names the cheating sender in every abort
      expect(r.namedSender).toBe(r.aborts);
    }, 900_000);
  }

  it('the encoding itself: the shares are uniform-looking and the gadget evaluates the sampled bits', () => {
    const rng = new FieldRng(5n);
    const g = makeGadget(64, () => rng.next());
    expect(g.length).toBe(61 + 192);
    expect(g.every((v) => v >= 0n && v < PRIME)).toBe(true);
    expect(() => makeGadget(39, () => 1n)).toThrow(/refused/);
    expect(() => new NoDealerOffline(2, 1n, { statSec: 8 })).toThrow(/refused/);
    expect(new NoDealerOffline(2, 1n).statSec).toBe(64);
    expect(encValue(makeGadget(0, () => 0n, true), plainShare(123456789n).bits)).toBe(123456789n);
  });
});
