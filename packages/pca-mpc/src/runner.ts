/**
 * The simulated multi-party runner: all N parties live in one process and exchange shares/openings
 * through explicit, inspectable data structures, so the whole protocol is deterministic and
 * testable. `composeSecure` computes EXACTLY `composeClear` under MPC, revealing only the composed
 * decision at the end.
 *
 * What is revealed (public output): the composed allow bit and the composed thermometers for t and
 * r (which encode precisely the agreed MAX). What is NEVER reconstructed: any individual party's
 * allow/t/r, or any party's thermometer bit — those stay additively shared throughout. The only
 * online messages are the Beaver openings (masked d, e values), collected in `opened`.
 *
 * Every secure operation (AND of allows, OR per thermometer position) is built from the one
 * interactive primitive, Beaver multiplication; MAX is reduced to OR via the thermometer encoding so
 * no comparison circuit is needed.
 */

import { FieldRng } from './field';
import { beaverMul, genTriple, type OpenedMsg, type Triple } from './beaver';
import {
  notBitSV,
  reconstruct,
  share,
  shareConstant,
  type SharedValue,
} from './sharing';
import { thermometerDecode, thermometerEncode } from './thermometer';
import { DEFAULT_Q, type DecisionVector } from './party';
import type { ComposedDecision } from './compose';

export interface MpcConfig {
  /** r-quantization domain {0..Q}. Must match the Q used to build the decision vectors. */
  Q?: number;
  /** Deterministic PRNG seed for sharing + triple randomness. */
  seed?: bigint;
}

/** The full additive sharing of one party's secret bit — exposed for test inspection only. */
export interface SharingRecord {
  label: string;
  party: number;
  /** Cleartext secret (0/1). Parties never see another party's secret; tests may. */
  secret: bigint;
  shares: bigint[];
}

/** One party's complete view of the protocol (what a semi-honest corruption of that party would see). */
export interface PartyView {
  party: number;
  /** This party's held share of every shared secret, in sharing order. */
  heldShares: bigint[];
  /** The public opened messages (identical broadcast transcript for every party). */
  opened: OpenedMsg[];
  /** The final revealed public output. */
  output: ComposedDecision;
}

export interface MpcResult {
  composed: ComposedDecision;
  parties: number;
  Q: number;
  /** All Beaver openings (the only online messages). */
  opened: OpenedMsg[];
  /** Full sharings of every input bit (test inspection). */
  sharings: SharingRecord[];
  views: PartyView[];
  /** Number of Beaver multiplications performed. */
  multiplications: number;
}

const T_M = 3; // threshold domain {0..3}; party thresholds are always in {1,2,3}

/** Compose stakeholder decision vectors under MPC. Requires >= 1 party (0 parties => fail closed). */
export function composeSecure(vectors: ReadonlyArray<DecisionVector>, cfg: MpcConfig = {}): MpcResult {
  const n = vectors.length;
  if (n === 0) throw new Error('composeSecure: no parties (fail closed)');
  const Q = cfg.Q ?? DEFAULT_Q;
  const rng = new FieldRng(cfg.seed);

  const opened: OpenedMsg[] = [];
  const sharings: SharingRecord[] = [];
  let mults = 0;
  const nextTriple = (): Triple => genTriple(n, rng);

  const shareBit = (bit: number, label: string, party: number): SharedValue => {
    const shares = share(BigInt(bit), n, rng);
    sharings.push({ label, party, secret: BigInt(bit), shares: shares.slice() });
    return shares;
  };

  // Secure AND over shared bits = product (N-1 multiplications).
  const andBits = (bits: SharedValue[]): SharedValue => {
    if (bits.length === 0) return shareConstant(1n, n);
    let acc = bits[0]!;
    for (let i = 1; i < bits.length; i++) {
      acc = beaverMul(acc, bits[i]!, nextTriple(), opened);
      mults++;
    }
    return acc;
  };

  // Secure OR over shared bits = 1 - Π(1 - b_i) (N-1 multiplications).
  const orBits = (bits: SharedValue[]): SharedValue => {
    if (bits.length === 0) return shareConstant(0n, n);
    let prod = notBitSV(bits[0]!);
    for (let i = 1; i < bits.length; i++) {
      prod = beaverMul(prod, notBitSV(bits[i]!), nextTriple(), opened);
      mults++;
    }
    return notBitSV(prod);
  };

  // --- 1. composed allow = AND of each party's allow bit ---
  const allowBits = vectors.map((v, p) => shareBit(v.allow, `p${p}.allow`, p));
  const allow: 0 | 1 = reconstruct(andBits(allowBits)) === 1n ? 1 : 0;

  // --- 2. composed t = MAX of thresholds (position-wise OR of thermometers over {1..3}) ---
  const tTherm = vectors.map((v) => thermometerEncode(v.t, T_M));
  const tGeMax: number[] = [];
  for (let k = 0; k < T_M; k++) {
    const bitsAtK = vectors.map((_, p) => shareBit(tTherm[p]![k]!, `p${p}.t.ge${k + 1}`, p));
    tGeMax.push(reconstruct(orBits(bitsAtK)) === 1n ? 1 : 0);
  }
  const t = clampT(thermometerDecode(tGeMax));

  // --- 3. composed r = MAX of rQuant (position-wise OR of thermometers over {1..Q}) ---
  const rTherm = vectors.map((v) => thermometerEncode(v.rQuant, Q));
  const rGeMax: number[] = [];
  for (let k = 0; k < Q; k++) {
    const bitsAtK = vectors.map((_, p) => shareBit(rTherm[p]![k]!, `p${p}.r.ge${k + 1}`, p));
    rGeMax.push(reconstruct(orBits(bitsAtK)) === 1n ? 1 : 0);
  }
  const rQuant = thermometerDecode(rGeMax);

  const composed: ComposedDecision = { allow, t, rQuant };
  const views: PartyView[] = [];
  for (let p = 0; p < n; p++) {
    views.push({
      party: p,
      heldShares: sharings.map((s) => s.shares[p]!),
      opened,
      output: composed,
    });
  }
  return { composed, parties: n, Q, opened, sharings, views, multiplications: mults };
}

function clampT(x: number): 1 | 2 | 3 {
  return Math.min(3, Math.max(1, x)) as 1 | 2 | 3;
}
