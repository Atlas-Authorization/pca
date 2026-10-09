/**
 * The MALICIOUS-secure (SPDZ) multi-party runner. Same composition semantics as the semi-honest
 * `composeSecure` (allow = AND, t = MAX, r = MAX, via the thermometer encoding and the one
 * interactive primitive, authenticated Beaver multiplication), but now every shared value carries a
 * SPDZ MAC and NOTHING is accepted as output until the batched MAC-check passes.
 *
 * Guarantee: for honest parties the output equals `composeClear` exactly; under up to N−1 ACTIVELY
 * malicious parties the output is either that same correct value or a `MacCheckAbort` — never a
 * silent wrong answer. (Malicious-with-abort, dishonest-majority.)
 *
 * Offline phase (two interchangeable sources, same tiny interface):
 *   - DEFAULT: a trusted dealer produces the authenticated triples / input sharings and knows α.
 *   - NO-DEALER: pass `cfg.offline` (a `NoDealerOffline` from `mascot.ts`) and the triples, input
 *     sharings and the distributed MAC key all come from real oblivious transfer — no dealer, and α
 *     is never reconstructed. Either way the ONLINE phase here is the same maliciously-secure protocol.
 * See spdz.ts + mascot.ts + docs §7 for the offline boundary.
 */

import { FieldRng } from './field';
import {
  authConstant,
  authShare,
  beaverMulAuth,
  type AuthSV,
  type AuthTriple,
  type Deviation,
  genAuthTriple,
  notBitAuth,
  setupMac,
  SpdzEngine,
  type MacContext,
} from './spdz';
import type { OfflineProvider } from './mascot';
import { thermometerDecode, thermometerEncode } from './thermometer';
import { DEFAULT_Q, type DecisionVector } from './party';
import type { ComposedDecision } from './compose';

export interface MaliciousMpcConfig {
  Q?: number;
  seed?: bigint;
  /** Active-adversary deviations injected into the online openings (empty => honest run). */
  deviations?: Deviation[];
  /**
   * A NO-DEALER offline provider (see `mascot.ts`). When present, the MAC key, authenticated triples
   * and authenticated input sharings all come from it (derived from OT, no trusted dealer). When
   * absent, the trusted-dealer functions (`setupMac`/`genAuthTriple`/`authShare`) are used.
   */
  offline?: OfflineProvider;
}

export interface MaliciousMpcResult {
  composed: ComposedDecision;
  parties: number;
  Q: number;
  /** Total partial-opens performed (lets callers/tests target the output opens, which are the last ones). */
  opens: number;
  /** Number of authenticated Beaver multiplications performed. */
  multiplications: number;
  /** True iff the SPDZ MAC-check passed (always true when a result is returned; an abort throws). */
  macChecked: true;
}

const T_M = 3;

/**
 * Compose stakeholder decision vectors under MALICIOUS-secure MPC. Returns the composed decision only
 * if the MAC-check passes; otherwise throws `MacCheckAbort` (fail-closed: no output on detected
 * cheating). Requires ≥ 1 party.
 */
export function composeSecureMalicious(
  vectors: ReadonlyArray<DecisionVector>,
  cfg: MaliciousMpcConfig = {},
): MaliciousMpcResult {
  const n = vectors.length;
  if (n === 0) throw new Error('composeSecureMalicious: no parties (fail closed)');
  const Q = cfg.Q ?? DEFAULT_Q;
  const rng = new FieldRng(cfg.seed);

  // --- Offline: MAC key + authenticated input sharings + triples ---
  // Either a NO-DEALER provider (OT-based, mascot.ts) or the trusted dealer, behind one interface.
  const offline = cfg.offline;
  if (offline && offline.n !== n) {
    throw new Error('composeSecureMalicious: offline provider party count != number of vectors');
  }
  const ctx: MacContext = offline ? offline.macContext : setupMac(n, rng);
  const engine = new SpdzEngine(ctx, cfg.deviations ?? []);
  let mults = 0;
  const nextTriple = (): AuthTriple => (offline ? offline.genAuthTriple() : genAuthTriple(ctx, rng));
  const shareBit = (bit: number, owner: number): AuthSV =>
    offline ? offline.authInput(BigInt(bit), owner) : authShare(BigInt(bit), ctx, rng);

  // Secure AND over authenticated bits = product.
  const andBits = (bits: AuthSV[]): AuthSV => {
    if (bits.length === 0) return authConstant(1n, ctx);
    let acc = bits[0]!;
    for (let i = 1; i < bits.length; i++) {
      acc = beaverMulAuth(acc, bits[i]!, nextTriple(), ctx, engine, `and${i}`);
      mults++;
    }
    return acc;
  };

  // Secure OR over authenticated bits = 1 − Π(1 − b_i).
  const orBits = (bits: AuthSV[]): AuthSV => {
    if (bits.length === 0) return authConstant(0n, ctx);
    let prod = notBitAuth(bits[0]!, ctx);
    for (let i = 1; i < bits.length; i++) {
      prod = beaverMulAuth(prod, notBitAuth(bits[i]!, ctx), nextTriple(), ctx, engine, `or${i}`);
      mults++;
    }
    return notBitAuth(prod, ctx);
  };

  // --- Circuit: compute authenticated allow / t-thermometer / r-thermometer (no opening yet) ---
  // Each input bit is authenticated-shared by its OWNER party p (the owner matters for the no-dealer
  // input gate; the dealer path ignores it).
  const allowBits = vectors.map((v, p) => shareBit(v.allow, p));
  const allowSV = andBits(allowBits);

  const tTherm = vectors.map((v) => thermometerEncode(v.t, T_M));
  const tGeSV: AuthSV[] = [];
  for (let k = 0; k < T_M; k++) {
    tGeSV.push(orBits(vectors.map((_, p) => shareBit(tTherm[p]![k]!, p))));
  }

  const rTherm = vectors.map((v) => thermometerEncode(v.rQuant, Q));
  const rGeSV: AuthSV[] = [];
  for (let k = 0; k < Q; k++) {
    rGeSV.push(orBits(vectors.map((_, p) => shareBit(rTherm[p]![k]!, p))));
  }

  // --- Output opening: partial-open every output value (recorded for the MAC-check) ---
  const allowOpen = engine.open(allowSV, 'out:allow');
  const tOpen = tGeSV.map((sv, k) => engine.open(sv, `out:t.ge${k + 1}`));
  const rOpen = rGeSV.map((sv, k) => engine.open(sv, `out:r.ge${k + 1}`));

  // --- MAC-check: verify EVERYTHING opened (Beaver d/e + outputs). Aborts (throws) on any cheat. ---
  engine.macCheck(rng);

  // --- Only now, with the transcript certified consistent, decode the outputs ---
  const allow: 0 | 1 = allowOpen === 1n ? 1 : 0;
  const t = clampT(thermometerDecode(tOpen.map((v) => (v === 1n ? 1 : 0))));
  const rQuant = thermometerDecode(rOpen.map((v) => (v === 1n ? 1 : 0)));

  return {
    composed: { allow, t, rQuant },
    parties: n,
    Q,
    opens: engine.openCount,
    multiplications: mults,
    macChecked: true,
  };
}

function clampT(x: number): 1 | 2 | 3 {
  return Math.min(3, Math.max(1, x)) as 1 | 2 | 3;
}
