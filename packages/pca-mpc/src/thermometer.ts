/**
 * Thermometer (unary) encoding of a bounded integer, which is what lets us compute MAX securely
 * using only the AND/OR primitive (hence only Beaver multiplication) — no comparison circuit.
 *
 * A value v in {0..M} is encoded as the bit vector ge[k] = [v >= k] for k = 1..M. Because v>=k
 * implies v>=k-1, the vector is monotone: a block of 1s followed by 0s. Then:
 *   - MAX of several values  = position-wise OR of their thermometers (OR preserves monotonicity,
 *     and (max v)>=k  iff  some v_i >= k). Decoding = counting the leading 1s.
 *   - OR of bits over N parties = 1 - Π_i (1 - b_i), i.e. built from multiplication.
 *
 * So "max over a small bounded domain" reduces to the same shared-multiplication primitive as "AND
 * of allow bits", and we never reveal any party's individual thermometer — only the composed one,
 * which encodes exactly the agreed MAX (the intended output).
 */

/** Encode v in {0..M} as ge[k] = (v >= k) for k=1..M. Clamps v into range (fail-safe). */
export function thermometerEncode(v: number, M: number): number[] {
  if (!Number.isInteger(M) || M < 0) throw new Error('thermometerEncode: M must be a non-negative integer');
  const clamped = Math.max(0, Math.min(M, Math.trunc(v)));
  const bits: number[] = [];
  for (let k = 1; k <= M; k++) bits.push(clamped >= k ? 1 : 0);
  return bits;
}

/**
 * Decode a thermometer back to an integer = the number of 1s. For a well-formed (monotone)
 * thermometer this is the encoded value; for the composed OR it is the MAX. Robust to non-monotone
 * input (counts set bits), which only matters defensively.
 */
export function thermometerDecode(bits: ReadonlyArray<number | bigint>): number {
  let count = 0;
  for (const b of bits) if (b === 1 || b === 1n) count++;
  return count;
}
