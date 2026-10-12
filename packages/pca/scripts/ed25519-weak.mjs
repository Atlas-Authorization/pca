// Deterministic Ed25519 "weak key / weak signature" crafting for the conformance generators. The TypeScript reference
// (src/keys.ts) is STRICTER than plain RFC 8032: besides S < L and canonical point encodings it rejects every small-order
// A or R and every mixed-order (A + T, T of order 2/4/8) A or R. A native verifier built on a plain RFC 8032 library (cofactorless
// `[S]B = R + [k]A`, or cofactored `[8][S]B = [8]R + [8][k]A`) can ACCEPT the artifacts crafted here, so each one is a
// discriminating vector: the helpers check the *plain* equation and only emit a signature that a plain verifier would accept.
import { createHash } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519';

const Pt = ed25519.ExtendedPoint;
export const N = ed25519.CURVE.n; // group order L
const P = ed25519.CURVE.Fp.ORDER; // 2^255 - 19
const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const sha512 = (...parts) => createHash('sha512').update(Buffer.concat(parts.map((x) => Buffer.from(x)))).digest();
const leNum = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
export const numLE = (n, len = 32) => { const o = new Uint8Array(len); for (let i = 0; i < len; i++) { o[i] = Number(n & 0xffn); n >>= 8n; } return o; };
const fromEnc = (b) => Pt.fromHex(b, true); // ZIP-215 permissive decode: accepts non-canonical y so we can reason about the point
export const enc = (pt) => pt.toRawBytes();
export const IDENTITY_ENC = hex('01' + '00'.repeat(31));

/** The eight small-order points (canonical encodings) of edwards25519. */
export const SMALL_ORDER = [
  ['identity-order1', '0100000000000000000000000000000000000000000000000000000000000000'],
  ['order2-y-minus1', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['order4-x-pos', '0000000000000000000000000000000000000000000000000000000000000000'],
  ['order4-x-neg', '0000000000000000000000000000000000000000000000000000000000000080'],
  ['order8-a-pos', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'],
  ['order8-a-neg', '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85'],
  ['order8-b-pos', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'],
  ['order8-b-neg', 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'],
].map(([name, h]) => ({ name, bytes: hex(h) }));

/** NON-canonical encodings of small-order points: y + p (y < 19 aliases) and the "negative zero" x = 0 with the sign bit set. */
export const SMALL_ORDER_NONCANON = [
  ['identity-y-plus-p', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'],
  ['identity-y-plus-p-sign', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
  ['identity-negative-zero', '0100000000000000000000000000000000000000000000000000000000000080'],
  ['order2-negative-zero', 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
  ['order4-y0-plus-p', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'.replace(/^ed/, 'ed')], // y = p (alias of y = 0)
  ['order4-y0-plus-p-sign', 'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'],
].map(([name, h]) => ({ name, bytes: hex(h) }));
// y = p aliases 0 (order-4 point), y = p + 1 aliases 1 (identity): fix the two entries above precisely
{ const yPlus = (y) => numLE(P + BigInt(y)); SMALL_ORDER_NONCANON[0].bytes = yPlus(1); SMALL_ORDER_NONCANON[4].bytes = yPlus(0); const s = (b) => { const c = Uint8Array.from(b); c[31] |= 0x80; return c; }; SMALL_ORDER_NONCANON[1].bytes = s(yPlus(1)); SMALL_ORDER_NONCANON[5].bytes = s(yPlus(0)); }

const ptOf = (e) => fromEnc(e);
const eight = (e) => ptOf(e);
export const ORDER8 = [SMALL_ORDER[4].bytes, SMALL_ORDER[6].bytes].map(eight); // two generators of the order-8 subgroup (x2 sign variants are their negations)
export const T8 = ORDER8[0];
export const T4 = SMALL_ORDER[2].bytes.length ? eight(SMALL_ORDER[2].bytes) : null;
export const T2 = eight(SMALL_ORDER[1].bytes);

/** Deterministic secret scalar `a` and honest public point A0 = a*B from a label. */
export function keyOf(label) {
  const a = (leNum(createHash('sha512').update('atlas-pca-conformance/ed-weak/' + label).digest()) % (N - 1n)) + 1n;
  return { a, A0: Pt.BASE.multiply(a) };
}
const kOf = (Renc, Aenc, M) => leNum(sha512(Renc, Aenc, M)) % N;
const mod = (x) => ((x % N) + N) % N;

/**
 * Craft signatures over message `msgFor(i)` (i = 0,1,2,... tweak) until `accepts(k)` holds, then return
 * { sig, tweak, A, plainOk } where `plainOk` is the plain cofactorless AND cofactored acceptance of the equation.
 * kind: 'mixedA' (A = A0 + T, R = rB, S = r + k a; needs k = 0 mod ord(T)),
 *       'mixedR' (A = A0, R = rB + T, S = r + k a; a COFACTORED verifier accepts),
 *       'smallA' (A small-order, R = identity, S = 0; needs k*A = O),
 *       'smallR' (A = A0, R small-order Q, S = k a; a COFACTORED verifier accepts),
 *       'nonCanonS' (honest A0, R = rB, S = r + k a + L),
 *       'smallBoth' (A and R small-order, S = 0; needs R + kA = O).
 */
export function craft({ kind, label, msgFor, T = T8, Aenc, Renc, maxTries = 4000 }) {
  const { a, A0 } = keyOf(label);
  const r = (leNum(createHash('sha512').update('atlas-pca-conformance/ed-weak/nonce/' + label + '/' + kind).digest()) % (N - 1n)) + 1n;
  for (let tweak = 0; tweak < maxTries; tweak++) {
    const M = msgFor(tweak);
    let A, R, Aenc_, Renc_, S;
    if (kind === 'mixedA') { A = A0.add(T); Aenc_ = enc(A); R = Pt.BASE.multiply(r); Renc_ = enc(R); const k = kOf(Renc_, Aenc_, M); if (k % 8n !== 0n) continue; S = mod(r + k * a); }
    else if (kind === 'mixedR') { A = A0; Aenc_ = enc(A); R = Pt.BASE.multiply(r).add(T); Renc_ = enc(R); const k = kOf(Renc_, Aenc_, M); S = mod(r + k * a); }
    else if (kind === 'smallA') { A = ptOf(Aenc); Aenc_ = Aenc; R = Pt.ZERO; Renc_ = Renc ?? IDENTITY_ENC; const k = kOf(Renc_, Aenc_, M); if (!mulSmall(A, k).equals(Pt.ZERO)) continue; S = 0n; }
    else if (kind === 'smallR') { A = A0; Aenc_ = enc(A); R = ptOf(Renc); Renc_ = Renc; const k = kOf(Renc_, Aenc_, M); S = mod(k * a); }
    else if (kind === 'nonCanonS') { A = A0; Aenc_ = enc(A); R = Pt.BASE.multiply(r); Renc_ = enc(R); const k = kOf(Renc_, Aenc_, M); S = mod(r + k * a) + N; }
    else if (kind === 'smallBoth') { A = ptOf(Aenc); Aenc_ = Aenc; R = ptOf(Renc); Renc_ = Renc; const k = kOf(Renc_, Aenc_, M); if (!R.add(mulSmall(A, k)).equals(Pt.ZERO)) continue; S = 0n; }
    else throw new Error('craft: unknown kind ' + kind);
    const sig = new Uint8Array(64); sig.set(Renc_, 0); sig.set(numLE(S), 32);
    return { sig, tweak, A: Aenc_, plain: plainVerify(Aenc_, M, sig) };
  }
  throw new Error(`craft(${kind}, ${label}): no tweak in ${maxTries} tries`);
}
const mulZ = (pt, n) => (n === 0n ? Pt.ZERO : pt.multiplyUnsafe(n));
// k * (small-order point): reduce k mod 8 first (the group of small-order points has exponent dividing 8)
function mulSmall(A, k) { const m = k % 8n; return m === 0n ? Pt.ZERO : A.multiplyUnsafe(m); }

/** Plain RFC 8032 verdicts (permissive point decode, S as given): { cofactorless, cofactored, sCanonical }. */
export function plainVerify(Aenc, M, sig) {
  try {
    const A = ptOf(Aenc), R = ptOf(sig.subarray(0, 32));
    const S = leNum(sig.subarray(32));
    const k = kOf(sig.subarray(0, 32), Aenc, M);
    const lhs = mulZ(Pt.BASE, S % N);
    const rhs = R.add(mulZ(A, k));
    return { cofactorless: lhs.equals(rhs), cofactored: mulZ(lhs, 8n).equals(mulZ(rhs, 8n)), sCanonical: S < N };
  } catch { return { cofactorless: false, cofactored: false, sCanonical: false }; }
}
export const hasPlainAcceptance = (p) => p.cofactorless || p.cofactored;

/** The public-key encoding a crafted signature of this spec will be checked under (known before the message is chosen). */
export function pubFor({ kind, label, T = T8, Aenc }) {
  const { A0 } = keyOf(label);
  if (kind === 'mixedA') return enc(A0.add(T));
  if (kind === 'mixedR' || kind === 'smallR' || kind === 'nonCanonS') return enc(A0);
  return Aenc;
}

/** The full weak-signature matrix, as specs { name, desc, kind, label, T?, Aenc?, Renc? }. */
export function specs() {
  const out = [];
  const o8 = [['t8a', T8], ['t8b', ORDER8[1]], ['t4', T4], ['t2', T2]];
  for (const [tn, T] of o8) out.push({ name: `mixed-order-A-${tn}-k0mod8`, desc: `Public key A = A0 + ${tn} (mixed order), signature valid for plain RFC 8032 because k = 0 (mod 8): strict verifiers reject the mixed-order key.`, kind: 'mixedA', label: 'ma-' + tn, T });
  for (const [tn, T] of o8) out.push({ name: `mixed-order-R-${tn}`, desc: `R = rB + ${tn} (mixed order) under an honest key: a cofactored verifier accepts, strict verifiers reject the mixed-order R.`, kind: 'mixedR', label: 'mr-' + tn, T });
  for (const so of SMALL_ORDER) out.push({ name: `small-order-A-${so.name}`, desc: `Small-order public key (${so.name}) with (R = identity, S = 0): verifies under plain RFC 8032 whenever k*A = O; strict verifiers reject small-order keys.`, kind: 'smallA', label: 'sa-' + so.name, Aenc: so.bytes });
  for (const so of SMALL_ORDER_NONCANON) out.push({ name: `small-order-A-noncanonical-${so.name}`, desc: `Non-canonical encoding (${so.name}) of a small-order public key with (R = identity, S = 0).`, kind: 'smallA', label: 'sn-' + so.name, Aenc: so.bytes });
  out.push({ name: 'small-order-A-identity-R-noncanonical', desc: 'Identity key with a non-canonical identity R (y = 1 + p).', kind: 'smallA', label: 'sa-id-nc', Aenc: SMALL_ORDER[0].bytes, Renc: SMALL_ORDER_NONCANON[0].bytes });
  for (const so of SMALL_ORDER) out.push({ name: `small-order-R-${so.name}`, desc: `Honest key, small-order R (${so.name}) with S = k*a: a cofactored verifier accepts, strict verifiers reject small-order R.`, kind: 'smallR', label: 'sr-' + so.name, Renc: so.bytes });
  for (const so of SMALL_ORDER_NONCANON) out.push({ name: `small-order-R-noncanonical-${so.name}`, desc: `Honest key, non-canonical encoding (${so.name}) of a small-order R.`, kind: 'smallR', label: 'sq-' + so.name, Renc: so.bytes });
  const both = [[4, 4], [4, 5], [6, 7], [2, 3], [1, 1], [0, 0]];
  for (const [i, j] of both) out.push({ name: `small-order-A-and-R-${SMALL_ORDER[i].name}-${SMALL_ORDER[j].name}`, desc: 'Small-order key AND small-order R with S = 0 chosen so that R + k*A = O.', kind: 'smallBoth', label: `sb-${i}-${j}`, Aenc: SMALL_ORDER[i].bytes, Renc: SMALL_ORDER[j].bytes });
  out.push({ name: 'noncanonical-S-plus-L', desc: 'Honest key and honest R with S replaced by S + L: plain RFC 8032 without the S < L check accepts, strict verifiers reject.', kind: 'nonCanonS', label: 'ncs' });
  return out;
}
