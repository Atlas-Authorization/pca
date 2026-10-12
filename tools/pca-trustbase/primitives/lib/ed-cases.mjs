// Ed25519 adversarial case generator. Independent BigInt curve arithmetic (NOT noble) so the cases do not inherit a noble bug.
import { createHash } from 'node:crypto';
import { hex, unhex, cat, Prng, BOUNDARY_LENGTHS } from './util.mjs';

export const P = (1n << 255n) - 19n;
export const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const D = (P - (121665n * inv(121666n, P)) % P) % P; // d = -121665/121666
function mod(a, m = P) { const r = a % m; return r >= 0n ? r : r + m; }
function pow(b, e, m = P) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
function inv(a, m = P) { return pow(a, m - 2n, m); }
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

export const toLE = (n, len = 32) => { const o = new Uint8Array(len); for (let i = 0; i < len; i++) { o[i] = Number(n & 255n); n >>= 8n; } return o; };
export const fromLE = (u) => { let n = 0n; for (let i = u.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u[i]); return n; };

/** Decode a 32-byte point with ZIP-215-style leniency (y may be >= p); returns null if not on curve. {x,y} affine mod p. */
export function decodeLenient(u) {
  const sign = u[31] >> 7; const y = mod(fromLE(u) & ((1n << 255n) - 1n));
  const y2 = (y * y) % P; const u_ = mod(y2 - 1n), v = mod(D * y2 + 1n);
  const x2 = (u_ * inv(v)) % P; let x = pow(x2, (P + 3n) / 8n);
  if (mod(x * x - x2) !== 0n) x = (x * SQRT_M1) % P;
  if (mod(x * x - x2) !== 0n) return null;
  if (x === 0n && sign === 1) { /* "negative zero": accepted by lenient decoders */ }
  if (Number(x & 1n) !== sign) x = mod(-x);
  return { x, y };
}
export function encode(pt) { const o = toLE(pt.y); if (pt.x & 1n) o[31] |= 0x80; return o; }
const ID = { x: 0n, y: 1n };
const D2 = (2n * D) % P;
const toExt = (a) => ({ X: a.x, Y: a.y, Z: 1n, T: (a.x * a.y) % P });
function addExt(p, q) { // add-2008-hwcd-3 (a = -1), complete on this curve
  const A = ((p.Y - p.X + P) * (q.Y - q.X + P)) % P, Bb = ((p.Y + p.X) * (q.Y + q.X)) % P, C = (((p.T * D2) % P) * q.T) % P, Dd = (2n * p.Z * q.Z) % P;
  const E = (Bb - A + P) % P, F = (Dd - C + P) % P, G = (Dd + C) % P, H = (Bb + A) % P;
  return { X: (E * F) % P, Y: (G * H) % P, T: (E * H) % P, Z: (F * G) % P };
}
const fromExt = (e) => { const zi = inv(e.Z); return { x: (e.X * zi) % P, y: (e.Y * zi) % P }; };
export function add(a, b) { return fromExt(addExt(toExt(a), toExt(b))); }
export function mul(pt, k) { let r = toExt(ID), q = toExt(pt); k = BigInt(k); while (k > 0n) { if (k & 1n) r = addExt(r, q); q = addExt(q, q); k >>= 1n; } return fromExt(r); }
export const B = decodeLenient(unhex('5866666666666666666666666666666666666666666666666666666666666666'));
export const eq = (a, b) => a.x === b.x && a.y === b.y;
export function order(pt) { for (const o of [1n, 2n, 4n, 8n]) if (eq(mul(pt, o), ID)) return Number(o); return 0; }

const sha512 = (...parts) => createHash('sha512').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
export function expand(sk) { const h = sha512(sk); const a = new Uint8Array(h.subarray(0, 32)); a[0] &= 248; a[31] &= 127; a[31] |= 64; return { a: fromLE(a) , prefix: new Uint8Array(h.subarray(32)) }; }

/** Sign with an explicit public-key ENCODING A_enc (may differ from [a]B, e.g. A+T) and nonce r; returns {R_enc,S,k}. */
export function signRaw(sk, msg, A_enc, r) {
  const { a } = expand(sk); const R = encode(mul(B, r)); return finish(a, msg, A_enc, R, r);
}
function finish(a, msg, A_enc, R_enc, r) { const k = fromLE(sha512(R_enc, A_enc, msg)) % L; const S = (r + k * a) % L; return { R_enc, S, k }; }
export function honest(sk, msg) { const { a, prefix } = expand(sk); const A = encode(mul(B, a)); const r = fromLE(sha512(prefix, msg)) % L; const { R_enc, S } = finish(a, msg, A, encode(mul(B, r)), r); return { A, sig: cat(R_enc, toLE(S)) }; }

// ---- the 8 torsion points and their lenient (non-canonical) re-encodings ----
export const TORSION_HEX = [
  '0100000000000000000000000000000000000000000000000000000000000000', // (0,1) identity, order 1
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // (0,-1) order 2
  '0000000000000000000000000000000000000000000000000000000000000000', // y=0, x=+sqrt(-1) order 4
  '0000000000000000000000000000000000000000000000000000000000000080', // y=0, x=-sqrt(-1) order 4
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05', // order 8
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', // order 8
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85', // order 8
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa', // order 8
];
export const TORSION = TORSION_HEX.map((h) => decodeLenient(unhex(h)));

/** Non-canonical encodings: y in [p, 2^255) i.e. y' = y + p (y < 19), both sign bits; plus sign-bit-on-zero-x ("negative zero"). */
export function nonCanonicalEncodings() {
  const out = [];
  for (let y = 0n; y < 19n; y++) for (const s of [0, 1]) { const u = toLE(y + P); if (s) u[31] |= 0x80; out.push({ enc: u, y, s, onCurve: decodeLenient(u) !== null }); }
  // canonical y with x == 0 but sign bit set (x = -0)
  for (const h of [TORSION_HEX[0], TORSION_HEX[1]]) { const u = unhex(h); u[31] |= 0x80; out.push({ enc: u, y: fromLE(u) & ((1n << 255n) - 1n), s: 1, onCurve: decodeLenient(u) !== null, negZero: true }); }
  // all-ones and y = 2^255-1 style
  out.push({ enc: new Uint8Array(32).fill(0xff), y: (1n << 255n) - 1n, s: 1, onCurve: decodeLenient(new Uint8Array(32).fill(0xff)) !== null });
  return out.filter((o) => o.onCurve);
}

const SMALL_ORDER_FAMILY = () => {
  const fam = TORSION_HEX.map((h, i) => ({ enc: unhex(h), label: 'T' + i })); // canonical
  for (const nc of nonCanonicalEncodings()) { const dec = decodeLenient(nc.enc); if (dec && order(dec) > 0) fam.push({ enc: nc.enc, label: 'NC' + hex(nc.enc).slice(0, 4) + (nc.s ? 's' : '') + (nc.negZero ? 'z' : '') }); }
  // de-dupe by hex
  const seen = new Set(); return fam.filter((f) => { const k = hex(f.enc); if (seen.has(k)) return false; seen.add(k); return true; });
};

/**
 * Cases: {cat, label, pk, msg, sig, expect}. expect = 'valid' (every conforming verifier must accept), 'invalid-rfc' (RFC 8032 rejects; pca
 * MUST reject), 'cofactored-only' (accepted by cofactored/ZIP-215 verification but not cofactorless; pca MUST reject).
 */
export function* edAdversarial({ seed = 1, perCat = 200 } = {}) {
  const rng = new Prng(seed);
  const msgs = [new Uint8Array(0), new TextEncoder().encode('Zebra'), rng.bytes(32), rng.bytes(200)];
  const Sset = [0n, 1n, 2n, L - 1n, L, L + 1n, L + 2n, (1n << 253n) - 1n, 1n << 253n, (1n << 255n) - 1n, (1n << 256n) - 1n];
  const fam = SMALL_ORDER_FAMILY();
  // (1) small-order A x small-order R x S
  for (const A of fam) for (const R of fam) for (const S of Sset) {
    const m = msgs[rng.int(2)];
    const bad = S >= L; const cat_ = bad ? 'S>=L+smallorder' : 'smallorder-A-R';
    yield { cat: cat_, label: `${A.label}/${R.label}/S=${S < 1n << 20n ? S : S.toString(16).slice(0, 6)}`, pk: A.enc, msg: m, sig: cat(R.enc, toLE(S)), expect: 'invalid-rfc' };
  }
  // (2) honest signatures and mutations
  const NHON = perCat;
  for (let i = 0; i < NHON; i++) {
    const sk = rng.bytes(32); const msg = rng.bytes(rng.pick([0, 1, 5, 32, 63, 64, 65, 127, 128, 300])); const { A, sig } = honest(sk, msg);
    yield { cat: 'valid', label: 'honest#' + i, pk: A, msg, sig, expect: 'valid' };
    const S = fromLE(sig.subarray(32));
    yield { cat: 'S>=L', label: 'S+L', pk: A, msg, sig: cat(sig.subarray(0, 32), toLE(S + L)), expect: 'invalid-rfc' };
    yield { cat: 'S>=L', label: 'S+2L', pk: A, msg, sig: cat(sig.subarray(0, 32), toLE(S + 2n * L)), expect: 'invalid-rfc' };
    const hs = sig.slice(); hs[63] |= 0x80; yield { cat: 'S-high-bit', label: 'S|2^255', pk: A, msg, sig: hs, expect: 'invalid-rfc' };
    const hs2 = sig.slice(); hs2[63] |= 0x20; hs2[63] |= 0x10; yield { cat: 'S-high-bit', label: 'S|2^253..4', pk: A, msg, sig: hs2, expect: 'invalid-rfc' };
    for (const pos of [0, 15, 31, 32, 48, 63]) { const f = sig.slice(); f[pos] ^= 1 << rng.int(8); yield { cat: 'bitflip', label: 'sig@' + pos, pk: A, msg, sig: f, expect: 'invalid-rfc' }; }
    const fa = A.slice(); fa[rng.int(32)] ^= 1 << rng.int(8); yield { cat: 'bitflip', label: 'pk', pk: fa, msg, sig, expect: 'invalid-rfc' };
    const fm = msg.slice(); if (fm.length) { fm[rng.int(fm.length)] ^= 1; yield { cat: 'bitflip', label: 'msg', pk: A, msg: fm, sig, expect: 'invalid-rfc' }; }
    yield { cat: 'length', label: 'sig63', pk: A, msg, sig: sig.subarray(0, 63), expect: 'invalid-rfc' };
    yield { cat: 'length', label: 'sig65', pk: A, msg, sig: cat(sig, new Uint8Array(1)), expect: 'invalid-rfc' };
    yield { cat: 'length', label: 'pk31', pk: A.subarray(0, 31), msg, sig, expect: 'invalid-rfc' };
    yield { cat: 'length', label: 'pk33', pk: cat(A, new Uint8Array(1)), msg, sig, expect: 'invalid-rfc' };
    yield { cat: 'wrong-key', label: 'pk=other', pk: honest(rng.bytes(32), msg).A, msg, sig, expect: 'invalid-rfc' };
    // (3) mixed-order A' = A + T_i : signature built over A'; valid only cofactored unless k*T = 0
    const { a } = expand(sk);
    const Apt = decodeLenient(A);
    for (const ti of [1, 2, 3, 4, 5, 6, 7]) {
      const Amix = encode(add(Apt, TORSION[ti]));
      // search a nonce/msg where k mod 8 != 0 (cofactored-only) and one where k mod 8 == 0 (valid cofactorless though mixed-order A)
      for (const want of ['nz', 'z']) {
        for (let t = 0; t < 64; t++) {
          const r = fromLE(rng.bytes(32)) % L; const Rb = encode(mul(B, r)); const k = fromLE(sha512(Rb, Amix, msg)) % L;
          if ((want === 'z') === (k % 8n === 0n)) { const S = (r + k * a) % L; yield { cat: want === 'z' ? 'mixed-A-k0mod8' : 'mixed-A', label: `A+T${ti}`, pk: Amix, msg, sig: cat(Rb, toLE(S)), expect: want === 'z' ? 'mixed-order-cofactorless-valid' : 'cofactored-only' }; break; }
        }
      }
    }
    // (4) mixed-order R' = R + T_i (S honest for R): cofactored-only
    for (const ti of [1, 2, 4, 5]) {
      const r = fromLE(rng.bytes(32)) % L; const R0 = mul(B, r); const Rm = encode(add(R0, TORSION[ti]));
      const k = fromLE(sha512(Rm, A, msg)) % L; const S = (r + k * a) % L;
      yield { cat: 'mixed-R', label: `R+T${ti}`, pk: A, msg, sig: cat(Rm, toLE(S)), expect: 'cofactored-only' };
    }
  }
  // (5) A / R not on curve, garbage encodings, zero/FF signatures
  for (let i = 0; i < perCat * 4; i++) {
    const A = rng.bytes(32); const msg = msgs[rng.int(4)];
    yield { cat: 'random-garbage', label: 'rand', pk: A, msg, sig: rng.bytes(64), expect: 'invalid-rfc' };
  }
  const honestK = honest(rng.bytes(32), msgs[1]);
  yield { cat: 'zero-sig', label: 'zero', pk: honestK.A, msg: msgs[1], sig: new Uint8Array(64), expect: 'invalid-rfc' };
  yield { cat: 'zero-sig', label: 'ff', pk: honestK.A, msg: msgs[1], sig: new Uint8Array(64).fill(255), expect: 'invalid-rfc' };
  yield { cat: 'zero-pk', label: 'pk=0', pk: new Uint8Array(32), msg: msgs[1], sig: new Uint8Array(64), expect: 'invalid-rfc' };
  yield { cat: 'zero-pk', label: 'pk=ff', pk: new Uint8Array(32).fill(255), msg: msgs[1], sig: honestK.sig, expect: 'invalid-rfc' };
  // off-curve A: scan y until no sqrt
  let offs = 0; for (let y = 2n; offs < 40; y++) { const u = toLE(y); if (decodeLenient(u) === null) { offs++; yield { cat: 'A-off-curve', label: 'y=' + y, pk: u, msg: msgs[1], sig: honestK.sig, expect: 'invalid-rfc' }; } }
  // R off-curve
  offs = 0; for (let y = 2n; offs < 40; y++) { const u = toLE(y); if (decodeLenient(u) === null) { offs++; yield { cat: 'R-off-curve', label: 'y=' + y, pk: honestK.A, msg: msgs[1], sig: cat(u, honestK.sig.subarray(32)), expect: 'invalid-rfc' }; } }
  // non-canonical A/R (y >= p) with otherwise honest-looking data
  for (const nc of nonCanonicalEncodings()) {
    yield { cat: 'noncanonical-A', label: hex(nc.enc).slice(0, 8), pk: nc.enc, msg: msgs[1], sig: honestK.sig, expect: 'invalid-rfc' };
    yield { cat: 'noncanonical-R', label: hex(nc.enc).slice(0, 8), pk: honestK.A, msg: msgs[1], sig: cat(nc.enc, honestK.sig.subarray(32)), expect: 'invalid-rfc' };
  }
  // message length boundaries with honest signatures (every verifier must accept)
  for (const n of BOUNDARY_LENGTHS.filter((x) => x <= 70000).concat([1 << 20])) {
    if (n > 8192 && n !== 1 << 20 && n !== 65536) continue;
    const sk = rng.bytes(32); const msg = rng.bytes(n); const { A, sig } = honest(sk, msg);
    yield { cat: 'valid', label: 'len' + n, pk: A, msg, sig, expect: 'valid' };
  }
}
