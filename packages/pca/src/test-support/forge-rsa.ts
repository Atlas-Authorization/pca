/**
 * TEST-ONLY deterministic RSA for the evidence forgers: a keypair derived from a seed string (BigInt prime search over a
 * SHA-256 counter stream), PKCS#1 v1.5 (RFC 8017 8.2) and RSASSA-PSS (8.1) signatures with a seed-derived salt.
 * `node:crypto` can only mint random RSA keys and random PSS salts, so a forged RSA chain or RS256 token would differ on
 * every run; this module makes the conformance vector file reproducible. Keys are small test keys (2048-bit) that sign
 * only test evidence under test roots: NEVER import from production code, never use for anything else.
 */
import { createHash } from 'node:crypto';
import { bitString, cat, fill, integer, nul, oid, seq } from './forge-x509';

const modpow = (b: bigint, e: bigint, m: bigint): bigint => {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    e >>= 1n;
    b = (b * b) % m;
  }
  return r;
};
const SMALL = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n, 127n, 131n, 137n, 139n, 149n, 151n, 157n, 163n, 167n, 173n, 179n, 181n, 191n, 193n, 197n, 199n];
function millerRabin(n: bigint): boolean {
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let comp = true;
    for (let i = 1; i < s; i++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        comp = false;
        break;
      }
    }
    if (comp) return false;
  }
  return true;
}
const toBig = (b: Uint8Array): bigint => BigInt(`0x${Buffer.from(b).toString('hex') || '0'}`);
const fromBig = (v: bigint, len: number): Uint8Array => Uint8Array.from(Buffer.from(v.toString(16).padStart(len * 2, '0'), 'hex'));
function egcdInv(a: bigint, m: bigint): bigint {
  let [r0, r1, t0, t1] = [m, a % m, 0n, 1n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [t0, t1] = [t1, t0 - q * t1];
  }
  return ((t0 % m) + m) % m;
}
function prime(seed: string, bits: number): bigint {
  for (let ctr = 0; ; ctr++) {
    const raw = fill(`rsa-prime/${seed}/${ctr}`, bits / 8);
    raw[0] = raw[0]! | 0xc0; // top two bits: the product has full length
    raw[raw.length - 1] = raw[raw.length - 1]! | 1;
    const c = toBig(raw);
    if (SMALL.some((p) => c % p === 0n)) continue;
    if ((c - 1n) % 65537n === 0n) continue;
    if (millerRabin(c)) return c;
  }
}

export interface ForgeRsaKey {
  bits: number;
  n: bigint;
  e: bigint;
  d: bigint;
  /** Modulus length in bytes. */
  k: number;
  /** DER RSAPublicKey. */
  rsaPublicKey: Uint8Array;
  /** SubjectPublicKeyInfo with the rsaEncryption algorithm. */
  spki: Uint8Array;
  /** SubjectPublicKeyInfo with the id-RSASSA-PSS algorithm (no parameters), as AMD's ARK/ASK carry. */
  spkiPss: Uint8Array;
  /** JWK members (base64url, big-endian, no padding). */
  jwk: { kty: 'RSA'; n: string; e: string };
  /** SHA-256 over {@link spki}. */
  spkiSha256: string;
}

const cache = new Map<string, ForgeRsaKey>();
/** Deterministic RSA key (e = 65537) for `seed`. */
export function forgeRsaKey(seed: string, bits = 2048): ForgeRsaKey {
  const ck = `${seed}/${bits}`;
  const hit = cache.get(ck);
  if (hit) return hit;
  const e = 65537n;
  let p = prime(`${seed}/p`, bits / 2);
  let q = prime(`${seed}/q`, bits / 2);
  if (p === q) q = prime(`${seed}/q2`, bits / 2);
  if (p < q) [p, q] = [q, p];
  const n = p * q;
  const d = egcdInv(e, (p - 1n) * (q - 1n));
  const k = bits / 8;
  const rsaPublicKey = seq(integer(fromBig(n, k)), integer(65537));
  const spki = seq(seq(oid('1.2.840.113549.1.1.1'), nul()), bitString(rsaPublicKey));
  const spkiPss = seq(seq(oid('1.2.840.113549.1.1.10')), bitString(rsaPublicKey));
  const key: ForgeRsaKey = {
    bits, n, e, d, k, rsaPublicKey, spki, spkiPss,
    jwk: { kty: 'RSA', n: Buffer.from(fromBig(n, k)).toString('base64url'), e: Buffer.from(fromBig(e, 3)).toString('base64url') },
    spkiSha256: createHash('sha256').update(spki).digest('hex'),
  };
  cache.set(ck, key);
  return key;
}

const DIGEST_INFO: Record<'sha256' | 'sha384', Uint8Array> = {
  sha256: Uint8Array.from(Buffer.from('3031300d060960864801650304020105000420', 'hex')),
  sha384: Uint8Array.from(Buffer.from('3041300d060960864801650304020205000430', 'hex')),
};

/** RSASSA-PKCS1-v1_5 signature (deterministic). */
export function rsaSignPkcs1(key: ForgeRsaKey, alg: 'sha256' | 'sha384', msg: Uint8Array): Uint8Array {
  const h = createHash(alg).update(msg).digest();
  const t = cat(DIGEST_INFO[alg], h);
  const em = cat(Uint8Array.of(0x00, 0x01), new Uint8Array(key.k - t.length - 3).fill(0xff), Uint8Array.of(0x00), t);
  return fromBig(modpow(toBig(em), key.d, key.n), key.k);
}

function mgf1(seed: Uint8Array, len: number, alg: 'sha256' | 'sha384'): Uint8Array {
  const out: Buffer[] = [];
  for (let c = 0; out.length * createHash(alg).digest().length < len; c++) {
    out.push(createHash(alg).update(seed).update(Uint8Array.of(c >>> 24, (c >>> 16) & 255, (c >>> 8) & 255, c & 255)).digest());
  }
  return Uint8Array.from(Buffer.concat(out)).subarray(0, len);
}

/** RSASSA-PSS signature (MGF1 with the same digest) with a seed-derived salt of `saltLen` bytes (deterministic). */
export function rsaSignPss(key: ForgeRsaKey, alg: 'sha256' | 'sha384', msg: Uint8Array, saltLen: number, saltSeed: string): Uint8Array {
  const hLen = createHash(alg).digest().length;
  const emBits = key.bits - 1;
  const emLen = Math.ceil(emBits / 8);
  const salt = fill(`pss-salt/${saltSeed}`, saltLen);
  const mHash = createHash(alg).update(msg).digest();
  const h = createHash(alg).update(new Uint8Array(8)).update(mHash).update(salt).digest();
  const db = cat(new Uint8Array(emLen - saltLen - hLen - 2), Uint8Array.of(0x01), salt);
  const mask = mgf1(h, emLen - hLen - 1, alg);
  const maskedDb = db.map((b, i) => b ^ mask[i]!);
  maskedDb[0] = maskedDb[0]! & (0xff >> (8 * emLen - emBits));
  const em = cat(maskedDb, h, Uint8Array.of(0xbc));
  return fromBig(modpow(toBig(em), key.d, key.n), key.k);
}
