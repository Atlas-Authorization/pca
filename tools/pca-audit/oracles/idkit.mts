// Shared deterministic key kit for the identity-credential oracles (dpop, webauthn, sdjwt, vc): keys derived from seeds (Ed25519,
// Ed448, ECDSA P-256/384/521 with RFC 6979 signatures, RSA built from seeded primes) and a compact-JWS writer, so a signed token
// is the same bytes on every run. Nothing here is random.
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto';
import { p256, p384, p521 } from '@noble/curves/nist';
import { ed448 } from '@noble/curves/ed448';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2';
import { rng, seed } from './lib.mjs';

export const T0 = 1_800_000_000;
export const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64url');
export const unb = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));
export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** {"$bytes": b64u} members become Uint8Array (the JSON args of an oracle case carry bytes that way). */
export function rev(v: any): any {
  if (Array.isArray(v)) return v.map(rev);
  if (v !== null && typeof v === 'object') {
    const ks = Object.keys(v);
    if (ks.length === 1 && ks[0] === '$bytes') return unb(v.$bytes);
    return Object.fromEntries(ks.map((k) => [k, rev(v[k])]));
  }
  return v;
}

export interface Kit {
  alg: string;
  pub: Record<string, string>;
  priv: Record<string, string>;
  sign(data: Uint8Array): Uint8Array;
}

const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
export function edKit(label: string): Kit & { seed: Uint8Array; raw: Uint8Array } {
  const s = seed(label);
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, Buffer.from(s)]), format: 'der', type: 'pkcs8' });
  const pub = createPublicKey(key).export({ format: 'jwk' }) as Record<string, string>;
  const priv = key.export({ format: 'jwk' }) as Record<string, string>;
  return { alg: 'EdDSA', seed: s, raw: unb(pub.x as string), pub: { kty: 'OKP', crv: 'Ed25519', x: pub.x as string }, priv: { kty: 'OKP', crv: 'Ed25519', x: pub.x as string, d: priv.d as string }, sign: (d) => new Uint8Array(nodeSign(null, d, key)) };
}

export function ed448Kit(label: string): Kit {
  const s = new Uint8Array(Buffer.concat([Buffer.from(seed(label)), Buffer.from(seed(label + '/2')).subarray(0, 25)]));
  const x = b64(ed448.getPublicKey(s));
  return { alg: 'EdDSA', pub: { kty: 'OKP', crv: 'Ed448', x }, priv: { kty: 'OKP', crv: 'Ed448', x, d: b64(s) }, sign: (d) => ed448.sign(d, s) };
}

const CURVES: Record<string, { c: any; h: (m: Uint8Array) => Uint8Array; alg: string; n: number }> = {
  'P-256': { c: p256, h: sha256, alg: 'ES256', n: 32 },
  'P-384': { c: p384, h: sha384, alg: 'ES384', n: 48 },
  'P-521': { c: p521, h: sha512, alg: 'ES512', n: 66 },
};
export function ecKit(crv: 'P-256' | 'P-384' | 'P-521', label: string, opts: { lowS?: boolean } = {}): Kit {
  const { c, h, alg, n } = CURVES[crv] as (typeof CURVES)[string];
  const raw = new Uint8Array(Buffer.concat([Buffer.from(seed(label)), Buffer.from(seed(label + '/2')), Buffer.from(seed(label + '/3'))]).subarray(0, n));
  raw[0] = (raw[0] as number) & (crv === 'P-521' ? 0x01 : 0x7f); // below the group order for every curve here
  const point = c.getPublicKey(raw, false) as Uint8Array;
  const x = b64(point.subarray(1, 1 + n)), y = b64(point.subarray(1 + n));
  return {
    alg,
    pub: { kty: 'EC', crv, x, y },
    priv: { kty: 'EC', crv, x, y, d: b64(raw) },
    sign: (data) => c.sign(h(data), raw, { lowS: opts.lowS ?? true }).toCompactRawBytes(),
  };
}

// ---- RSA from seeded primes ----
function modpow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b %= m;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
function probablePrime(n: bigint): boolean {
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n, s = 0;
  while ((d & 1n) === 0n) { d >>= 1n; s++; }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n]) {
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let comp = true;
    for (let i = 1; i < s; i++) { x = (x * x) % n; if (x === n - 1n) { comp = false; break; } }
    if (comp) return false;
  }
  return true;
}
function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x, y] = egcd(b, a % b);
  return [g, y, x - (a / b) * y];
}
const inv = (a: bigint, m: bigint): bigint => ((egcd(((a % m) + m) % m, m)[1] % m) + m) % m;
const bigB64 = (v: bigint): string => { let h = v.toString(16); if (h.length % 2) h = '0' + h; return Buffer.from(h, 'hex').toString('base64url'); };

export function rsaKit(label: string): Kit {
  const r = rng(createHash('sha256').update(label).digest().readUInt32BE(0));
  const prime = (bits: number): bigint => {
    for (;;) {
      let h = '';
      for (let i = 0; i < bits / 8; i++) h += r.int(0, 255).toString(16).padStart(2, '0');
      const c = BigInt('0x' + h) | (3n << BigInt(bits - 2)) | 1n;
      if (probablePrime(c) && (c - 1n) % 65537n !== 0n) return c;
    }
  };
  let p = prime(1024), q = prime(1024);
  if (p < q) [p, q] = [q, p];
  const n = p * q, e = 65537n;
  const lam = ((p - 1n) * (q - 1n)) / egcd(p - 1n, q - 1n)[0];
  const d = inv(e, lam);
  const pub = { kty: 'RSA', n: bigB64(n), e: bigB64(e) };
  const priv = { ...pub, d: bigB64(d), p: bigB64(p), q: bigB64(q), dp: bigB64(d % (p - 1n)), dq: bigB64(d % (q - 1n)), qi: bigB64(inv(q, p)) };
  const key = createPrivateKey({ key: priv as any, format: 'jwk' });
  return { alg: 'RS256', pub, priv, sign: (data) => new Uint8Array(nodeSign('sha256', data, key)) };
}

/** Compact JWS from a header and payload (objects are JSON.stringify-ed, strings are used verbatim) signed by `kit`. */
export function mkJws(header: unknown, payload: unknown, kit: Kit): string {
  const h = b64(utf8(typeof header === 'string' ? header : JSON.stringify(header)));
  const p = b64(utf8(typeof payload === 'string' ? payload : JSON.stringify(payload)));
  return `${h}.${p}.${b64(kit.sign(utf8(`${h}.${p}`)))}`;
}

/** The alias spellings of a compact JWS a lenient JOSE library may accept (padding, standard alphabet, whitespace, trailing bits). */
export function aliases(token: string): Array<[string, string]> {
  const [h, p, s] = token.split('.') as [string, string, string];
  const std = (x: string) => x.replace(/-/g, '+').replace(/_/g, '/');
  const out: Array<[string, string]> = [
    ['padded signature', `${h}.${p}.${s}=`],
    ['trailing newline', `${token}\n`],
    ['trailing space', `${token} `],
    ['leading space', ` ${token}`],
    ['interior newline', `${h}\n.${p}.${s}`],
    ['empty signature', `${h}.${p}.`],
    ['two segments', `${h}.${p}`],
    ['four segments', `${token}.x`],
  ];
  for (const [n, t] of [['std header', `${std(h)}.${p}.${s}`], ['std payload', `${h}.${std(p)}.${s}`], ['std sig', `${h}.${p}.${std(s)}`]] as const) if (t !== token) out.push([n, t]);
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  if (s.length % 4 === 2 || s.length % 4 === 3) {
    const spare = s.length % 4 === 2 ? 4 : 2;
    const idx = A.indexOf(s[s.length - 1] as string);
    const alt = (idx & ~((1 << spare) - 1)) | (((idx & ((1 << spare) - 1)) + 1) & ((1 << spare) - 1));
    out.push(['altered trailing bits', `${h}.${p}.${s.slice(0, -1)}${A[alt]}`]);
  }
  return out;
}

/** Flip one bit of the signature segment (byte index i). */
export function tamperSig(token: string, i = 0): string {
  const [h, p, s] = token.split('.') as [string, string, string];
  const b = Buffer.from(s, 'base64url');
  b[i % b.length] = (b[i % b.length] as number) ^ 1;
  return `${h}.${p}.${b.toString('base64url')}`;
}
