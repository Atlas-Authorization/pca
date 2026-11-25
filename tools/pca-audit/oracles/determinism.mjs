// Preloaded into every corpus generator (node --import, set by scripts/pca-ci-workflows/pca/scripts/oracle-corpora.mjs): two runs of one
// generator at one commit must write the same bytes. The reference draws fresh randomness (keys, salts, nonces, ids, ECDSA / PSS signing
// randomness) and reads the clock; here every one of those comes from a stream seeded by the generator's file name, and the clock starts at a fixed epoch and counts reads.
// Generators that already pin a source themselves (crypto.randomBytes replaced, a fixed NOW) simply override this.
//   - Math.random, crypto.randomBytes / randomFill(Sync) / randomInt / randomUUID / getRandomValues (node:crypto and the web crypto global)
//   - generateKeyPair(Sync) for ed25519, x25519, ec (P-256 / P-384 / P-521) and rsa
//   - crypto.sign: ECDSA by RFC 6979, RSA-PSS with a salt drawn from the stream (Ed25519 and PKCS#1 v1.5 are deterministic already)
//   - Date.now() and new Date() read PCA_ORACLE_NOW (default 1700000000000), frozen; a fired setTimeout / setInterval moves it to the time that timer was due
import crypto, { createHash, createPrivateKey, createPublicKey, KeyObject, constants } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { basename } from 'node:path';
import { promisify } from 'node:util';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { p384 } from '@noble/curves/p384';
import { p521 } from '@noble/curves/p521';

// node:crypto exports may be accessors (getRandomValues is a getter-only property): replace through defineProperty
const put = (o, k, v) => { try { Object.defineProperty(o, k, { value: v, configurable: true, writable: true, enumerable: true }); } catch { try { o[k] = v; } catch { /* a getter-only, non-configurable export stays as it is */ } } };
const patched = {};
const label = 'atlas-pca-oracle-rng/' + basename(process.argv[1] || 'node');
let ctr = 0, pool = Buffer.alloc(0);
const draw = (n) => {
  while (pool.length < n) pool = Buffer.concat([pool, createHash('sha256').update(label + '/' + ctr++).digest()]);
  const out = pool.subarray(0, n); pool = pool.subarray(n); return Buffer.from(out);
};
const b64u = (b) => Buffer.from(b).toString('base64url');
const big = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));
const unbig = (v, len) => Buffer.from(v.toString(16).padStart(len * 2, '0'), 'hex');

// ---- clock: frozen at NOW (see nowFn)
// (not 1800000000000: that is the epoch the generators put in their own timestamps, and a literal equal to the clock reads as "now")
const NOW = process.env.PCA_ORACLE_NOW ? Number(process.env.PCA_ORACLE_NOW) : 1700000000000;
const RealDate = Date;
let tick = 0;
// a generator may pin the clock itself (Date.now = () => T0): the assignment replaces the counting clock
// The clock is FROZEN at NOW (clockMs): every read returns exactly NOW, so a result that carries the clock (an age) is exactly reproducible by a replay that
// sets its clock to clockMs. A poll loop on the clock must still end, so after the first 100000 reads it advances one millisecond per 1000 reads (a count,
// never real time: the output stays deterministic).
const FREE_READS = 100_000;
// A wait on a real timer (a collect or lock timeout: setTimeout, then Date.now() against a deadline) never ends on a frozen clock, so a fired timer
// moves the clock to the time it was due (virtual time, as fake timers do): still deterministic, and a result read without waiting stays exactly NOW.
let virt = 0;
const creep = () => (tick < FREE_READS ? (tick++, 0) : Math.floor((tick++ - FREE_READS) / 1000) + 1);
let nowFn = () => NOW + virt + creep();
for (const name of ['setTimeout', 'setInterval']) {
  const real = globalThis[name];
  const wrapped = function (fn, ms, ...args) {
    if (typeof fn !== 'function') return real(fn, ms, ...args);
    const d = Math.max(0, Number(ms) || 0);
    let due = virt + d;
    return real(function (...a) { if (due > virt) virt = due; due = virt + d; return fn.apply(this, a); }, ms, ...args);
  };
  if (real[promisify.custom]) wrapped[promisify.custom] = real[promisify.custom];
  globalThis[name] = wrapped;
}
// the frozen clock the generator runs under, written into every corpus header as "clockMs" (the replays read it, never a constant)
let clockMs = NOW, pinned = false;
Object.defineProperty(globalThis, '__pcaOracleClockMs', { get: () => clockMs, configurable: true });
globalThis.Date = new Proxy(RealDate, {
  construct: (t, a, nt) => Reflect.construct(t, a.length ? a : [nowFn()], nt),
  apply: () => new RealDate(nowFn()).toString(),
  get: (t, k, r) => (k === 'now' ? nowFn : Reflect.get(t, k, r)),
  set: (t, k, v, r) => (k === 'now' && typeof v === 'function' ? ((nowFn = v), (pinned || ((clockMs = Number(v())), (pinned = true))), true) : Reflect.set(t, k, v, r)),
});

// ---- random bytes
Math.random = () => Number(big(draw(6))) / 2 ** 48;
const fill = (a) => { const v = new Uint8Array(a.buffer, a.byteOffset, a.byteLength); v.set(draw(v.length)); return a; };
patched.randomBytes = (n, cb) => { const b = draw(n); if (cb) { queueMicrotask(() => cb(null, b)); return undefined; } return b; };
patched.randomFillSync = (a, off = 0, size) => { const v = new Uint8Array(a.buffer ?? a, (a.byteOffset ?? 0) + off, size ?? (a.byteLength ?? a.length) - off); v.set(draw(v.length)); return a; };
patched.randomFill = (a, ...r) => { const cb = r.pop(); patched.randomFillSync(a, ...r); queueMicrotask(() => cb(null, a)); };
patched.randomInt = (...a) => {
  const cb = typeof a[a.length - 1] === 'function' ? a.pop() : null;
  const [min, max] = a.length === 1 ? [0, a[0]] : a;
  const v = min + Number(big(draw(8)) % BigInt(max - min));
  if (cb) { queueMicrotask(() => cb(null, v)); return undefined; } return v;
};
patched.randomUUID = () => { const b = draw(16); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; const h = b.toString('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; };
const grv = (a) => fill(a);
for (const o of [globalThis.crypto, crypto.webcrypto]) { try { Object.defineProperty(o, 'getRandomValues', { value: grv, configurable: true, writable: true }); } catch {} }
// node:crypto's own getRandomValues export is a non-configurable getter (Node 24): the web crypto object above is what generators and noble use

// ---- key generation
const CURVES = { 'P-256': [p256, 32], prime256v1: [p256, 32], secp256r1: [p256, 32], 'P-384': [p384, 48], secp384r1: [p384, 48], 'P-521': [p521, 66], secp521r1: [p521, 66] };
const CRV = { 32: 'P-256', 48: 'P-384', 66: 'P-521' };
const mod = (a, m) => ((a % m) + m) % m;
const pow = (b, e, m) => { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
const egcd = (a, b) => { let [r0, r1, s0, s1] = [a, b, 1n, 0n]; while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; } return [r0, s0]; };
const inv = (a, m) => mod(egcd(mod(a, m), m)[1], m);
const SMALL = []; for (let n = 2n; n < 2000n; n++) if (SMALL.every((s) => n % s)) SMALL.push(n);
const probablePrime = (p) => {
  for (const s of SMALL) if (p % s === 0n) return p === s;
  let d = p - 1n, r = 0; while (!(d & 1n)) { d >>= 1n; r++; }
  for (let i = 0; i < 24; i++) {
    const a = 2n + (big(draw(32)) % (p - 3n));
    let x = pow(a, d, p);
    if (x === 1n || x === p - 1n) continue;
    let ok = false;
    for (let j = 1; j < r && !ok; j++) { x = (x * x) % p; if (x === p - 1n) ok = true; }
    if (!ok) return false;
  }
  return true;
};
const prime = (bits, e) => {
  for (;;) {
    const c = (big(draw(Math.ceil(bits / 8))) & ((1n << BigInt(bits)) - 1n)) | (3n << BigInt(bits - 2)) | 1n; // top two bits set: p * q has the full modulus length
    if (egcd(e, c - 1n)[0] === 1n && probablePrime(c)) return c;
  }
};
const rsaJwk = (bits, e) => {
  for (;;) {
    const a = prime(bits >> 1, e), b = prime(bits - (bits >> 1), e);
    if (a === b) continue;
    const n = a * b; if (n.toString(2).length !== bits) continue;
    const [p, q] = a > b ? [a, b] : [b, a], d = inv(e, (p - 1n) * (q - 1n)), L = (v) => Math.ceil(v.toString(2).length / 8), h = (v, l = L(v)) => b64u(unbig(v, l));
    return { kty: 'RSA', n: h(n), e: h(e), d: h(d, L(n)), p: h(p), q: h(q), dp: h(d % (p - 1n), L(p)), dq: h(d % (q - 1n), L(p)), qi: h(inv(q, p), L(p)) };
  }
};
const genSync = crypto.generateKeyPairSync, genAsync = crypto.generateKeyPair;
const mkPair = (type, o) => {
  let jwk;
  if (type === 'ed25519') { const d = draw(32); jwk = { kty: 'OKP', crv: 'Ed25519', d: b64u(d), x: b64u(ed25519.getPublicKey(d)) }; }
  else if (type === 'x25519') { const d = draw(32); jwk = { kty: 'OKP', crv: 'X25519', d: b64u(d), x: b64u(x25519.getPublicKey(d)) }; }
  else if (type === 'ec' && CURVES[o?.namedCurve]) {
    const [c, len] = CURVES[o.namedCurve], d = unbig(1n + (big(draw(len + 8)) % (c.CURVE.n - 1n)), len), pub = c.getPublicKey(d, false);
    jwk = { kty: 'EC', crv: CRV[len], d: b64u(d), x: b64u(pub.subarray(1, 1 + len)), y: b64u(pub.subarray(1 + len)) };
  } else if (type === 'rsa' && o?.modulusLength) jwk = rsaJwk(o.modulusLength, BigInt(o.publicExponent ?? 65537));
  else return null;
  const privateKey = createPrivateKey({ key: jwk, format: 'jwk' }), publicKey = createPublicKey(privateKey);
  return { publicKey: o?.publicKeyEncoding ? publicKey.export(o.publicKeyEncoding) : publicKey, privateKey: o?.privateKeyEncoding ? privateKey.export(o.privateKeyEncoding) : privateKey };
};
patched.generateKeyPairSync = (type, o) => { const r = mkPair(type, o); return r ?? genSync(type, o); };
patched.generateKeyPair = (type, o, cb) => { const r = mkPair(type, o); if (!r) return genAsync(type, o, cb); queueMicrotask(() => cb(null, r.publicKey, r.privateKey)); };
patched.generateKeyPair[promisify.custom] = (type, o) => new Promise((res, rej) => patched.generateKeyPair(type, o, (e, publicKey, privateKey) => (e ? rej(e) : res({ publicKey, privateKey }))));

// ---- signing
const realSign = crypto.sign;
const mgf1 = (seed, len, hash) => { let out = Buffer.alloc(0); for (let i = 0; out.length < len; i++) out = Buffer.concat([out, createHash(hash).update(seed).update(Buffer.from([i >>> 24, (i >>> 16) & 255, (i >>> 8) & 255, i & 255])).digest()]); return out.subarray(0, len); };
const pssSign = (hash, data, key, saltLength) => {
  const hLen = createHash(hash).digest().length, nb = Buffer.from(key.export({ format: 'jwk' }).n, 'base64url'), modBits = nb.length * 8 - (Math.clz32(nb[0]) - 24);
  const k = Math.ceil(modBits / 8), emBits = modBits - 1, emLen = Math.ceil(emBits / 8);
  const sLen = saltLength === constants.RSA_PSS_SALTLEN_DIGEST ? hLen : saltLength === undefined || saltLength === constants.RSA_PSS_SALTLEN_MAX_SIGN ? emLen - hLen - 2 : saltLength;
  const salt = draw(sLen), mHash = createHash(hash).update(data).digest();
  const H = createHash(hash).update(Buffer.concat([Buffer.alloc(8), mHash, salt])).digest();
  const DB = Buffer.concat([Buffer.alloc(emLen - sLen - hLen - 2), Buffer.from([1]), salt]), mask = mgf1(H, emLen - hLen - 1, hash);
  const maskedDB = Buffer.from(DB.map((b, i) => b ^ mask[i])); maskedDB[0] &= 0xff >> (8 * emLen - emBits);
  const EM = Buffer.concat([maskedDB, H, Buffer.from([0xbc])]);
  return crypto.privateEncrypt({ key, padding: constants.RSA_NO_PADDING }, Buffer.concat([Buffer.alloc(k - emLen), EM]));
};
patched.sign = function (alg, data, key, cb) {
  try {
    const o = key && typeof key === 'object' && !(key instanceof KeyObject) && !Buffer.isBuffer(key) && 'key' in key ? key : { key };
    const ko = o.key instanceof KeyObject ? o.key : createPrivateKey(o.key);
    if (alg && ko.type === 'private') {
      const hash = String(alg).toLowerCase().replace(/^rsa-/, '').replace(/^sha-?/, 'sha');
      const buf = Buffer.isBuffer(data) ? data : ArrayBuffer.isView(data) ? Buffer.from(data.buffer, data.byteOffset, data.byteLength) : Buffer.from(data);
      let out = null;
      if (ko.asymmetricKeyType === 'ec' && CURVES[ko.export({ format: 'jwk' }).crv]) {
        const jwk = ko.export({ format: 'jwk' }), [c] = CURVES[jwk.crv];
        const sig = c.sign(createHash(hash).update(buf).digest(), Buffer.from(jwk.d, 'base64url'), { lowS: false });
        out = Buffer.from(o.dsaEncoding === 'ieee-p1363' ? sig.toCompactRawBytes() : sig.toDERRawBytes());
      } else if (ko.asymmetricKeyType === 'rsa' && o.padding === constants.RSA_PKCS1_PSS_PADDING) out = pssSign(hash, buf, ko, o.saltLength);
      if (out) { if (cb) { queueMicrotask(() => cb(null, out)); return undefined; } return out; }
    }
  } catch { /* fall through: the original decides (and reports the same refusal) */ }
  return realSign.call(this, alg, data, key, cb);
};
for (const [k, v] of Object.entries(patched)) put(crypto, k, v);
syncBuiltinESMExports();
