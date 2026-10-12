// Voters: independent implementations behind one line protocol. In-process: noble (the PRODUCTION libs, versions resolved from
// packages/pca), node:crypto (OpenSSL), and the real pca verify wrappers (keys.ts / pq.ts, needs tsx). Out-of-process (stdin/stdout
// batch): Rust (dalek, RustCrypto sha2/sha3/hmac, fips204, slh-dsa), Go stdlib, Python (hashlib, PyNaCl/libsodium, cryptography).
//
// Request = array [op, ...hexargs]; response = string. Booleans are "1"/"0"; unsupported = null (abstain); failure = "ERR ...".
//   H  algo msg            -> digest      (sha256|sha384|sha512|sha3-256|sha3-512|shake128:N|shake256:N)
//   M  algo key msg        -> hmac        (sha256|sha512)
//   EP sk32                -> pk          ES sk32 msg -> sig        EV pk msg sig -> 1/0
//   MK lvl seed32 -> "pk\tsk"   MS lvl seed32 msg rnd(''=zeros) -> sig (deterministic)   MSR lvl seed32 msg -> sig (hedged, any)   MV lvl pk msg sig -> 1/0
//   SK par seed(3n) -> "pk\tsk"  SS par sk msg optrand('') -> sig (deterministic)  SSR par sk msg -> sig  SV par pk msg sig -> 1/0
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';
import nodeCrypto from 'node:crypto';
import { hex, unhex } from './util.mjs';

const HERE = new URL('.', import.meta.url).pathname;
const PCA_PKG = HERE + '../../../../packages/pca/package.json';
const req = createRequire(PCA_PKG);
const imp = (s) => import(pathToFileURL(req.resolve(s)).href);
const verOf = (name) => { try { let d = path.dirname(req.resolve(name + '/' + (name.includes('curves') ? 'ed25519' : name.includes('hashes') ? 'sha256' : 'ml-dsa.js'))); for (let i = 0; i < 6; i++) { const f = path.join(d, 'package.json'); if (nodeFs.existsSync(f)) { const j = JSON.parse(nodeFs.readFileSync(f, 'utf8')); if (j.name === name) return j.version; } d = path.dirname(d); } } catch {} return '?'; };
import path from 'node:path';
import nodeFs from 'node:fs';

const isUnsup = (r) => r !== null && typeof r === 'string' && /^ERR (algo|op|variant|level|param)$/.test(r);

// ---- DER builders for node:crypto PQ keys (OpenSSL 3.5 formats) ----
const derLen = (n) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const tlv = (t, ...parts) => { const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([t]), derLen(body.length), body]); };
const algId = (last) => tlv(0x30, tlv(0x06, Buffer.from([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, last])));
const OID_ML = { 44: 17, 65: 18, 87: 19 };
const OID_SLH = { 'sha2-128f': 21, 'sha2-256s': 24 };
const spki = (last, raw) => tlv(0x30, algId(last), tlv(0x03, Buffer.from([0]), raw));
const pkcs8Seed = (last, seed) => tlv(0x30, tlv(0x02, Buffer.from([0])), algId(last), tlv(0x04, tlv(0x80, seed)));
const pkcs8Raw = (last, raw) => tlv(0x30, tlv(0x02, Buffer.from([0])), algId(last), tlv(0x04, raw));
const ED_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const ED_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');

class LRU { constructor(n = 512) { this.n = n; this.m = new Map(); } get(k) { const v = this.m.get(k); if (v !== undefined) { this.m.delete(k); this.m.set(k, v); } return v; } set(k, v) { this.m.set(k, v); if (this.m.size > this.n) this.m.delete(this.m.keys().next().value); } }

export async function loadNoble() {
  const [ed, sha2, sha512m, sha3m, hmacm, mld, slh] = await Promise.all([
    imp('@noble/curves/ed25519'), imp('@noble/hashes/sha256'), imp('@noble/hashes/sha512'), imp('@noble/hashes/sha3'), imp('@noble/hashes/hmac'),
    imp('@noble/post-quantum/ml-dsa.js'), imp('@noble/post-quantum/slh-dsa.js'),
  ]);
  return { ed25519: ed.ed25519, sha256: sha2.sha256, sha384: sha512m.sha384, sha512: sha512m.sha512, sha3_256: sha3m.sha3_256, sha3_512: sha3m.sha3_512, shake128: sha3m.shake128, shake256: sha3m.shake256, hmac: hmacm.hmac, ml_dsa44: mld.ml_dsa44, ml_dsa65: mld.ml_dsa65, ml_dsa87: mld.ml_dsa87, slh: { 'sha2-128f': slh.slh_dsa_sha2_128f, 'sha2-256s': slh.slh_dsa_sha2_256s },
    versions: { '@noble/curves': verOf('@noble/curves'), '@noble/hashes': verOf('@noble/hashes'), '@noble/post-quantum': verOf('@noble/post-quantum') } };
}

function inproc(name, fns, meta = {}) {
  return { name, kind: 'inproc', meta, async batch(reqs) { return reqs.map((r) => { try { const f = fns[r[0]]; if (!f) return null; const o = f(r); return o === undefined ? null : o; } catch (e) { return 'ERR ' + (e && e.message ? String(e.message).slice(0, 80) : 'throw'); } }); }, async close() {} };
}

/** noble voter. `edVariant`: 'strict' = zip215:false (the option pca passes), 'zip215' = noble default. */
export function nobleVoter(N, edVariant = 'strict') {
  const z = edVariant === 'zip215';
  const hashes = { sha256: N.sha256, sha384: N.sha384, sha512: N.sha512, 'sha3-256': N.sha3_256, 'sha3-512': N.sha3_512 };
  const ML = { 44: N.ml_dsa44, 65: N.ml_dsa65, 87: N.ml_dsa87 };
  const fns = {
    H: ([, a, m]) => { if (hashes[a]) return hex(hashes[a](unhex(m))); const mm = /^shake(128|256):(\d+)$/.exec(a); if (mm) return hex((mm[1] === '128' ? N.shake128 : N.shake256)(unhex(m), { dkLen: +mm[2] })); return null; },
    M: ([, a, k, m]) => (a === 'sha256' ? hex(N.hmac(N.sha256, unhex(k), unhex(m))) : a === 'sha512' ? hex(N.hmac(N.sha512, unhex(k), unhex(m))) : null),
    EP: ([, sk]) => hex(N.ed25519.getPublicKey(unhex(sk))),
    ES: ([, sk, m]) => hex(N.ed25519.sign(unhex(m), unhex(sk))),
    EV: ([, pk, m, sg]) => { try { return N.ed25519.verify(unhex(sg), unhex(m), unhex(pk), { zip215: z }) ? '1' : '0'; } catch { return '0'; } },
    MK: ([, l, seed]) => { const k = ML[l].keygen(unhex(seed)); return hex(k.publicKey) + '\t' + hex(k.secretKey); },
    MS: ([, l, seed, m, rnd]) => { const k = ML[l].keygen(unhex(seed)); return hex(ML[l].sign(k.secretKey, unhex(m), undefined, rnd ? unhex(rnd) : undefined)); },
    MV: ([, l, pk, m, sg, ctx]) => { try { return ML[l].verify(unhex(pk), unhex(m), unhex(sg), ctx ? unhex(ctx) : undefined) ? '1' : '0'; } catch { return '0'; } },
    SK: ([, p, seed]) => { const k = N.slh[p].keygen(unhex(seed)); return hex(k.publicKey) + '\t' + hex(k.secretKey); },
    SS: ([, p, sk, m, opt]) => hex(N.slh[p].sign(unhex(sk), unhex(m), undefined, opt ? unhex(opt) : undefined)),
    SV: ([, p, pk, m, sg, ctx]) => { try { return N.slh[p].verify(unhex(pk), unhex(m), unhex(sg), ctx ? unhex(ctx) : undefined) ? '1' : '0'; } catch { return '0'; } },
  };
  if (!z) fns.EV = ((orig) => orig)(fns.EV);
  return inproc(z ? 'noble-zip215' : 'noble-strict', fns, { versions: N.versions });
}

export function nodeCryptoVoter() {
  const c = nodeCrypto;
  const pubCache = new LRU(), mlPub = new LRU(64), slhPub = new LRU(64);
  const edPub = (pk) => { let k = pubCache.get(pk); if (!k) { k = c.createPublicKey({ key: Buffer.concat([ED_SPKI, Buffer.from(pk, 'hex')]), format: 'der', type: 'spki' }); pubCache.set(pk, k); } return k; };
  const nodeHash = { sha256: 'sha256', sha384: 'sha384', sha512: 'sha512', 'sha3-256': 'sha3-256', 'sha3-512': 'sha3-512' };
  const mlName = { 44: 'ml-dsa-44', 65: 'ml-dsa-65', 87: 'ml-dsa-87' };
  const fns = {
    H: ([, a, m]) => { if (nodeHash[a]) return c.createHash(nodeHash[a]).update(Buffer.from(m, 'hex')).digest('hex'); const mm = /^shake(128|256):(\d+)$/.exec(a); if (mm) return c.createHash('shake' + mm[1], { outputLength: +mm[2] }).update(Buffer.from(m, 'hex')).digest('hex'); return null; },
    M: ([, a, k, m]) => (a === 'sha256' || a === 'sha512' ? c.createHmac(a, Buffer.from(k, 'hex')).update(Buffer.from(m, 'hex')).digest('hex') : null),
    EP: ([, sk]) => { const pub = c.createPublicKey(c.createPrivateKey({ key: Buffer.concat([ED_PKCS8, Buffer.from(sk, 'hex')]), format: 'der', type: 'pkcs8' })); return pub.export({ format: 'der', type: 'spki' }).subarray(12).toString('hex'); },
    ES: ([, sk, m]) => c.sign(null, Buffer.from(m, 'hex'), c.createPrivateKey({ key: Buffer.concat([ED_PKCS8, Buffer.from(sk, 'hex')]), format: 'der', type: 'pkcs8' })).toString('hex'),
    EV: ([, pk, m, sg]) => { if (pk.length !== 64 || sg.length !== 128) return '0'; try { return c.verify(null, Buffer.from(m, 'hex'), edPub(pk), Buffer.from(sg, 'hex')) ? '1' : '0'; } catch { return '0'; } },
    MK: ([, l, seed]) => { const pub = c.createPublicKey(c.createPrivateKey({ key: pkcs8Seed(OID_ML[l], Buffer.from(seed, 'hex')), format: 'der', type: 'pkcs8' })); const raw = pub.export({ format: 'der', type: 'spki' }); return hex(raw.subarray(raw.length - { 44: 1312, 65: 1952, 87: 2592 }[l])) + '\tN/A'; },
    MSR: ([, l, seed, m]) => c.sign(null, Buffer.from(m, 'hex'), c.createPrivateKey({ key: pkcs8Seed(OID_ML[l], Buffer.from(seed, 'hex')), format: 'der', type: 'pkcs8' })).toString('hex'),
    MV: ([, l, pk, m, sg, ctx]) => { try { let k = mlPub.get(l + pk); if (!k) { k = c.createPublicKey({ key: spki(OID_ML[l], Buffer.from(pk, 'hex')), format: 'der', type: 'spki' }); mlPub.set(l + pk, k); } return c.verify(null, Buffer.from(m, 'hex'), ctx ? { key: k, context: Buffer.from(ctx, 'hex') } : k, Buffer.from(sg, 'hex')) ? '1' : '0'; } catch { return '0'; } },
    SSR: ([, p, sk, m]) => c.sign(null, Buffer.from(m, 'hex'), c.createPrivateKey({ key: pkcs8Raw(OID_SLH[p], Buffer.from(sk, 'hex')), format: 'der', type: 'pkcs8' })).toString('hex'),
    SV: ([, p, pk, m, sg, ctx]) => { try { let k = slhPub.get(p + pk); if (!k) { k = c.createPublicKey({ key: spki(OID_SLH[p], Buffer.from(pk, 'hex')), format: 'der', type: 'spki' }); slhPub.set(p + pk, k); } return c.verify(null, Buffer.from(m, 'hex'), ctx ? { key: k, context: Buffer.from(ctx, 'hex') } : k, Buffer.from(sg, 'hex')) ? '1' : '0'; } catch { return '0'; } },
  };
  return inproc('node-openssl', fns, { versions: { node: process.version, openssl: process.versions.openssl } });
}

/** The REAL production wrappers (packages/pca/src/keys.ts, pq.ts). Needs `node --import tsx`; returns null when .ts cannot be imported. */
export async function pcaVoter() {
  let keys, pq;
  try { keys = await import(pathToFileURL(HERE + '../../../../packages/pca/src/keys.ts').href); pq = await import(pathToFileURL(HERE + '../../../../packages/pca/src/pq.ts').href); } catch (e) { return null; }
  const fns = {
    EV: ([, pk, m, sg]) => (keys.verify(unhex(pk), unhex(m), unhex(sg)) ? '1' : '0'),
    EP: ([, sk]) => hex(keys.publicKeyOf(unhex(sk))), ES: ([, sk, m]) => hex(keys.sign(unhex(sk), unhex(m))),
    MV: ([, l, pk, m, sg, ctx]) => ctx ? null : (l === '65' ? pq.mlDsa65Verify : l === '87' ? pq.mlDsa87Verify : null)?.(unhex(pk), unhex(m), unhex(sg)) ? '1' : l === '65' || l === '87' ? '0' : null,
    SV: ([, p, pk, m, sg, ctx]) => (ctx ? null : (p === "sha2-128f" ? pq.slhDsa128fVerify : pq.slhDsa256sVerify)(unhex(pk), unhex(m), unhex(sg)) ? "1" : "0"),
    MK: ([, l, seed]) => { if (l !== '65' && l !== '87') return null; const k = (l === '65' ? pq.mlDsa65Keygen : pq.mlDsa87Keygen)(unhex(seed)); return hex(k.publicKey) + '\t' + hex(k.secretKey); },
    MS: ([, l, seed, m, rnd]) => { if (rnd || (l !== '65' && l !== '87')) return null; const k = (l === '65' ? pq.mlDsa65Keygen : pq.mlDsa87Keygen)(unhex(seed)); return hex((l === '65' ? pq.mlDsa65Sign : pq.mlDsa87Sign)(k.secretKey, unhex(m))); },
  };
  return inproc('pca-prod', fns, {});
}

/** External batch voter over a child process. `ev` (optional) is the variant token injected into EV requests. */
export function extVoter(name, cmd, args = [], { ev = null, env = {} } = {}) {
  let child = null, buf = '', waiters = [], dead = null, chain = Promise.resolve();
  const start = () => {
    child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'inherit'], env: { ...process.env, ...env } });
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (d) => { buf += d; pump(); });
    child.on('exit', (c) => { dead = 'exit ' + c; pump(true); });
    child.on('error', (e) => { dead = String(e); pump(true); });
  };
  const pump = (final) => { while (waiters.length) { const w = waiters[0]; const lines = []; let i = 0, ok = true; while (lines.length < w.n) { const j = buf.indexOf('\n', i); if (j < 0) { ok = false; break; } lines.push(buf.slice(i, j)); i = j + 1; } if (ok) { buf = buf.slice(i); waiters.shift(); w.res(lines); } else { if (final) { waiters.shift(); w.rej(new Error(name + ' died: ' + dead)); continue; } break; } } };
  const send = (lines) => new Promise((res, rej) => {
    if (!child) start();
    waiters.push({ n: lines.length, res, rej });
    const data = lines.join('\n') + '\n';
    if (!child.stdin.write(data)) { /* backpressure handled by awaiting reply */ }
  });
  return {
    name, kind: 'ext',
    batch(reqs) {
      const job = chain.then(async () => {
        const out = []; const CH = 400;
        for (let i = 0; i < reqs.length; i += CH) {
          const part = reqs.slice(i, i + CH).map((r) => (ev && r[0] === 'EV' ? ['EV', ev, ...r.slice(1)] : r).join('\t'));
          part.push('FLUSH');
          const lines = await send(part);
          for (let k = 0; k < lines.length - 1; k++) out.push(isUnsup(lines[k]) ? null : lines[k]);
        }
        return out;
      });
      chain = job.catch(() => {});
      return job;
    },
    async close() { if (child) { child.stdin.end(); child.kill(); } },
  };
}

/** Build the voter set from available resources. env PRIM_RUST / PRIM_SLH / PRIM_GO / PRIM_PY point at the built helpers. */
export async function buildVoters({ withPca = true } = {}) {
  const N = await loadNoble();
  const v = { N, list: [nobleVoter(N, 'strict'), nobleVoter(N, 'zip215'), nodeCryptoVoter()] };
  if (withPca) { const p = await pcaVoter(); if (p) v.list.push(p); }
  const E = process.env;
  if (E.PRIM_RUST) { v.list.push(extVoter('rust-dalek', E.PRIM_RUST, [], { ev: 'dalek' })); v.list.push(extVoter('rust-dalek-strict', E.PRIM_RUST, [], { ev: 'dalek-strict' })); }
  if (E.PRIM_SLH) v.list.push(extVoter('rust-slh', E.PRIM_SLH));
  if (E.PRIM_GO) v.list.push(extVoter('go-stdlib', E.PRIM_GO, [], { ev: 'go' }));
  if (E.PRIM_PY) { v.list.push(extVoter('py-libsodium', E.PRIM_PY, [HERE + '../voter.py', 'nacl'], { ev: 'nacl' })); v.list.push(extVoter('py-cryptography', E.PRIM_PY, [HERE + '../voter.py', 'cryptography'], { ev: 'cryptography' })); }
  v.byName = Object.fromEntries(v.list.map((x) => [x.name, x]));
  v.close = async () => { for (const x of v.list) await x.close(); };
  return v;
}

/** Run one request list on every voter; returns {name: results[]}. */
export async function runAll(voters, reqs) {
  const res = await Promise.all(voters.map((x) => x.batch(reqs)));
  return Object.fromEntries(voters.map((x, i) => [x.name, res[i]]));
}
