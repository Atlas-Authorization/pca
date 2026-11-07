#!/usr/bin/env node
// Regenerates testdata/kem-kat/hybrid-kat.json with an implementation independent of src/kem.ts: ML-KEM, X25519 and HKDF all come
// from OpenSSL through node:crypto (Node >= 24.7), the combiner is re-written here from the documented construction.
// The ML-KEM ciphertext is fresh per run (OpenSSL encapsulation is randomised): the committed file is a frozen sample.
// Usage: node scripts/gen-kem-kat.mjs > testdata/kem-kat/hybrid-kat.json
import crypto from 'node:crypto';

const PKCS8_X25519 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const xPriv = (sk) => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_X25519, sk]), format: 'der', type: 'pkcs8' });
const xPub = (sk) => crypto.createPublicKey(xPriv(sk)).export({ format: 'der', type: 'spki' }).subarray(-32);
const xDh = (sk, pub) =>
  crypto.diffieHellman({ privateKey: xPriv(sk), publicKey: crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), pub]), format: 'der', type: 'spki' }) });
const h = (s, n) => crypto.createHash('sha512').update(s).digest().subarray(0, n);

const out = {
  about: 'Known-answer vectors for the X25519 + ML-KEM hybrid KEMs of src/kem.ts. Every field was produced by OpenSSL via node:crypto (ML-KEM encapsulation, X25519, HKDF-SHA256), not by src/kem.ts.',
  generator: 'scripts/gen-kem-kat.mjs',
  vectors: [],
};
for (const [alg, label] of [['ml-kem-768', 'x25519-ml-kem-768'], ['ml-kem-1024', 'x25519-ml-kem-1024']]) {
  const mlSeed = h(`pca-kem-kat/${alg}/seed`, 64);
  const xsk = h(`pca-kem-kat/${alg}/x`, 32);
  const esk = h(`pca-kem-kat/${alg}/eph`, 32);
  const mlPriv = crypto.createPrivateKey({ key: mlSeed, format: 'raw-seed', asymmetricKeyType: alg }); // JWK-free raw seed import
  const mlPub = crypto.createPublicKey(mlPriv);
  const { ciphertext: mlCt, sharedKey: ssMl } = crypto.encapsulate(mlPub);
  const ephPub = xPub(esk);
  const recipX = xPub(xsk);
  const ssX = xDh(esk, recipX);
  const ikm = Buffer.concat([ssMl, ssX, ephPub, recipX]);
  const ss = Buffer.from(crypto.hkdfSync('sha256', ikm, Buffer.alloc(0), Buffer.from(`atlas-pca/kem/${label}/v1\0`), 32));
  out.vectors.push({
    suite: label,
    mlkem_seed: mlSeed.toString('hex'),
    x25519_sk: xsk.toString('hex'),
    ciphertext: Buffer.concat([ephPub, mlCt]).toString('hex'),
    shared_secret: ss.toString('hex'),
    ml_kem_public_key: Buffer.from(mlPub.export({ format: 'jwk' }).pub, 'base64url').toString('hex'),
  });
}
console.log(JSON.stringify(out, null, 2));
