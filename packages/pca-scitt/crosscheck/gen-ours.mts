// Emits statements, receipts and consistency proofs made by @atlasauth/pca-scitt for
// crosscheck/cose_python.py (pycose, cbor2, pymerkle) to verify independently.
//   Ed25519: fixed keys (RFC 8032 test vectors 1 and 2), so the output is byte-reproducible.
//   ES256:   freshly generated P-256 keys (ECDSA is randomized); the committed fixture records the public JWKs.
import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TransparencyService } from '../dist/index.js';

const ed = (seedHex: string): KeyObject =>
  createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
const jwk = (k: KeyObject): Record<string, string> => createPublicKey(k).export({ format: 'jwk' }) as Record<string, string>;
const p256 = (): KeyObject => generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;

const variants = [
  { alg: 'EdDSA' as const, issuer: ed('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'), ts: ed('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb') },
  { alg: 'ES256' as const, issuer: p256(), ts: p256() },
];
const out = variants.map((v) => {
  const svc = new TransparencyService({ alg: v.alg, key: v.ts, issuer: 'https://ts.example' });
  const entries = [];
  const roots: string[] = [];
  for (let i = 0; i < 9; i++) {
    const r = svc.appendAndReceipt({ n: i, verdict: i % 2 ? 'allow' : 'deny' }, { alg: v.alg, key: v.issuer, issuer: 'https://rs.example', subject: `sub-${i}` });
    roots.push(svc.root);
    entries.push({ index: i, statement: Buffer.from(r.statement).toString('base64'), receipt_at_registration: Buffer.from(r.receipt).toString('base64'), root_at_registration: r.root });
  }
  const finalReceipts = entries.map((_, i) => Buffer.from(svc.getReceipt(i).receipt).toString('base64'));
  const cons = [1, 2, 3, 4, 5, 8].map((m) => {
    const c = svc.consistencyProof(m);
    return { old_size: c.oldSize, new_size: c.newSize, old_root: c.oldRoot, new_root: c.newRoot, proof: Buffer.from(c.proof).toString('base64') };
  });
  return { alg: v.alg, issuer_jwk: jwk(v.issuer), ts_jwk: jwk(v.ts), entries, final_receipts: finalReceipts, final_root: svc.root, roots_by_size: roots, consistency: cons };
});
writeFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'ours.json'), JSON.stringify({ generator: '@atlasauth/pca-scitt via crosscheck/gen-ours.mts', variants: out }, null, 1));
console.log('ok');
