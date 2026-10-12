// Browser stand-in for `node:crypto`: only `createHash(sha256|sha384).update(bytes|string).digest()`, which is all the
// verified-core's ext-merkle glue uses. Backed by @noble/hashes (pure JS, synchronous).
import { sha256 } from '../../../packages/pca/node_modules/@noble/hashes/sha256.js';
import { sha384 } from '../../../packages/pca/node_modules/@noble/hashes/sha512.js';
const ALGS = { sha256, sha384 };
export function createHash(alg) {
  const f = ALGS[alg];
  if (!f) throw new Error('createHash: unsupported algorithm ' + alg);
  const h = f.create();
  const o = {
    update(d) { h.update(typeof d === 'string' ? new TextEncoder().encode(d) : d); return o; },
    digest() { return h.digest(); },
  };
  return o;
}
