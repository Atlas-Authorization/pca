// Run the FULL official-KAT reproduction + round trip against an INSTALLED copy of the package.
// Usage (from the install dir):  node kat-installed.mjs <path/to/less-252-45.digest.json>
// Imports the package by name, i.e. exactly what a consumer gets from the tarball.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
const less = await import('@atlasauth/pca-less-wasm');
const digest = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const sha = (b) => createHash('sha256').update(b).digest('hex');
let ok = 0;
const t = Date.now();
for (const e of digest.entries) {
  less.seedWith(Buffer.from(e.seed, 'hex'));
  const { publicKey, secretKey } = less.keygen();
  const msg = Buffer.from(e.msg, 'hex');
  const sm = less.sign(secretKey, msg);
  const r = less.open(publicKey, sm);
  if (sha(publicKey) === e.pkSha256 && Buffer.from(secretKey).toString('hex') === e.sk && sm.length === e.smlen &&
      sha(sm) === e.smSha256 && r.ok && Buffer.from(r.message).equals(msg)) ok++;
  else console.log('MISMATCH', e.count);
}
// random round trip + negatives
less.seedFromEntropy();
const k = less.keygen();
const m = new TextEncoder().encode('installed tarball');
const sig = less.signDetached(k.secretKey, m);
const good = less.verify(k.publicKey, m, sig);
const bad = sig.slice(); bad[10] ^= 1;
const rej = !less.verify(k.publicKey, m, bad) && !less.verify(k.publicKey, new Uint8Array(1), sig) && !less.verify(k.publicKey, m, new Uint8Array(0));
console.log(`KAT ${ok}/${digest.entries.length} byte-identical via installed package; roundtrip=${good} tamper/wrong-msg/empty rejected=${rej}; ${Date.now() - t} ms; node ${process.version}`);
process.exit(ok === digest.entries.length && good && rej ? 0 : 1);
