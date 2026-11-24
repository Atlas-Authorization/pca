// Live cross-check of @atlasauth/pca-webauthn against @simplewebauthn/server: builds assertions in the shapes real
// authenticators emit (platform passkey "none", "packed" hardware key with extension data, "fido-u2f", Ed25519, plus
// tampered variants) with fresh keys on every run, and requires BOTH verifiers to agree on every row.
// CI: pnpm --filter @atlasauth/pca-webauthn build
//     npm i --prefix "$RUNNER_TEMP/swa" @simplewebauthn/server@14.0.3
//     node crosscheck/live-crosscheck.mjs "$RUNNER_TEMP/swa/node_modules/@simplewebauthn/server"   (working dir: packages/pca-webauthn)
import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { pathToFileURL } from 'node:url';
import { verifyAssertion } from '../dist/index.js';

const swaDir = process.argv[2];
if (!swaDir) throw new Error('usage: live-crosscheck.mjs <path to @simplewebauthn/server>');
const swa = await import(pathToFileURL(`${swaDir}/esm/index.js`).href);
const b64u = (u) => Buffer.from(u).toString('base64url');
const enc = (o) => new TextEncoder().encode(typeof o === 'string' ? o : JSON.stringify(o));
const uint = (n) => (n < 24 ? [n] : [0x18, n]);
const nint = (n) => { const a = -1 - n; return a < 24 ? [0x20 | a] : [0x38, a]; };
const bstr = (b) => [0x58, b.length, ...b];
const RP = 'login.example.com';
const ORIGIN = 'https://login.example.com';
const CHALLENGE = crypto.getRandomValues(new Uint8Array(32));
const adata = (flags, count, tail = []) => {
  const o = new Uint8Array(37 + tail.length);
  o.set(sha256(enc(RP)), 0);
  o[32] = flags;
  new DataView(o.buffer).setUint32(33, count);
  o.set(tail, 37);
  return o;
};
const ext = Uint8Array.from([0xa1, 0x69, ...enc('credProps'), 0xa1, 0x62, ...enc('rk'), 0xf5]);

const esSk = p256.utils.randomPrivateKey();
const esPub = p256.getPublicKey(esSk, false);
const edSk = ed25519.utils.randomPrivateKey();
const edPub = ed25519.getPublicKey(edSk);
const KEYS = {
  ES256: { cose: Uint8Array.from([0xa5, ...uint(1), ...uint(2), ...uint(3), ...nint(-7), ...nint(-1), ...uint(1), ...nint(-2), ...bstr(esPub.slice(1, 33)), ...nint(-3), ...bstr(esPub.slice(33))]), sign: (m) => p256.sign(sha256(m), esSk).toDERRawBytes() },
  EdDSA: { cose: Uint8Array.from([0xa4, ...uint(1), ...uint(1), ...uint(3), ...nint(-8), ...nint(-1), ...uint(6), ...nint(-2), ...bstr(edPub)]), sign: (m) => ed25519.sign(m, edSk) },
};
// shape name -> authenticator data, whether UV is required for the check, and the stored counter
const SHAPES = {
  'platform passkey (none)': { ad: adata(0x1d, 0), uv: true, stored: 0 },
  'hardware key (packed, extensions)': { ad: adata(0x85, 42, ext), uv: true, stored: 41 },
  'u2f key, UV not required': { ad: adata(0x01, 7), uv: false, stored: 6 },
  'u2f key, UV required': { ad: adata(0x01, 7), uv: true, stored: 6 },
  'counter regression': { ad: adata(0x05, 3), uv: true, stored: 9 },
  'counter equal': { ad: adata(0x05, 9), uv: true, stored: 9 },
};
const rows = [];
for (const alg of ['ES256', 'EdDSA']) {
  for (const [shape, s] of Object.entries(SHAPES)) {
    for (const tamper of [false, true]) {
      const cd = enc({ type: 'webauthn.get', challenge: b64u(CHALLENGE), origin: ORIGIN, crossOrigin: false });
      let sig = KEYS[alg].sign(new Uint8Array([...s.ad, ...sha256(cd)]));
      if (tamper) { sig = sig.slice(); sig[sig.length >> 1] ^= 1; }
      rows.push({ name: `${alg} ${shape}${tamper ? ' (tampered signature)' : ''}`, alg, ...s, cd, sig });
    }
  }
}
let bad = 0;
for (const r of rows) {
  let theirs = false;
  try {
    const out = await swa.verifyAuthenticationResponse({
      response: { id: 'AAAA', rawId: 'AAAA', type: 'public-key', clientExtensionResults: {}, response: { authenticatorData: b64u(r.ad), clientDataJSON: b64u(r.cd), signature: b64u(r.sig) } },
      expectedChallenge: b64u(CHALLENGE), expectedOrigin: ORIGIN, expectedRPID: RP,
      credential: { id: 'AAAA', publicKey: KEYS[r.alg].cose, counter: r.stored }, requireUserVerification: r.uv,
    });
    theirs = out.verified === true;
  } catch { theirs = false; }
  const ours = verifyAssertion(
    { authenticatorData: r.ad, clientDataJSON: r.cd, signature: r.sig, publicKey: KEYS[r.alg].cose },
    { expectedChallenge: CHALLENGE, rpId: RP, origins: [ORIGIN], requireUV: r.uv, storedSignCount: r.stored },
  ).ok;
  const agree = ours === theirs;
  if (!agree) bad++;
  console.log(`${agree ? 'agree   ' : 'DISAGREE'} ours=${ours} library=${theirs}  ${r.name}`);
}
if (bad) { console.error(`${bad} disagreement(s)`); process.exit(1); }
console.log(`${rows.length} rows, 0 disagreements`);
