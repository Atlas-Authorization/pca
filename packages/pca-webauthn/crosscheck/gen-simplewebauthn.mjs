// Regenerates fixtures/simplewebauthn.json: assertions built here (noble) and judged by an established library
// (@simplewebauthn/server). Usage: node crosscheck/gen-simplewebauthn.mjs /path/to/dir/with/node_modules/@simplewebauthn/server
import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const swaDir = process.argv[2];
const swa = await import(pathToFileURL(`${swaDir}/esm/index.js`).href);
const swaVersion = JSON.parse(readFileSync(`${swaDir}/package.json`, 'utf8')).version;
const b64u = (u) => Buffer.from(u).toString('base64url');
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));

const uint = (n) => (n < 24 ? [n] : [0x18, n]);
const nint = (n) => { const a = -1 - n; return a < 24 ? [0x20 | a] : [0x38, a]; };
const bstr = (b) => [0x58, b.length, ...b];
const coseEc2 = (x, y) => Uint8Array.from([0xa5, ...uint(1), ...uint(2), ...uint(3), ...nint(-7), ...nint(-1), ...uint(1), ...nint(-2), ...bstr(x), ...nint(-3), ...bstr(y)]);
const coseOkp = (x) => Uint8Array.from([0xa4, ...uint(1), ...uint(1), ...uint(3), ...nint(-8), ...nint(-1), ...uint(6), ...nint(-2), ...bstr(x)]);

const RP = 'login.example.com';
const ORIGIN = 'https://login.example.com';
const CHALLENGE = Uint8Array.from({ length: 32 }, (_, i) => i * 7 + 1);
const authData = (flags, count, rp = RP) => {
  const o = new Uint8Array(37);
  o.set(sha256(new TextEncoder().encode(rp)), 0);
  o[32] = flags;
  new DataView(o.buffer).setUint32(33, count);
  return o;
};

const esSk = p256.utils.randomPrivateKey();
const esPub = p256.getPublicKey(esSk, false);
const edSk = ed25519.utils.randomPrivateKey();
const edPub = ed25519.getPublicKey(edSk);
const KEYS = {
  ES256: { cose: coseEc2(esPub.slice(1, 33), esPub.slice(33)), sign: (m) => p256.sign(sha256(m), esSk).toDERRawBytes() },
  EdDSA: { cose: coseOkp(edPub), sign: (m) => ed25519.sign(m, edSk) },
};

const cases = [];
for (const alg of ['ES256', 'EdDSA']) {
  const add = (name, o = {}) => {
    const ad = o.authData ?? authData(o.flags ?? 0x05, o.count ?? 5, o.rp);
    const cd = enc({ type: 'webauthn.get', challenge: b64u(CHALLENGE), origin: ORIGIN, crossOrigin: false, ...o.client });
    let sig = KEYS[alg].sign(new Uint8Array([...ad, ...sha256(cd)]));
    if (o.flipSig) { sig = sig.slice(); sig[sig.length - 1] ^= 1; }
    cases.push({
      name: `${alg}: ${name}`, alg,
      authenticatorData: b64u(ad), clientDataJSON: b64u(cd), signature: b64u(sig), cose: b64u(KEYS[alg].cose),
      expectedChallenge: b64u(o.expectedChallenge ?? CHALLENGE), origin: o.expectOrigin ?? ORIGIN, rpId: RP,
      requireUV: o.requireUV ?? true, storedSignCount: o.stored ?? 4,
    });
  };
  add('valid');
  add('valid, counter 0 vs stored 0', { count: 0, stored: 0 });
  add('wrong challenge', { expectedChallenge: new Uint8Array(32).fill(1) });
  add('wrong origin', { client: { origin: 'https://evil.example' } });
  add('wrong rpId', { rp: 'evil.example' });
  add('UV flag missing, UV required', { flags: 0x01 });
  add('UV flag missing, UV not required', { flags: 0x01, requireUV: false });
  add('UP flag missing', { flags: 0x04, requireUV: false });
  add('wrong ceremony type', { client: { type: 'webauthn.create' } });
  add('flipped signature bit', { flipSig: true });
  add('counter equal to stored', { count: 4 });
  add('counter lower than stored', { count: 2 });
  add('counter 0 with stored non-zero', { count: 0 });
}

const out = [];
for (const c of cases) {
  const cdBytes = Buffer.from(c.clientDataJSON, 'base64url');
  let verified = false;
  try {
    const r = await swa.verifyAuthenticationResponse({
      response: { id: 'AAAA', rawId: 'AAAA', type: 'public-key', clientExtensionResults: {},
        response: { authenticatorData: c.authenticatorData, clientDataJSON: c.clientDataJSON, signature: c.signature } },
      expectedChallenge: c.expectedChallenge, expectedOrigin: c.origin, expectedRPID: c.rpId,
      credential: { id: 'AAAA', publicKey: Buffer.from(c.cose, 'base64url'), counter: c.storedSignCount },
      requireUserVerification: c.requireUV,
    });
    verified = r.verified === true;
  } catch { verified = false; }
  out.push({ ...c, simplewebauthn: verified });
  void cdBytes;
}
writeFileSync(new URL('../fixtures/simplewebauthn.json', import.meta.url), JSON.stringify({ library: '@simplewebauthn/server', version: swaVersion, note: 'Assertions built with @noble/curves and judged by the library; our verifier must agree on every row.', cases: out }, null, 1) + '\n');
console.log(out.map((c) => `${c.simplewebauthn ? 'ACCEPT' : 'reject'}  ${c.name}`).join('\n'));
