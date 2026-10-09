/**
 * Cross-check @atlasauth/pca-webbotauth against Cloudflare's reference `web-bot-auth` library.
 * Setup: npm i --prefix "$WBA_LIB" web-bot-auth@0.2.0
 * Build: npx tsc -p tsconfig.build.json
 * Run:   WBA_LIB=/path node crosscheck/cloudflare.mts
 * 1. Requests signed by the reference library are written to fixtures/cloudflare.json (verified by the TS tests).
 * 2. Requests signed by pca-webbotauth are verified by the reference library (exits non-zero on failure).
 */
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { signRequest, verifySignedRequest } from '../dist/index.js';

const lib = process.env.WBA_LIB;
if (!lib) throw new Error('set WBA_LIB');
const req = createRequire(resolve(lib, 'x.js'));
const { sign, verify, generateNonce } = req('web-bot-auth');
const { signerFromJWK, verifierFromJWK } = req('web-bot-auth/crypto');
const version = JSON.parse(readFileSync(resolve(lib, 'node_modules/web-bot-auth/package.json'), 'utf8')).version;

// RFC 9421 Appendix B.1.4 test key.
const KEY = { kty: 'OKP', crv: 'Ed25519', alg: 'EdDSA', kid: 'test-key-ed25519', d: 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU', x: 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs' };
const keypair = { publicKey: new Uint8Array(Buffer.from(KEY.x, 'base64url')), secretKey: new Uint8Array(Buffer.from(KEY.d, 'base64url')) };
const URL1 = 'https://example.com/foo?x=1';
const THUMB = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';

// ---- 1: reference library signs ----
const created = Math.floor(Date.now() / 1000);
const cases: Array<Record<string, unknown>> = [];
for (const agent of ['sig1="https://signature-agent.test";type=directory', 'sig1="https://signature-agent.test"']) {
  const r = new Request(URL1, { method: 'POST', headers: { 'Signature-Agent': agent } });
  const f = await sign(r, { signer: await signerFromJWK(KEY), created: new Date(created * 1000), expires: new Date((created + 300) * 1000), nonce: generateNonce() });
  cases.push({ method: 'POST', url: URL1, headers: { 'Signature-Agent': agent, 'Signature-Input': f.signatureInput, Signature: f.signature }, created });
}
writeFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'cloudflare.json'), JSON.stringify({
  generator: `web-bot-auth ${version} (Cloudflare reference implementation), crosscheck/cloudflare.mts; key = RFC 9421 B.1.4`, keyid: THUMB, public_x: KEY.x, cases }, null, 1));
for (const c of cases) {
  const v = await verifySignedRequest({ method: String(c.method), url: String(c.url), headers: c.headers as Record<string, string> }, { resolveKey: () => keypair.publicKey, now: created + 10 });
  if (!v.valid) throw new Error(`pca-webbotauth rejected a reference-signed request: ${v.reason}`);
}
console.log('pca-webbotauth verified', cases.length, 'requests signed by web-bot-auth', version);

// ---- 2: pca-webbotauth signs, the reference library verifies ----
const verifier = await verifierFromJWK(KEY);
{
  const key = 'sig1'; // the reference library only accepts the dictionary form
  const signed = signRequest({ method: 'POST', url: URL1, key: keypair, keyid: THUMB, created, expiresInSec: 300, nonce: generateNonce(), agentDirectoryUrl: 'https://signature-agent.test', agentDirectoryKey: key, components: ['@authority'] });
  const r = new Request(URL1, { method: 'POST', headers: signed.headers });
  await verify(r, { resolver: () => verifier, validate: () => {} });
  console.log('web-bot-auth', version, 'verified a pca-webbotauth request (dictionary Signature-Agent)');
  const tampered = new Request('https://evil.example.com/foo?x=1', { method: 'POST', headers: signed.headers });
  let rejected = false;
  try { await verify(tampered, { resolver: () => verifier, validate: () => {} }); } catch { rejected = true; }
  if (!rejected) throw new Error('reference library accepted a request for a different authority');
  console.log('web-bot-auth rejected the same signature on a different authority');
}
