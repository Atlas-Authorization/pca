// Emits a matrix of DPoP proofs + requests + the verdict @atlasauth/pca-dpop gives each, for server_crosscheck.py.
// Run (from the package dir): npx tsx crosscheck/gen-matrix.mts > "$OUT/matrix.json"
import { exportJWK, generateKeyPair } from 'jose';
import { createDpopProof, athFor, jwkThumbprint, verifyDpopProof, DpopVerificationError } from '../src/index.ts';

const NOW = 1_800_000_000;
const URL = 'https://server.example.com/resource?q=1#frag';
const TOKEN = 'at-0123456789';
const cases: unknown[] = [];

for (const alg of ['EdDSA', 'ES256', 'ES384'] as const) {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const priv = await exportJWK(privateKey);
  const pub = await exportJWK(publicKey);
  const jkt = await jwkThumbprint(pub);
  const mk = (over: Record<string, unknown> = {}) =>
    createDpopProof({ method: 'POST', url: URL, privateKey: priv, publicJwk: pub, iat: NOW, jti: `${alg}-1`, ath: athFor(TOKEN), ...over });
  const good = await mk();
  const req = { method: 'POST', url: URL, now: NOW, maxAgeSec: 60, accessToken: TOKEN, expectedJkt: jkt };
  const variants: Array<[string, string, Record<string, unknown>]> = [
    ['good', good, {}],
    ['wrong method', good, { method: 'GET' }],
    ['wrong url', good, { url: 'https://server.example.com/other' }],
    ['stale', good, { now: NOW + 61 }],
    ['future', good, { now: NOW - 6 }],
    ['within skew', good, { now: NOW - 5 }],
    ['wrong ath', good, { accessToken: 'different-token' }],
    ['wrong jkt', good, { expectedJkt: 'x'.repeat(43) }],
    ['no ath proof, token presented', await mk({ ath: undefined }), {}],
  ];
  for (const [name, proof, over] of variants) {
    const r = { ...req, ...over };
    let ours: { ok: boolean; code?: string };
    try {
      await verifyDpopProof(proof, { method: r.method, url: r.url, maxAgeSec: r.maxAgeSec, nowSec: r.now, accessToken: r.accessToken, expectedJkt: r.expectedJkt, requireReplayStore: false });
      ours = { ok: true };
    } catch (e) {
      if (!(e instanceof DpopVerificationError)) throw e;
      ours = { ok: false, code: e.code };
    }
    cases.push({ name: `${alg}: ${name}`, proof, request: r, ours });
  }
  // Signature tamper: change one character in the middle of the signature (still canonical base64url).
  const [h, p, s] = good.split('.') as [string, string, string];
  const mid = Math.floor(s.length / 2);
  const tampered = `${h}.${p}.${s.slice(0, mid)}${s[mid] === 'A' ? 'B' : 'A'}${s.slice(mid + 1)}`;
  let t: { ok: boolean; code?: string };
  try {
    await verifyDpopProof(tampered, { method: 'POST', url: URL, maxAgeSec: 60, nowSec: NOW, requireReplayStore: false });
    t = { ok: true };
  } catch (e) {
    if (!(e instanceof DpopVerificationError)) throw e;
    t = { ok: false, code: e.code };
  }
  cases.push({ name: `${alg}: tampered signature`, proof: tampered, request: { ...req, accessToken: undefined, expectedJkt: undefined }, ours: t });
}
console.log(JSON.stringify(cases));
