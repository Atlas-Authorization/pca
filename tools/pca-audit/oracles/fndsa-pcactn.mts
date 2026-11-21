// Oracle: full PCActn with an FN-DSA leaf (fn-dsa-512 / fn-dsa-1024), signed by the TS reference, plus tampered variants.
// Keyless: every key derives from a seed LABEL, seed32 = sha256("atlas-pca-conformance/" + label) (Ed25519 seeds, FN-DSA keygen seeds
// and FN-DSA sign seeds alike). A native replay (a) derives the keys from the labels, signs `body` through its public agent-side
// sign path with the FN-DSA suite and must reproduce `pcactn` byte for byte (Ed25519 and FN-DSA signing are deterministic for a fixed
// sign seed), and (b) verifies `pcactn` through its public PCActn verifier with the grant `grant`, `audience`, `now_epoch` and
// insecure-skip-plan-root-check: result `allow` must equal `expect_allow` with libfndsa registered, and must be a deny (reason
// unsupported_suite where the lane reports reasons) when no FN-DSA backend is registered.
// Run: node_modules/.bin/tsx --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/fndsa-pcactn.mts
// Output: out/ref-fndsa-pcactn.json
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import * as P0 from '@atlasauth/pca';

const P: any = (P0 as any).mintRoot ? P0 : (P0 as any).default;
if (!P.isFnDsaBackendActive()) throw new Error('FN-DSA backend unavailable');
const seed = (l: string) => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${l}`).digest());
const b64u = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const plain = (v: unknown) => JSON.parse(JSON.stringify(v));
const T0 = 1_800_000_000_000;
const AUD = 'fndsa-pcactn-vectors';
const RISK = { weights: { alpha: 0.25, beta: 0.2, gamma: 0.2, delta: 0.2, epsilon: 0.1, zeta: 0.05 }, theta1: 0.25, theta2: 0.6, kappa: 1, lambda: 0.0005, rho: 0.5, bMax: 1 };

const VARIANTS = [
  { alg: 'fn-dsa-512', slot: 'fnDsa512', keygen: P.fnDsa512Keygen, vk: 897, sig: 666 },
  { alg: 'fn-dsa-1024', slot: 'fnDsa1024', keygen: P.fnDsa1024Keygen, vk: 1793, sig: 1280 },
];
const flip = (s: string, at: number) => { const b = Buffer.from(s, 'base64url'); b[at] ^= 1; return b.toString('base64url'); };

const labels = { principal: 'fndsa-pcactn/principal', agent: 'fndsa-pcactn/agent' };
const edSk = (l: string) => seed(l + '/ed25519');
const cases: any[] = [];
for (const v of VARIANTS) {
  const fnLabel = `fndsa-pcactn/${v.alg}/agent`, otherLabel = `fndsa-pcactn/${v.alg}/other`;
  const mk = (l: string) => { const kp = v.keygen(seed(l + '/keygen')); return { verifyingKey: kp.verifyingKey, signingKey: kp.signingKey, signSeed: seed(l + '/sign') }; };
  const fn = mk(fnLabel), other = mk(otherLabel);
  const pSk = edSk(labels.principal), aSk = edSk(labels.agent);
  const pPub = b64u(P.publicKeyOf(pSk)), aPub = b64u(P.publicKeyOf(aSk));
  const caveats = [{ type: 'envelope', goal_commit: P.goalCommitOf('fndsa pcactn goal', 'fndsa-salt'), predicates: [{ verb: 'refund', resource: 'orders/*' }], caveats: [], agent_binding: {}, risk_policy: RISK }];
  const root = P.mintRoot({ principalSecret: pSk, principalPublic: pPub, holder: aPub, holderPq: b64u(fn.verifyingKey), caveats });
  const plan = [{ id: 'n0', verb: 'refund', resource: 'orders/1', reversibility_class: 'compensable', params_digest: P.paramsDigest({ amount_cents: 500, currency: 'USD' }) }];
  const built = P.buildPCActn({ grant: root, chain: [root], plan, nodeId: 'n0', params: { amount_cents: 500, currency: 'USD' }, counter: 1, signerSecret: aSk, aud: AUD, iat: T0, exp: T0 + 1_200_000, nonce: b64u(createHash('sha256').update('fndsa-pcactn:nonce:' + v.alg).digest().subarray(0, 16)) });
  const { sig: _s, ...body } = built;
  const signed = P.signPCActnSuite(body, { alg: v.alg, edLeafSecret: aSk, [v.slot]: fn });
  if (signed.alg !== v.alg || signed.pq_pk !== b64u(fn.verifyingKey) || Buffer.from(signed.sig, 'base64url').length !== v.sig) throw new Error('unexpected signed shape');
  const verify = async (p: any) => (await P.verifyPCActnCore(p, { grant: root, nowEpoch: T0 + 1000, audience: AUD, insecureSkipPlanRootCheck: true })).allow === true;
  const add = async (name: string, p: any, note: string) => cases.push({ name: `${v.alg}/${name}`, alg: v.alg, note, pcactn: plain(p), expect_allow: await verify(p) });
  await add('valid', signed, 'untouched reference output');
  if (cases[cases.length - 1].expect_allow !== true) throw new Error('reference refused its own FN-DSA leaf: ' + v.alg);
  await add('tampered-sig', { ...signed, sig: flip(signed.sig, 20) }, 'one flipped byte in sig');
  await add('tampered-body', { ...signed, nonce: flip(signed.nonce, 0) }, 'body changed after signing');
  await add('wrong-pq_pk', { ...signed, pq_pk: b64u(other.verifyingKey) }, 'pq_pk of a different valid FN-DSA key');
  await add('short-pq_pk', { ...signed, pq_pk: signed.pq_pk.slice(0, -4) }, 'pq_pk shorter than the suite size');
  await add('alg-swap', { ...signed, alg: v.alg === 'fn-dsa-512' ? 'fn-dsa-1024' : 'fn-dsa-512' }, 'alg rewritten to the other FN-DSA suite');
  for (const c of cases.filter((c) => c.alg === v.alg && c.name !== `${v.alg}/valid`)) if (c.expect_allow) throw new Error('tamper accepted by the reference: ' + c.name);
  Object.assign(cases.find((c) => c.name === `${v.alg}/valid`), {
    grant: plain(root), audience: AUD, now_epoch: T0 + 1000, body: plain(body),
    key_labels: { principal_ed25519: labels.principal + '/ed25519', agent_ed25519: labels.agent + '/ed25519', fndsa_keygen: fnLabel + '/keygen', fndsa_sign_seed: fnLabel + '/sign' },
    pq_pk: b64u(fn.verifyingKey),
  });
}
// every case shares its variant's grant/audience/now_epoch: copy them onto the tamper cases for a self-contained replay
for (const c of cases) { const base = cases.find((x) => x.name === `${c.alg}/valid`); for (const k of ['grant', 'audience', 'now_epoch']) c[k] = base[k]; }
fs.mkdirSync(fileURLToPath(new URL('./out/', import.meta.url)), { recursive: true });
const out = fileURLToPath(new URL('./out/ref-fndsa-pcactn.json', import.meta.url));
fs.writeFileSync(out, JSON.stringify({ about: 'FN-DSA PCActn leaf fixtures (see generator header for the replay contract)', generator: 'tools/pca-audit/oracles/fndsa-pcactn.mts', seed_scheme: 'sha256("atlas-pca-conformance/"+label)', cases }, null, 1) + '\n');
console.log(`wrote ${cases.length} cases to ${out}`);
