// Oracle (java extra): suite signing of the intent artifacts (statement, observation, profile) under ML-DSA-65 / ML-DSA-87 / hybrid /
// nested hybrid, with the PQ key from a fixed seed. PQ signatures are not compared byte for byte: each case reports the shape of the signed artifact
// plus the verdict of the reference verifier under the matching pin.
// PORTING (fn(args) -> native entry point; compared by JSON value; a reference throw requires the native to throw):
//   signStatement(stmt, edSeedB64u, alg, pqSeedB64u)     IntentStatement.signIntent(stmt, Keys.suite(alg, edFromSeed, pqFromSeed(prim, pqSeed)))
//   signObservation(obs, edSeedB64u, alg, pqSeedB64u)    IntentObservation.signIntentObservation(obs, suiteKey)
//   signProfile(body, edSeedB64u, alg, pqSeedB64u)       IntentProfile.signIntentProfile(body, suiteKey)
//   output {alg, pq_pk, rest: artifact without sig/pq_sig/alg/pq_pk, sig_len, pq_sig_len, ok}: ok = native verify of the artifact with
//   pqPins {identity: pq_pk}; sig_len/pq_sig_len are the decoded byte lengths (null when the member is absent). prim: ml-dsa-65 / ml-dsa-87 suites use that ML-DSA parameter set.
import * as S0 from '../../../packages/pca-intent/src/statement';
import * as I0 from '../../../packages/pca/src/ext/intent';
import * as P0 from '../../../packages/pca-intent/src/profile';
import * as K0 from '../../../packages/pca/src/keys';
import * as Q0 from '../../../packages/pca/src/pq';
import { Oracle, refWrite, seed } from './lib.mjs';
import { sha256 } from '@noble/hashes/sha2';

const S: any = (S0 as any).default ?? S0;
const I: any = (I0 as any).default ?? I0;
const P: any = (P0 as any).default ?? P0;
const K: any = { ...((K0 as any).default ?? K0), ...((Q0 as any).default ?? Q0) };
const o = new Oracle('intent-suite-sign-java', 'tools/pca-audit/oracles/intent-suite-sign-java.mts', 'TS-reference oracle for suite signing of intent artifacts.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64url');
const un = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));
const dig = (x: string) => b64(sha256(new TextEncoder().encode(x)));
const ED = b64(seed('isj/ed')), PQS = b64(seed('isj/pq'));
const ALGS = ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'ml-dsa-87', 'hybrid-ed25519-ml-dsa-87'];
const suiteOf = (alg: string, pqSeed: string) => {
  if (alg === 'ed25519') return { alg };
  if (alg.endsWith('ml-dsa-87')) return { alg, mlDsa87: K.mlDsa87Keygen(un(pqSeed)) };
  return { alg, mlDsa: K.mlDsa65Keygen(un(pqSeed)) };
};
const len = (v: any) => (typeof v === 'string' ? Buffer.from(v, 'base64url').length : null);
const shape = (a: any, ok: boolean) => {
  const { sig, pq_sig, alg, pq_pk, ...rest } = a;
  return { alg: alg ?? null, pq_pk: pq_pk ?? null, rest, sig_len: len(sig), pq_sig_len: len(pq_sig), ok };
};
const signer = (a: any) => b64(K.publicKeyOf(un(ED)));
const stmt = { v: 1, text: 'refund up to 100 to bob', slots: { verbs: ['stripe.refund'] }, sources: [{ kind: 'conversation', digest: dig('t1') }], created_at: 1_800_000_000_000, nonce: 'n-1' };
const obs = { map_digest: dig('map'), verb: 'v.a', values: { 'action.params.a': 3 }, y: 1, source: 'runtime', observed_at: 1_800_000_000_000 };
const prof = { v: 1, kind: 'pca-intent-profile', profile_id: 'travel', version: 1, scope: { sites: ['shop.example'], verbs: ['stripe.refund'] },
  standing: { deny: [], permit: [{ verb: 'stripe.refund', resource: '/acct/*' }] }, prior: { observations: [], maps: [dig('m1')] }, expires_at: 1900000000000, revocation: { epoch_uri: 'https://rev.example/epoch' } };
const pins = (pk: string | undefined, who: string) => (pk === undefined ? {} : { pqPins: { [who]: pk } });
const sS = (b: any, ed: string, alg: string, pq: string) => { const a = S.signIntent(b, un(ed), suiteOf(alg, pq)); return shape(a, S.verifyIntent(a, pins(a.pq_pk, a.principal)).ok); };
const sO = (b: any, ed: string, alg: string, pq: string) => { const a = I.signIntentObservation(b, un(ed), suiteOf(alg, pq)); return shape(a, I.verifyIntentObservation(a, pins(a.pq_pk, a.signer)).ok); };
const sP = (b: any, ed: string, alg: string, pq: string) => { const a = P.signIntentProfile(b, un(ed), suiteOf(alg, pq)); return shape(a, P.verifyIntentProfile(a, pins(a.pq_pk, a.owner)).ok); };
const ED2 = b64(seed('isj/ed2')), PQ2 = b64(seed('isj/pq2'));
for (const alg of ALGS) for (const [e, p] of [[ED, PQS], [ED2, PQ2]]) {
  await run('signStatement', sS, [stmt, e, alg, p]);
  await run('signObservation', sO, [obs, e, alg, p]);
  await run('signProfile', sP, [prof, e, alg, p]);
}
const mine = b64(K.publicKeyOf(un(ED)));
for (const alg of ALGS) {
  await run('signStatement', sS, [{ ...stmt, principal: mine }, ED, alg, PQS]);
  await run('signStatement', sS, [{ ...stmt, principal: mine }, ED2, alg, PQ2]);
  await run('signStatement', sS, [{ ...stmt, text: '' }, ED, alg, PQS]);
  await run('signObservation', sO, [{ ...obs, y: 2 }, ED, alg, PQS]);
  await run('signProfile', sP, [{ ...prof, owner: mine }, ED, alg, PQS]);
  await run('signProfile', sP, [{ ...prof, owner: mine }, ED2, alg, PQ2]);
}
// signProfile beyond the happy path: a revocation authority key, a successor version, and each refusal of the signer (a profile without `revocation`
// was the only body the first 24 cases ever signed, so none of them reached a signature).
const { revocation: _r, ...noRev } = prof;
for (const alg of ALGS) {
  await run('signProfile', sP, [{ ...prof, revocation: { epoch_uri: 'https://rev.example/epoch', key: b64(K.publicKeyOf(un(ED2))) } }, ED, alg, PQS]);
  await run('signProfile', sP, [{ ...prof, version: 2, prev: dig('prev') }, ED, alg, PQS]);
}
for (const bad of [noRev, { ...prof, revocation: null }, { ...prof, revocation: {} }, { ...prof, revocation: { epoch_uri: '' } }, { ...prof, revocation: { epoch_uri: 'u', extra: 1 } },
  { ...prof, revocation: { epoch_uri: 'u', key: 'AA' } }, { ...prof, version: 2 }, { ...prof, prev: dig('prev') }, { ...prof, prev: 'AA', version: 2 }, { ...prof, version: 0 }, { ...prof, v: 2 },
  { ...prof, profile_id: 'has space' }, { ...prof, owner: 'AA' }, { ...prof, scope: { sites: [''] } }, { ...prof, scope: { other: [] } }, { ...prof, standing: { deny: [] } },
  { ...prof, standing: { deny: [{}], permit: [] } }, { ...prof, prior: { observations: [{ verb: 'v', values: {}, y: 2, at: 0 }], maps: [] } }, { ...prof, prior: { observations: [], maps: ['AA'] } },
  { ...prof, expires_at: -1 }, { ...prof, expires_at: 1.5 }, { ...prof, zz_unknown: 1 }, null, 'x', []]) {
  await run('signProfile', sP, [bad, ED, 'ed25519', PQS]);
  await run('signProfile', sP, [bad, ED, 'hybrid-ed25519-ml-dsa-65', PQS]);
}
for (const alg of ['nope', '']) await run('signProfile', sP, [prof, ED, alg, PQS]);
refWrite(o, 'intent-suite-sign-java');
