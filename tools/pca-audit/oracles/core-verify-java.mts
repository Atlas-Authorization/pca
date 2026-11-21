// Oracle: the core verifier entry `verifyPCActnCore(pcactn, opts)` of @atlasauth/pca (tri-state checks, audience opt-out, hooks,
// enforcement gates, PQ pins, plan-root policy, assurance report). Written for the Java lane (PcaCore); reusable by any native.
// Deterministic: keys from seed(label), fixed clock T0, explicit nonces. Writes out/ref-core-verify-java.json.gz.
//
// PORTING (fn(args) -> native entry point, comparison rule)
//   verifyCore(pcactn, opts) -> the core verify entry with the options below; result {allow, checks: {name: status}, reason?, assurance?}
//                               compared by JSON value (reason only when denied; check ORDER is compared by the native test).
//   opts (all optional; a missing key means "not given"):
//     grant            the verifier's stored grant (object; always present)
//     grantFromArtifact, nowEpoch, pqPins {issuer: pq_pk}, allowedSuites [alg...], insecureSkipPlanRootCheck, authorizedPlanRoots [root...]
//     audience         string = must equal; null = explicit opt-out; key absent = not given (fails when the PCActn carries `aud`)
//     hooks            {attestation|threshold|revocation|zk: H}   H = {enforced: false} | {enforced: true, ok, reason?, t?}   (a constant hook)
//     enforce          {freshness: {maxAgeMs, epochMs?, clockSkewMs?, now?}, attestation: {verifier: H, required?}}
//     assurance (bool), requireAssurance (object: {signature?, attestation?, zk?, threshold?, allowAwaitingAudit?})
//     intent           an intent policy {require?, minFidelityPpm?, maxResidualRiskPpm?}
import * as PCA0 from '@atlasauth/pca';
import { Oracle, refWrite, seed } from './lib.mjs';

const P: any = (PCA0 as any).default ?? PCA0;
const { b64u, buildPCActn, delegate, encodeKey, mintRoot, paramsDigest, publicKeyOf, verifyPCActnCore } = P;

const o = new Oracle('core-verify-java', 'tools/pca-audit/oracles/core-verify-java.mts', 'TS-reference oracle for verifyPCActnCore (Java lane).');
const T0 = 1_800_000_000_000;
const key = (l: string) => { const sk = seed('corev/' + l); return { sk, pk: encodeKey(publicKeyOf(sk)) }; };
const PR = key('principal'), AG = key('agent'), SUB = key('sub'), OTHER = key('other');

const grant = (caveats: any[] = []) => mintRoot({ principalSecret: PR.sk, principalPublic: PR.pk, holder: AG.pk, caveats });
const G = JSON.parse(JSON.stringify(grant()));
const plan = [{ id: 'n1', verb: 'charge', resource: 'merchant:m1', params_digest: paramsDigest({ amount: 5 }) }];
const act = (over: any = {}) => JSON.parse(JSON.stringify(buildPCActn({
  grant: G, chain: [G], plan, nodeId: 'n1', params: { amount: 5 }, counter: 1, signerSecret: AG.sk, aud: 'rs', now: T0, nonce: 'n-1', ...over,
})));
const A = act();
const root = A.plan.root;

const hook = (h: any) => async () => h;
const opts = (j: any) => {
  const out: any = { grant: j.grant ?? G };
  for (const k of ['grantFromArtifact', 'nowEpoch', 'pqPins', 'allowedSuites', 'insecureSkipPlanRootCheck', 'authorizedPlanRoots', 'assurance', 'requireAssurance', 'intent']) if (k in j) out[k] = j[k];
  if ('audience' in j) out.audience = j.audience;
  if (j.hooks) out.hooks = Object.fromEntries(Object.entries(j.hooks).map(([k, h]) => [k, hook(h)]));
  if (j.enforce) {
    out.enforce = {};
    if (j.enforce.freshness) out.enforce.freshness = j.enforce.freshness;
    if (j.enforce.attestation) out.enforce.attestation = { verifier: hook(j.enforce.attestation.verifier), ...('required' in j.enforce.attestation ? { required: j.enforce.attestation.required } : {}) };
  }
  return out;
};
const ref = async (p: any, j: any) => {
  const r = await verifyPCActnCore(p, opts(j));
  return { allow: r.allow, checks: r.checks, ...(r.reason !== undefined ? { reason: r.reason } : {}), ...(r.assurance !== undefined ? { assurance: r.assurance } : {}) };
};
let n = 0;
const add = (p: any, j: any, tag = '') => o.run('verifyCore', `c${n++}${tag}`, ref, [p, { grant: G, nowEpoch: T0 + 1000, ...j }]);

// The option sets exercised against the base PCActn.
const base = { audience: 'rs', insecureSkipPlanRootCheck: true };
const H_OK = { enforced: true, ok: true }, H_NO = { enforced: false }, H_BAD = { enforced: true, ok: false, reason: 'nope' }, H_T = (t: any) => ({ enforced: true, ok: true, t });
const OPTS: any[] = [
  base, {}, { audience: 'rs' }, { audience: null }, { audience: 'other', insecureSkipPlanRootCheck: true }, { audience: '', insecureSkipPlanRootCheck: true },
  { ...base, authorizedPlanRoots: [root] }, { ...base, authorizedPlanRoots: [] }, { ...base, authorizedPlanRoots: ['x'] },
  { audience: 'rs', authorizedPlanRoots: [root] }, { audience: 'rs', authorizedPlanRoots: [] },
  { ...base, nowEpoch: T0 + 3_600_000 + 61_000 }, { ...base, nowEpoch: T0 - 61_000 }, { ...base, nowEpoch: T0 - 60_000 }, { ...base, nowEpoch: 2 ** 53 }, { ...base, nowEpoch: -(2 ** 53) },
  { ...base, allowedSuites: ['ed25519'] }, { ...base, allowedSuites: [] }, { ...base, allowedSuites: ['ml-dsa-65'] },
  { ...base, pqPins: {} }, { ...base, pqPins: { [PR.pk]: 'AAAA' } }, { ...base, pqPins: { other: 'AAAA' } }, { ...base, pqPins: { [PR.pk]: 'AAAA' }, grantFromArtifact: true },
  { ...base, grantFromArtifact: true }, { ...base, grant: { ...G, id: 'x' } }, { ...base, grant: { ...G, alg: 'ml-dsa-65' } },
  { ...base, hooks: { attestation: H_OK } }, { ...base, hooks: { attestation: H_NO } }, { ...base, hooks: { attestation: H_BAD } },
  { ...base, hooks: { threshold: H_T(2) } }, { ...base, hooks: { threshold: H_OK } }, { ...base, hooks: { threshold: H_BAD } },
  { ...base, hooks: { revocation: H_OK } }, { ...base, hooks: { revocation: H_BAD } }, { ...base, hooks: { revocation: H_NO } },
  { ...base, hooks: { zk: H_OK } }, { ...base, hooks: { zk: H_BAD } }, { ...base, hooks: { zk: H_NO } },
  { ...base, hooks: { attestation: H_OK, threshold: H_T(1), revocation: H_OK, zk: H_OK } },
  { ...base, enforce: { attestation: { verifier: H_OK } } }, { ...base, enforce: { attestation: { verifier: H_NO } } },
  { ...base, enforce: { attestation: { verifier: H_NO, required: false } } }, { ...base, enforce: { attestation: { verifier: H_BAD } } },
  { ...base, enforce: { attestation: { verifier: H_OK } }, hooks: { attestation: H_BAD } },
  { ...base, enforce: { freshness: { maxAgeMs: 1000 } } }, { ...base, enforce: { freshness: { maxAgeMs: -1 } } }, { ...base, enforce: { freshness: { maxAgeMs: 1000, epochMs: 0 } } },
  { ...base, enforce: { freshness: { maxAgeMs: 1000, clockSkewMs: 5000, now: T0 } } },
  { ...base, assurance: true }, { ...base, assurance: true, hooks: { attestation: H_OK, threshold: H_T(2) } },
  { ...base, requireAssurance: { signature: 'pq' } }, { ...base, requireAssurance: {} }, { ...base, requireAssurance: { attestation: 'hardware' }, hooks: { attestation: H_OK } },
  { ...base, requireAssurance: { bogus: 1 } },
  { ...base, intent: { require: true } }, { ...base, intent: { minFidelityPpm: 500000 } },
];
for (const [i, j] of OPTS.entries()) await add(A, j, `/opt${i}`);

// PCActn variations (signed body changes break the signature on purpose; the verdict must still match check for check).
const frozen = (x: any) => JSON.parse(JSON.stringify(x));
const mut = (f: (x: any) => void) => { const x = frozen(A); f(x); return x; };
const variants: [string, any][] = [
  ['ver3', mut((x) => { x.ver = 3; })], ['verStr', mut((x) => { x.ver = '2'; })], ['noAud', mut((x) => { delete x.aud; })], ['emptyAud', mut((x) => { x.aud = ''; })],
  ['aud7', mut((x) => { x.aud = 7; })], ['iatBig', mut((x) => { x.iat = T0 + 70_000; })], ['expLow', mut((x) => { x.exp = x.iat; })], ['expLong', mut((x) => { x.exp = x.iat + 3_600_001; })],
  ['expired', mut((x) => { x.exp = T0 + 500; })], ['sig', mut((x) => { x.sig = 'AAAA'; })], ['sigNum', mut((x) => { x.sig = 5; })], ['noSig', mut((x) => { delete x.sig; })],
  ['counterNeg', mut((x) => { x.counter = -1; })], ['counterF', mut((x) => { x.counter = 1.5; })], ['counterBig', mut((x) => { x.counter = 2 ** 53; })], ['noCounter', mut((x) => { delete x.counter; })],
  ['grantRef', mut((x) => { x.grant_ref = 'zzz'; })], ['grantRefEmpty', mut((x) => { x.grant_ref = ''; })], ['noGrantRef', mut((x) => { delete x.grant_ref; })],
  ['planRoot', mut((x) => { x.plan.root = 'AAAA'; })], ['node', mut((x) => { x.plan.node_id = 'n2'; })], ['verb', mut((x) => { x.action.verb = 'refund'; })],
  ['emptyChain', mut((x) => { x.cap_chain = []; })], ['noChain', mut((x) => { delete x.cap_chain; })], ['chainStr', mut((x) => { x.cap_chain = 'x'; })],
  ['chainOther', mut((x) => { x.cap_chain = [{ ...G, issuer: OTHER.pk }]; })], ['chainSig', mut((x) => { x.cap_chain[0].sig = 'AAAA'; })],
  ['bond', mut((x) => { x.bond_ref = 'b'; })], ['bondObj', mut((x) => { x.bond_ref = { id: 'b' }; })],
  ['zk', mut((x) => { x.zk_compliance = { proof: 'p' }; })], ['alg', mut((x) => { x.alg = 'ml-dsa-65'; })], ['algBad', mut((x) => { x.alg = 'rsa'; })],
  ['freshness', mut((x) => { x.freshness = { beacon_ref: 'b1', epoch: Math.floor(T0 / 60_000) }; })], ['freshnessStub', mut((x) => { x.freshness = { beacon_ref: '', epoch: 0 }; })],
  ['freshnessOld', mut((x) => { x.freshness = { beacon_ref: 'b1', epoch: 5 }; })], ['freshnessFuture', mut((x) => { x.freshness = { beacon_ref: 'b1', epoch: 10 ** 9 }; })],
  ['extra', mut((x) => { x.extra = 1; })], ['nullP', null], ['arr', []], ['str', 'x'], ['num', 5],
  ['ttl', act({ ttlMs: 1 })], ['aud2', act({ aud: 'other' })], ['counter0', act({ counter: 0 })],
];
const VOPTS: any[] = [
  base, { ...base, hooks: { threshold: H_T(1), revocation: H_OK } }, { audience: 'rs' }, { audience: null, insecureSkipPlanRootCheck: true },
  { ...base, enforce: { freshness: { maxAgeMs: 120_000 } } }, { ...base, assurance: true },
];
for (const [name, p] of variants) for (const [i, j] of VOPTS.entries()) await add(p, j, `/${name}/v${i}`);
// delegated chain and the sub-agent leaf
{
  const sub = JSON.parse(JSON.stringify(delegate(G, SUB.pk, [], AG.sk)));
  const p2 = JSON.parse(JSON.stringify(buildPCActn({ grant: G, chain: [G, sub], plan, nodeId: 'n1', params: { amount: 5 }, counter: 1, signerSecret: SUB.sk, aud: 'rs', now: T0, nonce: 'n-2' })));
  for (const [i, j] of VOPTS.entries()) await add(p2, j, `/deleg/v${i}`);
  const bad = JSON.parse(JSON.stringify(p2)); bad.cap_chain[1].sig = 'AAAA';
  for (const [i, j] of VOPTS.slice(0, 2).entries()) await add(bad, j, `/delegbad/v${i}`);
  const p3 = JSON.parse(JSON.stringify(buildPCActn({ grant: G, chain: [G, sub], plan, nodeId: 'n1', params: { amount: 5 }, counter: 1, signerSecret: AG.sk, aud: 'rs', now: T0, nonce: 'n-3' })));
  await add(p3, base, '/wrongSigner');
}
console.log('cases', o.cases.length);
refWrite(o, 'core-verify-java');
