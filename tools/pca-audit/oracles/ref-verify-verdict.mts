// Oracle: the FULL verdict of the flagship resource-server verifier `verifyPCActn(pcactn, opts)` (@atlasauth/pca, server/verify):
// allow, r, requiredThreshold, every checks entry, the reasons with their exact texts, budget, assurance (and k1Bound / principal when present).
// Existing corpora record allow / checks / some reasons only. Deterministic: keys and salts from seed(label), fixed clock, constant hooks.
// Keys never reach the corpus (it carries signed artifacts and public keys only); still generate with
//   PCA_SEED_LOG=<dir>/ref-verify-verdict.txt PCA_ORACLE_STRICT=1 tsx --tsconfig tools/pca-audit/oracles/tsconfig.json tools/pca-audit/oracles/ref-verify-verdict.mts
// and strip with PCA_SEED_LABELS=<dir> strip-corpus-keys.py --any out/ref-verify-verdict.json.gz (a no-op here: the check below fails the run on a leak).
//
// PORTING (fn(args) -> native entry point, comparison rule)
//   verifyVerdict(pcactn, opts) -> the public verifier of the lane; the result is compared FIELD BY FIELD with the case's `out`:
//     allow, requiredThreshold {t, proof, optimisticAllowed}, checks (name -> status; the SET of names and each status; order is not compared),
//     reasons (exact strings, exact order), budget (absent == absent; B, tau, asOf numbers), assurance (when present), r (double, relative 1e-12).
//   pcactn: a PCActn object, or a string (the encoded wire form; a string the lane must decode itself).
//   opts: JSON; a missing key means "not given".
//     grant, now, audience (string | null | absent), insecureSkipPlanRootCheck, context {plan, planAuthorized, params, risk, budget, reversibilityClass,
//     revocationEpoch {epoch, guardianPublic, lastAcceptedEpoch?, maxAgeMs?}, beacon {beacon, issuers, instance, lastAcceptedSeq?}, ...}, require [names],
//     operation {verb, resource, params?}, pqPins, allowedSuites, requireRiskInputs [names], assurance (bool), requireAssurance {...}, allowUnsupported [names],
//     enforce {freshness {...}, attestation {verifier: H, required?}}, intent.
//     hooks {attestation|threshold|revocation|zk|replay: H}   H is a constant hook: {enforced: false} | {enforced: true, ok, reason?, t?} |
//       {throws: "msg"} (the hook throws) | {raw: value} (the hook returns that value). A `replay` hook is not part of the reference's hook set: it is ignored.
//   The reference treats `operation` as OPTIONAL (no `operation` check without it) and reports `revocation` as not-enforced without a revocation hook
//   (then the default `require` denies). A lane that is stricter on purpose asserts those cases as counted deviations.
import * as P0 from '../../../packages/pca/src/index.ts';
import { Oracle, refWrite, seed, ser } from './lib.mjs';

const P: any = (P0 as any).default ?? P0;
const { b64u, encodeKey, publicKeyOf, mintGrant, delegate, commitPlan, conditionsDigest, hashCanonical, signPCActn, PCACTN_VERSION, DEFAULT_RISK_POLICY, verifyPCActn,
  STATEFUL_REQUIRED_CHECKS, DEFAULT_REQUIRED_CHECKS, signRevocationEpoch, encodePCActn } = P;
const BC0: any = await import('../../../packages/pca/src/beacons.ts');
const { issueLivenessBeacon, beaconRef } = BC0.issueLivenessBeacon ? BC0 : BC0.default;

const o = new Oracle('ref-verify-verdict', 'tools/pca-audit/oracles/ref-verify-verdict.mts', 'TS-reference oracle for the flagship verifyPCActn: the full verdict (allow, r, requiredThreshold, checks, reasons, budget, assurance).');
const NOW = Date.UTC(2026, 9, 6, 12, 0, 0);
const AUD = 'rs-test';
const sk = (l: string) => seed('rvv/' + l);
const pkOf = (l: string) => encodeKey(publicKeyOf(sk(l)));

// ---- scenario builder (the verify.test fixture, with seeded keys) ----
type Sc = ReturnType<typeof scenario>;
function scenario(opts: { binding?: any; taskCaveats?: any[]; policy?: any; tag?: string; extraEnv?: any } = {}) {
  const tag = opts.tag ?? 'base';
  const { grant } = mintGrant({
    principalSecret: sk('principal'), principalPublic: pkOf('principal'), holder: pkOf('principal'), goal: 'tidy sessions', salt: b64u(seed('rvv/salt/' + tag)).slice(0, 22),
    envelope: {
      predicates: [{ verb: 'list_sessions', resource: 'session:*' }, { verb: 'rotate_recovery_keys', resource: 'account:me' }],
      caveats: [{ type: 'expires', at: NOW + 3_600_000 }, { type: 'delegation_depth', max: 2 }],
      agent_binding: opts.binding ?? {}, risk_policy: opts.policy ?? DEFAULT_RISK_POLICY, ...(opts.extraEnv ?? {}),
    },
  });
  const task = delegate(grant, pkOf('agent'), [{ type: 'expires', at: NOW + 600_000 }, ...(opts.taskCaveats ?? [])], sk('principal'));
  const chain = [grant, task];
  const params: any = { n1: {}, n2: { scope: 'all' }, n3: { limit: 5 } };
  const plan = [
    { id: 'n1', verb: 'list_sessions', resource: 'session:*', params_digest: hashCanonical(params.n1), reversibility_class: 'reversible' },
    { id: 'n2', verb: 'rotate_recovery_keys', resource: 'account:me', params_digest: hashCanonical(params.n2), reversibility_class: 'irreversible' },
    { id: 'n3', verb: 'list_sessions', resource: 'session:x', params_digest: hashCanonical(params.n3), reversibility_class: 'costly' },
  ];
  const committed = commitPlan(plan);
  const mk = (id: string, x: { counter?: number; tweak?: (a: any) => void; beaconRef?: string; extra?: any; signer?: string } = {}) => {
    const n: any = plan.find((q) => q.id === id)!;
    const action: any = { verb: n.verb, resource: n.resource, params_digest: n.params_digest, reversibility_class: n.reversibility_class };
    x.tweak?.(action);
    const body: any = {
      ver: PCACTN_VERSION, action, grant_ref: grant.id, cap_chain: chain,
      plan: { root: committed.root, inclusion_proof: committed.proofFor(n.id), node_id: n.id, conditions_digest: conditionsDigest(n.pre, n.post) },
      attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
      provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
      freshness: { beacon_ref: x.beaconRef ?? '', epoch: 0, accumulator_witness: '' },
      counter: x.counter ?? 1, risk_claim: { r: 0, inputs: {} }, aud: AUD, iat: NOW, exp: NOW + 600_000, ...(x.extra ?? {}),
    };
    return JSON.parse(ser(signPCActn(body, sk(x.signer ?? 'agent'))));
  };
  return { grant: JSON.parse(ser(grant)), plan, params, mk };
}

// ---- hooks as data ----
const H_OK = { enforced: true, ok: true }, H_NO = { enforced: false }, H_BAD = { enforced: true, ok: false, reason: 'nope' }, H_BAD0 = { enforced: true, ok: false };
const H_T = (t: any) => ({ enforced: true, ok: true, t });
const hookFn = (h: any) => async () => { if (h && 'throws' in h) throw new Error(h.throws); if (h && 'raw' in h) return h.raw; return h; };

const KEYS = ['now', 'insecureSkipPlanRootCheck', 'context', 'require', 'allowedSuites', 'pqPins', 'operation', 'intent', 'requireRiskInputs', 'assurance', 'requireAssurance', 'allowUnsupported', 'allowUnboundPq'];
const toOpts = (j: any) => {
  const out: any = { grant: j.grant };
  for (const k of KEYS) if (k in j) out[k] = j[k];
  if ('audience' in j) out.audience = j.audience;
  if (j.hooks) out.hooks = Object.fromEntries(Object.entries(j.hooks).filter(([k]) => k !== 'replay').map(([k, h]) => [k, hookFn(h)]));
  if (j.enforce) {
    out.enforce = {};
    if (j.enforce.freshness) out.enforce.freshness = j.enforce.freshness;
    if (j.enforce.attestation) out.enforce.attestation = { verifier: hookFn(j.enforce.attestation.verifier), ...('required' in j.enforce.attestation ? { required: j.enforce.attestation.required } : {}) };
  }
  return out;
};
const ref = async (p: any, j: any) => verifyPCActn(p, toOpts(j));

const LOW = { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 };
const S = scenario();
let n = 0;
const add = (p: any, j: any, tag: string) => o.run('verifyVerdict', `c${n++}/${tag}`, ref, [p, j]);
/** the standard opts of a passing verifier: audience, authorized plan, revocation hook, low risk */
const base = (s: Sc, node = 'n1', x: any = {}) => ({
  grant: s.grant, now: NOW, audience: AUD, hooks: { revocation: H_OK },
  context: { plan: s.plan, planAuthorized: true, risk: LOW, params: s.params[node], ...(x.context ?? {}) },
  ...Object.fromEntries(Object.entries(x).filter(([k]) => k !== 'context')),
});
const merge = (b: any, x: any) => ({ ...b, ...x, hooks: { ...b.hooks, ...(x.hooks ?? {}) }, context: { ...b.context, ...(x.context ?? {}) } });

// ================= 1. success / risk grid (thresholds, budget, hooks) =================
const rev = [1, 0.5, 0], blast = [0, 0.5, 1], conf = [1, 0.5], sem = [0, 1], taint = [0, 0.5, 1];
for (const node of ['n1', 'n2', 'n3'] as const) {
  for (const r1 of rev) for (const b of blast) for (const c of conf) for (const sd of sem) for (const t of taint) {
    // a deterministic thinning keeps the corpus a few hundred cases: every (node, rev, blast) pair with all of conf/sem/taint, plus two budgets
    if ((r1 * 4 + b * 2 + c + sd + t * 3) % 3 === 1 && node !== 'n2') continue;
    if (node !== 'n2' && (sd === 1 || t === 0.5)) continue;
    const risk = { reversibility: r1, blastRadius: b, confidence: c, semanticDistance: sd, taint: t };
    const bs = base(S, node, { context: { risk, budget: { B: 1, tau: NOW, asOf: NOW } } });
    const p = S.mk(node);
    const v: any = await ref(p, bs);
    const tag = `${node}/r${r1}b${b}c${c}s${sd}t${t}`;
    await add(p, bs, `budget1/${tag}`);
    if (v.requiredThreshold.t > 1 && (c === 1 && sd === 0)) {
      for (const tt of [v.requiredThreshold.t, v.requiredThreshold.t - 1, v.requiredThreshold.t + 1]) await add(p, merge(bs, { hooks: { threshold: H_T(tt) } }), `thr${tt}/${tag}`);
      await add(p, merge(bs, { hooks: { threshold: H_BAD } }), `thrbad/${tag}`);
    }
    if (c === 0.5 && sd === 1) await add(p, merge(bs, { context: { budget: undefined } }), `nobudget/${tag}`);
  }
}
// budget states at one risk point where the budget decides: absent, exhausted, partial, large, stale asOf
{
  const risk = { reversibility: 0.5, blastRadius: 0.25, confidence: 0.75, semanticDistance: 0.25, taint: 0.25 };
  for (const [l, bud] of [['absent', undefined], ['zero', { B: 0, tau: NOW, asOf: NOW }], ['tiny', { B: 0.001, tau: NOW, asOf: NOW }], ['half', { B: 0.5, tau: NOW, asOf: NOW }], ['full', { B: 1, tau: NOW, asOf: NOW }],
    ['no asOf', { B: 0.5, tau: NOW }], ['stale tau', { B: 1, tau: NOW - 86_400_000, asOf: NOW - 86_400_000 }], ['future asOf', { B: 1, tau: NOW, asOf: NOW + 60_000 }], ['over bMax', { B: 50, tau: NOW, asOf: NOW }],
    ['negative', { B: -1, tau: NOW, asOf: NOW }]] as const)
    for (const node of ['n1', 'n2'] as const) for (const rk of [risk, { ...risk, blastRadius: 1, reversibility: 0 }]) {
      const bs = base(S, node, { context: { risk: rk, ...(bud ? { budget: bud } : {}) } });
      await add(S.mk(node), bs, `budgetstate/${l}/${node}/${rk.blastRadius}`);
      await add(S.mk(node), merge(bs, { hooks: { threshold: H_T(3) } }), `budgetstate-thr3/${l}/${node}/${rk.blastRadius}`);
    }
}

// ================= 2. each check failing on its own =================
const b1 = base(S, 'n1', { context: { budget: { B: 1, tau: NOW, asOf: NOW } } });
const A1 = S.mk('n1');
const cl = (x: any) => JSON.parse(JSON.stringify(x));
const mut = (f: (x: any) => void) => { const x = cl(A1); f(x); return x; };
const variants: [string, any][] = [
  ['ver3', mut((x) => { x.ver = 3; })], ['verStr', mut((x) => { x.ver = '2'; })], ['noAud', mut((x) => { delete x.aud; })], ['emptyAud', mut((x) => { x.aud = ''; })], ['aud7', mut((x) => { x.aud = 7; })],
  ['otherAud', S.mk('n1', { extra: { aud: 'elsewhere' } })], ['iatFuture', mut((x) => { x.iat = NOW + 70_000; })], ['expEqIat', mut((x) => { x.exp = x.iat; })], ['expLong', mut((x) => { x.exp = x.iat + 3_600_001; })],
  ['expired', mut((x) => { x.exp = NOW - 1; })], ['badSig', mut((x) => { x.sig = 'AAAA'; })], ['sigNum', mut((x) => { x.sig = 5; })], ['noSig', mut((x) => { delete x.sig; })], ['counterNeg', mut((x) => { x.counter = -1; })],
  ['counterFrac', mut((x) => { x.counter = 1.5; })], ['counterBig', mut((x) => { x.counter = 2 ** 53; })], ['noCounter', mut((x) => { delete x.counter; })], ['counter0', S.mk('n1', { counter: 0 })],
  ['grantRefBad', mut((x) => { x.grant_ref = 'zzz'; })], ['grantRefEmpty', mut((x) => { x.grant_ref = ''; })], ['noGrantRef', mut((x) => { delete x.grant_ref; })],
  ['planRootBad', mut((x) => { x.plan.root = 'AAAA'; })], ['nodeOther', mut((x) => { x.plan.node_id = 'n2'; })], ['inclusionBad', mut((x) => { x.plan.inclusion_proof = []; })], ['verbOther', mut((x) => { x.action.verb = 'refund'; })],
  ['resourceOther', mut((x) => { x.action.resource = 'session:other'; })], ['digestOther', mut((x) => { x.action.params_digest = 'AAAA'; })], ['classOther', mut((x) => { x.action.reversibility_class = 'irreversible'; })],
  ['emptyChain', mut((x) => { x.cap_chain = []; })], ['noChain', mut((x) => { delete x.cap_chain; })], ['chainStr', mut((x) => { x.cap_chain = 'x'; })], ['chainSig', mut((x) => { x.cap_chain[0].sig = 'AAAA'; })],
  ['leafSig', mut((x) => { x.cap_chain[1].sig = 'AAAA'; })], ['wrongSigner', S.mk('n1', { signer: 'other' })], ['bond', mut((x) => { x.bond_ref = 'b'; })], ['zk', mut((x) => { x.zk_compliance = { proof: 'p' }; })],
  ['algBad', mut((x) => { x.alg = 'rsa'; })], ['algPq', mut((x) => { x.alg = 'ml-dsa-65'; })], ['caution', S.mk('n1', { extra: { caution: 0.9 } })], ['cautionLow', S.mk('n1', { extra: { caution: 0 } })],
  ['cautionBad', S.mk('n1', { extra: { caution: 'x' } })], ['toolBinding', S.mk('n1', { extra: { tool_binding: 'tb' } })], ['extra', mut((x) => { x.extra = 1; })], ['freshAt', S.mk('n1', { extra: { fresh_at: { x: 1 } } })],
  ['freshnessEpoch', S.mk('n1', { extra: { freshness: { beacon_ref: '', epoch: 5, accumulator_witness: '' } } })],
  ['nullP', null], ['arr', []], ['str', 'x'], ['num', 5], ['emptyStr', ''], ['jsonStr', '{}'], ['nullStr', 'null'], ['encoded', encodePCActn(A1)], ['encodedGarbage', 'eyJ4IjoxfQ'],
];
for (const [name, p] of variants) {
  await add(p, b1, `variant/${name}`);
  if (n % 3 === 0) await add(p, merge(b1, { assurance: true }), `variant-assurance/${name}`);
}
// option-side failures, each alone
const optCases: [string, any][] = [
  ['audience other', { audience: 'other' }], ['audience null', { audience: null }], ['audience absent', { audience: undefined }], ['audience empty', { audience: '' }],
  ['now expired', { now: NOW + 700_000 }], ['now before iat', { now: NOW - 61_000 }], ['now at iat-60s', { now: NOW - 60_000 }], ['now 2^53', { now: 2 ** 53 }], ['now negative', { now: -1 }],
  ['grant id other', { grant: { ...S.grant, id: 'x' } }], ['grant alg pq', { grant: { ...S.grant, alg: 'ml-dsa-65' } }], ['grant sig bad', { grant: { ...S.grant, sig: 'AAAA' } }],
  ['allowedSuites ed', { allowedSuites: ['ed25519'] }], ['allowedSuites empty', { allowedSuites: [] }], ['allowedSuites pq', { allowedSuites: ['ml-dsa-65'] }],
  ['pqPins empty', { pqPins: {} }], ['pqPins pinned issuer', { pqPins: { [pkOf('principal')]: 'AAAA' } }], ['pqPins other issuer', { pqPins: { other: 'AAAA' } }],
  ['revocation absent', { hooks: { revocation: undefined } }], ['revocation bad', { hooks: { revocation: H_BAD } }], ['revocation bad no reason', { hooks: { revocation: H_BAD0 } }], ['revocation not enforced', { hooks: { revocation: H_NO } }],
  ['revocation throws', { hooks: { revocation: { throws: 'boom' } } }], ['revocation raw null', { hooks: { revocation: { raw: null } } }], ['revocation raw empty', { hooks: { revocation: { raw: {} } } }],
  ['revocation raw ok without enforced', { hooks: { revocation: { raw: { ok: true } } } }],
  ['attestation ok', { hooks: { attestation: H_OK } }], ['attestation bad', { hooks: { attestation: H_BAD } }], ['attestation not enforced', { hooks: { attestation: H_NO } }], ['attestation throws', { hooks: { attestation: { throws: 'att' } } }],
  ['threshold ok t1', { hooks: { threshold: H_T(1) } }], ['threshold ok no t', { hooks: { threshold: H_OK } }], ['threshold bad', { hooks: { threshold: H_BAD } }], ['threshold t 3', { hooks: { threshold: H_T(3) } }],
  ['threshold t string', { hooks: { threshold: H_T('3') } }], ['threshold t fraction', { hooks: { threshold: H_T(1.5) } }], ['threshold t negative', { hooks: { threshold: H_T(-1) } }],
  ['zk ok', { hooks: { zk: H_OK } }], ['zk bad', { hooks: { zk: H_BAD } }], ['zk not enforced', { hooks: { zk: H_NO } }],
  ['all hooks ok', { hooks: { attestation: H_OK, threshold: H_T(1), revocation: H_OK, zk: H_OK } }],
  ['planAuthorized false', { context: { planAuthorized: false } }], ['planAuthorized absent', { context: { planAuthorized: undefined } }], ['no plan', { context: { plan: undefined, planAuthorized: undefined } }],
  ['plan mismatch', { context: { plan: S.plan.slice(0, 2) } }], ['plan mismatch authorized', { context: { plan: S.plan.slice(0, 1), planAuthorized: true } }],
  ['no plan, skip', { insecureSkipPlanRootCheck: true, context: { plan: undefined, planAuthorized: undefined } }], ['no plan, skip false', { insecureSkipPlanRootCheck: false, context: { plan: undefined, planAuthorized: undefined } }],
  ['params wrong', { context: { params: { evil: 1 } } }], ['params absent', { context: { params: undefined } }], ['params null', { context: { params: null } }],
  ['reversibility lie', { context: { reversibilityClass: 'costly' } }], ['reversibility match', { context: { reversibilityClass: 'reversible' } }], ['reversibility unknown', { context: { reversibilityClass: 'weird' } }],
  ['reversibility stricter', { context: { reversibilityClass: 'irreversible' } }],
  ['risk missing taint', { context: { risk: { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0 } } }], ['risk empty', { context: { risk: {} } }], ['risk absent', { context: { risk: undefined } }],
  ['requireRiskInputs ok', { requireRiskInputs: ['taint', 'blastRadius'] }], ['requireRiskInputs missing age', { requireRiskInputs: ['age'] }], ['requireRiskInputs missing two', { requireRiskInputs: ['age', 'taint', 'confidence'] }],
  ['requireRiskInputs semantic from plan', { requireRiskInputs: ['semanticDistance'], context: { risk: { ...LOW, semanticDistance: undefined } } }],
  ['requireRiskInputs semantic no plan', { requireRiskInputs: ['semanticDistance'], insecureSkipPlanRootCheck: true, context: { plan: undefined, planAuthorized: undefined, risk: { ...LOW, semanticDistance: undefined } } }],
  ['requireRiskInputs empty', { requireRiskInputs: [] }],
  ['recentActionTimes burst', { context: { recentActionTimes: Array.from({ length: 50 }, (_, i) => NOW - i * 10) } }],
  ['intent require', { intent: { require: true } }], ['intent fidelity', { intent: { minFidelityPpm: 500000 } }], ['intent residual', { intent: { maxResidualRiskPpm: 1000 } }],
  ['freshness gate', { enforce: { freshness: { maxAgeMs: 1000 } } }], ['freshness gate negative', { enforce: { freshness: { maxAgeMs: -1 } } }], ['freshness gate wide', { enforce: { freshness: { maxAgeMs: 10 ** 12, epochMs: 60_000, now: NOW } } }],
  ['attestation gate ok', { enforce: { attestation: { verifier: H_OK } } }], ['attestation gate not enforced', { enforce: { attestation: { verifier: H_NO } } }], ['attestation gate optional', { enforce: { attestation: { verifier: H_NO, required: false } } }],
  ['attestation gate bad', { enforce: { attestation: { verifier: H_BAD } } }],
  ['allowUnsupported bond', { allowUnsupported: ['bond'] }], ['allowUnsupported empty', { allowUnsupported: [] }], ['allowUnboundPq', { allowUnboundPq: true }],
];
for (const [name, x] of optCases) {
  const opts = merge(b1, x);
  for (const k of Object.keys(opts)) if (opts[k] === undefined) delete opts[k];
  for (const k of Object.keys(opts.context)) if (opts.context[k] === undefined) delete opts.context[k];
  for (const k of Object.keys(opts.hooks)) if (opts.hooks[k] === undefined) delete opts.hooks[k];
  if ('audience' in x && x.audience === undefined) delete opts.audience;
  await add(A1, opts, `opt/${name}`);
  if (n % 2 === 0) await add(S.mk('n1', { extra: { bond_ref: 'b1' } }), opts, `opt-bond/${name}`);
}

// ================= 3. the operation path (optional in the reference) =================
{
  const N = S.plan[0] as any;
  const opCases: [string, any][] = [
    ['absent', undefined], ['match', { verb: N.verb, resource: N.resource }], ['match with params', { verb: N.verb, resource: N.resource, params: {} }], ['verb other', { verb: 'delete', resource: N.resource }],
    ['resource other', { verb: N.verb, resource: 'session:zzz' }], ['both other', { verb: 'delete', resource: 'x' }], ['params differ', { verb: N.verb, resource: N.resource, params: { a: 1 } }],
    ['verb number', { verb: 5, resource: N.resource }], ['resource null', { verb: N.verb, resource: null }], ['no verb', { resource: N.resource }], ['empty', {}], ['verb empty', { verb: '', resource: '' }],
    ['null', null],
  ];
  for (const [name, op] of opCases) {
    for (const [cname, ctxParams] of [['ctx params same', {}], ['ctx params differ', { b: 2 }], ['ctx params absent', undefined]] as const) {
      const opts: any = base(S, 'n1', { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } });
      if (op !== undefined) opts.operation = op;
      if (ctxParams === undefined) delete opts.context.params; else opts.context.params = ctxParams;
      await add(A1, opts, `operation/${name}/${cname}`);
    }
  }
  // the n2 node: operation params open the digest and replace context params
  const B2 = base(S, 'n2', { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } });
  const N2 = S.plan[1] as any;
  for (const [name, op] of [['n2 match params', { verb: N2.verb, resource: N2.resource, params: { scope: 'all' } }], ['n2 wrong params', { verb: N2.verb, resource: N2.resource, params: { scope: 'mine' } }], ['n2 no params', { verb: N2.verb, resource: N2.resource }]] as const)
    await add(S.mk('n2'), merge(B2, { operation: op, hooks: { threshold: H_T(3) } }), `operation/${name}`);
}

// ================= 4. require lists: missing-revocation, replay (absent / alias / a hook the reference ignores), custom =================
{
  const nb = base(S, 'n1', { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } });
  const noRev = () => { const x = cl(nb); delete x.hooks.revocation; return x; };
  const requires: [string, any][] = [
    ['default', undefined], ['empty', []], ['stateful', [...STATEFUL_REQUIRED_CHECKS]], ['default list', [...DEFAULT_REQUIRED_CHECKS]], ['counter alias', ['counter']], ['replay', ['replay']], ['counter_format', ['counter_format']],
    ['unknown', ['nope']], ['all checks', ['cap_chain', 'plan_inclusion', 'leaf_signature', 'attestation', 'threshold', 'revocation', 'zk', 'freshness', 'beacon', 'budget', 'policy', 'params_digest']],
    ['duplicates', ['revocation', 'revocation', 'audience']], ['operation', ['operation']], ['pq_pin', ['pq_pin']], ['empty name', ['']],
  ];
  for (const [rname, req] of requires) {
    for (const [hname, hooks] of [['revocation ok', { revocation: H_OK }], ['no revocation hook', null], ['revocation ok + replay hook', { revocation: H_OK, replay: H_OK }], ['replay hook only', { replay: H_OK }], ['replay hook failing', { revocation: H_OK, replay: H_BAD }],
      ['revocation not enforced', { revocation: H_NO }], ['revocation bad', { revocation: H_BAD }]] as const) {
      const opts = noRev();
      if (hooks) opts.hooks = hooks;
      if (req !== undefined) opts.require = req;
      await add(A1, opts, `require/${rname}/${hname}`);
    }
  }
  // the 0.4 style report: no require, a verifier with no hooks at all
  await add(A1, { grant: S.grant, now: NOW, audience: AUD, require: [], context: { plan: S.plan, risk: LOW } }, 'require/report-only');
  await add(A1, { grant: S.grant, now: NOW, insecureSkipPlanRootCheck: true, require: [], context: { risk: LOW } }, 'require/report-only-skip');
  await add(A1, { grant: S.grant, now: NOW }, 'require/bare');
  await add(A1, { grant: S.grant }, 'require/bare-wall-clock-grant-only-shape');
}

// ================= 5. assurance requested / not =================
{
  const nb = base(S, 'n1', { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } });
  const asr: [string, any][] = [
    ['none', {}], ['assurance true', { assurance: true }], ['assurance false', { assurance: false }], ['assurance null', { assurance: null }], ['requireAssurance empty', { requireAssurance: {} }],
    ['signature pq', { requireAssurance: { signature: 'pq' } }], ['signature classical', { requireAssurance: { signature: 'classical' } }], ['attestation hardware', { requireAssurance: { attestation: 'hardware' } }],
    ['attestation software', { requireAssurance: { attestation: 'software' } }], ['zk snark', { requireAssurance: { zk: 'snark' } }], ['threshold', { requireAssurance: { threshold: 'verified' } }],
    ['threshold allowAwaitingAudit', { requireAssurance: { threshold: 'verified', allowAwaitingAudit: true } }], ['bogus key', { requireAssurance: { bogus: 1 } }], ['all four', { requireAssurance: { signature: 'pq', attestation: 'hardware', zk: 'snark', threshold: 'verified' } }],
  ];
  const hset: [string, any][] = [['no hooks', { revocation: H_OK }], ['attestation ok', { revocation: H_OK, attestation: H_OK }], ['attestation + zk + threshold', { revocation: H_OK, attestation: H_OK, zk: H_OK, threshold: H_T(1) }],
    ['attestation bad', { revocation: H_OK, attestation: H_BAD }], ['zk bad', { revocation: H_OK, zk: H_BAD }]];
  for (const [an, ax] of asr) for (const [hn, hk] of hset) {
    await add(A1, { ...nb, ...ax, hooks: hk }, `assurance/${an}/${hn}`);
    if (hn === 'no hooks' || hn === 'attestation ok') await add(S.mk('n1', { extra: { bond_ref: 'b1' } }), { ...nb, ...ax, hooks: hk, allowUnsupported: ['bond'] }, `assurance-bond/${an}/${hn}`);
  }
}

// ================= 6. grants that change the policy: agent_binding (attestation required), tight risk policy, delegated caveats =================
{
  const SB = scenario({ binding: { operator: 'acme' }, tag: 'binding' });
  const bb = base(SB, 'n1', { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } });
  for (const [name, hk] of [['none', {}], ['attestation ok', { attestation: H_OK }], ['attestation bad', { attestation: H_BAD }], ['attestation not enforced', { attestation: H_NO }]] as const)
    await add(SB.mk('n1'), { ...bb, hooks: { revocation: H_OK, ...hk } }, `binding/${name}`);
  await add(SB.mk('n1'), { ...bb, hooks: { revocation: H_OK }, enforce: { attestation: { verifier: H_OK } } }, 'binding/gate ok');
  const SBM = scenario({ binding: { min_measurement: 'm', operator: 'o' }, tag: 'binding2' });
  await add(SBM.mk('n1'), { ...base(SBM, 'n1', { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } }), hooks: { revocation: H_OK, attestation: H_OK } }, 'binding/measurement attestation ok');

  const TIGHT = { ...DEFAULT_RISK_POLICY, theta1: 0.01, theta2: 0.05 }, LOOSE = { ...DEFAULT_RISK_POLICY, theta1: 0.9, theta2: 0.95, bMax: 10 }, FLAT = { ...DEFAULT_RISK_POLICY, weights: { alpha: 1, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 } };
  const risks = [LOW, { reversibility: 0.5, blastRadius: 0.5, confidence: 0.5, semanticDistance: 0.5, taint: 0.5 }, { reversibility: 0, blastRadius: 1, confidence: 0, semanticDistance: 1, taint: 1 }];
  for (const [pname, pol] of [['tight', TIGHT], ['loose', LOOSE], ['flat', FLAT]] as const) {
    const SP = scenario({ policy: pol, tag: 'policy-' + pname });
    for (const node of ['n1', 'n2'] as const) for (const [i, rk] of risks.entries()) for (const bud of [{ B: 1, tau: NOW, asOf: NOW }, { B: 0, tau: NOW, asOf: NOW }]) {
      const opts = base(SP, node, { context: { risk: rk, budget: bud } });
      await add(SP.mk(node), opts, `policy/${pname}/${node}/risk${i}/B${bud.B}`);
      await add(SP.mk(node), merge(opts, { hooks: { threshold: H_T(3) } }), `policy-thr3/${pname}/${node}/risk${i}/B${bud.B}`);
    }
  }
  // delegated caveats on the task hop
  const sig = { props: { scope: { type: 'string', enum: ['all'] } }, required: ['scope'] };
  const AN = (P as any).agentNative ?? (P0 as any).agentNative;
  const delegated: [string, any[]][] = [
    ['tool_schema ok', [AN.toolSchemaCaveat('rotate_recovery_keys', sig)]], ['tool_schema strict', [AN.toolSchemaCaveat('rotate_recovery_keys', { props: { scope: { type: 'string', enum: ['mine'] } }, required: ['scope'] })]],
    ['tool_schema other tool', [AN.toolSchemaCaveat('other_tool', { props: {} })]], ['predicates in', [AN.predicatesCaveat([{ verb: 'rotate_recovery_keys', resource: 'account:me' }])]],
    ['predicates out', [AN.predicatesCaveat([{ verb: 'list_sessions', resource: 'session:*' }])]], ['expires past', [{ type: 'expires', at: NOW - 1 }]], ['max_spend', [{ type: 'max_spend', usd: 1 }]],
    ['delegation_depth 0', [{ type: 'delegation_depth', max: 0 }]], ['unknown caveat', [{ type: 'mystery' }]],
  ];
  for (const [dn, cav] of delegated) {
    const SD = scenario({ taskCaveats: cav, tag: 'deleg-' + dn.replace(/\W/g, '') });
    for (const node of ['n1', 'n2'] as const) await add(SD.mk(node), merge(base(SD, node, { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } }), { hooks: { threshold: H_T(3) } }), `delegated/${dn}/${node}`);
  }
}

// ================= 7. revocation epoch and liveness beacon (freshness / beacon checks) =================
{
  const nb = base(S, 'n1', { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } });
  const guardian = pkOf('guardian');
  const epochOf = (x: any = {}) => JSON.parse(ser(signRevocationEpoch(sk(x.signer ?? 'guardian'), { instance_id: 'inst', grant_ref: x.grant_ref ?? S.grant.id, epoch: x.epoch ?? 3, set_size: 0, root: 'r0', issued_at: x.issued_at ?? NOW - 1000, not_after: x.not_after ?? NOW + 100_000 })));
  const eps: [string, any, any][] = [
    ['ok', epochOf(), {}], ['grant other', epochOf({ grant_ref: 'other' }), {}], ['expired', epochOf({ not_after: NOW - 1 }), {}], ['future', epochOf({ issued_at: NOW + 120_000 }), {}], ['rollback', epochOf({ epoch: 2 }), { lastAcceptedEpoch: 3 }],
    ['not rollback', epochOf({ epoch: 3 }), { lastAcceptedEpoch: 3 }], ['maxAge', epochOf(), { maxAgeMs: 500 }], ['maxAge ok', epochOf(), { maxAgeMs: 5000 }], ['other signer', epochOf({ signer: 'other' }), {}],
    ['pcactn predates', epochOf({ epoch: 9 }), {}], ['tampered', { ...epochOf(), epoch: 4 }, {}], ['null epoch', null, {}],
  ];
  for (const [name, ep, x] of eps) {
    await add(A1, merge(nb, { context: { revocationEpoch: { epoch: ep, guardianPublic: guardian, ...x } } }), `epoch/${name}`);
    await add(S.mk('n1', { extra: { freshness: { beacon_ref: '', epoch: 5, accumulator_witness: '' } } }), merge(nb, { context: { revocationEpoch: { epoch: ep, guardianPublic: guardian, ...x } } }), `epoch-fresh5/${name}`);
    if (name === 'ok' || name === 'expired') await add(A1, merge(nb, { context: { revocationEpoch: { epoch: ep, guardianPublic: pkOf('other'), ...x } }, enforce: { freshness: { maxAgeMs: 1000 } } }), `epoch-wrongpin-gate/${name}`);
  }
  const bcn = (x: any = {}) => JSON.parse(ser(issueLivenessBeacon({ issuerSecret: sk(x.signer ?? 'principal'), instance: x.instance ?? 'inst', scope: x.scope ?? S.grant.id, seq: x.seq ?? 5, issuedAt: x.issuedAt ?? NOW - 1000, ...(x.validityMs ? { validityMs: x.validityMs } : {}) })));
  const bcs: [string, any, any, string[] | undefined, string | undefined][] = [
    ['ok', bcn(), {}, undefined, undefined], ['instance other', bcn({ instance: 'zz' }), {}, undefined, undefined], ['scope other', bcn({ scope: 'zz' }), {}, undefined, undefined], ['signer other', bcn({ signer: 'other' }), {}, undefined, undefined],
    ['expired', bcn({ issuedAt: NOW - 10 * 60_000 }), {}, undefined, undefined], ['replay', bcn({ seq: 2 }), { lastAcceptedSeq: 5 }, undefined, undefined], ['seq equal', bcn({ seq: 5 }), { lastAcceptedSeq: 5 }, undefined, undefined],
    ['issuers empty', bcn(), {}, [], undefined], ['unbound ref', bcn(), {}, undefined, 'unbound'],
  ];
  for (const [name, bc, x, issuers, refOverride] of bcs) {
    const ref0 = refOverride ?? beaconRef(bc);
    for (const withRef of [true, false]) await add(S.mk('n1', { beaconRef: withRef ? ref0 : '' }), merge(nb, { context: { beacon: { beacon: bc, issuers: issuers ?? [pkOf('principal')], instance: 'inst', ...x } } }), `beacon/${name}/ref${withRef}`);
  }
}

// ================= 8. hostile option shapes (fail-closed branches) =================
{
  const nb = base(S, 'n1', { context: { risk: LOW, budget: { B: 1, tau: NOW, asOf: NOW } } });
  for (const [name, x] of [['grant null', { grant: null }], ['grant string', { grant: 'g' }], ['grant empty', { grant: {} }], ['context null', { context: null }], ['context array', { context: [] }], ['plan not array', { context: { ...nb.context, plan: {} } }],
    ['plan with null', { context: { ...nb.context, plan: [null] } }], ['budget string', { context: { ...nb.context, budget: 'x' } }], ['budget NaN-ish', { context: { ...nb.context, budget: { B: null, tau: NOW } } }], ['risk string', { context: { ...nb.context, risk: 'x' } }],
    ['risk values strings', { context: { ...nb.context, risk: { reversibility: '1', blastRadius: '0', confidence: '1', semanticDistance: '0', taint: '0' } } }], ['risk out of range', { context: { ...nb.context, risk: { reversibility: 2, blastRadius: -1, confidence: 7, semanticDistance: 9, taint: -3 } } }],
    ['now string', { now: '1' }], ['require string', { require: 'revocation' }], ['require null', { require: null }], ['hooks empty', { hooks: {} }], ['audience number', { audience: 7 }]] as const)
    await add(A1, { ...nb, ...(x as any) }, `hostile/${name}`);
}

console.log('cases', o.cases.length);
// no private key may reach the corpus: scan the serialised cases for every seed this run derived
{
  const text = o.cases.map((c: any) => ser(c)).join('\n');
  for (const l of ['principal', 'agent', 'other', 'guardian']) if (text.includes(b64u(sk(l)))) throw new Error('private seed leaked into the corpus: ' + l);
}
const dist = new Map<string, number>();
for (const c of o.cases) { const k = ser({ a: c.out.allow, t: c.out.requiredThreshold, ch: c.out.checks, re: c.out.reasons }); dist.set(k, (dist.get(k) ?? 0) + 1); }
console.log('distinct verdict shapes', dist.size, 'allow', o.cases.filter((c: any) => c.out.allow === true).length, 'deny', o.cases.filter((c: any) => c.out.allow === false).length);
refWrite(o, 'verify-verdict');
