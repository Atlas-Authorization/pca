// Generates the shared PCA performance corpus (corpus format "pca-bench-corpus/1") on stdout.
//
//   node packages/pca-bench/gen-corpus.mjs > corpus.json            (after `pnpm --filter @atlasauth/pca build`)
//   npx tsx packages/pca-bench/gen-corpus.mjs > corpus.json         (PCA_REF=packages/pca/src/index.ts: straight from source)
//
// Deterministic: every key is derived from a seed label (seed(label, n), below); Ed25519, ML-DSA-65 signing and the
// canonical hash are deterministic, so two runs on any machine give identical bytes. Only PUBLIC data is written: grants,
// signed PCActns, public keys and expected hashes/signatures. The harnesses re-derive the signing secrets from `seed_labels`
// when they run the produce scenarios, so no private key is ever stored. Every scenario's expected verdict is checked
// against the TypeScript reference before anything is printed.
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const refUrl = process.env.PCA_REF ? pathToFileURL(process.env.PCA_REF).href : new URL('../pca/dist/index.js', import.meta.url).href;
const mod = await import(refUrl);
const pca = typeof mod.mintRoot === 'function' ? mod : mod.default;

export const CORPUS_FORMAT = 'pca-bench-corpus/1';
export const CORPUS_VERSION = 1;
const SEED_DOMAIN = 'pca-bench/v1/';
const NOW = 1_800_000_000_000;
const AUD = 'rs-bench';
const HYBRID = 'hybrid-ed25519-ml-dsa-65';

const sha = (s) => createHash('sha256').update(s).digest();
/** seed(label, n): the first n bytes of sha256(domain+label+"/0") || sha256(domain+label+"/1") || ... (the spec's one derivation). */
const seed = (label, n = 32) => {
  const out = [];
  for (let i = 0; out.length * 32 < n; i++) out.push(sha(`${SEED_DOMAIN}${label}/${i}`));
  return new Uint8Array(Buffer.concat(out).subarray(0, n));
};
const ed = (label) => {
  const secretKey = seed(label);
  return { secretKey, pub: pca.b64u(pca.publicKeyOf(secretKey)) };
};

const plan = [
  { id: 'n1', verb: 'read', resource: 'db/users', reversibility_class: 'reversible' },
  { id: 'n2', verb: 'read', resource: 'db/items', reversibility_class: 'reversible' },
];
const envelopeCaveat = {
  type: 'envelope',
  goal_commit: pca.goalCommitOf('bench', 'c2FsdA'),
  predicates: [{ verb: 'read', resource: 'db/*' }],
  caveats: [{ type: 'delegation_depth', max: 16 }],
  agent_binding: {},
  risk_policy: pca.DEFAULT_RISK_POLICY,
};
/** The caveat-heavy policy: `per` opaque caveats appended on every hop plus a monotone budget_alloc chain. */
const heavy = (hop, per) => [
  ...Array.from({ length: per }, (_, i) => ({ type: 'max_spend', usd: 1000 - hop * 10 - (i % 7), scope: `scope-${hop}-${i}`, label: `caveat-${hop}-${i}` })),
  pca.budgetAllocCaveat(1000 - hop * 50),
];

const principal = ed('principal');
const mlDsa = pca.mlDsa65Keygen(seed('mldsa65'));
const pqPk = pca.b64u(mlDsa.publicKey);

/**
 * One chain of `depth` hops: root (principal -> holder-0) then delegations. Every delegation hop and the leaf use `alg`
 * (ed25519 or the hybrid); the root stays Ed25519 unless pqRoot. `perHop` > 0 adds the caveat-heavy policy.
 */
function chain(alg, depth, { pqRoot = false, perHop = 0 } = {}) {
  const hybrid = alg === HYBRID;
  const suite = hybrid ? { alg, mlDsa } : undefined;
  const holders = Array.from({ length: depth }, (_, i) => ed(`holder-${i}`));
  const grant = pca.mintRoot({
    principalSecret: principal.secretKey,
    principalPublic: principal.pub,
    holder: holders[0].pub,
    ...(hybrid ? { holderPq: pqPk } : {}),
    caveats: [envelopeCaveat, ...(perHop ? heavy(0, perHop) : [])],
    ...(hybrid && pqRoot ? { suite } : {}),
  });
  const caps = [grant];
  for (let i = 1; i < depth; i++) {
    caps.push(pca.delegate(caps[i - 1], holders[i].pub, perHop ? heavy(i, perHop) : [], holders[i - 1].secretKey, suite, hybrid ? pqPk : undefined));
  }
  const leaf = holders[depth - 1];
  const base = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant, chain: caps, plan, nodeId: 'n1', counter: 1, signerSecret: leaf.secretKey });
  let pcactn = base;
  let body = null;
  if (hybrid) {
    const { sig: _s, ...b } = base;
    body = b;
    pcactn = pca.signPCActnSuite(b, { alg, edLeafSecret: leaf.secretKey, mlDsa });
  } else {
    const { sig: _s, ...b } = base;
    body = b;
  }
  return { grant, pcactn, body, leafLabel: `holder-${depth - 1}`, caps };
}

const plain = (v) => JSON.parse(JSON.stringify(v));
const clone = plain;
const verifyRef = (pcactn, grant, o = {}) => pca.verifyPCActnCore(pcactn, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: AUD, ...o });

const scenarios = [];
async function addVerify(id, group, c, expectAllow, extra = {}, ctx = {}) {
  const context = { now: ctx.now ?? NOW, aud: ctx.aud ?? AUD };
  // pca-core-verify: bench corpus generation checks the reference verdict; it never authorizes an action
  const r = await verifyRef(c.pcactn, c.grant, { nowEpoch: context.now, audience: context.aud });
  if (r.allow !== expectAllow) throw new Error(`${id}: reference verdict allow=${r.allow}, expected ${expectAllow} (${r.reason ?? ''})`);
  scenarios.push({ id, kind: 'verify', group, ...extra, grant: plain(c.grant), pcactn: plain(c.pcactn), context, expect: { allow: expectAllow } });
}

// ---- verify: allow paths (chain depth 1/3/8, classical and hybrid) -------------------------------------------------------
const CACHE = {};
for (const alg of ['ed25519', HYBRID]) {
  const tag = alg === 'ed25519' ? 'ed25519' : 'hybrid';
  for (const d of [1, 3, 8]) {
    const c = (CACHE[`${tag}.${d}`] = chain(alg, d));
    await addVerify(`verify.${tag}.d${d}`, 'verify', c, true, { suite: alg, depth: d, signature_checks: d + 1 });
  }
}
await addVerify('verify.hybrid-pqroot.d3', 'verify', chain(HYBRID, 3, { pqRoot: true }), true, { suite: HYBRID, depth: 3, signature_checks: 4 });
// ---- verify: caveat-heavy policy (24 opaque caveats + a budget_alloc per hop, 3 hops) ------------------------------------
await addVerify('verify.caveats.d3', 'verify', chain('ed25519', 3, { perHop: 24 }), true, { suite: 'ed25519', depth: 3, caveats_per_hop: 25 });

// ---- deny paths: each names the allow scenario it is derived from (`pair`); none may be slower than it (SPEC section 4) ---
const flip = (b64) => {
  const raw = Buffer.from(b64, 'base64url');
  raw[0] ^= 1;
  return raw.toString('base64url');
};
const denyOf = (tag, mut) => {
  const c = CACHE[tag];
  const p = clone(c.pcactn);
  mut(p);
  return { grant: c.grant, pcactn: p };
};
await addVerify('deny.hybrid.d8.leaf-sig', 'deny', denyOf('hybrid.8', (p) => { p.sig = flip(p.sig); }), false, { pair: 'verify.hybrid.d8' });
await addVerify('deny.hybrid.d8.pq-sig', 'deny', denyOf('hybrid.8', (p) => { p.pq_sig = flip(p.pq_sig); }), false, { pair: 'verify.hybrid.d8' });
await addVerify('deny.ed25519.d8.root-hop-sig', 'deny', denyOf('ed25519.8', (p) => { p.cap_chain[0].sig = flip(p.cap_chain[0].sig); }), false, { pair: 'verify.ed25519.d8' });
await addVerify('deny.ed25519.d8.audience', 'deny', CACHE['ed25519.8'], false, { pair: 'verify.ed25519.d8' }, { aud: 'rs-elsewhere' });
await addVerify('deny.ed25519.d8.expired', 'deny', CACHE['ed25519.8'], false, { pair: 'verify.ed25519.d8' }, { now: NOW + 7_200_000 });
await addVerify('deny.ed25519.d8.wire', 'deny', denyOf('ed25519.8', (p) => { delete p.action; }), false, { pair: 'verify.ed25519.d8' });
// 17 hops (one over the shared cap of 16), every signature genuine: only the hop limit may refuse it, and it must do so
// before the 17 signature checks, never after them.
await addVerify('deny.ed25519.d17.hop-limit', 'deny', chain('ed25519', 17), false, { pair: 'verify.ed25519.d8', depth: 17 });

// ---- canonicalize + hash -------------------------------------------------------------------------------------------------
for (const [id, tag] of [['canon.pcactn.ed25519.d3', 'ed25519.3'], ['canon.pcactn.hybrid.d8', 'hybrid.8']]) {
  const value = plain(CACHE[tag].pcactn);
  scenarios.push({ id, kind: 'canonicalize', group: 'canon', value, expect: { canonical_sha256: pca.hashCanonical(value) } });
}

// ---- produce / sign: the PCActn body + the leaf secret LABELS; the harness derives the secret and must reproduce the signature --
for (const [id, tag, alg] of [['sign.ed25519.d3', 'ed25519.3', 'ed25519'], ['sign.hybrid.d3', 'hybrid.3', HYBRID]]) {
  const c = CACHE[tag];
  const { sig, pq_sig, alg: a, pq_pk, ...rest } = plain(c.pcactn);
  void a; void pq_pk;
  scenarios.push({
    id, kind: 'sign', group: 'sign', suite: alg,
    body: rest, // the unsigned body: no sig / pq_sig / alg / pq_pk (the signer adds alg + pq_pk for a hybrid)
    seed_labels: { ed25519: c.leafLabel, ...(alg === HYBRID ? { ml_dsa_65: 'mldsa65' } : {}) },
    expect: { sig, ...(pq_sig !== undefined ? { pq_sig } : {}), ...(alg === HYBRID ? { pq_pk: pqPk, alg } : {}) },
  });
}

// ---- authorize: the full resource-server pipeline in single-step mode, as the lanes' shared authorize fixtures run it -----------
// One grant (principal -> agent) with a predicate that caps `payments.send` at 100 and a zero-weight risk policy (so the decision rests on
// binding, predicates, replay and provenance, which every lane ports). The action is a one-node plan. The server side: audience, clock,
// `plan: single-step`, the argument-provenance gate on (a principal-direct bundle under the mediator pinned from `provenance.seed_label`),
// a FRESH replay store per call (a stored counter would otherwise reject the second iteration), grant resolved by `grant_ref`, nothing revoked.
// `expect.allow` is checked against the TypeScript `createAuthorizer` before anything is written.
const AZ = { aud: 'payments-rs', now: Date.UTC(2026, 9, 25, 12, 0, 0), verb: 'payments.send', resource: 'payments/acme' };
const ZERO_RISK = { weights: { alpha: 0, beta: 0, gamma: 0, delta: 0, epsilon: 0, zeta: 0 }, theta1: 0.5, theta2: 0.8, kappa: 1, lambda: 0, rho: 0, bMax: 1_000 };
const agent = ed('azagent');
const azGrant = pca.mintGrant({
  principalSecret: principal.secretKey,
  principalPublic: principal.pub,
  holder: agent.pub,
  goal: 'pay invoices',
  envelope: { predicates: [{ verb: AZ.verb, resource: 'payments/*', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] }], caveats: [], agent_binding: {}, risk_policy: ZERO_RISK },
}).grant;
const azAction = (params) =>
  pca.buildPCActn({
    grant: azGrant,
    chain: [azGrant],
    plan: [{ id: 'n1', verb: AZ.verb, resource: AZ.resource, params_digest: pca.paramsDigest(params), reversibility_class: 'irreversible' }],
    nodeId: 'n1',
    params,
    counter: 1,
    signerSecret: agent.secretKey,
    aud: AZ.aud,
    now: AZ.now,
  });
const MEDIATOR = { mediator: 'bench-mediator', kid: 'k1', seed_label: 'mediator' };
const mediatorKey = seed(MEDIATOR.seed_label);
const recorder = () => pca.createProvenanceRecorder({ mediator: MEDIATOR.mediator, kid: MEDIATOR.kid, secretKey: mediatorKey });
const azRef = async (pcactn, operation, audience) => {
  const run = pca.createAuthorizer({
    audience,
    resolveGrant: async (ref) => (ref === azGrant.id ? azGrant : null),
    budgetStore: pca.atomicMemoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    plan: 'single-step',
    now: () => AZ.now,
    provenance: { mediators: [recorder().pin] },
  });
  return run({ pcactn, operation, provenance: pca.principalDirectProvenance(recorder(), operation) });
};
for (const [id, signed, executed, audience, allow] of [
  ['authorize.allow', 50, 50, AZ.aud, true],
  ['deny.authorize.policy', 400, 400, AZ.aud, false],
  ['deny.authorize.audience', 50, 50, 'rs-elsewhere', false],
]) {
  const pcactn = azAction({ amount: signed, currency: 'usd' });
  const operation = { verb: AZ.verb, resource: AZ.resource, params: { amount: executed, currency: 'usd' } };
  const r = await azRef(pcactn, operation, audience);
  if (r.allow !== allow) throw new Error(`${id}: reference authorize allow=${r.allow}, expected ${allow} (${r.reason ?? ''})`);
  scenarios.push({
    id, kind: 'authorize', group: allow ? 'authorize' : 'deny', ...(allow ? {} : { pair: 'authorize.allow' }),
    grant: plain(azGrant), pcactn: plain(pcactn), operation,
    server: { audience, now: AZ.now, plan: 'single-step', provenance: MEDIATOR },
    expect: { allow, status: r.status },
  });
}

const body = { format: CORPUS_FORMAT, version: CORPUS_VERSION, seed_domain: SEED_DOMAIN, now: NOW, aud: AUD, scenarios };
// the digest covers the scenarios only, so a harness can quote it without re-serialising anything else
const digest = createHash('sha256').update(JSON.stringify(scenarios)).digest('hex');
process.stdout.write(JSON.stringify({ ...body, digest }) + '\n');
