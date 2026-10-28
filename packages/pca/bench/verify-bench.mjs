// PCActn verification benchmark (library level).
//
// Measures, per signature suite and capability-chain depth, the time to verify one PCActn with
//   - verifyPCActnCore : the stateless core checks (wire .. counter) that every native verifier implements, and
//   - verifyPCActn     : the full resource-server verifier (core + Policy VM + verdict combinator), for a subset,
// plus the threshold hook at t = 1, 2, 3. Every chain hop and the leaf are signed under the suite being measured, so a
// depth-d chain costs d hop verifications plus one leaf verification.
//
// Two phases, so that no signing happens inside a measured run:
//   1. --gen-fixtures FILE  build and sign every scenario (grants, PCActns, signer sets: public data only) and write them;
//      run one process per suite in parallel, then merge with bench/merge-fixtures.mjs.
//   2. --fixtures FILE      load the pre-signed scenarios and measure. Run one process per suite, each pinned to its own
//      core (taskset), then merge the result files with bench/merge-results.mjs. See bench/run-parallel.sh.
//
// Sampling: n = --n (default 1000) timed calls after --warmup calls. Suites listed in --adaptive (default: the SLH-DSA
// and LESS suites, the slowest) stop early, at n >= --min-n (200) once the distribution-free 95% confidence interval of
// the median is within +-2% of the median; otherwise they run to --n. Every row reports n and the CI.
//
// Usage (from the repo root, after `pnpm --filter @atlasauth/pca build`):
//   node packages/pca/bench/verify-bench.mjs --gen-fixtures /tmp/fx-ed25519.json --suites ed25519
//   node packages/pca/bench/verify-bench.mjs --fixtures packages/pca/bench/fixtures/verify-fixtures.json.gz \
//        --suites ed25519 --out /tmp/res-ed25519.json
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { cpus, totalmem, release, platform, arch } from 'node:os';
import { dirname } from 'node:path';
import { performance } from 'node:perf_hooks';
import { gunzipSync } from 'node:zlib';
import * as pca from '../dist/index.js';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const N = Number(args.n ?? 1000);
const MIN_N = Number(args['min-n'] ?? 200);
const REL_CI = Number(args['rel-ci'] ?? 0.02);
const WARMUP = Number(args.warmup ?? 50);
const OUT = args.out ?? 'packages/pca/bench/results/verify.json';
const DEPTHS = (args.depths ?? '1,4,8').split(',').map(Number);
const ADAPTIVE = new Set((args.adaptive ?? 'slh-dsa-sha2-128f,hybrid-ed25519-slh-dsa-sha2-128f,slh-dsa-sha2-256s,hybrid-ed25519-slh-dsa-sha2-256s,less-cat1,hybrid-ed25519-less-cat1').split(',').filter(Boolean));
const WITH_THRESHOLD = (args.threshold ?? 'auto') === 'auto' ? undefined : args.threshold === '1';

const NOW = 1_800_000_000_000;
const AUD = 'rs-bench';
const seed = (label, n = 32) => {
  const out = new Uint8Array(n);
  let blk = createHash('sha256').update(`pca-bench/${label}`).digest();
  for (let i = 0; i < n; ) {
    for (let j = 0; j < blk.length && i < n; j++, i++) out[i] = blk[j];
    blk = createHash('sha256').update(blk).digest();
  }
  return out;
};
const ed = (label) => {
  const secretKey = seed(label);
  return { secretKey, pub: pca.b64u(pca.publicKeyOf(secretKey)) };
};

const fn = (gen, label) => ({ ...gen(seed(label)), signSeed: seed(`${label}/sign`) });
const FAMILIES = {
  mlDsa: () => pca.mlDsa65Keygen(seed('mldsa65')),
  mlDsa87: () => pca.mlDsa87Keygen(seed('mldsa87')),
  slhDsa: () => pca.slhDsa128fKeygen(seed('slh128f', 48)),
  slhDsa256s: () => pca.slhDsa256sKeygen(seed('slh256s', 96)),
  fnDsa512: () => fn(pca.fnDsa512Keygen, 'fn512'),
  fnDsa1024: () => fn(pca.fnDsa1024Keygen, 'fn1024'),
  lessCat1: () => ({ ...pca.lessCat1Keygen(seed('less')), signSeed: seed('less/sign') }),
};
const SUITE_FAMILY = {
  ed25519: null,
  'ml-dsa-65': 'mlDsa',
  'hybrid-ed25519-ml-dsa-65': 'mlDsa',
  'hybrid-nested-ed25519-ml-dsa-65': 'mlDsa',
  'ml-dsa-87': 'mlDsa87',
  'hybrid-ed25519-ml-dsa-87': 'mlDsa87',
  'slh-dsa-sha2-128f': 'slhDsa',
  'hybrid-ed25519-slh-dsa-sha2-128f': 'slhDsa',
  'slh-dsa-sha2-256s': 'slhDsa256s',
  'hybrid-ed25519-slh-dsa-sha2-256s': 'slhDsa256s',
  'fn-dsa-512': 'fnDsa512',
  'fn-dsa-1024': 'fnDsa1024',
  'less-cat1': 'lessCat1',
  'hybrid-ed25519-less-cat1': 'lessCat1',
};
const SUITES = (args.suites ? args.suites.split(',') : Object.keys(SUITE_FAMILY)).filter(Boolean);
for (const s of SUITES) if (!(s in SUITE_FAMILY)) throw new Error(`unknown suite ${s}`);
const FULL_SUITES = new Set(['ed25519', 'hybrid-ed25519-ml-dsa-65', 'ml-dsa-65']);
// The threshold rows ride with the ed25519 process unless told otherwise.
const doThreshold = WITH_THRESHOLD ?? SUITES.includes('ed25519');

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
// Server-held context for the full verifier: the RS knows and has authorized the plan, vouches for zero-risk inputs
// and holds a full budget, so the measured path is an ADMIT at t = 1 (the common case for a low-risk action).
const fullContext = {
  plan,
  planAuthorized: true,
  risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
  budget: { B: 1, tau: NOW },
};

// ------------------------------------------------------------------------------------------------ fixture generation
const principal = ed('principal');
const keyCache = new Map();
const familyKey = (fam) => {
  if (!keyCache.has(fam)) keyCache.set(fam, FAMILIES[fam]());
  return keyCache.get(fam);
};
/** b64u pq_pk a suite binds for this key material (read back from a throwaway signature). */
const pqPkFor = (alg) => {
  const fam = SUITE_FAMILY[alg];
  const holder = ed('probe');
  const root = pca.mintRoot({ principalSecret: principal.secretKey, principalPublic: principal.pub, holder: holder.pub, caveats: [envelopeCaveat] });
  const base = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan, nodeId: 'n1', counter: 1, signerSecret: holder.secretKey });
  const { sig: _s, ...body } = base;
  return pca.signPCActnSuite(body, { alg, edLeafSecret: holder.secretKey, [fam]: familyKey(fam) }).pq_pk;
};

/** A PCActn whose root (unless edRoot), every delegation hop and the leaf are signed under `alg`; chain length = depth. */
function scenario(alg, depth, { edRoot = false } = {}) {
  const fam = SUITE_FAMILY[alg];
  const pqPk = fam ? pqPkFor(alg) : undefined;
  const suite = fam ? { alg, [fam]: familyKey(fam) } : undefined;
  const holders = Array.from({ length: depth }, (_, i) => ed(`holder-${i}`));
  const grant = pca.mintRoot({
    principalSecret: principal.secretKey,
    principalPublic: principal.pub,
    holder: holders[0].pub,
    ...(pqPk ? { holderPq: pqPk } : {}),
    caveats: [envelopeCaveat],
    ...(suite && !edRoot ? { suite } : {}),
  });
  const chain = [grant];
  for (let i = 1; i < depth; i++) chain.push(pca.delegate(chain[i - 1], holders[i].pub, [], holders[i - 1].secretKey, suite, pqPk));
  const leaf = holders[depth - 1];
  const base = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant, chain, plan, nodeId: 'n1', counter: 1, signerSecret: leaf.secretKey });
  let pcactn = base;
  if (fam) {
    const { sig: _s, ...body } = base;
    pcactn = pca.signPCActnSuite(body, { alg, edLeafSecret: leaf.secretKey, [fam]: familyKey(fam) });
  }
  return { grant, pcactn, leaf };
}

function genFixtures(file) {
  const out = { now_epoch_ms: NOW, aud: AUD, suites: {}, threshold: [] };
  for (const alg of SUITES) {
    out.suites[alg] = {};
    for (const depth of DEPTHS) {
      const { grant, pcactn } = scenario(alg, depth);
      const row = { grant, pcactn };
      if (FULL_SUITES.has(alg) && alg !== 'ed25519') {
        // The full verifier's Policy VM re-verifies the chain without the verifier's PQ pin (see bench/README.md), so a
        // non-Ed25519 ROOT is denied there: its rows use an Ed25519 root with every hop and the leaf under `alg`.
        const f = scenario(alg, depth, { edRoot: true });
        row.full = { grant: f.grant, pcactn: f.pcactn };
      }
      out.suites[alg][depth] = row;
    }
  }
  if (doThreshold) {
    const guardian = ed('guardian');
    for (const depth of [1, 4]) {
      const { grant, pcactn, leaf } = scenario('ed25519', depth);
      const signerSet = [
        { role: 'agent', publicKey: leaf.pub },
        { role: 'guardian', publicKey: guardian.pub },
        { role: 'principal', publicKey: principal.pub },
      ];
      for (const t of [1, 2, 3]) {
        const msg = pca.thresholdMessage(pcactn);
        const shares = [];
        if (t >= 2) shares.push(pca.signShare('guardian', guardian.secretKey, msg, { signerSet, t }));
        if (t >= 3) shares.push(pca.signShare('principal', principal.secretKey, msg, { signerSet, t }));
        out.threshold.push({ depth, t, signerSet, grant, pcactn: shares.length ? { ...pcactn, threshold: pca.assembleThreshold(shares) } : pcactn });
      }
    }
  }
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(out));
  console.log(`wrote fixtures ${file} (${SUITES.join(',')}${doThreshold ? ' + threshold' : ''})`);
}

// ------------------------------------------------------------------------------------------------ measurement
/** Distribution-free 95% CI of the median: order statistics j..k with j, k from the binomial(n, 1/2) normal approx. */
function medianCI(sorted) {
  const n = sorted.length;
  const h = 1.96 * Math.sqrt(n) / 2;
  const j = Math.max(0, Math.floor(n / 2 - h) - 1);
  const k = Math.min(n - 1, Math.ceil(n / 2 + h));
  return [sorted[j], sorted[k]];
}
function stats(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)];
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  const [lo, hi] = medianCI(s);
  const r = (x) => +x.toFixed(4);
  return { n: s.length, median_ms: r(q(0.5)), median_ci95_ms: [r(lo), r(hi)], p95_ms: r(q(0.95)), p99_ms: r(q(0.99)), mean_ms: r(mean), min_ms: r(s[0]), max_ms: r(s[s.length - 1]) };
}
const ciOk = (xs) => {
  const s = [...xs].sort((a, b) => a - b);
  const med = s[Math.ceil(0.5 * s.length) - 1];
  const [lo, hi] = medianCI(s);
  return Math.max(med - lo, hi - med) <= REL_CI * med;
};

async function measure(fnc, adaptive) {
  for (let i = 0; i < WARMUP; i++) await fnc();
  const xs = [];
  while (xs.length < N) {
    const t = performance.now();
    await fnc();
    xs.push(performance.now() - t);
    if (adaptive && xs.length >= MIN_N && xs.length % 25 === 0 && ciOk(xs)) break;
  }
  return { ...stats(xs), sampling: adaptive ? `adaptive (stop at n>=${MIN_N} when the median's 95% CI is within +-${REL_CI * 100}%, cap ${N})` : `fixed n=${N}` };
}

async function runMeasure(file) {
  const raw = readFileSync(file);
  const fx = JSON.parse((file.endsWith('.gz') ? gunzipSync(raw) : raw).toString('utf8'));
  if (fx.now_epoch_ms !== NOW || fx.aud !== AUD) throw new Error('fixture constants differ from this script');
  const rows = [];
  const record = (row) => {
    rows.push(row);
    console.log(JSON.stringify(row));
  };
  for (const alg of SUITES) {
    const per = fx.suites[alg];
    if (!per) throw new Error(`no fixtures for ${alg}`);
    const adaptive = ADAPTIVE.has(alg);
    for (const depth of DEPTHS) {
      const { grant, pcactn, full } = per[depth];
      const bytes = Buffer.byteLength(JSON.stringify(pcactn));
      // pca-core-verify: allow benchmark that times the core verifier; it never authorizes an action
      const core = await pca.verifyPCActnCore(pcactn, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: AUD });
      if (!core.allow) throw new Error(`${alg} depth ${depth}: core verdict deny (${core.reason})`);
      // pca-core-verify: allow benchmark that times the core verifier; it never authorizes an action
      record({ bench: 'verifyPCActnCore', alg, root_alg: alg, depth, signature_checks: depth + 1, bytes, ...(await measure(() => pca.verifyPCActnCore(pcactn, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: AUD }), adaptive)) });
      if (FULL_SUITES.has(alg)) {
        // Prefer the same chain as the core rows (root signed under `alg`). Releases whose full verifier refuses a
        // non-Ed25519 root (0.4.1) fall back to the Ed25519-root variant; `root_alg` records which one was measured.
        const pqPins = alg === 'ed25519' ? undefined : { [grant.issuer]: grant.pq_pk };
        const same = (p, g) => pca.verifyPCActn(p, { insecureSkipPlanRootCheck: true, grant: g, audience: AUD, now: NOW, context: fullContext, ...(pqPins && g === grant ? { pqPins } : {}) });
        let f = { grant, pcactn, rootAlg: alg };
        if (!(await same(pcactn, grant)).allow && full) f = { ...full, rootAlg: 'ed25519' };
        const call = () => same(f.pcactn, f.grant);
        const v = await call();
        if (!v.allow) throw new Error(`${alg} depth ${depth}: full verdict deny (${JSON.stringify(v.reasons)})`);
        record({ bench: 'verifyPCActn', alg, root_alg: f.rootAlg, depth, signature_checks: depth + 1, bytes: Buffer.byteLength(JSON.stringify(f.pcactn)), ...(await measure(call, adaptive)) });
      }
    }
  }
  if (doThreshold) {
    for (const { depth, t, signerSet, grant, pcactn } of fx.threshold) {
      const hooks = { threshold: pca.createThresholdVerifier({ signerSet, t }) };
      // pca-core-verify: allow benchmark that times the core verifier; it never authorizes an action
      const r = await pca.verifyPCActnCore(pcactn, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: AUD, hooks });
      if (!r.allow || r.checks.threshold !== 'pass') throw new Error(`threshold t=${t}: ${r.reason}`);
      // pca-core-verify: allow benchmark that times the core verifier; it never authorizes an action
      record({ bench: 'verifyPCActnCore+threshold', alg: 'ed25519', depth, t, signature_checks: depth + 1 + (t - 1), bytes: Buffer.byteLength(JSON.stringify(pcactn)), ...(await measure(() => pca.verifyPCActnCore(pcactn, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: AUD, hooks }), false)) });
    }
  }
  const host = {
    cpu_model: cpus()[0]?.model,
    logical_cpus: cpus().length,
    mem_gib: +(totalmem() / 2 ** 30).toFixed(1),
    os: `${platform()} ${release()} ${arch()}`,
    node: process.version,
    pinned_cpu: process.env.BENCH_CPU ?? null,
  };
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify({ tool: 'packages/pca/bench/verify-bench.mjs', date: new Date().toISOString(), suites: SUITES, n_cap: N, min_n: MIN_N, rel_ci: REL_CI, warmup: WARMUP, now_epoch_ms: NOW, host, rows }, null, 2) + '\n');
  console.log(`wrote ${OUT} (${rows.length} rows)`);
}

if (args['gen-fixtures']) genFixtures(args['gen-fixtures']);
else if (args.fixtures) await runMeasure(args.fixtures);
else throw new Error('pass --gen-fixtures FILE or --fixtures FILE');
