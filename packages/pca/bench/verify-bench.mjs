// PCActn verification benchmark (library level).
//
// Measures, per signature suite and capability-chain depth, the time to verify one PCActn with
//   - verifyPCActnCore : the stateless core checks (wire .. counter) that every native verifier implements, and
//   - verifyPCActn     : the full resource-server verifier (core + Policy VM + verdict combinator), for a subset,
// plus the threshold hook at t = 2 and t = 3. Every chain hop and the leaf are signed under the suite being
// measured, so a depth-d chain costs d hop verifications plus one leaf verification.
//
// Usage (from the repo root, after `pnpm --filter @atlasauth/pca build`):
//   node packages/pca/bench/verify-bench.mjs [--n 1000] [--warmup 50] [--out packages/pca/bench/results/verify.json]
//                                            [--suites ed25519,ml-dsa-65] [--depths 1,4,8]
// Results are JSON: one row per configuration with n, median/p95/mean/min/max (ms) and the PCActn size in bytes,
// plus the host description (CPU model, cores, memory, OS, Node version).
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { cpus, totalmem, release, platform, arch, hostname } from 'node:os';
import { dirname } from 'node:path';
import { performance } from 'node:perf_hooks';
import * as pca from '../dist/index.js';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
);
const N = Number(args.n ?? 1000);
const WARMUP = Number(args.warmup ?? 50);
const OUT = args.out ?? 'packages/pca/bench/results/verify.json';
const DEPTHS = (args.depths ?? '1,4,8').split(',').map(Number);

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

// One PQ key set per family, shared by every holder in a chain (each holder commits to it with holder_pq).
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
const SUITES = (args.suites ? args.suites.split(',') : Object.keys(SUITE_FAMILY)).filter((s) => {
  if (!(s in pca.SIG_SUITES)) throw new Error(`unknown suite ${s}`);
  if (SUITE_FAMILY[s] === 'lessCat1' && !(pca.isLessBackendActive?.() ?? false)) {
    console.error(`skip ${s}: LESS backend unavailable`);
    return false;
  }
  if (SUITE_FAMILY[s]?.startsWith('fnDsa') && !pca.isFnDsaBackendActive()) {
    console.error(`skip ${s}: FN-DSA backend unavailable`);
    return false;
  }
  return true;
});
const FULL_SUITES = new Set(['ed25519', 'hybrid-ed25519-ml-dsa-65', 'ml-dsa-65']);

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

const principal = ed('principal');
// Server-held context for the full verifier: the RS knows and has authorized the plan, vouches for zero-risk inputs
// and holds a full budget, so the measured path is an ADMIT at t = 1 (the common case for a low-risk action).
const fullContext = {
  plan,
  planAuthorized: true,
  risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
  budget: { B: 1, tau: NOW },
};
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

/** A PCActn whose root, every delegation hop and the leaf are signed under `alg`; chain length = depth. */
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
    ...(suite && !edRoot ? { suite: { alg, [fam]: familyKey(fam) } } : {}),
  });
  const chain = [grant];
  for (let i = 1; i < depth; i++) {
    chain.push(pca.delegate(chain[i - 1], holders[i].pub, [], holders[i - 1].secretKey, suite, pqPk));
  }
  const leaf = holders[depth - 1];
  const base = pca.buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant, chain, plan, nodeId: 'n1', counter: 1, signerSecret: leaf.secretKey });
  let pcactn = base;
  if (fam) {
    const { sig: _s, ...body } = base;
    pcactn = pca.signPCActnSuite(body, { alg, edLeafSecret: leaf.secretKey, [fam]: familyKey(fam) });
  }
  return { grant, pcactn, leaf };
}

function stats(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)];
  const mean = s.reduce((a, b) => a + b, 0) / s.length;
  const r = (x) => +x.toFixed(4);
  return { n: s.length, median_ms: r(q(0.5)), p95_ms: r(q(0.95)), p99_ms: r(q(0.99)), mean_ms: r(mean), min_ms: r(s[0]), max_ms: r(s[s.length - 1]) };
}

async function measure(fnc) {
  for (let i = 0; i < WARMUP; i++) await fnc();
  const xs = new Array(N);
  for (let i = 0; i < N; i++) {
    const t = performance.now();
    await fnc();
    xs[i] = performance.now() - t;
  }
  return stats(xs);
}

const rows = [];
const record = (row) => {
  rows.push(row);
  console.log(JSON.stringify(row));
};

for (const alg of SUITES) {
  for (const depth of DEPTHS) {
    const { grant, pcactn } = scenario(alg, depth);
    const bytes = Buffer.byteLength(JSON.stringify(pcactn));
    // pca-core-verify: allow benchmark that times the core verifier; it never authorizes an action
    const core = await pca.verifyPCActnCore(pcactn, { grant, nowEpoch: NOW, audience: AUD });
    if (!core.allow) throw new Error(`${alg} depth ${depth}: core verdict deny (${core.reason})`);
    // pca-core-verify: allow benchmark that times the core verifier; it never authorizes an action
    record({ bench: 'verifyPCActnCore', alg, root_alg: alg, depth, signature_checks: depth + 1, bytes, ...(await measure(() => pca.verifyPCActnCore(pcactn, { grant, nowEpoch: NOW, audience: AUD }))) });
    if (FULL_SUITES.has(alg)) {
      // The full verifier's Policy VM re-verifies the chain rooted at the grant issuer's Ed25519 key and is given no PQ
      // pin for the root (see bench/README.md), so a non-Ed25519 ROOT is denied there. Measure the deployed pattern
      // instead: an Ed25519-signed root grant, with every delegation hop and the leaf under `alg`.
      const f = alg === 'ed25519' ? { grant, pcactn } : scenario(alg, depth, { edRoot: true });
      const fBytes = Buffer.byteLength(JSON.stringify(f.pcactn));
      const call = () => pca.verifyPCActn(f.pcactn, { grant: f.grant, audience: AUD, now: NOW, context: fullContext });
      const v = await call();
      if (!v.allow) throw new Error(`${alg} depth ${depth}: full verdict deny (${JSON.stringify(v.reasons)})`);
      record({ bench: 'verifyPCActn', alg, root_alg: 'ed25519', depth, signature_checks: depth + 1, bytes: fBytes, ...(await measure(call)) });
    }
  }
}

// Threshold step-up: Ed25519 leaf plus guardian (t = 2) and guardian + principal (t = 3) shares, verified through the
// threshold hook of verifyPCActnCore. Baseline t = 1 uses the same hook with the leaf signature only.
{
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
      const p = shares.length ? { ...pcactn, threshold: pca.assembleThreshold(shares) } : pcactn;
      const hooks = { threshold: pca.createThresholdVerifier({ signerSet, t }) };
      // pca-core-verify: allow benchmark that times the core verifier; it never authorizes an action
      const r = await pca.verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: AUD, hooks });
      if (!r.allow || r.checks.threshold !== 'pass') throw new Error(`threshold t=${t}: ${r.reason}`);
      // pca-core-verify: allow benchmark that times the core verifier; it never authorizes an action
      record({ bench: 'verifyPCActnCore+threshold', alg: 'ed25519', depth, t, signature_checks: depth + 1 + t, bytes: Buffer.byteLength(JSON.stringify(p)), ...(await measure(() => pca.verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: AUD, hooks }))) });
    }
  }
}

const host = {
  hostname: hostname(),
  cpu_model: cpus()[0]?.model,
  logical_cpus: cpus().length,
  mem_gib: +(totalmem() / 2 ** 30).toFixed(1),
  os: `${platform()} ${release()} ${arch()}`,
  node: process.version,
  pinned_cpu: process.env.BENCH_CPU ?? null,
};
mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify({ tool: 'packages/pca/bench/verify-bench.mjs', date: new Date().toISOString(), n: N, warmup: WARMUP, now_epoch_ms: NOW, host, rows }, null, 2) + '\n');
console.log(`wrote ${OUT} (${rows.length} rows)`);
