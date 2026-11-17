// TypeScript flagship harness (tinybench). Reads the shared corpus, writes one pca-bench-result/1 JSON.
//
//   node packages/pca-bench/bench.mjs --corpus corpus.json --out result-ts.json [--time 1500] [--min-samples 200]
//   (PCA_REF=<entry> to bench another build of the flagship: default ../pca/dist/index.js)
//
// Per scenario: warm up, then time every call individually (tinybench records one sample per call), and summarise with the
// shared lib (p50/p95/p99, ops/s, 7 time-ordered rounds). Cold start is the first call in a fresh process, taken before any
// warm-up. Allocation counts are not exposed by the runtime (null).
import { readFileSync, writeFileSync } from 'node:fs';
import { cpus, arch, platform } from 'node:os';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { Bench } from 'tinybench';
import { RESULT_SCHEMA, summarize } from './lib.mjs';

const args = Object.fromEntries(process.argv.slice(2).reduce((a, x, i, all) => (x.startsWith('--') ? [...a, [x.slice(2), all[i + 1]]] : a), []));
const TIME = Number(args.time ?? 1500);
const MIN = Number(args['min-samples'] ?? 200);
const corpus = JSON.parse(readFileSync(args.corpus ?? 'corpus.json', 'utf8'));
const refUrl = process.env.PCA_REF ? pathToFileURL(process.env.PCA_REF).href : new URL('../pca/dist/index.js', import.meta.url).href;
const mod = await import(refUrl);
const pca = typeof mod.verifyPCActnCore === 'function' ? mod : mod.default;
const pkg = JSON.parse(readFileSync(new URL('../pca/package.json', import.meta.url), 'utf8'));

const seed = (label, n = 32) => {
  const out = [];
  for (let i = 0; out.length * 32 < n; i++) out.push(Buffer.from(pca.sha256(pca.utf8(`${corpus.seed_domain}${label}/${i}`))));
  return new Uint8Array(Buffer.concat(out).subarray(0, n));
};

/** Build [setup-check, op] for a scenario. The op is the measured unit; the check proves it computes the recorded answer. */
function prepare(s) {
  switch (s.kind) {
    case 'verify': {
      // pca-core-verify: benchmark of the core verifier; it never authorizes an action
      const op = () => pca.verifyPCActnCore(s.pcactn, { insecureSkipPlanRootCheck: true, grant: s.grant, nowEpoch: s.context.now, audience: s.context.aud });
      return { op, check: async () => (await op()).allow === s.expect.allow };
    }
    case 'authorize': {
      // the full pipeline, a fresh replay store and authorizer per call; the provenance bundle is the mediator's work and is built once here
      const sv = s.server;
      const rec = () => pca.createProvenanceRecorder({ mediator: sv.provenance.mediator, kid: sv.provenance.kid, secretKey: seed(sv.provenance.seed_label) });
      const pin = rec().pin;
      const bundle = pca.principalDirectProvenance(rec(), s.operation);
      const op = () =>
        pca.createAuthorizer({
          audience: sv.audience,
          resolveGrant: async (ref) => (ref === s.grant.id ? s.grant : null),
          budgetStore: pca.atomicMemoryPcaStore(),
          hooks: { revocation: () => ({ enforced: true, ok: true }) },
          plan: sv.plan,
          now: () => sv.now,
          provenance: { mediators: [pin] },
        })({ pcactn: s.pcactn, operation: s.operation, provenance: bundle });
      return { op, check: async () => (await op()).allow === s.expect.allow };
    }
    case 'canonicalize': {
      const op = () => pca.hashCanonical(s.value);
      return { op, check: async () => op() === s.expect.canonical_sha256 };
    }
    case 'sign': {
      const ed = seed(s.seed_labels.ed25519);
      const hybrid = s.suite !== 'ed25519';
      const mlDsa = hybrid ? pca.mlDsa65Keygen(seed(s.seed_labels.ml_dsa_65)) : undefined;
      const op = () => (hybrid ? pca.signPCActnSuite(s.body, { alg: s.suite, edLeafSecret: ed, mlDsa }) : pca.signPCActn(s.body, ed));
      return { op, check: async () => { const r = op(); return r.sig === s.expect.sig && (s.expect.pq_sig === undefined || r.pq_sig === s.expect.pq_sig); } };
    }
    default:
      throw new Error(`unknown scenario kind ${s.kind}`);
  }
}

// ---- cold start: the very first calls of this process, before warm-up ----
const cold = {};
const prepared = new Map();
for (const s of corpus.scenarios) prepared.set(s.id, prepare(s));
for (const id of ['verify.ed25519.d1', 'verify.hybrid.d1']) {
  const p = prepared.get(id);
  if (!p) continue;
  const t = performance.now();
  await p.op();
  cold[id] = Math.round((performance.now() - t) * 1e6);
}

const out = [];
for (const s of corpus.scenarios) {
  const row = { id: s.id, kind: s.kind, group: s.group, ...(s.pair ? { pair: s.pair } : {}) };
  try {
    const p = prepared.get(s.id);
    if (!(await p.check())) throw new Error('result differs from the corpus expectation');
    const bench = new Bench({ time: TIME, warmupTime: 200, iterations: MIN, warmupIterations: 20 });
    bench.add(s.id, p.op);
    await bench.run();
    const r = bench.tasks[0].result;
    const samplesMs = r.samples ?? r.latency?.samples;
    if (!samplesMs || samplesMs.length < MIN) throw new Error(`only ${samplesMs?.length ?? 0} samples`);
    Object.assign(row, { status: 'ok', ...summarize(samplesMs.map((ms) => ms * 1e6), 7), allocs_per_op: null, bytes_per_op: null, samples: samplesMs.length });
  } catch (e) {
    Object.assign(row, { status: 'error', note: String(e?.message ?? e) });
  }
  out.push(row);
  console.error(`${row.status} ${s.id}${row.status === 'ok' ? ` p50=${(row.p50_ns / 1e3).toFixed(1)}us` : ` ${row.note}`}`);
}

const result = {
  schema: RESULT_SCHEMA,
  lang: 'ts',
  impl: '@atlasauth/pca',
  impl_version: pkg.version,
  tool: 'tinybench',
  runtime: `node ${process.version}`,
  runner: { os: platform(), arch: arch(), cpu: cpus()[0]?.model ?? 'unknown', cores: cpus().length },
  corpus: { version: corpus.version, digest: corpus.digest },
  cold_start_ns: cold,
  scenarios: out,
};
writeFileSync(args.out ?? 'result-ts.json', JSON.stringify(result, null, 1) + '\n');
