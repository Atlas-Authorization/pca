#!/usr/bin/env node
// Builds the versioned, hash-pinned PCA Verified corpus (corpus/corpus.jsonl.gz + corpus/manifest.json) from the shared
// conformance vector files of the PCA repository. Pure Node, no network, deterministic. The published package ships the
// OUTPUT; this script only runs in the PCA repository.
//   node scripts/build-corpus.mjs            write corpus/
//   node scripts/build-corpus.mjs --check    fail when corpus/ differs from a fresh build (decompressed content compared)
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync, gzipSync } from 'node:zlib';
import { REGISTERED_SUITES, suitesOf } from '../../../tools/pca-diff-fuzz/suites.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = join(HERE, '..');
const CONF = join(PKG, '../pca/conformance');
// Bump when the corpus content changes (a statement binds this version and the content hash).
// The base corpus (committed vector files) is 1.0.0; the corpus extended with the generated adversarial / mutation items and the
// regression vectors (--reference-items) is 1.1.0.
const REF_ITEMS = (() => { const i = process.argv.indexOf('--reference-items'); return i >= 0 ? process.argv[i + 1] : null; })();
const OUT_DIR = (() => { const i = process.argv.indexOf('--out'); return i >= 0 ? process.argv[i + 1] : join(PKG, 'corpus'); })();
const CORPUS_VERSION = REF_ITEMS ? '1.1.0' : '1.0.0';
const PROTOCOL_VERSION = '1';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const readJson = (f) => { const b = readFileSync(join(CONF, f)); return JSON.parse((f.endsWith('.gz') ? gunzipSync(b) : b).toString('utf8')); };
const sources = {};
const src = (f) => { sources[f] = sha256(readFileSync(join(CONF, f))); return f; };

const CHECK_ORDER = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format', 'intent'];
const LAYER_OF_CHECK = { wire: 'wire', version: 'wire', audience: 'proof', validity: 'proof', chain: 'capability', grant_ref_bound: 'capability', plan_inclusion: 'proof', leaf_signature: 'proof', counter_format: 'proof', intent: 'policy' };
// The gate keeps these `requires` vectors (the cross-implementation suites); other `requires` tags belong to each SDK's own suite.
const CROSS_SUITES = new Set(['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65']);

const PROFILES = {
  'core-verifier': {
    title: 'Core Verifier',
    description: 'Verifies PCActns: strict wire format, proofs, delegation chains, policy caveats, and a truthful suite manifest. A suite the implementation does not declare must be refused, never accepted.',
    layers: ['wire', 'proof', 'capability', 'policy', 'suites'],
  },
  producer: {
    title: 'Producer',
    description: 'Signs and builds PCA artifacts: every producer vector must reproduce the reference output byte for byte (an undeclared suite may be refused).',
    layers: ['producer'],
  },
  pq: {
    title: 'Post-quantum',
    description: 'Verifies the post-quantum and hybrid suites: declares at least ML-DSA-65 and the Ed25519 + ML-DSA-65 hybrid and verifies every vector that uses only declared suites.',
    layers: ['wire', 'proof', 'capability', 'policy'],
    requires_suites: ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'],
  },
  stateful: {
    title: 'Stateful',
    description: 'Runs ordered sequences against one store: replay, counter ordering, revocation mid-sequence, trust-budget depletion.',
    layers: ['stateful'],
  },
};

const items = [];
const seen = new Set();
const push = (it) => {
  const profiles = it.layer === 'producer' ? ['producer'] : it.layer === 'stateful' ? ['stateful'] : ['core-verifier', ...(it.pq ? ['pq'] : [])];
  if (it.suites && !it.suites.length) delete it.suites;
  if (!it.pq) delete it.pq;
  items.push({ ...it, profiles });
};
const idOf = (prefix, n) => `${prefix}-${String(n).padStart(4, '0')}`;
const pqOf = (suites) => suites.some((s) => s !== 'ed25519');

// ---- suites manifest
push({ id: 'suites-manifest', layer: 'suites', kind: 'suites', name: 'suite manifest', send: { kind: 'suites', raw: '', grant: '', now: 0, aud: '' }, expect: {} });

// ---- PCActn verify vectors: curated core + the full adversarial set (names are unique across both)
function addVectors(file, prefix, filterRequires) {
  const d = readJson(src(file));
  let n = 0;
  for (const v of d.vectors) {
    if (seen.has(v.name)) continue;
    if (filterRequires && v.requires && !CROSS_SUITES.has(v.requires)) continue;
    seen.add(v.name);
    const raw = v.pcactn_json ?? JSON.stringify(v.pcactn);
    const c = v.context;
    const send = { kind: 'verify', raw, grant: JSON.stringify(v.grant), now: c.now, aud: c.aud };
    for (const k of ['allowed_suites', 'intent_policy', 'intent_policy_json', 'intent_v2']) if (c[k] !== undefined) send[k] = c[k];
    const suites = suitesOf(raw, c.intent_v2);
    const checks = v.expect.checks;
    const failed = CHECK_ORDER.find((k) => k in checks && checks[k] === false);
    const layer = v.expect.allow ? 'proof' : LAYER_OF_CHECK[failed] ?? 'proof';
    push({ id: idOf(prefix, n++), layer, kind: 'verify', name: v.name, send, expect: { allow: v.expect.allow, checks }, suites, pq: pqOf(suites) });
  }
}
addVectors('vectors.json', 'vec', true);
addVectors('vectors-adversarial.json.gz', 'adv', false);

// ---- wire: strict JSON profile (accept -> canonical form, reject -> no canonical form)
function addJsonParse(tables, prefix) {
  let n = 0;
  for (const t of tables) {
    for (const j of t) {
      if (seen.has('jp:' + j.input)) continue;
      seen.add('jp:' + j.input);
      push({ id: idOf(prefix, n++), layer: 'wire', kind: 'canon', name: `json_parse ${JSON.stringify(j.input).slice(0, 60)}`, send: { kind: 'canon', raw: j.input, grant: '', now: 0, aud: '' }, expect: j.accept ? { accept: true, canon: j.canonical } : { accept: false } });
    }
  }
}
const core = readJson('vectors.json');
const adv = readJson('vectors-adversarial.json.gz');
addJsonParse([core.primitives.json_parse, adv.primitives.json_parse], 'json');

// ---- capability: the standalone chain API with verifier-side pins
{
  let n = 0;
  for (const v of core.primitives.chain_pin) {
    if (v.requires && !CROSS_SUITES.has(v.requires)) continue;
    const raw = JSON.stringify({ chain: v.chain, expected_root_issuer: v.expected_root_issuer, ...(v.pq_pins !== undefined ? { pq_pins: v.pq_pins } : {}), ...(v.trusted_root !== undefined ? { trusted_root: v.trusted_root } : {}), ...(v.allowed_suites !== undefined ? { allowed_suites: v.allowed_suites } : {}) });
    const suites = suitesOf(raw);
    push({ id: idOf('pin', n++), layer: 'capability', kind: 'chain', name: v.name, send: { kind: 'chain', raw, grant: '', now: 0, aud: '' }, expect: { ok: v.expect.ok }, suites, pq: pqOf(suites) });
  }
}

// ---- policy: the caveat projection (and, when a driver answers it, the whole decision)
{
  const d = readJson(src('policy-vectors.json'));
  d.policy_decision.forEach((v, i) => push({ id: idOf('pol', i), layer: 'policy', kind: 'policy', name: v.name, send: { kind: 'policy', raw: JSON.stringify({ grant: v.grant, chain: v.chain, context: v.context }), grant: '', now: 0, aud: '' }, expect: { caveats: v.expect.caveats, decision: v.expect.decision } }));
}

// ---- producer: signing vectors (keys are shared per file and re-attached when the line is sent)
const keysets = {};
{
  const ed = readJson(src('producer-vectors.json'));
  keysets.producer = { keys: ed.keys };
  ed.cases.forEach((c, i) => push({ id: idOf('prod', i), layer: 'producer', kind: 'produce', name: c.name, produce: { op: c.op, args: c.args, keyset: 'producer' }, expect: c.expect }));
  const pq = readJson(src('producer-pq-vectors.json'));
  keysets['producer-pq'] = { keys: pq.ed_keys, pq_keys: pq.pq_keys };
  let n = 0;
  // deterministic cases only: the ones every reference language reproduces byte for byte
  for (const c of pq.cases) {
    if ((c.exact ?? []).length < 8) continue;
    const alg = c.args.alg ?? c.args.family;
    const suites = typeof alg === 'string' && REGISTERED_SUITES.includes(alg) ? [alg] : [];
    push({ id: idOf('prodpq', n++), layer: 'producer', kind: 'produce', name: c.name, produce: { op: c.op, args: c.args, keyset: 'producer-pq' }, expect: c.expect, suites, pq: pqOf(suites) });
  }
}

// ---- stateful: the sequence is sent without its expectations
{
  const d = readJson(src('stateful-vectors.json'));
  d.stateful.forEach((s, i) => {
    const steps = s.steps.map(({ expect: _e, ...rest }) => rest);
    push({ id: idOf('st', i), layer: 'stateful', kind: 'stateful', name: s.name, send: { kind: 'stateful', raw: JSON.stringify({ setup: s.setup, steps }), grant: '', now: 0, aud: '' }, expect: { steps: s.steps.map((x) => (x.op === 'present' ? x.expect : null)) } });
  });
}

// ---- generated adversarial / mutation items and regression vectors, with the reference verdicts computed at build time
const extended = { adversarial: 0, regressions: 0, waived: 0, skipped: 0 };
if (REF_ITEMS) {
  const known = existsSync(join(CONF, '../../pca-conformance/adversarial/known-differences.json')) ? JSON.parse(readFileSync(join(CONF, '../../pca-conformance/adversarial/known-differences.json'), 'utf8')) : [];
  const waived = new Set(known.map((k) => k.vector));
  // categories already present as curated vectors (they are the committed vector files)
  const COVERED = new Set(['golden', 'golden-json', 'pq-binding', 'chain-pin']);
  for (const line of readFileSync(REF_ITEMS, 'utf8').split('\n').filter(Boolean)) {
    const g = JSON.parse(line);
    if (COVERED.has(g.category)) continue;
    if (waived.has(`${g.category}/${g.name}`)) { extended.waived++; continue; }
    const r = g.ref;
    // a canon reference refusal is `{error: 'parse'}` (the verdict); any other error is the reference itself failing: no expectation
    if (r.error !== undefined && !(g.kind === 'canon' && r.error === 'parse')) { extended.skipped++; continue; }
    const base = { id: `${g.source === 'regression' ? '' : 'gen-'}${g.id}`, name: `${g.category}/${g.name}`, soft: true };
    if (g.kind === 'canon') {
      push({ ...base, layer: 'wire', kind: 'canon', send: { kind: 'canon', raw: g.raw, grant: '', now: 0, aud: '' }, expect: r.canon !== undefined ? { accept: true, canon: r.canon } : { accept: false } });
    } else if (g.kind === 'chain') {
      const suites = suitesOf(g.raw);
      push({ ...base, layer: 'capability', kind: 'chain', send: { kind: 'chain', raw: g.raw, grant: '', now: 0, aud: '' }, expect: { ok: r.allow === true }, suites, pq: pqOf(suites) });
    } else {
      const send = { kind: 'verify', raw: g.raw, grant: g.grant, now: g.now, aud: g.aud };
      for (const k of ['allowed_suites', 'intent_policy', 'intent_policy_json', 'intent_v2']) if (g[k] !== undefined) send[k] = g[k];
      const suites = suitesOf(g.raw, g.intent_v2);
      const failed = CHECK_ORDER.find((k) => k in r.checks && r.checks[k] === false);
      push({ ...base, layer: r.allow ? 'proof' : LAYER_OF_CHECK[failed] ?? 'proof', kind: 'verify', send, expect: { allow: r.allow, checks: r.checks }, suites, pq: pqOf(suites) });
    }
    if (g.source === 'regression') extended.regressions++; else extended.adversarial++;
  }
}

// ---- assemble
const counts = (pred) => { const o = {}; for (const it of items) if (pred(it)) o[it.layer] = (o[it.layer] ?? 0) + 1; return o; };
const profiles = {};
for (const [id, p] of Object.entries(PROFILES)) {
  const its = items.filter((it) => it.profiles.includes(id));
  profiles[id] = { ...p, items: its.length, layer_items: counts((it) => it.profiles.includes(id)) };
}
const header = { corpus: { version: CORPUS_VERSION, protocol: PROTOCOL_VERSION, registered_suites: REGISTERED_SUITES, keysets } };
const text = [JSON.stringify(header), ...items.map((it) => JSON.stringify(it))].join('\n') + '\n';
const hash = sha256(text);
const manifest = { format: 'pca-verified-corpus/1', corpus_version: CORPUS_VERSION, protocol_version: PROTOCOL_VERSION, sha256: hash, bytes: Buffer.byteLength(text), items: items.length, layers: counts(() => true), profiles, registered_suites: REGISTERED_SUITES, sources, ...(REF_ITEMS ? { extended } : {}) };
const manifestText = JSON.stringify(manifest, null, 2) + '\n';

const gzPath = join(PKG, 'corpus/corpus.jsonl.gz');
const manPath = join(PKG, 'corpus/manifest.json');
const outGz = join(OUT_DIR, 'corpus.jsonl.gz');
const outMan = join(OUT_DIR, 'manifest.json');
if (process.argv.includes('--check')) {
  const okGz = existsSync(gzPath) && gunzipSync(readFileSync(gzPath)).toString('utf8') === text;
  const okMan = existsSync(manPath) && readFileSync(manPath, 'utf8') === manifestText;
  if (!okGz || !okMan) { console.error('corpus/ is stale: run `node scripts/build-corpus.mjs` and commit the result'); process.exit(1); }
  console.log(`corpus ok: ${items.length} items, sha256 ${hash}`);
} else {
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(outGz, gzipSync(Buffer.from(text), { level: 9 }));
  writeFileSync(outMan, manifestText);
  console.log(`wrote ${items.length} items, ${text.length} bytes, sha256 ${hash}`);
}
