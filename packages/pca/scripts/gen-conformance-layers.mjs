// The layer manifest (conformance/LAYERS.md): conformance/layers.json tags every committed conformance vector with exactly
// one layer (scripts/conformance-layers.mjs) and records per-layer counts, which sections each layer is made of, and how
// each section is gated. Fails when a `primitives` table or a conformance vector file has no layer, so a new section must
// be tagged before it can be committed.
//
//     node packages/pca/scripts/gen-conformance-layers.mjs [--check]
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { confDir, readAdversarial, readCore } from './conformance-io.mjs';
import { CHECK_LAYER, CHECK_ORDER, FILE_LAYER, LAYERS, LAYER_IDS, TABLE_LAYER, layerOfVerdict } from './conformance-layers.mjs';

const OUT = join(confDir, 'layers.json');
const read = (f) => JSON.parse(readFileSync(join(confDir, f), 'utf8'));
const zero = () => Object.fromEntries(LAYER_IDS.map((l) => [l, 0]));

function tagCorpus(doc, label) {
  const counts = zero();
  const tables = {};
  for (const [t, entries] of Object.entries(doc.primitives ?? {})) {
    const layer = TABLE_LAYER[t];
    if (!layer) throw new Error(`${label}: primitives.${t} has no layer (add it to TABLE_LAYER in scripts/conformance-layers.mjs)`);
    const n = Array.isArray(entries) ? entries.length : Object.keys(entries).length;
    tables[t] = { layer, n };
    counts[layer] += n;
  }
  const byLayer = Object.fromEntries(LAYER_IDS.map((l) => [l, []]));
  for (const v of doc.vectors ?? []) byLayer[layerOfVerdict(v.expect)].push(v.name);
  for (const l of LAYER_IDS) counts[l] += byLayer[l].length;
  return { counts, tables, vectors: byLayer };
}

const core = tagCorpus(readCore(), 'vectors.json');
const adv = tagCorpus(readAdversarial(), 'vectors-adversarial.json.gz');
const policy = read('policy-vectors.json');
const stateful = read('stateful-vectors.json');
for (const v of policy.policy_decision) if (v.layer !== 'policy') throw new Error(`policy-vectors.json ${v.name}: layer ${v.layer}`);
for (const s of stateful.stateful) if (s.layer !== 'stateful') throw new Error(`stateful-vectors.json ${s.name}: layer ${s.layer}`);

// every other *-vectors.json file must be tagged too
const files = {};
for (const f of readdirSync(confDir).filter((x) => /-vectors\.json$/.test(x)).sort()) {
  const layer = FILE_LAYER[f];
  if (!layer) throw new Error(`${f} has no layer (add it to FILE_LAYER in scripts/conformance-layers.mjs)`);
  const doc = read(f);
  const n = f === 'policy-vectors.json' ? doc.policy_decision.length : f === 'stateful-vectors.json' ? doc.stateful.length
    : Object.values(doc).filter(Array.isArray).reduce((a, x) => a + x.length, 0) + Object.values(doc).filter((x) => x && typeof x === 'object' && !Array.isArray(x)).reduce((a, o) => a + Object.values(o).filter(Array.isArray).reduce((b, x) => b + x.length, 0), 0);
  files[f] = { layer, n };
}

// the Core profile's selection, per layer
const profile = read('core-profile.json');
const coreDoc = readCore();
const coreCounts = zero();
const byName = new Map(coreDoc.vectors.map((v) => [v.name, v]));
for (const n of profile.vectors) coreCounts[layerOfVerdict(byName.get(n)?.expect)]++;
for (const [t, names] of Object.entries(profile.primitives)) coreCounts[TABLE_LAYER[t]] += names.length;

const totals = zero();
for (const c of [core.counts, adv.counts]) for (const l of LAYER_IDS) totals[l] += c[l];
for (const { layer, n } of Object.values(files)) totals[layer] += layer === 'stateful' ? 0 : n;
totals.stateful = stateful.counts.present_steps;

const SECTIONS = {
  wire: [{ section: 'vectors.json + vectors-adversarial.json.gz: wire tables and PCActn vectors whose first failing check is wire / version; adversarial corpus kind canon', gate: 'required in every implementation' }],
  proof: [{ section: 'vectors.json + vectors-adversarial.json.gz: proof tables, accepted PCActn vectors, first failing check audience / validity / plan_inclusion / leaf_signature / counter; suite vector files', gate: 'required in every implementation' }],
  capability: [{ section: 'chain_pin, malformed, depth; PCActn vectors whose first failing check is chain / grant_ref_bound; adversarial corpus kind chain', gate: 'required in every implementation' }],
  policy: [
    { section: 'primitives.caveat_eval, primitives.intent_*', gate: 'required in every implementation' },
    { section: 'intent-state-vectors.json: accumulator and monitor declarations, values and pre-states, session-history windows and monitor folds, sequencer key sets and reservation receipts', gate: 'required in the TypeScript, Go, Rust and Python verifiers; other native SDKs report-only' },
    { section: 'policy-vectors.json policy_decision: expect.caveats (the caveat projection)', gate: 'TypeScript required; native SDKs report-only (cross-language gate, kind policy)' },
    { section: 'policy-vectors.json policy_decision: expect.decision (the whole decision)', gate: 'TypeScript required; no native SDK implements it yet (reported as unsupported)' },
  ],
  stateful: [{ section: 'stateful-vectors.json stateful', gate: 'TypeScript required; no native SDK runs sequences yet (reported as not run)' }],
  extension: [
    { section: 'optimistic-vectors.json: optimistic_claim, optimistic_window, optimistic_fraud_proof (wire level), optimistic_settlement', gate: 'TypeScript required; Go, Python and Rust required (their native suites); other native SDKs not run' },
    { section: 'ledger-vectors.json: ledger_inclusion, ledger_consistency, ledger_tree_head, ledger_cosign, ledger_head_consistency, ledger_checkpoint_chain, ledger_witnessed_head, ledger_equivocation', gate: 'TypeScript required; Go, Python and Rust required (their native suites); other native SDKs not run' },
  ],
  integration: [{ section: 'none (per-SDK adapter tests)', gate: 'not part of the shared corpus' }],
};

const manifest = {
  format: 1,
  description: 'Conformance layer manifest (conformance/LAYERS.md). Generated by packages/pca/scripts/gen-conformance-layers.mjs; do not edit.',
  claim_rule: 'An implementation claims conformance per layer, never overall: layer L is claimed only when every section of L passes in that implementation with nothing skipped. A section reported as report-only, unsupported or not run is not passed.',
  layers: LAYERS.map((l) => ({ ...l, sections: SECTIONS[l.id], vectors: totals[l.id] })),
  rules: {
    pcactn_vector: 'the layer of its first failing check in check_order (check_layer); an accepted vector is proof',
    check_order: CHECK_ORDER,
    check_layer: CHECK_LAYER,
    gate_kinds: { canon: 'wire', chain: 'capability', verify: 'pcactn_vector rule on the reference verdict', policy: 'policy', stateful: 'stateful' },
  },
  tables: core.tables,
  files: {
    'vectors.json': { counts: core.counts },
    'vectors-adversarial.json.gz': { counts: adv.counts, tables: adv.tables },
    ...files,
  },
  core_profile: { profile: profile.profile, counts: coreCounts },
  counts: { ...totals, note: 'stateful counts presentation steps; every other layer counts vectors / primitives' },
  vectors: { 'vectors.json': core.vectors },
};
const text = JSON.stringify(manifest, null, 1) + '\n';
if (process.argv.includes('--check')) {
  let committed = '';
  try { committed = readFileSync(OUT, 'utf8'); } catch { /* absent */ }
  if (committed !== text) { console.error('layers.json differs from a fresh regeneration: re-run gen-conformance-layers.mjs and commit'); process.exit(1); }
  console.log('layers.json up to date');
} else {
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}: ${LAYER_IDS.map((l) => `${l} ${totals[l]}`).join(', ')}`);
}
