// Stage of the conformance pipeline for the Intent Layer v2 state functions (spec sections 2.1 and 3.1; rule 15): the
// accumulator and monitor declarations, values and pre-states, the session-history window and fold, the sequencer key sets
// and the reservation receipts. Writes conformance/intent-state-vectors.json (a separate file, like policy-vectors.json):
//
//   { format: "pca-intent-state-vectors", ver: 1, cases: [ { fn, name, args, out } ] }
//
// `out` is what the TypeScript reference (src/intent-acc.ts, src/intent-history.ts) returns for `args`; a function that
// throws on a corrupt history has out = {"throws": true}. A runner calls its own implementation of `fn` with `args` and
// compares the result to `out` (the reason text of an error function is compared by the verifiers that carry it, the
// verdict by the others). Numbers keep their lexeme (-0, 1.5, 2^53 - 1): parse the file with a lenient JSON parser. Cases
// that need a signature suite the runner lacks are reported as unsupported, never skipped silently.
//
//     node packages/pca/scripts/gen-conformance-intent-state.mjs            (reads ../dist, like every stage)
//     PCA_SRC=1 packages/pca/node_modules/.bin/tsx packages/pca/scripts/gen-conformance-intent-state.mjs
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadPca } from './pca-all.mjs';
import { buildIntentAccCases } from './intent-acc-cases.mjs';
import { buildIntentHistoryCases } from './intent-history-cases.mjs';
import { confDir } from './conformance-io.mjs';
import { ser } from './intent-acc-cases.mjs';

const pca = await loadPca();
const cases = [...buildIntentAccCases(pca), ...buildIntentHistoryCases(pca)];
const names = new Set();
for (const c of cases) {
  if (names.has(c.name)) throw new Error(`duplicate case name ${c.name}`);
  names.add(c.name);
}
const out = `{"format":"pca-intent-state-vectors","ver":1,"cases":[\n${cases.map((c) => ser(c)).join(',\n')}\n]}\n`;
writeFileSync(join(confDir, 'intent-state-vectors.json'), out);
const byFn = {};
for (const c of cases) byFn[c.fn] = (byFn[c.fn] ?? 0) + 1;
console.log(`intent state: ${cases.length} cases`, JSON.stringify(byFn));
