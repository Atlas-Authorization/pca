// Oracle for the native K042IntentAcc*Test differential tests (IntentAcc, rule 15): runs the TS reference
// (packages/pca/src/intent-acc.ts) on targeted inputs and writes sdks/java-pca/test-data/k042-intentacc.json.
//   cd <repo> && npx tsx tools/pca-audit/java-mutate/k042-intentacc-oracle.mjs [out.json]
// The cases are built by packages/pca/scripts/intent-acc-cases.mjs (also the source of the conformance corpus file
// intent-state-vectors.json). Every case is {fn, name, args, out}; the args are written as JSON text the native tests parse
// leniently (so -0 / 1.5 / 2^53 reach both sides as the same binary64). PQ signatures are deterministic.
import fs from 'node:fs';
import { buildIntentAccCases, ser } from '../../../packages/pca/scripts/intent-acc-cases.mjs';
import { loadPca } from '../../../packages/pca/scripts/pca-all.mjs';
process.env.PCA_SRC = '1';
const pca = await loadPca();

const OUT = process.argv[2] ?? new URL('../../../sdks/java-pca/test-data/k042-intentacc.json', import.meta.url).pathname;
const cases = buildIntentAccCases(pca);
fs.writeFileSync(OUT, '[\n' + cases.map((c) => ser(c)).join(',\n') + '\n]\n');
console.log(`wrote ${cases.length} cases to ${OUT}`);
