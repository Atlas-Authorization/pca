// Data generator (not an oracle): writes sdks/python-pca/atlas_pca/goal_ontologies.json, the five shipped intent ontologies and the
// selector catalog of each domain. They are derived data (the ontologies read the action definitions), so the native port ships the
// reference output instead of re-deriving it. Run from the repo root with the shared tsx env; re-run to refresh.
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import * as O0 from '../../../packages/pca-goal/src/ontologies/index';
import * as S0 from '../../../packages/pca-goal/src/selectors';
const O: any = (O0 as any).default ?? O0;
const S: any = (S0 as any).default ?? S0;
const ALL = O.ALL_ONTOLOGIES ?? O.default?.ALL_ONTOLOGIES;
const names = Object.keys(ALL).sort();
const out: any = { names, ontologies: {}, catalogs: {} };
for (const n of names) { out.ontologies[n] = ALL[n]; out.catalogs[n] = S.selCatalogOfDomain(n); }
fs.writeFileSync(fileURLToPath(new URL('../../../sdks/python-pca/atlas_pca/goal_ontologies.json', import.meta.url)), JSON.stringify(out));
console.log('ok', names);
