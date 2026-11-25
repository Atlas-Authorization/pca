// Data generator (python lane): @atlasauth/pca-actions import/rules.ts. Writes the data module sdks/python-pca/atlas_pca/actions_import_rules_data.py
// (the shipped suggestion rules as JSON). The behaviour is replayed from the shared corpora actions-import-suggest / actions-import-review.
import fs from 'node:fs';
import * as R0 from '../../../packages/pca-actions/src/import/rules.ts';
import { ROOT } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const R = un(R0);
fs.writeFileSync(ROOT + 'sdks/python-pca/atlas_pca/actions_import_rules_data.py',
  '"""The shipped suggestion rules of the TypeScript reference @atlasauth/pca-actions as data (generated; do not edit)."""\nimport json\n\nDEFAULT_RULES_JSON = json.loads(r\'\'\'' + JSON.stringify(R.DEFAULT_RULES) + '\'\'\')\n');
console.log('rules', R.DEFAULT_RULES.rules.length, R.DEFAULT_RULES.version);
