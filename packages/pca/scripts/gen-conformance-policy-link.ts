// Regenerate conformance/policy-link-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-conformance-policy-link.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildPolicyLinkVectors } from '../src/test-support/policy-link-vectors';

const out = join(__dirname, '..', 'conformance', 'policy-link-vectors.json');
const text = `${JSON.stringify(buildPolicyLinkVectors(), null, 2)}\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(out, 'utf8') !== text) {
    console.error('policy-link-vectors.json is stale: run tsx scripts/gen-conformance-policy-link.ts');
    process.exit(1);
  }
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}
