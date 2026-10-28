// Regenerate conformance/forbid-certificate-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-conformance-forbid-certificate.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildForbidCertificateVectors } from '../src/test-support/forbid-certificate-vectors';

const out = join(__dirname, '..', 'conformance', 'forbid-certificate-vectors.json');
const text = `${JSON.stringify(buildForbidCertificateVectors(), null, 2)}\n`;
if (process.argv.includes('--check')) {
  if (readFileSync(out, 'utf8') !== text) {
    console.error('forbid-certificate-vectors.json is stale: run tsx scripts/gen-conformance-forbid-certificate.ts');
    process.exit(1);
  }
} else {
  writeFileSync(out, text);
  console.log(`wrote ${out}`);
}
