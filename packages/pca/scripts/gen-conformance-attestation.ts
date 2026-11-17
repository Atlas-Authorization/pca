// Regenerate conformance/attestation-evidence-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-conformance-attestation.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildAttestationEvidenceVectors } from '../src/test-support/attestation-evidence-vectors';

const out = join(__dirname, '..', 'conformance', 'attestation-evidence-vectors.json');
buildAttestationEvidenceVectors().then(({ doc, suspicious }) => {
  if (suspicious.length) {
    console.error(`reasons that look like OpenSSL text but are not pass-through prefixes:\n${suspicious.join('\n')}`);
    process.exit(1);
  }
  const text = `${JSON.stringify(doc, null, 1)}\n`;
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== text) {
      console.error('attestation-evidence-vectors.json is stale: run tsx scripts/gen-conformance-attestation.ts');
      process.exit(1);
    }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${out}`);
  }
});
