// Regenerate conformance/passport-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-conformance-passport.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildPassportVectors } from '../src/test-support/passport-vectors';

const out = join(__dirname, '..', 'conformance', 'passport-vectors.json');
buildPassportVectors().then((doc) => {
  const text = `${JSON.stringify(doc, null, 2)}\n`;
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== text) {
      console.error('passport-vectors.json is stale: run tsx scripts/gen-conformance-passport.ts');
      process.exit(1);
    }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${out}`);
  }
});
