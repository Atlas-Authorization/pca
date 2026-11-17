// Regenerate packages/pca/conformance/break-glass-vectors.json from the TypeScript reference (deterministic).
//   tsx scripts/gen-break-glass-vectors.ts [--check]
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { buildBreakGlassVectors } from '../src/test-support/breakglass-vectors';

const out = join(__dirname, '..', '..', 'pca', 'conformance', 'break-glass-vectors.json');
buildBreakGlassVectors().then((v) => {
  const text = `${JSON.stringify(v, null, 2)}\n`;
  if (process.argv.includes('--check')) {
    if (readFileSync(out, 'utf8') !== text) {
      console.error('break-glass-vectors.json is stale: run tsx scripts/gen-break-glass-vectors.ts');
      process.exit(1);
    }
  } else {
    writeFileSync(out, text);
    console.log(`wrote ${out}`);
  }
});
