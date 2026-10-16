// TypeScript reference oracle for the adversarial canonical-form corpus.
//   tsx oracle.ts <corpus.jsonl> <oracle.jsonl>
// For each canon case: strict-parse the raw JSON text, produce the STRICT canonical string + its hash.
// A parse/profile violation is an `error` (the authoritative "this value is out of the wire profile").
import { readFileSync, writeFileSync } from 'node:fs';
import * as pca from '../../packages/pca/src/index';

const [inp, outp] = process.argv.slice(2);
const lines = readFileSync(inp!, 'utf8').split('\n').filter(Boolean);
const out: string[] = [];
for (const line of lines) {
  const c = JSON.parse(line);
  const r: Record<string, unknown> = { id: c.id };
  try {
    const v = pca.strictParse(c.raw);
    r.canon = pca.canonicalizeStrict(v);
    r.hash = pca.hashCanonical(v);
  } catch (e) {
    r.error = 'parse:' + (e as Error).message.slice(0, 80);
  }
  out.push(JSON.stringify(r));
}
writeFileSync(outp!, out.join('\n') + '\n');
