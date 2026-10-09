// Oracle driver: same protocol as the per-language drivers in tools/pca-diff-fuzz/drivers.
//   tsx ref-driver.ts <corpus.jsonl> <out.jsonl>
import { openSync, readFileSync, writeSync, closeSync } from 'node:fs';
import { refVerify, refCanon } from './ref';

async function main() {
  const [inp, outp] = process.argv.slice(2);
  const fd = openSync(outp!, 'w');
  for (const line of readFileSync(inp!, 'utf8').split('\n')) {
    if (!line) continue;
    const c = JSON.parse(line);
    const r = c.kind === 'verify' ? await refVerify(c.raw, c.grant, c.now, c.aud) : refCanon(c.raw);
    writeSync(fd, JSON.stringify({ id: c.id, ...r }) + '\n');
  }
  closeSync(fd);
}
main();
