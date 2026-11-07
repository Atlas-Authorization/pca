/**
 * Run every attack against every approach and print what happened.
 *
 *   npm start                       full report + the matrix
 *   npm start -- --markdown         only the matrix, as Markdown
 *   npm start -- --json             machine-readable results
 *   npm start -- --check <file.md>  exit 1 unless <file.md> contains the matrix exactly as generated now
 */
import { readFileSync } from 'node:fs';
import { SetupError } from './attacks.js';
import { matrix, runAll, type Row } from './suite.js';

function report(rows: Row[]): string {
  const out: string[] = [];
  for (const r of rows) {
    out.push(`${r.attack.id}  ${r.attack.title}`);
    out.push(wrap(r.attack.story, 4));
    for (const { ap, out: o } of r.results) {
      const head = `    ${ap.label.padEnd(20)} ${o.stopped ? 'STOPPED    ' : 'NOT STOPPED'}  `;
      out.push(head + (o.stopped ? `refused: ${o.reason}` : `allowed: ${o.reason}. ${o.why ?? ''}`));
    }
    out.push('');
  }
  return out.join('\n');
}

function wrap(text: string, indent: number, width = 110): string {
  const words = text.split(' ');
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width - indent) {
      lines.push(line.trim());
      line = w;
    } else line += ' ' + w;
  }
  if (line.trim()) lines.push(line.trim());
  return lines.map((l) => ' '.repeat(indent) + l).join('\n');
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const rows = await runAll();
  const md = matrix(rows);

  if (args.includes('--json')) {
    const json = rows.map((r) => ({
      attack: r.attack.id,
      title: r.attack.title,
      results: Object.fromEntries(r.results.map(({ ap, out }) => [ap.id, out])),
    }));
    console.log(JSON.stringify(json, null, 2));
    return;
  }
  if (args.includes('--markdown')) {
    console.log(md);
    return;
  }
  const checkIdx = args.indexOf('--check');
  if (checkIdx >= 0) {
    const file = args[checkIdx + 1];
    if (!file) throw new Error('--check needs a file path');
    const doc = readFileSync(file, 'utf8');
    if (doc.includes(md)) {
      console.log(`OK: ${file} contains the current matrix.`);
      return;
    }
    console.error(`MISMATCH: ${file} does not contain the matrix generated now:\n\n${md}`);
    process.exit(1);
  }

  console.log('Agent-authorization attacks: who stops what\n');
  console.log(report(rows));
  console.log('Matrix\n');
  console.log(md);
}

main().catch((err: unknown) => {
  if (err instanceof SetupError) console.error(`SETUP ERROR (the comparison is invalid): ${err.message}`);
  else console.error(err);
  process.exit(1);
});
