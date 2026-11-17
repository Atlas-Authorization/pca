#!/usr/bin/env node
// pca-bench CLI. Exit codes: 0 pass (including "no baseline yet"), 1 regression / deny-path failure, 2 bad input.
//
//   compare.mjs gate  --baseline FILE --candidate RUN.json [--candidate RUN2.json ...] [--threshold 0.2] [--alpha 0.05] [--summary OUT.md]
//   compare.mjs merge OUT.json RUN.json [RUN2.json ...]      pool repeated runs (this is how a baseline is produced)
//   compare.mjs table RESULT.json [RESULT2.json ...]         markdown results table (docs page, CI summary)
//   compare.mjs docs PAGE.md RESULT.json [RESULT2.json ...]  fill the results table between the bench-results markers of a docs page
import { existsSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { DEFAULTS, RESULT_SCHEMA, gate, markdownTable, mergeRuns } from './lib.mjs';

const load = (f) => {
  const j = JSON.parse(readFileSync(f, 'utf8'));
  if (j.schema !== RESULT_SCHEMA || !Array.isArray(j.scenarios)) throw new Error(`${f}: not a ${RESULT_SCHEMA} file`);
  return j;
};

function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === 'merge') {
    const [out, ...ins] = rest;
    if (!out || ins.length === 0) throw new Error('merge OUT.json RUN.json...');
    writeFileSync(out, JSON.stringify(mergeRuns(ins.map(load)), null, 1) + '\n');
    return 0;
  }
  if (cmd === 'table') {
    console.log(markdownTable(rest.map(load)));
    return 0;
  }
  if (cmd === 'docs') {
    const [page, ...ins] = rest;
    if (!page || ins.length === 0) throw new Error('docs PAGE.md RESULT.json...');
    const [open, close] = ['<!-- bench-results:start -->', '<!-- bench-results:end -->'];
    const text = readFileSync(page, 'utf8');
    const i = text.indexOf(open);
    const j = text.indexOf(close);
    if (i < 0 || j < i) throw new Error(`${page}: the bench-results markers are missing`);
    const rs = ins.map(load);
    const note = `_${rs.map((r) => `${r.lang}: ${r.impl} ${r.impl_version}, ${r.tool}, ${r.runner.cpu}`).join('; ')}_`;
    writeFileSync(page, `${text.slice(0, i + open.length)}\n\n${markdownTable(rs)}\n\n${note}\n\n${text.slice(j)}`);
    return 0;
  }
  if (cmd !== 'gate') throw new Error('usage: compare.mjs gate|merge|table|docs ...');
  const a = { candidate: [], threshold: DEFAULTS.threshold, alpha: DEFAULTS.alpha };
  for (let i = 0; i < rest.length; i += 2) {
    const k = rest[i]?.replace(/^--/, '');
    const v = rest[i + 1];
    if (v === undefined) throw new Error(`missing value for ${rest[i]}`);
    if (k === 'candidate') a.candidate.push(v);
    else if (k === 'baseline' || k === 'summary') a[k] = v;
    else if (k === 'threshold' || k === 'alpha') a[k] = Number(v);
    else throw new Error(`unknown option ${rest[i]}`);
  }
  if (a.candidate.length === 0) throw new Error('gate needs at least one --candidate');
  if (!(a.threshold > 0) || !(a.alpha > 0 && a.alpha < 1)) throw new Error('--threshold must be > 0 and --alpha in (0,1)');
  const cand = mergeRuns(a.candidate.map(load));
  const base = a.baseline && existsSync(a.baseline) ? load(a.baseline) : null;
  const r = gate(base, cand, { threshold: a.threshold, alpha: a.alpha });
  const lines = [`### pca-bench gate: ${cand.lang} (${cand.repeats} run(s)) - ${r.verdict.toUpperCase()}`, ''];
  for (const n of r.notices) lines.push(`> ${n}`);
  if (r.notices.length) lines.push('');
  if (r.rows.length) lines.push('| scenario | status | detail |', '|---|---|---|', ...r.rows.map((x) => `| ${x.id} | ${x.status} | ${x.note ?? ''} |`));
  const text = lines.join('\n');
  console.log(text);
  if (a.summary) appendFileSync(a.summary, text + '\n');
  for (const x of r.rows.filter((y) => y.status === 'FAIL')) console.log(`::error title=pca-bench ${cand.lang}::${x.id}: ${x.note}`);
  for (const n of r.notices) console.log(`::notice title=pca-bench ${cand.lang}::${n}`);
  return r.verdict === 'fail' ? 1 : 0;
}

try {
  process.exit(main(process.argv.slice(2)));
} catch (e) {
  console.error(`pca-bench: ${e.message}`);
  process.exit(2);
}
