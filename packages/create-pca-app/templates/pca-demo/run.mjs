#!/usr/bin/env node
/**
 * pca-demo - the whole Proof-Carrying Authority story in one command, no accounts, no Docker.
 *
 *   node run.mjs            colorized walkthrough, exits 1 if any outcome deviates
 *   node run.mjs --step     pause before each step (press Enter)
 *   node run.mjs --json     machine-readable result on stdout, nothing else
 *   node run.mjs --break    run against a mis-configured server to prove deviations exit nonzero
 */
import { createInterface } from 'node:readline';
import { loadPca } from './load.mjs';
import { runStory } from './story.mjs';

process.stdout.on('error', (e) => { if (e.code === 'EPIPE') process.exit(0); });
const args = new Set(process.argv.slice(2));
if (args.has('--help') || args.has('-h')) {
  console.log('Usage: pca-demo [--step] [--json] [--no-color] [--break]');
  process.exit(0);
}
const json = args.has('--json');
const stepMode = args.has('--step');
const color = !json && !args.has('--no-color') && !process.env.NO_COLOR && (process.stdout.isTTY || process.env.FORCE_COLOR);
const c = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const bold = c('1'), dim = c('2'), red = c('31'), green = c('32'), yellow = c('33'), cyan = c('36');
const out = (s = '') => { if (!json) console.log(s); };

let rl;
const pause = async () => {
  if (!stepMode || json) return;
  if (!process.stdin.isTTY) return;
  rl ??= createInterface({ input: process.stdin, output: process.stdout });
  await new Promise((r) => rl.question(dim('   [enter] to continue... '), () => r()));
};

const stepTitles = [];
const ui = {
  async step(n, title, why) {
    stepTitles.push({ n, title });
    out();
    out(bold(cyan(`== Step ${n}: ${title}`)));
    out(dim(`   ${why}`));
    await pause();
  },
  info(s) { out(`   ${s}`); },
  wire(what, r) {
    const mark = r.allowed ? green('ALLOWED') : red('DENIED ');
    out(`   ${dim('->')} ${what.padEnd(66)} ${mark} ${dim('HTTP ' + r.status)}`);
    if (!r.allowed) out(`      ${yellow('why:')} ${r.reason.length > 120 ? r.reason.slice(0, 117) + '...' : r.reason}`);
  },
  outcome() {},
};

const { pca, fetchGuard } = await loadPca();
const started = Date.now();
const result = await runStory({ pca, fetchGuard, ui, breakIt: args.has('--break') });
const ms = Date.now() - started;
rl?.close();

if (json) {
  console.log(JSON.stringify({ ok: result.ok, elapsedMs: ms, audience: result.audience, rows: result.rows }, null, 2));
  process.exit(result.ok ? 0 : 1);
}

out();
out(bold('Summary'));
const w = { s: 5, l: 50, e: 9, a: 9 };
out(dim(`${'step'.padEnd(w.s)} ${'action'.padEnd(w.l)} ${'expected'.padEnd(w.e)} ${'actual'.padEnd(w.a)} reason`));
for (const r of result.rows) {
  const actual = r.ok ? green(r.actual.padEnd(w.a)) : red(r.actual.padEnd(w.a));
  const reason = (r.reason || '').replace(/\s+/g, ' ');
  out(`${String(r.step).padEnd(w.s)} ${r.label.padEnd(w.l)} ${r.expected.padEnd(w.e)} ${actual} ${dim(reason.length > 70 ? reason.slice(0, 67) + '...' : reason)}`);
}
out();
const bad = result.rows.filter((r) => !r.ok);
if (bad.length === 0) out(bold(green(`All ${result.rows.length} outcomes matched expectations in ${ms} ms. PCA behaved as specified.`)));
else out(bold(red(`${bad.length} of ${result.rows.length} outcomes DEVIATED: ${bad.map((r) => r.step).join(', ')}`)));
process.exit(bad.length === 0 ? 0 : 1);
