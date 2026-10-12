// Stale-lock BREAK race at scale: W persistent workers, R rounds. Every round: fresh directory, a lock left by a DEAD process
// planted, all workers released at the same wall-clock instant, each doing one consume-once update on the same key.
// Exactly one TRUE per round is the contract; also the journal chain must verify afterwards and no worker may error.
//   node race-pool.mjs <rounds> <workers> [delayMs=40] [plant=legacy|gen|none]
import { fork } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir, hostname } from 'node:os';
const [rounds, W, delay = '40', plant = 'legacy'] = process.argv.slice(2);
const mjs = process.env.DURABLE_MJS;
const { openDurableState } = await import(mjs);
const kids = await Promise.all(Array.from({ length: Number(W) }, () => new Promise((res) => {
  const k = fork(new URL('./race-worker.mjs', import.meta.url).pathname, [], { env: process.env });
  k.once('message', () => res(k));
})));
let bad = 0, errs = 0, chainBad = 0; const hist = {};
for (let r = 0; r < Number(rounds); r++) {
  const dir = mkdtempSync(`${tmpdir()}/dlpool-`);
  if (plant === 'legacy') {
    writeFileSync(`${dir}/state.lock`, JSON.stringify({ pid: 2147483000, host: hostname(), nonce: 'dead', t: Date.now() - 100000 }));
    const old = new Date(Date.now() - 100000); utimesSync(`${dir}/state.lock`, old, old);
  } else if (plant === 'gen') {
    writeFileSync(`${dir}/state.lock.1`, JSON.stringify({ st: 'held', pid: 2147483000, host: hostname(), nonce: 'dead' }));
  }
  const at = Date.now() + Number(delay);
  const outs = await Promise.all(kids.map((k, i) => new Promise((res) => {
    const h = (m) => { if (m.id === r) { k.off('message', h); res(m.out); } };
    k.on('message', h); k.send({ dir, at, id: r });
  })));
  const t = outs.filter((o) => o === 'T').length;
  hist[t] = (hist[t] ?? 0) + 1;
  if (t !== 1) { bad++; console.log(`round ${r}: ${t} TRUE: ${outs.join(',')}`); }
  if (outs.some((o) => o.startsWith('E:'))) { errs++; if (t === 1) console.log(`round ${r}: error outcomes: ${outs.join(',')}`); }
  try { await (await openDurableState({ dir })).verify(); } catch (e) { chainBad++; console.log(`round ${r}: chain verify failed ${e.code}`); }
  const keep = process.env.KEEP && (t !== 1 || outs.some((o) => o.startsWith('E:')));
  if (keep) console.log(`kept ${dir}`); else rmSync(dir, { recursive: true, force: true });
}
kids.forEach((k) => k.send('exit'));
console.log(JSON.stringify({ rounds: Number(rounds), workers: Number(W), plant, roundsNotExactlyOneTrue: bad, roundsWithAnyWorkerError: errs, chainVerifyFailures: chainBad, histogramOfTrueCounts: hist }));
process.exit(bad || chainBad ? 1 : 0);
