// The stale-lock BREAK race (TLA: formal/tla/DurableLock.tla dl_dead_only): a lock file left by a dead process, many
// processes open the state at the same instant.  Each round: fresh dir, planted dead lock, W workers released at the same
// wall-clock instant, each doing ONE consume of the same key.  Exactly one TRUE is the contract.
//   node race.mjs <rounds> <workers> [delayMs=250]
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir, hostname } from 'node:os';
const [rounds, W, delay = '250'] = process.argv.slice(2);
const mjs = process.env.DURABLE_MJS ?? new URL('../durable-state.mjs', import.meta.url).pathname;
const child = `
const { openDurableState } = await import(${JSON.stringify(mjs)});
const [dir, at] = process.argv.slice(1);
while (Date.now() < Number(at)) {}
let first = false, out = 'err';
try { const st = await openDurableState({ dir, lockTimeoutMs: 15000 });
      await st.update('nonce', (c) => { if (c === undefined) { first = true; return 1; } return undefined; });
      out = first ? 'T' : 'F'; } catch (e) { out = 'E:' + e.code; }
console.log(out);`;
let bad = 0, trueTot = 0;
const hist = {};
for (let r = 0; r < Number(rounds); r++) {
  const dir = mkdtempSync(`${tmpdir()}/dlrace-`);
  writeFileSync(`${dir}/state.lock`, JSON.stringify({ pid: 2147483000, host: hostname(), nonce: 'dead', t: Date.now() - 100000 }));
  const old = new Date(Date.now() - 100000); utimesSync(`${dir}/state.lock`, old, old);
  const at = Date.now() + Number(delay);
  const outs = await Promise.all(Array.from({ length: Number(W) }, () => new Promise((res) => {
    const p = spawn(process.execPath, ['--input-type=module', '-e', child, dir, String(at)], { stdio: ['ignore', 'pipe', 'inherit'] });
    let o = ''; p.stdout.on('data', (d) => (o += d)); p.on('close', () => res(o.trim()));
  })));
  const t = outs.filter((o) => o === 'T').length; trueTot += t;
  hist[t] = (hist[t] ?? 0) + 1;
  if (t > 1) { bad++; console.log(`round ${r}: ${t} processes were told TRUE:`, outs.join(',')); }
  rmSync(dir, { recursive: true, force: true });
}
console.log(JSON.stringify({ rounds: Number(rounds), workers: Number(W), roundsWithMoreThanOneTrue: bad, histogramOfTrueCounts: hist }));
process.exit(bad ? 1 : 0);
