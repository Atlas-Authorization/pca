// One client process of the durable-state (DurableKv) linearizability test.  Records the same history format as the Go
// client so `pcalinz check` can verify consume-once semantics:  update(key, fn) with first-writer-wins.
//   node worker.mjs <statedir> <histdir> <proc> <secs> <unused> <epochMs> [spread=3] [sliceMs=40]
import { openSync, writeSync, mkdirSync } from 'node:fs';
import { hrtime } from 'node:process';
const [dir, hist, proc, secsS, staleS, epochS, spreadS = '3', sliceS = '40'] = process.argv.slice(2);
const { openDurableState } = await import(process.env.DURABLE_MJS ?? '../durable-state.mjs');
mkdirSync(hist, { recursive: true });
const fd = openSync(`${hist}/h-${proc}.log`, 'a');
const ns = () => BigInt(Date.now()) * 1000000n + (hrtime.bigint() % 1000000n);   // wall ms + sub-ms monotone
const st = await openDurableState({ dir, lockTimeoutMs: 20000 });
const epoch = Number(epochS), spread = Number(spreadS), slice = Number(sliceS);
const end = Date.now() + Number(secsS) * 1000;
let seq = 0, n = { t: 0, f: 0, e: 0 };
while (Date.now() < end) {
  const win = Math.floor((Date.now() - epoch) / slice);
  const key = `${process.env.RUN ?? 'r'}-${win}-${Math.floor(Math.random() * spread)}`;
  seq += 1;
  writeSync(fd, `i ${proc} 0 ${seq} ${ns()} c ${key} 0\n`);
  let first = false, res = 2;
  try {
    await st.update(key, (cur) => { if (cur === undefined) { first = true; return 1; } return undefined; });
    res = first ? 1 : 0;
  } catch (e) { res = 2; }
  writeSync(fd, `r ${proc} 0 ${seq} ${ns()} ${res}\n`);
  if (res === 1) n.t++; else if (res === 0) n.f++; else n.e++;
}
console.log(`worker ${proc} true=${n.t} false=${n.f} err=${n.e}`);
