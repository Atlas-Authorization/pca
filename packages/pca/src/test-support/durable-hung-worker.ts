// Child of durable-state-hung-owner.test.ts: takes the state lock, then STALLS inside the critical section (synchronous
// busy wait, like a blocked fsync / a SIGSTOP) for a long time, then returns its update.
// argv: <dir> <stallMs> <unused> <value>
import { openDurableState } from '../durable-state';

const [dir, stallS, , value] = process.argv.slice(2);

async function main(): Promise<void> {
  const st = await openDurableState({ dir: dir!, lockTimeoutMs: 30_000 });
  const res = await st.update('nonce', (cur) => {
    process.stdout.write('holding\n');
    const until = Date.now() + Number(stallS);
    while (Date.now() < until) {
      /* stalled while holding the lock */
    }
    return cur === undefined ? value : undefined; // consume-once: first writer wins
  });
  process.stdout.write(`committed ${JSON.stringify(res)}\n`);
}
main().catch((e: unknown) => {
  process.stdout.write(`rejected ${(e as { code?: string }).code ?? 'error'}\n`);
  process.exit(4);
});
