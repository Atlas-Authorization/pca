// Child process used by durable-state.test.ts: races other writers on one state directory.
// argv: <dir> <mode> <id> <n> [crashAt]
import { openDurableState } from '../durable-state';

const [dir, mode, id, nStr, crashAt] = process.argv.slice(2);
const n = Number(nStr);

async function main(): Promise<void> {
  const st = await openDurableState({
    dir: dir!,
    compactEvery: 12,
    lockTimeoutMs: 60_000,
    ...(crashAt === 'after-temp-write' || crashAt === 'after-journal-rename' ? { testCrashAt: crashAt } : {}),
  });
  if (mode === 'race') {
    for (let i = 1; i <= n; i++) {
      // counter: exact increment (lost update would show as a smaller final value)
      await st.update('counter', (p) => (typeof p === 'number' ? p : 0) + 1);
      // monotone high-water mark: max of writers' values
      const mine = Number(id) * 1000 + i;
      await st.update('hwm', (p) => (typeof p === 'number' && p >= mine ? undefined : mine));
    }
  } else if (mode === 'crash') {
    await st.set('victim', { v: 2 });
  }
  process.stdout.write('done\n');
}
main().catch((e: unknown) => {
  process.stderr.write(`${e instanceof Error ? e.stack ?? e.message : String(e)}\n`);
  process.exit(3);
});
