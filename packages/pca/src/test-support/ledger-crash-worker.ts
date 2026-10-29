// Child process used by ledger-store.test.ts: appends a commit (or writes a checkpoint) on a durable store whose commit is SIGKILLed.
// argv: <dir> <crashAt> <guardianSecretB64u> <mode: append|checkpoint> <nowMs>
import { openDurableState } from '../durable-state';
import { KvLedgerStore, StoredLedger } from '../ledger-store';
import { unb64u } from '../hash';

const [dir, crashAt, secret, mode, now] = process.argv.slice(2);

async function main(): Promise<void> {
  // setup on a handle that cannot crash, then reopen with the crash hook armed
  const plain = new KvLedgerStore(await openDurableState({ dir: dir!, lockTimeoutMs: 60_000 }));
  const opts = { guardianSecret: unb64u(secret!), instanceId: 'inst-1', principal: 'grant-1', clock: () => Number(now) };
  const setup = await StoredLedger.open({ ...opts, store: plain });
  void setup;
  const armed = new KvLedgerStore(await openDurableState({ dir: dir!, lockTimeoutMs: 60_000, testCrashAt: crashAt as 'after-temp-write' | 'after-journal-rename' }));
  const L = await StoredLedger.open({ ...opts, store: armed });
  if (mode === 'append') await L.append('crash-commit');
  else await L.checkpoint();
  process.stdout.write('survived\n');
}
main().catch((e: unknown) => {
  process.stderr.write(`${e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`);
  process.exit(3);
});
