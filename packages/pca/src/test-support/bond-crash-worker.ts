// Child process used by bond-store.test.ts: slashes an open bond on a durable store whose commit is SIGKILLed at a chosen point.
// argv: <dir> <crashAt> <guardianSecretB64u> <claimJson> <nowMs>
import { openDurableState } from '../durable-state';
import { KvBondStore, StoreBondLedger } from '../bond-store';
import { unb64u } from '../hash';

const [dir, crashAt, secret, claimJson, now] = process.argv.slice(2);

async function main(): Promise<void> {
  const kv = await openDurableState({ dir: dir!, lockTimeoutMs: 60_000, testCrashAt: crashAt as 'after-temp-write' | 'after-journal-rename' });
  const L = new StoreBondLedger({ guardianSecret: unb64u(secret!), store: new KvBondStore(kv), clock: () => Number(now) });
  const claim = JSON.parse(claimJson!);
  await L.slashBondOnRevocation({ claimId: claim.bond_ref, claim, revokedCapId: 'cap:leaf', treasury: 'treasury' });
  process.stdout.write('survived\n'); // never reached when the crash hook fires
}
main().catch((e: unknown) => {
  process.stderr.write(`${e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`);
  process.exit(3);
});
