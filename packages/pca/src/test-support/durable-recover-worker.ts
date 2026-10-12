// Child of durable-state-recover-crash.test.ts: a process that the test SIGKILLs at a named step through the test-only
// hook PCA_DURABLE_TEST_RECOVER_CRASH_AT (honoured only with NODE_ENV=test; see RECOVER_CRASH_ENV in durable-state.ts).
// argv: recover <dir> <expectedHolder JSON | unreadable>   operator recovery (recoverDurableState)
//       update  <dir> <value>                              open (taking over a dead holder if need be) + append to used-nonces
// Prints `RESULT ok <json>` or `RESULT err <code>` when it is NOT killed.
import { openDurableState, recoverDurableState } from '../durable-state';

const [mode, dir, arg] = process.argv.slice(2) as [string, string, string];

async function main(): Promise<void> {
  if (mode === 'recover') {
    const expectedHolder = arg === 'unreadable' ? 'unreadable' : (JSON.parse(arg) as { host: string; pid: number; nonce: string });
    const r = recoverDurableState({ dir, force: true, expectedHolder });
    process.stdout.write(`RESULT ok ${JSON.stringify(r)}\n`);
  } else if (mode === 'update') {
    const st = await openDurableState({ dir, lockTimeoutMs: 30_000 });
    const res = await st.update('used-nonces', (cur) => [...((cur as string[] | undefined) ?? []), arg]);
    process.stdout.write(`RESULT ok ${JSON.stringify(res)}\n`);
  } else {
    throw new Error(`unknown mode ${mode}`);
  }
}
main().catch((e: unknown) => {
  process.stdout.write(`RESULT err ${(e as { code?: string }).code ?? String(e)}\n`);
  process.exit(4);
});
