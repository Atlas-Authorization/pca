// Child of durable-state-fence.test.ts (R6-CORE-01/02): a lock holder that gets PAUSED (not killed) inside its commit.
// argv: <dir> <value> <goFile> <mode> [fakeNs]
//   mode 'fn'      : pause inside the update function (inside the critical section, BEFORE the pre-rename lock re-check)
//   mode 'journal' : pause inside renameSync(<tmp>, state.journal), i.e. AFTER the re-check passed, before the rename
//   mode 'head'    : pause inside renameSync(<tmp>, state.head), i.e. after the journal rename, before the head rename
// The pause point prints PAUSE-POINT and then waits for <goFile> to exist. The parent either just leaves it waiting
// (emulated pause, as in the round-6 PoCs) or ALSO stops it for real with SIGSTOP and resumes it with SIGCONT.
// fakeNs (optional) makes /proc/self/ns/pid read as that value: an emulated "other container" so operator recovery
// releases this holder without a real PID namespace (the real-namespace tests run this worker under `unshare --pid`).
// Prints `RESULT ok <json>` or `RESULT err <code>` at the end.
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';

const [dir, value, goFile, mode, fakeNs] = process.argv.slice(2) as [string, string, string, string, string | undefined];

const sleeper = new Int32Array(new SharedArrayBuffer(4));
const waitForGo = (): void => {
  process.stdout.write('PAUSE-POINT\n');
  while (!fs.existsSync(goFile)) Atomics.wait(sleeper, 0, 0, 5); // synchronous: the whole process is stuck here
};

let armed = false; // only the commit's head write pauses, not a head repair during open
const realRename = fs.renameSync;
fs.renameSync = ((a: fs.PathLike, b: fs.PathLike) => {
  if ((mode === 'journal' && String(b).endsWith('state.journal')) || (mode === 'head' && String(b).endsWith('state.head') && armed)) waitForGo();
  return realRename(a, b);
}) as typeof fs.renameSync;
if (fakeNs) {
  const realReadlink = fs.readlinkSync;
  fs.readlinkSync = ((p: fs.PathLike, o?: unknown) => (String(p) === '/proc/self/ns/pid' ? fakeNs : (realReadlink as (p: fs.PathLike, o?: unknown) => string)(p, o))) as typeof fs.readlinkSync;
}
syncBuiltinESMExports();

async function main(): Promise<void> {
  const { openDurableState } = await import('../durable-state');
  const st = await openDurableState({ dir, lockTimeoutMs: 30_000 });
  const res = await st.update('used-nonces', (cur) => {
    if (mode === 'fn') waitForGo();
    armed = true;
    return [...((cur as string[] | undefined) ?? []), value];
  });
  process.stdout.write(`RESULT ok ${JSON.stringify(res)}\n`);
}
main().catch((e: unknown) => {
  process.stdout.write(`RESULT err ${(e as { code?: string }).code ?? String(e)}\n`);
  process.exit(4);
});
