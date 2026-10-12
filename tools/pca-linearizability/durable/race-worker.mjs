// Persistent worker of race-pool.mjs: for every round message {dir, at} it busy-waits until the wall-clock instant `at`, opens
// the durable state in `dir` (a fresh handle) and performs ONE consume-once update; replies T | F | E:<code>.
const { openDurableState } = await import(process.env.DURABLE_MJS);
process.on('message', async (m) => {
  if (m === 'exit') process.exit(0);
  const { dir, at, id } = m;
  while (Date.now() < at) {}
  let first = false, out;
  try {
    const st = await openDurableState({ dir, lockTimeoutMs: 30000 });
    await st.update('nonce', (c) => { first = c === undefined; return first ? 1 : undefined; });
    out = first ? 'T' : 'F';
  } catch (e) { out = 'E:' + (e.code ?? 'error') + (process.env.DEBUG_ERR ? '(' + e.message + ')' : ''); }
  process.send({ id, out });
});
process.send('ready');
