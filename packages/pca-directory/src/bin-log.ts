#!/usr/bin/env node
/**
 * pca-directory-log: run a directory log.
 *
 *   pca-directory-log --id my-log --key log.key --data ./log-data --port 8080 [--issuer <key> ...] [--witness <key> ...] [--min-cosigs 2]
 *
 * Without --issuer the log is open: anyone holding a valid signed passport and its subject key can be listed (relying parties
 * choose which issuers to trust). The signing key is created (mode 0600) on first run; its public key is printed for pinning.
 */
import { parseArgs } from 'node:util';
import { b64u, publicKeyOf } from '@atlasauth/pca';
import { DirectoryLog } from './log';
import { FileDirectoryStore, loadOrCreateSecret, serveLog } from './node';

async function main(): Promise<void> {

  const { values } = parseArgs({
    options: {
      id: { type: 'string' },
      key: { type: 'string' },
      data: { type: 'string' },
      port: { type: 'string', default: '8080' },
      issuer: { type: 'string', multiple: true },
      witness: { type: 'string', multiple: true },
      'min-cosigs': { type: 'string', default: '0' },
      'max-per-hour': { type: 'string', default: '60' },
      'rotate-to': { type: 'string' },
      'rotation-threshold': { type: 'string', default: '1' },
    },
  });
  if (!values.id || !values.key || !values.data) {
    console.error('usage: pca-directory-log --id <log id> --key <file> --data <dir> [--port N] [--issuer <key> ...] [--witness <key> ...] [--min-cosigs N] [--max-per-hour N]');
    process.exit(2);
  }
  const { secret, created } = loadOrCreateSecret(values.key);
  const log = new DirectoryLog({
    id: values.id,
    secret,
    store: await FileDirectoryStore.open(values.data),
    issuers: values.issuer?.length ? values.issuer : 'any',
    witnessKeys: values.witness ?? [],
    flood: { max: Number(values['max-per-hour']), windowMs: 3_600_000 },
    rotationThreshold: Number(values['rotation-threshold']),
  });
  console.log(`log ${values.id}, signing key: ${b64u(publicKeyOf(secret))}${created ? ' (new)' : ''}`);
  await serveLog(log, { port: Number(values.port), host: process.env.HOST ?? '127.0.0.1', minCosigs: Number(values['min-cosigs']) });
  console.log(`listening on :${values.port}`);
  if (values['rotate-to']) {
    // Key rotation: propose the transition, let the witnesses cosign it (they pick it up on their next pass), then switch.
    const next = loadOrCreateSecret(values['rotate-to']);
    const { transition } = await log.proposeRotation(next.secret);
    console.log(`rotation proposed: ${transition.from} -> ${transition.to}; waiting for ${values['rotation-threshold']} witness cosignature(s)`);
    for (;;) {
      await new Promise((r) => setTimeout(r, 5000));
      try {
        const done = await log.completeRotation();
        console.log(`rotation complete (transition ${done.seq}); restart with --key ${values['rotate-to']} from now on`);
        break;
      } catch (e) {
        console.log(e instanceof Error ? e.message : String(e));
      }
    }
  }
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
