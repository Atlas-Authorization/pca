#!/usr/bin/env node
/**
 * pca-directory-witness: run an independent witness for one or more directory logs.
 *
 *   pca-directory-witness --key witness.key --state witness-state.json \
 *     --log https://example.com/v1/pca/directory=<log guardian key> [--log ...] [--port 8787] [--interval 60]
 *
 * Operator commands (a witness that was down during a key rotation, or a rotation that was abandoned):
 *
 *   pca-directory-witness follow --key witness.key --state witness-state.json --from <the old log key> \
 *     --log https://example.com/v1/pca/directory=<the NEW log key> --transition <file or URL of the key transitions> \
 *     --witness <trusted witness key> [--witness ...] --threshold 2
 *   pca-directory-witness cancel-retirement --key witness.key --state witness-state.json --guardian <the old log key>
 *
 * `follow` verifies the witnessed transition chain (every transition signed by both keys and cosigned by the threshold of the trusted
 * witnesses) and that what this witness already cosigned is part of the handed-over history, then adopts the new key.
 * `cancel-retirement` lets a retired key sign again after the log gave up its rotation.
 *
 * The key file is created (mode 0600) when it does not exist; the witness public key is printed so the log operator can trust it.
 */
import { parseArgs } from 'node:util';
import { Witness } from './witness';
import { cancelRetirementCommand, followCommand } from './witness-cli';
import { FileWitnessState, loadOrCreateSecret, serveWitness, witnessOnce, type FollowedLog } from './node';

async function subcommand(name: 'follow' | 'cancel-retirement', argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: {
      key: { type: 'string' },
      state: { type: 'string' },
      from: { type: 'string' },
      guardian: { type: 'string' },
      log: { type: 'string' },
      transition: { type: 'string' },
      witness: { type: 'string', multiple: true },
      threshold: { type: 'string' },
    },
  });
  const need = (...names: string[]) => {
    const missing = names.filter((n) => !(values as Record<string, unknown>)[n]);
    if (missing.length > 0) {
      console.error(`missing --${missing.join(', --')}`);
      process.exit(2);
    }
  };
  if (name === 'cancel-retirement') {
    need('key', 'state', 'guardian');
    for (const line of await cancelRetirementCommand({ key: values.key!, state: values.state!, guardian: values.guardian! })) console.log(line);
    return;
  }
  need('key', 'state', 'from', 'log', 'transition', 'witness', 'threshold');
  const i = values.log!.lastIndexOf('=');
  if (i < 1) throw new Error('--log must be <url>=<new log key>');
  for (const line of await followCommand({
    key: values.key!,
    state: values.state!,
    from: values.from!,
    log: { url: values.log!.slice(0, i), guardian: values.log!.slice(i + 1) },
    transition: values.transition!,
    witnesses: values.witness!,
    threshold: Number(values.threshold),
  })) console.log(line);
}

async function main(): Promise<void> {
  const sub = process.argv[2];
  if (sub === 'follow' || sub === 'cancel-retirement') return subcommand(sub, process.argv.slice(3));

  const { values } = parseArgs({
    options: {
      key: { type: 'string' },
      state: { type: 'string' },
      log: { type: 'string', multiple: true },
      port: { type: 'string' },
      interval: { type: 'string', default: '60' },
      once: { type: 'boolean', default: false },
    },
  });

  if (!values.key || !values.state || !values.log?.length) {
    console.error('usage: pca-directory-witness --key <file> --state <file> --log <url>=<guardian key> [--log ...] [--port N] [--interval seconds] [--once]');
    process.exit(2);
  }
  const followed: FollowedLog[] = values.log.map((s) => {
    const i = s.lastIndexOf('=');
    if (i < 1) throw new Error(`--log must be <url>=<guardian key>: ${s}`);
    return { url: s.slice(0, i), guardian: s.slice(i + 1) };
  });
  const { secret, created } = loadOrCreateSecret(values.key);
  const state = new FileWitnessState(values.state);
  const witness = new Witness(secret, followed.map((l) => ({ guardian: l.guardian })), state);
  console.log(`witness key: ${witness.publicKey}${created ? ' (new)' : ''}`);

  if (values.port) {
    await serveWitness(witness, { port: Number(values.port), host: process.env.HOST ?? '127.0.0.1' });
    console.log(`listening on :${values.port}`);
  }
  const pass = async () => {
    for (const line of await witnessOnce(witness, state, followed)) console.log(line);
  };
  await pass();
  if (!values.once) setInterval(() => void pass(), Math.max(5, Number(values.interval)) * 1000);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
