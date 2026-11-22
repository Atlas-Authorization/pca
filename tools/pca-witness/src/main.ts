/**
 * pca-witness: run a transparency-log witness.
 *
 *   pca-witness init  --key <file>                   create a witness key file (mode 0600) and print the PUBLIC key
 *   pca-witness serve --key <file> --state <dir> --logs <file> [--port 8080] [--host 0.0.0.0]
 *
 * The key file holds 32 random bytes, base64url. The logs file is JSON: [{ "instance_id", "principal", "guardian_public" }].
 * Nothing but the public key and per-request status lines is ever printed.
 */
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { b64u, publicKeyOf, unb64u } from '@atlasauth/pca';
import { openDurableState } from '@atlasauth/pca/durable-state';
import { createWitnessServer } from './server';
import { Witness, type WitnessLog } from './witness';

function flag(args: string[], name: string, def?: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : def;
}
const die = (msg: string): never => {
  process.stderr.write(`pca-witness: ${msg}\n`);
  process.exit(2);
};

export function loadKey(file: string): Uint8Array {
  if (!existsSync(file)) die(`key file ${file} does not exist (create it with: pca-witness init --key ${file})`);
  // owner-only (0600/0400), or group-readable (0640/0440) for orchestrators that mount secrets with a group; never writable by the group, never visible to others
  const mode = statSync(file).mode & 0o777;
  if ((mode & 0o037) !== 0) die(`key file ${file} has mode ${mode.toString(8)}; it must not be accessible to others or writable by the group (use 600, 400 or 440)`);
  let key: Uint8Array;
  try {
    key = unb64u(readFileSync(file, 'utf8').trim());
  } catch {
    return die(`key file ${file} is not base64url`);
  }
  if (key.length !== 32) die(`key file ${file} must hold exactly 32 bytes`);
  return key;
}

export function loadLogs(file: string): WitnessLog[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return die(`logs file ${file} is missing or not JSON`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) die('the logs file must be a non-empty JSON array');
  return parsed as WitnessLog[];
}

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  if (cmd === 'init') {
    const file = flag(args, 'key') ?? die('init needs --key <file>');
    if (existsSync(file!)) die(`${file} already exists; refusing to overwrite a witness key`);
    const secret = randomBytes(32);
    writeFileSync(file!, `${b64u(secret)}\n`, { mode: 0o600 });
    chmodSync(file!, 0o600);
    process.stdout.write(`${b64u(publicKeyOf(new Uint8Array(secret)))}\n`);
    return;
  }
  if (cmd !== 'serve') return die('usage: pca-witness init --key <file> | serve --key <file> --state <dir> --logs <file> [--port 8080] [--host 0.0.0.0]');
  const witnessSecret = loadKey(flag(args, 'key') ?? die('serve needs --key <file>'));
  const logs = loadLogs(flag(args, 'logs') ?? die('serve needs --logs <file>'));
  const kv = await openDurableState({ dir: flag(args, 'state') ?? die('serve needs --state <dir>') });
  const witness = new Witness({ kv, witnessSecret, logs });
  const port = Number(flag(args, 'port', process.env['PORT'] ?? '8080'));
  const host = flag(args, 'host', '0.0.0.0')!;
  const server = createWitnessServer(witness, (l) => process.stdout.write(`${new Date().toISOString()} ${l}\n`));
  server.listen(port, host, () => process.stdout.write(`pca-witness ${witness.publicKey} listening on ${host}:${port} for ${logs.length} log(s)\n`));
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => server.close(() => process.exit(0)));
}

if (require.main === module) void main();
