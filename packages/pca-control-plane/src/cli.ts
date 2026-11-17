#!/usr/bin/env node
/**
 * `pca-control-plane`: make and use the keys a human or a source holds.
 *
 *   pca-control-plane keygen [--out <file>]
 *   pca-control-plane sign unfreeze --directive <id> --key <file> [--ttl-sec 300]
 *   pca-control-plane sign revoke   --directive <id> --key <file> [--ttl-sec 300]
 *   pca-control-plane report --audit <pca-proxy audit log> --source <id> --key <file> --agent <name> --url <api origin> [--follow]
 *                            (the secret key `sk_...` comes from ATLAS_SECRET_KEY)
 *
 * A key file holds the base64url secret. Pin the printed public key under `auth_config.pca.controlPlane.humans` (a person who
 * may lift a freeze) or `.sources` (a gateway that reports events).
 */
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { b64u, decodeKey, generateKeyPair } from '@atlasauth/pca';
import { report } from './report';
import { MAX_HUMAN_ACTION_MS, signHumanAction } from './human';

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
}

export function run(argv: string[], out: (s: string) => void = (s) => process.stdout.write(`${s}\n`), now: () => number = Date.now): number {
  const [cmd, sub, ...rest] = argv;
  if (cmd === 'keygen') {
    const kp = generateKeyPair();
    const file = flag(argv, 'out');
    if (file) {
      writeFileSync(file, `${b64u(kp.secretKey)}\n`, { mode: 0o600, flag: 'wx' });
      out(`public key: ${b64u(kp.publicKey)}`);
      out(`secret key written to ${file}`);
    } else {
      out(JSON.stringify({ public: b64u(kp.publicKey), secret: b64u(kp.secretKey) }));
    }
    return 0;
  }
  if (cmd === 'sign' && (sub === 'unfreeze' || sub === 'revoke')) {
    const directive = flag(rest, 'directive');
    const keyFile = flag(rest, 'key');
    const ttl = Number(flag(rest, 'ttl-sec') ?? 300) * 1000;
    if (!directive || !keyFile || !Number.isFinite(ttl) || ttl < 1000 || ttl > MAX_HUMAN_ACTION_MS) {
      out(`usage: pca-control-plane sign ${sub} --directive <id> --key <file> [--ttl-sec 1..${MAX_HUMAN_ACTION_MS / 1000}]`);
      return 2;
    }
    const secret = decodeKey(readFileSync(keyFile, 'utf8').trim());
    const t = now();
    out(JSON.stringify(signHumanAction(secret, { op: sub, directive, nonce: randomBytes(16).toString('base64url'), iat: t, exp: t + ttl })));
    return 0;
  }
  out('usage: pca-control-plane keygen [--out <file>] | sign <unfreeze|revoke> --directive <id> --key <file> [--ttl-sec n]');
  return 2;
}

/** `run`, plus `report`, which needs the network. */
export async function runAsync(argv: string[], out: (s: string) => void = (s) => process.stdout.write(`${s}\n`)): Promise<number> {
  if (argv[0] !== 'report') return run(argv, out);
  const rest = argv.slice(1);
  const [file, source, keyFile, agent, url] = ['audit', 'source', 'key', 'agent', 'url'].map((n) => flag(rest, n));
  const apiKey = process.env.ATLAS_SECRET_KEY;
  if (!file || !source || !keyFile || !agent || !url || !apiKey) {
    out('usage: ATLAS_SECRET_KEY=sk_... pca-control-plane report --audit <file> --source <id> --key <file> --agent <name> --url <api origin> [--session <id>] [--follow]');
    return 2;
  }
  try {
    const n = await report({ file, source, secret: decodeKey(readFileSync(keyFile, 'utf8').trim()), agent, url, apiKey, follow: rest.includes('--follow'), out, ...(flag(rest, 'session') ? { session: flag(rest, 'session') as string } : {}) });
    out(`done: ${n} event(s) reported`);
    return 0;
  } catch (e) {
    out(`error: ${(e as Error).message}`);
    return 1;
  }
}

if (require.main === module) void runAsync(process.argv.slice(2)).then((c) => { process.exitCode = c; });
