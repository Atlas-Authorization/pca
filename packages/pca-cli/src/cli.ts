#!/usr/bin/env node
/**
 * `pca` — the PCA developer CLI entrypoint.
 *
 * A tiny, dependency-free argv parser dispatches to the pure command functions in `./index`. Input
 * that is a PCActn / JSON is read from a file path argument, or from STDIN when the argument is `-`.
 * Errors print to stderr and set a non-zero `process.exitCode` (we never call `process.exit`, so
 * buffered stdout always flushes first).
 */

import { readFileSync } from 'node:fs';

import { cmdDecode, cmdDiscovery, cmdExplain, cmdKeygen, cmdSimulate } from './index';

const USAGE = `pca — Proof-Carrying Authority dev CLI

Usage:
  pca decode <file|->                 Summarize a PCActn (JSON or base64url).
  pca explain <file|-> [--aud <id>]   Run the real verifier and explain each check (PASS/FAIL/—).
  pca keygen                          Mint a throwaway Ed25519 dev keypair (base64url).
  pca simulate <policy.json> <actions.json>
                                      Replay actions against a compiled policy (auto/step_up/deny).
  pca discovery --aud <id> [--suites a,b] [--stepup <url>] [--revocation <url>] [--beacon <url>] [--attest <url>]
                                      Emit a .well-known/pca-configuration document.

Notes:
  <-> reads from STDIN. Nothing here authorizes anything — the resource server's verifier decides.
`;

/** Read a positional file argument, or STDIN when it is '-'. */
function readSource(arg: string): string {
  if (arg === '-') return readFileSync(0, 'utf8');
  return readFileSync(arg, 'utf8');
}

interface ParsedArgs {
  positionals: string[];
  flags: Record<string, string>;
}

/**
 * Minimal hand-rolled parser (no dependency): everything after the sub-command, splitting
 * `--flag value` and `--flag=value` out of the positionals. A bare `--flag` with no value is treated
 * as the empty string.
 */
function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    if (a.startsWith('--')) {
      const body = a.slice(2);
      const eq = body.indexOf('=');
      if (eq >= 0) {
        flags[body.slice(0, eq)] = body.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next !== undefined && !next.startsWith('--')) {
          flags[body] = next;
          i++;
        } else {
          flags[body] = '';
        }
      }
    } else {
      positionals.push(a);
    }
  }
  return { positionals, flags };
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (command === undefined || command === '--help' || command === '-h' || command === 'help') {
    process.stdout.write(USAGE);
    return;
  }

  const { positionals, flags } = parseArgs(argv.slice(1));

  switch (command) {
    case 'decode': {
      const src = positionals[0];
      if (src === undefined) throw new Error("decode: expected a file path or '-' for STDIN");
      process.stdout.write(cmdDecode(readSource(src)) + '\n');
      return;
    }
    case 'explain': {
      const src = positionals[0];
      if (src === undefined) throw new Error("explain: expected a file path or '-' for STDIN");
      const opts: { audience?: string } = {};
      if (flags.aud !== undefined && flags.aud !== '') opts.audience = flags.aud;
      const res = await cmdExplain(readSource(src), opts);
      process.stdout.write(res.text + '\n');
      if (!res.allow) process.exitCode = 1;
      return;
    }
    case 'keygen': {
      process.stdout.write(cmdKeygen().text + '\n');
      return;
    }
    case 'simulate': {
      const policyPath = positionals[0];
      const actionsPath = positionals[1];
      if (policyPath === undefined || actionsPath === undefined) {
        throw new Error('simulate: expected <policy.json> <actions.json>');
      }
      process.stdout.write(cmdSimulate(readSource(policyPath), readSource(actionsPath)) + '\n');
      return;
    }
    case 'discovery': {
      if (flags.aud === undefined || flags.aud === '') throw new Error('discovery: --aud <id> is required');
      const endpoints: { attestation_challenge?: string; revocation_epoch?: string; liveness_beacon?: string; stepup?: string } = {};
      if (flags.attest) endpoints.attestation_challenge = flags.attest;
      if (flags.revocation) endpoints.revocation_epoch = flags.revocation;
      if (flags.beacon) endpoints.liveness_beacon = flags.beacon;
      if (flags.stepup) endpoints.stepup = flags.stepup;
      process.stdout.write(
        cmdDiscovery({
          audience: flags.aud,
          ...(flags.suites ? { suites: flags.suites.split(',').map((s) => s.trim()).filter(Boolean) } : {}),
          ...(Object.keys(endpoints).length ? { endpoints } : {}),
        }) + '\n',
      );
      break;
    }
    default:
      throw new Error(`unknown command '${command}'\n\n${USAGE}`);
  }
}

main().catch((e: unknown) => {
  process.stderr.write(`pca: ${e instanceof Error ? e.message : String(e)}\n`);
  process.exitCode = 1;
});
