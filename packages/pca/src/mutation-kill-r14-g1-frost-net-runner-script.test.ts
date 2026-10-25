/**
 * r14 g1: frost-net-runner.ts main(), run IN THIS PROCESS as if it were the entry script.
 *
 * main() only runs when `require.main === module`, so before this file it only ever ran in spawned child processes.
 * Stryker's vitest runner always reports in-process mutant coverage (even with coverage analysis off), so every main()
 * mutant was planned as NoCoverage and never run. Here the module is compiled the way Node runs a script: a fresh CJS
 * Module, made process.mainModule, compiled through tsx's CommonJS loader, so its own `require.main === module` is true.
 * process.argv / the env / exit / stdout / stderr are stubbed for the run and the signal handlers it installs are called
 * directly (never a real signal to this worker). Each run compiles the source again, so the active mutant applies.
 */
import Module, { createRequire } from 'node:module';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { frostTrustedDealerKeygen } from './frost';
import { generateKeyPair } from './keys';
import { b64u } from './hash';

const RUNNER = resolve(__dirname, 'frost-net-runner.ts');
const kg = frostTrustedDealerKeygen(2, 3);
const policy = generateKeyPair();
const p1 = kg.participantShares[0]!;
const cfg = { identifier: p1.identifier, share: b64u(p1.share), groupPublicKey: b64u(kg.groupPublicKey), threshold: 2, policyAuthorityPublicKey: b64u(policy.publicKey) };

interface ScriptRun {
  exits: number[];
  stdout: string;
  stderr: string;
  /** names of the process events main() subscribed to */
  subscribed: string[];
  /** result of calling each new SIGTERM / SIGINT handler: the exit codes recorded after it */
  afterSignal?: number[];
  /** HTTP status of a request to the signer while it was up */
  reachable?: number;
}

type ModuleInternals = typeof Module & {
  _nodeModulePaths(dir: string): string[];
  _extensions: Record<string, (m: Module, filename: string) => void>;
};

/** Run frost-net-runner.ts as the entry script with `argv` / `env`; optionally deliver `signal` once it is ready. */
async function runAsScript(argv: string[], env: Record<string, string | undefined>, signal?: 'SIGTERM' | 'SIGINT'): Promise<ScriptRun> {
  const req = createRequire(import.meta.url);
  const { register } = req('tsx/cjs/api') as { register(): () => void };
  const unregister = register();
  const out: ScriptRun = { exits: [], stdout: '', stderr: '', subscribed: [] };
  const savedArgv = process.argv;
  const savedEnv = { ...process.env };
  const savedMain = (process as { mainModule?: unknown }).mainModule;
  const before = new Map(['SIGTERM', 'SIGINT', ''].map((e) => [e, process.listeners(e as NodeJS.Signals).slice()]));
  const exit = vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    out.exits.push(code ?? 0);
  }) as never);
  const so = vi.spyOn(process.stdout, 'write').mockImplementation(((c: unknown) => ((out.stdout += String(c)), true)) as never);
  const se = vi.spyOn(process.stderr, 'write').mockImplementation(((c: unknown) => ((out.stderr += String(c)), true)) as never);
  const origOn = process.on.bind(process);
  const onSpy = vi.spyOn(process, 'on').mockImplementation(((ev: string, fn: (...a: unknown[]) => void) => {
    out.subscribed.push(ev);
    return origOn(ev as NodeJS.Signals, fn);
  }) as never);
  const added: Array<[string, (...a: unknown[]) => void]> = [];
  try {
    process.argv = [process.execPath, RUNNER, ...argv];
    for (const [k, v] of Object.entries(env)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    const m = new Module(RUNNER);
    m.filename = RUNNER;
    m.paths = (Module as ModuleInternals)._nodeModulePaths(dirname(RUNNER));
    (process as { mainModule?: unknown }).mainModule = m;
    (Module as ModuleInternals)._extensions['.ts']!(m, RUNNER);
    // main() is async: wait for an exit or the ready line
    const deadline = Date.now() + 8_000;
    while (Date.now() < deadline && out.exits.length === 0 && !out.stdout.includes('\n')) await new Promise((r) => setTimeout(r, 10));
    for (const [e, list] of before) for (const fn of process.listeners(e as NodeJS.Signals)) if (!list.includes(fn)) added.push([e, fn as (...a: unknown[]) => void]);
    if (out.stdout.startsWith('FROST_SIGNER_READY ')) {
      const info = JSON.parse(out.stdout.slice('FROST_SIGNER_READY '.length)) as { url: string };
      out.reachable = (await fetch(`${info.url}/nope`, { method: 'POST' })).status;
      if (signal) {
        const n = out.exits.length;
        for (const [e, fn] of added) if (e === signal) fn();
        const d2 = Date.now() + 8_000;
        while (Date.now() < d2 && out.exits.length === n) await new Promise((r) => setTimeout(r, 10));
        out.afterSignal = out.exits.slice(n);
      }
    }
    if (out.exits.length > 0) await new Promise((r) => setTimeout(r, 50)); // let a catch() after an exit finish
  } finally {
    // close a still-running server through its own handler (stubbed exit), then drop every listener main() added
    const stillUp = out.stdout.startsWith('FROST_SIGNER_READY ') && (out.afterSignal === undefined || out.afterSignal.length === 0);
    if (stillUp) for (const [e, fn] of added) if (e === 'SIGTERM' || e === 'SIGINT') { fn(); break; }
    if (stillUp) await new Promise((r) => setTimeout(r, 200));
    for (const [e, fn] of added) process.removeListener(e as NodeJS.Signals, fn);
    onSpy.mockRestore();
    exit.mockRestore();
    so.mockRestore();
    se.mockRestore();
    process.argv = savedArgv;
    for (const k of Object.keys(process.env)) if (!(k in savedEnv)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    (process as { mainModule?: unknown }).mainModule = savedMain;
    unregister();
  }
  return out;
}

let tmp = '';
let good = '';
let bad = '';
beforeAll(() => {
  tmp = mkdtempSync(join(tmpdir(), 'fnr-script-'));
  good = join(tmp, 'good.json');
  bad = join(tmp, 'bad.json');
  writeFileSync(good, JSON.stringify(cfg));
  writeFileSync(bad, JSON.stringify({ ...cfg, share: 'not-a-share' }));
});
afterAll(() => {
  if (tmp) rmSync(tmp, { recursive: true, force: true });
});

/** The parsed ready line, or a placeholder that fails the comparison (never a throw: a mutant must fail an assertion). */
const ready = (r: ScriptRun): { prefix: string; info: { identifier: number; url: string; port: number } } => {
  const line = r.stdout.split('\n')[0]!;
  try {
    return { prefix: line.slice(0, 'FROST_SIGNER_READY '.length), info: JSON.parse(line.slice('FROST_SIGNER_READY '.length)) as { identifier: number; url: string; port: number } };
  } catch {
    return { prefix: line, info: { identifier: -1, url: '', port: -1 } };
  }
};

describe('frost-net-runner main() in-process, as the entry script', () => {
  it('config from argv: serves, prints exactly one ready line, subscribes SIGTERM + SIGINT, exits 0 on SIGTERM', async () => {
    const r = await runAsScript([good], { FROST_SIGNER_CONFIG: undefined }, 'SIGTERM');
    const { prefix, info } = ready(r);
    expect({ prefix, info, lines: r.stdout.split('\n').length, stderr: r.stderr, subscribed: r.subscribed, reachable: r.reachable, afterSignal: r.afterSignal }).toEqual({
      prefix: 'FROST_SIGNER_READY ',
      info: { identifier: p1.identifier, url: `http://127.0.0.1:${info.port}`, port: info.port },
      lines: 2,
      stderr: '',
      subscribed: ['SIGTERM', 'SIGINT'],
      reachable: 404,
      afterSignal: [0],
    });
  }, 30_000);

  it('config from $FROST_SIGNER_CONFIG when argv has none; SIGINT also shuts down with exit 0', async () => {
    const r = await runAsScript([], { FROST_SIGNER_CONFIG: good }, 'SIGINT');
    expect({ id: ready(r).info.identifier, stderr: r.stderr, afterSignal: r.afterSignal, exitsBefore: r.exits.length - (r.afterSignal?.length ?? 0) }).toEqual({
      id: p1.identifier,
      stderr: '',
      afterSignal: [0],
      exitsBefore: 0,
    });
  }, 30_000);

  it('argv wins over $FROST_SIGNER_CONFIG', async () => {
    const r = await runAsScript([good], { FROST_SIGNER_CONFIG: bad }, 'SIGTERM');
    expect({ id: ready(r).info.identifier, stderr: r.stderr, afterSignal: r.afterSignal }).toEqual({ id: p1.identifier, stderr: '', afterSignal: [0] });
  }, 30_000);

  it('no config path: the usage line on stderr, then exit 2, before anything else', async () => {
    const r = await runAsScript([], { FROST_SIGNER_CONFIG: undefined });
    expect({ firstExit: r.exits[0], stdout: r.stdout, firstLine: r.stderr.split('\n')[0] }).toEqual({
      firstExit: 2,
      stdout: '',
      firstLine: 'usage: tsx frost-net-runner.ts <config.json>  (or set FROST_SIGNER_CONFIG)',
    });
  }, 30_000);

  it('a refused config: the error STACK on stderr, prefixed, then exit 1, and no ready line', async () => {
    const r = await runAsScript([bad], { FROST_SIGNER_CONFIG: undefined });
    expect({ exits: r.exits, stdout: r.stdout, head: r.stderr.split('\n')[0], second: r.stderr.split('\n')[1]?.startsWith('    at '), endsNl: r.stderr.endsWith('\n') }).toEqual({
      exits: [1],
      stdout: '',
      head: "frost-net-runner: Error: frost-net-runner: field 'share' is not 32-byte canonical base64url",
      second: true,
      endsNl: true,
    });
  }, 30_000);

  it('a config file that is not JSON: the SyntaxError stack, then exit 1', async () => {
    const notJson = join(tmp, 'x.json');
    writeFileSync(notJson, 'not json');
    const r = await runAsScript([notJson], { FROST_SIGNER_CONFIG: undefined });
    expect({ exits: r.exits, head: r.stderr.split('\n')[0]!.startsWith('frost-net-runner: SyntaxError: ') }).toEqual({ exits: [1], head: true });
  }, 30_000);
});
