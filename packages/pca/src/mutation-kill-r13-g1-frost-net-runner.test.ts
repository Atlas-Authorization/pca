/**
 * r13 g1: frost-net-runner.ts. Its only test (frost-net.test.ts) runs it as a child OS process, which perTest coverage never
 * sees, so every mutant was NoCoverage. This file drives it both ways:
 *  - in-process: buildService / runSigner (exact field refusals, port/host pinning, the exact ready line);
 *  - as real child processes (the `main()` entry point): argv vs $FROST_SIGNER_CONFIG, the usage exit, the error exit,
 *    graceful SIGTERM / SIGINT shutdown. Under Stryker the active mutant id is forwarded to the child through
 *    __STRYKER_ACTIVE_MUTANT__ (the instrumented source reads it), and this file runs with coverage analysis off
 *    (scripts/pca-ci-workflows/pca/scripts/ts-stryker-shard.sh).
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { frostTrustedDealerKeygen } from './frost';
import { generateKeyPair } from './keys';
import { b64u } from './hash';
import type { SignerRunnerConfig } from './frost-net-runner';

// The module is imported dynamically, with process.exit and stderr stubbed, so that a mutant which runs main() at import
// time (the `require.main === module` guard forced true) is caught by an assertion instead of exiting the test worker.
type Runner = typeof import('./frost-net-runner');
let mod: Runner;
let importEffects: { exitCalls: unknown[][]; stderr: string[] } = { exitCalls: [], stderr: [] };
beforeAll(async () => {
  const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
  const err = vi.spyOn(process.stderr, 'write').mockImplementation((() => true) as never);
  try {
    mod = await import('./frost-net-runner');
    await new Promise((r) => setTimeout(r, 200)); // let an import-time main() run to completion
    importEffects = { exitCalls: exit.mock.calls.map((c) => [...c]), stderr: err.mock.calls.map((c) => String(c[0])) };
  } finally {
    exit.mockRestore();
    err.mockRestore();
  }
});
const buildService: Runner['buildService'] = (cfg) => mod.buildService(cfg);
const runSigner: Runner['runSigner'] = (cfg) => mod.runSigner(cfg);

const RUNNER = resolve(__dirname, 'frost-net-runner.ts');
const kg = frostTrustedDealerKeygen(2, 3);
const policy = generateKeyPair();
const p1 = kg.participantShares[0]!;
const good = (): SignerRunnerConfig => ({
  identifier: p1.identifier,
  share: b64u(p1.share),
  groupPublicKey: b64u(kg.groupPublicKey),
  threshold: 2,
  policyAuthorityPublicKey: b64u(policy.publicKey),
});
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');

beforeEach(() => {
  const am = (globalThis as { __stryker__?: { activeMutant?: unknown } }).__stryker__?.activeMutant;
  if (am === undefined) delete process.env.__STRYKER_ACTIVE_MUTANT__;
  else process.env.__STRYKER_ACTIVE_MUTANT__ = String(am);
});

describe('frost-net-runner import', () => {
  it('importing the module (not running it as a script) starts nothing, writes nothing and never exits', () => {
    expect(importEffects).toEqual({ exitCalls: [], stderr: [] });
  });
});

describe('frost-net-runner buildService (in-process)', () => {
  it('builds a signer holding exactly the configured share', () => {
    const s = buildService(good());
    expect(s.identifier).toBe(p1.identifier);
    expect(hex(s.verificationShare)).toBe(hex(p1.publicKey));
    expect(hex(s.enrollment().publicKey)).toBe(hex(p1.publicKey));
  });

  it.each([
    ['share', 32],
    ['groupPublicKey', 32],
    ['policyAuthorityPublicKey', 32],
  ] as const)('refuses a non-canonical %s with the exact field name', (field, len) => {
    for (const bad of ['', b64u(new Uint8Array(31)), b64u(new Uint8Array(33)), `${good()[field]}=`]) {
      expect(() => buildService({ ...good(), [field]: bad })).toThrow(
        new Error(`frost-net-runner: field '${field}' is not ${len}-byte canonical base64url`),
      );
    }
  });
});

describe('frost-net-runner runSigner (in-process)', () => {
  let writes: string[] = [];
  let closeMe: (() => Promise<void>) | undefined;
  beforeEach(() => {
    writes = [];
    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    await closeMe?.();
    closeMe = undefined;
  });

  it('listens on an ephemeral loopback port and prints exactly one ready line', async () => {
    const http = await runSigner(good());
    closeMe = http.close;
    expect(http.port).toBeGreaterThan(0);
    expect(http.url).toBe(`http://127.0.0.1:${http.port}`);
    expect(writes).toEqual([`FROST_SIGNER_READY {"identifier":${p1.identifier},"url":"http://127.0.0.1:${http.port}","port":${http.port}}\n`]);
  });

  it('honours a pinned port and host', async () => {
    // find a free port, release it, then pin it
    const probe = await runSigner(good());
    const port = probe.port;
    await probe.close();
    writes = [];
    const http = await runSigner({ ...good(), port, host: 'localhost' });
    closeMe = http.close;
    expect(http.port).toBe(port);
    expect(http.url).toBe(`http://localhost:${port}`);
    expect(writes).toEqual([`FROST_SIGNER_READY {"identifier":${p1.identifier},"url":"http://localhost:${port}","port":${port}}\n`]);
  });

  it('a refused config never starts a server or prints a ready line', async () => {
    await expect(runSigner({ ...good(), share: 'x' })).rejects.toThrow("frost-net-runner: field 'share' is not 32-byte canonical base64url");
    expect(writes).toEqual([]);
  });
});

// ---- the main() entry point, as real OS processes ------------------------------------------------------------------

interface Ran {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

/** Spawns the runner; when it prints its ready line, calls onReady (e.g. to send a signal). Kills it after `limitMs`. */
function run(args: string[], env: Record<string, string | undefined>, onReady?: (child: ReturnType<typeof spawn>, line: string) => void, limitMs = 20_000): Promise<Ran> {
  return new Promise((res, rej) => {
    const childEnv: Record<string, string | undefined> = { ...process.env, ...env };
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete childEnv[k];
    const child = spawn(process.execPath, ['--import', 'tsx', RUNNER, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: childEnv as NodeJS.ProcessEnv });
    let stdout = '';
    let stderr = '';
    let readied = false;
    const timer = setTimeout(() => child.kill('SIGKILL'), limitMs);
    child.stdout!.on('data', (d: Buffer) => {
      stdout += d.toString();
      const line = stdout.split('\n').find((l) => l.startsWith('FROST_SIGNER_READY '));
      if (line && stdout.includes(`${line}\n`) && !readied) {
        readied = true;
        onReady?.(child, line);
      }
    });
    child.stderr!.on('data', (d: Buffer) => (stderr += d.toString()));
    child.on('error', rej);
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      res({ code, signal, stdout, stderr });
    });
  });
}

/** After the ready line: one HTTP round trip (so the child has finished main(), incl. its signal handlers), then `sig`. */
const pingThen =
  (sig: NodeJS.Signals, seen?: (status: number) => void) =>
  (child: ReturnType<typeof spawn>, line: string): void => {
    const info = JSON.parse(line.slice('FROST_SIGNER_READY '.length)) as { url: string };
    void fetch(`${info.url}/nope`, { method: 'POST' })
      .then((x) => seen?.(x.status))
      .catch(() => undefined)
      .finally(() => child.kill(sig));
  };

describe('frost-net-runner main() (child processes)', () => {
  let tmp = '';
  let cfgPath = '';
  let badPath = '';
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'frost-runner-r13-'));
    cfgPath = join(tmp, 'signer.json');
    badPath = join(tmp, 'bad.json');
    writeFileSync(cfgPath, JSON.stringify(good()));
    writeFileSync(badPath, JSON.stringify({ ...good(), share: 'not-a-share' }));
  });
  afterAll(() => {
    if (tmp) rmSync(tmp, { recursive: true, force: true });
  });

  const readyLine = (r: Ran): { identifier: number; url: string; port: number } => {
    const lines = r.stdout.split('\n').filter((l) => l !== '');
    expect(lines).toHaveLength(1);
    expect(lines[0]!.startsWith('FROST_SIGNER_READY {')).toBe(true);
    return JSON.parse(lines[0]!.slice('FROST_SIGNER_READY '.length)) as { identifier: number; url: string; port: number };
  };

  it('config from argv: serves, prints the ready line, and exits 0 on SIGTERM', async () => {
    let reachable = 0;
    const r = await run([cfgPath], { FROST_SIGNER_CONFIG: undefined }, pingThen('SIGTERM', (st) => (reachable = st)));
    expect({ code: r.code, signal: r.signal, stderr: r.stderr }).toEqual({ code: 0, signal: null, stderr: '' });
    const info = readyLine(r);
    expect(info).toEqual({ identifier: p1.identifier, url: `http://127.0.0.1:${info.port}`, port: info.port });
    expect(reachable).toBe(404);
  }, 30_000);

  it('config from $FROST_SIGNER_CONFIG (no argv): serves and exits 0 on SIGINT', async () => {
    const r = await run([], { FROST_SIGNER_CONFIG: cfgPath }, pingThen('SIGINT'));
    expect({ code: r.code, signal: r.signal, stderr: r.stderr }).toEqual({ code: 0, signal: null, stderr: '' });
    expect(readyLine(r).identifier).toBe(p1.identifier);
  }, 30_000);

  it('argv wins over $FROST_SIGNER_CONFIG', async () => {
    const r = await run([cfgPath], { FROST_SIGNER_CONFIG: badPath }, pingThen('SIGTERM'));
    expect({ code: r.code, signal: r.signal, stderr: r.stderr }).toEqual({ code: 0, signal: null, stderr: '' });
    expect(readyLine(r).identifier).toBe(p1.identifier);
  }, 30_000);

  it('no config path at all: prints the usage line and exits 2', async () => {
    const r = await run([], { FROST_SIGNER_CONFIG: undefined });
    expect(r).toEqual({
      code: 2,
      signal: null,
      stdout: '',
      stderr: 'usage: tsx frost-net-runner.ts <config.json>  (or set FROST_SIGNER_CONFIG)\n',
    });
  }, 30_000);

  it('a refused config: prints the error stack and exits 1, with no ready line', async () => {
    const r = await run([badPath], { FROST_SIGNER_CONFIG: undefined });
    expect({ code: r.code, signal: r.signal, stdout: r.stdout }).toEqual({ code: 1, signal: null, stdout: '' });
    expect(r.stderr.startsWith("frost-net-runner: Error: frost-net-runner: field 'share' is not 32-byte canonical base64url\n    at ")).toBe(true);
    expect(r.stderr.endsWith('\n')).toBe(true);
  }, 30_000);
});
