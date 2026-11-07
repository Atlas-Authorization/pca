#!/usr/bin/env node
/**
 * pca-store-conformance --adapter ./my-adapter.mjs [options]
 * Exit codes: 0 pass, 1 a contract violation was found, 3 unresolved (no violation, but not every key could be decided),
 * 2 usage / adapter error.
 */
import { loadAdapter } from './load';
import type { StoreAdapter } from './types';
import { ALL_TESTS, formatReport, reportJson, runConformance, type ConformanceOptions, type TestName } from './runner';
import { ALL_PCA_STATE_TESTS, formatPcaStateReport, loadPcaStateAdapter, runPcaStateConformance, type PcaStateTestName } from './pca-state';

export const USAGE = `pca-store-conformance --adapter <module|builtin:name> [options]

  --adapter <path>        module exporting a store adapter (default export, 'adapter' or 'createAdapter(options)')
                          or builtin:in-memory | builtin:durable-file | builtin:bad-* (reference adapters)
  --option k=v            passed to the adapter factory (repeatable)
  --tests a,b             subset of: ${ALL_TESTS.join(', ')} (default all)
  --clients N             concurrent clients (default 16)
  --duration MS           concurrent run length (default 2000)
  --rounds N              same-key burst rounds (default 20)
  --revisit-keys N        retention run size (default 500)
  --processes N           crash test: client processes alive at once (default 3)
  --kill-every MS         crash test: SIGKILL one client process this often (default 400)
  --budget N              search states per key before it is UNRESOLVED (default 200000)
  --values N              advance tests: counter values are drawn from [0, N) (default 20)
  --seed N                workload PRNG seed, to reproduce a run (default random)
  --json                  print the report as JSON
  --profile pca-state     test the store behind requirePCA instead (a module exporting createPcaStateAdapter(options),
                          or builtin:in-memory | builtin:durable-file | builtin:bad-*); --tests then takes a subset of:
                          ${ALL_PCA_STATE_TESTS.join(', ')}
                          (--rounds = race rounds, default 10; --clients = copies per round, default 16; --processes)

Exit: 0 pass, 1 violation found, 3 unresolved, 2 usage or adapter error.`;

export interface CliArgs {
  adapter?: string;
  profile?: 'pca-state';
  /** --tests under `--profile pca-state`. */
  pcaStateTests?: PcaStateTestName[];
  options: Record<string, string>;
  json: boolean;
  help: boolean;
  conf: ConformanceOptions;
  processes?: number;
  killEveryMs?: number;
}

const num = (flag: string, v: string | undefined): number => {
  const n = Number(v);
  if (v === undefined || !Number.isFinite(n) || n < 0) throw new Error(`${flag} needs a non-negative number`);
  return n;
};

export function parseCli(argv: readonly string[]): CliArgs {
  const a: CliArgs = { options: {}, json: false, help: false, conf: {} };
  let rawTests: string[] | undefined;
  for (let i = 0; i < argv.length; i++) {
    const f = argv[i]!;
    const next = (): string | undefined => argv[++i];
    switch (f) {
      case '--adapter':
        a.adapter = next();
        break;
      case '--option': {
        const kv = next() ?? '';
        const eq = kv.indexOf('=');
        if (eq < 1) throw new Error('--option needs k=v');
        a.options[kv.slice(0, eq)] = kv.slice(eq + 1);
        break;
      }
      case '--tests':
        rawTests = (next() ?? '').split(',').filter(Boolean);
        break;
      case '--profile': {
        const p = next();
        if (p !== 'pca-state') throw new Error(`--profile: unknown profile ${String(p)} (known: pca-state)`);
        a.profile = p;
        break;
      }
      case '--clients':
        a.conf.clients = num(f, next());
        break;
      case '--duration':
        a.conf.durationMs = num(f, next());
        break;
      case '--rounds':
        a.conf.rounds = num(f, next());
        break;
      case '--revisit-keys':
        a.conf.revisitKeys = num(f, next());
        break;
      case '--processes':
        a.processes = num(f, next());
        break;
      case '--kill-every':
        a.killEveryMs = num(f, next());
        break;
      case '--budget':
        a.conf.budget = num(f, next());
        break;
      case '--values': {
        const n = num(f, next());
        if (!Number.isInteger(n) || n < 1) throw new Error('--values needs a positive integer');
        a.conf.values = n;
        break;
      }
      case '--seed': {
        const n = num(f, next());
        if (!Number.isInteger(n)) throw new Error('--seed needs a non-negative integer');
        a.conf.seed = n;
        break;
      }
      case '--json':
        a.json = true;
        break;
      case '-h':
      case '--help':
        a.help = true;
        break;
      default:
        throw new Error(`unknown argument ${f}`);
    }
  }
  if (rawTests) {
    const known: readonly string[] = a.profile === 'pca-state' ? ALL_PCA_STATE_TESTS : ALL_TESTS;
    const bad = rawTests.filter((x) => !known.includes(x));
    if (bad.length || rawTests.length === 0) throw new Error(`--tests: unknown test(s) ${bad.join(', ') || '(none given)'}`);
    if (a.profile === 'pca-state') a.pcaStateTests = rawTests as PcaStateTestName[];
    else a.conf.tests = rawTests as TestName[];
  }
  return a;
}

async function mainPcaState(args: CliArgs, print: (s: string) => void, printErr: (s: string) => void): Promise<number> {
  let adapter;
  try {
    adapter = await loadPcaStateAdapter(args.adapter!, args.options);
  } catch (e) {
    printErr(`cannot load adapter: ${(e as Error).message}`);
    return 2;
  }
  try {
    const r = await runPcaStateConformance(adapter, {
      ...(args.pcaStateTests ? { tests: args.pcaStateTests } : {}),
      ...(args.conf.rounds !== undefined ? { rounds: args.conf.rounds } : {}),
      ...(args.conf.clients !== undefined ? { copies: args.conf.clients } : {}),
      ...(args.processes !== undefined ? { processes: args.processes } : {}),
      claim: args.conf,
      module: args.adapter!,
      moduleOptions: args.options,
    });
    print(args.json ? JSON.stringify(r, null, 2) : formatPcaStateReport(r));
    return r.status === 'pass' ? 0 : r.status === 'fail' ? 1 : 3;
  } catch (e) {
    printErr(`conformance run failed: ${(e as Error).message}`);
    return 2;
  } finally {
    await adapter.teardown?.();
  }
}

/** Runs the CLI; returns the exit code. `print` / `printErr` are injectable for tests. */
export async function main(argv: readonly string[], print: (s: string) => void = console.log, printErr: (s: string) => void = console.error): Promise<number> {
  let args: CliArgs;
  try {
    args = parseCli(argv);
  } catch (e) {
    printErr(`${(e as Error).message}\n\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    print(USAGE);
    return 0;
  }
  if (!args.adapter) {
    printErr(`--adapter is required\n\n${USAGE}`);
    return 2;
  }
  if (args.profile === 'pca-state') return mainPcaState(args, print, printErr);
  let adapter: StoreAdapter;
  try {
    adapter = await loadAdapter(args.adapter, args.options);
  } catch (e) {
    printErr(`cannot load adapter: ${(e as Error).message}`);
    return 2;
  }
  try {
    const crash = { module: args.adapter, options: args.options, processes: args.processes, killEveryMs: args.killEveryMs };
    const r = await runConformance(adapter, { ...args.conf, crash });
    print(args.json ? reportJson(r) : formatReport(r));
    return r.status === 'pass' ? 0 : r.status === 'fail' ? 1 : 3;
  } catch (e) {
    printErr(`conformance run failed: ${(e as Error).message}`);
    return 2;
  } finally {
    await adapter.teardown?.();
  }
}

// Stryker disable next-line all: process entry glue
if (require.main === module) void main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
