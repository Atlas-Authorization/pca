import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';
import * as indexModule from './index';
import { run } from './cli';

/**
 * Executes the CLI source file as a script (the way `node cli.js ...` does): it is transpiled to CommonJS and run with
 * `require.main === module`, a stand-in `process` and the sibling modules the test already imported.
 */
type EntryEnv = 'main' | 'imported' | 'noRequire' | 'noModule';

function runAsEntry(args: string[], env: EntryEnv = 'main'): { exits: number[]; lines: string[] } {
  const exits: number[] = [];
  const lines: string[] = [];
  const fakeProcess = {
    argv: ['node', 'cli.js', ...args],
    exit: (code: number): void => {
      exits.push(code);
    },
    stdout: {
      write: (s: string): void => {
        lines.push(s.replace(/\n$/, ''));
      },
    },
  };
  const source = readFileSync(join(__dirname, 'cli.ts'), 'utf8');
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText.replace(/^#!.*\n/, '');
  const real = createRequire(join(__dirname, 'cli.ts'));
  const mod: { exports: Record<string, unknown> } = { exports: {} };
  const load = (id: string): unknown => {
    if (id === './index') return indexModule;
    if (id === 'node:process') return fakeProcess;
    return real(id);
  };
  // 'imported': the file is a required module, not the main script. 'noRequire' / 'noModule': a runtime without that CommonJS global
  // (the imports are routed through `__r`, so only the entry guard sees the missing binding).
  const req = Object.assign((id: string): unknown => load(id), { main: env === 'main' ? (mod as unknown) : env === 'imported' ? ({} as unknown) : undefined });
  const body = env === 'noRequire' ? js.replace(/\brequire\(/g, '__r(') : js;
  new Function('exports', 'require', 'module', '__filename', '__dirname', '__r', body)(
    mod.exports,
    env === 'noRequire' ? undefined : req,
    env === 'noModule' ? undefined : mod,
    join(__dirname, 'cli.ts'),
    __dirname,
    load,
  );
  return { exits, lines };
}

const inProcess = (argv: string[]): { code: number; lines: string[] } => {
  const lines: string[] = [];
  const code = run(argv, (s) => lines.push(s));
  return { code, lines };
};

describe('running the file as a script', () => {
  it('exits with the status of run() on the arguments after the interpreter and script path', () => {
    const noFiles = runAsEntry([]);
    expect(noFiles.exits).toEqual([2]);
    expect(noFiles.lines.join('\n')).toBe(inProcess([]).lines.join('\n'));
    expect(noFiles.lines[0]).toBe('error: no policy files given');
  });
  it('passes the real arguments through and exits 0 for --help', () => {
    const help = runAsEntry(['--help']);
    expect(help.exits).toEqual([0]);
    expect(help.lines.join('\n')).toBe(inProcess(['--help']).lines.join('\n'));
  });
  it('does not run when the file is loaded as a module of another program', () => {
    expect(runAsEntry(['--help'], 'imported')).toEqual({ exits: [], lines: [] });
  });
  it('does not run, and does not fail, where require or module is not defined', () => {
    expect(runAsEntry(['--help'], 'noRequire')).toEqual({ exits: [], lines: [] });
    expect(runAsEntry(['--help'], 'noModule')).toEqual({ exits: [], lines: [] });
  });
});
