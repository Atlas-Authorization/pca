import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { lintRulesDigest } from '@atlasauth/pca-actions';

vi.mock('./index', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./index')>();
  return {
    ...actual,
    lint: vi.fn(actual.lint),
    diffCommand: vi.fn(actual.diffCommand),
    testCommand: vi.fn(actual.testCommand),
    coverageCommand: vi.fn(actual.coverageCommand),
  };
});

import { coverageCommand, diffCommand, lint, testCommand, type Finding } from './index';
import { parseArgs, run } from './cli';

const dir = mkdtempSync(join(tmpdir(), 'pca-policy-ci-clikill-'));
let counter = 0;
const file = (name: string, body: unknown): string => {
  const p = join(dir, `${counter++}-${name}`);
  writeFileSync(p, typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
  return p;
};
const cap = (argv: string[]): { code: number; lines: string[]; out: string } => {
  const lines: string[] = [];
  const code = run(argv, (s) => lines.push(s));
  return { code, lines, out: lines.join('\n') };
};
const lintMock = vi.mocked(lint);
const diffMock = vi.mocked(diffCommand);
const testMock = vi.mocked(testCommand);
const covMock = vi.mocked(coverageCommand);

beforeEach(() => {
  lintMock.mockClear();
  diffMock.mockClear();
  testMock.mockClear();
  covMock.mockClear();
});

const DOC = { predicates: [] };
const f = (rule: Finding['rule'], severity: Finding['severity'], message: string, where?: string): Finding =>
  where === undefined ? { rule, severity, message } : { rule, severity, message, where };
const SUMMARY = (e: number, w: number, i: number, n: number, threshold = 'error', ok = e === 0) =>
  `\n${ok ? 'PASS' : 'FAIL'} — ${e} error(s), ${w} warning(s), ${i} info across ${n} policy/policies (fail threshold: ${threshold})`;

describe('parseArgs', () => {
  const ok = (args: Record<string, unknown>) => ({ args: { files: [], maxSeverity: 'error', format: 'text', quiet: false, help: false, ...args } });

  it('defaults carry no schema or pin key', () => {
    expect(parseArgs([])).toStrictEqual(ok({}));
    expect(parseArgs(['a.json', 'b.json'])).toStrictEqual(ok({ files: ['a.json', 'b.json'] }));
  });
  it('skips holes in the argument list', () => {
    const sparse = ['a.json', , 'b.json'] as unknown as string[];
    expect(parseArgs(sparse)).toStrictEqual(ok({ files: ['a.json', 'b.json'] }));
  });
  it('help and quiet, long and short', () => {
    expect(parseArgs(['--help'])).toStrictEqual(ok({ help: true }));
    expect(parseArgs(['-h'])).toStrictEqual(ok({ help: true }));
    expect(parseArgs(['--quiet'])).toStrictEqual(ok({ quiet: true }));
    expect(parseArgs(['-q'])).toStrictEqual(ok({ quiet: true }));
  });
  it('--lint-rules-pin takes a file that does not look like an option', () => {
    expect(parseArgs(['--lint-rules-pin', 'p.txt'])).toStrictEqual(ok({ lintRulesPin: 'p.txt' }));
    expect(parseArgs(['--lint-rules-pin', 'pin-'])).toStrictEqual(ok({ lintRulesPin: 'pin-' }));
    expect(parseArgs(['--lint-rules-pin'])).toStrictEqual({ error: '--lint-rules-pin expects a file' });
    expect(parseArgs(['--lint-rules-pin', '-q'])).toStrictEqual({ error: '--lint-rules-pin expects a file' });
    expect(parseArgs(['--lint-rules-pin', '--quiet', 'a.json'])).toStrictEqual({ error: '--lint-rules-pin expects a file' });
  });
  it('--max-severity accepts exactly the three severities, as two words or with =', () => {
    for (const s of ['error', 'warn', 'info']) {
      expect(parseArgs(['--max-severity', s])).toStrictEqual(ok({ maxSeverity: s }));
      expect(parseArgs([`--max-severity=${s}`])).toStrictEqual(ok({ maxSeverity: s }));
    }
    const bad = { error: '--max-severity expects one of error|warn|info' };
    expect(parseArgs(['--max-severity'])).toStrictEqual(bad);
    expect(parseArgs(['--max-severity', 'fatal'])).toStrictEqual(bad);
    expect(parseArgs(['--max-severity', 'ERROR'])).toStrictEqual(bad);
    expect(parseArgs(['--max-severity', ''])).toStrictEqual(bad);
    expect(parseArgs(['--max-severity=fatal'])).toStrictEqual(bad);
    expect(parseArgs(['--max-severity='])).toStrictEqual(bad);
  });
  it('--schema takes a file, as two words or with =', () => {
    expect(parseArgs(['--schema', 's.json'])).toStrictEqual(ok({ schema: 's.json' }));
    expect(parseArgs(['--schema=s.json'])).toStrictEqual(ok({ schema: 's.json' }));
    expect(parseArgs(['--schema'])).toStrictEqual({ error: '--schema expects a file' });
  });
  it('--format is text or github', () => {
    expect(parseArgs(['--format', 'text'])).toStrictEqual(ok({ format: 'text' }));
    expect(parseArgs(['--format', 'github'])).toStrictEqual(ok({ format: 'github' }));
    expect(parseArgs(['--format=text'])).toStrictEqual(ok({ format: 'text' }));
    expect(parseArgs(['--format=github'])).toStrictEqual(ok({ format: 'github' }));
    const bad = { error: `--format expects 'text' or 'github'` };
    expect(parseArgs(['--format'])).toStrictEqual(bad);
    expect(parseArgs(['--format', 'json'])).toStrictEqual(bad);
    expect(parseArgs(['--format=json'])).toStrictEqual(bad);
    expect(parseArgs(['--format='])).toStrictEqual(bad);
  });
  it('an unknown option is named', () => {
    expect(parseArgs(['--nope'])).toStrictEqual({ error: `unknown option '--nope'` });
    expect(parseArgs(['a.json', '-x'])).toStrictEqual({ error: `unknown option '-x'` });
    expect(parseArgs(['-'])).toStrictEqual({ error: `unknown option '-'` });
  });
});

describe('run: usage and help', () => {
  it('--help prints the help text and exits 0', () => {
    const r = cap(['--help']);
    expect(r.code).toBe(0);
    expect(r.lines).toHaveLength(1);
    expect(r.lines[0]).toMatch(/^pca-policy-ci — statically catch unsafe PCA policies before they ship\./);
    expect(r.lines[0]).toContain('Usage:');
    expect(r.lines[0]).toContain('--lint-rules-pin <file>');
    expect(cap(['-h']).code).toBe(0);
    expect(cap(['-h', 'x.json']).lines).toHaveLength(1);
  });
  it('a bad option prints its error, then the help, and exits 2', () => {
    const r = cap(['--format', 'xml']);
    expect(r.code).toBe(2);
    expect(r.lines).toHaveLength(2);
    expect(r.lines[0]).toBe(`--format expects 'text' or 'github'`);
    expect(r.lines[1]).toContain('Usage:');
  });
  it('no files prints the error, then the help, and exits 2', () => {
    const r = cap([]);
    expect(r.code).toBe(2);
    expect(r.lines).toHaveLength(2);
    expect(r.lines[0]).toBe('error: no policy files given');
    expect(r.lines[1]).toContain('Usage:');
    expect(cap(['--quiet']).lines[0]).toBe('error: no policy files given');
  });
  it('the default writer sends each line to stdout with a newline', () => {
    const spy = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    try {
      run([]);
      const calls = spy.mock.calls.map((c) => String(c[0]));
      expect(calls).toHaveLength(2);
      expect(calls[0]).toBe('error: no policy files given\n');
      expect(calls[1]!.startsWith('pca-policy-ci — ')).toBe(true);
      expect(calls[1]!.endsWith('\n')).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('run: text output', () => {
  const FINDINGS = [f('over-broad-grant', 'error', 'm1', 'predicates[0]'), f('redundant-caveat', 'warn', 'm2'), f('redundant-caveat', 'info', 'm3', 'caveats[1]')];

  it('prints the label, one aligned line per finding, then the summary', () => {
    const p = file('a.json', DOC);
    lintMock.mockReturnValueOnce(FINDINGS);
    expect(cap([p])).toStrictEqual({
      code: 1,
      lines: [`\n${p}:`, '  ERROR over-broad-grant [predicates[0]]: m1', '  WARN  redundant-caveat: m2', '  INFO  redundant-caveat [caveats[1]]: m3', SUMMARY(1, 1, 1, 1)],
      out: expect.any(String),
    });
  });
  it('--quiet drops the labels and the clean marker but keeps findings and the summary', () => {
    const p = file('a.json', DOC);
    const q = file('b.json', DOC);
    lintMock.mockReturnValueOnce(FINDINGS).mockReturnValueOnce([]);
    const r = cap([p, q, '--quiet']);
    expect(r.code).toBe(1);
    expect(r.lines).toStrictEqual(['  ERROR over-broad-grant [predicates[0]]: m1', '  WARN  redundant-caveat: m2', '  INFO  redundant-caveat [caveats[1]]: m3', SUMMARY(1, 1, 1, 2)]);
  });
  it('a clean policy shows (clean) unless quiet', () => {
    const p = file('a.json', DOC);
    lintMock.mockReturnValueOnce([]);
    expect(cap([p])).toMatchObject({ code: 0, lines: [`\n${p}:`, '  (clean)', SUMMARY(0, 0, 0, 1)] });
    lintMock.mockReturnValueOnce([]);
    expect(cap([p, '-q'])).toMatchObject({ code: 0, lines: [SUMMARY(0, 0, 0, 1)] });
  });
  it('every file gets its own block, in order', () => {
    const p = file('a.json', DOC);
    const q = file('b.json', DOC);
    lintMock.mockReturnValueOnce([]).mockReturnValueOnce([f('redundant-caveat', 'warn', 'w')]);
    expect(cap([p, q]).lines).toStrictEqual([`\n${p}:`, '  (clean)', `\n${q}:`, '  WARN  redundant-caveat: w', SUMMARY(0, 1, 0, 2)]);
  });
  it('the threshold decides the exit code and is named in the summary', () => {
    const p = file('a.json', DOC);
    lintMock.mockReturnValueOnce([f('redundant-caveat', 'warn', 'w')]);
    expect(cap([p, '--max-severity', 'warn'])).toMatchObject({ code: 1 });
    lintMock.mockReturnValueOnce([f('redundant-caveat', 'warn', 'w')]);
    const r = cap([p, '--max-severity=error']);
    expect(r.code).toBe(0);
    expect(r.lines.at(-1)).toBe(SUMMARY(0, 1, 0, 1, 'error', true));
    lintMock.mockReturnValueOnce([f('redundant-caveat', 'info', 'i')]);
    expect(cap([p, '--max-severity=info']).lines.at(-1)).toBe(SUMMARY(0, 0, 1, 1, 'info', false));
  });
});

describe('run: files that cannot be linted', () => {
  it('a missing file and an invalid JSON file are reported as malformed-policy errors', () => {
    const missing = join(dir, 'does-not-exist.json');
    const bad = file('bad.json', '{nope');
    const r = cap([missing, bad]);
    expect(r.code).toBe(1);
    expect(r.lines[0]).toBe(`\n${missing}:`);
    expect(r.lines[1]).toMatch(/^ {2}ERROR malformed-policy: cannot read file: /);
    expect(r.lines[2]).toBe(`\n${bad}:`);
    expect(r.lines[3]).toMatch(/^ {2}ERROR malformed-policy: invalid JSON: ./);
    expect(r.lines[4]).toBe(SUMMARY(2, 0, 0, 2));
    expect(lintMock).not.toHaveBeenCalled();
  });
  it('a readable file is parsed and linted, with no schema key when none is given', () => {
    const doc = { predicates: [{ verb: 'a.b' }], caveats: [] };
    const p = file('a.json', doc);
    lintMock.mockReturnValueOnce([]);
    cap([p]);
    expect(lintMock.mock.calls).toHaveLength(1);
    expect(lintMock.mock.calls[0]![0]).toEqual(doc);
    expect(lintMock.mock.calls[0]![1]).toStrictEqual({});
  });
});

describe('run: --schema', () => {
  it('the schema file is parsed once and handed to every lint call', () => {
    const schema = [{ verb: 'a.b', params: {} }];
    const s = file('schema.json', schema);
    const p = file('a.json', DOC);
    const q = file('b.json', DOC);
    lintMock.mockReturnValueOnce([]).mockReturnValueOnce([]);
    expect(cap([p, q, '--schema', s]).code).toBe(0);
    expect(lintMock.mock.calls.map((c) => c[1])).toStrictEqual([{ schema }, { schema }]);
    lintMock.mockReturnValueOnce([]);
    cap([p, `--schema=${s}`]);
    expect(lintMock.mock.calls[2]![1]).toStrictEqual({ schema });
  });
  it('an unreadable or invalid schema file stops the run with exit 2 and names the file', () => {
    const p = file('a.json', DOC);
    const missing = join(dir, 'no-schema.json');
    const r = cap([p, '--schema', missing]);
    expect(r.code).toBe(2);
    expect(r.lines).toHaveLength(1);
    expect(r.lines[0]!.startsWith(`${missing}: `)).toBe(true);
    const bad = file('badschema.json', '{oops');
    const r2 = cap([p, '--schema', bad]);
    expect(r2.code).toBe(2);
    expect(r2.lines).toHaveLength(1);
    expect(r2.lines[0]!.startsWith(`${bad}: `)).toBe(true);
    expect(lintMock).not.toHaveBeenCalled();
  });
});

describe('run: github annotations', () => {
  it('one workflow command per finding with the level mapped, and no label or clean lines', () => {
    const p = file('a.json', DOC);
    const q = file('b.json', DOC);
    lintMock
      .mockReturnValueOnce([f('over-broad-grant', 'error', 'm1', 'predicates[0]'), f('redundant-caveat', 'warn', 'm2'), f('redundant-caveat', 'info', 'm3', 'caveats[1]')])
      .mockReturnValueOnce([]);
    const r = cap([p, q, '--format', 'github']);
    expect(r.code).toBe(1);
    expect(r.lines).toStrictEqual([
      `::error file=${p},title=over-broad-grant::predicates[0]: m1`,
      `::warning file=${p},title=redundant-caveat::m2`,
      `::notice file=${p},title=redundant-caveat::caveats[1]: m3`,
      SUMMARY(1, 1, 1, 2),
    ]);
  });
  it('escapes the file name and the message so neither can inject properties or commands', () => {
    const p = file('a%b,c:d.json', DOC);
    lintMock.mockReturnValueOnce([f('redundant-caveat', 'warn', 'p%q\r\nr:s,t', 'w')]);
    const r = cap([p, '--format=github']);
    const line = r.lines[0]!;
    expect(line).toContain('a%25b%2Cc%3Ad.json,title=redundant-caveat::');
    expect(line.endsWith('::w: p%25q%0D%0Ar:s,t')).toBe(true);
    expect(line.startsWith('::warning file=')).toBe(true);
    expect(line).not.toMatch(/[\r\n]/);
  });
});

describe('run: --lint-rules-pin', () => {
  const digest = lintRulesDigest();
  it('a matching pin passes on its own', () => {
    const pin = file('pin', `${digest}\n`);
    expect(cap(['--lint-rules-pin', pin])).toMatchObject({ code: 0, lines: [`PASS — lint rules digest ${digest} matches the pin`] });
  });
  it('a matching pin is followed by the normal run when files are given', () => {
    const pin = file('pin', digest);
    const p = file('a.json', DOC);
    lintMock.mockReturnValueOnce([]);
    const r = cap(['--lint-rules-pin', pin, p]);
    expect(r.code).toBe(0);
    expect(r.lines).toStrictEqual([`PASS — lint rules digest ${digest} matches the pin`, `\n${p}:`, '  (clean)', SUMMARY(0, 0, 0, 1)]);
  });
  it('a wrong pin fails on its own, and still fails a run whose policies pass', () => {
    const pin = file('pin', 'A'.repeat(43));
    const alone = cap(['--lint-rules-pin', pin]);
    expect(alone.code).toBe(1);
    expect(alone.lines).toHaveLength(1);
    expect(alone.lines[0]!.startsWith(`FAIL — lint rules digest ${digest} differs from the pin `)).toBe(true);
    const p = file('a.json', DOC);
    lintMock.mockReturnValueOnce([]);
    const both = cap(['--lint-rules-pin', pin, p]);
    expect(both.code).toBe(1);
    expect(both.lines[0]!.startsWith('FAIL — ')).toBe(true);
    expect(both.lines.at(-1)).toBe(SUMMARY(0, 0, 0, 1));
  });
  it('an unreadable pin file fails', () => {
    const r = cap(['--lint-rules-pin', join(dir, 'absent-pin')]);
    expect(r.code).toBe(1);
    expect(r.lines[0]!.startsWith('FAIL — cannot read the lint rules pin: ')).toBe(true);
  });
  it('a passing pin does not hide failing policies', () => {
    const pin = file('pin', digest);
    const p = file('a.json', DOC);
    lintMock.mockReturnValueOnce([f('over-broad-grant', 'error', 'bad')]);
    expect(cap(['--lint-rules-pin', pin, p]).code).toBe(1);
  });
});

describe('run: authoring subcommands', () => {
  const ok = (lines: string[], exitCode: 0 | 1 | 2 = 0) => ({ ok: exitCode === 0, exitCode, lines });
  const a = file('old.json', { n: 'old' });
  const b = file('new.json', { n: 'new' });

  it('diff passes every flag it was given, and nothing else, to the command', () => {
    diffMock.mockReturnValueOnce(ok(['one', 'two']));
    const r = cap(['diff', a, b, '--allow-widen', '--verb', 'pay', '--amount-field', 'amt', '--integer', '--window-secs', '60', '--max-exposure-increase', '3']);
    expect(r).toMatchObject({ code: 0, lines: ['one', 'two'] });
    expect(diffMock.mock.calls[0]).toStrictEqual([{ n: 'old' }, { n: 'new' }, { allowWiden: true, verb: 'pay', amountField: 'amt', integer: true, windowSecs: 60, maxExposureIncrease: 3 }]);
  });
  it('diff with no flags passes only the two booleans, false', () => {
    diffMock.mockReturnValueOnce(ok(['x']));
    cap(['diff', a, b]);
    expect(diffMock.mock.calls[0]![2]).toStrictEqual({ allowWiden: false, integer: false });
  });
  it('diff keeps a zero window and a zero exposure allowance, and accepts any amount field text', () => {
    diffMock.mockReturnValueOnce(ok(['x']));
    cap(['diff', a, b, '--window-secs', '0', '--max-exposure-increase', '0', '--amount-field', 'not a number']);
    expect(diffMock.mock.calls[0]![2]).toStrictEqual({ allowWiden: false, amountField: 'not a number', integer: false, windowSecs: 0, maxExposureIncrease: 0 });
    diffMock.mockReturnValueOnce(ok(['x']));
    cap(['diff', a, b, '--window-secs', '1e2', '--verb', 'v']);
    expect(diffMock.mock.calls[1]![2]).toStrictEqual({ allowWiden: false, verb: 'v', integer: false, windowSecs: 100 });
  });
  it('test passes requireDigest from the flag', () => {
    testMock.mockReturnValueOnce(ok(['t']));
    expect(cap(['test', a, b])).toMatchObject({ code: 0, lines: ['t'] });
    expect(testMock.mock.calls[0]).toStrictEqual([{ n: 'old' }, { n: 'new' }, { requireDigest: false }]);
    testMock.mockReturnValueOnce(ok(['t']));
    cap(['test', a, b, '--require-digest']);
    expect(testMock.mock.calls[1]![2]).toStrictEqual({ requireDigest: true });
    expect(diffMock).not.toHaveBeenCalled();
    expect(covMock).not.toHaveBeenCalled();
  });
  it('coverage passes each threshold it was given, including zero', () => {
    covMock.mockReturnValueOnce(ok(['c']));
    cap(['coverage', a, b]);
    expect(covMock.mock.calls[0]).toStrictEqual([{ n: 'old' }, { n: 'new' }, {}]);
    covMock.mockReturnValueOnce(ok(['c']));
    cap(['coverage', a, b, '--min-clauses', '0.5', '--min-boundaries', '0.25', '--min-mutation', '1', '--max-survivors', '0']);
    expect(covMock.mock.calls[1]![2]).toStrictEqual({ minClauses: 0.5, minBoundaries: 0.25, minMutation: 1, maxSurvivors: 0 });
    for (const [flag, key] of [['--min-clauses', 'minClauses'], ['--min-boundaries', 'minBoundaries'], ['--min-mutation', 'minMutation'], ['--max-survivors', 'maxSurvivors']] as const) {
      covMock.mockReturnValueOnce(ok(['c']));
      cap(['coverage', a, b, flag, '2']);
      expect(covMock.mock.calls.at(-1)![2]).toStrictEqual({ [key]: 2 });
    }
    expect(testMock).not.toHaveBeenCalled();
    expect(diffMock).not.toHaveBeenCalled();
  });
  it('returns the command exit code and prints each of its lines', () => {
    diffMock.mockReturnValueOnce(ok(['FAIL: x', 'FAIL'], 1));
    expect(cap(['diff', a, b])).toMatchObject({ code: 1, lines: ['FAIL: x', 'FAIL'] });
    covMock.mockReturnValueOnce(ok(['bad input'], 2));
    expect(cap(['coverage', a, b])).toMatchObject({ code: 2, lines: ['bad input'] });
  });
  it('flags that need a value say so when it is missing', () => {
    for (const flag of ['--verb', '--amount-field', '--window-secs', '--max-exposure-increase', '--min-clauses', '--min-boundaries', '--min-mutation', '--max-survivors']) {
      const r = cap(['diff', a, b, flag]);
      expect(r).toMatchObject({ code: 2, lines: [`${flag} expects a value`] });
    }
    expect(diffMock).not.toHaveBeenCalled();
  });
  it('numeric flags must be finite numbers', () => {
    for (const flag of ['--window-secs', '--max-exposure-increase', '--min-clauses', '--min-boundaries', '--min-mutation', '--max-survivors']) {
      for (const v of ['lots', '', '   ', 'Infinity', 'NaN']) {
        expect(cap(['coverage', a, b, flag, v])).toMatchObject({ code: 2, lines: [`${flag} expects a number, got '${v}'`] });
      }
    }
    expect(covMock).not.toHaveBeenCalled();
  });
  it('an unknown option is named and exits 2', () => {
    expect(cap(['diff', a, b, '--nope'])).toMatchObject({ code: 2, lines: [`unknown option '--nope'`] });
    expect(cap(['test', a, b, '-x'])).toMatchObject({ code: 2, lines: [`unknown option '-x'`] });
    expect(cap(['coverage', a, b, '-'])).toMatchObject({ code: 2, lines: [`unknown option '-'`] });
  });
  it('exactly two files are required, and the help follows the error', () => {
    for (const cmd of ['diff', 'test', 'coverage']) {
      for (const files of [[], [a], [a, b, a]]) {
        const r = cap([cmd, ...files]);
        expect(r.code).toBe(2);
        expect(r.lines).toHaveLength(2);
        expect(r.lines[0]).toBe(`error: ${cmd} takes exactly two files`);
        expect(r.lines[1]).toContain('Usage:');
      }
    }
    expect(diffMock).not.toHaveBeenCalled();
  });
  it('an unreadable or invalid file stops the command with exit 2, naming the first bad file', () => {
    const missing = join(dir, 'gone.json');
    const bad = file('invalid.json', '{nope');
    const r1 = cap(['diff', a, missing]);
    expect(r1.code).toBe(2);
    expect(r1.lines).toHaveLength(1);
    expect(r1.lines[0]!.startsWith(`${missing}: `)).toBe(true);
    const r2 = cap(['test', bad, missing]);
    expect(r2.code).toBe(2);
    expect(r2.lines).toHaveLength(1);
    expect(r2.lines[0]!.startsWith(`${bad}: `)).toBe(true);
    const r3 = cap(['coverage', missing, a]);
    expect(r3.lines[0]!.startsWith(`${missing}: `)).toBe(true);
    expect(diffMock).not.toHaveBeenCalled();
    expect(testMock).not.toHaveBeenCalled();
    expect(covMock).not.toHaveBeenCalled();
  });
  it('a subcommand name is only recognised as the first argument', () => {
    lintMock.mockReturnValueOnce([]);
    cap([a, 'diff']);
    expect(diffMock).not.toHaveBeenCalled();
    expect(lintMock).toHaveBeenCalledTimes(1);
  });
});

// The severity list and the severity-to-tag tables are built when the module loads: these load a fresh copy inside the test.
describe('module tables, loaded fresh', () => {
  const freshCli = async () => {
    vi.resetModules();
    const idx = await import('./index');
    const cli = await import('./cli');
    return { lint: vi.mocked(idx.lint), cli };
  };
  const FINDINGS = [f('over-broad-grant', 'error', 'm1', 'predicates[0]'), f('redundant-caveat', 'warn', 'm2'), f('redundant-caveat', 'info', 'm3', 'caveats[1]')];
  const capWith = (run: (argv: string[], write: (s: string) => void) => number, argv: string[]): string[] => {
    const lines: string[] = [];
    run(argv, (s) => lines.push(s));
    return lines;
  };

  it('the --max-severity refusal lists the three severities', async () => {
    const { cli } = await freshCli();
    expect(cli.parseArgs(['--max-severity', 'fatal'])).toStrictEqual({ error: '--max-severity expects one of error|warn|info' });
    expect(cli.parseArgs(['--max-severity=fatal'])).toStrictEqual({ error: '--max-severity expects one of error|warn|info' });
  });
  it('text tags and github levels for each severity', async () => {
    const { lint: lintFresh, cli } = await freshCli();
    const p = file('a.json', DOC);
    lintFresh.mockReturnValueOnce(FINDINGS);
    expect(capWith(cli.run, [p])).toStrictEqual([`\n${p}:`, '  ERROR over-broad-grant [predicates[0]]: m1', '  WARN  redundant-caveat: m2', '  INFO  redundant-caveat [caveats[1]]: m3', SUMMARY(1, 1, 1, 1)]);
    lintFresh.mockReturnValueOnce(FINDINGS);
    expect(capWith(cli.run, [p, '--format', 'github'])).toStrictEqual([
      `::error file=${p},title=over-broad-grant::predicates[0]: m1`,
      `::warning file=${p},title=redundant-caveat::m2`,
      `::notice file=${p},title=redundant-caveat::caveats[1]: m3`,
      SUMMARY(1, 1, 1, 1),
    ]);
  });
});
