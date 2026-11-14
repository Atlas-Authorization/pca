#!/usr/bin/env node
/**
 * pca-policy-ci — CLI for the PCA policy-safety gate.
 *
 * Usage:
 *   pca-policy-ci <files...> [--max-severity error|warn|info] [--format text|github] [--quiet]
 *
 * Each file is a JSON policy document: an `Envelope`, a minted grant (`Capability`), a compiled
 * policy, a bare `{ predicates, caveats }`, or a JSON ARRAY (treated as a delegation chain). Findings
 * are printed and the process exits non-zero when any finding is at or above `--max-severity`
 * (default `error`). `--format github` emits GitHub-Actions workflow annotations.
 */

import { readFileSync } from 'node:fs';
import process from 'node:process';
import { checkLintRulesPin, coverageCommand, diffCommand, lint, summarize, testCommand, type AuthoringResult, type Finding, type LabeledFindings, type Severity } from './index';

interface CliArgs {
  files: string[];
  maxSeverity: Severity;
  format: 'text' | 'github';
  quiet: boolean;
  help: boolean;
  schema?: string;
  /** File holding the pinned action-kit lint rule-list digest to enforce. */
  lintRulesPin?: string;
}

const SEVERITIES: readonly Severity[] = ['error', 'warn', 'info'];

function isSeverity(x: string): x is Severity {
  return x === 'error' || x === 'warn' || x === 'info';
}

export function parseArgs(argv: readonly string[]): { args: CliArgs } | { error: string } {
  const files: string[] = [];
  let maxSeverity: Severity = 'error';
  let format: 'text' | 'github' = 'text';
  let quiet = false;
  let help = false;
  let schema: string | undefined;
  let lintRulesPin: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    if (a === '--help' || a === '-h') {
      help = true;
    } else if (a === '--quiet' || a === '-q') {
      quiet = true;
    } else if (a === '--lint-rules-pin') {
      const v = argv[++i];
      if (v === undefined || v.startsWith('-')) return { error: '--lint-rules-pin expects a file' };
      lintRulesPin = v;
    } else if (a === '--max-severity') {
      const v = argv[++i];
      if (v === undefined || !isSeverity(v)) return { error: `--max-severity expects one of ${SEVERITIES.join('|')}` };
      maxSeverity = v;
    } else if (a.startsWith('--max-severity=')) {
      const v = a.slice('--max-severity='.length);
      if (!isSeverity(v)) return { error: `--max-severity expects one of ${SEVERITIES.join('|')}` };
      maxSeverity = v;
    } else if (a === '--schema') {
      const v = argv[++i];
      if (v === undefined) return { error: '--schema expects a file' };
      schema = v;
    } else if (a.startsWith('--schema=')) {
      schema = a.slice('--schema='.length);
    } else if (a === '--format') {
      const v = argv[++i];
      if (v !== 'text' && v !== 'github') return { error: `--format expects 'text' or 'github'` };
      format = v;
    } else if (a.startsWith('--format=')) {
      const v = a.slice('--format='.length);
      if (v !== 'text' && v !== 'github') return { error: `--format expects 'text' or 'github'` };
      format = v;
    } else if (a.startsWith('-')) {
      return { error: `unknown option '${a}'` };
    } else {
      files.push(a);
    }
  }
  return { args: { files, maxSeverity, format, quiet, help, ...(schema !== undefined ? { schema } : {}), ...(lintRulesPin !== undefined ? { lintRulesPin } : {}) } };
}

const HELP = `pca-policy-ci — statically catch unsafe PCA policies before they ship.

Usage:
  pca-policy-ci <files...> [options]
  pca-policy-ci diff <old.json> <new.json> [--allow-widen] [--verb V [--integer] [--amount-field F] [--window-secs N] [--max-exposure-increase N]]
  pca-policy-ci test <policy.json> <tests.json> [--require-digest]
  pca-policy-ci coverage <policy.json> <traffic-or-tests.json> [--min-clauses R] [--min-boundaries R] [--min-mutation R] [--max-survivors N]

Options:
  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)
  --format <text|github>            Output format (default: text; 'github' = workflow annotations)
  --schema <file>                   Also check each policy against this signed action schema (JSON)
  --lint-rules-pin <file>           Fail unless the action-kit lint rule list has the digest in <file>
  --quiet, -q                       Only print findings and the summary line
  --help, -h                        Show this help

Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array
treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.`;

function lintFile(file: string, schema?: unknown): Finding[] {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (e) {
    return [{ rule: 'malformed-policy', severity: 'error', message: `cannot read file: ${e instanceof Error ? e.message : String(e)}` }];
  }
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    return [{ rule: 'malformed-policy', severity: 'error', message: `invalid JSON: ${e instanceof Error ? e.message : String(e)}` }];
  }
  return lint(doc, schema !== undefined ? { schema: schema as never } : {});
}

const GH_LEVEL: Record<Severity, string> = { error: 'error', warn: 'warning', info: 'notice' };
const TEXT_TAG: Record<Severity, string> = { error: 'ERROR', warn: 'WARN', info: 'INFO' };

function printText(results: LabeledFindings[], quiet: boolean, write: (s: string) => void): void {
  for (const r of results) {
    if (!quiet) write(`\n${r.label}:`);
    if (r.findings.length === 0) {
      if (!quiet) write('  (clean)');
      continue;
    }
    for (const f of r.findings) {
      const loc = f.where !== undefined ? ` [${f.where}]` : '';
      write(`  ${TEXT_TAG[f.severity].padEnd(5)} ${f.rule}${loc}: ${f.message}`);
    }
  }
}

function escapeGh(s: string): string {
  return s.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/** Workflow-command PROPERTY values must also escape `:` and `,`, or a file name can add properties or end the command. */
function escapeGhProp(s: string): string {
  return escapeGh(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function printGithub(results: LabeledFindings[], write: (s: string) => void): void {
  for (const r of results) {
    for (const f of r.findings) {
      const props = [`file=${escapeGhProp(r.label)}`, `title=${escapeGhProp(f.rule)}`].join(',');
      const loc = f.where !== undefined ? `${f.where}: ` : '';
      write(`::${GH_LEVEL[f.severity]} ${props}::${escapeGh(`${loc}${f.message}`)}`);
    }
  }
}

function readJson(file: string): { ok: true; doc: unknown } | { ok: false; reason: string } {
  try {
    return { ok: true, doc: JSON.parse(readFileSync(file, 'utf8')) };
  } catch (e) {
    return { ok: false, reason: `${file}: ${e instanceof Error ? e.message : String(e)}` };
  }
}

const num = (flags: Map<string, string | true>, k: string): number | undefined => {
  const v = flags.get(k);
  return typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v)) ? Number(v) : undefined;
};

/** `diff`, `test` and `coverage`: two files and flags. Unknown or malformed flags are a usage error (exit 2). */
function runAuthoring(cmd: string, rest: readonly string[], write: (s: string) => void): number {
  const files: string[] = [];
  const flags = new Map<string, string | true>();
  const valued = new Set(['--verb', '--amount-field', '--window-secs', '--max-exposure-increase', '--min-clauses', '--min-boundaries', '--min-mutation', '--max-survivors']);
  const bools = new Set(['--allow-widen', '--integer', '--require-digest']);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (valued.has(a)) {
      const v = rest[++i];
      if (v === undefined) {
        write(`${a} expects a value`);
        return 2;
      }
      flags.set(a, v);
    } else if (bools.has(a)) flags.set(a, true);
    else if (a.startsWith('-')) {
      write(`unknown option '${a}'`);
      return 2;
    } else files.push(a);
  }
  for (const [k, v] of flags) {
    if (valued.has(k) && k !== '--verb' && k !== '--amount-field' && num(flags, k) === undefined) {
      write(`${k} expects a number, got '${String(v)}'`);
      return 2;
    }
  }
  if (files.length !== 2) {
    write(`error: ${cmd} takes exactly two files`);
    write(HELP);
    return 2;
  }
  const docs = files.map(readJson);
  const failed = docs.find((d) => !d.ok);
  if (failed && !failed.ok) {
    write(failed.reason);
    return 2;
  }
  const [a, b] = docs.map((d) => (d.ok ? d.doc : undefined)) as [unknown, unknown];
  let r: AuthoringResult;
  if (cmd === 'diff') {
    r = diffCommand(a, b, {
      allowWiden: flags.has('--allow-widen'),
      ...(typeof flags.get('--verb') === 'string' ? { verb: flags.get('--verb') as string } : {}),
      ...(typeof flags.get('--amount-field') === 'string' ? { amountField: flags.get('--amount-field') as string } : {}),
      integer: flags.has('--integer'),
      ...(num(flags, '--window-secs') !== undefined ? { windowSecs: num(flags, '--window-secs')! } : {}),
      ...(num(flags, '--max-exposure-increase') !== undefined ? { maxExposureIncrease: num(flags, '--max-exposure-increase')! } : {}),
    });
  } else if (cmd === 'test') r = testCommand(a, b, { requireDigest: flags.has('--require-digest') });
  else {
    r = coverageCommand(a, b, {
      ...(num(flags, '--min-clauses') !== undefined ? { minClauses: num(flags, '--min-clauses')! } : {}),
      ...(num(flags, '--min-boundaries') !== undefined ? { minBoundaries: num(flags, '--min-boundaries')! } : {}),
      ...(num(flags, '--min-mutation') !== undefined ? { minMutation: num(flags, '--min-mutation')! } : {}),
      ...(num(flags, '--max-survivors') !== undefined ? { maxSurvivors: num(flags, '--max-survivors')! } : {}),
    });
  }
  for (const l of r.lines) write(l);
  return r.exitCode;
}

export function run(argv: readonly string[], write: (s: string) => void = (s) => process.stdout.write(s + '\n')): number {
  if (argv[0] === 'diff' || argv[0] === 'test' || argv[0] === 'coverage') return runAuthoring(argv[0], argv.slice(1), write);
  const parsed = parseArgs(argv);
  if ('error' in parsed) {
    write(parsed.error);
    write(HELP);
    return 2;
  }
  const { args } = parsed;
  if (args.help) {
    write(HELP);
    return 0;
  }
  let pinFailed = false;
  if (args.lintRulesPin !== undefined) {
    let r;
    try { r = checkLintRulesPin(readFileSync(args.lintRulesPin, 'utf8')); } catch (e) { r = { ok: false, message: `cannot read the lint rules pin: ${e instanceof Error ? e.message : String(e)}` }; }
    write(`${r.ok ? 'PASS' : 'FAIL'} — ${r.message}`);
    pinFailed = !r.ok;
    if (args.files.length === 0) return pinFailed ? 1 : 0;
  }
  if (args.files.length === 0) {
    write('error: no policy files given');
    write(HELP);
    return 2;
  }

  let schema: unknown;
  if (args.schema !== undefined) {
    const s = readJson(args.schema);
    if (!s.ok) {
      write(s.reason);
      return 2;
    }
    schema = s.doc;
  }
  const results: LabeledFindings[] = args.files.map((file) => ({ label: file, findings: lintFile(file, schema) }));
  const summary = summarize(results, { maxSeverity: args.maxSeverity });

  if (args.format === 'github') printGithub(results, write);
  else printText(results, args.quiet, write);

  if (summary.reason) write(`error: ${summary.reason}`);
  write(
    `\n${summary.ok ? 'PASS' : 'FAIL'} — ${summary.counts.error} error(s), ${summary.counts.warn} warning(s), ${summary.counts.info} info across ${results.length} policy/policies (fail threshold: ${summary.maxSeverity})`,
  );
  return pinFailed ? Math.max(1, summary.exitCode) : summary.exitCode;
}

// Entry point (skipped when imported by tests). Guarded so it is inert under a test runner that may
// not provide the CommonJS `require`/`module` globals.
if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
  process.exit(run(process.argv.slice(2)));
}
