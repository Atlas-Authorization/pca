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
import { lint, summarize, type Finding, type LabeledFindings, type Severity } from './index';

interface CliArgs {
  files: string[];
  maxSeverity: Severity;
  format: 'text' | 'github';
  quiet: boolean;
  help: boolean;
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

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === undefined) continue;
    if (a === '--help' || a === '-h') {
      help = true;
    } else if (a === '--quiet' || a === '-q') {
      quiet = true;
    } else if (a === '--max-severity') {
      const v = argv[++i];
      if (v === undefined || !isSeverity(v)) return { error: `--max-severity expects one of ${SEVERITIES.join('|')}` };
      maxSeverity = v;
    } else if (a.startsWith('--max-severity=')) {
      const v = a.slice('--max-severity='.length);
      if (!isSeverity(v)) return { error: `--max-severity expects one of ${SEVERITIES.join('|')}` };
      maxSeverity = v;
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
  return { args: { files, maxSeverity, format, quiet, help } };
}

const HELP = `pca-policy-ci — statically catch unsafe PCA policies before they ship.

Usage:
  pca-policy-ci <files...> [options]

Options:
  --max-severity <error|warn|info>  Lowest severity that fails the gate (default: error)
  --format <text|github>            Output format (default: text; 'github' = workflow annotations)
  --quiet, -q                       Only print findings and the summary line
  --help, -h                        Show this help

Each file is a JSON policy (Envelope / grant / compiled / { predicates, caveats }) or a JSON array
treated as a delegation chain. Exits non-zero when any finding is at or above --max-severity.`;

function lintFile(file: string): Finding[] {
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
  return lint(doc);
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

function printGithub(results: LabeledFindings[], write: (s: string) => void): void {
  for (const r of results) {
    for (const f of r.findings) {
      const props = [`file=${escapeGh(r.label)}`, `title=${escapeGh(f.rule)}`].join(',');
      const loc = f.where !== undefined ? `${f.where}: ` : '';
      write(`::${GH_LEVEL[f.severity]} ${props}::${escapeGh(`${loc}${f.message}`)}`);
    }
  }
}

export function run(argv: readonly string[], write: (s: string) => void = (s) => process.stdout.write(s + '\n')): number {
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
  if (args.files.length === 0) {
    write('error: no policy files given');
    write(HELP);
    return 2;
  }

  const results: LabeledFindings[] = args.files.map((file) => ({ label: file, findings: lintFile(file) }));
  const summary = summarize(results, { maxSeverity: args.maxSeverity });

  if (args.format === 'github') printGithub(results, write);
  else printText(results, args.quiet, write);

  write(
    `\n${summary.ok ? 'PASS' : 'FAIL'} — ${summary.counts.error} error(s), ${summary.counts.warn} warning(s), ${summary.counts.info} info across ${results.length} policy/policies (fail threshold: ${summary.maxSeverity})`,
  );
  return summary.exitCode;
}

// Entry point (skipped when imported by tests). Guarded so it is inert under a test runner that may
// not provide the CommonJS `require`/`module` globals.
if (typeof require !== 'undefined' && typeof module !== 'undefined' && require.main === module) {
  process.exit(run(process.argv.slice(2)));
}
