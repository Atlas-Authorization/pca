// Oracle: @atlasauth/pca-store-conformance, the command line (argument parsing, usage text, exit codes of the usage paths). The pure
// history logic is covered by the shared store-conformance oracle; this one only adds what that one lacks. Deterministic.
// PORTING (net.atlasauth.pca.storeconformance.Cli / Kit):
//   consts()       -> {DEFAULT_SEARCH_BUDGET: Kit.DEFAULT_SEARCH_BUDGET, ALL_TESTS: Kit.ALL_TESTS, USAGE: Cli.USAGE}
//   parseCli(argv) -> Cli.parseCli(argv): JSON {options, json, help, conf, adapter?, profile?, pcaStateTests?, processes?, killEveryMs?}
//   main(argv)    -> Cli.main(argv, print, printErr) -> {code, out, err}; only paths that never load an adapter
import { Oracle, refWrite } from './lib.mjs';

const K: any = await import('../../../packages/pca-store-conformance/src/index.ts');
const Cli: any = await import('../../../packages/pca-store-conformance/src/cli.ts');
const o = new Oracle('store-conformance-java', 'tools/pca-audit/oracles/store-conformance-java.mts', 'TS-reference oracle for the store conformance kit command line.');
const run = (fn: string, name: string, ref: (...a: any[]) => any, args: any[]) => o.run(fn, name, ref, args);

await run('consts', 'all', () => ({ DEFAULT_SEARCH_BUDGET: K.DEFAULT_SEARCH_BUDGET, ALL_TESTS: [...K.ALL_TESTS], USAGE: Cli.USAGE }), []);
const argvs: string[][] = [[], ['--help'], ['-h'], ['--adapter', 'x'], ['--adapter'], ['--option', 'k=v'], ['--option', 'k=v', '--option', 'a=b=c'], ['--option', 'nov'], ['--option', '=x'], ['--tests', 'burst,crash'], ['--tests', 'nope'], ['--tests', ''], ['--tests'],
  ['--profile', 'pca-state'], ['--profile', 'other'], ['--profile'], ['--profile', 'pca-state', '--tests', 'claim-burst,processes'], ['--profile', 'pca-state', '--tests', 'burst'], ['--tests', 'claim-burst', '--profile', 'pca-state'],
  ['--clients', '4'], ['--clients', '-1'], ['--clients', 'x'], ['--clients'], ['--duration', '100'], ['--rounds', '3'], ['--revisit-keys', '9'], ['--processes', '2'], ['--kill-every', '50'], ['--budget', '10'], ['--values', '3'], ['--values', '0'], ['--values', '1.5'],
  ['--seed', '7'], ['--seed', '1.5'], ['--seed', '-1'], ['--json'], ['--bogus'], ['x'], ['--adapter', 'builtin:in-memory', '--json', '--clients', '2', '--seed', '3'], ['--help', '--bogus'], ['--clients', '1e2'], ['--clients', ' 5 '], ['--clients', '']];
let an = 0;
for (const a of argvs) await run('parseCli', `a${an++} ${a.join(' ')}`, (x: any) => Cli.parseCli(x), [a]);
const margs: string[][] = [['--help'], [], ['--bogus'], ['--clients', 'x'], ['--adapter', 'x', '--profile', 'other']];
an = 0;
for (const a of margs) {
  await run('main', `m${an++} ${a.join(' ')}`, async (x: any) => { const out: string[] = [], err: string[] = []; const code = await Cli.main(x, (s: string) => out.push(s), (s: string) => err.push(s)); return { code, out, err }; }, [a]);
}
refWrite(o, 'store-conformance-java');
