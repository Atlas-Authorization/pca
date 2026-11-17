// Oracle: @atlasauth/pca-policy-ci (the policy-safety CI gate: lint rules over the analyzer, summary and exit codes, pinned lint-rule digest,
// authoring gates and the command line). Inputs: hand-written policies, chains and grants for every rule and refusal, structural variants of
// seed policies (deleted nodes, hostile scalars, boundary edits), mutated argument lists, and CLI runs over small files in a temporary directory.
// A case whose reference result carries an `internal-error` finding is dropped: its message is the JavaScript engine's. Everything is JSON and
// compared by value; a throw is {"$throws"}. Clocks are fixed (FUTURE below).
// PORTING (fn(args) -> native entry point, comparison rule: JSON value equality of the whole result):
//   normalizePolicyInput(input) / normalizeChain(chain)   -> Normalize.normalizePolicyInput / normalizeChain   {ok:true, policy|hops} | {ok:false, reason}
//   isCapability(x) / isEnvelope(x)                        -> Normalize.isCapability / isEnvelope (boolean)
//   lintPolicy(input, opts?) / lintChain(chain, opts?) / lint(input, opts?) -> PolicyCi.lintPolicy / lintChain / lint (list of findings)
//   lintPolicies(items, opts?) / summarize(results, opts?) -> PolicyCi.lintPolicies / summarize
//   checkLintRulesPin(pinText, actual?)                    -> PolicyCi.checkLintRulesPin (one or two arguments)
//   toAnalyzerPolicy(doc) / diffCommand(old, new, opts?)   -> Authoring.toAnalyzerPolicy / diffCommand {ok, exitCode, lines}
//   testCommand / coverageCommand                          -> Authoring (only the input-refusal results, which never reach the analyzer's runner)
//   parseArgs(argv)                                        -> Cli.parseArgs
//   run({files, argv})                                     -> write each member of `files` (name -> text) into a fresh directory, run Cli.run(argv with
//                                                             the names resolved there) and return {code, lines}, lines with the directory prefix removed
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as CI0 from '../../../packages/pca-policy-ci/src/index';
import * as CLI0 from '../../../packages/pca-policy-ci/src/cli';
import * as ACT0 from '../../../packages/pca-actions/src/lint';
import * as C0 from '@atlasauth/pca';
import { Oracle, refWrite, rng, variants, capture, reparse } from './lib.mjs';

const CI: any = (CI0 as any).default ?? CI0;
const CLI: any = (CLI0 as any).default ?? CLI0;
const ACT: any = (ACT0 as any).default ?? ACT0;
const C: any = (C0 as any).default ?? C0;
const o = new Oracle('policy-ci', 'tools/pca-audit/oracles/policy-ci.mts', 'TS-reference oracle for @atlasauth/pca-policy-ci.');
const r = rng(0x51ed270b);
const FUTURE = 4_000_000_000_000;
const RP = C.DEFAULT_RISK_POLICY;
let n = 0;
let dropped = 0;
const run = async (fn: string, ref: (...a: any[]) => any, args: any[]) => {
  const a = reparse(args);
  const out = await capture(ref, a);
  if (JSON.stringify(out).includes('"internal-error"')) { dropped++; return; }
  o.add(fn, `#${n++}`, a, out);
};

// ---- policies ----------------------------------------------------------------------------------------------------------------------
const P = (verb: any, resource?: any, where?: any[]) => ({ verb, ...(resource !== undefined ? { resource } : {}), ...(where ? { where } : {}) });
const W = (field: string, op: string, value: any) => ({ field, op, value });
const EXP = { type: 'expires', at: FUTURE };
const GATE = { type: 'max_blast_radius', max: 0.1 };
const seeds: any[] = [
  { predicates: [P('*', '*')] }, { predicates: [P('*')] }, { predicates: [P('gmail.send', '*')] }, { predicates: [P('gmail.send')] }, { predicates: [P('account.transfer', '/acct/123')], caveats: [] }, { predicates: [P('account.transfer', '/acct/123')] },
  { predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])] }, { predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])], caveats: [GATE, EXP] },
  { predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])], caveats: [{ type: 'budget_alloc', limit: 5 }, EXP] }, { predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])], caveats: [{ type: 'rate', max: 5, window_secs: 60 }, EXP] },
  { predicates: [P('docs.read', '/docs/x', [W('action.params.size', 'lte', 10)])], caveats: [EXP, { type: 'expires', at: FUTURE + 1000 }] }, { predicates: [P('docs.read', '/docs/x', [W('action.params.size', 'lte', 10)])], caveats: [{ type: 'expires', at: FUTURE + 1000 }, EXP] },
  { predicates: [P('docs.read', '/docs/x', [W('action.params.amount', 'gte', 100), W('action.params.amount', 'lte', 10)])], caveats: [EXP] }, { predicates: [P('docs.read', '/docs/x', [W('action.params.size', 'lte', 10), W('action.params.size', 'lte', 20), W('action.params.size', 'gte', 1)])], caveats: [EXP, GATE] },
  { predicates: [P('docs.read', '/docs/x', [W('action.params.size', 'eq', 10), W('action.params.size', 'lte', 10)])], caveats: [EXP, GATE] }, { predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [EXP, GATE] },
  { predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [EXP, EXP] }, { predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [{ type: 'expires', at: FUTURE }, { at: FUTURE, type: 'expires' }] },
  { predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [{ type: 'not_before', at: 5 }, { type: 'not_before', at: 9 }, { type: 'delegation_depth', max: 3 }, { type: 'delegation_depth', max: 2 }, { type: 'budget_alloc', limit: 9 }, { type: 'budget_alloc', limit: 1.5 }, { type: 'max_blast_radius', max: 0.25 }, { type: 'max_blast_radius', max: 0.5 }] },
  { predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [{ type: 'expires', at: 'x' }, { type: 'expires' }, { type: 'expires', at: 1e21 }, { type: 'expires', at: 0.1 }, { type: 'expires', at: 0.30000000000000004 }] },
  { predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [null, 5, 'x', [], [1], { type: 5 }, {}, { type: null }, { type: 'expires', at: FUTURE }, { type: 'expires', at: FUTURE }] },
  { predicates: [P(['a.read', 'b.delete'], '*')], caveats: [EXP] }, { predicates: [P(['a.read', 'B.DELETE', 'c.Drop'], '*', [W('action.params.x', 'eq', 1)])], caveats: [EXP] }, { predicates: [P(['a.read', 5, null, '*'])] }, { predicates: [P([])] }, { predicates: [P(5)] }, { predicates: [P(null)] }, { predicates: [{}] }, { predicates: [{ resource: '*' }] },
  { predicates: [null, 5, 'x', [], [1], P('x.read', '/a')] }, { predicates: [] }, { predicates: [], caveats: [EXP] }, { predicates: [P('docs.read', null)] }, { predicates: [P('docs.read', 5)] }, { predicates: [P('docs.read', '')] },
  { predicates: [P('docs.read', '/a', [])] }, { predicates: [P('docs.read', '/a', 'x')] }, { predicates: [P('docs.read', '/a', [W('action.params.x', 'eq', 1), { all_of: [W('action.params.y', 'lt', 2)] }, { not: W('action.params.z', 'gt', 3) }, 5, null])], caveats: [EXP] },
  { predicates: [P('docs.read', '/a', [W('action.params.x', 'lt', 5), W('action.params.x', 'lt', 5)])], caveats: [EXP, GATE] }, { predicates: [P('docs.read', '/a', [W('action.params.x', 'gt', 5), W('action.params.x', 'gte', 5), W('action.params.x', 'lt', 9)])], caveats: [EXP, GATE] },
  { predicates: [P('docs.read', '/a', [{ field: 'action.params.x', op: 'lt', ref: 'action.params.y' }, W('action.params.x', 'lt', 5), W('action.params.x', 'lt', 6)])], caveats: [EXP, GATE] }, { predicates: [P('docs.read', '/a', [W('action.params.x', 'lt', 'a'), W('action.params.x', 'lt', 'b')])], caveats: [EXP, GATE] },
  { predicates: [P('docs.read', 're:/a/.*', [W('action.params.x', 'lt', 5)])], caveats: [EXP, GATE] }, { predicates: [P('admin.panel', 're:/a/.*')], caveats: [EXP] }, { predicates: [P('docs.read', '/a', [W('action.params.x', 'matches', '^a')])], caveats: [EXP, GATE] },
  { predicates: [P('payout.send', '/a', [W('action.params.amount', 'lte', 100)]), P('docs.read', '*')], caveats: [{ type: 'rate', max: 1, window_secs: 5 }] }, { predicates: [P('shutdown', '/vm/1', [W('env.hour', 'lt', 8)])], caveats: [{ type: 'reversibility_max', class: 'reversible' }] },
  { predicates: [P('rotate.key', '/k/1')], caveats: [{ type: 'delegation_depth', max: 1 }] }, { predicates: [P('deploy.prod', '/svc/*', [W('action.params.sha', 'like', 'a*')])], caveats: [GATE, EXP] },
  { predicates: [P('x.read', '/a')], caveats: [EXP], riskPolicy: { theta2: 0.5 } }, { predicates: [P('db.delete', '/a/1', [W('action.params.n', 'lte', 1)])], caveats: [EXP], extra: 1 },
  { predicates: [P('docs.read', '/a')], caveats: 'x' }, { predicates: [P('docs.read', '/a')], caveats: null }, { predicates: 'x' }, { predicates: null }, { caveats: [] }, {}, [], 5, null, 'x', true,
  { predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])], caveats: [EXP], riskPolicy: RP, actions: [] },
  { goal_commit: 'c', predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])], caveats: [EXP], agent_binding: {}, risk_policy: RP },
  { goal_commit: 'c', predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])], caveats: [EXP], agent_binding: {}, risk_policy: { ...RP, theta2: 0.7 } },
  { goal_commit: 'c', predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])], caveats: [EXP], agent_binding: {}, risk_policy: { ...RP, theta2: 1 } },
  { goal_commit: 'c', predicates: [P('*', '*')], caveats: [], agent_binding: {}, risk_policy: RP }, { goal_commit: 'c', predicates: [P('x.read', '/a')], caveats: [EXP], agent_binding: [], risk_policy: RP }, { goal_commit: 5, predicates: [P('x.read', '/a')], caveats: [EXP], agent_binding: {}, risk_policy: RP },
  { predicates: [P('db.delete', '/t/users', [W('action.params.n', 'lte', 10)])], caveats: [GATE], riskPolicy: { ...RP, theta2: 0.7 }, actions: [] },
];
const grantOf = (env: any, extra: any[] = [], over: any = {}) => ({ id: 'i', issuer: 'p', holder: 'h', body_digest: 'b', sig: 's', caveats: [{ type: 'envelope', goal_commit: 'commit', agent_binding: {}, risk_policy: RP, ...env }, ...extra], ...over });
const grants: any[] = [
  grantOf({ predicates: [P('account.transfer', '/acct/1')], caveats: [EXP] }), grantOf({ predicates: [P('account.transfer', '/acct/1')], caveats: [EXP] }, [GATE, { type: 'rate', max: 2, window_secs: 60 }]), grantOf({ predicates: [P('docs.read', '/d/*', [W('action.params.n', 'lte', 3)])], caveats: [EXP, GATE] }),
  grantOf({ predicates: [P('*', '*')], caveats: [] }), grantOf({ predicates: [P('docs.read', '/d/*')], caveats: [EXP] }, [{ type: 'envelope', predicates: [], caveats: [], goal_commit: 'x' }, EXP, null, 5]),
  { id: 'i', issuer: 'p', holder: 'h', body_digest: 'b', sig: 's', caveats: [] }, { id: 'i', issuer: 'p', holder: 'h', body_digest: 'b', sig: 's', caveats: [{ type: 'envelope' }] }, { id: 'i', issuer: 'p', holder: 'h', body_digest: 'b', sig: 's' }, { id: 5, issuer: 'p', holder: 'h', body_digest: 'b', sig: 's', caveats: [] },
  grantOf({ predicates: [P('x.read', '/a')], caveats: [EXP], risk_policy: { theta1: 5 } }), grantOf({ predicates: 'x', caveats: [] }), grantOf({ predicates: [], caveats: [EXP] }),
];
const chains: any[] = [
  [], [{ predicates: [P('docs.read', '/d/*')], caveats: [EXP, GATE] }], [{ predicates: [P('docs.read', '/d/*')], caveats: [EXP, GATE] }, { predicates: [P('docs.read', '/d/a')], caveats: [EXP, GATE] }],
  [{ predicates: [P('docs.read', '/d/a')], caveats: [EXP, GATE] }, { predicates: [P('docs.read', '/d/*')], caveats: [EXP, GATE] }], [{ predicates: [P('docs.read', '/d/a')], caveats: [EXP] }, { predicates: [P('docs.read', '/d/a')], caveats: [] }],
  [{ predicates: [P('docs.read', '/d/a')], caveats: [{ type: 'expires', at: 5 }] }, { predicates: [P('docs.read', '/d/a')], caveats: [{ type: 'expires', at: 9 }] }], [{ predicates: [P('docs.read', '/d/a')], caveats: [{ type: 'expires', at: 9 }] }, { predicates: [P('docs.read', '/d/a')], caveats: [{ type: 'expires', at: 5 }] }],
  [{ predicates: [P('docs.*', '/d/a')], caveats: [EXP] }, { predicates: [P('docs.read', '/d/a', [W('action.params.n', 'lte', 3)])], caveats: [EXP] }, { predicates: [P('docs.read', '/d/a', [W('action.params.n', 'lte', 3)])], caveats: [EXP, GATE] }],
  [{ predicates: [P('db.delete', '/t/a', [W('action.params.n', 'lte', 3)])], caveats: [EXP, GATE] }, { predicates: [P('db.delete', '/t/a', [W('action.params.n', 'lte', 30)])], caveats: [EXP, GATE] }],
  [{ predicates: [P('a.x', 're:/q/.*')], caveats: [EXP] }, { predicates: [P('a.x', 're:/q/.*')], caveats: [EXP] }], [{ predicates: [P('a.x', '/q', [{ field: 'action.params.a', op: 'eq', ref: 'action.params.b' }])], caveats: [EXP] }, { predicates: [P('a.x', '/q')], caveats: [EXP] }],
  [grants[0], grants[1]], [grants[1], grants[2]], [grants[0]], [grants[5], grants[0]], [grants[0], grants[5]], [grants[0], { predicates: [P('x.y', '/a')], caveats: [] }], [{ predicates: [P('x.y', '/a')], caveats: [] }, grants[0]], [grants[4], grants[0], grants[1]],
  [null], [5], ['x'], [{}], [{ predicates: [] }, { predicates: [] }], [{ predicates: [P('a.b', '/c')] }, 5], [{ goal_commit: 'c', predicates: [P('a.b', '/c')], caveats: [EXP], agent_binding: {}, risk_policy: RP }, { predicates: [P('a.b', '/c')], caveats: [EXP, GATE] }],
];

// ---- normalize / lint ---------------------------------------------------------------------------------------------------------------
const optsList: any[] = [undefined, {}, { rules: { overBroadGrant: false } }, { rules: { redundantCaveat: false, missingSafetyFloor: false } }, { rules: { dangerousReachability: false, privilegeEscalation: false } }, { rules: { overBroadGrant: { dangerousVerbs: ['read'] } } }, { rules: { overBroadGrant: { dangerousVerbs: [] } } },
  { rules: { dangerousReachability: { dangerousVerbs: ['docs'], targets: [{ verb: 'docs.read', resource: '/docs/x' }, { verb: 'x' }] } } }, { rules: { dangerousReachability: { targets: [{ verb: 'gmail.send', resource: '/m/1' }] } } }, { rules: { dangerousReachability: true, missingSafetyFloor: { requireExpiry: false } } },
  { rules: { missingSafetyFloor: { requireScopeGate: false } } }, { rules: { missingSafetyFloor: { requireExpiry: false, requireScopeGate: false } } }, { rules: { missingSafetyFloor: false, overBroadGrant: true } }, { maxCombinations: 0 }, { maxCombinations: 2 }, { maxCombinations: 50 }, { rules: {}, maxCombinations: 1e9 }];
for (const s of [...seeds, ...grants]) {
  await run('normalizePolicyInput', CI.normalizePolicyInput, [s]);
  for (const op of optsList.slice(0, 3)) await run('lintPolicy', CI.lintPolicy, op === undefined ? [s] : [s, op]);
  await run('lint', CI.lint, [s]);
  await run('isCapability', CI.isCapability, [s]);
  await run('isEnvelope', CI.isEnvelope, [s]);
}
for (const [i, s] of seeds.slice(0, 40).entries()) for (const op of optsList.slice(3)) if ((i + optsList.indexOf(op)) % 3 === 0) await run('lintPolicy', CI.lintPolicy, [s, op]);
for (const c of chains) {
  await run('normalizeChain', CI.normalizeChain, [c]);
  for (const op of [undefined, {}, optsList[3], optsList[4], optsList[13], optsList[14]]) await run('lintChain', CI.lintChain, op === undefined ? [c] : [c, op]);
  await run('lint', CI.lint, [c]);
}
// structural variants of a few seed policies (every node deleted / replaced / edited)
for (const si of [10, 6, 38]) {
  const seed = seeds[si];
  const vs = [...variants(seed, { maxPaths: 40, lens: [] })];
  for (const [k, v] of vs.filter((_, i) => i % 3 === 0).slice(0, 110)) await run('lintPolicy', CI.lintPolicy, [v]);
}
for (const [k, v] of [...variants(grants[1], { maxPaths: 60 })].filter((_, i) => i % 7 === 0).slice(0, 60)) await run('lintPolicy', CI.lintPolicy, [v]);
for (const [k, v] of [...variants(chains[2], { maxPaths: 60 })].filter((_, i) => i % 5 === 0).slice(0, 60)) await run('lintChain', CI.lintChain, [v]);

// ---- lintPolicies / summarize ----------------------------------------------------------------------------------------------------------
const items = [{ label: 'p1', policy: seeds[0] }, { policy: seeds[11] }, { label: 'clean', policy: { predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [EXP, GATE] } }, { label: null, policy: chains[2] }, { label: 'bad', policy: 5 }, { label: 'warn', policy: seeds[10] }];
for (const sel of [[], [0], [1], [2], [3], [4], [5], [2, 5], [0, 1, 2], [0, 1, 2, 3, 4, 5]]) for (const op of [undefined, { maxSeverity: 'warn' }, { maxSeverity: 'info' }, { maxSeverity: 'error', rules: { overBroadGrant: false } }, { maxSeverity: 'bogus' }, { maxSeverity: 'constructor' }, { maxSeverity: 5 }, { maxSeverity: null }, { maxSeverity: 'toString' }]) {
  await run('lintPolicies', CI.lintPolicies, op === undefined ? [sel.map((i) => items[i])] : [sel.map((i) => items[i]), op]);
}
const F = (rule: string, severity: any, message = 'm', where?: string) => ({ rule, severity, message, ...(where ? { where } : {}) });
const resultSets: any[] = [[], [{ label: 'a', findings: [] }], [{ label: 'a', findings: [F('x', 'error')] }], [{ label: 'a', findings: [F('x', 'warn')] }], [{ label: 'a', findings: [F('x', 'info')] }], [{ label: 'a', findings: [F('x', 'bogus')] }, { label: 'b', findings: [F('x', 'warn'), F('y', 'info', 'm', 'w')] }],
  [{ label: 'a', findings: [{ rule: 'x', message: 'm' }] }], [{ label: 'a', findings: [F('x', 'constructor'), F('x', 'toString'), F('x', 5), F('x', null)] }], [{ label: 'a', findings: [F('x', 'warn'), F('x', 'warn'), F('x', 'info'), F('x', 'error')] }, { label: 'b', findings: [] }]];
for (const rs of resultSets) for (const op of [undefined, {}, { maxSeverity: 'error' }, { maxSeverity: 'warn' }, { maxSeverity: 'info' }, { maxSeverity: 'x' }, { maxSeverity: 'hasOwnProperty' }, { maxSeverity: ['error'] }]) await run('summarize', CI.summarize, op === undefined ? [rs] : [rs, op]);

// ---- pinned rule list ------------------------------------------------------------------------------------------------------------------
const D = ACT.lintRulesDigest();
for (const t of [D, ` ${D}\n`, `\n${D}\n\n`, '', ' ', 'x', 'a'.repeat(43), 'a'.repeat(42), 'a'.repeat(44), D.slice(0, 42) + '!', D.toUpperCase(), D + 'x', ` ${D}﻿`, ` ${D}`, '᠎' + D]) await run('checkLintRulesPin', CI.checkLintRulesPin, [t]);
for (const [t, a] of [[D, D], [D, 'a'.repeat(43)], ['a'.repeat(43), 'a'.repeat(43)], ['b'.repeat(43), 'a'.repeat(43)], ['x', D]] as any[]) await run('checkLintRulesPin', CI.checkLintRulesPin, [t, a]);

// ---- authoring ---------------------------------------------------------------------------------------------------------------------------
const docs: any[] = [seeds[6], seeds[7], seeds[10], seeds[19], seeds[0], { predicates: [P('docs.read', '/d/*', [W('action.params.n', 'lte', 3)])], caveats: [EXP], vetoes: [P('docs.read', '/d/secret')], tighten: [W('action.params.n', 'lte', 2)] }, { predicates: [P('docs.read', '/d/*')], vetoes: 'x', tighten: 5 }, grants[0], 5, null, [], { predicates: [P('pay.send', '/a/*', [W('action.params.amount', 'lte', 100)])], caveats: [EXP, { type: 'rate', max: 5, window_secs: 3600 }] }, { predicates: [P('pay.send', '/a/*', [W('action.params.amount', 'lte', 500)])], caveats: [EXP, { type: 'rate', max: 5, window_secs: 3600 }] }];
for (const d of docs) await run('toAnalyzerPolicy', CI.toAnalyzerPolicy, [d]);
const diffOpts: any[] = [undefined, {}, { allowWiden: true }, { verb: 'pay.send' }, { verb: 'pay.send', amountField: 'action.params.amount' }, { verb: 'pay.send', amountField: 'action.params.amount', integer: true, windowSecs: 3600 }, { verb: 'pay.send', amountField: 'action.params.amount', maxExposureIncrease: 1000 }, { maxExposureIncrease: 5 }];
for (const a of docs) for (const b of docs) if (r.next() < 0.22) for (const op of diffOpts.filter(() => r.next() < 0.4)) await run('diffCommand', CI.diffCommand, op === undefined ? [a, b] : [a, b, op]);
await run('diffCommand', CI.diffCommand, [docs[11], docs[12], diffOpts[5]]);
await run('diffCommand', CI.diffCommand, [docs[12], docs[11], diffOpts[5]]);
await run('diffCommand', CI.diffCommand, [docs[11], docs[12], diffOpts[6]]);
const refusal = (ref: any) => async (...a: any[]) => { const out = await ref(...a); if (out.exitCode !== 2) throw new Error('skip'); return out; };
const keepRefusals = async (fn: string, ref: any, args: any[]) => { const a = reparse(args); try { const out = await ref(...a); if (out.exitCode === 2) o.add(fn, `#${n++}`, a, await capture(ref, a)); } catch { /* skip */ } };
const testDocs: any[] = [{ kind: 'pca-policy-tests', cases: [] }, { kind: 'other', cases: [] }, { kind: 'pca-policy-tests' }, { kind: 'pca-policy-tests', cases: 'x' }, 5, null, [], {}];
for (const d of docs.slice(0, 11)) for (const t of testDocs) await keepRefusals('testCommand', CI.testCommand, [d, t]);
const traffic: any[] = [5, null, 'x', {}, [5], [{}], [{ verb: 'a' }], [{ verb: 'a', resource: 5 }], [{ verb: 5, resource: 'b' }], { cases: [5] }, { cases: [{ action: { verb: 'a' } }] }, { cases: [{ nope: 1 }] }, { cases: 'x' }];
for (const d of docs.slice(0, 11)) for (const t of traffic) await keepRefusals('coverageCommand', CI.coverageCommand, [d, t]);

// ---- command line -------------------------------------------------------------------------------------------------------------------------
const TOK = ['a.json', 'b.json', '--max-severity', 'error', 'warn', 'info', 'bogus', '--max-severity=warn', '--max-severity=x', '--format', 'text', 'github', '--format=github', '--format=xml', '--quiet', '-q', '--help', '-h', '--schema', 's.json', '--schema=s.json', '--lint-rules-pin', 'pin.txt', '-x', '--unknown', '-', '--', 'diff', 'test', 'coverage'];
const argvs: string[][] = [[], ['a.json'], ['--help'], ['-h', 'a.json'], ['--max-severity'], ['--max-severity', 'warn', 'a.json'], ['--max-severity=info', 'a.json', 'b.json'], ['--max-severity', '--quiet'], ['--format'], ['--format', 'github'], ['--format', 'html'], ['--schema'], ['--schema', 's.json', 'a.json'], ['--schema=s.json'], ['--lint-rules-pin'], ['--lint-rules-pin', '-x'], ['--lint-rules-pin', 'pin.txt'], ['-q', '--quiet', 'a.json'], ['-z'], ['--max-severity=', 'a.json']];
for (let i = 0; i < 160; i++) argvs.push(Array.from({ length: r.int(0, 5) }, () => r.pick(TOK)));
for (const a of argvs) await run('parseArgs', CLI.parseArgs, [a]);

const ok1 = JSON.stringify({ predicates: [P('docs.read', '/docs/*', [W('action.params.size', 'lte', 100)])], caveats: [EXP, GATE] });
const bad1 = JSON.stringify({ predicates: [P('*', '*')] });
const warn1 = JSON.stringify(seeds[10]);
const chain1 = JSON.stringify(chains[3]);
const grant1 = JSON.stringify(grants[0]);
const schema1 = JSON.stringify({ vars: {} });
const diffOld = JSON.stringify(docs[11]), diffNew = JSON.stringify(docs[12]);
const files: Record<string, string> = { 'ok.json': ok1, 'bad.json': bad1, 'warn.json': warn1, 'chain.json': chain1, 'grant.json': grant1, 'arr.json': '[]', 'scalar.json': '5', 'old.json': diffOld, 'new.json': diffNew, 'old2.json': JSON.stringify(docs[7]), 'new2.json': JSON.stringify(docs[6]), 's.json': schema1, 'pinok.txt': ` ${D}\n`, 'pinbad.txt': 'a'.repeat(43), 'pinjunk.txt': 'junk', 'a b,c:d.json': bad1, 'tests.json': JSON.stringify({ kind: 'other', cases: [] }) };
const wrap = ({ files, argv }: any) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pcaci-'));
  const prev = process.cwd();
  try {
    for (const [k, v] of Object.entries(files)) fs.writeFileSync(path.join(dir, k), v as string);
    process.chdir(dir);
    const lines: string[] = [];
    const code = CLI.run(argv, (s: string) => lines.push(s));
    return { code, lines };
  } finally { process.chdir(prev); fs.rmSync(dir, { recursive: true, force: true }); }
};
const runCases: string[][] = [
  ['ok.json'], ['bad.json'], ['warn.json'], ['ok.json', 'bad.json', 'warn.json'], ['chain.json'], ['grant.json'], ['arr.json'], ['scalar.json'], ['--quiet', 'ok.json', 'bad.json'], ['--format', 'github', 'bad.json', 'warn.json'], ['--format=github', 'a b,c:d.json'], ['--max-severity', 'warn', 'warn.json'], ['--max-severity=info', 'ok.json'], ['--max-severity', 'warn', 'ok.json'],
  ['--help'], ['-h', 'ok.json'], [], ['--bogus'], ['--max-severity', 'x'], ['--lint-rules-pin', 'pinok.txt'], ['--lint-rules-pin', 'pinbad.txt'], ['--lint-rules-pin', 'pinjunk.txt'], ['--lint-rules-pin', 'pinok.txt', 'ok.json'], ['--lint-rules-pin', 'pinbad.txt', 'ok.json'], ['--lint-rules-pin', 'pinbad.txt', 'bad.json'], ['--lint-rules-pin', 'pinok.txt', 'bad.json', '--quiet'],
  ['diff', 'old.json', 'new.json'], ['diff', 'new.json', 'old.json'], ['diff', 'old.json', 'new.json', '--allow-widen'], ['diff', 'old.json', 'new.json', '--verb', 'pay.send', '--amount-field', 'action.params.amount', '--integer', '--window-secs', '3600'], ['diff', 'new.json', 'old.json', '--verb', 'pay.send', '--amount-field', 'action.params.amount', '--integer', '--window-secs', '3600', '--max-exposure-increase', '0'],
  ['diff', 'old2.json', 'new2.json'], ['diff', 'old.json'], ['diff', 'old.json', 'new.json', 'ok.json'], ['diff', 'old.json', 'new.json', '--verb'], ['diff', 'old.json', 'new.json', '--window-secs', 'abc'], ['diff', 'old.json', 'new.json', '--window-secs', '0x10', '--verb', 'pay.send'], ['diff', 'old.json', 'new.json', '--window-secs', ' 5 ', '--verb', 'pay.send'], ['diff', 'old.json', 'new.json', '--window-secs', '', '--verb', 'pay.send'], ['diff', 'old.json', 'new.json', '--window-secs', '1e3', '--verb', 'pay.send'], ['diff', 'old.json', 'new.json', '--window-secs', 'Infinity', '--verb', 'pay.send'],
  ['diff', 'old.json', 'new.json', '--bogus'], ['diff', 'scalar.json', 'new.json'], ['diff', 'old.json', 'scalar.json'], ['test'], ['test', 'ok.json'], ['test', 'ok.json', 'ok.json', '--bogus'], ['test', 'ok.json', 'ok.json', 'ok.json'], ['coverage'], ['coverage', 'ok.json', 'ok.json', '--min-clauses', 'x'], ['coverage', 'ok.json', 'ok.json', '--min-mutation'], ['coverage', 'ok.json'],
];
for (const argv of runCases) {
  const args = { files, argv };
  let out: any;
  try { out = wrap(args); } catch { continue; }
  if (JSON.stringify(out).includes('internal-error')) { dropped++; continue; }
  o.add('run', `#${n++}`, args, out);
}
console.log(`dropped ${dropped} cases (internal-error)`);
refWrite(o, 'policy-ci');
