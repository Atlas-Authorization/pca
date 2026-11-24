// Oracle: @atlasauth/pca-intent the k-compiler pipeline (compilers.ts): slotsPrompt, parseSlotsJSON, the compilers, runCompilers, analyzeDisagreement, committeeAnchors, panelFlags,
// compileAndCompare. The natural-language facade compiler (nlFacadeCompiler) needs the research grounding prompt / parser and is not in the corpus. Deterministic.
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality, doubles bit-exact):
//   slotsPrompt(text) / parseSlotsJSON(raw)   IntentCompilers.slotsPrompt / parseSlotsJSON (default catalog)
//   specs: compiler spec JSON -> compiler: {kind:"captured", id?} | {kind:"fixed", id, family, policy} (fixedCompiler over a constant policy) | {kind:"throws", id, family} (fixedCompiler whose function throws "boom")
//     | {kind:"slots", id, family, raw} (slotsCompiler whose completion returns raw) | {kind:"slotsThrows", id, family} (completion throws "llm down")
//   runScenario(input, specs) -> runCompilers(input, compilers)
//   analyze(outputs, opts) -> analyzeDisagreement ; anchors(outputs, lambda) ; flags(outputs, opts) -> panelFlags(analyzeDisagreement(outputs, opts))
//   compareScenario(input, specs, opts) -> compileAndCompare(input, compilers, opts)
import * as C0 from '../../../packages/pca-intent/src/compilers';
import { Oracle, refWrite } from './lib.mjs';

const C: any = (C0 as any).default ?? C0;
const o = new Oracle('intent-compilers', 'tools/pca-audit/oracles/intent-compilers.mts', 'TS-reference oracle for the compiler pipeline.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const A = 'action.params.';
const w = (field: string, op: string, value: any) => ({ field, op, value });
const pol = (...ps: any[]) => ({ predicates: ps, caveats: [] });
const POLS: Record<string, any> = {
  A: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 100)] }), B: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 50)] }),
  C: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 100), w(A + 'recipient', 'prefix', 'team-')] }), D: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 100)] }, { verb: 'gmail.send', resource: '*', where: [w(A + 'to', 'prefix', 'p-')] }),
  E: { predicates: [], caveats: [] }, F: { predicates: [{ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'lte', 100)] }], caveats: [{ type: 'reversibility_max', class: 'reversible' }, { type: 'expires_at', at: 5 }] },
  G: pol({ verb: 'stripe.refund', resource: '*', where: [w(A + 'amount', 'gte', 10), w(A + 'amount', 'lte', 100)] }),
};
const SLOTS1 = { verbs: ['stripe.refund'], constraints: [{ verb: 'stripe.refund', path: A + 'amount', max: 100 }] };
const SLOTS2 = { verbs: ['stripe.refund', 'gmail.send'], constraints: [{ verb: 'stripe.refund', path: A + 'amount', max: 40 }, { verb: 'gmail.send', path: A + 'to', prefixOneOf: ['p-'] }] };
const mkC = (s: any): any => {
  switch (s.kind) {
    case 'captured': return s.id === undefined ? C.capturedSlotsCompiler() : C.capturedSlotsCompiler(s.id);
    case 'fixed': return C.fixedCompiler(s.id, s.family, () => s.policy);
    case 'throws': return C.fixedCompiler(s.id, s.family, () => { throw new Error('boom'); });
    case 'slots': return C.slotsCompiler({ id: s.id, family: s.family, complete: async () => s.raw });
    default: return C.slotsCompiler({ id: s.id, family: s.family, complete: async () => { throw new Error('llm down'); } });
  }
};
const fx = (id: string, family: string, p: string) => ({ kind: 'fixed', id, family, policy: POLS[p] });

for (const t of ['refund up to 100', '', 'line1\nline2 "quoted" {braces}', 'unicode é中😀']) await run('slotsPrompt', C.slotsPrompt, [t]);
const raws: string[] = [
  JSON.stringify(SLOTS1), JSON.stringify(SLOTS2), '```json\n' + JSON.stringify(SLOTS1) + '\n```', 'Sure! Here you go: ' + JSON.stringify(SLOTS1) + ' hope that helps', '   ﻿' + JSON.stringify(SLOTS1) + '  ', '', '   ', 'not json', '{', '}{', '{}', '[]', 'null', '5', '"x"', 'true', '[1,2]', '{"verbs":"stripe.refund"}', '{"verbs":null,"constraints":null}',
  '{"verbs":["nope","stripe.refund",5,null,["a"],{"k":1},"stripe.refund"],"constraints":[]}', '{"verbs":["stripe.refund"],"constraints":[null,5,"x",[],true]}',
  '{"verbs":["stripe.refund"],"constraints":[{"path":"action.params.amount","max":1.5,"min":"3"},{"path":"env.hour","min":9,"max":17},{"path":"action.resource","prefixOneOf":["/a"]}]}', '{"verbs":["stripe.refund"],"constraints":[{"path":"action.params.Amount","max":1},{"path":"nope","max":1},{"max":1},{"path":5},{"path":"action.params.x_1","max":-3},{"path":"action.params.1x","max":3}]}',
  '{"verbs":["stripe.refund"],"constraints":[{"verb":"gmail.send","path":"action.params.to","oneOf":["a"]},{"verb":5,"path":"action.params.to"},{"verb":null,"path":"action.params.to","max":1},{"verb":"stripe.refund","path":"action.params.recipient","oneOf":["a","b"],"noneOf":[],"prefixOneOf":"x"}]}',
  '{"verbs":["stripe.refund"],"constraints":[{"path":"action.params.amount"},{"verb":"stripe.refund","path":"action.params.amount"},{"path":"action.params.amount","oneOf":[1]},{"path":"action.params.amount","noneOf":["a",2]}]}',
  '{"verbs":["gmail.send","stripe.refund","github.read"],"constraints":[{"path":"action.params.amount","max":9007199254740991,"min":-9007199254740991},{"path":"action.params.amount","max":1e3},{"path":"action.params.amount","max":2.0}]}',
  'prefix {"verbs":["stripe.refund"]} middle {"verbs":["gmail.send"]} suffix', '{"verbs":["stripe.refund"],"constraints":[{"path":"action.params.amount","max":1,"oneOf":[]}], "extra": 1}'];
for (const r of raws) await run('parseSlotsJSON', (x: string) => C.parseSlotsJSON(x), [r]);

const input = (text: string, slots?: any) => ({ text, ...(slots ? { slots } : {}) });
const runScenario = async (inp: any, specs: any[]) => C.runCompilers(inp, specs.map(mkC));
const panels: any[][] = [[fx('a', 'm1', 'A')], [fx('a', 'm1', 'A'), fx('b', 'm2', 'B')], [fx('a', 'm1', 'A'), fx('b', 'm1', 'A'), fx('c', 'm2', 'C')], [fx('a', 'm1', 'F'), fx('e', 'm3', 'E')], [{ kind: 'captured' }, fx('a', 'm1', 'A')], [{ kind: 'captured', id: 'cap2' }, fx('d', 'm1', 'D')],
  [{ kind: 'throws', id: 't', family: 'x' }, fx('a', 'm1', 'A')], [{ kind: 'slots', id: 's', family: 'm4', raw: JSON.stringify(SLOTS1) }, fx('b', 'm2', 'B')], [{ kind: 'slots', id: 's', family: 'm4', raw: 'garbage' }], [{ kind: 'slotsThrows', id: 'st', family: 'm5' }, fx('a', 'm1', 'A')], [], [fx('g', 'm1', 'G'), fx('a', 'm2', 'A'), fx('b', 'm3', 'B')]];
for (const p of panels) for (const inp of [input('refund up to 100'), input('refund', SLOTS1), input('refund and mail', SLOTS2), input('x', { verbs: [], constraints: [] })]) await run('runScenario', runScenario, [inp, p]);

const outsOf = async (inp: any, specs: any[]) => C.runCompilers(inp, specs.map(mkC));
const analyzeCases: [any, any[], any][] = [];
for (const p of panels.slice(0, 6).concat(panels.slice(7, 8), panels.slice(11))) for (const [slots, opts] of [[undefined, {}], [SLOTS1, {}], [SLOTS2, {}], [SLOTS1, { riskWeighted: true }], [undefined, { limit: 3 }], [SLOTS1, { limit: 0 }], [undefined, { omega: { domains: { 'action.params.amount': { lo: 0, hi: 1000 } } } }], [SLOTS1, { limit: 2, riskWeighted: true }]] as any[]) analyzeCases.push([input('t', slots), p, { ...opts, ...(slots ? { slots } : {}) }]);
for (const [inp, p, opts] of analyzeCases) {
  const outs = await outsOf(inp, p);
  await run('analyze', (os: any[], op: any) => C.analyzeDisagreement(os, op), [outs, opts]);
  await run('flags', (os: any[], op: any) => C.panelFlags(C.analyzeDisagreement(os, op)), [outs, opts]);
  await run('anchors', C.committeeAnchors, [outs, 3]);
}
await run('analyze', (os: any[], op: any) => C.analyzeDisagreement(os, op), [[], {}]);
await run('anchors', C.committeeAnchors, [[], 1]);
const cmp = (inp: any, specs: any[], opts: any) => C.compileAndCompare(inp, specs.map(mkC), opts);
for (const p of [panels[1], panels[2], panels[4], panels[6], panels[11]]) for (const [inp, opts] of [[input('t'), {}], [input('t', SLOTS1), {}], [input('t', SLOTS2), { riskWeighted: true, limit: 4 }]] as any[]) await run('compareScenario', cmp, [inp, p, opts]);
refWrite(o, 'intent-compilers');
