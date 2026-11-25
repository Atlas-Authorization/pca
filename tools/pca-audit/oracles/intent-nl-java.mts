// Oracle (java extra): the natural-language facade compiler of @atlasauth/pca-intent (compilers.ts nlFacadeCompiler) over the research grounding prompt and strict
// parser (nl.ts nlPrompt, parseNLPolicy). Deterministic: the completion returns a fixed text. `extras` is null (the default catalog) or a list of
// {connector, action, reversibility, blastRadius, amountField?, description, aliases?} added to the built-in catalog (buildCatalog([...BUILTIN, ...extras])).
// PORTING (fn(args) -> native entry point, comparison rule; JSON value equality):
//   nlPrompt(text, extras)             IntentCompilers.nlPrompt(text, catalog)
//   parseNLPolicy(raw, extras)         IntentCompilers.parseNLPolicy(raw, catalog) -> {permissions, limits, unknownVerbs, droppedLimits}
//   nlCompile(text, raw, extras)       {prompt, output}: IntentCompilers.nlFacadeCompiler(id "nl", family "fam", completion = prompt -> raw, recording the prompt).compile({text, catalog}); a throw requires a throw
//   nlRun(text, raw, extras)           IntentCompilers.runCompilers({text, catalog}, [nlFacadeCompiler]) with raw "THROWS" meaning the completion throws "llm down"
import * as C0 from '../../../packages/pca-intent/src/compilers';
import * as NL0 from '../../../packages/pca/src/nl';
import * as CT0 from '../../../packages/pca/src/catalog';
import { Oracle, refWrite } from './lib.mjs';

const C: any = (C0 as any).default ?? C0;
const NL: any = (NL0 as any).default ?? NL0;
const CT: any = (CT0 as any).default ?? CT0;
const o = new Oracle('intent-nl-java', 'tools/pca-audit/oracles/intent-nl-java.mts', 'TS-reference oracle for the NL facade compiler.');
let n = 0;
const run = (fn: string, f: any, args: any[]) => o.run(fn, String(n++), f, args);
const EXTRAS: any[] = [
  { connector: 'jira', action: 'create_issue', reversibility: 'irreversible', blastRadius: 0.4, description: 'Opens an issue.', aliases: ['file_ticket', 'open_issue'] },
  { connector: 'jira', action: 'comment', reversibility: 'rate_limited', blastRadius: 0.2, description: 'Comments on an issue.', aliases: ['open_issue'] },
  { connector: 'bank', action: 'transfer', reversibility: 'irreversible', blastRadius: 0.9, amountField: 'sum', description: 'Wire transfer.', aliases: ['wire', 'send_money'] },
  { connector: 'stripe', action: 'void', reversibility: 'irreversible', blastRadius: 0.5, description: 'Voids a charge.', aliases: ['refund'] },
];
const catOf = (extras: any[] | null) => (extras === null ? CT.DEFAULT_CATALOG : CT.buildCatalog([...CT.BUILTIN_ACTIONS, ...extras.map((e) => CT.defineAction(e))]));
const CATS: (any[] | null)[] = [null, EXTRAS];
const J = (x: any) => JSON.stringify(x);
const RAWS: string[] = [
  J({ permissions: { stripe: ['refund'] }, limits: { refund: '$200/day' } }),
  J({ permissions: { stripe: ['refund', 'charge'], gmail: ['send'] }, limits: { 'stripe.refund': '$50/day', send: '5/hour', charge: '10' } }),
  '```json\n' + J({ permissions: { stripe: ['refund'] }, limits: { refund: '$20' } }) + '\n```',
  'Sure! Here you go: ' + J({ permissions: { github: ['read'] } }) + ' hope that helps {not json}',
  J({ permissions: { stripe: ['issue_refund'] }, limits: { issue_refund: '$5/day', refund: '$6/day' } }),
  J({ permissions: { stripe: ['bill', 'bill'] } }),
  J({ permissions: { stripe: ['refund', 'refund', 'charge', 'refund'] } }),
  J({ permissions: { stripe: ['nuke'], evil: ['x'], gmail: ['send_email'] }, limits: { send_email: '3/day', nuke: '1' } }),
  J({ permissions: { gmail: ['send'] }, limits: { send: 'abc', draft: '3', 'gmail.send': '2/fortnight' } }),
  J({ permissions: { gmail: ['send'] }, limits: { send: 5, 'gmail.send': null, x: ['1'] } }),
  J({ permissions: { gmail: ['send'] }, limits: { send: '  7 / day ', 'gmail.send': '$ 3 / hour' } }),
  J({ permissions: { stripe: ['refund'] }, limits: { refund: '$' + '9'.repeat(70) } }),
  J({ permissions: { stripe: 'refund' } }),
  J({ permissions: { stripe: [1, null, 'refund', { a: 1 }] } }),
  J({ permissions: [['stripe']] }),
  J({ permissions: ['x', ['refund']] }),
  J({ permissions: null, limits: null }),
  J({ permissions: {}, limits: { a: '1' } }),
  J({ limits: { a: '1' } }),
  J({ permissions: { stripe: ['refund'] }, limits: ['1'] }),
  J({ permissions: { stripe: ['refund'] }, limits: [] }),
  J({ permissions: { 1: ['github'], 0: ['read'], github: ['read'] } }),
  J({ permissions: { github: ['read'], 10: ['x'], 2: ['y'] } }),
  '{"permissions":{"stripe":["refund"]},"permissions":{"gmail":["draft"]}}',
  '{"permissions":{"stripe":["refund"]},"limits":{"refund":"$1/day","refund":"$2/day"}}',
  '[1,2,3]', '5', 'null', 'true', '"str"', '', '   ', '{', '}', '{}', '}{', 'no json at all', '{"a":}', '{"permissions": {"stripe": ["refund"]}} trailing } brace',
  'prefix { "permissions": {"stripe": ["refund"]} }  and {"x":1}',
  ' \n\t' + J({ permissions: { stripe: ['refund'] } }) + '  ﻿',
  J({ permissions: { jira: ['file_ticket', 'open_issue', 'create_issue'] }, limits: { file_ticket: '4/day', 'jira.create_issue': '2/day', open_issue: '1' } }),
  J({ permissions: { stripe: ['refund'], bank: ['wire', 'send_money', 'transfer'] }, limits: { wire: '$500/day', transfer: '3/day', refund: '$100' } }),
  J({ permissions: { jira: ['open_issue'] } }),
  J({ permissions: { stripe: ['refund', 'void'] } }),
  J({ permissions: { ' stripe': ['refund'], 'stripe ': ['refund'], 'Stripe': ['refund'] } }),
  J({ permissions: { 'sl.ack': ['x'], '': ['y'] }, limits: { '': '1' } }),
  J({ permissions: { stripe: ['refund'] }, limits: { 'stripe.refund': '$1.5/day', refund: '1e3' } }),
  J({ permissions: { stripe: ['refund'] }, limits: { refund: '-5' } }),
  J({ permissions: { files: ['read', 'write', 'delete'], http: ['get', 'post'], calendar: ['create_event'] }, limits: { write: '10/day', post: '5/hour' } }),
  J({ permissions: { stripe: ['refund', 'charge', 'payout'] }, limits: { refund: '$100/day', charge: '$300/week', payout: '$1000/month' } }),
  J({ permissions: { stripe: ['refund'], slack: ['post_message'] }, limits: { refund: '$100/hour', post_message: '20/min', 'slack.post_message': '9/s' } }),
];
const TEXTS = ['let the support bot refund up to $200/day and email customers', '', 'line1\nline2 "quoted" {braces}', 'unicode é中😀'];
for (const ex of CATS) {
  for (const t of TEXTS) await run('nlPrompt', (tx: string, e: any) => NL.nlPrompt(tx, catOf(e)), [t, ex]);
  for (const r of RAWS) await run('parseNLPolicy', (rw: string, e: any) => NL.parseNLPolicy(rw, catOf(e)), [r, ex]);
}
const nlc = (raw: string, rec: { prompt?: string }, id = 'nl', fam = 'fam') => C.nlFacadeCompiler({ id, family: fam, complete: async (p: string) => { rec.prompt = p; if (raw === 'THROWS') throw new Error('llm down'); return raw; } });
const compile = async (text: string, raw: string, e: any) => { const rec: { prompt?: string } = {}; const output = await nlc(raw, rec).compile({ text, catalog: catOf(e) }); return { prompt: rec.prompt, output }; };
const runAll = async (text: string, raw: string, e: any) => { const rec: { prompt?: string } = {}; return C.runCompilers({ text, catalog: catOf(e) }, [nlc(raw, rec)]); };
for (const ex of CATS) for (const r of RAWS) await run('nlCompile', compile, ['refund things', r, ex]);
for (const ex of CATS) for (const t of TEXTS) await run('nlCompile', compile, [t, RAWS[0]!, ex]);
for (const ex of CATS) for (const r of [...RAWS.slice(0, 12), 'THROWS']) await run('nlRun', runAll, ['refund things', r, ex]);
refWrite(o, 'intent-nl-java');
