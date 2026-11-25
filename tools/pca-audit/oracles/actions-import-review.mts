// Oracle: @atlasauth/pca-actions import/{review,pipeline,registry,eval}.ts. Writes out/ref-actions-import-review.json.gz.
// PORTING table: fn(args) -> native entry point (net.atlasauth.pca.actions.importers), comparison rule = JSON value equality
//   Argument conventions: a registry argument "core" is Actions.CORE_REGISTRY; a rules argument "default" is ImportRules.DEFAULT_RULES; a seed is a label whose
//   Ed25519 seed is sha256("atlas-pca-conformance/" + label); a source of {$bytes} is not used here.
//   importActions(kind, source, opts) -> ImportPipeline.importActions            IMPORTERS[kind](doc, opts) -> ImportPipeline.runImporter(kind, doc, opts)
//   suggestDefs(defs, {mode?, rules?, models?}) -> ImportPipeline.suggestDefs(defs, SuggestOpts)  (models: [{id, version?, answer?, throws?}], registry core)
//   importAndSuggest(kind, src, opts, suggestOpts) -> ImportPipeline.importAndSuggest         defsToJsonl(defs) / jsonlToDefs(text) -> same names
//   verifyAttestation(def, pins, "core") / reviewStatus / revertStale -> ImportReview.<same>(def, pins, registry)      reviewPriority(def, "core"), reviewQueueOrder(defs, "core")
//   prepareReview(def, "core", previous?) -> ImportReview.prepareReview
//   confirmDef(def, {kid, seed, pins?, finalTraits, dismissed?, ts}) -> ImportReview.confirmDef(def, core, kid, seedBytes, pins, finalTraits, dismissed, ts)
//   parseHandTsv(text) / parseCorpusJsonl(text) / realSplit(spec) -> ImportEval.<same>    importCorpus(entries) -> ImportEval.importCorpus  ({defs: {id: def}, todo})
//   evalSuggest(entries, rules|"default"?, alpha?) -> ImportEval.evalSuggest(entries, rules, CORE, alpha)    renderEvalMarkdown(report) / floorFailures(report, floors) -> same names
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import * as PCA0 from '@atlasauth/pca';
import * as RV0 from '../../../packages/pca-actions/src/import/review.ts';
import * as PL0 from '../../../packages/pca-actions/src/import/pipeline.ts';
import * as RG0 from '../../../packages/pca-actions/src/import/registry.ts';
import * as EV0 from '../../../packages/pca-actions/src/import/eval.ts';
import * as S0 from '../../../packages/pca-actions/src/import/suggest.ts';
import * as R0 from '../../../packages/pca-actions/src/import/rules.ts';
import * as MC0 from '../../../packages/pca-actions/src/import/mcp.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import { Oracle, refWrite, seed, rng } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const { publicKeyOf, b64u } = (PCA0 as any).default ?? PCA0; // package namespace; a CJS build keeps its exports under default
const RV = un(RV0), PL = un(PL0), RG = un(RG0), EV = un(EV0), S = un(S0), R = un(R0), MC = un(MC0), CT = un(CT0);
const o = new Oracle('actions-import-review', 'tools/pca-audit/oracles/actions-import-review.mts', 'TS-reference oracle for the review flow, the import pipeline and the suggestion evaluation.');
const RNG = rng(0x7e11);
const take = <T,>(xs: T[], n: number): T[] => { const k = Math.max(1, Math.floor(xs.length / n)); return xs.filter((_, i) => i % k === 0).slice(0, n); };
const CORE = CT.CORE_REGISTRY;
const rulesOf = (x: any) => (x === 'default' || x === undefined || x === null ? undefined : x);
const mk = (spec: any) => ({ id: spec.id, ...(spec.version !== undefined ? { version: spec.version } : {}), complete: () => { if (spec.throws !== undefined) throw new Error(spec.throws); return spec.answer; } });
const pk = (l: string) => b64u(publicKeyOf(seed(l)));

// ---- eval: parsing ----
const corpusDir = fileURLToPath(new URL('../../../packages/pca-actions/corpus/', import.meta.url));
const handText = fs.readFileSync(corpusDir + 'hand.tsv', 'utf8');
await o.run('parseHandTsv', 'hand.tsv', EV.parseHandTsv, [handText]);
const HT = ['', '# c\n\n', 'openapi\tgetThing\tGET /a/{id}\tid:string,limit:integer\t-\tGet thing', 'mcp\tx\t-\t-\tmoney,destr\tD', 'openapi\tx\tPOST\t-\t-\td', 'openapi\tx\tPOST /a b/c\t-\t-\td', 'mcp\tx\t-\t-\tbogus\td', 'mcp\tx\t-\t-\tpii_access\td', 'mcp\tshort', 'mcp\tx\t-\t\t\td', 'graphql\tx\t-\ta:array\tfin\td\textra', '  \nmcp\ta\t-\t-\t-\td\r\n', 'grpc\tS/M\t-\ta:b:c\t-\té'];
for (const [i, t] of HT.entries()) await o.run('parseHandTsv', `t${i}`, EV.parseHandTsv, [t]);
const synText = fs.readFileSync(corpusDir + 'synthetic.jsonl', 'utf8').split('\n').filter(Boolean);
const realText = fs.readFileSync(corpusDir + 'real.jsonl', 'utf8').split('\n').filter(Boolean);
for (const [i, t] of ['', '\n\n', synText[0] + '\n' + synText[1], synText[0] + '\n{', '[1,2]\n  \n"x"'].entries()) await o.run('parseCorpusJsonl', `t${i}`, EV.parseCorpusJsonl, [t]);
for (const [i, s] of [undefined, null, '', 'a', 'ady_A2APaymentsService-v1', 'é', '\u{1F600}x', '\u{1F601}x', 'x'.repeat(200), 'real/1', '0'].entries()) await o.run('realSplit', `s${i}`, (x: any) => EV.realSplit(x === null ? undefined : x), s === undefined ? [] : [s]);
for (const sp of [...new Set(realText.map((l) => JSON.parse(l).spec))].slice(0, 80)) await o.run('realSplit', `spec ${sp}`, EV.realSplit, [sp]);

// ---- eval: corpus import and scoring ----
const hand = EV.parseHandTsv(handText);
const syn = take(synText.map((l) => JSON.parse(l)), 120);
const real = take(realText.map((l) => JSON.parse(l)), 140);
await o.run('importCorpus', 'hand', EV.importCorpus, [hand]);
await o.run('importCorpus', 'syn', EV.importCorpus, [syn]);
await o.run('importCorpus', 'real', EV.importCorpus, [real]);
await o.run('importCorpus', 'empty', EV.importCorpus, [[]]);
const evalRun = (entries: any, rules?: any, alpha?: any) => EV.evalSuggest(entries, { ...(rulesOf(rules) ? { rules } : {}), ...(alpha !== undefined ? { alpha } : {}) });
const reports: any[] = [];
for (const [n, es, rules, alpha] of [['hand', hand, undefined, undefined], ['syn', syn, undefined, 0.1], ['real', real, undefined, undefined], ['mix', [...take(hand, 40), ...take(syn, 40), ...take(real, 60)], 'default', 0.01], ['empty', [], undefined, undefined]] as any[]) {
  await o.run('evalSuggest', n, evalRun, alpha === undefined ? (rules === undefined ? [es] : [es, rules]) : [es, rules ?? 'default', alpha]);
  reports.push([n, evalRun(es, rules, alpha)]);
}
for (const [n, rep] of reports) await o.run('renderEvalMarkdown', n, EV.renderEvalMarkdown, [rep]);
const floors = JSON.parse(fs.readFileSync(corpusDir + 'recall-floors.json', 'utf8'));
const lowFloors = JSON.parse(JSON.stringify(floors)); lowFloors.real.min_entries = 1; for (const k of Object.keys(lowFloors.real.min_positives)) lowFloors.real.min_positives[k] = 0; for (const k of Object.keys(lowFloors.real.recall_lower)) lowFloors.real.recall_lower[k] = 0.01; for (const k of Object.keys(lowFloors.regression.recall_lower)) lowFloors.regression.recall_lower[k] = 0.01;
const hiFloors = JSON.parse(JSON.stringify(lowFloors)); for (const k of Object.keys(hiFloors.real.recall_lower)) hiFloors.real.recall_lower[k] = 0.99; for (const k of Object.keys(hiFloors.regression.recall_lower)) hiFloors.regression.recall_lower[k] = 0.99; hiFloors.real.min_positives.money_moving = 5;
for (const [n, rep] of reports) for (const [fn, f] of [['floors', floors], ['low', lowFloors], ['high', hiFloors]] as any[]) await o.run('floorFailures', `${n} ${fn}`, EV.floorFailures, [rep, f]);

// ---- pipeline ----
const OPT = { ns: 'api' };
const SRC: Record<string, any> = {
  openapi: { openapi: '3.0.0', paths: { '/v1/payments': { post: { operationId: 'createPayment', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { amount: { type: 'integer' }, currency: { type: 'string' } } } } } } }, get: {} }, '/v1/users/{id}': { delete: { operationId: 'deleteUser' } } } },
  mcp: [{ name: 'send_email', description: 'Send mail', inputSchema: { type: 'object', properties: { to: { type: 'string', format: 'email' } } } }, { name: 'run_script', annotations: { destructiveHint: true } }],
  graphql: 'type Query { balance: Int } type Mutation { transferFunds(amount: Int!, to: ID!): Boolean deleteAccount(id: ID!): Boolean }',
  grpc: 'package p; message R { string id = 1; } message E {} service S { rpc Charge(R) returns (E); rpc ListAll(R) returns (E); }',
  asyncapi: { asyncapi: '2.6.0', channels: { 'payments/refund': { publish: { message: { payload: { type: 'object', properties: { amount: { type: 'integer' } } } } } } } },
  jsonschema: { type: 'object', properties: { amount: { type: 'integer' }, to: { type: 'string' } } },
};
for (const [k, src] of Object.entries(SRC)) {
  const opts = k === 'jsonschema' ? { ...OPT, verb: 'api.pay.send', effects: ['pay'] } : OPT;
  await o.run('importActions', k, PL.importActions, [k, src, opts]);
  await o.run('IMPORTERS', k, (kind: string, d: any, op: any) => PL ? RG.IMPORTERS[kind](d, op) : null, [k, src, k === 'jsonschema' ? { ...OPT, verb: 'api.pay.send' } : OPT]);
  for (const mode of [undefined, 'rules', 'none']) await o.run('importAndSuggest', `${k} ${mode}`, async (kind: string, d: any, op: any, so: any) => PL.importAndSuggest(kind, d, { ...op, suggest: so }), [k, src, opts, mode === undefined ? {} : { mode }]);
  await o.run('importAndSuggest', `${k} model`, async (kind: string, d: any, op: any, so: any) => PL.importAndSuggest(kind, d, { ...op, suggest: { mode: so.mode, models: so.models.map(mk) } }), [k, src, opts, { mode: 'model', models: [{ id: 'm', answer: '["pca.destructive","pca.money_moving"]' }, { id: 'bad', throws: 'boom' }] }]);
}
await o.run('IMPORTERS', 'jsonschema noverb', (kind: string, d: any, op: any) => RG.IMPORTERS[kind](d, op), ['jsonschema', SRC.jsonschema, OPT]);
for (const x of ['nope', '', 'constructor']) { await o.run('importActions', `bad ${x}`, PL.importActions, [x, {}, OPT]); await o.run('IMPORTERS', `bad ${x}`, (kind: string, d: any, op: any) => { if (!Object.prototype.hasOwnProperty.call(RG.IMPORTERS, kind)) throw new Error('no importer'); return RG.IMPORTERS[kind](d, op); }, [x, {}, OPT]); }
const dfs: any[] = MC.importMcp(SRC.mcp.concat([{ name: 'delete_all', description: 'Delete everything' }, { name: 'refund_charge', description: 'Refund a charge', inputSchema: { type: 'object', properties: { amount: { type: 'integer' }, currency: { type: 'string' } } } }]), OPT).defs;
for (const [n, so] of [['none', { mode: 'none' }], ['rules', {}], ['rules custom', { rules: 'default' }], ['model', { mode: 'model', models: [{ id: 'a', version: '1', answer: '["pca.bulk"]' }, { id: 'b', throws: 'x' }] }], ['model none', { mode: 'model', models: [] }], ['model nomodels', { mode: 'model' }]] as any[])
  await o.run('suggestDefs', n, async (d: any, s: any) => PL.suggestDefs(d, { ...s, ...(s.rules === 'default' ? { rules: { ...R.DEFAULT_RULES, rules: R.DEFAULT_RULES.rules.slice(0, 20) } } : {}), ...(s.models ? { models: s.models.map(mk) } : {}) }), [dfs, so]);
await o.run('suggestDefs', 'empty', async (d: any) => PL.suggestDefs(d), [[]]);
await o.run('defsToJsonl', 'defs', PL.defsToJsonl, [dfs]); await o.run('defsToJsonl', 'empty', PL.defsToJsonl, [[]]); await o.run('defsToJsonl', 'reversed', PL.defsToJsonl, [[...dfs].reverse()]);
const jl = PL.defsToJsonl(dfs);
for (const [n, t] of [['roundtrip', jl], ['blank lines', '\n' + jl + '\n\n  \n'], ['crlf', jl.replace(/\n/g, '\r\n')], ['bad json', jl + '{'], ['bad def', jl + '{"a":1}\n'], ['empty', ''], ['array', '[]'], ['two', jl.split('\n')[0] + '\n' + jl.split('\n')[0]]] as any[]) await o.run('jsonlToDefs', n, PL.jsonlToDefs, [t]);

// ---- review ----
const KID = 'rv-1';
const PINS = { keys: [{ kid: KID, pk: pk('rv-seed-1'), roles: ['reviewer'] }, { kid: 'imp', pk: pk('imp-seed'), roles: ['importer'] }] };
const sugg = (d: any) => { const s = S.suggestWithRules(d, R.DEFAULT_RULES, CORE); return S.applySuggestion(d, s, { rules: { version: '1.1.0', digest: 'dg', fired: s.fired } }); };
const POOL: any[] = [...dfs, ...MC.importMcp([{ name: 'create_payment', inputSchema: { type: 'object', properties: { amount: { type: 'integer' }, currency: { type: 'string' } } } }, { name: 'grant_admin', description: 'Grant admin' }, { name: 'get_status' }, { name: 'publish_page' }], OPT).defs].map(sugg);
const confirmArgs = (d: any, extra: any = {}) => [d, { kid: KID, seed: 'rv-seed-1', pins: PINS, finalTraits: d.traits ?? [], ts: 1_800_000_000, ...extra }];
const confirmFn = (d: any, c: any) => RV.confirmDef(d, { registry: CORE, reviewer: { kid: c.kid, secret: seed(c.seed) }, ...(c.pins ? { pins: c.pins } : {}), finalTraits: c.finalTraits, ...(c.dismissed ? { dismissed: c.dismissed } : {}), ts: c.ts });
const confirmed: any[] = [];
for (const d of POOL) { await o.run('confirmDef', d.verb, confirmFn, confirmArgs(d)); try { confirmed.push(confirmFn(d, confirmArgs(d)[1])); } catch { /* recorded above */ } }
const d0 = POOL[0], dm = POOL.find((d: any) => (d.traits ?? []).length > 1) ?? POOL[1];
for (const [n, extra] of [
  ['no pins', { pins: undefined }], ['ts neg', { ts: -1 }], ['ts frac', { ts: 1.5 }], ['ts 0', { ts: 0 }], ['unknown trait', { finalTraits: ['pca.nope'] }], ['unreviewed', { finalTraits: ['pca.unreviewed'] }], ['dup final', { finalTraits: ['pca.bulk', 'pca.bulk'] }],
  ['empty final', { finalTraits: [] }], ['wrong kid', { kid: 'imp' }], ['unknown kid', { kid: 'zz' }], ['wrong seed', { seed: 'rv-seed-2' }], ['bad pins', { pins: { keys: [] , x: 1 } }], ['pins not obj', { pins: { keys: 'x' } }],
  ['dismiss blank', { finalTraits: [], dismissed: [{ trait: (dm.traits ?? ['pca.bulk'])[0], reason: '  ' }] }], ['dismiss long', { finalTraits: [], dismissed: [{ trait: (dm.traits ?? ['pca.bulk'])[0], reason: 'x'.repeat(257) }] }],
  ['dismiss ok', { finalTraits: [], dismissed: (dm.traits ?? []).map((t: string) => ({ trait: t, reason: 'not applicable' })) }], ['dismiss twice', { dismissed: [{ trait: 'pca.bulk', reason: 'a' }, { trait: 'pca.bulk', reason: 'b' }] }],
  ['dismiss never suggested', { dismissed: [{ trait: 'pca.persistence', reason: 'a' }] }], ['dismiss final', { dismissed: [{ trait: (dm.traits ?? ['pca.bulk'])[0], reason: 'a' }] }],
] as any[]) await o.run('confirmDef', `extra ${n}`, confirmFn, confirmArgs(dm, extra));
const tamper = (d: any, f: (x: any) => void) => { const c = JSON.parse(JSON.stringify(d)); f(c); return c; };
const vA = (d: any, pins: any) => RV.verifyAttestation(d, { pins, registry: CORE });
const cd = confirmed[0], cm = confirmed.find((d: any) => (d.traits ?? []).length > 1) ?? confirmed[1];
const VAR: [string, any, any][] = [];
for (const d of confirmed.slice(0, 6)) VAR.push([`ok ${d.verb}`, d, PINS]);
VAR.push(['unconfirmed', POOL[0], PINS], ['no attestation', tamper(cd, (x) => { delete x.review.attestation; }), PINS], ['unsigned', tamper(cd, (x) => { delete x.review.attestation.sig; }), PINS], ['sig flip', tamper(cd, (x) => { x.review.attestation.sig = (x.review.attestation.sig[0] === 'A' ? 'B' : 'A') + x.review.attestation.sig.slice(1); }), PINS],
  ['title changed', tamper(cd, (x) => { x.title += '!'; }), PINS], ['traits changed', tamper(cd, (x) => { x.traits = [...(x.traits ?? []), 'pca.persistence']; }), PINS], ['final mismatch', tamper(cd, (x) => { x.review.attestation.final_traits = ['pca.persistence']; }), PINS],
  ['facts string', tamper(cd, (x) => { x.review.attestation.facts_digest = 5; }), PINS], ['final null', tamper(cd, (x) => { x.review.attestation.final_traits = null; }), PINS], ['dismissed bad', tamper(cd, (x) => { x.review.attestation.dismissed = [1]; }), PINS], ['ts frac', tamper(cd, (x) => { x.review.attestation.ts = 1.5; }), PINS],
  ['ts neg zero', tamper(cd, (x) => { x.review.attestation.ts = -0; }), PINS], ['kid num', tamper(cd, (x) => { x.review.attestation.reviewer_kid = 7; }), PINS], ['traits digest', tamper(cd, (x) => { x.review.attestation.traits_digest = 'x'; }), PINS],
  ['dismissed conflict', tamper(cd, (x) => { x.review.attestation.dismissed = [{ trait: (x.review.attestation.final_traits[0] ?? 'pca.bulk'), reason: 'r' }]; }), PINS], ['dismissed blank', tamper(cd, (x) => { x.review.attestation.dismissed = [{ trait: 'pca.persistence', reason: ' ' }]; }), PINS],
  ['wrong pk', cd, { keys: [{ kid: KID, pk: pk('rv-seed-2'), roles: ['reviewer'] }] }], ['no reviewer role', cd, { keys: [{ kid: KID, pk: pk('rv-seed-1'), roles: ['publisher'] }] }], ['unknown kid', cd, { keys: [{ kid: 'other', pk: pk('rv-seed-1'), roles: ['reviewer'] }] }],
  ['before', cd, { keys: [{ kid: KID, pk: pk('rv-seed-1'), roles: ['reviewer'], not_before: 1_800_000_001 }] }], ['after', cd, { keys: [{ kid: KID, pk: pk('rv-seed-1'), roles: ['reviewer'], not_after: 1_799_999_999 }] }], ['window ok', cd, { keys: [{ kid: KID, pk: pk('rv-seed-1'), roles: ['reviewer'], not_before: 1, not_after: 2_000_000_000 }] }],
  ['bad pins', cd, { keys: [{ kid: KID, pk: 'x', roles: ['reviewer'] }] }], ['no pins keys', cd, {}], ['extra digests', cd, { ...PINS, traits_digests: ['abc'] }], ['machine same key', cd, { keys: [{ kid: KID, pk: pk('rv-seed-1'), roles: ['reviewer'] }, { kid: 'm', pk: pk('rv-seed-1'), roles: ['model'] }] }],
  ['state authored', tamper(cd, (x) => { x.review.state = 'authored'; }), PINS], ['no review', tamper(cd, (x) => { delete x.review; }), PINS]);
if (cm) VAR.push(['multi ok', cm, PINS], ['multi traits reordered', tamper(cm, (x) => { x.traits = [...x.traits].reverse(); }), PINS]);
for (const [n, d, p] of VAR) {
  await o.run('verifyAttestation', n, vA, [d, p]);
  await o.run('reviewStatus', n, (dd: any, pp: any) => RV.reviewStatus(dd, { pins: pp, registry: CORE }), [d, p]);
  await o.run('revertStale', n, (dd: any, pp: any) => RV.revertStale(dd, { pins: pp, registry: CORE }), [d, p]);
}
for (const d of [...POOL, ...confirmed.slice(0, 3)]) { await o.run('reviewPriority', `${d.verb} ${d.review.state}`, (dd: any) => RV.reviewPriority(dd, CORE), [d]); await o.run('prepareReview', `${d.verb} ${d.review.state}`, (dd: any) => RV.prepareReview(dd, CORE), [d]); }
for (const d of POOL.slice(0, 6)) await o.run('prepareReview', `${d.verb} previous`, (dd: any, pr: any) => RV.prepareReview(dd, CORE, { previous: pr }), [d, tamper(d, (x) => { x.title += '?'; x.params = {}; x.review.state = 'authored'; x.since = '1.0.0'; })]);
await o.run('reviewQueueOrder', 'pool', (ds: any) => RV.reviewQueueOrder(ds, CORE), [POOL]);
await o.run('reviewQueueOrder', 'reversed', (ds: any) => RV.reviewQueueOrder(ds, CORE), [[...POOL].reverse()]);
await o.run('reviewQueueOrder', 'empty', (ds: any) => RV.reviewQueueOrder(ds, CORE), [[]]);
void RNG;
refWrite(o, 'actions-import-review');
