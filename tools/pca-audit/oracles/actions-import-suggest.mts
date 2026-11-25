// Oracle: @atlasauth/pca-actions import/{suggest,rules,model,providers}.ts. Writes out/ref-actions-import-suggest.json.gz.
// PORTING table: fn(args) -> native entry point (net.atlasauth.pca.actions.importers), comparison rule = JSON value equality
//   Argument conventions: a rules argument that is the string "default" stands for the shipped DEFAULT_RULES (ImportRules.DEFAULT_RULES);
//   a registry argument "core" stands for the core trait registry (Actions.CORE_REGISTRY), null for none; a "seed" is a label whose Ed25519
//   seed is sha256("atlas-pca-conformance/" + label).
//   suggestRulesError(rules, knownList|null) -> ImportSuggest.suggestRulesError(rules, set|null)   rulesDigest(rules) / sealRules(rules) -> same names
//   DEFAULT_RULES() -> ImportRules.DEFAULT_RULES (full JSON)   DEFAULT_RULES_SEALED_DIGEST() -> ImportRules.DEFAULT_RULES_SEALED["digest"]
//   signRules(rules, kid, seed) -> ImportSuggest.signRules   verifyRules(doc, pins[{kid,pk}]) -> ImportSuggest.verifyRules (the {ok, reason?} map)
//   stem(s) -> stem   factsOf(def) -> ImportSuggest.factsOf(def).toJson()   suggestWithRules(def, rules, registry) -> suggestWithRules
//   unionSuggestions(a, b) / applySuggestion(def, suggestion, by) -> same names
//   vocabulary(registry) / promptDigest(registry) / buildRequest(def, registry) / parseTraitList(text, registry) -> ImportModel.<same>
//   suggestWithModels(def, adapters[{id, version?, answer?, throws?}], registry) -> ImportModel.suggestWithModels (an adapter returns `answer` or throws `throws`)
//   modelConfigFromEnv(env, flags) -> ImportProviders.modelConfigFromEnv(env, flags).toMap()
//   providerAdapterComplete(cfg{provider,model,apiKey}, fetchSpec{ok?, status?, json?, throws?}, req) -> ImportProviders.providerAdapter(...).complete over a fake
//        transport; compared as {call: {url, headers, body} | null, text? | error?}
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import * as S0 from '../../../packages/pca-actions/src/import/suggest.ts';
import * as R0 from '../../../packages/pca-actions/src/import/rules.ts';
import * as M0 from '../../../packages/pca-actions/src/import/model.ts';
import * as PR0 from '../../../packages/pca-actions/src/import/providers.ts';
import * as MC0 from '../../../packages/pca-actions/src/import/mcp.ts';
import * as OA0 from '../../../packages/pca-actions/src/import/openapi.ts';
import * as EV0 from '../../../packages/pca-actions/src/import/eval.ts';
import * as CT0 from '../../../packages/pca-actions/src/core-traits.ts';
import * as PCA0 from '@atlasauth/pca';
import { Oracle, variants, refWrite, seed, rng } from './lib.mjs';

const un = (m: any) => (m.default && Object.keys(m).length <= 2 ? m.default : m);
const { publicKeyOf, b64u } = (PCA0 as any).default ?? PCA0; // package namespace; a CJS build keeps its exports under default
const S = un(S0), R = un(R0), M = un(M0), PR = un(PR0), MC = un(MC0), OA = un(OA0), EV = un(EV0), CT = un(CT0);
const o = new Oracle('actions-import-suggest', 'tools/pca-audit/oracles/actions-import-suggest.mts', 'TS-reference oracle for the suggestion rules, model assist and provider adapters of the pca-actions importers.');
const RNG = rng(0x5ee7);
const take = <T,>(xs: T[], n: number): T[] => { const k = Math.max(1, Math.floor(xs.length / n)); return xs.filter((_, i) => i % k === 0).slice(0, n); };
const rulesOf = (x: any) => (x === 'default' ? R.DEFAULT_RULES : x);
const regOf = (x: any) => (x === 'core' ? CT.CORE_REGISTRY : undefined);

// ---- real defs from the importers ----
const TOOLS = [
  ['delete_user', 'Delete a user account permanently.', { id: { type: 'string' } }], ['send_email', 'Send an email to a customer.', { to: { type: 'string', format: 'email' }, body: { type: 'string' } }],
  ['create_payment', 'Create a payment.', { amount: { type: 'integer' }, currency: { type: 'string' } }], ['refund_charge', 'Refund a charge.', { charge_id: { type: 'string' }, amount: { type: 'integer' } }],
  ['list_invoices', 'List invoices.', { limit: { type: 'integer' } }], ['get_balance', 'Read the account balance.', {}], ['run_script', 'Execute a shell script.', { cmd: { type: 'string' } }],
  ['grant_admin', 'Grant admin rights to a member.', { user_id: { type: 'string' }, role: { type: 'string' } }], ['update_api_key', 'Rotate the API key.', { key_name: { type: 'string' } }],
  ['export_data', 'Export all customer data to a bucket.', { bucket: { type: 'string' }, ssn: { type: 'string' } }], ['publish_post', 'Publish a blog post.', { title: { type: 'string' } }],
  ['create_webhook', 'Create a webhook for events.', { url: { type: 'string', format: 'url' } }], ['schedule_job', 'Schedule a recurring job.', { cron: { type: 'string' } }],
  ['transfer_funds', 'Transfer funds between accounts.', { from_account: { type: 'string' }, to_account: { type: 'string' }, amount: { type: 'integer' }, currency: { type: 'string', format: 'iso_currency' } }],
  ['cancel_subscription', 'Cancel a subscription.', { sub: { type: 'string' } }], ['upload_file', 'Upload a file.', { path: { type: 'string' }, content: { type: 'string' } }],
  ['invite_member', 'Invite a member by email.', { email: { type: 'string', format: 'email' } }], ['search_docs', 'Search documentation.', { q: { type: 'string' } }],
  ['verify_phone', 'Send a verification code by SMS.', { phone: { type: 'string' }, otp: { type: 'string' } }], ['merge_pull_request', 'Merge a pull request.', { repo: { type: 'string' }, number: { type: 'integer' } }],
  ['reset_password', 'Reset a user password.', { user: { type: 'string' }, password: { type: 'string' } }], ['book_flight', 'Book a flight.', { flight: { type: 'string' } }],
  ['truncate_table', 'Remove all rows.', { table: { type: 'string' } }], ['fetch_url', 'Fetch a web page.', { url: { type: 'string' } }], ['ping', '', {}],
];
const mcpDefs: any[] = MC.importMcp(TOOLS.map(([name, description, properties]) => ({ name, description, inputSchema: { type: 'object', properties } })), { ns: 'tools' }).defs;
const oaDefs: any[] = OA.importOpenApi({ openapi: '3.0.0', paths: {
  '/v1/payments': { post: { operationId: 'createPayment', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { amount: { type: 'integer' }, currency: { type: 'string' } } } } } } }, get: {} },
  '/v1/payments/{id}': { delete: { operationId: 'cancelPayment' }, get: {} }, '/v1/users/{id}/password': { put: {} }, '/admin/roles': { post: { summary: 'Grant a role' } }, '/files/export': { post: {} },
  '/v1/ünï': { get: { operationId: 'readThing' } },
} }, { ns: 'oa' }).defs;
const handText = fs.readFileSync(fileURLToPath(new URL('../../../packages/pca-actions/corpus/hand.tsv', import.meta.url)), 'utf8');
const corpus = EV.parseHandTsv(handText);
const handDefs: any[] = [...EV.importCorpus(corpus.slice(0, 300)).defs.values()];
const DEFS = [...mcpDefs, ...oaDefs, ...take(handDefs, 70)];
console.error('defs', mcpDefs.length, oaDefs.length, handDefs.length);

// ---- stem / facts ----
for (const w of ['charges', 'charged', 'charging', 'process', 'boxes', 'buzzes', 'watches', 'wishes', 'policies', 'ies', 'cies', 'is', 'class', 'classes', 'less', 'ed', 'used', 'using', 'make', 'a', 'sses', 'passes', 'e', 'tree', 'agree', 'bus', 'status', 'ing', 'string', 'strings', 'dropped', 'gases', '']) await o.run('stem', w, S.stem, [w]);
for (const d of DEFS) await o.run('factsOf', d.verb, (x: any) => { const f = S.factsOf(x); return { ...f, methods: [...f.methods], effects: [...f.effects] }; }, [d]);

// ---- rule sets ----
await o.run('DEFAULT_RULES', 'all', () => R.DEFAULT_RULES, []);
await o.run('DEFAULT_RULES_SEALED_DIGEST', 'd', () => R.DEFAULT_RULES_SEALED.digest, []);
const BASE: any = { v: 1, kind: 'pca-suggest-rules', version: '1.0.0', rules: [
  { id: 'SR-001', match: { methods: ['DELETE'] }, adds: ['pca.destructive'], note: 'HTTP DELETE' },
  { id: 'SR-002', match: { name_tokens: ['refund', 'charge.card'], effects: ['create', 'update'] }, adds: ['pca.money_moving'], note: 'moves money' },
  { id: 'SR-003', match: { param_names: ['amount', 'total'], param_types: ['integer'] }, adds: ['money.amount', 'tag:pci'], note: 'amount params' },
  { id: 'SR-004', match: { param_names_all: ['amount', 'currency'] }, adds: ['pca.money_moving'], note: 'amount and currency' },
  { id: 'SR-005', match: { path_re: '^/v1/pay(ments)?(/|$)' }, adds: ['pca.financial_data_read'], note: 'payments path' },
  { id: 'SR-006', match: { name_tokens_strict: ['password'], param_formats: ['email'] }, adds: ['tag:secret', 'pca.credential_access'], note: 'password' },
  { id: 'SR-007', match: { roles: ['money.amount'] }, adds: ['pca.cost_incurring'], note: 'role present' },
  { id: 'SR-0008', match: { param_names: ['email', 'to'], param_formats: ['email'] }, adds: ['pca.external_communication', 'tag:pii', 'contact.email'], note: 'email param' },
  { id: 'SR-009', match: { path_re: 'tool|[a-z]+_script' }, adds: ['pca.code_execution', 'pca.unreviewed'], note: 'script' },
] };
await o.run('suggestRulesError', 'base', S.suggestRulesError, [BASE]);
await o.run('suggestRulesError', 'base known', (r: any, k: any) => S.suggestRulesError(r, new Set(k)), [BASE, ['pca.destructive', 'pca.money_moving']]);
await o.run('suggestRulesError', 'default', (x: any) => S.suggestRulesError(rulesOf(x)), ['default']);
await o.run('suggestRulesError', 'default known', (x: any, k: any) => S.suggestRulesError(rulesOf(x), new Set(k)), ['default', [...CT.CORE_REGISTRY.traits.keys()]]);
await o.run('suggestRulesError', 'default known-short', (x: any, k: any) => S.suggestRulesError(rulesOf(x), new Set(k)), ['default', ['pca.destructive']]);
const RX = ['a**', 'a*+', '(a+)+', '(a|b)*', '(?i)a', '(?=a)', '(?<n>a)', '(?:a)', 'a{2,1}', 'a{', 'a{,3}', '[a-', '[z-a]', '\\', '(', ')', 'a)', '\\1(a)', '[^]', '[]', '\\d+\\s*\\w', '\\/v1\\/', 'a|*', '*a', '^*', '$a', 'x{2}', 'x{2,}?', 'a??', '.*', '\\u00e9\\x41', '\\cA', '\\k', '[\\s\\S]', 'a{1}{2}', '\\p{L}', '^$', '\\b\\w+\\b', '[a-z]{2,3}(?:_[0-9])?', 'é', '\\é', '(?!a)', 'a{1,2', '}', ']', '{2}', '(a)(b)', 'a\\', 'x'.repeat(129), ''];
for (const re of RX) { const r = JSON.parse(JSON.stringify(BASE)); r.rules[4].match.path_re = re; await o.run('suggestRulesError', `re ${re.slice(0, 20)}`, S.suggestRulesError, [r]); }
for (const [lab, v] of take([...variants(BASE, { maxPaths: 900 })] as [string, any][], 220)) await o.run('suggestRulesError', lab, S.suggestRulesError, [v]);
await o.run('rulesDigest', 'base', S.rulesDigest, [BASE]);
await o.run('rulesDigest', 'default', (x: any) => S.rulesDigest(rulesOf(x)), ['default']);
await o.run('sealRules', 'base', S.sealRules, [BASE]);
const withSig = (r: any, sig: any) => ({ ...S.sealRules(r), ...(sig !== undefined ? { sig } : {}) });
await o.run('signRules', 'base', (r: any, kid: string, l: string) => S.signRules(r, kid, seed(l)), [BASE, 'pub-1', 'suggest-pub-1']);
await o.run('signRules', 'bad', (r: any, kid: string, l: string) => S.signRules(r, kid, seed(l)), [{ ...BASE, rules: [] }, 'pub-1', 'suggest-pub-1']);
const pk = (l: string) => b64u(publicKeyOf(seed(l)));
const SIGNED = S.signRules(BASE, 'pub-1', seed('suggest-pub-1'));
const PINS = [{ kid: 'pub-1', pk: pk('suggest-pub-1') }];
const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
for (const [n, doc, pins] of [
  ['ok', SIGNED, PINS], ['unsigned', S.sealRules(BASE), PINS], ['no digest', BASE, PINS], ['bad digest', { ...SIGNED, digest: flip(SIGNED.digest) }, PINS],
  ['wrong key', SIGNED, [{ kid: 'pub-1', pk: pk('suggest-pub-2') }]], ['unknown kid', SIGNED, [{ kid: 'other', pk: pk('suggest-pub-1') }]], ['no pins', SIGNED, []],
  ['bad sig', { ...SIGNED, sig: { ...SIGNED.sig, value: flip(SIGNED.sig.value) } }, PINS], ['sig str', { ...SIGNED, sig: 'x' }, PINS], ['sig no kid', { ...SIGNED, sig: { alg: 'ed25519', value: SIGNED.sig.value } }, PINS],
  ['sig noncanon', { ...SIGNED, sig: { ...SIGNED.sig, value: SIGNED.sig.value + 'A' } }, PINS], ['edited rule', { ...SIGNED, rules: [{ ...SIGNED.rules[0], note: 'changed' }, ...SIGNED.rules.slice(1)] }, PINS],
  ['malformed', { ...SIGNED, v: 2 }, PINS], ['null', null, PINS], ['array', [], PINS], ['extra', { ...SIGNED, extra: 1 }, PINS],
] as any[]) await o.run('verifyRules', n, S.verifyRules, [doc, pins]);

// ---- suggestions ----
const REG = [undefined, 'core'] as any[];
for (const d of DEFS) for (const reg of REG) await o.run('suggestWithRules', `${d.verb} ${reg ?? 'noreg'}`, (dd: any, r: any, g: any) => S.suggestWithRules(dd, rulesOf(r), regOf(g)), reg === undefined ? [d, 'default'] : [d, 'default', reg]);
for (const d of DEFS) await o.run('suggestWithRules', `${d.verb} base`, (dd: any, r: any, g: any) => S.suggestWithRules(dd, rulesOf(r), regOf(g)), [d, BASE, 'core']);
const FIRED = DEFS.map((d: any) => ({ d, s: S.suggestWithRules(d, R.DEFAULT_RULES, CT.CORE_REGISTRY) }));
for (const { d, s } of FIRED) await o.run('applySuggestion', d.verb, S.applySuggestion, [d, s, { rules: { version: '1.1.0', digest: 'dg', fired: s.fired } }]);
for (const { d, s } of take(FIRED, 40)) {
  const d2 = S.applySuggestion(d, s, { rules: { version: '1.1.0', digest: 'dg', fired: s.fired } });
  await o.run('applySuggestion', `${d.verb} twice`, S.applySuggestion, [d2, s, {}]);
  await o.run('applySuggestion', `${d.verb} models`, S.applySuggestion, [d2, { traits: ['pca.bulk', 'pca.destructive'], roles: { x: 'money.amount' }, tags: { x: ['pci'] }, fired: [] }, { models: [{ id: 'm', prompt_digest: 'p', input_digest: 'i', output_digest: 'o', temperature: 0, traits: ['pca.bulk'] }] }]);
  const conf = { ...d, review: { ...d.review, state: 'confirmed' } };
  await o.run('applySuggestion', `${d.verb} confirmed`, S.applySuggestion, [conf, s, {}]);
  await o.run('applySuggestion', `${d.verb} authored`, S.applySuggestion, [{ ...d, review: { ...d.review, state: 'authored' }, traits: ['pca.bulk'] }, s, { rules: { version: '1', digest: 'x', fired: [] } }]);
}
const MONEY = DEFS.find((d: any) => d.verb === 'tools.transfer.funds' || /transfer/.test(d.verb)) ?? DEFS[0];
await o.run('applySuggestion', 'money idem', S.applySuggestion, [MONEY, { traits: ['pca.money_moving'], roles: {}, tags: {}, fired: ['SR-1'] }, {}]);
await o.run('applySuggestion', 'money idem none', S.applySuggestion, [{ ...MONEY, idempotency: { mode: 'none' } }, { traits: ['pca.money_moving'], roles: {}, tags: {}, fired: [] }, {}]);
await o.run('applySuggestion', 'money idem natural', S.applySuggestion, [{ ...MONEY, idempotency: { mode: 'natural' } }, { traits: ['pca.money_moving'], roles: {}, tags: {}, fired: [] }, {}]);
const SUGS = [{ traits: ['pca.a'], roles: { p: 'x.y' }, tags: { p: ['pii'] }, fired: ['SR-001'] }, { traits: ['pca.b', 'pca.a'], roles: { p: 'q.z', r: 'id.k' }, tags: { p: ['phi'], r: ['pci', 'pii'] }, fired: ['SR-002'] }, { traits: [], roles: {}, tags: {}, fired: [] }];
for (const [i, a] of SUGS.entries()) for (const [j, b] of SUGS.entries()) await o.run('unionSuggestions', `${i}-${j}`, S.unionSuggestions, [a, b]);

// ---- model assist ----
for (const reg of ['core', null]) { await o.run('vocabulary', String(reg), (g: any) => M.vocabulary(regOf(g) ?? CT.CORE_REGISTRY), [reg]); await o.run('promptDigest', String(reg), (g: any) => M.promptDigest(regOf(g) ?? CT.CORE_REGISTRY), [reg]); }
for (const d of DEFS) await o.run('buildRequest', d.verb, (dd: any) => M.buildRequest(dd, CT.CORE_REGISTRY), [d]);
const TL = ['["pca.destructive","pca.money_moving"]', 'sure: ["pca.bulk", "nope", 5, "pca.bulk"] and more [x]', 'no array', '[', '[1,2', '[]', '[["pca.bulk"]]', 'text [pca.bulk] ["pca.bulk"]', '["pca.unreviewed","pca.irreversible"]', '{"a":["pca.bulk"]}', '[\"pca.bulk\", ]', "['pca.bulk']", '["pca.\\u0062ulk"]', '', '[null, "pca.bulk"]'];
for (const [i, t] of TL.entries()) await o.run('parseTraitList', `t${i}`, (x: string) => M.parseTraitList(x, CT.CORE_REGISTRY), [t]);
const mk = (spec: any) => ({ id: spec.id, ...(spec.version !== undefined ? { version: spec.version } : {}), complete: () => { if (spec.throws !== undefined) throw new Error(spec.throws); return spec.answer; } });
const ADS: any[][] = [[], [{ id: 'm1', answer: '["pca.destructive"]' }], [{ id: 'm1', version: '2026-01', answer: '["pca.money_moving","pca.bulk"]' }, { id: 'm2', answer: '["pca.bulk", "pca.destructive"]' }], [{ id: 'bad', throws: 'boom' }, { id: 'm3', answer: 'none' }], [{ id: 'x'.repeat(200), version: 'v'.repeat(80), answer: 'é'.repeat(70000) }], [{ id: 'e', throws: '' }], [{ id: 'sp ace  id', answer: '[ "pca.bulk" ]' }]];
for (const d of take(DEFS, 8)) for (const [i, a] of ADS.entries()) await o.run('suggestWithModels', `${d.verb} a${i}`, (dd: any, ads: any[]) => { const r = M.suggestWithModels(dd, ads.map(mk), CT.CORE_REGISTRY); return r.then ? r.then((x: any) => ({ ...x, suggestion: x.suggestion })) : r; }, [d, a]);

// ---- providers ----
for (const [n, env, flags] of [
  ['default', { ANTHROPIC_API_KEY: 'k' , ATLAS_PCA_SUGGEST_MODEL: 'claude-x' }, {}], ['openai', { OPENAI_API_KEY: 'k' }, { provider: 'openai', model: 'gpt-4.1' }], ['envprov', { ATLAS_PCA_SUGGEST_PROVIDER: 'openai', OPENAI_API_KEY: 'k', ATLAS_PCA_SUGGEST_MODEL: 'm:1/x' }, {}],
  ['flag wins', { ATLAS_PCA_SUGGEST_PROVIDER: 'openai', ANTHROPIC_API_KEY: 'k', ATLAS_PCA_SUGGEST_MODEL: 'env' }, { provider: 'anthropic', model: 'flag' }], ['badprov', { ANTHROPIC_API_KEY: 'k' }, { provider: 'gemini', model: 'm' }],
  ['nomodel', { ANTHROPIC_API_KEY: 'k' }, {}], ['badmodel', { ANTHROPIC_API_KEY: 'k' }, { model: 'bad model!' }], ['longmodel', { ANTHROPIC_API_KEY: 'k' }, { model: 'm'.repeat(129) }], ['nokey', {}, { model: 'm' }], ['emptykey', { ANTHROPIC_API_KEY: '' }, { model: 'm' }],
  ['wrongkey', { OPENAI_API_KEY: 'k' }, { model: 'm' }], ['null flags', { ANTHROPIC_API_KEY: 'k', ATLAS_PCA_SUGGEST_MODEL: 'm' }, { provider: null, model: null }],
] as any[]) await o.run('modelConfigFromEnv', n, PR.modelConfigFromEnv, [env, flags]);
const REQ = { system: 'SYS', user: 'USR', temperature: 0 };
const adapt = async (cfg: any, spec: any, req: any) => {
  let call: any = null;
  const fetchImpl = async (url: string, init: any) => {
    call = { url, headers: init.headers, body: init.body };
    if (spec.throws !== undefined) throw new Error(spec.throws);
    return { ok: spec.ok ?? true, status: spec.status ?? 200, json: async () => { if (spec.badjson) throw new Error('bad json'); return spec.json; } };
  };
  const a = PR.providerAdapter(Object.defineProperty({ provider: cfg.provider, model: cfg.model }, 'apiKey', { value: cfg.apiKey, enumerable: false }), fetchImpl);
  try { return { call, text: await a.complete(req) }; } catch (e: any) { return { call, error: e.message }; }
};
const CFGS = [{ provider: 'anthropic', model: 'claude-x', apiKey: 'sk-ant' }, { provider: 'openai', model: 'gpt-x', apiKey: 'sk-oa' }];
const FS = [
  { json: { content: [{ type: 'text', text: '["pca.bulk"]' }] } }, { json: { content: [{ type: 'tool_use' }, { type: 'text', text: 'second' }, { type: 'text', text: 'third' }] } }, { json: { content: [] } }, { json: {} }, { json: null }, { json: { content: [{ type: 'text', text: 5 }] } },
  { json: { choices: [{ message: { content: 'hi' } }] } }, { json: { choices: [] } }, { json: { choices: [{ message: {} }] } }, { json: { choices: 'x' } }, { ok: false, status: 429, json: { content: [{ type: 'text', text: 'ignored' }] } }, { ok: false, status: 500 },
  { throws: 'network down sk-ant' }, { badjson: true },
];
for (const [ci, cfg] of CFGS.entries()) for (const [fi, fs_] of FS.entries()) await o.run('providerAdapterComplete', `c${ci} f${fi}`, adapt, [cfg, fs_, REQ]);
await o.run('suggestWithModels', 'long answer', (dd: any, ads: any[]) => M.suggestWithModels(dd, ads.map(mk), CT.CORE_REGISTRY), [DEFS[0], [{ id: 'long', answer: 'é'.repeat(70000) + '["pca.bulk"]' }]]);
void RNG;
const sz: Record<string, number> = {}; for (const c of o.cases) sz[c.fn] = (sz[c.fn] ?? 0) + JSON.stringify(c).length; console.error(sz);
refWrite(o, 'actions-import-suggest');
