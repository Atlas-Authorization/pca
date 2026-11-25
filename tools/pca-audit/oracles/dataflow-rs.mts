// Oracle: @atlasauth/pca-dataflow trace rules (the `never X after Y within T` language, the Invariant-rule import, the compile to
// derive caveats, the lethal-trifecta lint) and categoryId. Deterministic. Writes out/ref-dataflow-rs.json.gz.
// PORTING (fn(args) -> native entry point, comparison rule; a TraceRuleError carries `code`, compared exactly):
//   parseTraceRule(id, text, reason?)          JSON equal
//   parseInvariantRule(id, text, opts)         JSON equal ({rule, dropped})
//   compileTraceRules(rules, table)            JSON equal ({caveats, edges, digest})
//   compileTexts(rules: [[id, text]], table)   compileTraceRules(rules.map(parseTraceRule), table)
//   lethalTrifecta(table, edges, opts?)        JSON equal
//   categoryId(s)                              string equal
import { Oracle, refWrite } from './lib.mjs';

const M: any = await import('../../../packages/pca-dataflow/src/trace-rules.ts');
const D: any = await import('../../../packages/pca-dataflow/src/detectors.ts');
const o = new Oracle('dataflow-rs', 'tools/pca-audit/oracles/dataflow-rs.mts', 'TS-reference oracle for the dataflow trace-rule language, its compiler and the lethal-trifecta lint.');

// ---- parseTraceRule ------------------------------------------------------------------------------------------------------
const texts = [
  'never tool:email.send after tool:files.read within 10m', '  never tool:a after tool:b within 2h  ', 'never trait:pca.network_egress after trait:pca.pii_access within 7d',
  'never any after tool:x within 1ms', 'never tool:a,tool:b after any within 30d', 'never tool:a after tool:b within 31d', 'never tool:a after tool:b within 0m',
  'never tool:a after tool:b within 10', 'never tool:a after tool:b within 1w', 'never tool:a after tool:b within 01m', 'never tool:a after tool:b within 9999999999ms',
  'never tool:a after resource:/acct within 1h', 'never resource:/x after tool:a within 1h', 'never tool:a after resource: within 1h', 'never tool:a after resource:' + 'x'.repeat(256) + ' within 1h',
  'never tool:a after resource:' + 'x'.repeat(257) + ' within 1h', 'never bogus after tool:a within 1h', 'never tool: after tool:a within 1h', 'never tool:a b after tool:c within 1h',
  'never tool:a after tool:b', 'always tool:a after tool:b within 1h', '', 'never  after tool:b within 1h', 'never tool:a after tool:b after tool:c within 1h',
  'never tool:a ,tool:b after tool:c within 1h', 'never tool:a,, after tool:c within 1h', 'never tool:é after tool:c within 1h', 'never tool:a/b:c-d.e_f after tool:c within 1h',
  'NEVER tool:a AFTER tool:b WITHIN 1h', 'never\ttool:a\tafter\ttool:b\twithin\t1h', 'never tool:a after tool:b within 1h extra', 'never any,any after any within 1s',
];
for (const [i, t] of texts.entries()) await o.run('parseTraceRule', `t${i}`, M.parseTraceRule, ['r1', t]);
for (const [i, id] of ['r', 'a_b9', 'A', '1a', '', 'a-b', 'a'.repeat(40), 'a'.repeat(41), 'é'].entries()) await o.run('parseTraceRule', `id${i}`, M.parseTraceRule, [id, texts[0]]);
await o.run('parseTraceRule', 'reason', M.parseTraceRule, ['r', texts[0], 'exfil risk']);
await o.run('parseTraceRule', 'reason empty', M.parseTraceRule, ['r', texts[0], '']);

// ---- parseInvariantRule ----------------------------------------------------------------------------------------------------
const inv = (...l: string[]) => l.join('\n');
const invs = [
  inv('raise "exfil" if:', '(call: ToolCall) -> (send: ToolCall)', 'call is tool:read_file', 'send is tool:send_email'),
  inv("raise 'single quoted' if:", '(out: ToolOutput) -> (c: ToolCall)', 'c is tool:http.post'),
  inv('raise "no tools" if:', '(a: ToolCall) -> (b: ToolCall)'),
  inv('# comment', '', 'raise "m" if:', '  (a: ToolCall) -> (b: ToolCall)  ', 'a is tool:x', '# another', 'b is tool:y'),
  inv('raise "args" if:', '(a: ToolCall) -> (b: ToolCall)', 'a is tool:x({"path": "/etc"})', 'b is tool:y'),
  inv('raise "two" if:', '(a: ToolCall) -> (b: ToolCall)', 'a is tool:x', 'a is tool:z'),
  inv('raise "same" if:', '(a: ToolCall) -> (a: ToolCall)'),
  inv('raise "msg" if:', '(a: Message) -> (b: ToolCall)'),
  inv('raise "out" if:', '(a: ToolCall) -> (b: ToolOutput)'),
  inv('raise "three" if:', '(a: ToolCall) -> (b: ToolCall) -> (c: ToolCall)'),
  inv('raise "other" if:', '(a: ToolCall) -> (b: ToolCall)', 'a.args.path == "/x"'),
  inv('raise "unknown var" if:', '(a: ToolCall) -> (b: ToolCall)', 'z is tool:x'),
  inv('raise x if:', '(a: ToolCall) -> (b: ToolCall)'), inv('raise "x"', '(a: ToolCall) -> (b: ToolCall)'), '', inv('raise "only head" if:'),
  inv('raise "" if:', '(a: ToolCall) -> (b: ToolCall)'),
];
const iopts: any[] = [{ horizon: '1h' }, { horizon: '1h', dropUnsupported: true }];
for (const [i, t] of invs.entries()) for (const [j, op] of iopts.entries()) await o.run('parseInvariantRule', `i${i}/${j}`, M.parseInvariantRule, ['inv1', t, op]);
for (const [j, op] of ([{}, { horizon: 5 }, { horizon: '31d' }, { horizon: 'x' }, null] as any[]).entries()) await o.run('parseInvariantRule', `opts${j}`, M.parseInvariantRule, ['inv1', invs[0], op]);
await o.run('parseInvariantRule', 'bad id', M.parseInvariantRule, ['Bad', invs[0], iopts[0]]);

// ---- compileTraceRules + lethalTrifecta -------------------------------------------------------------------------------------
const TABLE: any = {
  'files.read': { traits: ['pca.pii_access'], effects: ['read'] },
  'web.fetch': { traits: ['pca.network_egress'], effects: ['read'] },
  'email.send': { traits: ['pca.external_communication'], effects: ['write'] },
  'http.post': { traits: ['pca.network_egress'] },
  'db.query': { traits: ['pca.financial_data_read', 'pca.regulated_data'], effects: ['read'] },
  'export.csv': { traits: ['pca.data_export'], effects: ['read'] },
  'notes.write': { traits: [], effects: ['write'] },
};
const BIG: any = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`v${String(i).padStart(2, '0')}`, { traits: ['t.x'], effects: ['write'] }]));
const ruleSets: [string, string][][] = [
  [['r1', 'never tool:email.send after tool:files.read within 10m']],
  [['r1', 'never trait:pca.external_communication,trait:pca.network_egress after trait:pca.pii_access within 1h']],
  [['r1', 'never any after tool:web.fetch within 1s']],
  [['r1', 'never tool:email.send after resource:/secrets,resource:/a,resource:/secrets within 1h']],
  [['r1', 'never tool:email.send after tool:files.read,resource:/acct within 2h'], ['r2', 'never tool:http.post after tool:web.fetch within 5m']],
  [['r1', 'never tool:nope after tool:files.read within 1h']],
  [['r1', 'never trait:pca.none after tool:files.read within 1h']],
  [['r1', 'never tool:email.send after tool:files.read within 1h'], ['r1', 'never tool:http.post after tool:files.read within 1h']],
  [],
];
for (const [i, rs] of ruleSets.entries()) await o.run('compileTexts', `s${i}`, (r: any, t: any) => M.compileTraceRules(r.map(([id, x]: any) => M.parseTraceRule(id, x)), t), [rs, TABLE]);
await o.run('compileTexts', 'big chunks', (r: any, t: any) => M.compileTraceRules(r.map(([id, x]: any) => M.parseTraceRule(id, x)), t), [[['big', 'never any after trait:t.x within 1m']], BIG]);
await o.run('compileTexts', 'big one side', (r: any, t: any) => M.compileTraceRules(r.map(([id, x]: any) => M.parseTraceRule(id, x)), t), [[['big', 'never any after tool:v00 within 1m']], BIG]);
const sel = (x: any = {}) => ({ tools: [], traits: [], resources: [], any: false, ...x });
const raw: any[] = [
  [{ id: 'r', never: sel({ tools: ['email.send'] }), after: sel({ tools: ['files.read'] }), within_ms: 1000 }],
  [{ id: 'r', never: sel({ tools: ['email.send'] }), after: sel({ tools: ['files.read'] }), within_ms: 0 }],
  [{ id: 'r', never: sel({ tools: ['email.send'] }), after: sel({ tools: ['files.read'] }), within_ms: 1.5 }],
  [{ id: 'r', never: sel({ tools: ['email.send'] }), after: sel({ tools: ['files.read'] }), within_ms: 30 * 86_400_000 + 1 }],
  [{ id: 'r', never: sel({ resources: ['/x'] }), after: sel({ tools: ['files.read'] }), within_ms: 1000 }],
  [{ id: 'r', never: sel(), after: sel({ tools: ['files.read'] }), within_ms: 1000 }],
  [{ id: 'r', never: sel({ tools: ['email.send'] }), after: sel(), within_ms: 1000 }],
  [{ id: 'R', never: sel({ tools: ['email.send'] }), after: sel({ tools: ['files.read'] }), within_ms: 1000 }],
  [{ id: 'r', never: sel({ tools: ['email.send', 'email.send'] }), after: sel({ tools: ['files.read'], resources: ['/b', '/a'] }), within_ms: 1000, reason: 'ignored' }],
];
for (const [i, r] of raw.entries()) await o.run('compileTraceRules', `raw${i}`, M.compileTraceRules, [r, TABLE]);

const edgesOf = (rs: [string, string][]) => M.compileTraceRules(rs.map(([id, x]) => M.parseTraceRule(id, x)), TABLE).edges;
const edgeSets: any[] = [[], edgesOf([['r1', 'never tool:email.send after tool:files.read within 1h']]), edgesOf([['r1', 'never tool:email.send,tool:export.csv after tool:files.read,tool:web.fetch,tool:db.query within 1h']]),
  edgesOf([['r1', 'never any after any within 1h']]), [{ rule: 'x', from: { resource: '/a' }, to: 'email.send', within_ms: 1 }]];
const lopts: any[] = [undefined, { untrusted: ['notes.write'] }, { untrusted_traits: ['pca.financial_data_read'] }, { untrusted: [], untrusted_traits: [] }];
for (const [i, e] of edgeSets.entries()) for (const [j, op] of lopts.entries()) await o.run('lethalTrifecta', `e${i}/o${j}`, M.lethalTrifecta, op === undefined ? [TABLE, e] : [TABLE, e, op]);
await o.run('lethalTrifecta', 'no private', M.lethalTrifecta, [{ 'web.fetch': TABLE['web.fetch'], 'email.send': TABLE['email.send'] }, []]);
await o.run('lethalTrifecta', 'empty', M.lethalTrifecta, [{}, []]);
await o.run('lethalTrifecta', 'egress write is a send not untrusted', M.lethalTrifecta, [{ 'files.read': TABLE['files.read'], 'http.post': TABLE['http.post'], 'web.fetch': TABLE['web.fetch'] }, []]);

// ---- categoryId ---------------------------------------------------------------------------------------------------------------
for (const [i, s] of (['prompt_injection', 'Prompt Injection', '  --PII--  ', '9lives', '___', '', 'é', 'a'.repeat(70), 'jailbreak/v2', 'A1-B2', '_x_', 'x'.repeat(63) + '_y', null, 5, ['a'], {}] as any[]).entries())
  await o.run('categoryId', `c${i}`, D.categoryId, [s]);

refWrite(o, 'dataflow-rs');
