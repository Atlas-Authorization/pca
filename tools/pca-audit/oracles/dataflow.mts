// Oracle: @atlasauth/pca-dataflow: the capability-tagged data-flow model (core `@atlasauth/pca/dataflow`), the trace rules (parse /
// compile / lethal-trifecta lint) and the detector adapters (signed tighten-only receipts). Deterministic (seeded Ed25519 gateway key).
// Data-flow values cross as specs, since a tagged value is a minted object, not JSON:
//   tagged  {"$t": <value>, "cap": {sources:[...], isTrusted, readers?:[...]}}  -> tag(value, cap)   (the case throws if tag throws)
//   raw     {"$raw": <v>}                                                        -> v itself (an UNtagged value, e.g. a look-alike {value, cap})
//   a tagged value prints as {value, cap:{sources:[insertion order], isTrusted, readers?:[insertion order]}}
//   sink    {id, accepts:{external?, requireTrusted?, allowedSources?:[...], deniedSources?:[...]}}  (arrays become Sets); odd shapes pass through
// PORTING (fn(args) -> native entry point; JSON equality, a throw requires the native to refuse, and a `code` is compared when present):
//   tag(value, cap) / fromTrustedQuery(v, opts) / fromToolOutput(name, v, opts) / fromSource(src, v, opts)   Dataflow.tag / from*   (opts.readers: [..])
//   unionSources(caps) / combineCaps(caps)   Dataflow.unionSources / combineCaps over capability specs
//   derive(inputs, name)                     Dataflow.derive; name: count -> number of inputs, pair -> the value list, first -> first value, throw -> combiner throws
//   classifyFlow(v, sink) / canFlow(v, sink) Dataflow.classifyFlow / canFlow
//   checkAction(action, args, governor, opts) Dataflow.checkAction; args items: a tagged / raw spec, null (explicit undefined) or {"$hole":true};
//                                            governor {sink: <sink>} | {throws: true}; opts {expectedArgs?}
//   dualContext(spec)                        Dataflow.dualContext; spec {query:<value>, plan: identity|wrap|throw, quarantine: tagged_untrusted|trusted|raw|throw}
//   externalSendSink(id) / sensitiveSink(id) / levelOf(v) / consts (TRUSTED_QUERY, toolProvenance("x"))
//   parseTraceRule(id, text[, reason]) / parseInvariantRule(id, text, opts) / compileTraceRules(rules, table) / lethalTrifecta(table, edges, opts) / traceConsts
//                                            TraceRules.* (JSON trees)
//   categoryId(s)                            Detectors.categoryId
//   lakeraReceipt / promptSecurityReceipt / genericReceipt (response, ctx)   Detectors.*; ctx.secretKey is {"$bytes": seed} (Ed25519 seed)
import * as D from '@atlasauth/pca-dataflow';
import { Oracle, refWrite, rng, seed } from './lib.mjs';

const X: any = (D as any).default ?? D;
const o = new Oracle('dataflow', 'tools/pca-audit/oracles/dataflow.mts', 'TS-reference oracle for the data-flow model, trace rules and detector adapters.');
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const run = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), ref, args);

// ---- spec plumbing ------------------------------------------------------------------------------------------------------------------
const mkCap = (c: any): any => (c !== null && typeof c === 'object' && !Array.isArray(c) ? { ...c, ...(Array.isArray(c.sources) ? { sources: new Set(c.sources) } : {}), ...(Array.isArray(c.readers) ? { readers: new Set(c.readers) } : {}) } : c);
const capJson = (c: any) => ({ sources: [...c.sources], isTrusted: c.isTrusted, ...(c.readers !== undefined ? { readers: [...c.readers] } : {}) });
const taggedJson = (t: any) => ({ value: t.value, cap: capJson(t.cap) });
const val = (s: any): any => (s !== null && typeof s === 'object' && '$raw' in s ? s.$raw : s !== null && typeof s === 'object' && '$t' in s ? X.tag(s.$t, mkCap(s.cap)) : s);
const mkSink = (s: any): any => (s !== null && typeof s === 'object' && s.accepts !== null && typeof s.accepts === 'object' ? { ...s, accepts: { ...s.accepts, ...(Array.isArray(s.accepts.allowedSources) ? { allowedSources: new Set(s.accepts.allowedSources) } : {}), ...(Array.isArray(s.accepts.deniedSources) ? { deniedSources: new Set(s.accepts.deniedSources) } : {}) } } : s);
const T = (v: any, sources: string[], isTrusted: boolean, readers?: string[]) => ({ $t: v, cap: { sources, isTrusted, ...(readers ? { readers } : {}) } });

const COMBINE: Record<string, (...v: any[]) => any> = { count: (...v) => v.length, pair: (...v) => v, first: (...v) => v[0], throw: () => { throw new Error('combiner failed'); } };
const DUAL_PLAN: Record<string, (q: any) => any> = { identity: (q) => q, wrap: (q) => ({ planned: q }), throw: () => { throw new Error('planner failed'); } };
const DUAL_Q: Record<string, (p: any) => any> = { tagged_untrusted: (p) => X.fromToolOutput('quarantine', p), trusted: (p) => X.fromTrustedQuery(p), raw: (p) => ({ value: p, cap: { sources: new Set(['trusted-query']), isTrusted: true } }), throw: () => { throw new Error('q failed'); } };

// ---- the value / sink pools -----------------------------------------------------------------------------------------------------------------
const VALUES: any[] = [
  T('q', ['trusted-query'], true), T('q', ['user'], true), T('web', ['tool:search'], false), T('mix', ['trusted-query', 'tool:fetch'], false), T('u', ['user'], false), T('none', [], false),
  T('r1', ['trusted-query'], true, ['email', 'log']), T('r2', ['tool:x'], false, ['log']), T('r3', ['tool:x'], false, []), T('r4', ['user', 'tool:y'], false, ['a b', 'é']),
  T({ a: 1 }, ['tool:b', 'tool:a', 'zzz'], false), T(1.5, ['trusted-query', 'user'], true, ['sink']),
];
const SINKS: any[] = [
  { id: 'email', accepts: { external: true } }, { id: 'db', accepts: { requireTrusted: true } }, { id: 'log', accepts: {} }, { id: 'email', accepts: { external: true, requireTrusted: true } },
  { id: 's', accepts: { allowedSources: ['trusted-query', 'user'] } }, { id: 's', accepts: { allowedSources: [] } }, { id: 's', accepts: { deniedSources: ['tool:search'] } }, { id: 's', accepts: { deniedSources: ['tool:a', 'zzz'] } },
  { id: 's', accepts: { allowedSources: ['user'], deniedSources: ['user'] } }, { id: 'e', accepts: { external: true, allowedSources: ['trusted-query', 'tool:fetch'] } }, { id: 'sink', accepts: { external: false, requireTrusted: false } },
  { id: 'e', accepts: { external: 1 } }, { id: 'e', accepts: { requireTrusted: 'true' } },
  { id: '', accepts: {} }, { id: 5, accepts: {} }, { id: 'x', accepts: null }, { id: 'x', accepts: 5 }, { id: 'x' }, null, 5, 'sink', {},
];
const RAWS: any[] = [{ $raw: { value: 'x', cap: { sources: ['trusted-query'], isTrusted: true } } }, { $raw: 'plain' }, { $raw: null }, { $raw: 5 }, { $raw: {} }, { $raw: [] }];

for (const [i, v] of [...VALUES, ...RAWS].entries()) {
  for (const [j, s] of SINKS.entries()) {
    await run('classifyFlow', `v${i}/s${j}`, (a: any, b: any) => X.classifyFlow(val(a), mkSink(b)), [v, s]);
    if ((i + j) % 2 === 0) await run('canFlow', `v${i}/s${j}`, (a: any, b: any) => X.canFlow(val(a), mkSink(b)), [v, s]);
  }
}

// ---- constructors / algebra ---------------------------------------------------------------------------------------------------------------------
const CAPS: any[] = VALUES.map((v) => v.cap);
for (const [i, v] of VALUES.entries()) await run('tag', `v${i}`, (value: any, cap: any) => taggedJson(X.tag(value, mkCap(cap))), [v.$t, v.cap]);
for (const [i, c] of ([
  { sources: [], isTrusted: true }, { sources: ['tool:x'], isTrusted: true }, { sources: ['trusted-query', 'tool:x'], isTrusted: true }, { sources: ['a'], isTrusted: 'yes' }, { sources: ['a'] }, { isTrusted: false },
  { sources: 'abc', isTrusted: false }, { sources: ['a'], isTrusted: false, readers: 'x' }, { sources: ['a'], isTrusted: false, readers: ['x', 'x', 'y'] }, { sources: ['b', 'a', 'b'], isTrusted: false },
  null, 5, 'x', [], { sources: ['tool:'], isTrusted: true }, { sources: ['Tool:x'], isTrusted: true }, { sources: ['tooling'], isTrusted: true },
] as any[]).entries()) await run('tag', `cap${i}`, (value: any, cap: any) => taggedJson(X.tag(value, mkCap(cap))), ['v', c]);
for (const [i, v] of ['q', 5, null, { a: [1, { b: 2 }] }, [1, 2], '', 1.5].entries()) {
  for (const opts of [{}, { readers: [] }, { readers: ['a', 'b', 'a'] }]) {
    await run('fromTrustedQuery', `v${i}/${JSON.stringify(opts)}`, (value: any, op: any) => taggedJson(X.fromTrustedQuery(value, op)), [v, opts]);
    await run('fromToolOutput', `v${i}/${JSON.stringify(opts)}`, (name: any, value: any, op: any) => taggedJson(X.fromToolOutput(name, value, op)), ['search', v, opts]);
  }
}
for (const name of ['', 'x', 'a:b', 'é', 'tool:x']) await run('fromToolOutput', `name/${name}`, (nme: any, value: any, op: any) => taggedJson(X.fromToolOutput(nme, value, op)), [name, 'v', {}]);
for (const src of ['user', 'trusted-query', 'tool:x', '', 'other']) {
  for (const opts of [{}, { isTrusted: true }, { isTrusted: false }, { isTrusted: 1 }, { isTrusted: 'true' }, { isTrusted: true, readers: ['s'] }, { readers: ['s', 't'] }]) {
    await run('fromSource', `${src}/${JSON.stringify(opts)}`, (s: any, value: any, op: any) => taggedJson(X.fromSource(s, value, op)), [src, 'v', opts]);
  }
}
for (const [i, a] of CAPS.entries()) {
  await run('unionSources', `c${i}`, (cs: any[]) => [...X.unionSources(cs.map(mkCap))], [[a]]);
  for (const [j, b] of CAPS.entries()) {
    if ((i + j) % 2 === 0) await run('unionSources', `c${i}+${j}`, (cs: any[]) => [...X.unionSources(cs.map(mkCap))], [[a, b]]);
    await run('combineCaps', `c${i}+${j}`, (cs: any[]) => capJson(X.combineCaps(cs.map(mkCap))), [[a, b]]);
  }
}
for (const [i, a] of CAPS.entries()) for (const [j, b] of CAPS.entries()) if ((i * 3 + j) % 5 === 0) for (const [k, c] of CAPS.entries()) if ((i + j + k) % 6 === 0) await run('combineCaps', `c${i}+${j}+${k}`, (cs: any[]) => capJson(X.combineCaps(cs.map(mkCap))), [[a, b, c]]);
await run('combineCaps', 'empty', (cs: any[]) => capJson(X.combineCaps(cs.map(mkCap))), [[]]);
await run('unionSources', 'empty', (cs: any[]) => [...X.unionSources(cs.map(mkCap))], [[]]);
for (const [i, a] of VALUES.entries()) {
  for (const name of ['count', 'pair', 'first', 'throw']) {
    await run('derive', `${name}/v${i}`, (ins: any[], nme: string) => taggedJson(X.derive(ins.map(val), COMBINE[nme]!)), [[a], name]);
    for (const [j, b] of VALUES.entries()) if ((i + j) % 4 === 0) await run('derive', `${name}/v${i}+${j}`, (ins: any[], nme: string) => taggedJson(X.derive(ins.map(val), COMBINE[nme]!)), [[a, b], name]);
  }
}
for (const [i, ins] of ([[], [{ $raw: 'x' }], [VALUES[0], { $raw: { value: 'y', cap: { sources: ['trusted-query'], isTrusted: true } } }], [VALUES[0], { $raw: null }], [VALUES[2], VALUES[3], VALUES[6]]] as any[]).entries())
  for (const name of ['count', 'pair']) await run('derive', `odd${i}/${name}`, (xs: any[], nme: string) => taggedJson(X.derive(xs.map(val), COMBINE[nme]!)), [ins, name]);

// ---- checkAction --------------------------------------------------------------------------------------------------------------------------------
const mkArgs = (spec: any[]) => { const a: any[] = []; spec.forEach((s, i) => { if (s !== null && typeof s === 'object' && s.$hole === true) { a.length = i + 1; } else a[i] = s === null ? undefined : val(s); }); return a; };
const mkGov = (g: any) => ({ sinkFor: () => { if (g.throws) throw new Error('governor failed'); return mkSink(g.sink); } });
const ACTION = { verb: 'send_email', resource: 'mail:out' };
const GOVS: any[] = [{ sink: SINKS[0] }, { sink: SINKS[1] }, { sink: SINKS[2] }, { sink: SINKS[4] }, { sink: SINKS[13] }, { sink: SINKS[15] }, { sink: null }, { throws: true }, { sink: SINKS[6] }];
const ARGLISTS: any[][] = [
  [], [VALUES[0]], [VALUES[2]], [VALUES[0], VALUES[2]], [VALUES[2], VALUES[0]], [VALUES[0], VALUES[1], VALUES[3]], [VALUES[6], VALUES[7]], [VALUES[0], null, VALUES[2]], [VALUES[0], { $hole: true }], [{ $hole: true }, VALUES[2]],
  [{ $raw: 'plain' }], [VALUES[0], { $raw: { value: 1, cap: {} } }], [null, null], [VALUES[3], VALUES[4], VALUES[5], VALUES[8], VALUES[9]], [VALUES[10], VALUES[11]],
];
for (const [i, g] of GOVS.entries()) for (const [j, a] of ARGLISTS.entries()) {
  for (const opts of [{}, { expectedArgs: a.length }, { expectedArgs: a.length + 1 }]) {
    if (opts.expectedArgs !== undefined && (i + j) % 3 !== 0) continue;
    await run('checkAction', `g${i}/a${j}/${JSON.stringify(opts)}`, (act: any, args: any[], gov: any, op: any) => X.checkAction(act, mkArgs(args), mkGov(gov), op), [ACTION, a, g, opts]);
  }
}
for (const e of [0, 1, 1.5, -1, 2 ** 31, 1e21]) await run('checkAction', `expected/${e}`, (act: any, args: any[], gov: any, op: any) => X.checkAction(act, mkArgs(args), mkGov(gov), op), [ACTION, [VALUES[0]], GOVS[2], { expectedArgs: e }]);

// ---- dualContext / presets / levelOf -----------------------------------------------------------------------------------------------------------------
for (const [i, q] of [...VALUES, ...RAWS].entries()) {
  for (const plan of ['identity', 'wrap', 'throw']) for (const qu of ['tagged_untrusted', 'trusted', 'raw', 'throw']) {
    if ((i + plan.length + qu.length) % 3 !== 0 && i > 1) continue;
    await run('dualContext', `q${i}/${plan}/${qu}`, (spec: any) => { const r = X.dualContext({ query: val(spec.query), plan: DUAL_PLAN[spec.plan]!, quarantine: DUAL_Q[spec.quarantine]! }); return { plan: r.plan, result: taggedJson(r.result) }; }, [{ query: q, plan, quarantine: qu }]);
  }
}
for (const id of ['', 'x', 'send', 'é']) { await run('externalSendSink', id, X.externalSendSink, [id]); await run('sensitiveSink', id, X.sensitiveSink, [id]); }
for (const [i, v] of [...VALUES, ...RAWS].entries()) await run('levelOf', `v${i}`, (x: any) => X.levelOf(val(x)), [v]);
o.add('consts', 'all', [], { TRUSTED_QUERY: X.TRUSTED_QUERY, tool: X.toolProvenance('x'), tool2: X.toolProvenance('') });

// ---- trace rules -----------------------------------------------------------------------------------------------------------------------------------------
const TABLE: any = {
  'mail.read': { traits: ['pca.pii_access'], effects: ['read'] }, 'mail.send': { traits: ['pca.external_communication'], effects: ['write'] }, 'web.fetch': { traits: ['pca.network_egress'], effects: ['read'] },
  'db.read': { traits: ['pca.financial_data_read', 'pca.regulated_data'], effects: ['read'] }, 'db.write': { traits: ['x'], effects: ['write'] }, 'file.export': { traits: ['pca.data_export'] },
  'creds.get': { traits: ['pca.credential_access'], effects: ['read'] }, 'post.public': { traits: ['pca.public_exposure', 'pca.network_egress'], effects: ['write', 'read'] },
  'noop': { traits: [] }, 'a:b/c-d.e_f': { traits: ['t1'] },
};
const RULE_TEXTS = [
  'never tool:mail.send after tool:mail.read within 10m', 'never tool:mail.send after tool:web.fetch within 2h', 'never trait:pca.external_communication after trait:pca.pii_access within 7d', 'never any after any within 1s',
  'never tool:mail.send after resource:/secret within 5m', 'never resource:/x after tool:mail.read within 5m', 'never tool:db.write after tool:db.read, tool:mail.read within 30d', 'never tool:db.write after tool:db.read within 31d',
  'never tool:db.write after tool:db.read within 720h', 'never tool:db.write after tool:db.read within 43200m', 'never tool:db.write after tool:db.read within 2592000s', 'never tool:db.write after tool:db.read within 2592000001ms',
  'never tool:mail.send after tool:mail.read within 0s', 'never tool:mail.send after tool:mail.read within 01s', 'never tool:mail.send after tool:mail.read within 10', 'never tool:mail.send after tool:mail.read within 10x', 'never tool:mail.send after tool:mail.read within 99999999999d',
  'never tool:mail.send after tool:mail.read', 'never after tool:mail.read within 1m', 'never tool:mail.send after within 1m', 'NEVER tool:mail.send after tool:mail.read within 1m', '  never   tool:mail.send   after   tool:mail.read   within   1m  ',
  'never tool:mail.send after tool:mail.read within 1m\n', 'never tool:mail.send\nafter tool:mail.read within 1m', 'never tool:mail send after tool:mail.read within 1m', 'never tool: after tool:a within 1m', 'never tool:a b after tool:c within 1m',
  'never tool:a after tool:b within 1m within 2m', 'never tool:a after tool:b after tool:c within 1m', 'never tool:a,tool:b,trait:t after tool:c,any within 3h', 'never tool:a,,tool:b after tool:c within 1m', 'never tool:a, after tool:c within 1m',
  'never trait: after tool:c within 1m', 'never resource: after tool:c within 1m', 'never tool:c after resource:' + 'x'.repeat(256) + ' within 1m', 'never tool:c after resource:' + 'x'.repeat(257) + ' within 1m', 'never tool:' + 'v'.repeat(256) + ' after tool:c within 1m', 'never tool:' + 'v'.repeat(257) + ' after tool:c within 1m',
  'never any after any within 1m', 'never  any,any after any within 1m', 'never tool:a after bogus within 1m', 'never tool:a after tool:é within 1m', 'never tool:a  after tool:b within 1m', 'never tool:a after tool:b within 1m', '', 'x', null as any,
];
for (const [i, t] of RULE_TEXTS.entries()) {
  if (t === null) continue;
  for (const id of ['r1', 'a', 'A', '1a', '', 'x'.repeat(40), 'x'.repeat(41), 'a_b9']) {
    if (id !== 'r1' && i % 4 !== 0) continue;
    await run('parseTraceRule', `${i}/${id.length}${id.slice(0, 3)}`, X.parseTraceRule, [id, t]);
  }
  await run('parseTraceRule', `${i}/reason`, X.parseTraceRule, ['r1', t, 'because']);
}
await run('parseTraceRule', 'reason-null', X.parseTraceRule, ['r1', RULE_TEXTS[0], null]);
await run('parseTraceRule', 'reason-empty', X.parseTraceRule, ['r1', RULE_TEXTS[0], '']);
const INV = (extra: string[] = [], head = 'raise "no leak" if:', flow = '(a: ToolOutput) -> (b: ToolCall)') => [head, flow, ...extra].join('\n');
const INV_TEXTS = [
  INV(['a is tool:get_website', 'b is tool:send_email']), INV(['a is tool:get_website']), INV(), INV(['b is tool:send_email']), INV(['a is tool:x', 'a is tool:y', 'b is tool:z']), INV(['a is tool:x', 'a is tool:x']),
  INV(['a is tool:get_website({q: 1})', 'b is tool:send_email']), INV(['a is tool:get_website', 'b is tool:send_email', 'a.content contains "x"']), INV(['c is tool:zzz']), INV(['a is tool:x', '# comment', '', '  b is tool:y  ']),
  INV([], "raise 'single' if:"), INV([], 'raise "" if:'), INV([], 'raise "x" if: '), INV([], 'raise "x" if'), INV([], 'raise x if:'), INV([], 'rais "x" if:'), INV([], 'raise "x" if:', '(a: ToolCall) -> (b: ToolCall)'), INV([], 'raise "x" if:', '(a: Message) -> (b: ToolCall)'),
  INV([], 'raise "x" if:', '(a: ToolOutput) -> (b: ToolOutput)'), INV([], 'raise "x" if:', '(a: ToolOutput) -> (b: Message)'), INV([], 'raise "x" if:', '(a: ToolCall) -> (a: ToolCall)'), INV([], 'raise "x" if:', '(a: ToolOutput) -> (b: ToolCall) -> (c: ToolCall)'),
  INV([], 'raise "x" if:', '(a:ToolCall)->(b:ToolCall)'), INV([], 'raise "x" if:', '( a: ToolCall ) -> ( b: ToolCall )'), INV([], 'raise "x" if:', 'a -> b'), '', 'raise "x" if:', '# only a comment', '\n\nraise "x" if:\n(a: ToolCall) -> (b: ToolCall)\r\na is tool:t\r\n',
  INV(['a is tool:' + 'v'.repeat(300)]), INV(['a is tool:é']), INV(['a  is  tool:ok']), INV(['b is tool:z', 'a is tool:y', 'b is tool:w']),
];
for (const [i, t] of INV_TEXTS.entries()) {
  for (const [j, op] of ([{ horizon: '7d' }, { horizon: '7d', dropUnsupported: true }, { horizon: '31d' }, { horizon: 5 }, {}, { horizon: '1m', dropUnsupported: 1 }, { horizon: '10m', dropUnsupported: false }] as any[]).entries()) {
    if (j > 1 && i % 3 !== 0) continue;
    await run('parseInvariantRule', `${i}/o${j}`, X.parseInvariantRule, ['inv', t, op]);
  }
}
for (const id of ['', 'Bad', 'ok']) await run('parseInvariantRule', `id/${id}`, X.parseInvariantRule, [id, INV_TEXTS[0], { horizon: '1d' }]);
await run('parseInvariantRule', 'null-opts', X.parseInvariantRule, ['inv', INV_TEXTS[0], null]);

// compile: the table x parsed rules, plus hand-built selectors and hostile rules
const sel = (over: any = {}) => ({ tools: [], traits: [], resources: [], any: false, ...over });
const rule = (id: string, never: any, after: any, within_ms = 600_000, extra: any = {}) => ({ id, never: sel(never), after: sel(after), within_ms, ...extra });
const RULES: any[][] = [
  [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] })],
  [rule('r1', { tools: ['mail.send', 'post.public'] }, { tools: ['mail.read', 'db.read'], resources: ['/secret', '/a', '/secret'] })],
  [rule('r1', { traits: ['pca.external_communication'] }, { traits: ['pca.pii_access'] })],
  [rule('r1', { any: true }, { any: true })], [rule('r1', { any: true }, { tools: ['noop'] }, 1)],
  [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }), rule('r2', { tools: ['file.export'] }, { traits: ['pca.network_egress'] })],
  [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }), rule('r1', { tools: ['file.export'] }, { tools: ['mail.read'] })],
  [rule('r1', { tools: ['nope'] }, { tools: ['mail.read'] })], [rule('r1', { tools: ['mail.send'] }, { tools: ['nope'] })], [rule('r1', { traits: ['no.such.trait'] }, { tools: ['mail.read'] })], [rule('r1', { tools: ['mail.send'] }, { traits: ['no.such'] })],
  [rule('r1', { tools: ['mail.send'], resources: ['/x'] }, { tools: ['mail.read'] })], [rule('r1', { tools: ['mail.send'] }, { resources: ['/only'] })], [rule('r1', {}, { tools: ['mail.read'] })], [rule('r1', { tools: ['mail.send'] }, {})],
  [rule('R1', { tools: ['mail.send'] }, { tools: ['mail.read'] })], [rule('', { tools: ['mail.send'] }, { tools: ['mail.read'] })],
  [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }, 0)], [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }, 2_592_000_000)], [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }, 2_592_000_001)],
  [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }, 1.5)], [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }, -1)], [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }, '10' as any)],
  [], [rule('r1', { tools: ['a:b/c-d.e_f'] }, { tools: ['a:b/c-d.e_f'] })], [rule('r1', { any: true }, { any: true, resources: ['/p', '/q'] })],
  [rule('r1', { tools: ['mail.send'] }, { tools: ['mail.read'] }, 600_000, { reason: 'why' })],
  // many caveats: 3 rules x (any|any) = 8 verbs each... exceed the cap with resource prefixes
  [rule('big', { any: true }, { any: true, resources: Array.from({ length: 70 }, (_, i) => '/p' + i) })],
  [rule('big', { any: true }, { any: true, resources: Array.from({ length: 5 }, (_, i) => '/p' + i) })],
];
for (const [i, rs] of RULES.entries()) await run('compileTraceRules', `r${i}`, X.compileTraceRules, [rs, TABLE]);
{
  const parsed = RULE_TEXTS.slice(0, 12).map((t, i) => { try { return X.parseTraceRule('p' + i, t); } catch { return null; } }).filter((x) => x !== null);
  for (const [i, r] of parsed.entries()) await run('compileTraceRules', `parsed${i}`, X.compileTraceRules, [[r], TABLE]);
  await run('compileTraceRules', 'parsed-all', X.compileTraceRules, [parsed, TABLE]);
  const inv = INV_TEXTS.slice(0, 5).map((t, i) => { try { return X.parseInvariantRule('i' + i, t, { horizon: '7d', dropUnsupported: true }).rule; } catch { return null; } }).filter((x) => x !== null);
  for (const [i, r] of inv.entries()) await run('compileTraceRules', `inv${i}`, X.compileTraceRules, [[r], { ...TABLE, get_website: { traits: [] }, send_email: { traits: [] }, x: { traits: [] }, y: { traits: [] }, z: { traits: [] } }]);
}
for (const t of [{}, { a: { traits: [] } }, { a: null }, { a: { traits: 'x' } }, { a: {} }]) await run('compileTraceRules', `table/${JSON.stringify(t)}`, X.compileTraceRules, [[rule('r1', { any: true }, { any: true })], t]);
for (const rs of [null, {}, 'x', [null], [5], [{}], [{ id: 'r1' }], [{ id: 'r1', never: null, after: sel(), within_ms: 5 }]]) await run('compileTraceRules', `hostile/${JSON.stringify(rs)}`, X.compileTraceRules, [rs, TABLE]);

// lethal trifecta
const EDGES = (pairs: [string, string][]) => pairs.map(([f, t]) => ({ rule: 'r', from: { tool: f }, to: t, within_ms: 1 }));
const TRIFECTA: any[] = [
  { ...TABLE }, { 'mail.read': TABLE['mail.read'], 'mail.send': TABLE['mail.send'] }, { 'mail.read': TABLE['mail.read'], 'mail.send': TABLE['mail.send'], 'web.fetch': TABLE['web.fetch'] },
  { 'db.read': TABLE['db.read'], 'post.public': TABLE['post.public'], 'x.read': { traits: ['untrusted'], effects: ['read'] } }, {}, { a: { traits: [] } },
  { r: { traits: ['pca.pii_access'], effects: ['read'] }, s: { traits: ['pca.external_communication'], effects: ['read'] }, u: { traits: ['pca.network_egress'], effects: ['read'] } },
  { r: { traits: ['pca.pii_access'] }, s: { traits: ['pca.data_export'], effects: [] }, u: { traits: ['pca.network_egress'] } }, { r: { traits: ['pca.pii_access'] }, s: { traits: ['pca.data_export'], effects: ['read', 'write'] }, u: { traits: ['pca.network_egress'], effects: ['read'] } },
];
const EDGESETS: any[] = [[], EDGES([['web.fetch', 'mail.send']]), EDGES([['mail.read', 'mail.send']]), EDGES([['web.fetch', 'mail.send'], ['mail.read', 'mail.send']]), EDGES([['web.fetch', 'file.export'], ['db.read', 'post.public'], ['x.read', 'post.public']]), [{ rule: 'r', from: { resource: '/x' }, to: 'mail.send', within_ms: 1 }], EDGES([['u', 's']]), EDGES([['r', 's'], ['u', 's']])];
for (const [i, t] of TRIFECTA.entries()) for (const [j, e] of EDGESETS.entries()) for (const [k, op] of ([{}, { untrusted: ['mail.read'] }, { untrusted_traits: ['pca.pii_access'] }, { untrusted: ['nope'], untrusted_traits: ['x'] }] as any[]).entries()) {
  if ((i + j + k) % 3 !== 0) continue;
  await run('lethalTrifecta', `t${i}/e${j}/o${k}`, X.lethalTrifecta, [t, e, op]);
}
await run('lethalTrifecta', 'null-opts', X.lethalTrifecta, [TRIFECTA[0], [], null]);
o.add('traceConsts', 'all', [], { MAX_TRACE_CAVEATS: X.MAX_TRACE_CAVEATS, PRIVATE_READ_TRAITS: X.PRIVATE_READ_TRAITS, EXTERNAL_SEND_TRAITS: X.EXTERNAL_SEND_TRAITS });

// ---- detectors ---------------------------------------------------------------------------------------------------------------------------------------------
const SEED = Buffer.from(seed('dataflow/gateway')).toString('base64url');
const CTX = (over: any = {}) => ({ detector: 'lakera', version: 'v2.1', content: 'hello world', secretKey: { $bytes: SEED }, now: 1_800_000_000_000, ...over });
const wrap = (f: string) => (resp: any, ctx: any) => X[f](resp, { ...ctx, secretKey: new Uint8Array(Buffer.from(ctx.secretKey.$bytes, 'base64url')) });
for (const s of ['Prompt Injection', 'prompt_injection', 'pii/email', '  x  ', '123abc', '9', '', '---', 'é', 'ÀB', 'A'.repeat(70), 'a'.repeat(64), 'a'.repeat(65), '_a_', 'a__b', 'a-b-c', 'ǅ', 'İx', 'ΑΣ', '1' + 'a'.repeat(70), '\ud800', 'x\u0000y', 'unicode_ß', 'dotted.name.here']) await run('categoryId', s.slice(0, 20), X.categoryId, [s]);
for (const v of [null, 5, true, [], {}, ['x']]) await run('categoryId', `nonstring/${JSON.stringify(v)}`, X.categoryId, [v]);
const LAKERA = [
  { flagged: false }, { flagged: true }, { flagged: false, breakdown: [] }, { flagged: false, breakdown: [{ detector_type: 'moderated_content/hate', detected: false }] }, { flagged: false, breakdown: [{ detector_type: 'prompt_attack', detected: true }] },
  { flagged: true, breakdown: [{ detector_type: 'pii/email', detected: true }, { detector_type: 'prompt_attack', detected: true }, { detector_type: 'x', detected: false }] }, { flagged: false, breakdown: [{ detected: true }] }, { flagged: false, breakdown: [{ detector_type: 5, detected: true }] },
  { flagged: 'yes' }, { flagged: 1 }, {}, null, 5, 'x', [], { flagged: false, breakdown: 'x' }, { flagged: false, breakdown: null }, { flagged: false, breakdown: [null] }, { flagged: false, breakdown: [{ detector_type: 'a', detected: 'yes' }] },
  { flagged: true, breakdown: Array.from({ length: 12 }, (_, i) => ({ detector_type: 'cat' + i, detected: true })) }, { flagged: false, metadata: { request_uuid: 'x' }, breakdown: [{ detector_type: 'a b', detected: true }, { detector_type: 'A-B', detected: true }] },
];
const PS = [
  { result: { action: 'log' } }, { result: { action: 'block' } }, { result: { action: 'modify' } }, { result: { action: 'allow', prompt: { action: 'log' } } }, { result: { prompt: { action: 'block', violations: ['jailbreak', 'pii'] } } },
  { result: { prompt: { action: 'log', violations: [] } } }, { result: { prompt: { action: 'log', violations: ['x y'] } } }, { result: { action: 'block', prompt: { action: 'modify', violations: ['a'] } } }, { result: { prompt: { action: 'log', violations: 'x' } } },
  { result: { prompt: 'x' } }, { result: { prompt: null } }, { result: { prompt: { violations: [] } } }, { result: {} }, { result: null }, { result: 'x' }, {}, null, 5, { result: { action: 5 } }, { result: { action: 'log', prompt: { action: 7 } } },
  { result: { action: null } }, { result: { action: 'log', prompt: { action: 'log', violations: [5, null, { a: 1 }] } } }, { result: { action: 'LOG' } }, { result: { action: 'Block' } }, [], { result: [] },
];
const GEN = [
  { flagged: false }, { flagged: true }, { flagged: true, categories: ['pii', 'jailbreak'] }, { flagged: false, categories: [] }, { flagged: false, categories: ['x'] }, { flagged: true, categories: [] }, { flagged: true, categories: 'x' }, { flagged: 'no' }, {}, null, 5, [], { flagged: true, categories: [5, null, 'a b', 'A B'] },
  { flagged: true, categories: Array.from({ length: 12 }, (_, i) => 'c' + (11 - i)) }, { flagged: true, categories: ['b', 'a', 'b'] }, { flagged: false, categories: null }, { flagged: true, categories: null },
];
const CTXS: any[] = [
  CTX(), CTX({ detector: 'Bad' }), CTX({ detector: '' }), CTX({ version: '' }), CTX({ version: 'v'.repeat(64) }), CTX({ version: 'v'.repeat(65) }), CTX({ version: 'é'.repeat(32) }), CTX({ version: 'é'.repeat(33) }), CTX({ content: { a: [1, 2] } }), CTX({ content: null }),
  CTX({ now: 0 }), CTX({ now: -1 }), CTX({ now: 1.5 }), CTX({ now: -0 }), CTX({ now: 2 ** 53 }), CTX({ session: Buffer.alloc(32, 7).toString('base64url') }), CTX({ session: 'short' }), CTX({ session: null }), CTX({ calibration_ref: 'bench-2026' }), CTX({ calibration_ref: '' }),
  CTX({ calibration_ref: 'c'.repeat(256) }), CTX({ calibration_ref: 'c'.repeat(257) }), CTX({ content: '\ud800' }),
];
for (const [i, c] of CTXS.entries()) {
  await run('lakeraReceipt', `ctx${i}/a`, wrap('lakeraReceipt'), [LAKERA[0], c]);
  await run('lakeraReceipt', `ctx${i}/b`, wrap('lakeraReceipt'), [LAKERA[5], c]);
  await run('promptSecurityReceipt', `ctx${i}`, wrap('promptSecurityReceipt'), [PS[1], c]);
  await run('genericReceipt', `ctx${i}`, wrap('genericReceipt'), [GEN[2], c]);
}
for (const [i, r] of LAKERA.entries()) await run('lakeraReceipt', `r${i}`, wrap('lakeraReceipt'), [r, CTX()]);
for (const [i, r] of PS.entries()) await run('promptSecurityReceipt', `r${i}`, wrap('promptSecurityReceipt'), [r, CTX({ detector: 'prompt_security' })]);
for (const [i, r] of GEN.entries()) await run('genericReceipt', `r${i}`, wrap('genericReceipt'), [r, CTX({ detector: 'home_grown' })]);
refWrite(o, 'dataflow');
