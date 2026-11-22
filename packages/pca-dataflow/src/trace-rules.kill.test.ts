import { DERIVE_MAX_WINDOW_MS, hashCanonical } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  MAX_TRACE_CAVEATS,
  TraceRuleError,
  compileTraceRules,
  lethalTrifecta,
  parseInvariantRule,
  parseTraceRule,
  type TraceRule,
  type TraceSelector,
  type VerbTable,
} from './trace-rules';

const err = (f: () => unknown): { code: string; message: string } => {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(TraceRuleError);
    const t = e as TraceRuleError;
    expect(t.name).toBe('TraceRuleError');
    return { code: t.code, message: t.message };
  }
  throw new Error('did not throw');
};
const sel = (over: Partial<TraceSelector> = {}): TraceSelector => ({ tools: [], traits: [], resources: [], any: false, ...over });
const rule = (over: Partial<TraceRule> = {}): TraceRule => ({ id: 'r', never: sel({ tools: ['b'] }), after: sel({ tools: ['a'] }), within_ms: 1000, ...over });
const T = (...verbs: string[]): VerbTable => Object.fromEntries(verbs.map((v) => [v, { traits: [] as string[] }]));

describe('parseTraceRule: id, syntax and duration', () => {
  it('a malformed id is refused with the pattern in the message', () => {
    for (const id of ['', 'A', '1a', 'a-b', 'a'.repeat(41)]) {
      expect(err(() => parseTraceRule(id, 'never tool:b after tool:a within 1h'))).toEqual({ code: 'id', message: `rule id '${id}' must match ^[a-z][a-z0-9_]{0,39}$` });
    }
    expect(parseTraceRule('a'.repeat(40), 'never tool:b after tool:a within 1h').id).toBe('a'.repeat(40));
  });
  it('the rule text is anchored at both ends and tolerates surrounding and doubled whitespace', () => {
    const ok = (t: string) => parseTraceRule('r', t).within_ms;
    expect(ok('  never tool:b after tool:a within 1h')).toBe(3_600_000);
    expect(ok('never tool:b after tool:a within 1h   ')).toBe(3_600_000);
    expect(ok('never tool:b after tool:a within  1h')).toBe(3_600_000);
    expect(ok('never   tool:b   after   tool:a   within   1h')).toBe(3_600_000);
    for (const bad of ['x never tool:b after tool:a within 1h', 'never tool:b after tool:a within 1h extra', 'never tool:b after tool:a', 'tool:b after tool:a within 1h']) {
      const e = err(() => parseTraceRule('r', bad));
      expect(e).toEqual({ code: 'syntax', message: `expected 'never <selector> after <selector> within <duration>', got '${bad}'` });
    }
    // an all-space selector still matches the grammar (the space is the selector); it is then refused as an empty selector
    for (const bad of ['never   after tool:a within 1h', 'never tool:b after   within 1h']) {
      expect(err(() => parseTraceRule('r', bad))).toEqual({ code: 'selector', message: "'' is not tool:<verb>, trait:<id>, resource:<prefix> or any" });
    }
  });
  it('durations: units, bounds, and the 30-day ceiling', () => {
    const d = (t: string) => parseTraceRule('r', `never tool:b after tool:a within ${t}`).within_ms;
    expect([d('1ms'), d('2s'), d('3m'), d('4h'), d('5d')]).toEqual([1, 2000, 180_000, 14_400_000, 432_000_000]);
    expect(d('30d')).toBe(DERIVE_MAX_WINDOW_MS);
    expect(err(() => d('31d'))).toEqual({ code: 'window', message: 'a window of 31d exceeds the 30-day history the verifier keeps' });
    for (const bad of ['10x', '0m', '05m', '5mx', 'x5m', '1.5h', '12345678901s', 'h']) {
      expect(err(() => d(bad))).toEqual({ code: 'duration', message: `'${bad}' is not a duration like 10m, 2h or 7d` });
    }
  });
});

describe('parseTraceRule: selectors', () => {
  it('atoms are trimmed and sliced past their prefix', () => {
    const r = parseTraceRule('r', 'never tool:mail.send , tool:slack.post,trait:pca.x after any within 1h');
    expect(r.never).toEqual({ tools: ['mail.send', 'slack.post'], traits: ['pca.x'], resources: [], any: false });
    expect(r.after).toEqual({ tools: [], traits: [], resources: [], any: true });
  });
  it('resource selectors name the earlier action only, with a 1..256 character prefix', () => {
    const r = parseTraceRule('r', 'never tool:b after resource:crm/ within 1h');
    expect(r.after.resources).toEqual(['crm/']);
    expect(parseTraceRule('r', `never tool:b after resource:${'p'.repeat(256)} within 1h`).after.resources).toEqual(['p'.repeat(256)]);
    expect(parseTraceRule('r', 'never tool:b after resource:p within 1h').after.resources).toEqual(['p']);
    expect(err(() => parseTraceRule('r', 'never resource:crm/ after tool:a within 1h'))).toEqual({
      code: 'resource_on_effect',
      message: 'a resource selector can only name the earlier action (the check reads the current verb)',
    });
    for (const a of ['resource:', `resource:${'p'.repeat(257)}`, 'zzzzzzzzzzzzzz', 'resourcezzzzzzz']) {
      expect(err(() => parseTraceRule('r', `never tool:b after ${a} within 1h`)).code).toBe('selector');
    }
  });
  it('anything else is refused naming the atom', () => {
    for (const a of ['bogus', 'tool:', 'tool:a b', 'trait:', 'ANY']) {
      expect(err(() => parseTraceRule('r', `never tool:b after ${a} within 1h`))).toEqual({ code: 'selector', message: `'${a}' is not tool:<verb>, trait:<id>, resource:<prefix> or any` });
    }
  });
  it('the reason is carried only when given', () => {
    expect('reason' in parseTraceRule('r', 'never tool:b after tool:a within 1h')).toBe(false);
    expect(parseTraceRule('r', 'never tool:b after tool:a within 1h', 'why').reason).toBe('why');
  });
});

describe('parseInvariantRule', () => {
  const head = 'raise "no leak" if:';
  const flow = '(a: ToolOutput) -> (b: ToolCall)';
  const imp = (lines: string[], o: { horizon: string; dropUnsupported?: boolean } = { horizon: '1h' }) => parseInvariantRule('r', lines.join('\n'), o);

  it('compiles the supported subset', () => {
    const r = imp([head, flow, 'a is tool:get_website', 'b is tool:send_email']);
    expect(r.rule).toEqual({ id: 'r', never: { tools: ['send_email'], traits: [], resources: [], any: false }, after: { tools: ['get_website'], traits: [], resources: [], any: false }, within_ms: 3_600_000, reason: 'no leak' });
    expect(r.dropped).toEqual([]);
  });
  it('an unconstrained side matches any tool', () => {
    const r = imp([head, flow]);
    expect(r.rule.never).toEqual({ tools: [], traits: [], resources: [], any: true });
    expect(r.rule.after.any).toBe(true);
  });
  it('single-quoted and empty messages are read', () => {
    expect(imp([`raise 'it works' if:`, flow]).rule.reason).toBe('it works');
    expect(imp(['raise "" if:', flow]).rule.reason).toBe('');
    expect(imp([`raise 'a "quoted" word' if:`, flow]).rule.reason).toBe('a "quoted" word');
  });
  it('blank lines and # comments are ignored, but a leading space is not part of the line', () => {
    const r = imp(['', '# a comment', `   ${head}`, '', flow, '# another', 'a is tool:x', '', 'b is tool:y']);
    expect(r.rule.after.tools).toEqual(['x']);
    expect(r.rule.never.tools).toEqual(['y']);
    expect(imp(['#', head, flow, '#x#']).rule.reason).toBe('no leak');
  });
  it('the first line must be raise "<message>" if:', () => {
    const msg = 'the first line must be raise "<message>" if:';
    for (const bad of ['', 'xraise "m" if:', 'raise "m" if: extra', 'raise m if:', 'raise "m"', `raise 'a' "b" if:`, 'raise "m" if', 'raise"m" if:']) {
      expect(err(() => imp([bad, flow]))).toEqual({ code: 'syntax', message: msg });
    }
    expect(err(() => parseInvariantRule('r', '', { horizon: '1h' }))).toEqual({ code: 'syntax', message: msg });
    for (const good of ['raise  "m" if:', 'raise "m"  if:', `raise 'abc' if:`, `raise 'ab' if:`]) expect(imp([good, flow]).rule.id).toBe('r');
  });
  it('the second line must be one ToolCall/ToolOutput -> ToolCall flow', () => {
    const msg = `the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)`;
    for (const bad of ['', 'x(a: ToolCall) -> (b: ToolCall)', '(a: ToolCall) -> (b: ToolCall) extra', '(a: ToolCall) -> (b: ToolCall) -> (c: ToolCall)', '(a: Tool) -> (b: ToolCall)', '(a: ToolCall) => (b: ToolCall)']) {
      expect(err(() => imp([head, bad]))).toEqual({ code: 'unsupported', message: msg });
    }
    for (const good of ['(a:ToolCall)->(b:ToolCall)', '(a:  ToolOutput)  ->  (b:  ToolCall)', '(a: ToolCall)->(b: ToolCall)', '(a: ToolCall) ->(b: ToolCall)']) expect(imp([head, good]).rule.id).toBe('r');
  });
  it('a message start, or a non-call end, cannot be compiled', () => {
    const msg = 'only a tool call or tool output followed by a tool call can be compiled';
    expect(err(() => imp([head, '(a: Message) -> (b: ToolCall)']))).toEqual({ code: 'unsupported', message: msg });
    expect(err(() => imp([head, '(a: ToolCall) -> (b: ToolOutput)']))).toEqual({ code: 'unsupported', message: msg });
    expect(err(() => imp([head, '(a: ToolCall) -> (b: Message)']))).toEqual({ code: 'unsupported', message: msg });
  });
  it('the two events need distinct names', () => {
    expect(err(() => imp([head, '(a: ToolCall) -> (a: ToolCall)']))).toEqual({ code: 'syntax', message: 'the two events need distinct names' });
  });
  it('a malformed id or missing horizon is refused', () => {
    expect(err(() => parseInvariantRule('Bad', `${head}\n${flow}`, { horizon: '1h' }))).toEqual({ code: 'id', message: `rule id 'Bad' must match ^[a-z][a-z0-9_]{0,39}$` });
    const h = { code: 'horizon', message: 'an Invariant rule has no window: pass the horizon explicitly' };
    expect(err(() => parseInvariantRule('r', `${head}\n${flow}`, undefined as never))).toEqual(h);
    expect(err(() => parseInvariantRule('r', `${head}\n${flow}`, { horizon: 3600 as never }))).toEqual(h);
    expect(err(() => parseInvariantRule('r', `${head}\n${flow}`, { horizon: '40d' })).code).toBe('window');
  });
  it('conditions outside the subset are refused naming the line', () => {
    for (const l of ['a is tool:x(args)', 'z is tool:x', 'a is not tool:x', 'junk a is tool:x', 'a is tool:x trailing', 'a contains "x"']) {
      expect(err(() => imp([head, flow, l]))).toEqual({ code: 'unsupported', message: `'${l}' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead` });
    }
    for (const ok of ['a  is tool:x', 'a is  tool:x', 'a is tool:x.y:z/w-1']) expect(imp([head, flow, ok]).rule.after.tools).toHaveLength(1);
  });
  it('dropUnsupported keeps the tool of an argument pattern and lists every dropped line', () => {
    const r = imp([head, flow, 'a is tool:x({"k": 1})', 'z is tool:y', 'a contains "q"'], { horizon: '1h', dropUnsupported: true });
    expect(r.rule.after.tools).toEqual(['x']);
    expect(r.rule.never.tools).toEqual([]);
    expect(r.dropped).toEqual(['a is tool:x({"k": 1})', 'z is tool:y', 'a contains "q"']);
    expect(imp([head, flow, 'a is tool:x'], { horizon: '1h', dropUnsupported: false }).dropped).toEqual([]);
  });
  it('a variable bound to two tools can never fire', () => {
    for (const v of ['a', 'b']) {
      expect(err(() => imp([head, flow, `${v} is tool:x`, `${v} is tool:y`]))).toEqual({ code: 'unsatisfiable', message: `'${v}' is constrained to two different tools, so the rule can never fire` });
    }
  });
});

describe('compileTraceRules', () => {
  it('output ids, order and edges are deterministic and sorted', () => {
    const t = T('z', 'm', 'a', 'b');
    const c = compileTraceRules([rule({ never: sel({ tools: ['z', 'a'] }), after: sel({ tools: ['m'] }) })], t);
    expect(c.edges.map((e) => e.to)).toEqual(['a', 'z']);
    const c2 = compileTraceRules([rule({ never: sel({ any: true }), after: sel({ tools: ['b', 'a'] }) })], t);
    expect(c2.edges.map((e) => `${(e.from as { tool: string }).tool}>${e.to}`)).toEqual(['a>a', 'a>b', 'a>m', 'a>z', 'b>a', 'b>b', 'b>m', 'b>z']);
    expect(c2.caveats.map((x) => x.id)).toEqual(['trace.r.0', 'trace.r.1']);
  });
  it('B verbs are chunked eight per caveat with consecutive indices', () => {
    const eight = Array.from({ length: 8 }, (_, i) => `v${i}`);
    const nine = [...eight, 'v8'];
    expect(compileTraceRules([rule({ never: sel({ tools: eight }), after: sel({ tools: ['a'] }) })], T('a', ...nine)).caveats.map((c) => c.id)).toEqual(['trace.r.0']);
    expect(compileTraceRules([rule({ never: sel({ tools: nine }), after: sel({ tools: ['a'] }) })], T('a', ...nine)).caveats.map((c) => c.id)).toEqual(['trace.r.0', 'trace.r.1']);
  });
  it('resource prefixes become count defs and edges, deduplicated and sorted', () => {
    const c = compileTraceRules([rule({ after: sel({ tools: ['a'], resources: ['b/', 'a/', 'b/'] }) })], T('a', 'b'));
    expect(c.edges).toEqual([
      { rule: 'r', from: { tool: 'a' }, to: 'b', within_ms: 1000 },
      { rule: 'r', from: { resource: 'a/' }, to: 'b', within_ms: 1000 },
      { rule: 'r', from: { resource: 'b/' }, to: 'b', within_ms: 1000 },
    ]);
    expect(c.caveats.map((x) => x.defs[0])).toEqual([
      { name: 'seen', kind: 'count', window_ms: 1000, verb: 'a' },
      { name: 'seen', kind: 'count', window_ms: 1000, resource_prefix: 'a/' },
      { name: 'seen', kind: 'count', window_ms: 1000, resource_prefix: 'b/' },
    ]);
  });
  it('the digest pins domain and caveats', () => {
    const c = compileTraceRules([rule()], T('a', 'b'));
    expect(c.digest).toBe(hashCanonical({ d: 'atlas-pca/trace-rules/v1', caveats: c.caveats }));
    expect(compileTraceRules([], T('a')).digest).toBe(hashCanonical({ d: 'atlas-pca/trace-rules/v1', caveats: [] }));
  });
  it('rule ids must be well-formed and unique', () => {
    const m = (id: string) => ({ code: 'id', message: `rule id '${id}' is malformed or repeated` });
    expect(err(() => compileTraceRules([rule({ id: 'Bad' })], T('a', 'b')))).toEqual(m('Bad'));
    expect(err(() => compileTraceRules([rule(), rule()], T('a', 'b')))).toEqual(m('r'));
    expect(compileTraceRules([rule({ id: 'r1' }), rule({ id: 'r2' })], T('a', 'b')).caveats.map((c) => c.id)).toEqual(['trace.r1.0', 'trace.r2.0']);
  });
  it('within_ms must be a safe integer in 1..30 days', () => {
    const w = (n: number) => compileTraceRules([rule({ within_ms: n })], T('a', 'b'));
    expect(w(1).caveats).toHaveLength(1);
    expect(w(DERIVE_MAX_WINDOW_MS).caveats).toHaveLength(1);
    for (const bad of [0, -5, 0.5, 1.5, DERIVE_MAX_WINDOW_MS + 1, Number.NaN, Infinity, 2 ** 53]) {
      expect(err(() => w(bad))).toEqual({ code: 'window', message: "rule 'r': within_ms must be 1..30 days" });
    }
  });
  it('a resource selector on the effect side is refused', () => {
    expect(err(() => compileTraceRules([rule({ never: sel({ tools: ['b'], resources: ['x'] }) })], T('a', 'b')))).toEqual({
      code: 'resource_on_effect',
      message: "rule 'r': a resource selector cannot name the later action",
    });
  });
  it('unknown tools and empty traits name the rule, the side and the selector', () => {
    expect(err(() => compileTraceRules([rule({ never: sel({ tools: ['nope'] }) })], T('a')))).toEqual({ code: 'unknown_tool', message: "rule 'r' never: tool 'nope' is not an action in the verb table" });
    expect(err(() => compileTraceRules([rule({ after: sel({ tools: ['nope'] }) })], T('b')))).toEqual({ code: 'unknown_tool', message: "rule 'r' after: tool 'nope' is not an action in the verb table" });
    expect(err(() => compileTraceRules([rule({ never: sel({ traits: ['t.x'] }) })], T('a')))).toEqual({ code: 'empty_selector', message: "rule 'r' never: trait 't.x' matches no action" });
    expect(err(() => compileTraceRules([rule({ after: sel({ traits: ['t.x'] }) })], T('b')))).toEqual({ code: 'empty_selector', message: "rule 'r' after: trait 't.x' matches no action" });
    expect(err(() => compileTraceRules([rule({ after: sel({ tools: ['toString'] }) })], T('b'))).code).toBe('unknown_tool');
  });
  it('a trait expands to every verb that carries it', () => {
    const t: VerbTable = { a: { traits: ['t.x'] }, b: { traits: ['t.y'] }, c: { traits: ['t.x', 't.y'] } };
    const c = compileTraceRules([rule({ never: sel({ traits: ['t.x'] }), after: sel({ tools: ['b'] }) })], t);
    expect(c.edges.map((e) => e.to)).toEqual(['a', 'c']);
  });
  it('a side that matches nothing is refused even when only one side is empty', () => {
    const m = { code: 'empty_selector', message: "rule 'r': a side matches nothing" };
    expect(err(() => compileTraceRules([rule({ never: sel(), after: sel({ tools: ['a'] }) })], T('a')))).toEqual(m);
    expect(err(() => compileTraceRules([rule({ never: sel({ tools: ['b'] }), after: sel() })], T('b')))).toEqual(m);
    expect(err(() => compileTraceRules([rule({ never: sel(), after: sel() })], T('a')))).toEqual(m);
  });
  it('at most 64 caveats', () => {
    const verbs = Array.from({ length: MAX_TRACE_CAVEATS + 1 }, (_, i) => `v${String(i).padStart(2, '0')}`);
    const t = T('b', ...verbs);
    expect(compileTraceRules([rule({ after: sel({ tools: verbs.slice(0, MAX_TRACE_CAVEATS) }) })], t).caveats).toHaveLength(MAX_TRACE_CAVEATS);
    expect(err(() => compileTraceRules([rule({ after: sel({ tools: verbs }) })], t))).toEqual({
      code: 'too_large',
      message: 'more than 64 caveats: split the rule set or narrow the selectors',
    });
  });
  it('a verb the derive language cannot carry is an internal error naming the rule and the problem', () => {
    const long = 'x'.repeat(300);
    const e = err(() => compileTraceRules([rule({ never: sel({ tools: ['b'] }), after: sel({ any: true }) })], T('b', long)));
    expect(e.code).toBe('internal');
    expect(e.message).toBe("rule 'r' compiled to an invalid caveat: def 'seen': verb must be a non-empty string");
  });
});

describe('lethalTrifecta', () => {
  const PRIV = 'pca.pii_access';
  const NET = 'pca.network_egress';
  const SEND = 'pca.external_communication';
  // an arbitrary phrase a caller could legitimately use as a verb name and as a trait id
  const sentinel = Buffer.from('U3RyeWtlciB3YXMgaGVyZQ==', 'base64').toString();

  it('lists verbs in sorted order and reports one finding per open send', () => {
    const t: VerbTable = {
      s2: { traits: [SEND], effects: ['create'] },
      u1: { traits: [NET], effects: ['read'] },
      p1: { traits: [PRIV], effects: ['read'] },
      s1: { traits: [SEND], effects: ['create'] },
      p0: { traits: [PRIV], effects: ['read'] },
    };
    const r = lethalTrifecta(t, []);
    expect(r.private_reads).toEqual(['p0', 'p1']);
    expect(r.untrusted_reads).toEqual(['u1']);
    expect(r.sends).toEqual(['s1', 's2']);
    expect(r.findings).toEqual([
      { send: 's1', from_untrusted: ['u1'], from_private: ['p0', 'p1'] },
      { send: 's2', from_untrusted: ['u1'], from_private: ['p0', 'p1'] },
    ]);
  });
  it('an edge cuts a leg only when it comes from that very tool to that very send', () => {
    const t: VerbTable = { p: { traits: [PRIV], effects: ['read'] }, u: { traits: [NET], effects: ['read'] }, s: { traits: [SEND], effects: ['create'] }, o: { traits: [], effects: ['read'] } };
    const edge = (from: TraceRule['id'], to: string) => ({ rule: 'r', from: { tool: from }, to, within_ms: 1 });
    expect(lethalTrifecta(t, [edge('o', 's')]).findings).toHaveLength(1);
    expect(lethalTrifecta(t, [edge('u', 'o')]).findings).toHaveLength(1);
    expect(lethalTrifecta(t, [{ rule: 'r', from: { resource: 'u' }, to: 's', within_ms: 1 }]).findings).toHaveLength(1);
    expect(lethalTrifecta(t, [edge('u', 's')]).findings).toEqual([]);
    expect(lethalTrifecta(t, [edge('p', 's')]).findings).toEqual([]);
    expect(lethalTrifecta(t, [edge('p', 's'), edge('u', 'o')]).findings).toEqual([]);
  });
  it('no finding unless private reads, untrusted reads and a send all exist', () => {
    const p = { traits: [PRIV], effects: ['read'] };
    const u = { traits: [NET], effects: ['read'] };
    const s = { traits: [SEND], effects: ['create'] };
    expect(lethalTrifecta({ u, s }, []).findings).toEqual([]);
    expect(lethalTrifecta({ p, s }, []).findings).toEqual([]);
    expect(lethalTrifecta({ p, u }, []).findings).toEqual([]);
    expect(lethalTrifecta({ p, u, s }, []).findings).toHaveLength(1);
  });
  it('read-only status needs effects that are non-empty and all read', () => {
    const base = { p: { traits: [PRIV], effects: ['read'] }, s: { traits: [SEND], effects: ['create'] } };
    const net = (effects?: string[]) => lethalTrifecta({ ...base, n: { traits: [NET, SEND], ...(effects ? { effects } : {}) } }, []);
    expect(net(['read']).untrusted_reads).toEqual(['n']);
    expect(net(['read']).sends).toEqual(['s']);
    for (const e of [undefined, [], ['read', 'create'], ['create']]) {
      expect(net(e).untrusted_reads).toEqual([]);
      expect(net(e).sends).toEqual(['n', 's']);
    }
  });
  it('callers can name untrusted verbs and untrusted traits explicitly', () => {
    const t: VerbTable = { p: { traits: [PRIV] }, a: { traits: ['x.t'] }, b: { traits: [] }, s: { traits: [SEND], effects: ['create'] } };
    expect(lethalTrifecta(t, []).untrusted_reads).toEqual([]);
    expect(lethalTrifecta(t, [], { untrusted: ['b'] }).untrusted_reads).toEqual(['b']);
    expect(lethalTrifecta(t, [], { untrusted_traits: ['x.t'] }).untrusted_reads).toEqual(['a']);
  });
  it('defaults are empty: no verb or trait is untrusted by accident', () => {
    const t: VerbTable = { [sentinel]: { traits: [PRIV] }, q: { traits: [sentinel] } };
    expect(lethalTrifecta(t, []).untrusted_reads).toEqual([]);
  });
});
