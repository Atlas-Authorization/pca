// Exact outcomes for the AsyncAPI, JSON Schema and MCP importers and the CLI registry: error codes and messages, todo
// entries, boundaries and annotation handling.
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { ActionKitError, IMPORTERS, defsToYaml, importAsyncApi, importJsonSchema, importMcp } from '../src';

const thrown = (f: () => unknown): ActionKitError => {
  try { f(); } catch (e) { return e as ActionKitError; }
  throw new Error('expected a throw');
};
const obj = (...names: string[]) => ({ type: 'object', properties: Object.fromEntries(names.map((n) => [n, { type: 'string' }])) });
const A = { ns: 'ev' };

describe('AsyncAPI importer details', () => {
  it('refuses a document without a 2.x/3.x asyncapi string, with the exact error', () => {
    const msg = "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')";
    for (const doc of [{ openapi: '3.0.0' }, { asyncapi: 2.1 }, { asyncapi: '12.0.0' }, { asyncapi: '4.0.0' }]) {
      const e = thrown(() => importAsyncApi(doc, A));
      expect(e).toBeInstanceOf(ActionKitError);
      expect(e.code).toBe('bad_source');
      expect(e.message).toBe(msg);
    }
  });

  it('notes an unresolvable channel reference and skips it', () => {
    const r = importAsyncApi({ asyncapi: '2.6.0', channels: { c1: { $ref: '#/channels/missing' } } }, A);
    expect(r.defs).toEqual([]);
    expect(r.todo).toEqual([{ where: 'c1', code: 'unresolved_ref', message: "reference '#/channels/missing' does not resolve locally" }]);
  });

  it('follows a reference chain 8 deep and stops at 9', () => {
    const build = (n: number) => {
      const x: Record<string, unknown> = {};
      for (let i = 0; i < n; i++) x[`r${i}`] = { $ref: `#/x/r${i + 1}` };
      x[`r${n}`] = { publish: { operationId: 'ping', message: { payload: obj('a') } } };
      return { asyncapi: '2.6.0', x, channels: { c1: { $ref: '#/x/r0' } } };
    };
    const ok = importAsyncApi(build(8), A);
    expect(ok.todo).toEqual([]);
    expect(ok.defs.map((d) => d.verb)).toEqual(['ev.ping']);
    const deep = importAsyncApi(build(9), A);
    expect(deep.defs).toEqual([]);
    expect(deep.todo).toEqual([{ where: 'c1', code: 'ref_depth', message: 'a reference chain is too deep' }]);
  });

  const one = (message: unknown) => importAsyncApi({ asyncapi: '2.6.0', channels: { t: { publish: { operationId: 'opx', message } } } }, A);

  it('payload shapes: object, properties-only, no payload, and non-object', () => {
    expect(one({ payload: { type: 'string' } }).todo).toEqual([{ where: 'send t', code: 'payload_shape', message: 'the message payload is not an object schema; it is not declared' }]);
    expect(one({ payload: { type: 'string' } }).defs[0]!.params).toEqual({});
    const unresolved = one({ payload: { $ref: '#/nope' } });
    expect(unresolved.todo).toEqual([
      { where: 'send t: payload', code: 'unresolved_ref', message: "reference '#/nope' is not a local reference that resolves (declared string; refine or drop)" },
      { where: 'send t', code: 'payload_shape', message: 'the message payload is not an object schema; it is not declared' },
    ]);
    expect(one({}).todo).toEqual([]);
    expect(one({ payload: { type: 'object' } }).todo).toEqual([]);
    expect(one({ payload: { type: 'object' } }).defs[0]!.params).toEqual({});
    expect(Object.keys(one({ payload: { properties: { a: { type: 'string' } } } }).defs[0]!.params)).toEqual(['a']);
  });

  it('several message variants: only the first is declared, and a lone message is not a variant', () => {
    const r = one({ oneOf: [{ payload: obj('x') }, { payload: obj('y') }] });
    expect(r.todo).toEqual([{ where: 'send t', code: 'message_variants', message: '2 message variants: only the first is declared' }]);
    expect(Object.keys(r.defs[0]!.params)).toEqual(['x']);
    const single = one({ oneOf: [{ payload: obj('x') }] });
    expect(single.todo).toEqual([]);
    const gone = one({ oneOf: [{ $ref: '#/nope' }, { payload: obj('x') }] });
    expect(gone.todo).toEqual([{ where: 'send t', code: 'unresolved_ref', message: "reference '#/nope' does not resolve locally" }]);
    expect(Object.keys(gone.defs[0]!.params)).toEqual(['x']);
  });

  it('channel parameters are declared in sorted order and sanitised', () => {
    const r = importAsyncApi({ asyncapi: '2.6.0', channels: { c: { parameters: { zeta: {}, 'a-b': {}, alpha: {} }, publish: { operationId: 'op1' } } } }, A);
    expect(r.defs[0]!.params).toEqual({ a_b: { type: 'string', max_len: 256 }, alpha: { type: 'string', max_len: 256 }, zeta: { type: 'string', max_len: 256 } });
    expect(Object.keys(r.defs[0]!.params)).toEqual(['a_b', 'alpha', 'zeta']);
  });

  it('2.x: channels are visited in sorted order; operationId, summary and description shape the def', () => {
    const r = importAsyncApi({
      asyncapi: '2.6.0',
      channels: {
        z: { publish: { operationId: 'zed', message: {} } },
        a: { publish: { operationId: 'aye', message: {} } },
      },
    }, A);
    expect(r.defs.map((d) => d.verb)).toEqual(['ev.aye', 'ev.zed']);

    const n = importAsyncApi({
      asyncapi: '2.6.0',
      channels: {
        'user/events': {
          publish: { operationId: 'announceIt', summary: 'Say it', description: '  Long   text ', message: { payload: obj('a') } },
          subscribe: { message: { payload: obj('a') } },
        },
      },
    }, A);
    const [named, unnamed] = n.defs;
    expect(named!.verb).toBe('ev.announce_it');
    expect(named!.title).toBe('Say it');
    expect(named!.description).toBe('Long text');
    expect(named!.aliases).toEqual(['announce_it']);
    expect(named!.effects).toEqual(['send']);
    expect(named!.bindings).toEqual({ asyncapi: { channel: 'user/events', op: 'send' } });
    expect(unnamed!.verb).toBe('ev.user.events.receive');
    expect(unnamed!.title).toBe('Receive user events');
    expect(unnamed!.description).toBeUndefined();
    expect(unnamed!.aliases).toBeUndefined();
    expect(unnamed!.effects).toEqual(['read']);
    expect(unnamed!.bindings).toEqual({ asyncapi: { channel: 'user/events', op: 'receive' } });
  });

  it('an empty or non-string operationId is treated as absent', () => {
    const r = importAsyncApi({
      asyncapi: '2.6.0',
      channels: { t: { publish: { operationId: '', message: { payload: obj('a') } }, subscribe: { operationId: 5, message: { payload: obj('a') } } } },
    }, A);
    expect(r.defs.map((d) => d.verb)).toEqual(['ev.t.send', 'ev.t.receive']);
  });

  it('3.x: skipped operations, channel naming, and message selection', () => {
    const ch = { $ref: '#/channels/userEvents' };
    const r = importAsyncApi({
      asyncapi: '3.0.0',
      channels: { userEvents: { messages: { b: { payload: obj('yy') }, a: { payload: obj('xx') } } } },
      operations: {
        bad: { action: 'x', channel: ch },
        one: { action: 'receive', channel: ch },
        two: { action: 'send', channel: ch, messages: [] },
        three: { action: 'send', channel: ch, messages: [{ payload: obj('fromOp') }] },
        four: { action: 'send', channel: { messages: { m: { payload: obj('inline') } } } },
      },
    }, A);
    expect(r.todo).toEqual([
      { where: 'bad', code: 'skipped_op', message: 'an operation without action send|receive is skipped' },
      { where: 'receive userEvents', code: 'message_variants', message: '2 message variants: only the first is declared' },
      { where: 'send userEvents', code: 'message_variants', message: '2 message variants: only the first is declared' },
    ]);
    expect(r.defs.map((d) => d.verb)).toEqual(['ev.four', 'ev.one', 'ev.three', 'ev.two']);
    const by = (v: string) => r.defs.find((d) => d.verb === v)!;
    expect(Object.keys(by('ev.four').params)).toEqual(['inline']);
    expect(by('ev.four').bindings).toEqual({ asyncapi: { channel: 'four', op: 'send' } });
    expect(Object.keys(by('ev.one').params)).toEqual(['xx']);
    expect(by('ev.one').bindings).toEqual({ asyncapi: { channel: 'userEvents', op: 'receive' } });
    expect(Object.keys(by('ev.two').params)).toEqual(['xx']);
    expect(Object.keys(by('ev.three').params)).toEqual(['fromOp']);
  });
});

describe('JSON Schema importer details', () => {
  const O = { ns: 'fn', verb: 'fn.search.run' };
  it('refuses a bad verb with the exact error', () => {
    const msg = "verb must be a valid verb in namespace 'fn'";
    for (const verb of ['other.x.y', 'fnx.a.b', 'fn.X', 'fn.', 5, new String('fn.a.b')]) {
      const e = thrown(() => importJsonSchema({}, { ns: 'fn', verb: verb as never }));
      expect(e).toBeInstanceOf(ActionKitError);
      expect(e.code).toBe('bad_verb');
      expect(e.message).toBe(msg);
    }
  });
  it('refuses bad effects with the exact error', () => {
    for (const effects of [[], ['read', 'fly'], 'read']) {
      const e = thrown(() => importJsonSchema({}, { ...O, effects: effects as never }));
      expect(e).toBeInstanceOf(ActionKitError);
      expect(e.code).toBe('bad_effects');
      expect(e.message).toBe('effects must be 1+ known effects');
    }
  });
  it('refuses a schema that is not an object with the exact error', () => {
    for (const s of [[], 'a string']) {
      const e = thrown(() => importJsonSchema(s, O));
      expect(e.code).toBe('bad_source');
      expect(e.message).toBe('a JSON Schema must be an object');
    }
  });
  it('notes a non-object schema; an object schema without properties is not noted', () => {
    expect(importJsonSchema({ type: 'string' }, O).todo).toContainEqual({ where: 'fn.search.run', code: 'not_object', message: 'the schema is not an object schema: the def has no parameters' });
    expect(importJsonSchema({ type: 'object' }, O).todo.map((t) => t.code)).not.toContain('not_object');
    expect(Object.keys(importJsonSchema({ properties: { a: { type: 'string' } } }, O).defs[0]!.params)).toEqual(['a']);
  });
  it('derives the def name from the verb (alias and fallback title)', () => {
    const d = importJsonSchema({ type: 'object', properties: { a: { type: 'string' } } }, O).defs[0]!;
    expect(d.aliases).toEqual(['search_run']);
    expect(d.title).toBe('Search run');
  });
});

describe('MCP importer details', () => {
  const one = (t: Record<string, unknown>) => importMcp([{ name: 't1', ...t }], { ns: 'm' }).defs[0]!;
  it('refuses a source that is not a tool list, with the exact error', () => {
    const e = thrown(() => importMcp({}, { ns: 'm' }));
    expect(e.code).toBe('bad_source');
    expect(e.message).toBe('an MCP source is a tool array or a tools/list result {tools: [...]}');
  });
  it('skips entries without a usable name (0 and 257 characters are unusable, 256 is fine)', () => {
    const r = importMcp([5, null, { name: '' }, { name: 'x'.repeat(257) }, { name: 7 }, { name: 'x'.repeat(256) }], { ns: 'm' });
    const skipped = { where: '(tool)', code: 'skipped_op', message: 'an entry without a usable name is skipped' };
    expect(r.todo).toEqual([skipped, skipped, skipped, skipped, skipped]);
    expect(r.defs).toHaveLength(1);
    expect((r.defs[0]!.bindings as { mcp: { tool: string } }).mcp.tool).toHaveLength(256);
  });
  it('keeps the first of a duplicated tool name', () => {
    const r = importMcp([{ name: 't1', description: 'first' }, { name: 't1', description: 'second' }], { ns: 'm' });
    expect(r.todo).toEqual([{ where: 't1', code: 'duplicate_tool', message: 'a tool name listed twice; the first is kept' }]);
    expect(r.defs.map((d) => d.description)).toEqual(['first']);
  });
  it('locates schema problems under the tool name', () => {
    const r = importMcp([{ name: 't1', inputSchema: { $ref: '#/nope' } }], { ns: 'm' });
    expect(r.todo).toEqual([{ where: 't1: inputSchema', code: 'unresolved_ref', message: "reference '#/nope' is not a local reference that resolves (declared string; refine or drop)" }]);
  });
  it('annotations: effects, idempotency and network egress', () => {
    const rows: [Record<string, unknown> | undefined, string[], unknown, unknown][] = [
      [undefined, ['update'], undefined, undefined],
      [{}, ['update'], undefined, undefined],
      [{ readOnlyHint: true }, ['read'], undefined, undefined],
      [{ readOnlyHint: false }, ['update'], undefined, undefined],
      [{ readOnlyHint: true, destructiveHint: true }, ['delete', 'update'], undefined, undefined],
      [{ readOnlyHint: true, destructiveHint: false }, ['read'], undefined, undefined],
      [{ destructiveHint: true }, ['delete', 'update'], undefined, undefined],
      [{ destructiveHint: false }, ['update'], undefined, undefined],
      [{ idempotentHint: true }, ['update'], { mode: 'natural' }, undefined],
      [{ idempotentHint: false }, ['update'], undefined, undefined],
      [{ openWorldHint: true }, ['update'], undefined, ['pca.network_egress']],
      [{ openWorldHint: false }, ['update'], undefined, undefined],
    ];
    const r = importMcp(rows.map(([annotations], i) => ({ name: `t${i}`, ...(annotations ? { annotations } : {}) })), { ns: 'm' });
    expect(r.defs.map((d) => ({ effects: d.effects, idem: d.idempotency, traits: d.traits }))).toEqual(rows.map(([, effects, idem, traits]) => ({ effects, idem, traits })));
  });
  it('title: a non-empty annotation title wins, else the tool title, else a humanised name', () => {
    expect(one({ title: 'Plain', annotations: { title: 'Ann' } }).title).toBe('Ann');
    expect(one({ title: 'Plain', annotations: { title: '' } }).title).toBe('Plain');
    expect(one({ title: 'Plain' }).title).toBe('Plain');
    expect(one({}).title).toBe('T1');
  });
  it('binds the tool name', () => {
    expect(one({}).bindings).toEqual({ mcp: { tool: 't1' } });
  });
});

describe('CLI registry details', () => {
  it('renders todos as "<where>: <message>"', () => {
    expect(IMPORTERS['mcp']!({ tools: [{ name: '' }] }, { ns: 'x' }).todo).toEqual(['(tool): an entry without a usable name is skipped']);
  });
  it('defsToYaml re-attaches a rules block only to the action it belongs to', () => {
    const defs = importMcp([{ name: 't1' }, { name: 't2' }], { ns: 'x' }).defs;
    const y = parse(defsToYaml('x', defs, { 'x.t1': { max: 3 } })) as { ns: string; actions: { verb: string; rules?: unknown }[] };
    expect(y.ns).toBe('x');
    expect(y.actions.map((a) => a.verb)).toEqual(['x.t1', 'x.t2']);
    expect(y.actions[0]!.rules).toEqual({ max: 3 });
    expect(y.actions[1]!.rules).toBeUndefined();
  });
});
