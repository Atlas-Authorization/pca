import { describe, expect, it } from 'vitest';
import { bridgeToolCall, messageSegments, provenanceHeaders, recordInput, recordMessages, recordPrincipal } from './adapters';
import { PROV_HEADER, type ProvenanceBundle, type ProvenanceRecorder } from './arg-provenance';
import type { Agent } from './facade';
import { canonicalizeStrict } from './hash';

const recorder = () => {
  const calls: unknown[][] = [];
  const rec = {
    forAction: () => undefined,
    principal: (t: unknown) => calls.push(['principal', t]),
    tool: (s: unknown, c: unknown) => calls.push(['tool', s, c]),
  } as unknown as ProvenanceRecorder;
  return { rec, calls };
};
const user = (content: unknown) => ({ role: 'user', content });
const P = (content: unknown) => ({ origin: 'principal', source: 'user', content });

describe('provenance header size bound', () => {
  const bundleOf = (k: number) => ({ pad: 'a'.repeat(k) }) as unknown as ProvenanceBundle;
  it('carries a bundle whose encoding is exactly the maximum and drops one a byte group larger', () => {
    const k = 6144 - canonicalizeStrict(bundleOf(0)).length; // 6144 bytes encode to exactly 8192 base64url characters
    expect(Object.keys(provenanceHeaders(bundleOf(k)))).toEqual([PROV_HEADER]);
    expect(provenanceHeaders(bundleOf(k))[PROV_HEADER]!.length).toBe(8192);
    expect(provenanceHeaders(bundleOf(k + 1))).toEqual({});
  });
});

describe('recordPrincipal', () => {
  it('forwards the text to the agent provenance recorder', () => {
    const seen: string[] = [];
    recordPrincipal({ provenance: { principal: (t: string) => seen.push(t) } } as unknown as Pick<Agent, 'provenance'>, 'hi');
    expect(seen).toEqual(['hi']);
  });
  it('does nothing for an agent without provenance', () => {
    expect(() => recordPrincipal({ provenance: undefined }, 'hi')).not.toThrow();
  });
});

describe('messageSegments roles', () => {
  it('non-objects add nothing', () => {
    for (const m of ['str', 5, true, null, undefined]) expect(messageSegments(m), String(m)).toEqual([]);
  });
  it('a turn of no known role is untrusted tool output named "tool"', () => {
    expect(messageSegments({ content: 'x' })).toEqual([{ origin: 'tool', source: 'tool', content: 'x' }]);
    expect(messageSegments({ type: 5, content: 'x' })).toEqual([{ origin: 'tool', source: 'tool', content: 'x' }]);
  });
  it('the role comes from role, else from a string type, else from the getType helpers', () => {
    expect(messageSegments({ type: 'human', content: 'x' })).toEqual([P('x')]);
    expect(messageSegments({ type: 'user', content: 'x' })).toEqual([P('x')]);
    expect(messageSegments({ role: 5, type: 'human', content: 'x' })).toEqual([P('x')]);
    expect(messageSegments({ role: 'USER', content: 'x' })).toEqual([P('x')]);
  });
  it('getType helpers count only when they are functions returning a string', () => {
    expect(messageSegments({ _getType: { call: () => 'human' }, type: 'ai', content: 'x' })).toEqual([]);
    expect(messageSegments({ _getType: () => 5, role: 'user', content: 'x' })).toEqual([P('x')]);
    expect(messageSegments({ _getType: () => { throw new Error('boom'); }, getType: () => 'human', content: 'x' })).toEqual([P('x')]);
    expect(messageSegments({ _getType: () => 'ai', role: 'user', content: 'x' })).toEqual([]);
  });
  it('a user turn without content is an empty principal message', () => {
    expect(messageSegments({ role: 'user' })).toEqual([P('')]);
  });
});

describe('messageSegments parts of a user turn', () => {
  it('plain strings and text parts are joined into one principal message', () => {
    expect(messageSegments(user(['abc', { type: 'text', text: 't2' }]))).toEqual([P('abc\nt2')]);
    expect(messageSegments(user([null]))).toEqual([P('null')]);
    expect(messageSegments(user([5, 'x']))).toEqual([P('5\nx')]);
  });
  it('a part without string text is its own principal segment and adds no text message', () => {
    expect(messageSegments(user([{ type: 'image', text: 5 }]))).toEqual([P({ type: 'image', text: 5 })]);
    expect(messageSegments(user([{ type: 'image', url: 'u' }, { type: 'text', text: 'hi' }]))).toEqual([P('hi'), P({ type: 'image', url: 'u' })]);
  });
  it('tool result parts are untrusted, named by their tool', () => {
    expect(messageSegments(user([{ type: 'function_call_output', output: 'o', name: 'fn' }]))).toEqual([{ origin: 'tool', source: 'fn', content: 'o' }]);
    expect(messageSegments(user([{ type: 'tool_result', content: 'c', toolName: 'T' }]))).toEqual([{ origin: 'tool', source: 'T', content: 'c' }]);
    expect(messageSegments(user([{ type: 'tool-result', result: 'r', toolCallId: 'k' }]))).toEqual([{ origin: 'tool', source: 'k', content: 'r' }]);
  });
});

describe('recordMessages', () => {
  it('ignores a missing target or a non-list', () => {
    expect(() => recordMessages(undefined, [user('hi')])).not.toThrow();
    expect(() => recordMessages(null as never, [user('hi')])).not.toThrow();
    const { rec, calls } = recorder();
    recordMessages(rec, 'abc' as never);
    expect(calls).toEqual([]);
  });
  it('a rejected non-list does not advance the cursor', () => {
    const { rec, calls } = recorder();
    recordMessages(rec, 'abc' as never);
    recordMessages(rec, [user('a'), user('b'), user('c')]);
    expect(calls.map((c) => c[1])).toEqual(['a', 'b', 'c']);
  });
  it('records each message once, resumes at the end of the list, and starts over on a shorter list', () => {
    const { rec, calls } = recorder();
    const list = [user('a'), user('b')];
    recordMessages(rec, list);
    recordMessages(rec, list);
    expect(calls).toHaveLength(2);
    recordMessages(rec, [...list, user('c')]);
    expect(calls.map((c) => c[1])).toEqual(['a', 'b', 'c']);
    recordMessages(rec, [user('z')]);
    expect(calls.map((c) => c[1])).toEqual(['a', 'b', 'c', 'z']);
  });
  it('records string content as is, other content as canonical JSON text, and tool output with its source', () => {
    const { rec, calls } = recorder();
    recordMessages(rec, [user('hi'), user([{ type: 'image', url: 'u' }]), user([{ type: 'x', toJSON: () => undefined }]), { role: 'tool', name: 't1', content: 'out' }]);
    expect(calls).toEqual([
      ['principal', 'hi'],
      ['principal', '{"type":"image","url":"u"}'],
      ['principal', ''],
      ['tool', 't1', 'out'],
    ]);
  });
});

describe('recordInput', () => {
  it('records a string, a message list and {messages}', () => {
    const a = recorder();
    recordInput(a.rec, 'hello');
    recordInput(a.rec, [user('a')]);
    expect(a.calls).toEqual([['principal', 'hello'], ['principal', 'a']]);
    const b = recorder();
    recordInput(b.rec, { messages: [user('m')] });
    expect(b.calls).toEqual([['principal', 'm']]);
  });
  it('reads each named string member in order', () => {
    const { rec, calls } = recorder();
    recordInput(rec, { text: '6', message: '5', question: '4', query: '3', prompt: '2', input: '1' });
    expect(calls).toEqual([['principal', '1'], ['principal', '2'], ['principal', '3'], ['principal', '4'], ['principal', '5'], ['principal', '6']]);
  });
  it('reads a message list under a named member', () => {
    const { rec, calls } = recorder();
    recordInput(rec, { input: [user('x')] });
    expect(calls).toEqual([['principal', 'x']]);
  });
  it('records nothing, and does not throw, for anything else', () => {
    const { rec, calls } = recorder();
    for (const x of [undefined, null, 5, true, {}, { messages: 'no' }, { input: 5 }]) expect(() => recordInput(rec, x), String(x)).not.toThrow();
    expect(calls).toEqual([]);
    expect(() => recordInput(undefined, 'x')).not.toThrow();
    expect(() => recordInput(null as never, 'x')).not.toThrow();
  });
});

describe('bridgeToolCall carries the provenance bundle', () => {
  const bundle = { v: 1, kind: 'pca-provenance', receipts: [] } as unknown as ProvenanceBundle;
  const agentWith = (provenance: ProvenanceBundle | undefined) => ({ act: () => ({ pcactn: {}, encoded: 'e', provenance }) }) as unknown as Agent;
  const map = () => ({ verb: 'v', resource: 'r' });
  it('returns the bundle and its header when the action has one', () => {
    const c = bridgeToolCall(agentWith(bundle), { name: 't', arguments: {} }, map)!;
    expect(c.provenance).toBe(bundle);
    expect(Object.keys(c.headers)).toContain(PROV_HEADER);
  });
  it('has no provenance member when the action has none', () => {
    const c = bridgeToolCall(agentWith(undefined), { name: 't', arguments: {} }, map)!;
    expect('provenance' in c).toBe(false);
    expect(Object.keys(c.headers)).not.toContain(PROV_HEADER);
  });
});
