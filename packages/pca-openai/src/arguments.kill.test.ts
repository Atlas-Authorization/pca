import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { type OpenAIToolCall, type PcaCall, dispatchToolCall, dispatchToolCalls, withPCACompletions } from './index';

const mkAgent = () => agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'rs' });
const map = () => ({ verb: 'stripe.refund', resource: 'charge:ch_1' });
const call = (args: string): OpenAIToolCall => ({ id: 'c', type: 'function', function: { name: 'refund', arguments: args } });
const MSG = 'dispatchToolCall: tool_call arguments must be a JSON object';

async function argsSeen(raw: unknown): Promise<unknown> {
  let seen: unknown = 'unset';
  await dispatchToolCall(mkAgent(), call(raw as string), map, { refund: (a) => ((seen = a), { ok: true }) });
  return seen;
}

describe('pca-openai: argument parsing', () => {
  it('a missing arguments value is an empty object', async () => {
    expect(await argsSeen(null)).toEqual({});
    expect(await argsSeen(undefined)).toEqual({});
  });
  it('whitespace-only arguments are an empty object', async () => {
    expect(await argsSeen('  \n\t ')).toEqual({});
  });
  it('surrounding whitespace is ignored around an object', async () => {
    expect(await argsSeen('  {"a":1}\n')).toEqual({ a: 1 });
  });
  it.each(['null', '[1]', '[]', '"s"', '5', 'true'])('refuses non-object JSON %s with the exact message', async (raw) => {
    await expect(argsSeen(raw)).rejects.toThrow(new Error(MSG));
  });
  it('refuses unparseable JSON', async () => {
    await expect(argsSeen('{')).rejects.toThrow();
  });
});

describe('pca-openai: counters and completions', () => {
  it('without a counter option, no counter is forced and options are passed through', async () => {
    const counters: Array<number | undefined> = [];
    const h = { refund: (_a: Record<string, unknown>, pca: PcaCall) => (counters.push(pca.pcactn.counter), { ok: true }) };
    await dispatchToolCall(mkAgent(), call('{}'), map, h);
    await dispatchToolCalls(mkAgent(), [call('{}'), call('{}')], map, h, { aud: 'rs' });
    await dispatchToolCalls(mkAgent(), [call('{}')], map, h);
    expect(counters.every((c) => typeof c === 'number' && Number.isFinite(c))).toBe(true);
  });
  it('with a counter option, each call gets counter + index', async () => {
    const counters: number[] = [];
    const h = { refund: (_a: Record<string, unknown>, pca: PcaCall) => (counters.push(pca.pcactn.counter), { ok: true }) };
    await dispatchToolCalls(mkAgent(), [call('{}'), call('{}'), call('{}')], map, h, { counter: 10 });
    expect(counters).toEqual([10, 11, 12]);
  });
  it('withPCACompletions records only an array of messages and tolerates missing params', async () => {
    const a = mkAgent();
    const create = withPCACompletions(a, (p: { messages?: unknown[] } | undefined) => p);
    expect(create(undefined as never)).toBeUndefined();
    const noMsgs = {};
    expect(create(noMsgs)).toBe(noMsgs);
    expect(create({ messages: 'nope' as never })).toEqual({ messages: 'nope' });
    expect(a.provenance?.receipts() ?? []).toEqual([]);
  });
});
