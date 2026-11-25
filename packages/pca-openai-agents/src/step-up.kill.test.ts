/** pca-openai-agents: what the step-up helpers hand to the core review, with the review controlled. */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { agent, generateKeyPair } from '@atlasauth/pca';
import { pcaNeedsApproval, reviewToolCall, withApproval, type AgentTool } from './index';

const st = vi.hoisted(() => ({ calls: [] as unknown[][], review: { kind: 'auto' } as unknown }));
vi.mock('@atlasauth/pca', async (orig) => {
  const actual = await orig<typeof import('@atlasauth/pca')>();
  return { ...actual, reviewAction: (...a: unknown[]) => (st.calls.push(a), st.review) };
});

const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_su' });
const stepUp = { kind: 'step_up', request: { id: 'r1' } };

describe('reviewToolCall', () => {
  beforeEach(() => { st.calls.length = 0; st.review = { kind: 'auto' }; });
  it('an unmapped tool is auto and the review is not consulted', () => {
    expect(reviewToolCall(a, 't', { x: 1 }, { intent: () => null })).toStrictEqual({ tool: 't', review: { kind: 'auto' } });
    expect(st.calls).toEqual([]);
  });
  it('passes the mapped action and only the options that were given', () => {
    reviewToolCall(a, 't', { x: 1 }, { intent: () => ({ verb: 'v', resource: 'r', params: { p: 1 } }) });
    expect(st.calls[0]!.slice(1)).toStrictEqual(['v', 'r', { p: 1 }, {}]);
    st.calls.length = 0;
    reviewToolCall(a, 't', { x: 1 }, { intent: () => ({ verb: 'v', resource: 'r' }) });
    expect(st.calls[0]!.slice(1)).toStrictEqual(['v', 'r', { x: 1 }, {}]);
  });
  it('forwards now, goal, standing, renderer and insecureUnboundApproval', () => {
    const renderer = (() => 'r') as never;
    const standing = [{ cls: 'c' }] as never;
    reviewToolCall(a, 't', undefined, { intent: () => ({ verb: 'v', resource: 'r' }), now: 5, goal: 'g', standing, renderer, insecureUnboundApproval: false });
    expect(st.calls[0]![4]).toStrictEqual({ now: 5, goal: 'g', standing, renderer, insecureUnboundApproval: false });
  });
});

describe('pcaNeedsApproval and withApproval', () => {
  beforeEach(() => { st.calls.length = 0; });
  const intent = vi.fn(() => ({ verb: 'v', resource: 'r' }));
  it('deny routes to approval by default and only with denyNeedsApproval not false', () => {
    st.review = { kind: 'deny' };
    expect(pcaNeedsApproval(a, { intent })({}, {})).toBe(true);
    expect(pcaNeedsApproval(a, { intent, denyNeedsApproval: false })({}, {})).toBe(false);
    expect(pcaNeedsApproval(a, { intent, denyNeedsApproval: true })({}, {})).toBe(true);
  });
  it('auto does not interrupt; a step-up interrupts once unless approved', () => {
    st.review = { kind: 'auto' };
    expect(pcaNeedsApproval(a, { intent })({}, {})).toBe(false);
    st.review = stepUp;
    const seen: unknown[] = [];
    expect(pcaNeedsApproval(a, { intent, toolName: 'T', onStepUp: (p) => seen.push(p) })({}, {})).toBe(true);
    expect(seen).toEqual([{ tool: 'T', request: stepUp.request }]);
    expect(pcaNeedsApproval(a, { intent, approved: () => true })({}, {})).toBe(false);
    expect(pcaNeedsApproval(a, { intent, approved: () => false })({}, {})).toBe(true);
  });
  it('the tool name seeds the intent lookup, defaulting to (tool)', () => {
    st.review = { kind: 'auto' };
    const names: string[] = [];
    const spy = (t: string) => (names.push(t), null);
    pcaNeedsApproval(a, { intent: spy })({}, {});
    pcaNeedsApproval(a, { intent: spy, toolName: 'named' })({}, {});
    const plain: AgentTool = { execute: async () => 1 };
    withApproval(plain, a, { intent: spy }).needsApproval;
    (withApproval(plain, a, { intent: spy }).needsApproval as (c: object, i: object) => boolean)({}, {});
    (withApproval({ ...plain, name: 'tn' }, a, { intent: spy }).needsApproval as (c: object, i: object) => boolean)({}, {});
    (withApproval({ ...plain, name: 'tn' }, a, { intent: spy, toolName: 'over' }).needsApproval as (c: object, i: object) => boolean)({}, {});
    expect(names).toEqual(['(tool)', 'named', '(tool)', 'tn', 'over']);
  });
});
