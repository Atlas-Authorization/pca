import { describe, expect, it } from 'vitest';
import type { TrustedChannel } from './channel';
import { clarifyHandler, questionHandler } from './index';

const ACTION = { verb: 'pay', resource: 'invoice', params: { amount: 5 }, reversibility_class: 'irreversible' };

function stub(receive: (ir: unknown, ctx: unknown) => unknown, clarify: (b: unknown) => unknown = () => ({})) {
  const calls: unknown[] = [];
  const ch = {
    receive: (ir: unknown, ctx: unknown) => {
      calls.push([ir, ctx]);
      return receive(ir, ctx);
    },
    clarify,
  } as unknown as TrustedChannel;
  return { ch, calls };
}

describe('question handler wire behaviour', () => {
  it('404 unknown_session with the exact body', () => {
    expect(questionHandler(() => undefined)('s', {})).toEqual({ status: 404, body: { error: 'unknown_session' } });
  });

  it('a non-object body is bad_request without a detail', () => {
    const { ch } = stub(() => ({ ok: true, questionId: 'q', friction: 'tap' }));
    const h = questionHandler(() => ch);
    expect(h('s', null)).toEqual({ status: 400, body: { error: 'bad_request' } });
    expect(h('s', 'str')).toEqual({ status: 400, body: { error: 'bad_request' } });
  });

  it('an unknown member names itself', () => {
    const { ch, calls } = stub(() => ({ ok: true, questionId: 'q', friction: 'tap' }));
    expect(questionHandler(() => ch)('s', { intent_required: {}, action: ACTION, foo: 1 })).toEqual({
      status: 400,
      body: { error: 'bad_request', detail: 'unknown member "foo"' },
    });
    expect(calls).toHaveLength(0);
  });

  it('refuses a malformed action or a non-object intent_required, never reaching the channel', () => {
    const { ch, calls } = stub(() => ({ ok: true, questionId: 'q', friction: 'tap' }));
    const h = questionHandler(() => ch);
    const bad: unknown[] = [
      null,
      'x',
      { ...ACTION, verb: 1 },
      { ...ACTION, resource: 1 },
      { ...ACTION, reversibility_class: 1 },
      { ...ACTION, params: null },
      { ...ACTION, params: [] },
      { verb: 'pay', resource: 'invoice', reversibility_class: 'irreversible' },
      { ...ACTION, extra: true },
    ];
    for (const action of bad) expect(h('s', { intent_required: {}, action })).toEqual({ status: 400, body: { error: 'bad_request' } });
    // a valid action but intent_required missing / not an object
    expect(h('s', { action: ACTION })).toEqual({ status: 400, body: { error: 'bad_request' } });
    expect(h('s', { intent_required: 'x', action: ACTION })).toEqual({ status: 400, body: { error: 'bad_request' } });
    expect(h('s', { intent_required: [], action: ACTION })).toEqual({ status: 400, body: { error: 'bad_request' } });
    // an invalid action with a valid intent_required
    expect(h('s', { intent_required: { a: 1 }, action: null })).toEqual({ status: 400, body: { error: 'bad_request' } });
    expect(calls).toHaveLength(0);
  });

  it('passes exactly the four action members to the channel and answers 202', () => {
    const { ch, calls } = stub(() => ({ ok: true, questionId: 'q_1', friction: 'hold' }));
    const ir = { a: 1 };
    expect(questionHandler(() => ch)('s', { intent_required: ir, action: ACTION })).toEqual({ status: 202, body: { question_id: 'q_1', friction: 'hold' } });
    expect(calls).toEqual([[ir, { action: ACTION }]]);
  });

  it('maps refusal codes to their status; an unlisted code is 400', () => {
    const table: Record<string, number> = {
      bad_site_signature: 401, wrong_session: 409, stale_map: 409, action_mismatch: 422, cell_mismatch: 422, not_uncertain: 409,
      already_asked: 409, frozen: 429, cap_session: 429, cap_hour: 429, cell_too_large: 422, bad_request: 400, render_failed: 422, something_new: 400,
    };
    for (const [code, status] of Object.entries(table)) {
      const { ch } = stub(() => ({ ok: false, code }));
      expect(questionHandler(() => ch)('s', { intent_required: {}, action: ACTION })).toEqual({ status, body: { error: code } });
    }
  });
});

describe('clarify handler wire behaviour', () => {
  it('404 unknown_session with the exact body', () => {
    expect(clarifyHandler(() => undefined)('s', {})).toEqual({ status: 404, body: { error: 'unknown_session' } });
  });

  it('a channel error is a 400 with its detail', () => {
    const { ch } = stub(() => ({}), () => ({ status: 200, verdicts: [], error: 'why' }));
    expect(clarifyHandler(() => ch)('s', {})).toEqual({ status: 400, body: { error: 'bad_request', detail: 'why' } });
  });

  it('emits question_id and refused only when present', () => {
    const run = (r: unknown) => clarifyHandler(() => stub(() => ({}), () => r).ch)('s', {});
    const v = [{ x: 1 }];
    const a = run({ status: 200, verdicts: v });
    expect(a).toEqual({ status: 200, body: { verdicts: v } });
    expect(Object.keys(a.body)).toEqual(['verdicts']);
    const b = run({ status: 202, verdicts: v, questionId: 'q_9' });
    expect(Object.keys(b.body).sort()).toEqual(['question_id', 'verdicts']);
    expect(b.body.question_id).toBe('q_9');
    const c = run({ status: 429, verdicts: v, refused: 'cap_hour' });
    expect(Object.keys(c.body).sort()).toEqual(['refused', 'verdicts']);
    expect(c).toEqual({ status: 429, body: { verdicts: v, refused: 'cap_hour' } });
    const d = run({ status: 200, verdicts: v, questionId: 'q', refused: 'frozen' });
    expect(d.body).toEqual({ verdicts: v, question_id: 'q', refused: 'frozen' });
  });
});
