import { describe, expect, it } from 'vitest';

import {
  canFlow,
  checkAction,
  classifyFlow,
  derive,
  dualContext,
  fromSource,
  fromToolOutput,
  fromTrustedQuery,
  levelOf,
  tag,
  type FlowGovernor,
  type Provenance,
  type Sink,
} from './dataflow';

const twoTools = () => derive([fromToolOutput('b', 1), fromToolOutput('a', 2)], (x, y) => x + y);
const INVALID = 'the sink is not a valid sink (fail closed)';
const gov = (sink: unknown): FlowGovernor => ({ sinkFor: () => sink as Sink });
const ACTION = { verb: 'send', resource: '/r' };

describe('capability sets', () => {
  it('the set prototype add only refuses on a sealed capability set', () => {
    const add = Object.getPrototypeOf(fromSource('s', 1).cap.sources).add as (this: Set<string>, x: string) => Set<string>;
    const plain = new Set<string>();
    expect(add.call(plain, 'x')).toBe(plain);
    expect([...plain]).toEqual(['x']);
  });
  it('a capability set is unsealed while it is being filled', () => {
    const ctor = fromSource('s', 1).cap.sources.constructor;
    const orig = Set.prototype.add;
    const seen: unknown[] = [];
    Set.prototype.add = function (this: Set<unknown>, x: unknown) {
      if (this instanceof ctor) seen.push(Reflect.get(this, 'sealed'));
      return orig.call(this, x);
    };
    try {
      fromSource('t', 2);
    } finally {
      Set.prototype.add = orig;
    }
    expect(seen).toEqual([false]);
  });
});

describe('tag: capability validation', () => {
  it('a non-boolean isTrusted is refused with the shape message', () => {
    expect(() => tag(1, { sources: new Set(['user']), isTrusted: 1 as unknown as boolean })).toThrow('tag: a capability needs a set of sources and a boolean isTrusted');
  });
  it('a trusted capability with a non-string source is accepted (only string tool: sources are refused)', () => {
    const t = tag(1, { sources: new Set([5 as unknown as Provenance, 'user']), isTrusted: true });
    expect(t.cap.isTrusted).toBe(true);
    expect([...t.cap.sources]).toEqual([5, 'user']);
  });
});

describe('boundary constructors carry readers exactly when given', () => {
  it('fromTrustedQuery', () => {
    expect([...(fromTrustedQuery('q', { readers: ['a'] }).cap.readers ?? ['missing'])]).toEqual(['a']);
    expect(fromTrustedQuery('q').cap.readers).toBeUndefined();
    expect('readers' in fromTrustedQuery('q').cap).toBe(false);
  });
  it('fromToolOutput', () => {
    expect([...(fromToolOutput('t', 1, { readers: ['a'] }).cap.readers ?? ['missing'])]).toEqual(['a']);
    expect('readers' in fromToolOutput('t', 1).cap).toBe(false);
  });
  it('fromSource', () => {
    expect([...(fromSource('s', 1, { readers: ['a', 'b'] }).cap.readers ?? ['missing'])]).toEqual(['a', 'b']);
    expect('readers' in fromSource('s', 1).cap).toBe(false);
    expect(fromSource('s', 1).cap.readers).toBeUndefined();
  });
});

describe('classifyFlow: sink validation', () => {
  const v = fromSource('user', 1);
  it('refuses every malformed sink with the exact decision', () => {
    const fn = Object.assign(() => undefined, { id: 'x', accepts: {} });
    for (const s of [null, 'x', fn, { id: 5, accepts: {} }, { id: '', accepts: {} }, { id: 'x', accepts: null }, { id: 'x', accepts: 'x' }]) {
      expect(classifyFlow(v, s as unknown as Sink)).toEqual({ outcome: 'deny', reason: INVALID, path: ['user'] });
    }
  });
  it('a well-formed sink with no policy allows', () => {
    expect(classifyFlow(v, { id: 'x', accepts: {} })).toEqual({ outcome: 'allow' });
  });
});

describe('classifyFlow: exact reasons and sorted paths', () => {
  it('readers deny lists the readers sorted, or the empty-set marker', () => {
    expect(classifyFlow(fromSource('user', 1, { readers: ['b', 'a'] }), { id: 'c', accepts: {} })).toEqual({
      outcome: 'deny',
      reason: "value's readers capability [a, b] does not include sink 'c'",
      path: ['user'],
    });
    expect(classifyFlow(fromSource('user', 1, { readers: [] }), { id: 'c', accepts: {} })).toEqual({
      outcome: 'deny',
      reason: "value's readers capability [∅] does not include sink 'c'",
      path: ['user'],
    });
  });
  it('denied sources: exact reason; a null list denies nothing', () => {
    expect(classifyFlow(twoTools(), { id: 's', accepts: { deniedSources: new Set(['tool:a', 'tool:b']) } })).toEqual({
      outcome: 'deny',
      reason: "provenance [tool:a, tool:b] is forbidden at sink 's'",
      path: ['tool:a', 'tool:b'],
    });
    expect(classifyFlow(twoTools(), { id: 's', accepts: { deniedSources: null as unknown as Set<string> } })).toEqual({ outcome: 'allow' });
  });
  it('allow-list: exact reason; a null list admits nothing', () => {
    const expected = { outcome: 'deny', reason: "provenance [tool:a, tool:b] is not in the allow-list of sink 's'", path: ['tool:a', 'tool:b'] };
    expect(classifyFlow(twoTools(), { id: 's', accepts: { allowedSources: new Set(['user']) } })).toEqual(expected);
    expect(classifyFlow(twoTools(), { id: 's', accepts: { allowedSources: null as unknown as Set<string> } })).toEqual(expected);
  });
  it('external sink: exact reason and sorted path', () => {
    expect(classifyFlow(twoTools(), { id: 'mail', accepts: { external: true } })).toEqual({
      outcome: 'deny',
      reason: "untrusted value (provenance [tool:a, tool:b]) may not flow to external-send sink 'mail' — exfiltration / prompt-injection path",
      path: ['tool:a', 'tool:b'],
    });
  });
  it('requireTrusted: exact step_up; absent requireTrusted allows an untrusted value', () => {
    expect(classifyFlow(twoTools(), { id: 'db', accepts: { requireTrusted: true } })).toEqual({
      outcome: 'step_up',
      reason: "sink 'db' requires trusted provenance; value provenance [tool:a, tool:b] is untrusted — needs human review",
      path: ['tool:a', 'tool:b'],
    });
    expect(classifyFlow(twoTools(), { id: 'db', accepts: {} })).toEqual({ outcome: 'allow' });
  });
});

describe('canFlow', () => {
  it('an allow has no reason key; a deny carries the reason', () => {
    const ok = canFlow(fromSource('user', 1), { id: 'x', accepts: {} });
    expect(ok).toStrictEqual({ ok: true });
    expect(Object.keys(ok)).toEqual(['ok']);
    expect(canFlow(fromSource('user', 1), { id: '', accepts: {} })).toStrictEqual({ ok: false, reason: INVALID });
  });
});

describe('checkAction', () => {
  it('an empty sink id is unresolved', () => {
    expect(checkAction(ACTION, [], gov({ id: '', accepts: {} }))).toStrictEqual({
      outcome: 'deny',
      sink: '(unresolved)',
      reason: 'the sink for this action is not a valid sink (fail closed)',
    });
  });
  it('an explicit undefined element is skipped, a hole is refused', () => {
    expect(checkAction(ACTION, [undefined as never], gov({ id: 'x', accepts: {} }))).toStrictEqual({ outcome: 'allow', sink: 'x' });
    const holes = new Array<never>(1);
    expect(checkAction(ACTION, holes, gov({ id: 'x', accepts: {} }))).toStrictEqual({ outcome: 'deny', sink: 'x', arg: 0, reason: 'an argument was not tagged (fail closed)' });
  });
  it('the worst decision carries exactly outcome, sink, arg, reason and path', () => {
    const r = checkAction(ACTION, [fromTrustedQuery('q'), twoTools()], gov({ id: 'mail', accepts: { external: true } }));
    expect(Object.keys(r)).toEqual(['outcome', 'sink', 'arg', 'reason', 'path']);
    expect(r.path).toEqual(['tool:a', 'tool:b']);
  });
});

describe('dualContext refusals', () => {
  it('a missing context is the typed refusal, not a property-access crash', () => {
    expect(() => dualContext(undefined as never)).toThrow('dualContext: the query must be a tagged value made by this module');
  });
  it('an untrusted query names its sorted provenance', () => {
    expect(() => dualContext({ query: twoTools(), plan: () => 1, quarantine: () => fromSource('x', 1) })).toThrow(
      'dualContext: the privileged planner may only run on a TRUSTED query; got provenance [tool:a, tool:b]',
    );
  });
});

describe('levelOf', () => {
  it('untagged values are agent', () => {
    expect(levelOf(5)).toBe('agent');
    expect(levelOf(null)).toBe('agent');
    expect(levelOf({ value: 1, cap: { sources: new Set(['trusted-query']), isTrusted: true } })).toBe('agent');
  });
  it('trusted capability is trusted', () => {
    expect(levelOf(fromTrustedQuery('q'))).toBe('trusted');
  });
  it('only tool sources is tool', () => {
    expect(levelOf(fromToolOutput('a', 1))).toBe('tool');
    expect(levelOf(twoTools())).toBe('tool');
  });
  it('any non-tool source, an empty source set, or a non-string source is agent', () => {
    expect(levelOf(fromSource('user', 1))).toBe('agent');
    expect(levelOf(fromSource('x-tool:', 1))).toBe('agent');
    expect(levelOf(derive([fromToolOutput('a', 1), fromSource('user', 2)], (x, y) => x + y))).toBe('agent');
    expect(levelOf(derive([fromSource('user', 2), fromToolOutput('a', 1)], (x, y) => x + y))).toBe('agent');
    expect(levelOf(tag(1, { sources: new Set<Provenance>(), isTrusted: false }))).toBe('agent');
    expect(levelOf(tag(1, { sources: new Set([5 as unknown as Provenance]), isTrusted: false }))).toBe('agent');
  });
});
