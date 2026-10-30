import { describe, expect, it } from 'vitest';
import {
  type FlowGovernor,
  type Sink,
  type Tagged,
  canFlow,
  checkAction,
  classifyFlow,
  combineCaps,
  derive,
  dualContext,
  externalSendSink,
  fromSource,
  fromToolOutput,
  fromTrustedQuery,
  isTagged,
  sensitiveSink,
  tag,
} from './dataflow';

const SEND = externalSendSink('email.send');
const gov = (sink: Sink): FlowGovernor => ({ sinkFor: () => sink });
const forged = (trusted: boolean): Tagged<string> => ({ value: 'x', cap: { sources: new Set(['trusted-query']), isTrusted: trusted } }) as never;

describe('a tag only means something if this module made it', () => {
  it('a hand-built look-alike (or one revived from JSON) is not tagged and flows nowhere', () => {
    for (const v of [forged(true), JSON.parse('{"value":"x","cap":{"sources":["trusted-query"],"isTrusted":true}}'), 'raw string', null, undefined, 5, {}]) {
      expect(isTagged(v)).toBe(false);
      expect(classifyFlow(v as never, SEND)).toEqual({ outcome: 'deny', reason: 'value carries no provenance tag made by this module (fail closed)', path: [] });
      expect(canFlow(v as never, sensitiveSink('db.write')).ok).toBe(false);
    }
  });
  it('values made by the constructors and derive are tagged', () => {
    const a = fromTrustedQuery('a');
    const b = fromToolOutput('web', 'b');
    for (const v of [a, b, fromSource('user', 'c'), tag('d', { sources: new Set(['user']), isTrusted: true }), derive([a, b] as const, (x: string, y: string) => `${x}${y}`)]) expect(isTagged(v)).toBe(true);
  });
  it('derive refuses an input that is not tagged', () => {
    expect(() => derive([forged(true), fromTrustedQuery('b')] as never, (a: unknown, b: unknown) => `${a}${b}`)).toThrow('derive: every input must be a tagged value made by this module');
    expect(() => derive('x' as never, () => 1)).toThrow('derive: every input must be a tagged value made by this module');
  });
  it('checkAction denies an untagged argument instead of throwing', () => {
    const r = checkAction({ verb: 'send', resource: 'r' }, [fromTrustedQuery('ok'), 'raw' as never], gov(SEND));
    expect(r).toEqual({ outcome: 'deny', sink: 'email.send', arg: 1, reason: 'value carries no provenance tag made by this module (fail closed)', path: [] });
  });
});

describe('a capability cannot be widened after the fact', () => {
  it('readers and sources are immutable sets', () => {
    const v = fromToolOutput('web', 'x', { readers: ['db.write'] });
    expect(() => (v.cap.readers as Set<string>).add('email.send')).toThrow('capability sets are immutable');
    expect(() => (v.cap.readers as Set<string>).delete('db.write')).toThrow('capability sets are immutable');
    expect(() => (v.cap.readers as Set<string>).clear()).toThrow('capability sets are immutable');
    expect(() => (v.cap.sources as Set<string>).add('trusted-query')).toThrow('capability sets are immutable');
    expect([...v.cap.readers!]).toEqual(['db.write']);
    expect(canFlow(v, externalSendSink('email.send')).ok).toBe(false);
  });
  it('the set passed in is copied: changing it later changes nothing', () => {
    const readers = new Set(['a']);
    const v = fromTrustedQuery('x', { readers });
    readers.add('b');
    expect([...v.cap.readers!]).toEqual(['a']);
  });
  it('combined capabilities are immutable too', () => {
    const c = combineCaps([fromTrustedQuery('a', { readers: ['x', 'y'] }).cap, fromTrustedQuery('b', { readers: ['y'] }).cap]);
    expect([...c.readers!]).toEqual(['y']);
    expect(() => (c.readers as Set<string>).add('x')).toThrow();
  });
});

describe('trust is earned by a source', () => {
  it('tag refuses a trusted capability with no sources or with a tool source', () => {
    expect(() => tag('x', { sources: new Set(), isTrusted: true })).toThrow('tag: a trusted capability needs at least one source');
    expect(() => tag('x', { sources: new Set(['tool:web']), isTrusted: true })).toThrow('tag: tool output can never be trusted');
    expect(() => tag('x', { sources: new Set(['trusted-query', 'tool:web']), isTrusted: true })).toThrow('tag: tool output can never be trusted');
    expect(() => fromSource('tool:web', 'x', { isTrusted: true })).toThrow('tag: tool output can never be trusted');
  });
  it('tag refuses a malformed capability', () => {
    for (const cap of [null, undefined, {}, { sources: ['a'], isTrusted: true }, { sources: new Set(), isTrusted: 'yes' }, { sources: new Set(['a']), isTrusted: false, readers: ['x'] }]) {
      expect(() => tag('x', cap as never), JSON.stringify(cap)).toThrow('tag: ');
    }
  });
  it('an untrusted capability with no sources is allowed and stays untrusted', () => {
    const v = tag('x', { sources: new Set(), isTrusted: false });
    expect(v.cap.isTrusted).toBe(false);
    expect(combineCaps([]).isTrusted).toBe(false);
  });
  it('fromSource is untrusted unless the caller vouches', () => {
    expect(fromSource('user', 'x').cap.isTrusted).toBe(false);
    expect(fromSource('user', 'x', { isTrusted: true }).cap.isTrusted).toBe(true);
    expect(fromSource('user', 'x', { isTrusted: 'true' as never }).cap.isTrusted).toBe(false);
  });
});

describe('sinks and governors fail closed', () => {
  const act = { verb: 'send', resource: 'r' };
  it('a governor that throws, or returns something that is not a sink, denies', () => {
    expect(checkAction(act, [fromTrustedQuery('a')], { sinkFor: () => { throw new Error('x'); } })).toEqual({ outcome: 'deny', sink: '(unresolved)', reason: 'the sink for this action could not be resolved (fail closed)' });
    for (const bad of [null, undefined, {}, { id: '' }, { id: 5 }, 'sink']) {
      expect(checkAction(act, [fromTrustedQuery('a')], { sinkFor: () => bad as never }).outcome, JSON.stringify(bad)).toBe('deny');
    }
  });
  it('a sink without a policy denies a flow', () => {
    expect(classifyFlow(fromTrustedQuery('a'), { id: 's' } as never)).toEqual({ outcome: 'deny', reason: 'the sink is not a valid sink (fail closed)', path: ['trusted-query'] });
  });
  it('arguments that are not a list deny', () => {
    expect(checkAction(act, 'x' as never, gov(SEND))).toEqual({ outcome: 'deny', sink: 'email.send', reason: 'the tagged arguments are not a list (fail closed)' });
  });
  it('expectedArgs makes a missing tag a refusal', () => {
    expect(checkAction(act, [], gov(SEND), { expectedArgs: 2 })).toEqual({ outcome: 'deny', sink: 'email.send', reason: 'expected 2 tagged argument(s), got 0 (fail closed)' });
    expect(checkAction(act, [fromTrustedQuery('a'), fromTrustedQuery('b')], gov(SEND), { expectedArgs: 2 }).outcome).toBe('allow');
  });
  it('a hole in the argument list is an untagged argument', () => {
    const args = [fromTrustedQuery('a'), , fromTrustedQuery('c')] as unknown as Tagged<unknown>[];
    expect(checkAction(act, args, gov(SEND))).toEqual({ outcome: 'deny', sink: 'email.send', arg: 1, reason: 'an argument was not tagged (fail closed)' });
  });
  it('no arguments to a sink is an allow: nothing flows', () => {
    expect(checkAction(act, [], gov(SEND))).toEqual({ outcome: 'allow', sink: 'email.send' });
  });
  it('the worst outcome wins, with the index and path of the offender', () => {
    const r = checkAction(act, [fromTrustedQuery('a'), fromToolOutput('web', 'b'), fromTrustedQuery('c')], gov(SEND));
    expect([r.outcome, r.arg, r.path]).toEqual(['deny', 1, ['tool:web']]);
    const s = checkAction(act, [fromToolOutput('web', 'b')], gov(sensitiveSink('db.write')));
    expect(s.outcome).toBe('step_up');
  });
  it('an empty readers capability reaches no sink', () => {
    expect(classifyFlow(fromTrustedQuery('x', { readers: [] }), SEND).outcome).toBe('deny');
  });
});

describe('dualContext keeps the planner and the quarantine apart', () => {
  it('the query and the quarantined result must be tagged by this module', () => {
    const ok = fromTrustedQuery('q');
    expect(() => dualContext({ query: forged(true), plan: (q: string) => q, quarantine: () => fromToolOutput('web', 'r') })).toThrow('dualContext: the query must be a tagged value made by this module');
    expect(() => dualContext({ query: null as never, plan: (q: string) => q, quarantine: () => fromToolOutput('web', 'r') })).toThrow('dualContext: the query must be a tagged value');
    expect(() => dualContext({ query: ok, plan: (q: string) => q, quarantine: () => 'raw text' as never })).toThrow('dualContext: the quarantined handler must return a tagged value made by this module');
    expect(() => dualContext({ query: fromToolOutput('web', 'q'), plan: (q: string) => q, quarantine: () => fromToolOutput('web', 'r') })).toThrow('may only run on a TRUSTED query');
  });
  it('the planner sees the trusted value and nothing else', () => {
    let seen: unknown[] = [];
    const out = dualContext({ query: fromTrustedQuery('book a flight'), plan: (...a: unknown[]) => ((seen = a), 'plan'), quarantine: (p) => fromToolOutput('web', `result for ${p}`) });
    expect(seen).toEqual(['book a flight']);
    expect(out.result.cap.isTrusted).toBe(false);
  });
});
