import { describe, expect, it } from 'vitest';
import { classVerdictsError, decideClasses } from './policy-classes';

describe('policy classes edges', () => {
  it('fails closed with the exact record when evaluating the list throws', () => {
    const hostile = new Proxy([], { get() { throw new Error('boom'); } });
    expect(decideClasses(hostile)).toEqual({ decision: 'deny', classes: [], denied_by: [], escalated_by: [], reason: 'evaluation error (fail closed)' });
  });
  it('reports a null member as a non-object without throwing', () => {
    expect(classVerdictsError([null])).toBe('policy_classes[0] must be an object');
    expect(classVerdictsError(['x'])).toBe('policy_classes[0] must be an object');
    expect(classVerdictsError([[]])).toBe('policy_classes[0] must be an object');
  });
  it('refuses a non-string digest', () => {
    const v = { class: 'org', revision: 1, decision: 'allow' };
    expect(classVerdictsError([{ ...v, digest: ['abc'] }])).toBe('policy_classes[0].digest invalid');
    expect(classVerdictsError([{ ...v, digest: 5 }])).toBe('policy_classes[0].digest invalid');
    expect(classVerdictsError([{ ...v, digest: 'd' }])).toBeNull();
  });
});
