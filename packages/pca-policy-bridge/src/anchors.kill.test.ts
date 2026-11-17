/** Statement anchors and unbalanced list brackets: text around a modeled form must not be read as the form itself. */
import { describe, expect, it } from 'vitest';
import { translateCedar } from './cedar';
import { regoToPca } from './rego';

describe('rego glob.match must start the statement', () => {
  const preds = (body: string) => regoToPca(`default allow = false\nallow {\n${body}\n}\n`).predicates;
  it('a statement with text before an otherwise valid call is not translated', () => {
    expect(preds('x glob.match("a", null, input.p)')).toEqual([]);
    expect(preds('glob.match("a", null, input.p)')).toEqual([{ verb: '*', where: [{ field: 'env.p', op: 'like', value: 'a' }] }]);
  });
});

describe('cedar action list in a condition', () => {
  const cedar = (cond: string) => translateCedar(`permit(principal, action, resource) when { ${cond} };`, false);
  it('a list that does not close is not read as a list of verbs', () => {
    const bad = cedar('action in [Action::"a"x');
    expect(bad.predicates).toEqual([]);
    expect(bad.report.skipped.length + bad.report.errors.length).toBeGreaterThan(0);
    expect(cedar('action in [Action::"a"]').predicates.length).toBe(1);
  });
});
