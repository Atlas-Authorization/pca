import { describe, expect, it } from 'vitest';
import { validatePolicyAgainstSchema, verbShapes, verbShapesFromActionDefs, type ActionDefStructural } from './index';

describe('ActionDef adapter', () => {
  const defs: ActionDefStructural[] = [
    { verb: 'pay.refund', params: { amount: { type: 'integer', role: 'money.amount', min: 0, max: 1000, sensitivity: 'material' }, when: { type: 'datetime' }, kind: { type: 'string', values: ['full', 'part'] } } },
  ];
  it('maps the real member names to verb shapes; types the policy language cannot compare stay untyped', () => {
    expect(verbShapesFromActionDefs(defs)).toEqual([
      { verb: 'pay.refund', params: { amount: { type: 'integer', semantic: 'money.amount', min: 0, max: 1000, sensitivity: 'material' }, when: {}, kind: { type: 'string', values: ['full', 'part'] } } },
    ]);
  });
  it('validation reads them: an undeclared parameter and an unbounded money verb', () => {
    const r = validatePolicyAgainstSchema({ predicates: [{ verb: 'pay.refund', where: [{ field: 'action.params.amout', op: 'lte', value: 5 }] }] }, defs);
    expect(r.findings.map((f) => f.code)).toEqual(['undeclared-param', 'unbounded-money']);
    expect(verbShapes(defs)[0]!.params.amount!.semantic).toBe('money.amount');
  });

  // Checked against the REAL package when it is available: PCA_ACTIONS_SRC=<.../pca-actions/src>. A real ActionDef must be
  // assignable to ActionDefStructural (the call below is type-checked) and every builtin def must adapt without loss of its verb.
  const src = process.env.PCA_ACTIONS_SRC;
  it.skipIf(!src)('every builtin ActionDef adapts', async () => {
    const mod = (await import(/* @vite-ignore */ `${src}/builtin.ts`)) as { BUILTIN_DEFS: readonly ActionDefStructural[] };
    const shapes = verbShapesFromActionDefs(mod.BUILTIN_DEFS);
    expect(shapes.map((s) => s.verb)).toEqual(mod.BUILTIN_DEFS.map((d) => d.verb));
    expect(shapes.length).toBeGreaterThan(5);
  });
});
