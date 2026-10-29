import { describe, expect, it } from 'vitest';
import { explainRefusal } from './refusal-help';

describe('explainRefusal', () => {
  it('maps a reason by its leading check and links a doc', () => {
    const h = explainRefusal('audience: signed aud ins_a is not ins_b');
    expect(h.check).toBe('audience');
    expect(h.docs).toMatch(/^https:\/\//);
  });
  it('maps the missing-component refusal to the quickstart', () => {
    expect(explainRefusal('authorize: missing required component(s): budgetStore (fail closed)').fix).toMatch(/protect\(\)/);
  });
  it('never throws on junk', () => {
    expect(explainRefusal(undefined).check).toBe('unknown');
    expect(explainRefusal(42).docs).toMatch(/refusals/);
  });
});
