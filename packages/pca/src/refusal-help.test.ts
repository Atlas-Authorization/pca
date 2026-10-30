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
  it('explains the 0.5 provenance and undo checks', () => {
    const p = explainRefusal('provenance_flow: escalate: arg to derives from a tool result');
    expect([p.check, p.docs]).toEqual(['provenance_flow', expect.stringMatching(/guides\/prompt-injection-provenance\.md$/)]);
    const u = explainRefusal('undo_window: runs now under a veto window until 1');
    expect([u.check, u.docs]).toEqual(['undo_window', expect.stringMatching(/guides\/undo-windows\.md$/)]);
  });
  it('never throws on junk', () => {
    expect(explainRefusal(undefined).check).toBe('unknown');
    expect(explainRefusal(42).docs).toMatch(/refusals/);
  });
});
