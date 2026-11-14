import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { buildEscalationRequest, verifyEscalationAnswer } from './escalation';
import { decideTighten, decideUnits, decisionOf, foldV2Reasons, meet, pepDecision, tighten, type Decision } from './decision';

// Shared with the Go, Rust and Python verifiers: conformance/decision-vectors.json (rules 20, 21, the ternary decision).
const doc = JSON.parse(readFileSync(new URL('../conformance/decision-vectors.json', import.meta.url), 'utf8')).primitives as Record<string, { name: string; input: any; input_text?: string; expect: any }[]>;
// `input_text` is raw JSON text each runner parses itself (key order is part of the input)
const inputOf = (e: { input: any; input_text?: string }) => (e.input_text !== undefined ? JSON.parse(e.input_text) : e.input);

describe('decision-vectors.json', () => {
  it.each(doc.intent_units!)('units: $name', (e) => {
    const r = decideUnits(inputOf(e));
    expect(r.ok ? { ok: true } : { ok: false, reason: r.reason }).toEqual(e.expect);
  });
  it.each(doc.intent_tighten!)('tighten: $name', (e) => {
    const r = decideTighten(inputOf(e));
    expect({ outcome: r.outcome, legacy: r.legacy, offending: r.offending, ...(r.reason !== undefined ? { reason: r.reason } : {}) }).toEqual(e.expect);
  });
  it.each(doc.decision_of!)('decision_of: $name', (e) => expect(decisionOf(e.input)).toBe(e.expect.decision));
  it.each(doc.escalation_truncate!)('truncate: $name', (e) => {
    const r = buildEscalationRequest({ aud: 'a', grant: { id: 'g' } as never, pcactn: { action: { verb: 'v', resource: 'r' } } as never, lastCounter: undefined, reasons: e.input.reasons, now: 1 });
    expect(JSON.stringify(r.reasons)).toBe(e.expect.wire);
  });
  it.each(doc.escalation_fold!)('fold: $name', (e) => {
    const reasons = foldV2Reasons(e.input.core_reasons, e.input.v2);
    const allow = !Object.values(e.input.checks).includes('fail');
    expect({ reasons, decision: decisionOf({ allow, checks: e.input.checks, reasons }) }).toEqual(e.expect);
  });
  it.each(doc.escalation_answer!)('escalation_answer: $name', (e) => {
    const i = inputOf(e);
    const r = verifyEscalationAnswer(i.answer, i.principals, i.bind, i.now);
    expect(r.ok).toBe(e.expect.ok);
    if (r.ok) expect({ principal: r.principal, decision: r.decision }).toEqual({ principal: e.expect.principal, decision: e.expect.decision });
    else expect(r.reason).toContain(e.expect.reason_contains);
  });
  it.each(doc.decision_lattice!)('lattice: $name', (e) => {
    const i = e.input;
    const got: Decision = e.name.startsWith('meet-') ? meet(i.a, i.b) : e.name.startsWith('pep-') ? pepDecision(i.decision, i.answered) : tighten(i.decision, i.signal);
    expect(got).toBe(e.expect.decision);
  });
});
