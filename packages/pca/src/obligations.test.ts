import { describe, expect, it } from 'vitest';
import { collectObligations, mergeObligations, obligationError, obligationKey, obligationOutcome, pepObligationGate, MAX_OBLIGATIONS } from './obligations';
import { buildDiscoveryDocument, parseDiscoveryDocument } from './discovery';

describe('obligations (exact outcomes beyond the shared vectors)', () => {
  it('obligationError names the problem', () => {
    expect(obligationError({ kind: 'notify' })).toBe('notify.to is required (a non-empty string of at most 256 characters)');
    expect(obligationError({ kind: 'shred' })).toBe("unknown obligation kind 'shred'");
    expect(obligationError({ kind: 'log', due: 1.5 })).toBe('due must be a non-negative safe integer');
    expect(obligationError(null)).toBe('an obligation must be an object');
  });
  it('the key is order independent and includes due', () => {
    expect(obligationKey({ kind: 'redact', params: { fields: ['a'] } })).toBe('{"kind":"redact","params":{"fields":["a"]}}');
    expect(obligationKey({ kind: 'log', due: 5 })).toBe('{"due":5,"kind":"log","params":{}}');
  });
  it('an allow with an unsupported obligation carries the reason', () => {
    const r = pepObligationGate('allow', false, [{ kind: 'watermark', params: { id: 'x' } }], ['log']);
    expect(r).toEqual({ decision: 'deny', perform: [], unsupported: ['watermark'], reason: 'the enforcement point does not support obligation(s) watermark' });
  });
  it('the supported set may list kinds the vocabulary does not know (a PEP from the future): they never help an unknown obligation', () => {
    expect(pepObligationGate('allow', false, [{ kind: 'log' }], ['log', 'shred']).decision).toBe('allow');
    expect(pepObligationGate('allow', false, [{ kind: 'shred' }], ['log', 'shred']).decision).toBe('deny');
  });
  it('collectObligations: true and unknown add duties, false does not', () => {
    const rules = [
      { id: 'big', when: { field: 'action.params.amount', op: 'gt', value: 100 }, obligations: [{ kind: 'notify', params: { to: 'finance' } }] },
      { id: 'pii', when: { field: 'env.contains_pii', op: 'eq', value: true }, obligations: [{ kind: 'redact', params: { fields: ['ssn'] } }] },
    ];
    const none = collectObligations(rules, { action: { params: { amount: 5 } }, env: { contains_pii: false } });
    expect(none).toEqual({ ok: true, obligations: [] });
    const some = collectObligations(rules, { action: { params: { amount: 500 } }, env: {} });
    expect(some.ok && some.obligations.map((o) => o.kind)).toEqual(['notify', 'redact']);
    expect(collectObligations([{ id: 'x', when: {}, obligations: [] }], {}).ok).toBe(false);
    expect(collectObligations([rules[0], rules[0]], {}).ok).toBe(false);
    expect(collectObligations('x', {}).ok).toBe(false);
  });
  it('merge refuses more than the limit', () => {
    const many = Array.from({ length: MAX_OBLIGATIONS }, (_, i) => ({ kind: 'log', params: { sink: `s${i}` } }));
    expect(mergeObligations(many, [{ kind: 'notify', params: { to: 'x' } }]).ok).toBe(false);
  });
  it('an overdue obligation escalates and never allows', () => {
    const list = [{ kind: 'require_receipt', due: 100 }, { kind: 'log' }];
    expect(obligationOutcome(list, [], 99)).toEqual({ outcome: 'ok', overdue: [] });
    expect(obligationOutcome(list, [], 100)).toEqual({ outcome: 'escalate', overdue: [0], status: 'obligation_unmet' });
    expect(obligationOutcome(list, [0], 100)).toEqual({ outcome: 'ok', overdue: [] });
    expect(obligationOutcome(undefined, [], 100)).toEqual({ outcome: 'ok', overdue: [] });
  });
  it('discovery carries obligations_supported', () => {
    const d = buildDiscoveryDocument({ audience: 'rs', obligationsSupported: ['log'] });
    expect(parseDiscoveryDocument(JSON.parse(JSON.stringify(d))).obligations_supported).toEqual(['log']);
    expect(() => parseDiscoveryDocument({ ...d, obligations_supported: 'log' })).toThrow('obligations_supported must be a string[]');
    expect(buildDiscoveryDocument({ audience: 'rs' }).obligations_supported).toBeUndefined();
  });
});
