import { mergeObligations, obligationOutcome, obligationsError, pepObligationGate, type Obligation } from '../obligations';

/**
 * Shared vectors for decision obligations (conformance/obligations-vectors.json). Expectations are hand-written and proved
 * against the reference before the file is written. Natives compare: validate -> ok; merge -> ok and the exact list (sorted by
 * the canonical key: strict-canonical JSON of {kind, params ({} when absent), due?}, compared in UTF-8 byte order); gate -> the
 * whole result; outcome -> the whole result. Error text is not compared.
 * Regenerate: OBLIGATIONS_VECTORS_WRITE=1 vitest run src/obligations-vectors.test.ts
 */
const L = (sink?: string, due?: number): Obligation => ({ kind: 'log', ...(sink !== undefined ? { params: { sink } } : {}), ...(due !== undefined ? { due } : {}) });
const N = (to: string, due?: number): Obligation => ({ kind: 'notify', params: { to }, ...(due !== undefined ? { due } : {}) });
const R = (fields: string[]): Obligation => ({ kind: 'redact', params: { fields } });
const W = (id: string): Obligation => ({ kind: 'watermark', params: { id } });
const Q = (due?: number): Obligation => ({ kind: 'require_receipt', ...(due !== undefined ? { due } : {}) });
const ALL = ['log', 'notify', 'redact', 'require_receipt', 'watermark'];
const T = 1_800_000_000_000;

export function buildObligationsVectors() {
  const validate: { name: string; input: unknown; expect: { ok: boolean } }[] = [
    { name: 'absent-is-empty', input: undefined, expect: { ok: true } },
    { name: 'empty-list', input: [], expect: { ok: true } },
    { name: 'every-kind', input: [L('siem'), N('secops'), R(['a.b']), W('wm1'), Q(T)], expect: { ok: true } },
    { name: 'log-without-params', input: [L()], expect: { ok: true } },
    { name: 'not-an-array', input: { kind: 'log' }, expect: { ok: false } },
    { name: 'unknown-kind', input: [{ kind: 'shred' }], expect: { ok: false } },
    { name: 'unknown-member', input: [{ kind: 'log', extra: 1 }], expect: { ok: false } },
    { name: 'unknown-param', input: [{ kind: 'log', params: { sink: 'a', x: 1 } }], expect: { ok: false } },
    { name: 'require-receipt-takes-no-params', input: [{ kind: 'require_receipt', params: { a: 1 } }], expect: { ok: false } },
    { name: 'notify-needs-to', input: [{ kind: 'notify' }], expect: { ok: false } },
    { name: 'watermark-needs-id', input: [{ kind: 'watermark', params: {} }], expect: { ok: false } },
    { name: 'redact-needs-fields', input: [{ kind: 'redact', params: { fields: [] } }], expect: { ok: false } },
    { name: 'redact-field-must-be-a-path', input: [R(['a b'])], expect: { ok: false } },
    { name: 'redact-duplicate-field', input: [R(['a', 'a'])], expect: { ok: false } },
    { name: 'due-must-be-a-safe-integer', input: [L('x', 1.5)], expect: { ok: false } },
    { name: 'negative-due', input: [{ kind: 'log', due: -1 }], expect: { ok: false } },
    { name: 'duplicate-obligation', input: [L('a'), L('a')], expect: { ok: false } },
    { name: 'same-kind-different-params-is-fine', input: [L('a'), L('b')], expect: { ok: true } },
    { name: 'seventeen-is-too-many', input: Array.from({ length: 17 }, (_, i) => L(`s${i}`)), expect: { ok: false } },
    { name: 'sixteen-is-the-limit', input: Array.from({ length: 16 }, (_, i) => L(`s${i}`)), expect: { ok: true } },
    { name: 'prototype-key-is-not-a-kind', input: [{ kind: 'constructor' }], expect: { ok: false } },
  ];
  const mergeOk = (obligations: Obligation[]) => ({ ok: true, obligations });
  const merge: { name: string; inputs: unknown[]; expect: Record<string, unknown> }[] = [
    { name: 'union-dedupes-and-sorts', inputs: [[W('w'), L('a')], [L('a'), N('x')]], expect: mergeOk([L('a'), N('x'), W('w')]) },
    { name: 'order-of-inputs-does-not-matter', inputs: [[L('a'), N('x')], [W('w'), L('a')]], expect: mergeOk([L('a'), N('x'), W('w')]) },
    { name: 'same-kind-sorts-by-params', inputs: [[L('b')], [L('a')], [L()]], expect: mergeOk([L('a'), L('b'), L()]) },
    { name: 'due-makes-a-different-obligation', inputs: [[Q(T)], [Q()]], expect: mergeOk([Q(T), Q()]) },
    { name: 'empty-and-absent-inputs', inputs: [[], undefined, [Q()]], expect: mergeOk([Q()]) },
    { name: 'nothing-to-merge', inputs: [], expect: mergeOk([]) },
    { name: 'a-malformed-input-refuses-the-merge', inputs: [[L('a')], [{ kind: 'shred' }]], expect: { ok: false } },
    { name: 'too-many-after-merging', inputs: [Array.from({ length: 9 }, (_, i) => L(`a${i}`)), Array.from({ length: 9 }, (_, i) => L(`b${i}`))], expect: { ok: false } },
  ];
  const perform = (p: Obligation[]) => ({ decision: 'allow', perform: p, unsupported: [] as string[] });
  const dec = (d: string) => ({ decision: d, perform: [] as Obligation[], unsupported: [] as string[] });
  const gate: { name: string; decision: string; answered: boolean; obligations: unknown; supported: unknown; expect: Record<string, unknown> }[] = [
    { name: 'allow-with-no-obligations', decision: 'allow', answered: false, obligations: undefined, supported: [], expect: perform([]) },
    { name: 'allow-with-supported-obligations', decision: 'allow', answered: false, obligations: [L('s'), Q()], supported: ALL, expect: perform([L('s'), Q()]) },
    { name: 'allow-with-an-unsupported-obligation-is-deny', decision: 'allow', answered: false, obligations: [L('s'), W('w')], supported: ['log'], expect: { decision: 'deny', perform: [], unsupported: ['watermark'] } },
    { name: 'every-unsupported-kind-is-listed-sorted-once', decision: 'allow', answered: false, obligations: [W('w'), N('x'), N('y'), Q()], supported: ['log'], expect: { decision: 'deny', perform: [], unsupported: ['notify', 'require_receipt', 'watermark'] } },
    { name: 'no-supported-kinds-at-all', decision: 'allow', answered: false, obligations: [L()], supported: [], expect: { decision: 'deny', perform: [], unsupported: ['log'] } },
    { name: 'malformed-obligations-deny', decision: 'allow', answered: false, obligations: [{ kind: 'shred' }], supported: ALL, expect: dec('deny') },
    { name: 'malformed-supported-denies', decision: 'allow', answered: false, obligations: [L()], supported: 'log', expect: dec('deny') },
    { name: 'supported-with-a-non-string-denies', decision: 'allow', answered: false, obligations: [L()], supported: ['log', 1], expect: dec('deny') },
    { name: 'deny-stays-deny-whatever-the-obligations', decision: 'deny', answered: false, obligations: [L()], supported: ALL, expect: dec('deny') },
    { name: 'deny-is-not-upgraded-by-an-answer', decision: 'deny', answered: true, obligations: [L()], supported: ALL, expect: dec('deny') },
    { name: 'unanswered-escalate-stays-escalate', decision: 'escalate', answered: false, obligations: [L()], supported: ALL, expect: dec('escalate') },
    { name: 'answered-escalate-becomes-allow-and-carries-the-obligations', decision: 'escalate', answered: true, obligations: [N('sec')], supported: ALL, expect: perform([N('sec')]) },
    { name: 'answered-escalate-with-an-unsupported-obligation-is-deny', decision: 'escalate', answered: true, obligations: [N('sec')], supported: ['log'], expect: { decision: 'deny', perform: [], unsupported: ['notify'] } },
    { name: 'unknown-decision-is-deny', decision: 'maybe', answered: false, obligations: [], supported: ALL, expect: dec('deny') },
  ];
  const ok = { outcome: 'ok', overdue: [] as number[] };
  const unmet = (overdue: number[]) => ({ outcome: 'escalate', overdue, status: 'obligation_unmet' });
  const outcome: { name: string; obligations: unknown; fulfilled: unknown; now: unknown; expect: Record<string, unknown> }[] = [
    { name: 'no-obligations', obligations: [], fulfilled: [], now: T, expect: ok },
    { name: 'no-due-time-is-never-overdue', obligations: [L('a'), Q()], fulfilled: [], now: T * 2, expect: ok },
    { name: 'not-yet-due', obligations: [Q(T)], fulfilled: [], now: T - 1, expect: ok },
    { name: 'due-now-and-unreported-is-unmet', obligations: [Q(T)], fulfilled: [], now: T, expect: unmet([0]) },
    { name: 'fulfilled-in-time', obligations: [Q(T)], fulfilled: [0], now: T + 5, expect: ok },
    { name: 'only-the-unreported-ones-are-overdue', obligations: [L('a', T), N('x', T), Q(T + 100)], fulfilled: [1], now: T + 10, expect: unmet([0]) },
    { name: 'a-fulfilled-index-out-of-range-is-ignored', obligations: [Q(T)], fulfilled: [5], now: T, expect: unmet([0]) },
    { name: 'malformed-input-is-everything-overdue', obligations: [L('a'), Q()], fulfilled: 'x', now: T, expect: unmet([0, 1]) },
    { name: 'a-bad-clock-is-everything-overdue', obligations: [Q(T)], fulfilled: [0], now: 1.5, expect: unmet([0]) },
    { name: 'a-negative-fulfilled-index-is-malformed', obligations: [Q(T)], fulfilled: [-1], now: T, expect: unmet([0]) },
  ];
  // prove the hand-written expectations against the reference, so a drifted builder cannot ship
  const same = (a: unknown, b: unknown, what: string) => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${what}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`); };
  for (const v of validate) same({ ok: obligationsError(v.input) === null }, v.expect, `validate ${v.name}`);
  for (const v of merge) { const r = mergeObligations(...v.inputs); same(r.ok ? { ok: true, obligations: r.obligations } : { ok: false }, v.expect, `merge ${v.name}`); }
  for (const v of gate) { const r = pepObligationGate(v.decision as never, v.answered, v.obligations, v.supported); same({ decision: r.decision, perform: r.perform, unsupported: r.unsupported }, v.expect, `gate ${v.name}`); }
  for (const v of outcome) { const r = obligationOutcome(v.obligations, v.fulfilled, v.now); same(r, v.expect, `outcome ${v.name}`); }
  return {
    format: 'pca-obligations-vectors',
    ver: 1,
    about: 'Conformance vectors for decision obligations. validate: a list is well formed iff ok. merge: the union of the lists, deduplicated and sorted by the canonical key (strict-canonical JSON of {kind, params ({} when absent), due?}) in UTF-8 byte order. gate: (decision, answered, obligations, supported kinds) -> the effective decision, the obligations to perform and the unsupported kinds; an allow (or an answered escalate) with an unsupported kind is a deny; deny and unanswered escalate pass through. outcome: obligations past their due time and not reported fulfilled (indexes) -> escalate with status obligation_unmet. An unknown decision string is treated as deny. Generated by src/test-support/obligations-vectors.ts.',
    validate, merge, gate, outcome,
  };
}
