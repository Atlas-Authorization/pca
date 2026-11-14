import { describe, expect, it } from 'vitest';
import type { AttestationDocument } from '@atlasauth/pca';
import { admitBlueprintInstance, admitWithEvidence, type AdmissionEvidence } from './blueprint-admission';
import type { AgentBlueprint } from './blueprint';

const bpOf = (runtime_pins?: unknown[]): AgentBlueprint => ({ runtime_pins }) as unknown as AgentBlueprint;
const ev = (r: unknown) => () => r as AdmissionEvidence;
const PIN = { runtime_measurement: 'rt-1', operator: 'acme' };
const goodId = { runtime_measurement: 'rt-1', operator: 'acme' };

describe('admitWithEvidence', () => {
  it('no pins is a no_pins deny with exactly that shape', async () => {
    for (const pins of [undefined, []]) expect(await admitWithEvidence(bpOf(pins), ev({ ok: true, bound: true, identity: goodId }))).toStrictEqual({ admitted: false, code: 'no_pins' });
  });
  it('a throwing verifier is named by error name, or "error" for a non-Error', async () => {
    expect(await admitWithEvidence(bpOf([PIN]), () => { throw new TypeError('x'); })).toStrictEqual({ admitted: false, code: 'verifier_error', reason: 'TypeError' });
    expect(await admitWithEvidence(bpOf([PIN]), () => Promise.reject('plain'))).toStrictEqual({ admitted: false, code: 'verifier_error', reason: 'error' });
  });
  it('not ok: missing result, false ok, and the reason only when it is a string', async () => {
    expect(await admitWithEvidence(bpOf([PIN]), ev(undefined))).toStrictEqual({ admitted: false, code: 'not_ok' });
    expect(await admitWithEvidence(bpOf([PIN]), ev({ ok: false, bound: true, reason: 5 }))).toStrictEqual({ admitted: false, code: 'not_ok' });
    expect(await admitWithEvidence(bpOf([PIN]), ev({ ok: 'yes', bound: true }))).toStrictEqual({ admitted: false, code: 'not_ok' });
    expect(await admitWithEvidence(bpOf([PIN]), ev({ ok: false, bound: true, reason: 'why' }))).toStrictEqual({ admitted: false, code: 'not_ok', reason: 'why' });
  });
  it('unbound evidence is not_bound', async () => {
    expect(await admitWithEvidence(bpOf([PIN]), ev({ ok: true, bound: 'true', identity: goodId }))).toStrictEqual({ admitted: false, code: 'not_bound' });
  });
  it('a missing or non-object identity is no_identity', async () => {
    for (const identity of [undefined, null, 'str', 5, true]) {
      expect(await admitWithEvidence(bpOf([{ a: 'str' }]), ev({ ok: true, bound: true, identity })), String(identity)).toStrictEqual({ admitted: false, code: 'no_identity' });
    }
  });
  it('a pin needs every field equal and defined, and an empty pin matches nothing', async () => {
    const run = (pin: unknown, identity: unknown) => admitWithEvidence(bpOf([pin]), ev({ ok: true, bound: true, identity }));
    expect(await run(PIN, goodId)).toStrictEqual({ admitted: true, identity: goodId, pin: PIN });
    expect(await run(PIN, { ...goodId, operator: 'evil' })).toStrictEqual({ admitted: false, code: 'no_matching_pin' });
    expect(await run({ runtime_measurement: 'rt-1', operator: undefined }, { runtime_measurement: 'rt-1' })).toStrictEqual({ admitted: false, code: 'no_matching_pin' });
    expect(await run({}, goodId)).toStrictEqual({ admitted: false, code: 'no_matching_pin' });
  });
});

describe('admitBlueprintInstance', () => {
  const doc = {} as AttestationDocument;
  const mk = (calls: unknown[]) => ({ verify: async (a: unknown) => (calls.push(a), { ok: true, bound: true, measured: goodId }) }) as never;
  const base = (over: Record<string, unknown>) => ({ blueprint: bpOf([PIN]), document: doc, verifier: mk([]), ctx: {} as never, expected: {} as never, nowMs: 5, ...over }) as never;
  it('no pins never reaches the verifier, even with no document', async () => {
    const calls: unknown[] = [];
    for (const pins of [undefined, []]) {
      expect(await admitBlueprintInstance(base({ blueprint: bpOf(pins), document: undefined, verifier: mk(calls) }))).toStrictEqual({ admitted: false, code: 'no_pins' });
    }
    expect(calls).toHaveLength(0);
  });
  it('no document is not_ok with the "no evidence" reason and the verifier is not called', async () => {
    const calls: unknown[] = [];
    for (const document of [undefined, null]) {
      expect(await admitBlueprintInstance(base({ document, verifier: mk(calls) }))).toStrictEqual({ admitted: false, code: 'not_ok', reason: 'no evidence' });
    }
    expect(calls).toHaveLength(0);
  });
  it('hands the verifier the document, context, clock and expected binding', async () => {
    const calls: unknown[] = [];
    const ctx = { c: 1 };
    const expected = { e: 1 };
    const r = await admitBlueprintInstance(base({ verifier: mk(calls), ctx, expected }));
    expect(calls).toStrictEqual([{ document: doc, ctx, nowMs: 5, expected }]);
    expect(r).toStrictEqual({ admitted: true, identity: goodId, pin: PIN });
  });
});
