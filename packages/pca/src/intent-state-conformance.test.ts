/**
 * The Intent Layer v2 state vectors (conformance/intent-state-vectors.json): accumulator and monitor declarations, values and
 * pre-states, the session-history window and fold, sequencer key sets and reservation receipts. The committed file must be
 * exactly what the reference produces now (a stale file fails), every case must be unique, and the fail-closed cases (a corrupt
 * history throws, an unreadable time is in no window) must be present.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import * as root from './index';
import * as intent from './ext/intent';

const dir = join(__dirname, '..');
const file = readFileSync(join(dir, 'conformance', 'intent-state-vectors.json'), 'utf8');
const doc = JSON.parse(file) as { format: string; ver: number; cases: { fn: string; name: string; args: unknown[]; out: unknown }[] };

describe('intent-state-vectors.json', () => {
  it('is the reference output (regenerate with scripts/gen-conformance-intent-state.mjs)', async () => {
    const acc = (await import(join(dir, 'scripts', 'intent-acc-cases.mjs'))) as { buildIntentAccCases: (p: unknown) => unknown[]; ser: (v: unknown) => string };
    const hist = (await import(join(dir, 'scripts', 'intent-history-cases.mjs'))) as { buildIntentHistoryCases: (p: unknown) => unknown[] };
    const pca = { ...root, ...intent };
    const cases = [...acc.buildIntentAccCases(pca), ...hist.buildIntentHistoryCases(pca)];
    const want = `{"format":"pca-intent-state-vectors","ver":1,"cases":[\n${cases.map((c) => acc.ser(c)).join(',\n')}\n]}\n`;
    expect(file === want).toBe(true);
  }, 120_000);

  it('has the documented shape, unique names and every function', () => {
    expect([doc.format, doc.ver]).toEqual(['pca-intent-state-vectors', 1]);
    expect(new Set(doc.cases.map((c) => c.name)).size).toBe(doc.cases.length);
    const fns = new Set(doc.cases.map((c) => c.fn));
    for (const f of ['accumulatorDeclError', 'monitorDeclError', 'accValueOf', 'combineAcc', 'verifyReceiptAgainstHolder', 'verifyKeySet', 'inWindow', 'accKeyOf', 'accPreState', 'accPost', 'monitorStep', 'monitorState']) expect(fns.has(f)).toBe(true);
    expect(doc.cases.length).toBeGreaterThan(3000);
  });

  it('pins the history rules a verifier would otherwise get wrong', () => {
    const by = (n: string) => doc.cases.find((c) => c.name === n)!.out;
    expect(by('inWindow/slide100/t1000/ti-100')).toBe(false); // (t - ms, t]
    expect(by('inWindow/slide100/t1000/ti-99')).toBe(true);
    expect(by('inWindow/slide100/t1000/ti+1')).toBe(true); // a future-stamped counted event has not left the window
    expect(by('inWindow/task/t1000/ti-1001')).toBe(true);
    expect(by('accPreState/corrupt/time-float')).toEqual({ throws: true }); // an unreadable time never silently drops a counted event
    expect(by('accPreState/corrupt/time-float-released-ignored')).toEqual({ sum: 0 });
    expect(by('accPreState/corrupt/sum-overflow')).toEqual({ throws: true });
    expect(by('accPreState/ok/max-no-overflow')).toEqual({ max: Number.MAX_SAFE_INTEGER });
    expect(by('monitorState/responds_within-2/buy-x-x-confirm')).toBe('missed');
  });
});
