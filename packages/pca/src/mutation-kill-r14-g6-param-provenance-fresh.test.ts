/**
 * r14 g6: param-provenance.ts module-level constants and helpers (static mutants), checked on a freshly evaluated module
 * (vi.resetModules + dynamic import).
 */
import { describe, expect, it, vi } from 'vitest';
import { b64u, sha256, utf8 } from './hash';

async function fresh() {
  vi.resetModules();
  return import('./param-provenance');
}

describe('param-provenance constants (fresh module)', () => {
  it('LABEL_REF_PREFIX and the label-ref parser', async () => {
    const m = await fresh();
    const d = b64u(sha256(utf8('r')));
    expect(m.LABEL_REF_PREFIX).toBe('pca-labels:');
    expect([m.parseLabelRef(`pca-labels:${d}#f`), m.parseLabelRef(`${d}#f`)]).toEqual([{ receipt: d, field: 'f' }, null]);
  });
  it('PROV_PATH_RE / isProvPath: action.params.<1..64 of [A-Za-z0-9_]>, never a prototype name', async () => {
    const m = await fresh();
    const cases = ['action.params.a', 'action.params.ab', 'action.params.A_1', 'action.params.' + 'a'.repeat(64), 'action.params.' + 'a'.repeat(65), 'x.action.params.a', 'action.params.a.b', 'action.params.a-b', 'action.params.', 'action.params.__proto__', 'action.params.constructor', 'action.params.prototype'];
    expect(cases.map((k) => m.PROV_PATH_RE.test(k))).toEqual([true, true, true, true, false, false, false, false, false, true, true, true]);
    expect(cases.map((k) => m.isProvPath(k))).toEqual([true, true, true, true, false, false, false, false, false, false, false, false]);
  });
  it('the tainted modes accepted by the policy', async () => {
    const m = await fresh();
    expect(['allow', 'question', 'question_typed', 'deny', 'x'].map((v) => m.validateProvenancePolicy({ params: {}, material_tainted: v as never }))).toEqual([
      null, null, null, null, 'material_tainted must be allow | question | question_typed | deny',
    ]);
    expect(['question', 'question_typed', 'deny', 'x'].map((v) => m.validateProvenancePolicy({ params: {}, critical_tainted: v as never }))).toEqual([
      null, null, null, 'critical_tainted must be question | question_typed | deny',
    ]);
  });
  it('a decision joins and names labels per path (levelOf) in bytewise order (sortUtf8)', async () => {
    const m = await fresh();
    const d = m.decideParamProvenance({
      aud: 'a.example', session: b64u(sha256(utf8('s'))),
      action: { params: { zz: 1, aa: 2 } },
      prov: { 'action.params.zz': ['reg:tr'], 'action.params.aa': ['reg:fp', 'reg:tr'] },
      policy: { params: { 'action.params.zz': 'material', 'action.params.aa': 'critical' }, registry: { 'reg:tr': 'trusted', 'reg:fp': 'first_party' } },
    });
    expect(d.outcome).toBe('pass');
    expect(Object.entries(d.labels)).toEqual([['action.params.aa', 'first_party'], ['action.params.zz', 'trusted']]);
  });
});
