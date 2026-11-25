import { b64u, canonicalBytesStrict, publicKeyOf, sha256, sign, utf8, verifyB64u } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  assertAskable,
  ceilingAdmitters,
  cellKeyOf,
  cellStats,
  decideOutcomeLayers,
  latticeView,
  layerCells,
  LAYER_APPROVAL_DOMAIN,
  normalizeRule,
  ownerRisk,
  signLayerApproval,
  verifyQuorumApprovals,
  type Admitter,
  type CeilingAdmitters,
  type CellView,
  type HarmModel,
  type IntentLearner,
  type LayerApprovalStatement,
  type LatticeView,
  type NumDim,
  type Omega,
  type Outcome,
} from './index';

// Hand-built Ω̃: verb `a` has two 3-cell dimensions (9 cells), verb `b` one (3 cells), so flat cell keys differ from joined ones.
const X: NumDim = { kind: 'num', path: 'action.params.x', lo: 0, hi: 9, cuts: [5], dist: 'uniform' };
const Y: NumDim = { kind: 'num', path: 'action.params.y', lo: 0, hi: 9, cuts: [5], dist: 'uniform' };
const omega: Omega = {
  v: 1,
  verbs: [
    { verb: 'a', reversibility: 'reversible', weight: 0.5, dims: [X, Y] },
    { verb: 'b', reversibility: 'reversible', weight: 0.5, dims: [X] },
  ],
  approximate: [],
};
const xBelow5: Admitter = { admits: (_vs, o) => (o.values['action.params.x'] as number) < 5 };

const cv = (verb: string, cell: number[], p: number, inGrant: boolean, vetoed: boolean): CellView => ({ verb, cell, p, mass: 0.1, harm: 1, inGrant, vetoed });
const stubTask = (tau: number, cells: CellView[]) => ({ omega, tau, cells: () => cells }) as unknown as IntentLearner;

describe('ceilingAdmitters', () => {
  it('absent ceilings are null, present ones compile, in org/site/std slots', () => {
    expect(ceilingAdmitters({})).toEqual({ org: null, site: null, std: null });
    const c = ceilingAdmitters({ site: { predicates: [] } });
    expect(c.org).toBeNull();
    expect(c.std).toBeNull();
    expect(typeof c.site?.admits).toBe('function');
    expect(Object.keys(ceilingAdmitters({})).sort()).toEqual(['org', 'site', 'std']);
  });
  it('a present null ceiling throws with its name', () => {
    expect(() => ceilingAdmitters({ org: null as never })).toThrow('ceilingAdmitters: the org ceiling is malformed (null or not an object)');
    expect(() => ceilingAdmitters({ std: [] as never })).toThrow('ceilingAdmitters: the std ceiling is malformed (null or not an object)');
  });
});

describe('latticeView classification', () => {
  const tau = 0.5;
  it('splits vetoed / effective / uncertain / neither exactly, boundaries included', () => {
    const cells = [
      cv('a', [0, 0], 0.9, true, true), // vetoed: dropped even though in grant
      cv('a', [0, 1], 0.9, true, false), // effective
      cv('a', [0, 2], 0.3, false, false), // uncertain
      cv('a', [1, 0], 0, false, false), // p = 0: neither
      cv('a', [1, 1], 1e-12, false, false), // p = 1e-12 exactly: neither
      cv('a', [1, 2], tau - 1e-12, false, false), // p = τ - 1e-12 exactly: neither
      cv('a', [2, 0], 0.75, false, false), // p > τ yet not in grant: neither
      cv('a', [2, 1], 0.3, false, true), // vetoed uncertain: dropped
    ];
    expect(latticeView(stubTask(tau, cells), {})).toEqual({ effective: [{ verb: 'a', cell: [0, 1] }], uncertain: [{ verb: 'a', cell: [0, 2] }], ceiling: [] });
  });
  it('a ceiling-excluded cell goes to `ceiling` with its layer and nowhere else', () => {
    const deny: Admitter = { admits: () => false };
    const c: CeilingAdmitters = { std: deny };
    const view = latticeView(stubTask(tau, [cv('b', [1], 0.9, true, false), cv('b', [2], 0.3, false, false)]), c);
    expect(view).toEqual({ effective: [], uncertain: [], ceiling: [{ verb: 'b', cell: [1], layer: 'std' }, { verb: 'b', cell: [2], layer: 'std' }] });
  });
  it('the first excluding layer in org, site, std order is named', () => {
    const deny: Admitter = { admits: () => false };
    const view = latticeView(stubTask(tau, [cv('b', [1], 0.9, true, false)]), { site: deny, std: deny });
    expect(view.ceiling).toEqual([{ verb: 'b', cell: [1], layer: 'site' }]);
  });
});

describe('decideOutcomeLayers', () => {
  const stub = (vetoed: boolean, acc: number, admits: boolean) => ({ omega, isVetoed: () => vetoed, acceptance: () => acc, admitsOutcome: () => admits }) as unknown as IntentLearner;
  const o: Outcome = { verb: 'b', values: { 'action.params.x': 1 } };
  const none = ceilingAdmitters({});
  it('a verb outside Ω is denied (even when the task would admit it)', () => {
    expect(decideOutcomeLayers(stub(false, 1, true), none, { verb: 'zzz', values: {} })).toEqual({ decision: 'intent_denied' });
  });
  it('vetoed or zero-acceptance outcomes are denied, boundary 1e-12 included', () => {
    expect(decideOutcomeLayers(stub(true, 1, true), none, o)).toEqual({ decision: 'intent_denied' });
    expect(decideOutcomeLayers(stub(false, 0, true), none, o)).toEqual({ decision: 'intent_denied' });
    expect(decideOutcomeLayers(stub(false, 1e-12, true), none, o)).toEqual({ decision: 'intent_denied' });
    expect(decideOutcomeLayers(stub(false, 2e-12, true), none, o)).toEqual({ decision: 'admit', by: 0 });
  });
  it('in-grant is admit, not-in-grant is intent_required', () => {
    expect(decideOutcomeLayers(stub(false, 0.4, true), none, o)).toEqual({ decision: 'admit', by: 0 });
    expect(decideOutcomeLayers(stub(false, 0.4, false), none, o)).toEqual({ decision: 'intent_required' });
  });
  it('a ceiling beats a vetoed cell', () => {
    expect(decideOutcomeLayers(stub(true, 0, false), { org: { admits: () => false } }, o)).toEqual({ decision: 'ceiling', layer: 'org' });
  });
});

describe('assertAskable', () => {
  const view: LatticeView = { effective: [], uncertain: [{ verb: 'a', cell: [1, 2] }, { verb: 'b', cell: [1] }], ceiling: [] };
  it('accepts a listed cell and names the cell when refusing', () => {
    expect(() => assertAskable(view, { verb: 'a', cell: [1, 2] })).not.toThrow();
    expect(() => assertAskable(view, { verb: 'b', cell: [1] })).not.toThrow();
    expect(() => assertAskable(view, { verb: 'a', cell: [1] })).toThrow('layers: cell a|1 is not an uncertain cell inside every ceiling (never a question)');
    expect(() => assertAskable(view, { verb: 'a', cell: [2, 1] })).toThrow('layers: cell a|2,1 is not');
    expect(() => assertAskable({ effective: [], uncertain: [], ceiling: [] }, { verb: 'a', cell: [0] })).toThrow('layers: cell a|0 is not');
  });
});

describe('ownerRisk', () => {
  const harm: HarmModel = { verb: () => 3, dim: () => 1 };
  it('sums mass * (1 - acceptability) * harm over known cells and skips unknown verbs', () => {
    const cells = [{ verb: 'a', cell: [0, 1] }, { verb: 'b', cell: [2] }, { verb: 'zzz', cell: [0] }];
    const want = cells.slice(0, 2).reduce((s, c) => {
      const vs = omega.verbs.find((v) => v.verb === c.verb)!;
      const st = cellStats(vs, c.cell, harm);
      return s + st.mass * 0.75 * st.harm;
    }, 0);
    expect(want).toBeGreaterThan(0);
    expect(ownerRisk(omega, cells, () => 0.25, harm)).toBeCloseTo(want, 12);
    expect(ownerRisk(omega, [{ verb: 'zzz', cell: [0] }], () => 0, harm)).toBe(0);
    expect(ownerRisk(omega, [], () => 0, harm)).toBe(0);
  });
});

describe('layerCells / cellKeyOf', () => {
  it('lists exactly the admitted cells, no extra past the cell count', () => {
    expect(layerCells(omega, xBelow5)).toEqual([
      { verb: 'a', cell: [0, 0] },
      { verb: 'a', cell: [0, 1] },
      { verb: 'a', cell: [0, 2] },
      { verb: 'b', cell: [0] },
    ]);
    expect(layerCells(omega, { admits: () => true })).toHaveLength(12);
    expect(layerCells(omega, { admits: () => false })).toEqual([]);
  });
  it('keys a known verb by the flat cell index and an unknown verb by the joined cell', () => {
    expect(cellKeyOf(omega, { verb: 'a', cell: [1, 2] })).toBe('a|5');
    expect(cellKeyOf(omega, { verb: 'b', cell: [2] })).toBe('b|2');
    expect(cellKeyOf(omega, { verb: 'zzz', cell: [1, 2] })).toBe('zzz|1,2');
  });
});

describe('quorum approvals: exact verdicts', () => {
  const sk = (l: string) => sha256(utf8(`atlas-pca-test/layers-kill/${l}`));
  const keys = ['a', 'b', 'c'].map((l) => ({ sk: sk(l), pk: b64u(publicKeyOf(sk(l))) }));
  const members = keys.map((k) => k.pk);
  const stmt: Omit<LayerApprovalStatement, 'v' | 'kind'> = { layer: 'org', session: b64u(sk('session')), seq: 2, map_digest: b64u(sk('map2')), prev: b64u(sk('d1')) };
  const approve = (i: number, over: Partial<typeof stmt> = {}) => signLayerApproval({ ...stmt, ...over }, keys[i]!.sk);
  const q1 = { kind: 'quorum' as const, k: 1 };

  it('an approval is the statement plus signer and a signature over domain || canonical statement', () => {
    const a = approve(0);
    expect(a).toEqual({ v: 1, kind: 'pca-intent-layer-approval', ...stmt, signer: members[0], sig: a.sig });
    const body = canonicalBytesStrict({ v: 1, kind: 'pca-intent-layer-approval', layer: 'org', session: stmt.session, seq: 2, map_digest: stmt.map_digest, prev: stmt.prev });
    const d = utf8(LAYER_APPROVAL_DOMAIN);
    const msg = new Uint8Array(d.length + body.length);
    msg.set(d);
    msg.set(body, d.length);
    expect(a.sig).toBe(b64u(sign(keys[0]!.sk, msg)));
    expect(verifyB64u(members[0]!, msg, a.sig)).toBe(true);
    expect(verifyB64u(members[0]!, body, a.sig)).toBe(false);
  });

  it('a clean quorum has no ignored entries', () => {
    expect(verifyQuorumApprovals([approve(0), approve(1)], members, { kind: 'quorum', k: 2 }, stmt)).toEqual({ ok: true, signers: [members[0], members[1]], ignored: [] });
  });

  it('every non-counting approval is reported with its index and reason', () => {
    const outsider = signLayerApproval(stmt, sk('outsider'));
    const forged = { ...approve(1), sig: approve(2).sig };
    const approvals = [null, 5, outsider, approve(0), approve(0), approve(1, { seq: 3 }), forged, { ...approve(2), v: 2 }, { ...approve(2), kind: 'other' }] as never[];
    const another = 'approval is for another (layer, session, seq, map_digest, prev)';
    expect(verifyQuorumApprovals(approvals, members, q1, stmt)).toEqual({
      ok: true,
      signers: [members[0]],
      ignored: [
        { index: 0, reason: 'not an object' },
        { index: 1, reason: 'not an object' },
        { index: 2, reason: 'signer is not a member' },
        { index: 4, reason: 'second approval from the same member' },
        { index: 5, reason: another },
        { index: 6, reason: 'bad signature' },
        { index: 7, reason: another },
        { index: 8, reason: another },
      ],
    });
  });

  it('a statement the canonical encoder refuses is a bad signature, never a counted approval', () => {
    const lone = '\ud800';
    const a = { v: 1, kind: 'pca-intent-layer-approval', layer: 'org', session: lone, seq: 2, map_digest: stmt.map_digest, prev: stmt.prev, signer: members[0], sig: 'AAAA' } as never;
    expect(verifyQuorumApprovals([a], members, q1, { ...stmt, session: lone })).toEqual({ ok: false, signers: [], ignored: [{ index: 0, reason: 'bad signature' }] });
  });

  it('malformed inputs fail closed with the index -1 reason', () => {
    const shape = 'approvals and members must be arrays and expected an object';
    const bad = (r: unknown) => ({ ok: false, signers: [], ignored: [{ index: -1, reason: r }] });
    expect(verifyQuorumApprovals(5 as never, members, q1, stmt)).toEqual(bad(shape));
    expect(verifyQuorumApprovals([], 5 as never, q1, stmt)).toEqual(bad(shape));
    expect(verifyQuorumApprovals([approve(0)], members, q1, null as never)).toEqual(bad(shape));
    expect(verifyQuorumApprovals([approve(0)], members, q1, 5 as never)).toEqual(bad(shape));
    const keysMsg = 'members must be distinct 32-byte keys';
    expect(verifyQuorumApprovals([approve(0)], [members[0]!, members[0]!], q1, stmt)).toEqual(bad(keysMsg));
    expect(verifyQuorumApprovals([approve(0)], [members[0]!, 'not-a-key'], q1, stmt)).toEqual(bad(keysMsg));
    expect(verifyQuorumApprovals([approve(0)], [members[0]!, 5 as never], q1, stmt)).toEqual(bad(keysMsg));
  });

  it('a rule normalizeRule refuses reports its message', () => {
    const rule = { kind: 'quorum' as const, k: 4 };
    let msg = '';
    try {
      normalizeRule(rule, [...members]);
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).not.toBe('');
    expect(verifyQuorumApprovals([approve(0)], members, rule, stmt)).toEqual({ ok: false, signers: [], ignored: [{ index: -1, reason: msg }] });
  });
});
