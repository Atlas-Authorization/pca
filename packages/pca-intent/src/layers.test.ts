import { b64u, publicKeyOf, sha256, utf8, type ActionContext } from '@atlasauth/pca';
import { describe, expect, it } from 'vitest';
import {
  admitter,
  assertAskable,
  ceilingAdmitters,
  cellKeyOf,
  createLearner,
  decideLayers,
  decideOutcomeLayers,
  deriveOmega,
  emitIntentMap,
  elicit,
  latticeView,
  layerCells,
  orgLayerFromMaps,
  ownerRisk,
  rng,
  signLayerApproval,
  verifyQuorumApprovals,
  type LayerApprovalStatement,
  type LayerPolicy,
  type PolicyInput,
} from './index';

// Intent Layer v2 milestone V5: layered lattice (deny anywhere wins, T18) and quorum-signed shared-layer deltas.

const AMT = 'action.params.amount';
const V = 'stripe.refund';
const cap = (max: number): LayerPolicy & PolicyInput => ({ predicates: [{ verb: V, resource: '*', where: [{ field: AMT, op: 'lte', value: max }] }] });
const ctx = (amount: number): ActionContext => ({ action: { verb: V, resource: 'acct/1', params: { amount } } });

describe('decideLayers (verifier side)', () => {
  it('checks org, site, std ceilings first, then denied regions, then the task union, else intent_required', () => {
    const g = { org: cap(500), site: cap(400), std: cap(300), task: [cap(100), cap(200)], denied: [{ predicates: [{ verb: V, where: [{ field: AMT, op: 'eq' as const, value: 150 }] }] }] };
    expect(decideLayers(g, ctx(600))).toEqual({ decision: 'ceiling', layer: 'org' });
    expect(decideLayers(g, ctx(450))).toEqual({ decision: 'ceiling', layer: 'site' });
    expect(decideLayers(g, ctx(350))).toEqual({ decision: 'ceiling', layer: 'std' });
    expect(decideLayers(g, ctx(150))).toEqual({ decision: 'intent_denied' });
    expect(decideLayers(g, ctx(50))).toEqual({ decision: 'admit', by: 0 });
    expect(decideLayers(g, ctx(180))).toEqual({ decision: 'admit', by: 1 });
    expect(decideLayers(g, ctx(250))).toEqual({ decision: 'intent_required' });
  });

  it('absent ceilings are Ω̃, a null ceiling is malformed (fails as that ceiling); an empty task layer admits nothing', () => {
    expect(decideLayers({ task: [cap(100)] }, ctx(50))).toEqual({ decision: 'admit', by: 0 });
    expect(decideLayers({ org: null as unknown as LayerPolicy, task: [cap(100)] }, ctx(50))).toEqual({ decision: 'ceiling', layer: 'org' });
    expect(decideLayers({ task: [] }, ctx(50))).toEqual({ decision: 'intent_required' });
  });

  it('T18 (no bypass): whatever the task layer and the deltas admit, an admitted action is inside every ceiling', () => {
    const r = rng(18);
    for (let i = 0; i < 300; i++) {
      const n = () => Math.floor(r() * 1000);
      const g = { ...(r() < 0.3 ? {} : { org: cap(n()) }), site: cap(n()), ...(r() < 0.5 ? {} : { std: cap(n()) }), task: Array.from({ length: 1 + Math.floor(r() * 4) }, () => cap(n())) };
      const a = n();
      const d = decideLayers(g, ctx(a));
      if (d.decision === 'admit') {
        for (const layer of [(g as { org?: LayerPolicy }).org, g.site, (g as { std?: LayerPolicy }).std]) if (layer) expect(a).toBeLessThanOrEqual((layer.predicates[0]!.where![0] as unknown as { value: number }).value);
      }
    }
  });
});

describe('the lattice over Ω̃ (wallet side)', () => {
  const omega = deriveOmega({ policies: [cap(200), cap(400)], slots: { verbs: [V], constraints: [{ path: AMT, max: 100 }, { path: AMT, max: 300 }] } });
  const vs = omega.verbs[0]!;
  const truth = admitter(cap(300));
  const org = ceilingAdmitters({ org: cap(200) });
  const orgCells = new Set(layerCells(omega, admitter(cap(200))).map((c) => cellKeyOf(omega, c)));

  it('T18: for random answer sequences, G^eff and U_k stay inside every ceiling; ceiling cells are never asked', () => {
    for (let seed = 1; seed <= 25; seed++) {
      const r = rng(seed);
      const l = createLearner(omega, { nullMass: 0.05 });
      for (let k = 0; k < 6; k++) {
        const view = latticeView(l, org);
        for (const c of [...view.effective, ...view.uncertain]) expect(orgCells.has(cellKeyOf(omega, c))).toBe(true);
        for (const c of view.ceiling) expect(() => assertAskable(view, c)).toThrow(/never a question/);
        const q = l.nextQuestion();
        if (!q) break;
        l.observe(q.outcome, r() < 0.5 ? 1 : 0); // ANY answer sequence
      }
    }
  });

  it('T18 (per-owner risk): R_i(G^eff) <= R_i(G^i) for an arbitrary owner acceptability', () => {
    const l = createLearner(omega, { nullMass: 0.05 });
    elicit(l, (q) => (truth.admits(vs, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions: 40 });
    const view = latticeView(l, org);
    for (let seed = 1; seed <= 20; seed++) {
      const r = rng(seed * 7);
      const table = new Map<string, number>();
      const a = (_v: typeof vs, o: { verb: string; values: Record<string, number | string> }) => {
        const key = JSON.stringify(o.values);
        if (!table.has(key)) table.set(key, r());
        return table.get(key)!;
      };
      expect(ownerRisk(omega, view.effective, a)).toBeLessThanOrEqual(ownerRisk(omega, layerCells(omega, admitter(cap(200))), a) + 1e-12);
    }
  });

  it('a ceiling denies even what the principal said yes to (deny anywhere wins)', () => {
    const l = createLearner(omega, { nullMass: 0.05 });
    elicit(l, (q) => (truth.admits(vs, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions: 40 });
    const o = { verb: V, values: { [AMT]: 250 } };
    expect(l.admitsOutcome(o)).toBe(true);
    expect(decideOutcomeLayers(l, org, o)).toEqual({ decision: 'ceiling', layer: 'org' });
    expect(decideOutcomeLayers(l, org, { verb: V, values: { [AMT]: 150 } })).toEqual({ decision: 'admit', by: 0 });
    expect(decideOutcomeLayers(l, ceilingAdmitters({}), o)).toEqual({ decision: 'admit', by: 0 });
  });

  it('an org layer can itself be a learned joint map (multi.ts aggregation)', () => {
    const mapOf = (ref: string, max: number) => {
      const l = createLearner(omega, { nullMass: 0.05 });
      const t = admitter(cap(max));
      elicit(l, (q) => (t.admits(vs, q.outcome) ? 1 : 0), { epsRisk: 0, epsBurden: 0, maxQuestions: 40 });
      return emitIntentMap(l, ref);
    };
    const { policy } = orgLayerFromMaps([mapOf('A', 200), mapOf('B', 400)], { kind: 'unanimity' });
    const joint = admitter(policy);
    expect(joint.admits(vs, { verb: V, values: { [AMT]: 150 } })).toBe(true);
    expect(joint.admits(vs, { verb: V, values: { [AMT]: 250 } })).toBe(false);
  });
});

describe('quorum-signed shared-layer approvals', () => {
  const sk = (l: string) => sha256(utf8(`atlas-pca-test/layers/${l}`));
  const keys = ['a', 'b', 'c'].map((l) => ({ sk: sk(l), pk: b64u(publicKeyOf(sk(l))) }));
  const members = keys.map((k) => k.pk);
  const stmt: Omit<LayerApprovalStatement, 'v' | 'kind'> = { layer: 'org', session: b64u(sk('session')), seq: 2, map_digest: b64u(sk('map2')), prev: b64u(sk('d1')) };
  const approve = (i: number, over: Partial<typeof stmt> = {}) => signLayerApproval({ ...stmt, ...over }, keys[i]!.sk);

  it('quorum(2): two distinct members suffice, one does not, a member counts once', () => {
    expect(verifyQuorumApprovals([approve(0), approve(1)], members, { kind: 'quorum', k: 2 }, stmt)).toMatchObject({ ok: true, signers: [members[0], members[1]] });
    expect(verifyQuorumApprovals([approve(0)], members, { kind: 'quorum', k: 2 }, stmt).ok).toBe(false);
    expect(verifyQuorumApprovals([approve(0), approve(0)], members, { kind: 'quorum', k: 2 }, stmt).ok).toBe(false);
  });

  it('approvals for another session, seq, map digest, prev or layer do not count; nor do non-members or bad signatures', () => {
    const rule = { kind: 'quorum' as const, k: 2 };
    expect(verifyQuorumApprovals([approve(0), approve(1, { seq: 3 })], members, rule, stmt).ok).toBe(false);
    expect(verifyQuorumApprovals([approve(0), approve(1, { session: b64u(sk('other')) })], members, rule, stmt).ok).toBe(false);
    expect(verifyQuorumApprovals([approve(0), approve(1, { map_digest: b64u(sk('x')) })], members, rule, stmt).ok).toBe(false);
    expect(verifyQuorumApprovals([approve(0), approve(1, { prev: b64u(sk('y')) })], members, rule, stmt).ok).toBe(false);
    expect(verifyQuorumApprovals([approve(0), approve(1, { layer: 'task' })], members, rule, stmt).ok).toBe(false);
    const outsider = signLayerApproval(stmt, sk('outsider'));
    expect(verifyQuorumApprovals([approve(0), outsider], members, rule, stmt).ok).toBe(false);
    const forged = { ...approve(1), sig: approve(2).sig };
    expect(verifyQuorumApprovals([approve(0), forged], members, rule, stmt).ok).toBe(false);
  });

  it('weighted rules and vetoers follow multi.ts', () => {
    const weighted = { kind: 'weighted' as const, weights: { [members[0]!]: 3, [members[1]!]: 1, [members[2]!]: 1 }, threshold: 4 };
    expect(verifyQuorumApprovals([approve(1), approve(2)], members, weighted, stmt).ok).toBe(false);
    expect(verifyQuorumApprovals([approve(0), approve(2)], members, weighted, stmt).ok).toBe(true);
    const vetoed = { kind: 'quorum' as const, k: 1, vetoers: [members[2]!] };
    expect(verifyQuorumApprovals([approve(0)], members, vetoed, stmt).ok).toBe(false);
    expect(verifyQuorumApprovals([approve(2)], members, vetoed, stmt).ok).toBe(true);
  });

  it('k − 1 members can never reach quorum(k), whatever subset signs', () => {
    for (let k = 1; k <= 3; k++) {
      for (let mask = 0; mask < 8; mask++) {
        const subset = [0, 1, 2].filter((i) => mask & (1 << i));
        const r = verifyQuorumApprovals(subset.map((i) => approve(i)), members, { kind: 'quorum', k }, stmt);
        expect(r.ok).toBe(subset.length >= k);
      }
    }
  });

  it('a malformed member list or rule fails closed', () => {
    expect(verifyQuorumApprovals([approve(0)], [members[0]!, members[0]!], { kind: 'quorum', k: 1 }, stmt).ok).toBe(false);
    expect(verifyQuorumApprovals([approve(0)], members, { kind: 'quorum', k: 4 }, stmt).ok).toBe(false);
  });
});

describe('verifyQuorumApprovals never throws', () => {
  it('fails closed on non-array approvals / members or a non-object expected', () => {
    for (const x of [null, undefined, 1, 'x', {}]) {
      expect(verifyQuorumApprovals(x as never, x as never, { kind: 'quorum', k: 1 }, x as never).ok).toBe(false);
    }
  });
});
