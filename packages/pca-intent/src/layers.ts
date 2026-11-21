import { b64u, canonicalBytesStrict, decodeB64uStrict, publicKeyOf, sign, utf8, verifyB64u } from '@atlasauth/pca';
import { LAYER_CEILINGS, type CeilingKind, type LayerDecision } from '@atlasauth/pca/ext/intent';
import type { IntentLearner } from './learner';
import { aggregateIntentMaps, normalizeRule, ruleAdmits, type AggregationRule, type NormalRule } from './multi';
import type { IntentMap } from './map';
import { cellRep, cellStats, decodeCell, DEFAULT_HARM, encodeCell, verbCellCount, type HarmModel, type Omega, type Outcome, type VerbSpace } from './omega';
import { admitter, type Admitter, type PolicyInput } from './policy';

/**
 * LAYERED INTENT LATTICE AND QUORUM (Intent Layer v2 §2.4, §3.5, milestone V5; T18).
 *
 * Four layers, each a subset of Ω̃:
 *   G^org   the org / operator ceiling (signed by the org; absent = Ω̃);
 *   G^site  the site's own verifier policy;
 *   G^std   the principal's standing profile rules;
 *   G^task  the task map's grant G^task_0 and the principal-signed deltas D_1 … D_k (a union).
 * Effective grant:  G^eff_k = G^org ∩ G^site ∩ G^std ∩ (G^task_0 ∪ D_1 ∪ … ∪ D_k) ∖ vetoed.
 * DENY ANYWHERE WINS: a cell outside a ceiling is denied with reason `ceiling` and is NEVER a question (the
 * principal cannot widen a ceiling), whatever the task layer says. So for every answer sequence
 * G^eff_k ⊆ G^org ∩ G^site ∩ G^std (T18), and since harm terms are non-negative each layer owner's own risk measure
 * of G^eff is at most that of their own layer (R_i(G^eff) ≤ R_i(G^i)): {@link ownerRisk}.
 *
 * The verifier side (`decideLayerCeilings`, the §5 `layers` check, and `decideLayers`) lives in `@atlasauth/pca`
 * (`intent-layers.ts`) and is re-exported here: layer grants are predicate sets for the one evaluator. Shared layers
 * (an org whose expense policy is itself a learned map, a household booking) widen only through a k-of-n QUORUM of principal-signed approvals over the same (layer, σ_id, k, map_digest_k, prev), with the
 * joint rule of `multi.ts` (unanimity, quorum(k), weighted, vetoers): {@link verifyQuorumApprovals}.
 */

export { decideLayerCeilings, decideLayers, LAYER_CEILINGS, type CeilingKind, type LayerCeilings, type LayerDecision, type LayeredGrant, type LayerPolicy } from '@atlasauth/pca/ext/intent';

const CEILINGS: readonly CeilingKind[] = LAYER_CEILINGS;

// ---- wallet side: the lattice over the cells of Ω̃ ------------------------------------------------------------

export interface CellKey {
  verb: string;
  cell: number[];
}

export interface CeilingAdmitters {
  org?: Admitter | null;
  site?: Admitter | null;
  std?: Admitter | null;
}

/** Compile ceiling layers into admitters over Ω̃. ABSENT = no ceiling; a ceiling PRESENT with null (or not an object) is malformed: throws. */
export function ceilingAdmitters(layers: { org?: PolicyInput; site?: PolicyInput; std?: PolicyInput }): CeilingAdmitters {
  const one = (k: CeilingKind): Admitter | null => {
    const l = Object.prototype.hasOwnProperty.call(layers, k) ? layers[k] : undefined;
    if (l === undefined) return null;
    if (l === null || typeof l !== 'object' || Array.isArray(l)) throw new Error(`ceilingAdmitters: the ${k} ceiling is malformed (null or not an object)`);
    return admitter(l);
  };
  return { org: one('org'), site: one('site'), std: one('std') };
}

/** The first ceiling that excludes ω (null when every ceiling admits it). Ceilings are evaluated at the cell's own outcome. */
export function ceilingOf(c: CeilingAdmitters, vs: VerbSpace, o: Outcome): CeilingKind | null {
  for (const k of CEILINGS) {
    const a = c[k];
    if (a && !a.admits(vs, o)) return k;
  }
  return null;
}

export interface LatticeView {
  /** G^eff: inside every ceiling, in the task grant (G_τ of the task map, which already holds every delta), not vetoed. */
  effective: CellKey[];
  /** U_k: inside every ceiling, 0 < p < τ, not vetoed: the ONLY cells ever asked about. */
  uncertain: CellKey[];
  /** Cells some ceiling excludes (denied with reason `ceiling`, never asked). */
  ceiling: (CellKey & { layer: CeilingKind })[];
}

/**
 * The lattice of a task learner under ceiling layers. Under NF the task map after k answers is m_k and
 * G̃_τ(m_k) = G^task_0 ∪ D_1 ∪ … ∪ D_k (T14), so the learner's grant IS the task layer with its deltas.
 */
export function latticeView(task: IntentLearner, ceilings: CeilingAdmitters): LatticeView {
  const out: LatticeView = { effective: [], uncertain: [], ceiling: [] };
  const byVerb = new Map(task.omega.verbs.map((v) => [v.verb, v] as const));
  for (const c of task.cells()) {
    const vs = byVerb.get(c.verb)!;
    const layer = ceilingOf(ceilings, vs, cellRep(vs, c.cell));
    if (layer) {
      out.ceiling.push({ verb: c.verb, cell: c.cell, layer });
      continue;
    }
    if (c.vetoed) continue;
    if (c.inGrant) out.effective.push({ verb: c.verb, cell: c.cell });
    else if (c.p > 1e-12 && c.p < task.tau - 1e-12) out.uncertain.push({ verb: c.verb, cell: c.cell });
  }
  return out;
}

/** The wallet-side counterpart of {@link decideLayers} for a concrete outcome against a task learner. */
export function decideOutcomeLayers(task: IntentLearner, ceilings: CeilingAdmitters, o: Outcome): LayerDecision {
  const vs = task.omega.verbs.find((v) => v.verb === o.verb);
  if (!vs) return { decision: 'intent_denied' };
  const layer = ceilingOf(ceilings, vs, o);
  if (layer) return { decision: 'ceiling', layer };
  if (task.isVetoed(o) || task.acceptance(o) <= 1e-12) return { decision: 'intent_denied' };
  if (task.admitsOutcome(o)) return { decision: 'admit', by: 0 };
  return { decision: 'intent_required' };
}

/** A question may only be about a cell of U_k (inside every ceiling). Throws otherwise. */
export function assertAskable(view: LatticeView, c: CellKey): void {
  const key = `${c.verb}|${c.cell.join(',')}`;
  if (!view.uncertain.some((u) => `${u.verb}|${u.cell.join(',')}` === key)) {
    throw new Error(`layers: cell ${key} is not an uncertain cell inside every ceiling (never a question)`);
  }
}

/**
 * Layer owner i's own risk measure of a set of cells: R_i(G) = Σ_{c∈G} μ(c)·(1 − a_i(c))·E[h | c], with a_i the
 * owner's acceptability at the cell's outcome. T18: R_i(G^eff) ≤ R_i(G^i) because G^eff ⊆ G^i.
 */
export function ownerRisk(omega: Omega, cells: readonly CellKey[], acceptability: (vs: VerbSpace, o: Outcome) => number, harm: HarmModel = DEFAULT_HARM): number {
  let r = 0;
  const byVerb = new Map(omega.verbs.map((v) => [v.verb, v] as const));
  for (const c of cells) {
    const vs = byVerb.get(c.verb);
    if (!vs) continue;
    const { mass, harm: h } = cellStats(vs, c.cell, harm);
    r += mass * (1 - acceptability(vs, cellRep(vs, c.cell))) * h;
  }
  return r;
}

/** Every cell of Ω̃ an admitter admits (the layer as a cell set). */
export function layerCells(omega: Omega, a: Admitter): CellKey[] {
  const out: CellKey[] = [];
  for (const vs of omega.verbs) {
    for (let f = 0; f < verbCellCount(vs); f++) {
      const cell = decodeCell(vs, f);
      if (a.admits(vs, cellRep(vs, cell))) out.push({ verb: vs.verb, cell });
    }
  }
  return out;
}

/** Flat key of a cell (for set operations in callers and tests). */
export function cellKeyOf(omega: Omega, c: CellKey): string {
  const vs = omega.verbs.find((v) => v.verb === c.verb);
  return `${c.verb}|${vs ? encodeCell(vs, c.cell) : c.cell.join(',')}`;
}

/**
 * An org layer that is itself a LEARNED map over a shared Ω (an expense policy the employer has not fully
 * specified): the joint grant of the org approvers' maps under the org's rule (`multi.ts` aggregation). Its
 * uncertain cells go to the org's approvers, and a widening needs an org delta with a quorum of their signatures.
 */
export function orgLayerFromMaps(maps: readonly IntentMap[], rule: AggregationRule): { map: IntentMap; policy: PolicyInput } {
  const map = aggregateIntentMaps(maps, rule);
  return { map, policy: map.grant };
}

// ---- quorum-signed layer approvals ----------------------------------------------------------------------------

export const LAYER_APPROVAL_DOMAIN = 'atlas-pca/intent-layer-approval/v1\0';

/** What every approver of a shared-layer widening signs. */
export interface LayerApprovalStatement {
  v: 1;
  kind: 'pca-intent-layer-approval';
  layer: 'org' | 'task';
  /** σ_id (b64u 32). */
  session: string;
  /** k: the delta's position in the session's chain. */
  seq: number;
  /** The map digest after the k-th answer (b64u 32). */
  map_digest: string;
  /** The previous delta's id, or the session root's digest for k = 1 (b64u 32). */
  prev: string;
}

export interface LayerApproval extends LayerApprovalStatement {
  /** The approver's Ed25519 public key (b64u 32). */
  signer: string;
  sig: string;
}

const statementOf = (a: LayerApprovalStatement): LayerApprovalStatement => ({
  v: 1,
  kind: 'pca-intent-layer-approval',
  layer: a.layer,
  session: a.session,
  seq: a.seq,
  map_digest: a.map_digest,
  prev: a.prev,
});

function approvalMessage(s: LayerApprovalStatement): Uint8Array {
  const d = utf8(LAYER_APPROVAL_DOMAIN);
  const b = canonicalBytesStrict(statementOf(s));
  const m = new Uint8Array(d.length + b.length);
  m.set(d);
  m.set(b, d.length);
  return m;
}

/** Sign an approval of a shared-layer widening. */
export function signLayerApproval(s: Omit<LayerApprovalStatement, 'v' | 'kind'>, secretKey: Uint8Array): LayerApproval {
  const st = statementOf({ v: 1, kind: 'pca-intent-layer-approval', ...s });
  return { ...st, signer: b64u(publicKeyOf(secretKey)), sig: b64u(sign(secretKey, approvalMessage(st))) };
}

export interface QuorumResult {
  ok: boolean;
  /** Distinct members whose valid approval counted, in member order. */
  signers: string[];
  /** Approvals that did not count, with the reason. */
  ignored: { index: number; reason: string }[];
}

/**
 * Verify a set of approvals against the layer's members and rule. An approval counts iff its signer is a member, it
 * is the FIRST approval from that member, its statement equals `expected` field by field, and its signature
 * verifies. The rule is `multi.ts`'s, over member keys (a weighted rule's weights are keyed by member key; vetoers
 * are member keys). k − 1 colluding members cannot reach a quorum of k: every counted approval is a distinct
 * member's EUF-CMA signature over this exact (layer, session, seq, map_digest, prev).
 */
export function verifyQuorumApprovals(
  approvals: readonly LayerApproval[],
  members: readonly string[],
  rule: AggregationRule,
  expected: Omit<LayerApprovalStatement, 'v' | 'kind'>,
): QuorumResult {
  const ignored: { index: number; reason: string }[] = [];
  if (!Array.isArray(approvals) || !Array.isArray(members) || expected === null || typeof expected !== 'object') {
    return { ok: false, signers: [], ignored: [{ index: -1, reason: 'approvals and members must be arrays and expected an object' }] };
  }
  if (members.some((m) => typeof m !== 'string') || new Set(members).size !== members.length || members.some((m) => decodeB64uStrict(m, 32) === null)) {
    return { ok: false, signers: [], ignored: [{ index: -1, reason: 'members must be distinct 32-byte keys' }] };
  }
  let n: NormalRule;
  try {
    n = normalizeRule(rule, [...members]);
  } catch (e) {
    return { ok: false, signers: [], ignored: [{ index: -1, reason: (e as Error).message }] };
  }
  const want = statementOf({ v: 1, kind: 'pca-intent-layer-approval', ...expected });
  const counted = new Set<string>();
  approvals.forEach((a, i) => {
    if (!a || typeof a !== 'object') return ignored.push({ index: i, reason: 'not an object' });
    if (!members.includes(a.signer)) return ignored.push({ index: i, reason: 'signer is not a member' });
    if (counted.has(a.signer)) return ignored.push({ index: i, reason: 'second approval from the same member' });
    const st = statementOf(a);
    const same = (Object.keys(want) as (keyof LayerApprovalStatement)[]).every((k) => st[k] === want[k]) && a.v === 1 && a.kind === 'pca-intent-layer-approval';
    if (!same) return ignored.push({ index: i, reason: 'approval is for another (layer, session, seq, map_digest, prev)' });
    let ok = false;
    try {
      ok = verifyB64u(a.signer, approvalMessage(st), a.sig);
    } catch {
      ok = false;
    }
    if (!ok) return ignored.push({ index: i, reason: 'bad signature' });
    counted.add(a.signer);
    return undefined;
  });
  const signers = members.filter((m) => counted.has(m));
  return { ok: ruleAdmits(n, members.map((m) => counted.has(m))), signers, ignored };
}
