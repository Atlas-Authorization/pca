import {
  intentActionDigest,
  mintSessionGrant,
  pcactnDigest,
  signIntentRequired,
  verifyIntentRequired,
  type ActionSchemaKey,
  type Capability,
  type CellCoords,
  type ConformResult,
  type Friction,
  type IntentRequiredBody,
  type MintSessionGrantArgs,
  type PCActn,
  type SignedIntentRequired,
  type SignerSuiteOpts,
} from '@atlasauth/pca';
import { boxesToPredicates, type IntentLearner } from './learner';
import { cellOf, encodeCell, verbCellCount, type Omega, type Outcome, type VerbSpace } from './omega';

/**
 * LAZY JUST-IN-TIME ELICITATION (PCA Intent Layer v2 §3.3; milestone V3, T13, T14, T15).
 *
 * Start narrow (G^task_0 = G̃_1(m_0)). When the agent attempts ω, the verifier computes c = cell(lift(ξ, ω, t)) and
 * decides, IN ORDER:
 *   c = ⊠ (schema violation, or a value outside Ω̃)          -> deny `schema_violation` (never a question);
 *   c ∉ G^org ∩ G^site ∩ G^std                               -> deny `ceiling` (the principal cannot widen a ceiling);
 *   c vetoed, or p(c) = 0                                    -> deny `intent_denied`;
 *   c ∈ G^eff                                                 -> continue verification;
 *   otherwise (c ∈ U_k)                                       -> `intent_required` (one question about c).
 * A "yes" is replayed into the task map (m_{k-1} -> m_k) and becomes the DELTA GRANT
 * D_k = G̃_1(m_k) ∖ G̃_1(m_{k-1}), minted as a ROOT capability signed by the PRINCIPAL key and chained by
 * (σ, k, prev = id(D_{k-1}), root = digest(S)). A "no" produces no delta: it is a veto.
 */

export type VisitDecision =
  | { kind: 'schema_violation'; reason: string }
  | { kind: 'ceiling' }
  | { kind: 'intent_denied'; vetoed: boolean }
  | { kind: 'admit'; cell: number[] }
  | { kind: 'intent_required'; cell: number[]; p: number };

export interface VisitInput {
  /** The task map's learner over Ω̃ (m_k). */
  learner: IntentLearner;
  /** lift(ξ, ω, t) as an outcome of Ω̃. */
  lifted: Outcome;
  /** The schema conformance of the plaintext action (`conformAction`). */
  conform: ConformResult;
  /** Ceiling layers (G^org, G^site, G^std): each must admit the lifted outcome. Deny anywhere wins. */
  ceilings?: ((vs: VerbSpace, o: Outcome) => boolean)[];
  /** Is the cell in G^eff (the union of G^task_0 and the deltas, as the verifier evaluates the presented grant)? */
  inEffective: boolean;
}

/** The ordered lazy-elicitation decision of §3.3 step 2. */
export function decideVisit(i: VisitInput): VisitDecision {
  if (!i.conform.ok) return { kind: 'schema_violation', reason: `${i.conform.code}: ${i.conform.reason}` };
  const vs = i.learner.omega.verbs.find((v) => v.verb === i.lifted.verb);
  const cell = vs ? cellOf(vs, i.lifted) : null;
  if (!vs || !cell) return { kind: 'schema_violation', reason: 'the lifted action lies outside Ω̃' };
  for (const ceiling of i.ceilings ?? []) if (!ceiling(vs, i.lifted)) return { kind: 'ceiling' };
  const vetoed = i.learner.isVetoed(i.lifted);
  const p = i.learner.acceptance(i.lifted);
  if (vetoed || p <= 0) return { kind: 'intent_denied', vetoed };
  if (i.inEffective) return { kind: 'admit', cell };
  return { kind: 'intent_required', cell, p };
}

/** The coordinates of one cell (numeric: [i, i]; categorical: the cell's value). Never text about the value. */
export function cellCoords(vs: VerbSpace, cell: readonly number[]): CellCoords {
  const out: CellCoords = {};
  vs.dims.forEach((d, k) => {
    out[d.path] = d.kind === 'num' ? [cell[k]!, cell[k]!] : [d.values[cell[k]!]!.value];
  });
  return out;
}

/** Coordinates -> per-dimension cell indices (inverse of {@link cellCoords} for a single cell), or null. */
export function cellFromCoords(vs: VerbSpace, coords: CellCoords): number[] | null {
  if (Object.keys(coords).length !== vs.dims.length) return null;
  const out: number[] = [];
  for (const d of vs.dims) {
    const c = coords[d.path];
    if (c === undefined) return null;
    if (d.kind === 'num') {
      if (typeof c[0] !== 'number' || c[0] !== c[1]) return null;
      out.push(c[0]);
    } else {
      if (c.length !== 1 || typeof c[0] !== 'string') return null;
      const i = d.values.findIndex((v) => v.value === c[0]);
      if (i < 0) return null;
      out.push(i);
    }
  }
  return out;
}

export interface IntentRequiredInput {
  session: string;
  mapDigest: string;
  schemaDigest: string;
  pcactn: PCActn;
  vs: VerbSpace;
  cell: number[];
  questionId: string;
  friction: Friction;
  deliveredTo: 'wallet' | 'agent';
  expiresAt: number;
}

/** The site's `pca-intent-required` body for a visited uncertain cell (sign it with `signIntentRequired`). */
export function intentRequiredBody(i: IntentRequiredInput): IntentRequiredBody {
  return {
    v: 1,
    kind: 'pca-intent-required',
    session: i.session,
    map_digest: i.mapDigest,
    schema: i.schemaDigest,
    pcactn_digest: pcactnDigest(i.pcactn),
    action_digest: intentActionDigest(i.pcactn.action),
    cell: { verb: i.vs.verb, coords: cellCoords(i.vs, i.cell) },
    reason: 'uncertain',
    question_id: i.questionId,
    friction: i.friction,
    delivered_to: i.deliveredTo,
    expires_at: i.expiresAt,
  };
}

export function signedIntentRequired(i: IntentRequiredInput, kid: string, siteSecret: Uint8Array, suite?: SignerSuiteOpts): SignedIntentRequired {
  return signIntentRequired(intentRequiredBody(i), kid, siteSecret, suite);
}

/**
 * The WALLET's check of an `intent_required` (whether it came straight from the site or was relayed by the agent):
 * the site signature under its discovery keys, the expiry, the session and map, and the CELL, which the wallet
 * re-derives from its own Ω̃ and the lifted action. Any disagreement refuses the question (nothing is asked).
 */
export function walletCheckIntentRequired(
  body: unknown,
  w: { keys: readonly ActionSchemaKey[]; now: number; session: string; mapDigest: string; omegaTilde: Omega; lifted: Outcome; pcactn: PCActn },
): { ok: true; vs: VerbSpace; cell: number[] } | { ok: false; reason: string } {
  const v = verifyIntentRequired(body, w.keys, w.now);
  if (!v.ok) return v;
  const b = body as SignedIntentRequired;
  if (b.session !== w.session || b.map_digest !== w.mapDigest) return { ok: false, reason: 'the question is for another session or map' };
  if (b.pcactn_digest !== pcactnDigest(w.pcactn) || b.action_digest !== intentActionDigest(w.pcactn.action)) return { ok: false, reason: 'the question is about another action' };
  const vs = w.omegaTilde.verbs.find((x) => x.verb === w.lifted.verb);
  const mine = vs ? cellOf(vs, w.lifted) : null;
  if (!vs || !mine || b.cell.verb !== vs.verb) return { ok: false, reason: 'the wallet cannot place the action in Ω̃' };
  const theirs = cellFromCoords(vs, b.cell.coords);
  if (!theirs || theirs.some((x, k) => x !== mine[k])) return { ok: false, reason: 'the site cell differs from the cell the wallet derives' };
  return { ok: true, vs, cell: mine };
}

// ---- delta grants --------------------------------------------------------------------------------------------

/** Per verb, the cells G̃_1(m_k) adds over G̃_1(m_{k-1}) (both learners over the same Ω̃). */
export function deltaCells(prev: IntentLearner, next: IntentLearner): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  const prevIn = new Set(prev.cells().filter((c) => c.inGrant).map((c) => `${c.verb}|${c.cell.join(',')}`));
  for (const vs of next.omega.verbs) {
    const a = new Uint8Array(verbCellCount(vs));
    let any = false;
    for (const c of next.cells()) {
      if (c.verb !== vs.verb || !c.inGrant || prevIn.has(`${c.verb}|${c.cell.join(',')}`)) continue;
      a[encodeCell(vs, c.cell)] = 1;
      any = true;
    }
    if (any) out.set(vs.verb, a);
  }
  return out;
}

/** The predicates of a delta (one maximal box per covered region, per verb). */
export function deltaPredicates(omegaTilde: Omega, delta: Map<string, Uint8Array>) {
  return omegaTilde.verbs.flatMap((vs) => (delta.has(vs.verb) ? boxesToPredicates(vs, delta.get(vs.verb)!) : []));
}

/**
 * Mint D_k from the k-th answer: null when the answer added no cell ("no" answers and noise-free repeats produce no
 * delta). The caller passes the PRINCIPAL key (the wallet holds it); the agent's key never signs a grant.
 */
export function mintDelta(
  prev: IntentLearner,
  next: IntentLearner,
  a: Omit<MintSessionGrantArgs, 'predicates'> & { prevGrant: Capability },
): { grant: Capability; goalSalt: string; cells: number } | null {
  const delta = deltaCells(prev, next);
  let cells = 0;
  for (const v of delta.values()) for (const x of v) cells += x;
  if (cells === 0) return null;
  if (a.prev !== undefined && a.prev !== a.prevGrant.id) throw new Error('mintDelta: prev must be the id of the previous session grant');
  const { prevGrant, ...rest } = a;
  const r = mintSessionGrant({ ...rest, prev: prevGrant.id, predicates: deltaPredicates(next.omega, delta) });
  return { ...r, cells };
}
