import { decodeB64uStrict, hashCanonical, verifyIntentRequired, type ActionSchemaKey, type Reversibility, type SignedIntentRequired } from '@atlasauth/pca';
import { cellRep, cellStats, DEFAULT_HARM, type HarmModel, type IntentLearner, type Omega, type VerbSpace } from '@atlasauth/pca-intent';
import { verifyAssertion, type CredentialPublicKey } from '@atlasauth/pca-webauthn';
import { boxCells, cellInBox, cellOfAction, coordsOfCell, flatIndex, resolveCoords, type CellBox } from './box';
import { cellKey, pickCanary, recordCanary, type CellAt, type NoiseCounts } from './canary';
import { expectedTyped, normalizeTyped, partialError, renderCard, type CardResponse, type ClarifyReason, type TierEvidence, type TrustedCard, type Unit } from './card';
import { parseClarifyRequest, planClarification, type ClarifyVerdict } from './clarify';
import { admissionPolicy, DEFAULT_FATIGUE, doubleConfirmed, noiseState, type ConfirmationRecord, type FatigueModel, type SlidingWindowCounter } from './fatigue';
import { DEFAULT_FRICTION_THRESHOLDS, frictionFor, type FrictionThresholds, type ParamProvenance, type Sensitivity } from './friction';
import {
  actionValuesOf,
  deviceChallenge,
  frictionRank,
  maxFriction,
  MIN_HOLD_MS,
  signIntentAnswer,
  pcaActionDigest,
  typedDigest,
  type ActionValues,
  type AnswerSource,
  type AnswerUx,
  type CellCoords,
  type FrictionTier,
  type PartialSpec,
  type PcaAction,
  type SignedIntentAnswer,
} from './wire';

/**
 * THE TRUSTED QUESTION CHANNEL (§3.4, §3.14). One instance per session, wallet side.
 *
 *  1. SELECTION belongs to the verifier: questions enter only as a site-signed `intent_required` (checked against the
 *     site's discovery keys, the session, the current map digest and the action digest; the wallet re-derives the cell
 *     from its own Ω and the action and refuses on any disagreement), or as a structured agent clarification whose
 *     cell the wallet picks itself (§3.14). Neither path carries agent text.
 *  2. RENDERING belongs to the wallet: `renderCard` (fixed templates); the card digest is signed into the answer.
 *  3. ORDERING belongs to the wallet: friction desc, E[h|c]·μ̃(c) desc, cell index asc. A typed or device question is
 *     always alone on its screen.
 *  4. FRICTION scales with harm (`frictionFor`), never below the site's minimum.
 *  5. CANARIES are inserted with probability ρ and rendered like real questions; their answers only update the noise
 *     counts (T16: this class never hands a canary answer to anything but `onNoise`).
 *  6. CAPS: at most `perSession` (default 6) questions per session and `perHour` (default 12) per hour across the
 *     principal's sessions (a shared sliding-window accumulator). When the estimated false-yes rate passes η_stop the
 *     session is FROZEN: uncertain cells are refused and listed in `summary()` instead.
 *  7. T13: a cell is asked at most once per session (clarified cells count as visited).
 *  8. Under estimated noise an irreversible cell needs two typed/device confirmations on screens at least two apart.
 *
 * What the channel returns for a real answer is the principal-signed observation (M6). Minting the delta grant from it
 * is the V3 wallet module's job (`packages/pca-intent/src/jit.ts`, owned elsewhere); a "no" is a veto the caller
 * pushes to the site.
 */

/** The wallet's view of the effective grant (G^eff_k and the ceilings). */
export interface GrantView {
  /** p_k(c). */
  p(verb: string, idx: readonly number[]): number;
  vetoed(verb: string, idx: readonly number[]): boolean;
  /** Outside G^org ∩ G^site ∩ G^std: never a question (the principal cannot widen a ceiling). */
  outsideCeiling(verb: string, idx: readonly number[]): boolean;
  /** Cells currently in G^eff (for near-boundary canaries). */
  confirmed(): CellAt[];
}

/** A GrantView over a pca-intent learner, with an optional ceiling predicate (true = inside every ceiling). */
export function learnerView(l: IntentLearner, opts: { insideCeiling?: (verb: string, idx: readonly number[]) => boolean } = {}): GrantView {
  const vsOf = (verb: string): VerbSpace => {
    const vs = l.omega.verbs.find((v) => v.verb === verb);
    if (!vs) throw new Error(`learnerView: unknown verb ${verb}`);
    return vs;
  };
  return {
    p: (verb, idx) => l.acceptance(cellRep(vsOf(verb), idx)),
    vetoed: (verb, idx) => l.isVetoed(cellRep(vsOf(verb), idx)),
    outsideCeiling: (verb, idx) => (opts.insideCeiling ? !opts.insideCeiling(verb, idx) : false),
    confirmed: () => l.cells().filter((c) => c.inGrant).map((c) => ({ verb: c.verb, idx: c.cell })),
  };
}

export interface DeviceTrust {
  rpId: string;
  origins: string[];
  credentials: Readonly<Record<string, CredentialPublicKey>>;
}

export interface ChannelOptions {
  omega: Omega;
  session: string;
  /** The current task-map digest (it changes as deltas are minted). */
  mapDigest: () => string;
  principalSecret: Uint8Array;
  /** The site as verified from discovery: origin, display name, and its `intent.schema_keys` (which sign M5). */
  site: { origin: string; name: string; keys: readonly ActionSchemaKey[] };
  statementText?: string;
  units?: Readonly<Record<string, Unit>>;
  /** Value-dependent reversibility of a box (from the signed schema). Default: the verb's. */
  reversibility?: (vs: VerbSpace, box: CellBox) => Reversibility;
  /** Sensitivity of parameters by path (from the signed schema, after the wallet floor). Default: material. */
  sensitivity?: Readonly<Record<string, Sensitivity>>;
  /** Paths of critical identity parameters (party.*, person.*, credential.* semantic types). */
  identityPaths?: readonly string[];
  view: GrantView;
  /**
   * Lift an attempted action into Ω̃: its parameters plus the wallet's own accumulator posts, provenance classes and
   * world values (the V2 trajectory module). Default: `actionValuesOf` (scalar params and the resource only).
   */
  lift?: (a: PcaAction) => ActionValues;
  /** Lift a clarification candidate (already in Ω paths) into Ω̃. Default: identity. */
  liftCandidate?: (a: ActionValues) => ActionValues;
  harm?: HarmModel;
  friction?: FrictionThresholds;
  caps?: { perSession?: number; perHour?: number };
  /** The principal's question counter across sessions (shared instance). */
  hourly: SlidingWindowCounter;
  /** The principal's canary counts (shared across sessions) and where to persist them. */
  noise: () => NoiseCounts;
  onNoise: (n: NoiseCounts) => void;
  fatigue?: FatigueModel;
  rho?: number;
  rand: () => number;
  now: () => number;
  device?: DeviceTrust;
  maxPerScreen?: number;
  /** Cap on the number of cells a single question may cover (bounds the work of E[h|c]). Default 4096. */
  maxBoxCells?: number;
}

type ItemKind = 'real' | 'canary' | 'confirmation';

interface Item {
  id: string;
  kind: ItemKind;
  source: AnswerSource;
  verb: string;
  box: CellBox;
  coords: CellCoords;
  card: TrustedCard;
  action?: ActionValues;
  actionDigest?: string;
  irreversible: boolean;
  expected?: 0 | 1;
  weight: number;
  flat: number;
  expiresAt?: number;
  shownOn?: number;
  /** For a confirmation item: the first answer, and the earliest screen it may appear on. */
  first?: SignedIntentAnswer;
  notBefore?: number;
  /** Was the item a JIT-consent candidate (from intent_required)? */
  jit: boolean;
}

export type RefusalCode =
  | 'bad_site_signature'
  | 'wrong_session'
  | 'stale_map'
  | 'action_mismatch'
  | 'cell_mismatch'
  | 'not_uncertain'
  | 'already_asked'
  | 'frozen'
  | 'cap_session'
  | 'cap_hour'
  | 'cell_too_large'
  | 'bad_request'
  | 'render_failed';

export type Enqueued = { ok: true; questionId: string; friction: FrictionTier } | { ok: false; code: RefusalCode; reason: string };

export interface Screen {
  screen: number;
  kind: 'questions' | 'interstitial';
  questions: { questionId: string; card: TrustedCard }[];
}

export type AnswerResult =
  | { ok: true; kind: 'answer'; answer: SignedIntentAnswer }
  | { ok: true; kind: 'veto'; answer: SignedIntentAnswer }
  | { ok: true; kind: 'canary'; answer: SignedIntentAnswer }
  | { ok: true; kind: 'pending_confirmation'; answer: SignedIntentAnswer }
  | { ok: true; kind: 'confirmed'; answers: [SignedIntentAnswer, SignedIntentAnswer] }
  | { ok: false; code: 'unknown_question' | 'not_shown' | 'bad_response' | 'tier_evidence' | 'typed_mismatch' | 'expired'; reason: string };

export interface ClarifyResult {
  status: 200 | 400 | 429;
  verdicts: ClarifyVerdict[];
  questionId?: string;
  refused?: RefusalCode;
  error?: string;
}

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export class TrustedChannel {
  private readonly o: ChannelOptions;
  private readonly pending = new Map<string, Item>();
  private readonly asked = new Set<string>();
  private readonly canaryUsed = new Set<string>();
  private readonly knownYes: CellAt[] = [];
  private readonly confirmations = new Map<string, ConfirmationRecord[]>();
  private readonly refusedWhileFrozen: { verb: string; coords: CellCoords }[] = [];
  private sessionQuestions = 0;
  private canaries = 0;
  private screenNo = 0;

  constructor(opts: ChannelOptions) {
    this.o = opts;
  }

  private get perSession(): number {
    return this.o.caps?.perSession ?? 6;
  }
  private get perHour(): number {
    return this.o.caps?.perHour ?? 12;
  }
  private get fatigue(): FatigueModel {
    return this.o.fatigue ?? DEFAULT_FATIGUE;
  }

  /** The current noise state (η̄⁺ under load, frozen?). */
  noise() {
    return noiseState(this.o.noise(), this.o.hourly.count(this.o.now()), this.fatigue);
  }

  /** The admission policy the learner should use now (τ, η⁺, η⁻; double confirmation). */
  admission() {
    return admissionPolicy(this.noise(), this.fatigue);
  }

  /** Questions asked so far in this session (the `questions` accumulator of the session root). */
  questionsAsked(): number {
    return this.sessionQuestions;
  }

  private newId(): string {
    let s = 'q_';
    for (let i = 0; i < 10; i++) s += B64U[Math.floor(this.o.rand() * 64) % 64]!;
    return this.pending.has(s) ? this.newId() : s;
  }

  private boxStats(vs: VerbSpace, box: CellBox): { weight: number; meanHarm: number } | null {
    const cells = boxCells(box);
    if (cells.length > (this.o.maxBoxCells ?? 4096)) return null;
    let m = 0;
    let mh = 0;
    for (const idx of cells) {
      const s = cellStats(vs, idx, this.o.harm ?? DEFAULT_HARM);
      m += s.mass;
      mh += s.mass * s.harm;
    }
    return { weight: mh, meanHarm: m > 0 ? mh / m : 0 };
  }

  private frictionOf(vs: VerbSpace, box: CellBox, meanHarm: number, siteMin: FrictionTier | undefined, irreversible: boolean): FrictionTier {
    const provenance: ParamProvenance[] = [];
    let widensIdentity = false;
    vs.dims.forEach((d, k) => {
      if (d.path.startsWith('env.prov.') && d.kind === 'cat') {
        const param = d.path.slice('env.prov.'.length);
        const levels = box[k]!.flatMap((i) => {
          const v = d.values[i]!;
          return (v.kind === 'prefix' ? `${v.value}*` : v.value).split(/[|,]/);
        });
        provenance.push({ path: param, sensitivity: this.o.sensitivity?.[param] ?? 'material', levels });
      }
      if (d.kind === 'cat' && (this.o.identityPaths ?? []).includes(d.path)) {
        // Widening an identity parameter = the box admits a value beyond the confirmed (exact, named) ones.
        if (box[k]!.some((i) => d.values[i]!.kind !== 'exact')) widensIdentity = true;
      }
    });
    const rev = this.o.reversibility ? this.o.reversibility(vs, box) : vs.reversibility;
    let tier = frictionFor({ reversibility: rev, expectedHarm: meanHarm, provenance, widensCriticalIdentity: widensIdentity, ...(siteMin ? { siteMin } : {}) }, this.o.friction ?? DEFAULT_FRICTION_THRESHOLDS).tier;
    if (irreversible && this.admission().doubleConfirmIrreversible) tier = maxFriction(tier, 'typed');
    return tier;
  }

  private render(kind: 'question' | 'clarification', verb: string, coords: CellCoords, friction: FrictionTier, action: ActionValues | undefined, vs: VerbSpace, box: CellBox, reason?: ClarifyReason): { card: TrustedCard; friction: FrictionTier } | null {
    const base = {
      omega: this.o.omega,
      verb,
      coords,
      site: { origin: this.o.site.origin, name: this.o.site.name },
      ...(this.o.statementText !== undefined ? { statementText: this.o.statementText } : {}),
      reversibility: this.o.reversibility ? this.o.reversibility(vs, box) : vs.reversibility,
      ...(this.o.units ? { units: this.o.units } : {}),
      ...(action ? { action } : {}),
      kind,
      ...(reason ? { reason } : {}),
    };
    let r = renderCard({ ...base, friction });
    // A typed question needs a value to type; with none on the card, the only stronger tier is the device.
    if (r.ok && frictionRank(friction) === frictionRank('typed') && !r.card.typed) r = renderCard({ ...base, friction: 'device' });
    return r.ok ? { card: r.card, friction: r.card.friction } : null;
  }

  private gate(): { ok: true } | { ok: false; code: RefusalCode; reason: string } {
    if (this.noise().frozen) return { ok: false, code: 'frozen', reason: 'the estimated false-yes rate is above η_stop: no more questions this session' };
    if (this.sessionQuestions >= this.perSession) return { ok: false, code: 'cap_session', reason: `at most ${this.perSession} questions per session` };
    if (this.o.hourly.count(this.o.now()) >= this.perHour) return { ok: false, code: 'cap_hour', reason: `at most ${this.perHour} questions per hour` };
    return { ok: true };
  }

  private enqueue(it: Omit<Item, 'flat' | 'weight'> & { vs: VerbSpace; weight: number }): void {
    const { vs, ...rest } = it;
    const flat = Math.min(...boxCells(it.box).map((idx) => flatIndex(vs, idx)));
    this.pending.set(it.id, { ...rest, flat });
  }

  private count(): void {
    this.sessionQuestions++;
    if (!this.o.hourly.tryAdd(this.o.now(), Number.MAX_SAFE_INTEGER)) throw new Error('unreachable');
  }

  /** Insert a canary with probability ρ (rendered and ordered like a real question). */
  private maybeCanary(): void {
    const exclude = new Set<string>([...this.canaryUsed, ...[...this.pending.values()].flatMap((p) => boxCells(p.box).map((idx) => cellKey(p.verb, idx)))]);
    const lowHarm = [...this.pending.values()].every((p) => p.kind !== 'real' || frictionRank(p.card.friction) <= frictionRank('hold'));
    const c = pickCanary({
      omega: this.o.omega,
      confirmed: this.o.view.confirmed(),
      knownNo: (verb, idx) => (this.o.view.outsideCeiling(verb, idx) ? 'ceiling' : this.o.view.vetoed(verb, idx) ? 'veto' : null),
      knownYes: this.knownYes,
      exclude,
      rand: this.o.rand,
      ...(this.o.rho !== undefined ? { rho: this.o.rho } : {}),
      lowHarmSession: lowHarm,
      canariesSoFar: this.canaries,
    });
    if (!c) return;
    const vs = this.o.omega.verbs.find((v) => v.verb === c.verb)!;
    const box = c.idx.map((i) => [i]);
    const st = this.boxStats(vs, box);
    if (!st) return;
    const coords = coordsOfCell(vs, c.idx);
    const action = { verb: c.verb, values: cellRep(vs, c.idx).values };
    const friction = this.frictionOf(vs, box, st.meanHarm, undefined, false);
    const r = this.render('question', c.verb, coords, friction, action, vs, box);
    if (!r) return;
    this.canaries++;
    this.canaryUsed.add(cellKey(c.verb, c.idx));
    this.enqueue({ id: this.newId(), kind: 'canary', source: 'elicitation', verb: c.verb, box, coords, card: r.card, action, irreversible: false, expected: c.expected, weight: st.weight, jit: false, vs });
  }

  /**
   * Receive a site-signed intent_required (delivered directly, or relayed unchanged by the agent) together with the
   * action the agent attempted. Every check fails closed.
   */
  receive(ir: SignedIntentRequired, ctx: { action: PcaAction }): Enqueued {
    const now = this.o.now();
    const v = verifyIntentRequired(ir, this.o.site.keys, now);
    if (!v.ok) return { ok: false, code: 'bad_site_signature', reason: v.reason };
    if (ir.session !== this.o.session) return { ok: false, code: 'wrong_session', reason: 'the question is for another session' };
    if (ir.map_digest !== this.o.mapDigest()) return { ok: false, code: 'stale_map', reason: 'the question names another map version' };
    if (ctx.action.verb !== ir.cell.verb || pcaActionDigest(ctx.action) !== ir.action_digest) return { ok: false, code: 'action_mismatch', reason: 'the action does not match the signed action digest' };
    const lifted = this.o.lift ? this.o.lift(ctx.action) : actionValuesOf(ctx.action);
    const r = resolveCoords(this.o.omega, ir.cell.verb, ir.cell.coords);
    if (!r.ok) return { ok: false, code: 'cell_mismatch', reason: r.reason };
    const at = cellOfAction(this.o.omega, lifted);
    if (!at || !cellInBox(r.box, at.idx)) return { ok: false, code: 'cell_mismatch', reason: "the action's cell (re-derived by the wallet) is not the cell the site names" };
    const st = this.boxStats(r.vs, r.box);
    if (!st) return { ok: false, code: 'cell_too_large', reason: 'the question covers too many cells' };
    const cells = boxCells(r.box);
    for (const idx of cells) {
      if (this.o.view.outsideCeiling(r.vs.verb, idx)) return { ok: false, code: 'not_uncertain', reason: 'the cell is outside a ceiling: the principal cannot widen it' };
      if (this.o.view.vetoed(r.vs.verb, idx)) return { ok: false, code: 'not_uncertain', reason: 'the cell was vetoed' };
    }
    const pa = this.o.view.p(r.vs.verb, at.idx);
    if (!(pa > 0 && pa < 1)) return { ok: false, code: 'not_uncertain', reason: pa <= 0 ? 'the cell is denied' : 'the cell is already in the grant' };
    if (cells.some((idx) => this.asked.has(cellKey(r.vs.verb, idx)))) return { ok: false, code: 'already_asked', reason: 'a cell is asked at most once per session' };
    const g = this.gate();
    if (!g.ok) {
      if (g.code === 'frozen') this.refusedWhileFrozen.push({ verb: r.vs.verb, coords: ir.cell.coords });
      return g;
    }
    const rev = this.o.reversibility ? this.o.reversibility(r.vs, r.box) : r.vs.reversibility;
    const irreversible = rev === 'irreversible';
    const friction = this.frictionOf(r.vs, r.box, st.meanHarm, ir.friction, irreversible);
    const rendered = this.render('question', ir.cell.verb, ir.cell.coords, friction, lifted, r.vs, r.box);
    if (!rendered) return { ok: false, code: 'render_failed', reason: 'the card could not be rendered' };
    if (this.pending.has(ir.question_id)) return { ok: false, code: 'already_asked', reason: 'duplicate question id' };
    for (const idx of cells) this.asked.add(cellKey(r.vs.verb, idx));
    this.count();
    this.enqueue({ id: ir.question_id, kind: 'real', source: 'elicitation', verb: ir.cell.verb, box: r.box, coords: ir.cell.coords, card: rendered.card, action: lifted, actionDigest: ir.action_digest, irreversible, weight: st.weight, expiresAt: ir.expires_at, jit: true, vs: r.vs });
    this.maybeCanary();
    return { ok: true, questionId: ir.question_id, friction: rendered.friction };
  }

  /**
   * An agent clarification (§3.14): `{candidates: [≤ 8 structured actions], reason}`, no text. Certain cells are
   * answered at once (dry run); among the uncertain ones the wallet picks the most informative and asks it.
   */
  clarify(body: unknown): ClarifyResult {
    const parsed = parseClarifyRequest(body);
    if (!parsed.ok) return { status: 400, verdicts: [], error: parsed.error };
    const st = this.noise();
    const plan = planClarification({
      omega: this.o.omega,
      view: this.o.view,
      candidates: parsed.request.candidates,
      asked: this.asked,
      etaPos: Math.min(0.5 - 1e-9, st.etaPosBar),
      etaNeg: Math.min(0.5 - 1e-9, st.etaNegBar),
      harm: this.o.harm ?? DEFAULT_HARM,
      ...(this.o.liftCandidate ? { lift: this.o.liftCandidate } : {}),
    });
    if (!plan.ask) return { status: 200, verdicts: plan.verdicts };
    const g = this.gate();
    if (!g.ok) return { status: g.code === 'frozen' ? 200 : 429, verdicts: plan.verdicts, refused: g.code };
    const vs = this.o.omega.verbs.find((v) => v.verb === plan.ask!.verb)!;
    const box = plan.ask.idx.map((i) => [i]);
    const stats = this.boxStats(vs, box)!;
    const coords = coordsOfCell(vs, plan.ask.idx);
    const raw = parsed.request.candidates[plan.ask.index]!;
    const action = this.o.liftCandidate ? this.o.liftCandidate(raw) : raw;
    const rev = this.o.reversibility ? this.o.reversibility(vs, box) : vs.reversibility;
    const irreversible = rev === 'irreversible';
    const friction = this.frictionOf(vs, box, stats.meanHarm, undefined, irreversible);
    const rendered = this.render('clarification', vs.verb, coords, friction, action, vs, box, parsed.request.reason);
    if (!rendered) return { status: 200, verdicts: plan.verdicts, refused: 'render_failed' };
    const id = this.newId();
    this.asked.add(cellKey(vs.verb, plan.ask.idx));
    this.count();
    this.enqueue({ id, kind: 'real', source: 'clarification', verb: vs.verb, box, coords, card: rendered.card, action, irreversible, weight: stats.weight, jit: false, vs });
    this.maybeCanary();
    return { status: 200, verdicts: plan.verdicts, questionId: id };
  }

  /** Pending items in display order: friction desc, E[h|c]·μ̃(c) desc, cell index asc, id asc. */
  private ordered(): Item[] {
    return [...this.pending.values()].sort(
      (a, b) => frictionRank(b.card.friction) - frictionRank(a.card.friction) || b.weight - a.weight || a.flat - b.flat || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
    );
  }

  /** The next screen. A typed or device question is always alone; tap/hold questions share up to `maxPerScreen`. */
  nextScreen(): Screen | null {
    const now = this.o.now();
    for (const [id, it] of this.pending) if (it.expiresAt !== undefined && now > it.expiresAt) this.pending.delete(id);
    const items = this.ordered().filter((it) => it.shownOn === undefined);
    if (items.length === 0) return null;
    const next = this.screenNo + 1;
    const eligible = items.filter((it) => it.notBefore === undefined || next >= it.notBefore);
    this.screenNo = next;
    if (eligible.length === 0) return { screen: next, kind: 'interstitial', questions: [] };
    const first = eligible[0]!;
    const picked: Item[] = [first];
    if (frictionRank(first.card.friction) <= frictionRank('hold')) {
      for (const it of eligible.slice(1)) {
        if (picked.length >= (this.o.maxPerScreen ?? 3)) break;
        if (frictionRank(it.card.friction) <= frictionRank('hold')) picked.push(it);
      }
    }
    for (const it of picked) it.shownOn = next;
    return { screen: next, kind: 'questions', questions: picked.map((it) => ({ questionId: it.id, card: it.card })) };
  }

  /** The principal's response to a shown question. */
  answer(questionId: string, response: CardResponse): AnswerResult {
    const it = this.pending.get(questionId);
    if (!it) return { ok: false, code: 'unknown_question', reason: 'no such pending question' };
    if (it.shownOn === undefined) return { ok: false, code: 'not_shown', reason: 'the question was never shown' };
    const now = this.o.now();
    if (it.expiresAt !== undefined && now > it.expiresAt) {
      this.pending.delete(questionId);
      return { ok: false, code: 'expired', reason: 'the question expired' };
    }
    let y: 0 | 1;
    let partial: PartialSpec | undefined;
    if (response.answer === 'no') y = 0;
    else if (response.answer === 'partly') {
      const e = partialError(it.card, response.partial);
      if (e) return { ok: false, code: 'bad_response', reason: e };
      y = 1;
      partial = response.partial;
    } else y = 1;
    const ux: AnswerUx = { tier: it.card.friction, rendered_digest: it.card.rendered_digest, canary: it.kind === 'canary' };
    if (y === 1) {
      const ev = this.tierEvidence(it, response, questionId);
      if (!ev.ok) return ev;
      Object.assign(ux, ev.ux);
    }
    const plainYes = y === 1 && partial === undefined;
    if (it.kind !== 'canary' && it.jit && it.irreversible && plainYes && it.actionDigest && frictionRank(it.card.friction) >= frictionRank('typed')) {
      ux.action_digest = it.actionDigest;
      ux.consent_for_action = true;
    }
    const answer = signIntentAnswer(
      { map_digest: this.o.mapDigest(), session: this.o.session, question_id: questionId, verb: it.verb, cell: it.coords, y, ...(partial ? { partial } : {}), source: it.source, observed_at: now, ux },
      this.o.principalSecret,
    );
    this.pending.delete(questionId);
    if (it.kind === 'canary') {
      this.o.onNoise(recordCanary(this.o.noise(), it.expected!, y));
      return { ok: true, kind: 'canary', answer };
    }
    if (y === 0) return { ok: true, kind: 'veto', answer };
    if (plainYes && frictionRank(it.card.friction) >= frictionRank('typed') && it.box.every((ids) => ids.length === 1)) {
      // A verified high-friction yes: a source of known-yes canaries.
      this.knownYes.push({ verb: it.verb, idx: it.box.map((ids) => ids[0]!) });
    }
    if (plainYes && it.irreversible && this.admission().doubleConfirmIrreversible) {
      const key = `${it.verb}|${JSON.stringify(it.coords)}`;
      const recs = [...(this.confirmations.get(key) ?? []), { screen: it.shownOn, tier: it.card.friction }];
      this.confirmations.set(key, recs);
      if (it.kind === 'confirmation' && it.first && doubleConfirmed(recs)) return { ok: true, kind: 'confirmed', answers: [it.first, answer] };
      if (it.kind === 'confirmation') return { ok: true, kind: 'pending_confirmation', answer };
      // Schedule the second, independent confirmation: at least one other screen in between.
      const second: Item = { ...it, id: this.newId(), kind: 'confirmation', first: answer, notBefore: it.shownOn + 2 };
      delete second.shownOn;
      this.pending.set(second.id, second);
      return { ok: true, kind: 'pending_confirmation', answer };
    }
    return { ok: true, kind: 'answer', answer };
  }

  private tierEvidence(it: Item, response: CardResponse, questionId: string): { ok: true; ux: Partial<AnswerUx> } | Extract<AnswerResult, { ok: false }> {
    const r: TierEvidence = response.answer === 'no' ? {} : response;
    switch (it.card.friction) {
      case 'tap':
        return { ok: true, ux: {} };
      case 'hold':
        if (!(Number.isInteger(r.holdMs) && (r.holdMs as number) >= MIN_HOLD_MS)) return { ok: false, code: 'tier_evidence', reason: `hold for at least ${MIN_HOLD_MS} ms` };
        return { ok: true, ux: { hold_ms: r.holdMs as number } };
      case 'typed': {
        const t = it.card.typed;
        if (!t || !it.action || typeof r.typed !== 'string') return { ok: false, code: 'tier_evidence', reason: 'type the value shown on the card' };
        const want = expectedTyped(it.card, it.action);
        const got = normalizeTyped(r.typed, t.mode, this.o.units?.[t.path]);
        if (want === null || got === null || got !== want) return { ok: false, code: 'typed_mismatch', reason: 'the typed value does not match the card' };
        return { ok: true, ux: { typed_digest: typedDigest(questionId, got) } };
      }
      case 'device': {
        const wa = r.webauthn;
        const dev = this.o.device;
        if (!wa || !dev) return { ok: false, code: 'tier_evidence', reason: 'a security-key assertion is required' };
        const pk = dev.credentials[wa.credential_id];
        const ad = decodeB64uStrict(wa.authenticator_data);
        const cd = decodeB64uStrict(wa.client_data_json);
        const sg = decodeB64uStrict(wa.signature);
        if (!pk || !ad || !cd || !sg) return { ok: false, code: 'tier_evidence', reason: 'unknown credential or malformed assertion' };
        const challenge = deviceChallenge({ questionId, renderedDigest: it.card.rendered_digest, y: 1, ...(it.jit && it.irreversible && it.actionDigest ? { actionDigest: it.actionDigest } : {}) });
        const res = verifyAssertion({ authenticatorData: ad, clientDataJSON: cd, signature: sg, publicKey: pk }, { expectedChallenge: challenge, rpId: dev.rpId, origins: dev.origins, requireUV: true });
        if (!res.ok) return { ok: false, code: 'tier_evidence', reason: `security key: ${res.reason}` };
        return { ok: true, ux: { webauthn: { ...wa } } };
      }
    }
  }

  /** The WebAuthn challenge the wallet UI passes to `navigator.credentials.get` for a shown device-tier question. */
  deviceChallengeFor(questionId: string): string | null {
    const it = this.pending.get(questionId);
    if (!it || it.shownOn === undefined || it.card.friction !== 'device') return null;
    return deviceChallenge({ questionId, renderedDigest: it.card.rendered_digest, y: 1, ...(it.jit && it.irreversible && it.actionDigest ? { actionDigest: it.actionDigest } : {}) });
  }

  /** The end-of-session summary shown instead of questions once the session froze (§3.4 item 6). */
  summary(): { frozen: boolean; refused: { verb: string; coords: CellCoords }[]; asked: number; canaries: number } {
    return { frozen: this.noise().frozen, refused: [...this.refusedWhileFrozen], asked: this.sessionQuestions, canaries: this.canaries };
  }

  /** A stable digest of the channel's pending state (for tests and audit logs). */
  stateDigest(): string {
    return hashCanonical({ d: 'atlas-pca/wallet-channel-state/v1', p: this.ordered().map((i) => ({ id: i.id, k: i.kind, d: i.card.rendered_digest })), a: [...this.asked].sort(), n: this.sessionQuestions });
  }
}
