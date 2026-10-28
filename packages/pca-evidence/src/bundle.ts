import {
  hashCanonical,
  pcactnDigest,
  type Capability,
  type InclusionProof,
  type PCActn,
} from '@atlasauth/pca';
import {
  type AccReceipt,
  type ActionSchema,
  type ClassifierVerdict,
  type PcaFact,
  type PcaLabels,
  type PcaOfferSet,
  type SessionRevocationEvidence,
  type SessionRoot,
  type SignedIntentStatement,
} from '@atlasauth/pca/ext/intent';
import { type SignedTreeHead } from '@atlasauth/pca/ext/ledger';
import type { IntentMap } from '@atlasauth/pca-intent';
import type { SignedIntentAnswer } from '@atlasauth/pca-wallet';

/**
 * THE DISPUTE EVIDENCE BUNDLE `pca-intent-evidence` v1 (Intent Layer v2, docs/specs/pca-intent-layer-v2.md §3.11, §4.4).
 *
 * One ordered document that carries everything a card issuer, an arbiter or a regulator needs to REPLAY how an agent's
 * action was authorized: the principal's statement (or its commitment), the session root, the site's signed schema,
 * the task map versions, every signed answer (with its friction tier and rendered-card digest), the canary labels,
 * every principal-signed delta grant, the PCActns, the site's verdicts, the accumulator events, the effect records and
 * the revocation epochs. Each element is signed by its own author; the bundle itself is NOT signed: it is evidence to be
 * re-verified by every reader (`verifyEvidenceBundle`), never trusted.
 *
 * Decisions this package makes where the spec leaves the wire open (all documented in the README of the findings):
 *  - `root_grant` (G_0) is a member: the delta chain's `prev` of seq 1 is G_0's id, so the verifier needs it.
 *  - `canary_labels`: the KNOWN label of every canary answer (the wallet chose the canary because its label was known:
 *    a ceiling or veto cell is a known "no", an earlier verified high-friction yes is a known "yes"). The claimed
 *    `canaries` summary is never trusted: it is recomputed from the answers and these labels, and a mismatch fails.
 *  - The bundle digest ({@link evidenceDigest}) commits to the COMMITMENTS-ONLY normal form ({@link commitmentForm}):
 *    `anchors` are dropped (an anchor names the digest, so it cannot be inside it), and every optional plaintext OPENING
 *    of a committed value is removed: the statement is reduced to `{commit}`, each map entry to `{seq, commit,
 *    disclosed?}`, and each effect record loses its raw `params` (an opening of the PCActn's signed `params_digest`).
 *    So the anchored digest survives withholding openings (privacy: the principal may decline to reveal the statement
 *    or the map, the site may redact the params), and an opening that IS revealed is verified against its commitment
 *    separately, where a wrong opening FAILS its own finding: the statement via `intentRef(opening) === commit`, a map
 *    via `intentMapDigest(map) === commit`, the params via `paramsDigest(params) === action.params_digest`.
 *  - Effect records carry the raw `params` so the verifier can bind them to the PCActn's signed `params_digest`.
 *  - `offer_sets` and `labels` (site-signed offer sets and label receipts, V6 / V14) are members, verified with the core
 *    verifiers like the facts and classifier verdicts.
 *
 * Every artifact type with a core format is the core type from `@atlasauth/pca` (session root, action schema,
 * reservation receipt, fact, offer set, label receipt, classifier verdict, session revocation evidence).
 */

export const EVIDENCE_DOMAIN = 'atlas-pca/intent-evidence/v1';

export interface MapEntry {
  seq: number;
  /** The map digest (or the salted Merkle `map_commit` of a private map). */
  commit: string;
  /** The full map, when the principal (or the escrow) revealed it: it is then replayed. */
  map?: IntentMap;
  /** Names of disclosed leaves of a committed map (selective disclosure, V15). */
  disclosed?: string[];
}

export interface CanaryLabel {
  question_id: string;
  label: 0 | 1;
}

export interface CanarySummary {
  asked: number;
  false_yes: number;
  false_no: number;
}

/** A site verdict record (V3 format; verified through the `verdict` port). */
export interface VerdictRecord {
  pcactn_digest: string;
  allow: boolean;
  reasons?: string[];
  [k: string]: unknown;
}

export interface AccumulatorEvent {
  /** Accumulator id from the session root. */
  acc: string;
  post: number;
  pcactn_digest: string;
  /** seq of the admitting grant (0 = G_0, k = D_k). */
  delta?: number;
  status?: 'reserved' | 'committed' | 'released' | 'reverted';
}

export interface AccumulatorRecord {
  holder: 'site_local' | 'sequenced';
  events: AccumulatorEvent[];
  /** Sequencer reservation receipts (core `pca-acc-receipt`). */
  receipts?: AccReceipt[];
  /** The sequencers' root-signed key sets the receipts' `kid`s resolve in (core `pca-sequencer-keys`). */
  sequencer_keys?: unknown[];
}

/** A site effect record (V9 has no core format yet: its signature is verified through the `effect` port). */
export interface EffectRecord {
  pcactn_digest: string;
  /** The raw request params, bound to the PCActn's signed `params_digest`. */
  params?: Record<string, unknown>;
  /** The amount the site charged and the parameter path that bounds it (e.g. `action.params.total`). */
  charged?: { amount: number; ref: string };
  pre?: Record<string, string>;
  post?: Record<string, string>;
  /** Monitored variables outside the write set that changed (§2.9). Non-empty = a divergence. */
  frame_violations?: string[];
  sig?: unknown;
  [k: string]: unknown;
}

export interface AnchorEntry {
  kind: 'evidence' | 'schema' | 'statement' | 'map' | 'observation';
  digest: string;
  index: number;
  proof: InclusionProof;
  signed_tree_head: SignedTreeHead;
}

export interface EvidenceBundle {
  v: 1;
  kind: 'pca-intent-evidence';
  subject: { pcactn_digest: string; aud: string; session: string };
  statement: { commit: string; opening?: SignedIntentStatement };
  session_root: SessionRoot;
  schema: { doc: ActionSchema; anchor?: { log: string; index: number; head: string } };
  root_grant: Capability;
  maps: MapEntry[];
  answers: SignedIntentAnswer[];
  canary_labels: CanaryLabel[];
  canaries: CanarySummary;
  deltas: Capability[];
  pcactns: PCActn[];
  verdicts: VerdictRecord[];
  accumulator: AccumulatorRecord;
  facts?: PcaFact[];
  classifier?: ClassifierVerdict[];
  offer_sets?: PcaOfferSet[];
  labels?: PcaLabels[];
  effects: EffectRecord[];
  settlements?: unknown[];
  revocation_epochs: SessionRevocationEvidence[];
  anchors: AnchorEntry[];
}

export type EvidenceParts = Omit<EvidenceBundle, 'v' | 'kind'>;

const TOP_KEYS = [
  'v', 'kind', 'subject', 'statement', 'session_root', 'schema', 'root_grant', 'maps', 'answers', 'canary_labels', 'canaries',
  'deltas', 'pcactns', 'verdicts', 'accumulator', 'facts', 'classifier', 'offer_sets', 'labels', 'effects', 'settlements', 'revocation_epochs', 'anchors',
] as const;

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);
const plain = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

function closed(o: unknown, keys: readonly string[], where: string): string | null {
  if (!isObj(o)) return `${where} must be an object`;
  for (const k of Object.keys(o)) if (!keys.includes(k)) return `${where}: unknown member "${k}"`;
  return null;
}

/** Closed-member shape validation (unknown members are refused at every level the bundle owns). */
export function bundleShapeError(b: unknown): string | null {
  const top = closed(b, TOP_KEYS, 'bundle');
  if (top) return top;
  const x = b as Record<string, unknown>;
  if (x.v !== 1 || x.kind !== 'pca-intent-evidence') return 'not a pca-intent-evidence v1 bundle';
  const subj = closed(x.subject, ['pcactn_digest', 'aud', 'session'], 'subject');
  if (subj) return subj;
  const s = x.subject as Record<string, unknown>;
  if (typeof s.pcactn_digest !== 'string' || typeof s.aud !== 'string' || typeof s.session !== 'string') return 'subject members must be strings';
  const st = closed(x.statement, ['commit', 'opening'], 'statement');
  if (st) return st;
  if (typeof (x.statement as Record<string, unknown>).commit !== 'string') return 'statement.commit must be a string';
  const sr = x.session_root;
  if (!isObj(sr) || sr.v !== 1 || sr.kind !== 'pca-intent-session') return 'session_root is not a pca-intent-session v1';
  if (typeof sr.session !== 'string' || typeof sr.intent_ref !== 'string' || !isInt(sr.expires_at)) return 'session_root is missing session / intent_ref / expires_at';
  if (!Array.isArray(sr.principals) || sr.principals.length === 0 || !sr.principals.every((p) => isObj(p) && typeof p.key === 'string')) return 'session_root.principals must be a non-empty key list';
  const sc = closed(x.schema, ['doc', 'anchor'], 'schema');
  if (sc) return sc;
  const doc = (x.schema as Record<string, unknown>).doc;
  if (!isObj(doc) || doc.kind !== 'pca-action-schema' || !isObj(doc.sig)) return 'schema.doc is not a signed pca-action-schema';
  if (!isObj(x.root_grant)) return 'root_grant must be a capability';
  for (const k of ['maps', 'answers', 'canary_labels', 'deltas', 'pcactns', 'verdicts', 'effects', 'revocation_epochs', 'anchors'] as const) {
    if (!Array.isArray(x[k])) return `${k} must be an array`;
  }
  for (const k of ['facts', 'classifier', 'offer_sets', 'labels', 'settlements'] as const) if (x[k] !== undefined && !Array.isArray(x[k])) return `${k} must be an array`;
  for (const [i, m] of (x.maps as unknown[]).entries()) {
    const e = closed(m, ['seq', 'commit', 'map', 'disclosed'], `maps[${i}]`);
    if (e) return e;
    const mm = m as Record<string, unknown>;
    if (!isInt(mm.seq) || mm.seq < 0 || typeof mm.commit !== 'string') return `maps[${i}] needs an integer seq and a commit`;
  }
  for (const [i, c] of (x.canary_labels as unknown[]).entries()) {
    const e = closed(c, ['question_id', 'label'], `canary_labels[${i}]`);
    if (e) return e;
    const cc = c as Record<string, unknown>;
    if (typeof cc.question_id !== 'string' || (cc.label !== 0 && cc.label !== 1)) return `canary_labels[${i}] is malformed`;
  }
  const cs = closed(x.canaries, ['asked', 'false_yes', 'false_no'], 'canaries');
  if (cs) return cs;
  const cn = x.canaries as Record<string, unknown>;
  if (![cn.asked, cn.false_yes, cn.false_no].every((n) => isInt(n) && (n as number) >= 0)) return 'canaries counts must be non-negative integers';
  const ac = closed(x.accumulator, ['holder', 'events', 'receipts', 'sequencer_keys'], 'accumulator');
  if (ac) return ac;
  const acc = x.accumulator as Record<string, unknown>;
  if (acc.holder !== 'site_local' && acc.holder !== 'sequenced') return 'accumulator.holder must be site_local or sequenced';
  if (!Array.isArray(acc.events)) return 'accumulator.events must be an array';
  for (const [i, ev] of acc.events.entries()) {
    const e = closed(ev, ['acc', 'post', 'pcactn_digest', 'delta', 'status'], `accumulator.events[${i}]`);
    if (e) return e;
    const evv = ev as Record<string, unknown>;
    if (typeof evv.acc !== 'string' || !isInt(evv.post) || evv.post < 0 || typeof evv.pcactn_digest !== 'string') return `accumulator.events[${i}] is malformed`;
    if (evv.delta !== undefined && !(isInt(evv.delta) && evv.delta >= 0)) return `accumulator.events[${i}].delta must be a non-negative integer`;
  }
  if (acc.receipts !== undefined && !Array.isArray(acc.receipts)) return 'accumulator.receipts must be an array';
  if (acc.sequencer_keys !== undefined && !Array.isArray(acc.sequencer_keys)) return 'accumulator.sequencer_keys must be an array';
  for (const [i, r] of (x.revocation_epochs as unknown[]).entries()) {
    const e = closed(r, ['epoch', 'revoked'], `revocation_epochs[${i}]`);
    if (e) return e;
    const rr = r as Record<string, unknown>;
    if (!isObj(rr.epoch) || !Array.isArray(rr.revoked)) return `revocation_epochs[${i}] needs an epoch and its revoked list`;
  }
  for (const [i, a] of (x.anchors as unknown[]).entries()) {
    const e = closed(a, ['kind', 'digest', 'index', 'proof', 'signed_tree_head'], `anchors[${i}]`);
    if (e) return e;
  }
  for (const [i, ef] of (x.effects as unknown[]).entries()) {
    if (!isObj(ef) || typeof ef.pcactn_digest !== 'string') return `effects[${i}] needs a pcactn_digest`;
  }
  return null;
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const seqOf = (c: Capability): number => {
  const cv = c.caveats.find((k) => k.type === 'intent_session');
  return cv && isInt(cv.seq) ? cv.seq : Number.MAX_SAFE_INTEGER;
};

/**
 * Deterministic normal form. Members that are SETS (answers, deltas, PCActns, verdicts, effects, epochs, anchors, maps,
 * canary labels) are sorted by a content key, so two exports of the same evidence produce the same bytes whatever the
 * order the site stored them in. `accumulator.events` is a SEQUENCE (admission order) and is never reordered.
 */
export function normalizeBundle(b: EvidenceBundle): EvidenceBundle {
  const x = plain(b);
  const key = (v: unknown) => hashCanonical(v);
  x.maps.sort((a, c) => a.seq - c.seq || cmp(a.commit, c.commit));
  x.answers.sort((a, c) => a.observed_at - c.observed_at || cmp(a.question_id, c.question_id) || cmp(a.sig, c.sig));
  x.canary_labels.sort((a, c) => cmp(a.question_id, c.question_id) || a.label - c.label);
  x.deltas.sort((a, c) => seqOf(a) - seqOf(c) || cmp(a.id, c.id));
  x.pcactns.sort((a, c) => a.iat - c.iat || a.counter - c.counter || cmp(pcactnDigest(a), pcactnDigest(c)));
  x.verdicts.sort((a, c) => cmp(a.pcactn_digest, c.pcactn_digest) || cmp(key(a), key(c)));
  // Sorted without the params opening, so withholding an opening never reorders the commitments-only form.
  const effectKey = (e: EffectRecord) => {
    const { params: _p, ...k } = e;
    void _p;
    return key(k);
  };
  x.effects.sort((a, c) => cmp(a.pcactn_digest, c.pcactn_digest) || cmp(effectKey(a), effectKey(c)));
  // Issue order (not epoch number): a rollback, an epoch issued later with a lower number, must stay visible.
  x.revocation_epochs.sort((a, c) => a.epoch.issued_at - c.epoch.issued_at || a.epoch.epoch - c.epoch.epoch || cmp(key(a), key(c)));
  x.anchors.sort((a, c) => cmp(a.kind, c.kind) || a.index - c.index || cmp(a.digest, c.digest));
  const sortSet = (arr: unknown[] | undefined) => arr?.sort((a, c) => cmp(key(a), key(c)));
  sortSet(x.facts);
  sortSet(x.classifier);
  sortSet(x.offer_sets);
  sortSet(x.labels);
  sortSet(x.settlements);
  if (x.accumulator.receipts) x.accumulator.receipts.sort((a, c) => cmp(key(a), key(c)));
  return x;
}

/** Assemble a bundle in normal form. Throws on a malformed part (the exporter's bug, not evidence). */
export function buildEvidenceBundle(parts: EvidenceParts): EvidenceBundle {
  const b = normalizeBundle({ v: 1, kind: 'pca-intent-evidence', ...parts });
  const bad = bundleShapeError(b);
  if (bad) throw new Error(`buildEvidenceBundle: ${bad}`);
  return b;
}

/**
 * The commitments-only normal form (see the header): no anchors, no statement opening, no full maps, no effect params.
 * Everything else, every signed artifact and every claim, stays in.
 */
export function commitmentForm(b: EvidenceBundle): Omit<EvidenceBundle, 'anchors'> {
  const n = normalizeBundle(b);
  const { anchors: _anchors, ...rest } = n;
  void _anchors;
  return {
    ...rest,
    statement: { commit: n.statement.commit },
    maps: n.maps.map((m) => ({ seq: m.seq, commit: m.commit, ...(m.disclosed !== undefined ? { disclosed: m.disclosed } : {}) })),
    effects: n.effects.map((e) => {
      const { params: _params, ...kept } = e;
      void _params;
      return kept;
    }),
  };
}

/** The bundle's content address: H over the commitments-only normal form. Anchors, SCITT and the CLI use it. */
export function evidenceDigest(b: EvidenceBundle): string {
  return hashCanonical({ d: EVIDENCE_DOMAIN, b: commitmentForm(b) });
}
