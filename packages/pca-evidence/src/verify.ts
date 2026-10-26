import {
  decodeB64uStrict,
  hashCanonical,
  isGroupCondition,
  isLeafCondition,
  paramsDigest,
  pcactnDigest,
  readEnvelope,
  unb64u,
  verifyChain,
  verifyPCActnCore,
  type Capability,
  type Condition,
  type PCActn,
} from '@atlasauth/pca';
import {
  DEFAULT_REVOCATION_MAX_AGE_S,
  FACT_DOMAIN,
  INTENT_ANCHOR_DOMAIN,
  INTENT_ANCHOR_LOG,
  INTENT_CLASSIFIER_DOMAIN,
  OFFER_SET_DOMAIN,
  accContextFor,
  accValueOf,
  actionSchemaDigest,
  checkSessionRevocation,
  deltaRevocationId,
  grantSessionCaveat,
  intentActionDigest,
  intentRef,
  intentSessionCaveatError,
  mapRevocationId,
  pcactnReservationDigest,
  receiptArithmeticOk,
  sessionRevocationId,
  sessionRootDigest,
  validateClassifierVerdictWire,
  validateFactWire,
  validateOfferSetWire,
  RECEIPT_SKEW_MS,
  verifyReceiptAgainstHolder,
  verifySequencerKeySet,
  sequencerKeySetDigest,
  verifyActionSchema,
  verifyArtifactSig,
  verifyIntentStatement,
  verifyLabels,
  verifySessionRoot,
  type AccumulatorDecl,
  type ActionSchemaKey,
  type ReceiptFreshness,
  type SequencerKeySet,
  type TrackedKeySet,
  type IntentEvent,
  type IntentV2Context,
  type LabelKey,
  type SessionRoot,
} from '@atlasauth/pca/ext/intent';
import { verifyLedgerInclusion, verifyTreeHead } from '@atlasauth/pca/ext/ledger';
import { intentMapDigest, verifyIntentMap } from '@atlasauth/pca-intent';
import { answerRef, deviceChallenge, frictionRank, typedDigest, verifyIntentAnswer, type FrictionTier, type SignedIntentAnswer, type Verdict } from '@atlasauth/pca-wallet';
import { verifyAssertion, type Es256Jwk, type EdDsaJwk } from '@atlasauth/pca-webauthn';
import { bundleShapeError, evidenceDigest, normalizeBundle, type EvidenceBundle } from './bundle';

/**
 * `verifyEvidenceBundle`: deterministic replay of a dispute evidence bundle (spec §3.11). Every finding is RECOMPUTED
 * from the signed artifacts; nothing the bundle claims about itself (the canary summary, the accumulator posts, the
 * verdicts) is taken on trust. The output is a findings report whose text comes from fixed templates, so two readers
 * of the same bundle with the same trust inputs get byte-identical reports (`report_digest`).
 *
 * Three statuses, never mixed: `pass` (re-verified here), `fail` (re-verification refuted the artifact or a claim),
 * `unverified` (this verifier had no way to check it: a format with no core verifier and no port supplied, a committed
 * but unopened map, a missing trust key). `unverified` is never reported as `pass`: `complete` is false whenever one is
 * present.
 *
 * Core verifiers from `@atlasauth/pca` are the DEFAULT for every artifact that has one: the session root
 * (`verifySessionRoot`, `sessionRootDigest`), the action schema (`verifyActionSchema`, `actionSchemaDigest`), the
 * `intent_session` grant caveat (`intentSessionCaveatError`), reservation receipts (`verifyReceiptAgainstHolder`,
 * `receiptArithmeticOk`), oracle facts, offer sets, classifier verdicts and label receipts (their wire validators plus the
 * pinned-key artifact signature), session revocation (`checkSessionRevocation`), and the subject's JIT-consent digest
 * (`intentActionDigest`). A `trust.verifiers.<name>` port OVERRIDES the default. Artifacts with no core format yet (effect
 * records, site verdicts, settlements) are checked only through their port.
 */

export const EVIDENCE_REPORT_DOMAIN = 'atlas-pca/intent-evidence-report/v1';

export type FindingStatus = 'pass' | 'fail' | 'unverified';

export interface Finding {
  code: FindingCode;
  status: FindingStatus;
  text: string;
  refs: string[];
}

/** A verifier for one artifact. For artifacts with a core verifier it overrides the default. */
export type Port<T> = (artifact: T, bundle: EvidenceBundle) => Verdict;

export interface CredentialKey {
  publicKey: Es256Jwk | EdDsaJwk;
  rpId: string;
  origins: string[];
}

export interface EvidenceTrust {
  /** Site keys (discovery `intent.schema_keys`): the action schema, and (by kid) offer sets and label receipts. */
  siteKeys?: ActionSchemaKey[];
  /**
   * PINNED principal keys, obtained OUT OF BAND (the cardholder's account record, the wallet's enrolment): the only way a
   * bundle is attributed to a known principal. Without pins the bundle's self-signed session root names its own
   * principals, so a fully fabricated bundle is internally consistent: attribution is then `unverified` and `ok` is
   * false. Closed and typed: `{key, pq_pk?}`, keys canonical base64url (32 bytes).
   */
  principals?: PinnedPrincipal[];
  /** Override the session-root reference (default: core `sessionRootDigest`). */
  sessionRootDigest?: string;
  /** Minimum friction tier per verb for a non-canary "yes". */
  minTier?: Record<string, FrictionTier>;
  /** Tier a JIT consent for an irreversible action needs. Default `typed`. */
  jitTier?: FrictionTier;
  /** Typed values per question id (from the action, as the site recomputes them) to re-derive `typed_digest`. */
  typedValues?: Record<string, string>;
  /** Registered authenticators by credential id, for device-tier answers. */
  credentials?: Record<string, CredentialKey>;
  /** Known canary labels; override the bundle's `canary_labels`. */
  canaryLabels?: Record<string, 0 | 1>;
  /** Pinned oracle keys by oracle id, for world facts. */
  oracleKeys?: Record<string, string>;
  /** Pinned classifier judge keys. */
  judges?: string[];
  /** Pinned label-receipt keys; default: `siteKeys` under the schema's `site`. */
  labelKeys?: LabelKey[];
  /** The intent anchor log's guardian and instance. */
  anchorGuardian?: { public: string; instance: string };
  /**
   * Rule-15 freshness bounds, as core `policy.acc` (closed; non-negative safe integers, in seconds). Absent members take
   * the core defaults (receipts 900 s, key sets 3600 s). An invalid value fails the whole replay closed.
   */
  acc?: AccTrust;
  verifiers?: {
    sessionRoot?: Port<SessionRoot>;
    schema?: Port<unknown>;
    receipt?: Port<unknown>;
    fact?: Port<unknown>;
    classifier?: Port<unknown>;
    offerSet?: Port<unknown>;
    labels?: Port<unknown>;
    effect?: Port<unknown>;
    verdict?: Port<unknown>;
    settlement?: Port<unknown>;
  };
}

export interface PinnedPrincipal {
  key: string;
  /** The principal's pinned PQ key, for a PQ / hybrid principal suite: it must equal the session root's `pq_pk`. */
  pq_pk?: string;
}

/** `{ [key]: pq_pk }` from the reader's pinned principals (own properties only; no prototype); `{}` when none are pinned. */
function readerPqPins(principals: readonly PinnedPrincipal[] | undefined): Record<string, string> {
  const out = Object.create(null) as Record<string, string>;
  for (const p of principals ?? []) if (typeof p.pq_pk === 'string') out[p.key] = p.pq_pk;
  return out;
}

/** Validate `trust.principals`: a non-empty array of closed `{key, pq_pk?}` with canonical keys. Null = valid. */
export function principalsTrustError(p: unknown): string | null {
  if (p === undefined) return null;
  if (!Array.isArray(p) || p.length === 0) return 'trust.principals must be a non-empty array of {key, pq_pk?}';
  for (const [i, x] of p.entries()) {
    if (x === null || typeof x !== 'object' || Array.isArray(x)) return `trust.principals[${i}] must be an object {key, pq_pk?}`;
    for (const k of Object.keys(x)) if (k !== 'key' && k !== 'pq_pk') return `trust.principals[${i}]: unknown member '${k}'`;
    const o = x as Record<string, unknown>;
    if (decodeB64uStrict(o.key, 32) === null) return `trust.principals[${i}].key must be canonical base64url (32 bytes)`;
    if (o.pq_pk !== undefined && decodeB64uStrict(o.pq_pk) === null) return `trust.principals[${i}].pq_pk must be canonical base64url`;
  }
  return null;
}

export interface AccTrust {
  max_receipt_age_s?: number;
  max_keyset_age_s?: number;
}

/** Validate `trust.acc` like core `policy.acc`: closed members, non-negative safe integers. Null = valid. */
export function accTrustError(a: unknown): string | null {
  if (a === undefined) return null;
  if (a === null || typeof a !== 'object' || Array.isArray(a)) return 'trust.acc must be an object';
  for (const [k, v] of Object.entries(a)) {
    if (k !== 'max_receipt_age_s' && k !== 'max_keyset_age_s') return `trust.acc: unknown member '${k}'`;
    if (!(typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0))) return `trust.acc.${k} must be a non-negative safe integer`;
  }
  return null;
}

export interface FindingsSummary {
  /** `G_0` or `D_<k>`: the grant that admitted the subject action. */
  admitted_under: string | null;
  principal_keys: string[];
  answers: { total: number; yes: number; no: number; partial: number; canaries: number };
  refusals: string[];
  consent: { question_id: string; tier: FrictionTier; signer: string } | null;
  charged: { amount: number; bound: number } | null;
  canary_accuracy: { correct: number; asked: number };
  /** Attribution: whether the signing session-root keys are pinned, and the keys to check out of band when not. */
  attribution: { pinned: boolean; keys_to_check: string[] };
  proven: string[];
  not_proven: string[];
}

export interface FindingsReport {
  /** Verified AND attributed: consistent, and every signing session-root key is pinned by the reader. */
  ok: boolean;
  /** Internally consistent: no finding failed (whoever made the keys). */
  consistent: boolean;
  /** Attributed to pinned principal keys (`principal.pinned` passed). */
  attributed: boolean;
  complete: boolean;
  /** The bundle digest (`evidenceDigest`), or null when the bundle is malformed. */
  digest: string | null;
  findings: Finding[];
  summary: FindingsSummary;
  /** H(report): equal for every reader with the same trust inputs. */
  report_digest: string;
}

// ---- fixed templates ------------------------------------------------------------------------------------------------

const TEMPLATES = {
  'shape': 'The bundle is well formed (pca-intent-evidence v1, closed members)',
  'principal.pinned': "Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)",
  'trust.principals': 'The pinned principal keys (trust.principals) are well formed',
  'statement.commit': 'The session root commits to the intent statement the bundle names',
  'statement.opening': 'The opened statement is signed by a principal and hashes to the committed ref',
  'session_root.signature': 'The session root is signed by one of its principal keys',
  'schema.signature': 'The action schema is signed by a site key',
  'schema.digest': 'The session root binds this action schema',
  'schema.anchor': 'The action schema is anchored in a transparency log',
  'map.replay': 'The task map replays to its committed digest',
  'root_grant': 'The root intent grant G_0 is principal-signed and bound to the session',
  'delta.signature': 'The delta grant is a root capability signed by a principal of the session',
  'delta.chain': 'The delta grant chains to the session (session, seq, prev, root)',
  'delta.backed': 'Every delta grant is backed by a principal "yes" answer',
  'answer.signature': 'The answer is signed by a principal of the session, for this session',
  'answer.map': 'The answer refers to a map version in the bundle',
  'answer.tier': 'The answer meets the site minimum friction tier for the verb',
  'answer.typed': 'The typed-tier value re-derives the signed typed digest',
  'answer.device': 'The device-tier WebAuthn assertion verifies with user verification',
  'canaries.summary': 'The canary summary equals the one recomputed from the signed canary answers',
  'pcactn.verify': 'The PCActn verifies (signature, chain, audience, validity at its issue time)',
  'pcactn.root': "The PCActn's root capability is G_0 or a bundled delta grant",
  'pcactn.session': "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
  'subject.present': 'The subject PCActn is in the bundle',
  'jit.consent': 'The irreversible subject action carries a principal JIT consent bound to its exact action digest',
  'accumulator.declared': 'The accumulator is declared in the session root',
  'accumulator.arithmetic': 'The accumulator posts are the running values of the counted events',
  'accumulator.cap': "Every accumulator post is within the admitting grant's cap",
  'accumulator.receipts': 'The sequencer reservation receipt verifies and is consistent',
  'acc.keysets.equivocation': 'No two different sequencer key sets share one root and version',
  'acc.keysets': "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
  'trust.acc': 'The verifier freshness configuration (trust.acc) is well formed',
  'effect.binding': "The effect record is bound to the PCActn's signed params",
  'effect.charged': 'The charged amount is within the confirmed value',
  'effect.frame': 'No monitored state outside the write set changed',
  'effect.signature': 'The effect record is signed by the site',
  'verdict.signature': 'The site verdict record verifies',
  'fact.signature': 'The oracle fact verifies under a pinned oracle key',
  'classifier.signature': 'The classifier verdict verifies under a pinned judge key',
  'offer_set.signature': 'The offer set is signed by a site key, for this session',
  'labels.signature': 'The label receipt is signed by a pinned site key, for this session',
  'settlement.signature': 'The settlement record verifies',
  'revocation.history': 'The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)',
  'revocation.epoch': 'A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time',
  'anchor.inclusion': 'The anchored artifact is included under a guardian-signed head of the intent log',
} as const;

export type FindingCode = keyof typeof TEMPLATES;

const STATUS_TEXT: Record<FindingStatus, string> = { pass: 'verified', fail: 'REFUTED', unverified: 'not verified here' };

const NOT_PROVEN = [
  'That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.',
  "That the site's signed schema describes what its endpoints really do (SCH).",
  "That the site's effect records and any oracle facts are true (EFF, ORC).",
  'Acceptance of this bundle by any card network, court or regulator.',
];

class Findings {
  readonly list: Finding[] = [];
  add(code: FindingCode, status: FindingStatus, refs: string[] = [], detail?: string): void {
    const text = `${TEMPLATES[code]}: ${STATUS_TEXT[status]}${detail ? ` (${detail})` : ''}.`;
    this.list.push({ code, status, text, refs });
  }
  verdict(code: FindingCode, v: Verdict, refs: string[] = []): void {
    if (v.ok) this.add(code, 'pass', refs);
    else this.add(code, 'fail', refs, v.reason);
  }
  /** Run `port` if supplied, else the core default; with neither, the artifact stays unverified. */
  check<T>(code: FindingCode, port: Port<T> | undefined, core: (() => Verdict | null) | undefined, artifact: T, bundle: EvidenceBundle, refs: string[], what: string): void {
    let v: Verdict | null;
    try {
      v = port ? port(artifact, bundle) : core ? core() : null;
    } catch (e) {
      v = { ok: false, reason: `verifier threw: ${(e as Error).message}` };
    }
    if (v === null) this.add(code, 'unverified', refs, `no verifier for ${what}`);
    else this.verdict(code, v, refs);
  }
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const nul = (e: string | null): Verdict => (e === null ? { ok: true } : { ok: false, reason: e });

/** The intent-log leaf for an anchored artifact (the same construction as `intentAnchorCommit`, any kind). */
export function anchorCommit(kind: string, digest: string): string {
  return hashCanonical({ d: INTENT_ANCHOR_DOMAIN, kind, digest });
}

function leafCaps(conds: readonly Condition[] | undefined, path: string): number[] {
  const out: number[] = [];
  for (const c of conds ?? []) {
    if (isLeafCondition(c)) {
      if (c.field !== path || c.ref !== undefined || typeof c.value !== 'number') continue;
      if (c.op === 'lte') out.push(c.value);
      else if (c.op === 'lt') out.push(c.value - 1);
    } else if (isGroupCondition(c) && 'all_of' in c) out.push(...leafCaps(c.all_of, path));
  }
  return out;
}

/**
 * The cap `env.acc.<id>.post <= v` that the grant's envelope states for `verb`: per predicate the tightest bound in its
 * `where` (descending into `all_of`); across predicates (a union) the loosest. Null when a predicate admitting the verb
 * states no bound, or none admits it.
 */
export function capOf(grant: Capability, accId: string, verb: string): number | null {
  const env = readEnvelope(grant);
  if (!env) return null;
  const path = `env.acc.${accId}.post`;
  let cap: number | null = null;
  for (const p of env.predicates) {
    const verbs = Array.isArray(p.verb) ? p.verb.map(String) : [String(p.verb)];
    if (!verbs.includes(verb) && !verbs.includes('*')) continue;
    const caps = leafCaps(p.where, path);
    if (caps.length === 0) return null;
    const m = Math.min(...caps);
    cap = cap === null ? m : Math.max(cap, m);
  }
  return cap;
}

function emptySummary(): FindingsSummary {
  return {
    admitted_under: null,
    principal_keys: [],
    answers: { total: 0, yes: 0, no: 0, partial: 0, canaries: 0 },
    refusals: [],
    consent: null,
    charged: null,
    canary_accuracy: { correct: 0, asked: 0 },
    attribution: { pinned: false, keys_to_check: [] },
    proven: [],
    not_proven: [...NOT_PROVEN],
  };
}

function finish(f: Findings, digest: string | null, summary: FindingsSummary): FindingsReport {
  const findings = [...f.list].sort((a, b) => cmp(a.code, b.code) || cmp(a.refs.join(','), b.refs.join(',')) || cmp(a.status, b.status) || cmp(a.text, b.text));
  const consistent = findings.length > 0 && !findings.some((x) => x.status === 'fail');
  const attributed = findings.some((x) => x.code === 'principal.pinned' && x.status === 'pass') && !findings.some((x) => x.code === 'principal.pinned' && x.status !== 'pass');
  const ok = consistent && attributed;
  const complete = !findings.some((x) => x.status === 'unverified');
  if (consistent && !attributed && summary.attribution.keys_to_check.length) {
    summary.not_proven.unshift(`The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: ${summary.attribution.keys_to_check.join(', ')}.`);
  }
  const unverifiedCodes = [...new Set(findings.filter((x) => x.status === 'unverified').map((x) => x.code))].sort();
  if (unverifiedCodes.length) summary.not_proven.push(`Checked only through a supplied verifier, or not at all: ${unverifiedCodes.join(', ')}.`);
  const body = { ok, consistent, attributed, complete, digest, findings, summary };
  return { ...body, report_digest: hashCanonical({ d: EVIDENCE_REPORT_DOMAIN, r: body }) };
}

/** Replay a bundle. Never throws; a malformed bundle is a report with a failed `shape` finding. */
export async function verifyEvidenceBundle(input: unknown, trust: EvidenceTrust = {}): Promise<FindingsReport> {
  const f = new Findings();
  const summary = emptySummary();
  const te = accTrustError(trust.acc);
  if (te) {
    f.add('trust.acc', 'fail', [], te);
    return finish(f, null, summary);
  }
  const pe = principalsTrustError(trust.principals);
  if (pe) {
    f.add('trust.principals', 'fail', [], pe);
    return finish(f, null, summary);
  }
  const bad = bundleShapeError(input);
  if (bad) {
    f.add('shape', 'fail', [], bad);
    return finish(f, null, summary);
  }
  let b: EvidenceBundle;
  let digest: string;
  try {
    b = normalizeBundle(input as EvidenceBundle);
    digest = evidenceDigest(b);
  } catch (e) {
    f.add('shape', 'fail', [], `not canonicalizable: ${(e as Error).message}`);
    return finish(f, null, summary);
  }
  f.add('shape', 'pass');
  try {
    await replay(b, digest, trust, f, summary);
  } catch (e) {
    f.add('shape', 'fail', [], `replay aborted: ${(e as Error).message}`);
  }
  return finish(f, digest, summary);
}

async function replay(b: EvidenceBundle, digest: string, trust: EvidenceTrust, f: Findings, summary: FindingsSummary): Promise<void> {
  const S = b.session_root;
  const session = b.subject.session;
  // Consistency is checked against the keys the session root names; ATTRIBUTION (below) against the reader's pins.
  const principals = S.principals.map((p) => p.key).sort();
  summary.principal_keys = principals;
  const sRef = trust.sessionRootDigest ?? sessionRootDigest(S);
  const ports = trust.verifiers ?? {};
  // The reader's PQ pins (trust.principals[].pq_pk, obtained out of band; NEVER the bundle's own S.principals): the only
  // keys a pure-PQ / hybrid session root, G_0, a delta or a PCActn root verifies under. Without one such an artifact fails.
  const pqPins = readerPqPins(trust.principals);
  const siteKeys = trust.siteKeys;

  // -- session root -----------------------------------------------------------------------------------------------
  if (S.session !== session) f.add('session_root.signature', 'fail', ['session_root'], 'session root is for another session');
  else f.check('session_root.signature', ports.sessionRoot, () => verifySessionRoot(S, { pqPins }), S, b, ['session_root'], 'the session root');

  // -- statement --------------------------------------------------------------------------------------------------
  f.add('statement.commit', S.intent_ref === b.statement.commit ? 'pass' : 'fail', ['statement']);
  const opening = b.statement.opening;
  if (opening === undefined) f.add('statement.opening', 'unverified', ['statement'], 'the statement was not opened (it stays a commitment)');
  else {
    const v = verifyIntentStatement(opening);
    if (!v.ok) f.add('statement.opening', 'fail', ['statement'], v.reason);
    else if (intentRef(opening) !== b.statement.commit) f.add('statement.opening', 'fail', ['statement'], 'the opening does not hash to the commitment');
    else if (!principals.includes(opening.principal)) f.add('statement.opening', 'fail', ['statement'], 'signed by a key that is not a principal of the session');
    else f.add('statement.opening', 'pass', ['statement']);
  }

  // -- schema -----------------------------------------------------------------------------------------------------
  f.check('schema.signature', ports.schema, siteKeys ? () => verifyActionSchema(b.schema.doc, siteKeys) : undefined, b.schema.doc, b, ['schema'], 'the action schema (no site keys supplied)');
  const schemaDigest = actionSchemaDigest(b.schema.doc);
  f.add('schema.digest', S.schema.digest === schemaDigest && S.schema.aud === b.subject.aud ? 'pass' : 'fail', ['schema']);

  // -- maps -------------------------------------------------------------------------------------------------------
  const mapCommits = new Set(b.maps.map((m) => m.commit));
  for (const m of b.maps) {
    const ref = [`map:${m.seq}`];
    if (!m.map) {
      f.add('map.replay', 'unverified', ref, 'committed map not revealed');
      continue;
    }
    const r = verifyIntentMap(m.map);
    if (!r.ok) f.add('map.replay', 'fail', ref, r.problems.slice(0, 3).join('; '));
    else if (intentMapDigest(m.map) !== m.commit) f.add('map.replay', 'fail', ref, 'the revealed map does not hash to its commit');
    else f.add('map.replay', 'pass', ref);
  }

  // -- grants: G_0 and the delta chain (core intent_session caveat) -------------------------------------------------
  const grants = new Map<string, { cap: Capability; seq: number }>();
  const g0 = b.root_grant;
  {
    const cv = grantSessionCaveat(g0);
    const chain = verifyChain([g0], g0.issuer, { pqPins });
    if (!chain.ok) f.add('root_grant', 'fail', ['G_0'], chain.reason);
    else if (!principals.includes(g0.issuer)) f.add('root_grant', 'fail', ['G_0'], 'not signed by a principal of the session');
    else if (!cv || intentSessionCaveatError(cv) !== null) f.add('root_grant', 'fail', ['G_0'], cv ? (intentSessionCaveatError(cv) ?? '') : 'no intent_session caveat');
    else if (cv.session !== session || cv.seq !== 0 || cv.root !== sRef) f.add('root_grant', 'fail', ['G_0'], 'intent_session caveat does not bind seq 0 of this session root');
    else {
      f.add('root_grant', 'pass', ['G_0']);
      grants.set(g0.id, { cap: g0, seq: 0 });
    }
  }
  let prevId = g0.id;
  b.deltas.forEach((d, i) => {
    const want = i + 1;
    const ref = [`D_${want}`];
    const chain = verifyChain([d], d.issuer, { pqPins });
    if (!chain.ok || !principals.includes(d.issuer) || d.parent !== undefined) {
      f.add('delta.signature', 'fail', ref, !chain.ok ? chain.reason : 'not a principal-signed root capability');
      return;
    }
    f.add('delta.signature', 'pass', ref);
    const cv = grantSessionCaveat(d);
    const nCv = d.caveats.filter((k) => k.type === 'intent_session').length;
    let why: string | null = null;
    if (!cv || nCv !== 1) why = 'no single intent_session caveat';
    else if (intentSessionCaveatError(cv) !== null) why = intentSessionCaveatError(cv);
    else if (cv.session !== session) why = 'bound to another session';
    else if (cv.root !== sRef) why = 'bound to another session root';
    else if (cv.seq !== want) why = `seq ${String(cv.seq)} where ${want} was expected (gap, duplicate or reorder)`;
    else if (cv.prev !== prevId) why = 'prev does not name the previous grant';
    if (why) f.add('delta.chain', 'fail', ref, why);
    else {
      f.add('delta.chain', 'pass', ref);
      grants.set(d.id, { cap: d, seq: want });
    }
    prevId = d.id;
  });

  // -- answers ----------------------------------------------------------------------------------------------------
  const verified: SignedIntentAnswer[] = [];
  for (const a of b.answers) {
    const ref = [`answer:${a.question_id}`];
    const v = verifyIntentAnswer(a, principals);
    if (!v.ok) {
      f.add('answer.signature', 'fail', ref, v.reason);
      continue;
    }
    if (a.session !== session) {
      f.add('answer.signature', 'fail', ref, 'answer for another session');
      continue;
    }
    f.add('answer.signature', 'pass', ref);
    verified.push(a);
    f.add('answer.map', mapCommits.has(a.map_digest) ? 'pass' : 'fail', ref);
    if (a.ux.canary || a.y !== 1) continue;
    const min = trust.minTier?.[a.verb];
    if (min !== undefined) f.add('answer.tier', frictionRank(a.ux.tier) >= frictionRank(min) ? 'pass' : 'fail', ref, `${a.ux.tier} vs minimum ${min}`);
    if (a.ux.tier === 'typed') {
      const tv = trust.typedValues?.[a.question_id];
      if (tv === undefined) f.add('answer.typed', 'unverified', ref, 'the typed value is not known to this verifier');
      else f.add('answer.typed', typedDigest(a.question_id, tv) === a.ux.typed_digest ? 'pass' : 'fail', ref);
    }
    if (a.ux.tier === 'device') {
      const wa = a.ux.webauthn;
      const cred = wa ? trust.credentials?.[wa.credential_id] : undefined;
      if (!wa || !cred) f.add('answer.device', 'unverified', ref, 'unknown authenticator');
      else {
        const r = verifyAssertion(
          { authenticatorData: unb64u(wa.authenticator_data), clientDataJSON: unb64u(wa.client_data_json), signature: unb64u(wa.signature), publicKey: cred.publicKey },
          {
            expectedChallenge: deviceChallenge({ questionId: a.question_id, renderedDigest: a.ux.rendered_digest, y: a.y, ...(a.ux.action_digest !== undefined ? { actionDigest: a.ux.action_digest } : {}) }),
            rpId: cred.rpId,
            origins: cred.origins,
            requireUV: true,
          },
        );
        f.add('answer.device', r.ok ? 'pass' : 'fail', ref, r.ok ? undefined : r.reason);
      }
    }
  }
  const real = verified.filter((a) => !a.ux.canary);
  const canaries = verified.filter((a) => a.ux.canary);
  summary.answers = {
    total: real.length,
    yes: real.filter((a) => a.y === 1 && a.partial === undefined).length,
    no: real.filter((a) => a.y === 0).length,
    partial: real.filter((a) => a.partial !== undefined).length,
    canaries: canaries.length,
  };
  summary.refusals = real.filter((a) => a.y === 0).map((a) => a.question_id).sort();
  const yesCount = real.filter((a) => a.y === 1).length;
  f.add('delta.backed', yesCount >= b.deltas.length ? 'pass' : 'fail', [], `${b.deltas.length} delta(s), ${yesCount} principal yes answer(s)`);

  // -- canaries: recomputed, the claimed summary is never trusted ----------------------------------------------------
  {
    const labels = new Map(b.canary_labels.map((c) => [c.question_id, c.label] as const));
    let falseYes = 0;
    let falseNo = 0;
    let missing = 0;
    for (const a of canaries) {
      const label = trust.canaryLabels?.[a.question_id] ?? labels.get(a.question_id);
      if (label === undefined) missing++;
      else if (label === 0 && a.y === 1) falseYes++;
      else if (label === 1 && a.y === 0) falseNo++;
    }
    summary.canary_accuracy = { correct: canaries.length - missing - falseYes - falseNo, asked: canaries.length };
    const c = b.canaries;
    if (missing > 0) f.add('canaries.summary', 'fail', [], `${missing} canary answer(s) without a known label`);
    else if (c.asked !== canaries.length || c.false_yes !== falseYes || c.false_no !== falseNo) {
      f.add('canaries.summary', 'fail', [], `claimed ${c.asked}/${c.false_yes}/${c.false_no}, recomputed ${canaries.length}/${falseYes}/${falseNo}`);
    } else f.add('canaries.summary', 'pass', [], `${canaries.length} asked, ${falseYes} false yes, ${falseNo} false no`);
  }

  // -- sequencer key sets (rule 15): replayed per root in issue order, versions monotone like core keyset_versions -----
  const freshness = (ks: { tracked: TrackedKeySet | undefined; minV: number | undefined }): ReceiptFreshness => ({
    ...(trust.acc?.max_receipt_age_s !== undefined ? { maxReceiptAgeMs: trust.acc.max_receipt_age_s * 1000 } : {}),
    ...(trust.acc?.max_keyset_age_s !== undefined ? { maxKeySetAgeMs: trust.acc.max_keyset_age_s * 1000 } : {}),
    ...(ks.tracked !== undefined ? { tracked: ks.tracked } : ks.minV !== undefined ? { minKeySetVersion: ks.minV } : {}),
  });
  const rootHolders = new Map<string, Extract<AccumulatorDecl['holder'], { kind: 'sequenced' }>>();
  for (const a of S.accumulators) if (a.holder.kind === 'sequenced') rootHolders.set(a.holder.root, a.holder);
  const acceptedKeySets: SequencerKeySet[] = [];
  /** Signed under a pinned root and not a rollback (equivocating sets included): the tracked-version history. */
  const verifiedKeySets: SequencerKeySet[] = [];
  const equivocatedSlots = new Set<string>();
  {
    const sets = [...(b.accumulator.sequencer_keys ?? [])]
      .map((k) => k as SequencerKeySet)
      .sort((x, y) => (Number(x?.issued_at) || 0) - (Number(y?.issued_at) || 0) || (Number(x?.version) || 0) - (Number(y?.version) || 0) || cmp(hashCanonical(x), hashCanonical(y)));
    const tracked = new Map<string, number>();
    const byVersion = new Map<string, { digest: string; ref: string }>();
    sets.forEach((k, i) => {
      const ref = [`keyset#${i}:${isObj(k) ? String(k.version) : '?'}`];
      const holder = isObj(k) && typeof k.sequencer === 'string' ? rootHolders.get(k.sequencer) : undefined;
      if (!holder) return f.add('acc.keysets', 'fail', ref, 'not signed by a sequencer root the session root pins');
      if (!verifySequencerKeySet(k, holder.root, holder.root_pq_pk)) return f.add('acc.keysets', 'fail', ref, 'the key set does not verify under its pinned root');
      const prev = tracked.get(holder.root);
      if (prev !== undefined && k.version < prev) return f.add('acc.keysets', 'fail', ref, `version ${k.version} rolls back the tracked version ${prev}`);
      // Equivocation (core rule 15, tracked {version, digest}): two DIFFERENT sets under one root and version. Both
      // are refused, so no receipt can rely on either; an identical duplicate (same digest) is not equivocation.
      const slot = `${holder.root}#${k.version}`;
      const digest = sequencerKeySetDigest(k);
      const seen = byVersion.get(slot);
      if (seen && seen.digest !== digest) {
        equivocatedSlots.add(slot);
        verifiedKeySets.push(k);
        return f.add('acc.keysets.equivocation', 'fail', [seen.ref, ref[0]!], `two different key sets under version ${k.version} of one sequencer root`);
      }
      if (!seen) byVersion.set(slot, { digest, ref: ref[0]! });
      verifiedKeySets.push(k);
      tracked.set(holder.root, Math.max(prev ?? 0, k.version));
      acceptedKeySets.push(k);
      f.add('acc.keysets', 'pass', ref);
    });
    for (let i = acceptedKeySets.length - 1; i >= 0; i--) {
      const k = acceptedKeySets[i]!;
      if (equivocatedSlots.has(`${k.sequencer}#${k.version}`)) acceptedKeySets.splice(i, 1);
    }
  }
  // Receipt checks: in force = accepted sets of the holder's root issued by admission (+ the core skew). The tracked
  // state is the newest VERIFIED set issued at or before admission, equivocating ones included: when that version is
  // equivocated there is no trustworthy digest, so only the version floor is passed and, both sets being refused, no
  // receipt admitted from then on can rely on that version (and an older set would be a rollback).
  const keySetsAt = (root: string, t: number): { sets: SequencerKeySet[]; minV: number | undefined; tracked: TrackedKeySet | undefined } => {
    const own = acceptedKeySets.filter((k) => k.sequencer === root);
    const newest = verifiedKeySets.filter((k) => k.sequencer === root && k.issued_at <= t).reduce<SequencerKeySet | undefined>((m, k) => (m === undefined || k.version > m.version ? k : m), undefined);
    const poisoned = newest !== undefined && equivocatedSlots.has(`${root}#${newest.version}`);
    return {
      sets: own.filter((k) => k.issued_at <= t + RECEIPT_SKEW_MS && k.version >= (newest?.version ?? 0)),
      minV: newest?.version,
      // core tracked state {version, digest} (rule 15)
      tracked: newest && !poisoned ? { version: newest.version, digest: sequencerKeySetDigest(newest) } : undefined,
    };
  };

  // -- PCActns ----------------------------------------------------------------------------------------------------
  const byDigest = new Map<string, PCActn>();
  const rootSeq = new Map<string, number>();
  const effectOf = (d: string) => b.effects.find((e) => e.pcactn_digest === d);
  const digestOf = (p: PCActn): string | null => {
    try {
      return pcactnDigest(p);
    } catch {
      return null;
    }
  };
  const grantsBySeq = [...grants.values()].sort((x, y) => x.seq - y.seq).map((g) => g.cap);
  /** Index of the epoch in force at t (the last one issued at or before t, in issue order), or -1. */
  const epochIdxAt = (t: number) => b.revocation_epochs.map((r) => r.epoch.issued_at <= t).lastIndexOf(true);
  // The admitted history, as the site's store held it: one event per accumulator-bearing PCActn, in event order.
  const history: IntentEvent[] = [];
  for (const ev of b.accumulator.events) {
    if (history.some((h) => h.id === ev.pcactn_digest)) continue;
    const p = b.pcactns.find((x) => digestOf(x) === ev.pcactn_digest);
    const params = effectOf(ev.pcactn_digest)?.params;
    if (p && params) history.push({ id: ev.pcactn_digest, verb: p.action.verb, resource: p.action.resource, params, t: p.iat, status: ev.status ?? 'committed' });
  }
  /** The verifier state `decideIntentV2` reads, rebuilt from the bundle (null when the bundle lacks the plaintext params). */
  const v2Context = (p: PCActn, d: string, seq: number | undefined): IntentV2Context | null => {
    const params = effectOf(d)?.params;
    if (!params || seq === undefined) return null;
    const idx = history.findIndex((h) => h.id === d);
    const before = idx >= 0 ? history.slice(0, idx) : history.filter((h) => h.t <= p.iat);
    const acc = accContextFor(S, before, { params, t: p.iat }, { verbs: b.schema.doc.verbs });
    const ri = epochIdxAt(p.iat);
    const rev = ri >= 0 ? b.revocation_epochs[ri] : undefined;
    const revLast = ri > 0 ? b.revocation_epochs[ri - 1] : undefined;
    return {
      params,
      schema: { docs: [b.schema.doc], keys: siteKeys ?? [] },
      session: { root: S, grants: grantsBySeq.slice(0, seq), pq_pins: pqPins, ...(rev ? { revocation: rev } : {}), ...(revLast ? { revocation_last: revLast } : {}) },
      acc: {
        ...acc,
        receipts: b.accumulator.receipts ?? [],
        // the key sets in force at this admission, with the tracked minimum version per root (core keyset_versions)
        sequencer_keys: [...rootHolders.keys()].flatMap((root) => keySetsAt(root, p.iat).sets),
        keyset_versions: Object.fromEntries([...rootHolders.keys()].flatMap((root) => {
          const t = keySetsAt(root, p.iat).tracked;
          return t === undefined ? [] : [[root, t]];
        })),
      },
      ...(trust.acc ? { policy: { acc: trust.acc } } : {}),
    };
  };
  const V2_CHECKS = ['schema', 'intent_session', 'accumulators'];
  for (const p of b.pcactns) {
    const d = digestOf(p);
    if (d === null) {
      f.add('pcactn.verify', 'fail', ['pcactn:?'], 'not canonicalizable');
      continue;
    }
    byDigest.set(d, p);
    const ref = [`pcactn:${d}`];
    const root = Array.isArray(p.cap_chain) ? p.cap_chain[0] : undefined;
    if (!root) {
      f.add('pcactn.verify', 'fail', ref, 'empty capability chain');
      continue;
    }
    const g = grants.get(root.id);
    const sameRoot = g !== undefined && hashCanonical(g.cap) === hashCanonical(root);
    const is = p.intent_session;
    const ctx = is !== undefined && sameRoot ? v2Context(p, d, g.seq) : null;
    // pca-unsafe-root: allow offline replay: the root's authority is pcactn.root (byte-equal to G_0 / a verified delta) plus principal.pinned (trust.principals); a non-Ed25519 root verifies only under the reader's pqPins (trust.principals[].pq_pk), else it is refused (fail closed)
    const r = await verifyPCActnCore(p, { grant: root, grantFromArtifact: true, pqPins, nowEpoch: p.iat, audience: b.subject.aud, ...(ctx ? { intentV2: ctx } : {}) });
    const failed = Object.entries(r.checks).filter(([, st]) => st === 'fail').map(([k]) => k).sort();
    const v1f = failed.filter((k) => !V2_CHECKS.includes(k));
    const v2f = failed.filter((k) => V2_CHECKS.includes(k));
    f.add('pcactn.verify', v1f.length ? 'fail' : 'pass', ref, v1f.length ? `${v1f.join(', ')}: ${r.reason ?? ''}` : undefined);
    if (sameRoot) {
      f.add('pcactn.root', 'pass', ref, g.seq === 0 ? 'G_0' : `D_${g.seq}`);
      rootSeq.set(d, g.seq);
    } else f.add('pcactn.root', 'fail', ref, 'rooted at a grant that is not G_0 or a verified delta of this session');
    if (is !== undefined) {
      let why: string | null = null;
      if (is.session !== session) why = 'another session';
      else if (is.root !== sRef) why = 'another session root';
      else if (is.schema !== schemaDigest) why = 'another schema';
      else if (g && is.seq !== g.seq) why = `seq ${is.seq} but rooted at seq ${g.seq}`;
      else
        for (const c of is.acc ?? []) {
          const ev = b.accumulator.events.find((e) => e.pcactn_digest === d && e.acc === c.id);
          if (!ev || ev.post !== c.post) why = `the signed claim ${c.id}.post = ${c.post} has no matching accumulator event`;
        }
      if (why === null && v2f.length) why = `core v2 checks failed: ${v2f.join(', ')}`;
      if (why !== null) f.add('pcactn.session', 'fail', ref, why);
      else if (!ctx) f.add('pcactn.session', 'unverified', ref, 'the core v2 checks need the plaintext params of the effect record');
      else f.add('pcactn.session', 'pass', ref);
    }
  }
  const subject = byDigest.get(b.subject.pcactn_digest);
  f.add('subject.present', subject ? 'pass' : 'fail', [`pcactn:${b.subject.pcactn_digest}`]);
  const sSeq = rootSeq.get(b.subject.pcactn_digest);
  summary.admitted_under = sSeq === undefined ? null : sSeq === 0 ? 'G_0' : `D_${sSeq}`;

  // -- effects (no core format yet: signature through the port) -------------------------------------------------------
  for (const e of b.effects) {
    const ref = [`effect:${e.pcactn_digest}`];
    const p = byDigest.get(e.pcactn_digest);
    if (!p) {
      f.add('effect.binding', 'fail', ref, 'no such PCActn in the bundle');
      continue;
    }
    if (e.params === undefined) f.add('effect.binding', 'unverified', ref, 'no raw params to bind');
    else f.add('effect.binding', paramsDigest(e.params) === p.action.params_digest ? 'pass' : 'fail', ref);
    if (e.charged) {
      const name = e.charged.ref.startsWith('action.params.') ? e.charged.ref.slice('action.params.'.length) : null;
      const bound = name !== null && e.params ? e.params[name] : undefined;
      if (!isNum(bound) || !isNum(e.charged.amount)) f.add('effect.charged', 'unverified', ref, `no numeric ${e.charged.ref} to compare`);
      else {
        f.add('effect.charged', e.charged.amount <= bound ? 'pass' : 'fail', ref, `${e.charged.amount} vs ${bound}`);
        if (e.pcactn_digest === b.subject.pcactn_digest) summary.charged = { amount: e.charged.amount, bound };
      }
    }
    if (e.frame_violations !== undefined) f.add('effect.frame', e.frame_violations.length === 0 ? 'pass' : 'fail', ref, e.frame_violations.length ? [...e.frame_violations].sort().join(', ') : undefined);
    f.check('effect.signature', ports.effect, undefined, e, b, ref, 'effect records (no core format yet)');
  }

  // -- JIT consent for an irreversible subject action (core action digest) -------------------------------------------
  if (subject && subject.action.reversibility_class === 'irreversible') {
    const ref = [`pcactn:${b.subject.pcactn_digest}`];
    const ad = intentActionDigest(subject.action);
    const need = trust.jitTier ?? 'typed';
    const c = real.find((a) => a.y === 1 && a.ux.consent_for_action === true && a.ux.action_digest === ad && frictionRank(a.ux.tier) >= frictionRank(need));
    if (c) {
      f.add('jit.consent', 'pass', ref, `question ${c.question_id}, ${c.ux.tier} tier`);
      summary.consent = { question_id: c.question_id, tier: c.ux.tier, signer: c.signer };
    } else f.add('jit.consent', 'fail', ref, `no principal yes at ${need} tier or above bound to this action digest`);
  }

  // -- accumulators (core declarations and value rule) ----------------------------------------------------------------
  const decls = new Map<string, AccumulatorDecl>(S.accumulators.map((a) => [a.id, a] as const));
  const schemaVerbs = { verbs: b.schema.doc.verbs };

  const valueOf = (decl: AccumulatorDecl, d: string): number | null => {
    const p = byDigest.get(d);
    const params = effectOf(d)?.params;
    if (!p || !params) return null;
    const v = accValueOf(decl, p.action.verb, params, schemaVerbs);
    return v.ok ? v.val : null;
  };
  const running = new Map<string, number>();
  for (const [i, ev] of b.accumulator.events.entries()) {
    const ref = [`acc:${ev.acc}#${i}`];
    const decl = decls.get(ev.acc);
    if (!decl) {
      f.add('accumulator.declared', 'fail', ref);
      continue;
    }
    const p = byDigest.get(ev.pcactn_digest);
    const counted = ev.status !== 'released' && ev.status !== 'reverted';
    const prev = running.get(ev.acc) ?? 0;
    let expected: number | null = null;
    if (!counted) expected = prev;
    else if (decl.agg === 'count') expected = prev + 1;
    else if (decl.agg === 'sum' || decl.agg === 'max') {
      const val = valueOf(decl, ev.pcactn_digest);
      if (val !== null) expected = decl.agg === 'sum' ? prev + val : Math.max(prev, val);
    }
    if (!p) f.add('accumulator.arithmetic', 'fail', ref, 'event names a PCActn that is not in the bundle');
    else if (expected === null) {
      f.add('accumulator.arithmetic', ev.post >= prev ? 'unverified' : 'fail', ref, ev.post >= prev ? 'contribution not recomputable' : 'post decreased');
    } else f.add('accumulator.arithmetic', ev.post === expected ? 'pass' : 'fail', ref, ev.post === expected ? undefined : `post ${ev.post}, recomputed ${expected}`);
    running.set(ev.acc, counted ? ev.post : prev);
    if (!counted) continue;
    const seq = p ? rootSeq.get(ev.pcactn_digest) : undefined;
    if (ev.delta !== undefined && seq !== undefined && ev.delta !== seq) {
      f.add('accumulator.cap', 'fail', ref, 'the event names a different admitting grant from the PCActn root');
      continue;
    }
    const grant = [...grants.values()].find((g) => g.seq === (seq ?? ev.delta));
    const caps = [grant && p ? capOf(grant.cap, ev.acc, p.action.verb) : null, isNum(decl.domain_max) ? decl.domain_max : null, isNum(decl.cap) ? decl.cap : null].filter((x): x is number => x !== null);
    if (caps.length === 0) f.add('accumulator.cap', 'unverified', ref, 'no cap stated for this accumulator');
    else {
      const cap = Math.min(...caps);
      f.add('accumulator.cap', ev.post <= cap ? 'pass' : 'fail', ref, `post ${ev.post}, cap ${cap}`);
    }
  }
  const receipts = b.accumulator.receipts ?? [];

  if (b.accumulator.holder === 'sequenced' && receipts.length === 0) f.add('accumulator.receipts', 'fail', ['accumulator'], 'a sequenced accumulator without receipts');
  receipts.forEach((r, i) => {
    // null = the signature and freshness held but the contribution cannot be recomputed (params withheld): unverified.
    const core = (): Verdict | null => {
      const decl = decls.get(r.acc);
      if (!decl || decl.holder.kind !== 'sequenced') return { ok: false, reason: 'the receipt names an accumulator that is not sequenced in the session root' };
      const holder = decl.holder;
      if (r.session !== session || r.aud !== b.subject.aud) return { ok: false, reason: 'receipt for another session or audience' };
      const d = [...byDigest.entries()].find(([, p]) => pcactnReservationDigest(p as unknown as Record<string, unknown>) === r.pcactn_digest)?.[0];
      if (d === undefined) return { ok: false, reason: 'the receipt reserves for a PCActn that is not in the bundle' };
      // Rule 15 freshness is judged at ADMISSION time (the reserved PCActn's iat), never at bundle-verification time: the
      // receipt, the key set and the signing key's window must all have been valid when the site admitted the action.
      const admittedAt = byDigest.get(d)!.iat;
      const ks = keySetsAt(holder.root, admittedAt);
      if (!verifyReceiptAgainstHolder(r, holder, ks.sets, admittedAt, freshness(ks))) return { ok: false, reason: 'not signed by a key the pinned sequencer root listed, or not fresh, at admission time' };
      if (!(admittedAt <= r.expires_at)) return { ok: false, reason: 'the receipt had expired when the action was admitted' };
      const val = valueOf(decl, d);
      if (val === null) return null;
      if (!receiptArithmeticOk(decl, r, val)) return { ok: false, reason: 'pre + delta does not give post for the reserved value' };
      return { ok: true };
    };
    f.check('accumulator.receipts', ports.receipt, core, r, b, [`receipt:${r.acc}#${r.seq ?? i}`], 'the reserved contribution (the effect params were withheld)');
  });

  // -- W-B artifacts: facts, classifier verdicts, offer sets, label receipts -----------------------------------------
  for (const [i, x] of (b.facts ?? []).entries()) {
    const pk = isObj(x) && typeof x.oracle === 'string' ? trust.oracleKeys?.[x.oracle] : undefined;
    const core = pk === undefined ? undefined : () => {
      const w = validateFactWire(x);
      if (w) return { ok: false, reason: w } as Verdict;
      return verifyArtifactSig(FACT_DOMAIN, x as unknown as Record<string, unknown>, pk) ? ({ ok: true } as Verdict) : { ok: false, reason: 'bad oracle signature' };
    };
    f.check('fact.signature', ports.fact, core, x, b, [`fact:${i}`], 'this fact (oracle key not pinned)');
  }
  for (const [i, x] of (b.classifier ?? []).entries()) {
    const judge = isObj(x) && typeof x.judge === 'string' ? x.judge : undefined;
    const core = judge === undefined || !(trust.judges ?? []).includes(judge) ? undefined : () => {
      const w = validateClassifierVerdictWire(x);
      if (w) return { ok: false, reason: w } as Verdict;
      if (x.session !== session) return { ok: false, reason: 'verdict for another session' } as Verdict;
      return verifyArtifactSig(INTENT_CLASSIFIER_DOMAIN, x as unknown as Record<string, unknown>, judge) ? ({ ok: true } as Verdict) : { ok: false, reason: 'bad judge signature' };
    };
    f.check('classifier.signature', ports.classifier, core, x, b, [`classifier:${i}`], 'this classifier verdict (judge not pinned)');
  }
  for (const [i, x] of (b.offer_sets ?? []).entries()) {
    const key = siteKeys?.find((k) => isObj(x) && k.kid === x.kid && k.alg === 'ed25519');
    const core = key === undefined ? undefined : () => {
      const w = validateOfferSetWire(x);
      if (w) return { ok: false, reason: w } as Verdict;
      if (x.session !== session) return { ok: false, reason: 'offer set for another session' } as Verdict;
      return verifyArtifactSig(OFFER_SET_DOMAIN, x as unknown as Record<string, unknown>, key.pk) ? ({ ok: true } as Verdict) : { ok: false, reason: 'bad site signature' };
    };
    f.check('offer_set.signature', ports.offerSet, core, x, b, [`offer_set:${i}`], 'this offer set (site key not pinned)');
  }
  const labelKeys = trust.labelKeys ?? (siteKeys ?? []).filter((k) => k.alg === 'ed25519').map((k) => ({ site: b.schema.doc.site, kid: k.kid, pk: k.pk }));
  for (const [i, x] of (b.labels ?? []).entries()) {
    const core = labelKeys.length === 0 ? undefined : () => {
      const e = verifyLabels(x, labelKeys);
      if (e === null && x.session !== session) return { ok: false, reason: 'label receipt for another session' } as Verdict;
      return nul(e);
    };
    f.check('labels.signature', ports.labels, core, x, b, [`labels:${i}`], 'this label receipt (no site keys)');
  }

  // -- ported artifacts with no core format -------------------------------------------------------------------------
  b.verdicts.forEach((v) => f.check('verdict.signature', ports.verdict, undefined, v, b, [`verdict:${v.pcactn_digest}`], 'site verdicts (no core format yet)'));
  (b.settlements ?? []).forEach((x, i) => f.check('settlement.signature', ports.settlement, undefined, x, b, [`settlement:${i}`], 'settlement records (no core format yet)'));

  // -- revocation (core checkSessionRevocation, rule 13 step 7) -------------------------------------------------------
  // The bundle's epochs, in issue order, must form ONE append-only chain signed by the session's dedicated revocation
  // authority: every epoch is checked by the core checker as of its own issue time with its predecessor as the tracked
  // `last` (no rollback, no dropped id, no equivocation). The epoch in force at the action time then decides.
  if (b.revocation_epochs.length === 0) f.add('revocation.epoch', 'unverified', [], 'no revocation epoch in the bundle');
  else if (!S.revocation) f.add('revocation.epoch', 'fail', [], 'the session root names no revocation authority');
  else {
    const authority = S.revocation.key;
    const maxAgeMs = (S.revocation.max_age_s ?? DEFAULT_REVOCATION_MAX_AGE_S.default) * 1000;
    const pin = S.revocation.pq_pk !== undefined ? { pqPins: { [authority]: S.revocation.pq_pk } } : undefined;
    const chain = b.revocation_epochs;
    let historyOk = true;
    chain.forEach((ev, i) => {
      const last = i > 0 ? chain[i - 1] : undefined;
      const v = checkSessionRevocation(ev, { session, authority, ids: [], now: ev.epoch.issued_at, maxAgeMs, ...(pin ? { pin } : {}), ...(last ? { last } : {}) });
      if (!v.ok) historyOk = false;
      f.verdict('revocation.history', v, [`epoch#${i}:${ev.epoch.epoch}`]);
    });
    if (!subject) f.add('revocation.epoch', 'unverified', [], 'no subject action time');
    else {
      const ids = [sessionRevocationId(session), ...b.maps.map((m) => mapRevocationId(m.commit)), ...b.deltas.map((d) => deltaRevocationId(d.id))];
      const idx = epochIdxAt(subject.iat);
      const ev = idx >= 0 ? chain[idx] : undefined;
      if (!ev) f.add('revocation.epoch', 'fail', [], 'every epoch was issued after the action');
      else if (!historyOk) f.add('revocation.epoch', 'fail', [`epoch:${ev.epoch.epoch}`], 'the bundled epochs are not one append-only chain');
      else {
        const last = idx > 0 ? chain[idx - 1] : undefined;
        f.verdict('revocation.epoch', checkSessionRevocation(ev, { session, authority, ids, now: subject.iat, maxAgeMs, ...(pin ? { pin } : {}), ...(last ? { last } : {}) }), [`epoch:${ev.epoch.epoch}`]);
      }
    }
  }

  // -- anchors ----------------------------------------------------------------------------------------------------
  if (b.schema.anchor) f.add('schema.anchor', 'unverified', ['schema'], 'the anchor names a log position without an inclusion proof');
  const anchorable = (kind: string, d: string): boolean => {
    if (kind === 'evidence') return d === digest;
    if (kind === 'statement') return d === b.statement.commit;
    if (kind === 'map') return mapCommits.has(d);
    if (kind === 'schema') return d === schemaDigest;
    if (kind === 'observation') return verified.some((a) => answerRef(a) === d);
    return false;
  };
  if (!b.anchors.some((a) => a.kind === 'evidence')) f.add('anchor.inclusion', 'unverified', ['anchor:evidence'], 'the bundle is not anchored');
  for (const a of b.anchors) {
    const ref = [`anchor:${a.kind}:${a.index}`];
    if (!anchorable(a.kind, a.digest)) {
      f.add('anchor.inclusion', 'fail', ref, 'the anchor names an artifact that is not this one');
      continue;
    }
    const g = trust.anchorGuardian;
    if (!g) {
      f.add('anchor.inclusion', 'unverified', ref, 'no anchor-log guardian key supplied');
      continue;
    }
    const h = a.signed_tree_head;
    const ok =
      h.principal === INTENT_ANCHOR_LOG &&
      h.instance_id === g.instance &&
      verifyTreeHead(h, g.public) &&
      a.proof.index === a.index &&
      a.proof.size === h.size &&
      verifyLedgerInclusion(h.root, a.proof, anchorCommit(a.kind, a.digest));
    f.add('anchor.inclusion', ok ? 'pass' : 'fail', ref);
  }

  // -- attribution: the session-root keys that sign in this bundle must be pinned by the reader ----------------------
  // Everything above verifies against keys the bundle's own self-signed session root names, so it proves internal
  // consistency only: an attacker who generates a key and signs S, the answers, the deltas and the PCActns produces a
  // consistent bundle. Attribution to a known principal needs keys pinned out of band. The revocation authority and the
  // sequencer roots are named inside S, so they are attributed transitively once S's signer is pinned. The core
  // session root carries no quorum rule (each artifact has one signer), so "satisfiable by pinned keys" is: every
  // signing key is pinned.
  {
    const signing = new Set<string>([S.signer, g0.issuer, ...b.deltas.map((d) => d.issuer), ...b.answers.map((a) => a.signer), ...(opening ? [opening.principal] : [])]);
    const keys = [...signing].filter((k) => typeof k === 'string').sort();
    summary.attribution.keys_to_check = keys;
    if (trust.principals === undefined) f.add('principal.pinned', 'unverified', keys, 'no pinned principal keys: the bundle names its own principals; verify these keys out of band');
    else {
      const pins = new Map(trust.principals.map((p) => [p.key, p] as const));
      const unpinned = keys.filter((k) => !pins.has(k));
      const pqMismatch = keys.filter((k) => {
        const pin = pins.get(k);
        const sp = S.principals.find((x) => x.key === k);
        return pin !== undefined && (pin.pq_pk ?? null) !== (sp?.pq_pk ?? null);
      });
      if (unpinned.length) f.add('principal.pinned', 'fail', unpinned, 'signing keys that are not pinned principals');
      else if (pqMismatch.length) f.add('principal.pinned', 'fail', pqMismatch, 'the session root binds a different PQ key than the pin');
      else {
        f.add('principal.pinned', 'pass', keys);
        summary.attribution.pinned = true;
      }
    }
  }

  // -- plain-language facts (only what passed) ------------------------------------------------------------------------
  const proven: string[] = [];
  const passed = (code: FindingCode) => f.list.some((x) => x.code === code && x.status === 'pass') && !f.list.some((x) => x.code === code && x.status === 'fail');
  if (summary.admitted_under && passed('pcactn.verify')) proven.push(`The subject action was signed by the agent under ${summary.admitted_under}, a grant signed by the session principal${summary.attribution.pinned ? ' (pinned)' : ' (NOT pinned)'}.`);
  const who = (k: string) => (summary.attribution.pinned ? `Pinned principal key ${k}` : `Session-root key ${k} (NOT pinned: not attributed to a known principal)`);
  if (summary.consent) proven.push(`${who(summary.consent.signer)} signed a ${summary.consent.tier}-tier "yes" bound to this exact action (question ${summary.consent.question_id}).`);
  if (summary.charged && summary.charged.amount <= summary.charged.bound) proven.push(`The charged amount ${summary.charged.amount} is within the confirmed value ${summary.charged.bound}.`);
  if (summary.refusals.length) proven.push(`The principal refused ${summary.refusals.length} question(s): ${summary.refusals.join(', ')}.`);
  if (summary.canary_accuracy.asked) proven.push(`Canary accuracy ${summary.canary_accuracy.correct}/${summary.canary_accuracy.asked}.`);
  if (passed('accumulator.cap')) proven.push('Every accumulator post is within the cap of the grant that admitted it.');
  if (passed('effect.frame')) proven.push('The site reports no change to monitored state outside the write set.');
  summary.proven = proven;
}
