import {
  b64u,
  canonicalBytesStrict,
  decodeB64uStrict,
  hashCanonical,
  paramsDigest,
  publicKeyOf,
  sign,
  utf8,
  verifyB64u,
} from '@atlasauth/pca';
import { cellCoordsError, intentActionDigest, type Friction } from '@atlasauth/pca/ext/intent';

/**
 * WIRE FORMATS OF THE TRUSTED QUESTION CHANNEL (Intent Layer v2, docs/specs/pca-intent-layer-v2.md §3.3, §3.4, §4 M5/M6, §8).
 *
 *  - `pca-intent-required` (M5), the SITE-signed question, is owned by the V3 core module (`@atlasauth/pca`
 *    `signIntentRequired` / `verifyIntentRequired` / `intentProblem` / `intentActionDigest`); the wallet consumes it.
 *  - `pca-intent-observation` v2 (M6) is defined here: the PRINCIPAL-signed answer, the v1 runtime observation plus
 *    `session`, `question_id`, `cell` and the `ux` member (friction tier, rendered-card digest, typed digest, WebAuthn
 *    assertion, canary flag, JIT-consent binding to the V3 action digest).
 *
 * The spec fixes M6's shape but not its signing domain. `atlas-pca/intent-obs/v2\0` is this package's choice (the v1
 * observation uses `atlas-pca/intent-obs/v1\0`). Every body is signed as `utf8(domain) || canonicalBytesStrict(body
 * without sig)`, Ed25519; the suite is a member of the body, so it is signed.
 */

export const INTENT_ANSWER_SIG_DOMAIN = 'atlas-pca/intent-obs/v2\0';
export const INTENT_ANSWER_REF_DOMAIN = 'atlas-pca/intent-answer-ref/v1';
export const INTENT_TYPED_DOMAIN = 'atlas-pca/intent-typed/v1';
export const INTENT_DEVICE_CHALLENGE_DOMAIN = 'atlas-pca/intent-device/v1';

// ---- friction ------------------------------------------------------------------------------------------------

/** φ(c): tap < hold < typed < device (§2.5); the core's `Friction`. */
export type FrictionTier = Friction;
export const FRICTION_ORDER: readonly FrictionTier[] = ['tap', 'hold', 'typed', 'device'];

export function isFrictionTier(x: unknown): x is FrictionTier {
  return typeof x === 'string' && (FRICTION_ORDER as readonly string[]).includes(x);
}

export function frictionRank(t: FrictionTier): number {
  return FRICTION_ORDER.indexOf(t);
}

export function maxFriction(...ts: FrictionTier[]): FrictionTier {
  let best: FrictionTier = 'tap';
  for (const t of ts) if (frictionRank(t) > frictionRank(best)) best = t;
  return best;
}

// ---- cells ----------------------------------------------------------------------------------------------------

/** A numeric coordinate is an inclusive cell-INDEX range [lo, hi]; a categorical one is a set of value labels. */
export type CellCoord = [number, number] | string[];
/** Coordinates keyed by dimension key (a parameter path, an accumulator / world id, or `prov:<path>`). */
export type CellCoords = Record<string, CellCoord>;

export interface CellRef {
  verb: string;
  coords: CellCoords;
}

/** A concrete outcome over the wallet's Ω: verb plus one value per dimension path (`action.params.*`, `env.*`). */
export interface ActionValues {
  verb: string;
  values: Record<string, number | string>;
}

/** The action as the agent attempted it and the site digested it: the PCActn's `action` with its raw params. */
export interface PcaAction {
  verb: string;
  resource: string;
  params: Record<string, unknown>;
  reversibility_class: string;
}

/** The V3 action digest of an attempted action (what `intent_required.action_digest` and a JIT consent bind to). */
export function pcaActionDigest(a: PcaAction): string {
  return intentActionDigest({ verb: a.verb, resource: a.resource, params_digest: paramsDigest(a.params), reversibility_class: a.reversibility_class });
}

/**
 * The default projection of an attempted action onto Ω paths: `action.resource` and every SCALAR param as
 * `action.params.<name>`. Set-valued or structured params, accumulator posts, provenance and world values are the
 * lift's job (the wallet's V2 trajectory module); a dimension the projection cannot fill makes the cell undefined, and
 * the wallet refuses the question (fail closed).
 */
export function actionValuesOf(a: PcaAction): ActionValues {
  const values: Record<string, number | string> = { 'action.resource': a.resource };
  for (const [k, v] of Object.entries(a.params)) if (typeof v === 'string' || (typeof v === 'number' && Number.isFinite(v))) values[`action.params.${k}`] = v;
  return { verb: a.verb, values };
}

// ---- helpers ---------------------------------------------------------------------------------------------------

export const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
export const isB64u32 = (v: unknown): v is string => decodeB64uStrict(v, 32) !== null;
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);
const plain = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

function domainMessage(domain: string, body: unknown): Uint8Array {
  const d = utf8(domain);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(d.length + b.length);
  out.set(d, 0);
  out.set(b, d.length);
  return out;
}

function onlyKeys(o: Record<string, unknown>, allowed: readonly string[]): string | null {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) return `unknown member "${k}"`;
  return null;
}

/** Coordinates as the core validates them (shared with `intent_required`). */
export const coordsError = cellCoordsError;

export type Verdict = { ok: true } | { ok: false; reason: string };

const QID_RE = /^[A-Za-z0-9_-]{1,64}$/;

// ---- M6: the signed answer (observation v2) ------------------------------------------------------------------------

export interface WebAuthnEvidence {
  credential_id: string;
  authenticator_data: string;
  client_data_json: string;
  signature: string;
}

export interface AnswerUx {
  tier: FrictionTier;
  /** Digest of the rendered card the human saw (reproducible from its inputs). */
  rendered_digest: string;
  /** typed tier: digest of the value typed (see {@link typedDigest}). */
  typed_digest?: string;
  /** hold tier: the measured press-and-hold dwell in ms (≥ 2000). */
  hold_ms?: number;
  /** device tier: the WebAuthn assertion over {@link deviceChallenge}. */
  webauthn?: WebAuthnEvidence;
  /** true for a canary: the answer only updates the noise estimates, never the grant (T16). */
  canary: boolean;
  /** JIT consent: the one action this answer also consents to (v1 L4); covers that action digest only, not the cell. */
  action_digest?: string;
  consent_for_action?: boolean;
}

/** A "Partly…" answer: a structured restriction of the cell (never text). */
export type PartialSpec =
  | { path: string; upTo: number }
  | { path: string; from: number }
  | { path: string; except: number[] }
  | { path: string; notFor: string[] };

export type AnswerSource = 'elicitation' | 'clarification';

export interface IntentAnswer {
  v: 2;
  kind: 'pca-intent-observation';
  map_digest: string;
  session: string;
  question_id: string;
  verb: string;
  cell: CellCoords;
  y: 0 | 1;
  partial?: PartialSpec;
  source: AnswerSource;
  observed_at: number;
  ux: AnswerUx;
  signer: string;
  alg: 'ed25519';
}

export interface SignedIntentAnswer extends IntentAnswer {
  sig: string;
}

const ANS_KEYS = ['v', 'kind', 'map_digest', 'session', 'question_id', 'verb', 'cell', 'y', 'partial', 'source', 'observed_at', 'ux', 'signer', 'alg', 'sig'] as const;
const UX_KEYS = ['tier', 'rendered_digest', 'typed_digest', 'hold_ms', 'webauthn', 'canary', 'action_digest', 'consent_for_action'] as const;
const WA_KEYS = ['credential_id', 'authenticator_data', 'client_data_json', 'signature'] as const;

export const MIN_HOLD_MS = 2000;

function partialError(p: unknown): string | null {
  if (!isObj(p) || typeof p.path !== 'string' || p.path.length === 0) return 'partial.path must be a non-empty string';
  const keys = Object.keys(p).filter((k) => k !== 'path');
  if (keys.length !== 1) return 'partial must carry exactly one of upTo / from / except / notFor';
  const k = keys[0]!;
  const v = p[k];
  if ((k === 'upTo' || k === 'from') && !isInt(v)) return `partial.${k} must be an integer`;
  if (k === 'except' && !(Array.isArray(v) && v.length > 0 && v.every(isInt))) return 'partial.except must be a non-empty integer array';
  if (k === 'notFor' && !(Array.isArray(v) && v.length > 0 && v.every((x) => typeof x === 'string' && x.length > 0))) return 'partial.notFor must be a non-empty string array';
  if (!['upTo', 'from', 'except', 'notFor'].includes(k)) return `unknown partial member "${k}"`;
  return null;
}

export function answerShapeError(a: unknown): string | null {
  if (!isObj(a)) return 'not an object';
  const extra = onlyKeys(a, ANS_KEYS);
  if (extra) return extra;
  if (a.v !== 2 || a.kind !== 'pca-intent-observation') return 'not a pca-intent-observation v2';
  for (const k of ['map_digest', 'session', 'signer'] as const) if (!isB64u32(a[k])) return `${k} is not canonical base64url (32 bytes)`;
  if (typeof a.question_id !== 'string' || !QID_RE.test(a.question_id)) return 'question_id must match [A-Za-z0-9_-]{1,64}';
  if (typeof a.verb !== 'string' || a.verb.length === 0) return 'verb must be a non-empty string';
  const ce = coordsError(a.cell);
  if (ce) return `cell: ${ce}`;
  if (a.y !== 0 && a.y !== 1) return 'y must be 0 or 1';
  if (a.partial !== undefined) {
    const pe = partialError(a.partial);
    if (pe) return pe;
    if (a.y !== 1) return 'a partial answer carries y = 1 (yes for the part)';
  }
  if (a.source !== 'elicitation' && a.source !== 'clarification') return 'source must be elicitation or clarification';
  if (!isInt(a.observed_at) || a.observed_at < 0) return 'observed_at must be a non-negative safe integer';
  if (a.alg !== 'ed25519') return 'alg must be ed25519';
  const ux = a.ux;
  if (!isObj(ux)) return 'ux must be an object';
  const ue = onlyKeys(ux, UX_KEYS);
  if (ue) return `ux: ${ue}`;
  if (!isFrictionTier(ux.tier)) return 'ux.tier is not a friction tier';
  if (!isB64u32(ux.rendered_digest)) return 'ux.rendered_digest is not canonical base64url (32 bytes)';
  if (typeof ux.canary !== 'boolean') return 'ux.canary must be a boolean';
  if (ux.typed_digest !== undefined && !isB64u32(ux.typed_digest)) return 'ux.typed_digest is not canonical base64url (32 bytes)';
  if (ux.hold_ms !== undefined && !(isInt(ux.hold_ms) && ux.hold_ms >= 0)) return 'ux.hold_ms must be a non-negative integer';
  if (ux.action_digest !== undefined && !isB64u32(ux.action_digest)) return 'ux.action_digest is not canonical base64url (32 bytes)';
  if (ux.consent_for_action !== undefined && typeof ux.consent_for_action !== 'boolean') return 'ux.consent_for_action must be a boolean';
  if (ux.consent_for_action === true && (ux.action_digest === undefined || a.y !== 1 || a.partial !== undefined)) return 'consent_for_action needs action_digest and a plain yes';
  if (ux.consent_for_action === true && ux.canary === true) return 'a canary never consents to an action';
  if (ux.webauthn !== undefined) {
    if (!isObj(ux.webauthn) || onlyKeys(ux.webauthn, WA_KEYS) || !WA_KEYS.every((k) => typeof (ux.webauthn as Record<string, unknown>)[k] === 'string')) return 'ux.webauthn is malformed';
  }
  // The tier's own evidence must be present (a "yes" only: a "no" needs no friction).
  if (a.y === 1 && !ux.canary) {
    if (ux.tier === 'hold' && !(isInt(ux.hold_ms) && ux.hold_ms >= MIN_HOLD_MS)) return `hold tier needs hold_ms >= ${MIN_HOLD_MS}`;
    if (ux.tier === 'typed' && ux.typed_digest === undefined) return 'typed tier needs typed_digest';
    if (ux.tier === 'device' && ux.webauthn === undefined) return 'device tier needs a WebAuthn assertion';
  }
  return null;
}

function answerBody(a: IntentAnswer): IntentAnswer {
  return plain({
    v: a.v, kind: a.kind, map_digest: a.map_digest, session: a.session, question_id: a.question_id, verb: a.verb, cell: a.cell, y: a.y,
    ...(a.partial !== undefined ? { partial: a.partial } : {}),
    source: a.source, observed_at: a.observed_at, ux: a.ux, signer: a.signer, alg: a.alg,
  });
}

/** Wallet side: sign the principal's answer with the principal key. */
export function signIntentAnswer(a: Omit<IntentAnswer, 'v' | 'kind' | 'signer' | 'alg'>, principalSecret: Uint8Array): SignedIntentAnswer {
  const body = answerBody({ ...a, v: 2, kind: 'pca-intent-observation', signer: b64u(publicKeyOf(principalSecret)), alg: 'ed25519' });
  const bad = answerShapeError(body);
  if (bad) throw new Error(`signIntentAnswer: ${bad}`);
  return { ...body, sig: b64u(sign(principalSecret, domainMessage(INTENT_ANSWER_SIG_DOMAIN, body))) };
}

/** Verify a signed answer; `principals` restricts the signer (the keys named in the session root). Never throws. */
export function verifyIntentAnswer(a: unknown, principals?: readonly string[]): Verdict {
  try {
    const bad = answerShapeError(a);
    if (bad) return { ok: false, reason: bad };
    const ans = a as unknown as SignedIntentAnswer;
    if (principals && !principals.includes(ans.signer)) return { ok: false, reason: 'signer is not a principal of the session' };
    if (typeof ans.sig !== 'string' || !verifyB64u(ans.signer, domainMessage(INTENT_ANSWER_SIG_DOMAIN, answerBody(ans)), ans.sig)) return { ok: false, reason: 'bad signature' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `malformed answer: ${(e as Error).message}` };
  }
}

/** Content address of a signed answer (evidence bundles and delta grants refer to it). */
export function answerRef(a: SignedIntentAnswer): string {
  return hashCanonical({ d: INTENT_ANSWER_REF_DOMAIN, a });
}

/**
 * The typed-tier digest. The value to type is drawn from the card (§3.4) and normalized, so a site or an auditor that
 * knows the action can recompute the expected digest and check the tier was really typed against THIS value.
 */
export function typedDigest(questionId: string, normalizedValue: string): string {
  return hashCanonical({ d: INTENT_TYPED_DOMAIN, q: questionId, v: normalizedValue });
}

/** The 32-byte WebAuthn challenge of a device-tier answer: binds the question, the card the human saw, y and the action. */
export function deviceChallenge(args: { questionId: string; renderedDigest: string; y: 0 | 1; actionDigest?: string }): string {
  return hashCanonical({ d: INTENT_DEVICE_CHALLENGE_DOMAIN, q: args.questionId, r: args.renderedDigest, y: args.y, a: args.actionDigest ?? null });
}
