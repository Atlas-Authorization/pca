/**
 * UNDO WINDOWS (0.5): reversible actions execute at once and the principal gets a veto window in which they can undo them.
 *
 * This module is the PURE, language-neutral part (spec: docs/pca/specs/undo-windows.md): the undo record and its state
 * machine, the signed one-click undo token, the signed and hash-chained audit receipts, and the durable store contract with
 * a reference store. Admission, compensation and notification live in `server/undo.ts`.
 *
 * STATE MACHINE (every transition is total, idempotent under retry and checked against the stored version):
 *
 *     open --veto (now <= window_end)--> vetoed --compensated--> compensated
 *       |                                  |  \--compensation_failed--> compensation_failed --retry--> vetoed
 *       |                                  |                                   \--compensated--> compensated
 *       +--finalize (now > window_end)--> finalized
 *       +--abort (the effect never ran)--> finalized
 *
 * A veto after `window_end` is refused (`window_closed`); a second veto of a vetoed record is a replay that changes nothing;
 * nothing leaves `finalized` or `compensated`. A compensation that fails is NEVER silent: the record parks in
 * `compensation_failed` (its budget stays reserved) and the coordinator raises an alert.
 *
 * WHAT IS CLAIMED. A record exists (durably) before the effect it can undo runs; only a valid veto inside the window starts a
 * compensation; a compensation runs at most once per attempt; every transition is receipted under the undo service key.
 */
import { b64u, canonicalBytesStrict, decodeB64uStrict, hashCanonical, utf8 } from './hash';
import { publicKeyOf, sign, verifyB64u } from './keys';
import { isSafeInt } from './intent-strict';
import type { DurableKv } from './durable-state';

export const UNDO_TOKEN_DOMAIN = 'atlas-pca/undo-token/v1\0';
export const UNDO_RECEIPT_DOMAIN = 'atlas-pca/undo-receipt/v1\0';
export const UNDO_COMPENSATION_DOMAIN = 'atlas-pca/undo-compensation/v1';
export const UNDO_RECEIPT_REF_DOMAIN = 'atlas-pca/undo-receipt-ref/v1';
export const UNDO_TOKEN_KIND = 'pca-undo-token';
export const UNDO_RECEIPT_KIND = 'pca-undo-receipt';

/** The realistic floor of a veto window (the same 30 s floor as the optimistic challenge window): a human must be able to react. */
export const UNDO_MIN_WINDOW_MS = 30_000;
export const UNDO_DEFAULT_WINDOW_MS = 15 * 60_000;
export const UNDO_MAX_WINDOW_MS = 24 * 60 * 60_000;

export const UNDO_STATES = ['open', 'vetoed', 'compensated', 'compensation_failed', 'finalized'] as const;
export type UndoState = (typeof UNDO_STATES)[number];
export const UNDO_EVENTS = ['opened', 'vetoed', 'compensated', 'compensation_failed', 'finalized', 'aborted', 'retried', 'effect'] as const;
export type UndoEvent = (typeof UNDO_EVENTS)[number];
export const VETO_VIAS = ['token', 'operator', 'fraud_proof', 'revocation'] as const;
export type VetoVia = (typeof VETO_VIAS)[number];

export type UndoErrorCode = 'not_durable' | 'store_missing' | 'store_corrupt' | 'invalid' | 'conflict_exhausted' | 'signer_missing' | 'config';
export class UndoError extends Error {
  constructor(
    readonly code: UndoErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'UndoError';
  }
}

/** The compensating action of an undo record: decided BEFORE the original effect runs. */
export interface UndoCompensation {
  verb: string;
  /** The original operation's resource (a compensation acts on what the original acted on). */
  resource: string;
  /** The original params the compensating definition declares under the same name and type. */
  params: Record<string, unknown>;
  /** The operation id of the original action (its idempotency key): the compensator looks its result up by it. */
  undo_of: string;
  /** Digest of the confirmed compensating ActionDef. */
  def_digest: string;
  /** The compensating definition's resource-id parameter, filled at execution from the original's result. */
  target_param?: string;
}

export interface UndoVeto {
  at: number;
  via: VetoVia;
  /** Who vetoed: the token's principal, an operator id, the settlement record digest, the revoked grant. */
  by: string;
  /** Evidence digest (the token digest, a settlement record digest, ...). */
  evidence?: string;
}

/** A signed audit receipt of one transition. Receipts of a record form a hash chain (`prev`). */
export interface UndoReceipt {
  v: 1;
  kind: typeof UNDO_RECEIPT_KIND;
  record: string;
  event: UndoEvent;
  /** The state after the event. */
  state: UndoState;
  at: number;
  /** The record's compensation digest (binds every receipt to what an undo does). */
  compensation_digest: string;
  /** Digest of the previous receipt of this record, '' for the first. */
  prev: string;
  /** Short machine reason (veto via, failure reason, ...), '' when none. */
  note: string;
  signer: string;
  sig: string;
}

export interface UndoOutcomeInfo {
  at: number;
  status: 'compensated' | 'compensation_failed' | 'finalized' | 'aborted';
  reason?: string;
  /** What the compensator returned (keep it JSON-serialisable). */
  result?: unknown;
}

export interface UndoRecord {
  v: 1;
  /** The original operation id (`AuthorizedOperation.id` = the PCActn digest). Also the optimistic claim's `pcactn_digest`. */
  id: string;
  aud: string;
  grant_ref: string;
  /** The leaf holder (the agent key) and the principal (the grant issuer) the veto window belongs to. */
  holder: string;
  principal: string;
  action: { verb: string; resource: string; params_digest: string; def_digest: string };
  compensation: UndoCompensation;
  compensation_digest: string;
  /** K7: H(R) of the original action's canonical render: what the human is shown and the token binds. */
  render_digest?: string;
  opened_at: number;
  window_end: number;
  /** True when the window replaced a prior approval (the guard's decision was `escalate`). */
  converted: boolean;
  state: UndoState;
  /** Compare-and-swap version, bumped by every write. */
  ver: number;
  /** The original PCActn (encoded): its verified chain is the authority the compensation is decided under. */
  pcactn: string;
  /** Aggregate budget reservations held until the window closes (committed on finalize, released on compensation). */
  budget?: { key: string; id: string }[];
  /** The optimistic claim's bond (a slash with a fraud proof vetoes this record). */
  bond_ref?: string;
  veto?: UndoVeto;
  /** The original effect's outcome, reported after it ran. */
  effect?: { at: number; result?: unknown };
  /** Compensation attempts started (an attempt that never started is retried under the next number). */
  attempt: number;
  outcome?: UndoOutcomeInfo;
  receipts: UndoReceipt[];
}

// ---- digests ------------------------------------------------------------------------------------------------------------

export function compensationDigest(c: UndoCompensation): string {
  return hashCanonical({
    d: UNDO_COMPENSATION_DOMAIN,
    verb: c.verb,
    resource: c.resource,
    params: c.params,
    undo_of: c.undo_of,
    def_digest: c.def_digest,
    ...(c.target_param !== undefined ? { target_param: c.target_param } : {}),
  });
}

const ID_MAX = 256;
const idOk = (s: unknown): s is string => typeof s === 'string' && s.length > 0 && s.length <= ID_MAX && !/[\u0000-\u001f]/.test(s);
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const domainBytes = (domain: string, body: unknown): Uint8Array => {
  const dom = utf8(domain);
  const b = canonicalBytesStrict(body);
  const out = new Uint8Array(dom.length + b.length);
  out.set(dom);
  out.set(b, dom.length);
  return out;
};

// ---- the one-click undo token ---------------------------------------------------------------------------------------------

/**
 * A signed capability to veto ONE record: bound to the record (= the action digest), the compensation it starts, the render
 * the human was shown and the window end. Signed by the undo service key; delivered only through the principal's channels.
 */
export interface UndoToken {
  v: 1;
  kind: typeof UNDO_TOKEN_KIND;
  record: string;
  aud: string;
  principal: string;
  compensation_digest: string;
  /** '' when the record carries no render digest. */
  render_digest: string;
  exp: number;
  signer: string;
  sig: string;
}
type TokenBody = Omit<UndoToken, 'sig'>;
const tokenBody = (t: TokenBody): TokenBody => ({ v: t.v, kind: t.kind, record: t.record, aud: t.aud, principal: t.principal, compensation_digest: t.compensation_digest, render_digest: t.render_digest, exp: t.exp, signer: t.signer });

export function signUndoToken(rec: Pick<UndoRecord, 'id' | 'aud' | 'principal' | 'compensation_digest' | 'render_digest' | 'window_end'>, secret: Uint8Array): UndoToken {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new UndoError('signer_missing', 'the undo service key must be a 32-byte Ed25519 secret');
  const body: TokenBody = { v: 1, kind: UNDO_TOKEN_KIND, record: rec.id, aud: rec.aud, principal: rec.principal, compensation_digest: rec.compensation_digest, render_digest: rec.render_digest ?? '', exp: rec.window_end, signer: b64u(publicKeyOf(secret)) };
  return { ...body, sig: b64u(sign(secret, domainBytes(UNDO_TOKEN_DOMAIN, body))) };
}

/** The first check a token fails; `ok` when none. The cross-language vectors name these. */
export type UndoTokenCheck = 'ok' | 'malformed' | 'signer' | 'signature' | 'record' | 'binding' | 'expired';

/**
 * Check a token against the pinned undo service key and the stored record, at `now`. Order: shape, signer pin, signature,
 * record id, binding (aud, principal, compensation, render, window end), expiry (`now > exp`). Total; never throws.
 */
export function undoTokenCheck(token: unknown, expectedSigner: string, rec: Pick<UndoRecord, 'id' | 'aud' | 'principal' | 'compensation_digest' | 'render_digest' | 'window_end'>, now: number): UndoTokenCheck {
  try {
    if (!isObj(token)) return 'malformed';
    const keys = ['v', 'kind', 'record', 'aud', 'principal', 'compensation_digest', 'render_digest', 'exp', 'signer', 'sig'];
    if (Object.keys(token).length !== keys.length || !keys.every((k) => Object.prototype.hasOwnProperty.call(token, k))) return 'malformed';
    const t = token as unknown as UndoToken;
    if (t.v !== 1 || t.kind !== UNDO_TOKEN_KIND || !idOk(t.record) || typeof t.aud !== 'string' || typeof t.principal !== 'string' || typeof t.compensation_digest !== 'string' || typeof t.render_digest !== 'string' || !isSafeInt(t.exp) || typeof t.signer !== 'string' || decodeB64uStrict(t.sig, 64) === null) return 'malformed';
    if (t.signer !== expectedSigner) return 'signer';
    if (!verifyB64u(expectedSigner, domainBytes(UNDO_TOKEN_DOMAIN, tokenBody(t)), t.sig)) return 'signature';
    if (t.record !== rec.id) return 'record';
    if (t.aud !== rec.aud || t.principal !== rec.principal || t.compensation_digest !== rec.compensation_digest || t.render_digest !== (rec.render_digest ?? '') || t.exp !== rec.window_end) return 'binding';
    if (!isSafeInt(now) || now > t.exp) return 'expired';
    return 'ok';
  } catch {
    return 'malformed';
  }
}

/** The token as a URL-safe string (base64url of its strict-canonical JSON) for a one-click link. */
export const encodeUndoToken = (t: UndoToken): string => b64u(canonicalBytesStrict(t));
/** Inverse of {@link encodeUndoToken}; undefined for anything that is not a token-shaped JSON object. */
export function decodeUndoToken(s: unknown): unknown {
  try {
    if (typeof s !== 'string' || s.length === 0 || s.length > 4096) return undefined;
    const b = decodeB64uStrict(s);
    if (b === null) return undefined;
    const x = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b)) as unknown;
    return isObj(x) ? x : undefined;
  } catch {
    return undefined;
  }
}
export const undoTokenDigest = (t: UndoToken): string => hashCanonical({ d: 'atlas-pca/undo-token-ref/v1', t });

// ---- receipts -------------------------------------------------------------------------------------------------------------

type ReceiptBody = Omit<UndoReceipt, 'sig'>;
const receiptBody = (r: ReceiptBody): ReceiptBody => ({ v: r.v, kind: r.kind, record: r.record, event: r.event, state: r.state, at: r.at, compensation_digest: r.compensation_digest, prev: r.prev, note: r.note, signer: r.signer });
export const undoReceiptDigest = (r: UndoReceipt): string => hashCanonical({ d: UNDO_RECEIPT_REF_DOMAIN, r });

export function signUndoReceipt(body: Omit<ReceiptBody, 'v' | 'kind' | 'signer'>, secret: Uint8Array): UndoReceipt {
  const b: ReceiptBody = { v: 1, kind: UNDO_RECEIPT_KIND, record: body.record, event: body.event, state: body.state, at: body.at, compensation_digest: body.compensation_digest, prev: body.prev, note: body.note, signer: b64u(publicKeyOf(secret)) };
  return { ...b, sig: b64u(sign(secret, domainBytes(UNDO_RECEIPT_DOMAIN, b))) };
}

/** True iff `r` is well formed and signed by `expectedSigner` over exactly its content. Never throws. */
export function verifyUndoReceipt(r: unknown, expectedSigner: string): boolean {
  try {
    if (!isObj(r)) return false;
    const x = r as unknown as UndoReceipt;
    if (x.v !== 1 || x.kind !== UNDO_RECEIPT_KIND || !idOk(x.record) || !(UNDO_EVENTS as readonly string[]).includes(x.event) || !(UNDO_STATES as readonly string[]).includes(x.state) || !isSafeInt(x.at) || typeof x.compensation_digest !== 'string' || typeof x.prev !== 'string' || typeof x.note !== 'string' || x.signer !== expectedSigner || decodeB64uStrict(x.sig, 64) === null) return false;
    if (Object.keys(x).length !== 11) return false;
    return verifyB64u(expectedSigner, domainBytes(UNDO_RECEIPT_DOMAIN, receiptBody(x)), x.sig);
  } catch {
    return false;
  }
}

/**
 * Verify a record's receipt chain: every receipt verifies, names this record and its compensation, `prev` links each to the
 * one before ('' for the first), the first is `opened`, times never go back, and the last state is the record's state.
 * Returns null when sound, else the reason.
 */
export function undoReceiptChainError(rec: Pick<UndoRecord, 'id' | 'compensation_digest' | 'state' | 'receipts'>, expectedSigner: string): string | null {
  const rs = rec.receipts;
  if (!Array.isArray(rs) || rs.length === 0) return 'no receipts';
  let prev = '';
  let at = -Infinity;
  for (const [i, r] of rs.entries()) {
    if (!verifyUndoReceipt(r, expectedSigner)) return `receipt ${i} does not verify`;
    if (r.record !== rec.id || r.compensation_digest !== rec.compensation_digest) return `receipt ${i} is for another record`;
    if (r.prev !== prev) return `receipt ${i} does not link to the previous one`;
    if (i === 0 && r.event !== 'opened') return 'the first receipt is not opened';
    if (r.at < at) return `receipt ${i} goes back in time`;
    prev = undoReceiptDigest(r);
    at = r.at;
  }
  return rs[rs.length - 1]!.state === rec.state ? null : 'the last receipt does not state the record state';
}

// ---- the pure transitions -------------------------------------------------------------------------------------------------

export type UndoTransitionEvent =
  | { kind: 'veto'; veto: UndoVeto }
  | { kind: 'finalize' }
  | { kind: 'abort'; reason: string }
  | { kind: 'effect'; result?: unknown }
  | { kind: 'compensated'; result?: unknown }
  | { kind: 'compensation_failed'; reason: string }
  | { kind: 'retry' };

export type UndoTransitionCode = 'window_closed' | 'window_open' | 'finalized' | 'not_vetoed' | 'compensated' | 'vetoed' | 'effect_recorded' | 'not_failed' | 'invalid';
export type UndoTransition =
  | { outcome: 'applied'; record: UndoRecord; receipt: { event: UndoEvent; note: string } }
  /** The same transition already happened (a retry): nothing to write. */
  | { outcome: 'replayed'; record: UndoRecord }
  | { outcome: 'refused'; code: UndoTransitionCode; reason: string };

const refused = (code: UndoTransitionCode, reason: string): UndoTransition => ({ outcome: 'refused', code, reason });

/**
 * The state machine, pure: `rec` is not modified; an applied transition returns the next record (version bumped, receipt
 * NOT yet appended: the store layer signs and links it). `now` is the trusted server clock. Total; never throws.
 */
export function undoTransition(rec: UndoRecord, ev: UndoTransitionEvent, now: number): UndoTransition {
  try {
    if (!isObj(rec) || !(UNDO_STATES as readonly string[]).includes(rec.state) || !isSafeInt(rec.window_end) || !isSafeInt(rec.ver)) return refused('invalid', 'malformed record');
    if (!isSafeInt(now)) return refused('invalid', 'now must be a safe integer');
    const next = (patch: Partial<UndoRecord>, event: UndoEvent, note = ''): UndoTransition => ({ outcome: 'applied', record: { ...structuredClone(rec), ...patch, ver: rec.ver + 1 }, receipt: { event, note } });
    switch (ev?.kind) {
      case 'veto': {
        const v = ev.veto;
        if (!isObj(v) || !isSafeInt(v.at) || !(VETO_VIAS as readonly string[]).includes(v.via) || typeof v.by !== 'string' || v.by.length === 0) return refused('invalid', 'malformed veto');
        if (rec.state === 'vetoed' || rec.state === 'compensated' || rec.state === 'compensation_failed') return { outcome: 'replayed', record: rec };
        if (rec.state === 'finalized') return refused('finalized', 'the window is closed and the action is final');
        if (now > rec.window_end) return refused('window_closed', `the veto window closed at ${rec.window_end}`);
        return next({ state: 'vetoed', veto: { ...v } }, 'vetoed', v.via);
      }
      case 'finalize':
        if (rec.state === 'finalized') return { outcome: 'replayed', record: rec };
        if (rec.state !== 'open') return refused('vetoed', `a ${rec.state} record is not finalized`);
        if (now <= rec.window_end) return refused('window_open', `the veto window is open until ${rec.window_end}`);
        return next({ state: 'finalized', outcome: { at: now, status: 'finalized' } }, 'finalized');
      case 'abort':
        if (rec.state === 'finalized' && rec.outcome?.status === 'aborted') return { outcome: 'replayed', record: rec };
        if (rec.state !== 'open' && rec.state !== 'vetoed') return refused('finalized', `a ${rec.state} record cannot be aborted`);
        if (rec.effect !== undefined) return refused('effect_recorded', 'the effect ran: it can only be compensated or finalized');
        return next({ state: 'finalized', outcome: { at: now, status: 'aborted', reason: String(ev.reason).slice(0, 512) } }, 'aborted', String(ev.reason).slice(0, 128));
      case 'effect':
        if (rec.effect !== undefined) return { outcome: 'replayed', record: rec };
        if (rec.state !== 'open' && rec.state !== 'vetoed') return refused('finalized', `a ${rec.state} record takes no effect report`);
        return next({ effect: { at: now, ...(ev.result !== undefined ? { result: structuredClone(ev.result) } : {}) } }, 'effect');
      case 'compensated':
        if (rec.state === 'compensated') return { outcome: 'replayed', record: rec };
        if (rec.state !== 'vetoed' && rec.state !== 'compensation_failed') return refused('not_vetoed', `a ${rec.state} record is not being compensated`);
        return next({ state: 'compensated', outcome: { at: now, status: 'compensated', ...(ev.result !== undefined ? { result: structuredClone(ev.result) } : {}) } }, 'compensated');
      case 'compensation_failed':
        if (rec.state === 'compensation_failed') return { outcome: 'replayed', record: rec };
        if (rec.state !== 'vetoed') return refused('not_vetoed', `a ${rec.state} record is not being compensated`);
        return next({ state: 'compensation_failed', outcome: { at: now, status: 'compensation_failed', reason: String(ev.reason).slice(0, 512) } }, 'compensation_failed', String(ev.reason).slice(0, 128));
      case 'retry':
        if (rec.state !== 'compensation_failed') return refused('not_failed', `a ${rec.state} record is not retried`);
        if (!isSafeInt(rec.attempt) || rec.attempt < 0) return refused('invalid', 'malformed record'); // a NaN attempt would make the once-per-attempt guard meaningless
        return next({ state: 'vetoed', attempt: rec.attempt + 1 }, 'retried');
      default:
        return refused('invalid', 'unknown event');
    }
  } catch {
    return refused('invalid', 'evaluation error (fail closed)');
  }
}

/** Append the signed receipt of an applied transition (linked to the previous one). */
export function withReceipt(rec: UndoRecord, r: { event: UndoEvent; note: string }, at: number, secret: Uint8Array): UndoRecord {
  const last = rec.receipts[rec.receipts.length - 1];
  const receipt = signUndoReceipt({ record: rec.id, event: r.event, state: rec.state, at, compensation_digest: rec.compensation_digest, prev: last ? undoReceiptDigest(last) : '', note: r.note }, secret);
  return { ...rec, receipts: [...rec.receipts, receipt] };
}

// ---- the store contract ---------------------------------------------------------------------------------------------------

export interface UndoQuery {
  state: UndoState;
  /** Only records whose window ended at or before this time (the finalize sweep). */
  windowEndedBy?: number;
  grantRef?: string;
  bondRef?: string;
  limit?: number;
}

/**
 * The persistence contract of the undo ledger. Implement it over a database (a row per record with a unique id and a version
 * column: `UPDATE ... WHERE id = $1 AND ver = $2`) or use {@link KvUndoStore}; run the conformance in `undo.test.ts` against it.
 */
export interface UndoStore {
  /** True ONLY when acknowledged writes survive a restart or crash. The coordinator refuses a store that does not say so. */
  readonly durable: boolean;
  get(id: string): Promise<UndoRecord | undefined>;
  /** Atomically insert if no record with this id exists; otherwise return the stored one unchanged. */
  create(rec: UndoRecord): Promise<{ created: true } | { created: false; record: UndoRecord }>;
  /** Atomically replace the record iff its stored `ver` is `expectedVer`. */
  replace(id: string, expectedVer: number, next: UndoRecord): Promise<boolean>;
  list(q: UndoQuery): Promise<UndoRecord[]>;
}

export function isUndoStore(s: unknown): s is UndoStore {
  const x = s as Partial<UndoStore> | null | undefined;
  return !!x && typeof x.get === 'function' && typeof x.create === 'function' && typeof x.replace === 'function' && typeof x.list === 'function' && typeof x.durable === 'boolean';
}

const matches = (r: UndoRecord, q: UndoQuery): boolean =>
  r.state === q.state && (q.windowEndedBy === undefined || r.window_end <= q.windowEndedBy) && (q.grantRef === undefined || r.grant_ref === q.grantRef) && (q.bondRef === undefined || r.bond_ref === q.bondRef);

function decodeRecord(raw: unknown): UndoRecord | undefined {
  if (raw === undefined) return undefined;
  if (!isObj(raw) || raw.v !== 1 || !idOk(raw.id) || !(UNDO_STATES as readonly string[]).includes(raw.state as string) || !isSafeInt(raw.ver) || !Array.isArray(raw.receipts)) throw new UndoError('store_corrupt', 'an undo record has the wrong shape');
  return raw as unknown as UndoRecord;
}

const PREFIX = 'pca-undo/v1/';

/**
 * The reference {@link UndoStore} over any {@link DurableKv} (one document per record, every write one atomic
 * read-modify-write). `durable` is declared by the caller because a kv cannot tell: true only over a persistent kv
 * (`openDurableState({ dir })` from `@atlasauth/pca/durable-state`), false over an in-memory one.
 * shortcut: `list` scans every key (fine for a single host's backlog); a database store indexes (state, window_end).
 */
export class KvUndoStore implements UndoStore {
  constructor(
    private readonly kv: DurableKv,
    readonly durable: boolean,
  ) {
    if (!kv || typeof kv.get !== 'function' || typeof kv.update !== 'function' || typeof kv.keys !== 'function') throw new UndoError('store_missing', 'KvUndoStore needs a DurableKv');
    if (typeof durable !== 'boolean') throw new UndoError('invalid', 'say whether the kv is durable (true or false)');
  }
  private k(id: string): string {
    if (!idOk(id)) throw new UndoError('invalid', 'an undo record id is a non-empty string without control characters');
    return PREFIX + id;
  }
  async get(id: string): Promise<UndoRecord | undefined> {
    const r = decodeRecord(await this.kv.get(this.k(id)));
    return r === undefined ? undefined : structuredClone(r);
  }
  async create(rec: UndoRecord): Promise<{ created: true } | { created: false; record: UndoRecord }> {
    let existing: UndoRecord | undefined;
    await this.kv.update(this.k(rec.id), (prev) => {
      existing = decodeRecord(prev);
      return existing ? undefined : structuredClone(rec);
    });
    return existing ? { created: false, record: structuredClone(existing) } : { created: true };
  }
  async replace(id: string, expectedVer: number, next: UndoRecord): Promise<boolean> {
    if (next.id !== id) throw new UndoError('invalid', 'replace: the record id cannot change');
    let done = false;
    await this.kv.update(this.k(id), (prev) => {
      const cur = decodeRecord(prev);
      done = cur !== undefined && cur.ver === expectedVer;
      return done ? structuredClone(next) : undefined;
    });
    return done;
  }
  async list(q: UndoQuery): Promise<UndoRecord[]> {
    const out: UndoRecord[] = [];
    for (const key of (await this.kv.keys()).filter((x) => x.startsWith(PREFIX)).sort()) {
      const r = decodeRecord(await this.kv.get(key));
      if (r && matches(r, q)) out.push(structuredClone(r));
      if (q.limit !== undefined && out.length >= q.limit) break;
    }
    return out;
  }
}

/**
 * A process-memory {@link UndoStore}: `durable` is false, so the coordinator refuses it unless the caller says, for a test,
 * that it accepts losing every open window on restart. Never use it in production.
 */
export class MemoryUndoStore implements UndoStore {
  readonly durable = false;
  private readonly m = new Map<string, UndoRecord>();
  async get(id: string) {
    const r = this.m.get(id);
    return r ? structuredClone(r) : undefined;
  }
  async create(rec: UndoRecord): Promise<{ created: true } | { created: false; record: UndoRecord }> {
    if (!idOk(rec?.id)) throw new UndoError('invalid', 'an undo record id is a non-empty string without control characters');
    const cur = this.m.get(rec.id);
    if (cur) return { created: false, record: structuredClone(cur) };
    this.m.set(rec.id, structuredClone(rec));
    return { created: true };
  }
  async replace(id: string, expectedVer: number, next: UndoRecord) {
    if (next.id !== id) throw new UndoError('invalid', 'replace: the record id cannot change');
    if (this.m.get(id)?.ver !== expectedVer) return false;
    this.m.set(id, structuredClone(next));
    return true;
  }
  async list(q: UndoQuery) {
    const out = [...this.m.values()].filter((r) => matches(r, q)).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return structuredClone(q.limit !== undefined ? out.slice(0, q.limit) : out);
  }
}

/** Clamp a requested window into [max(UNDO_MIN_WINDOW_MS, minMs), maxMs]; absent or non-finite -> the default. */
export function resolveUndoWindow(requestedMs: number | undefined, policy: { minMs?: number; maxMs?: number; defaultMs?: number } = {}): number {
  const min = Math.max(UNDO_MIN_WINDOW_MS, policy.minMs ?? UNDO_MIN_WINDOW_MS);
  const max = Math.max(min, Math.min(policy.maxMs ?? UNDO_MAX_WINDOW_MS, UNDO_MAX_WINDOW_MS));
  const want = typeof requestedMs === 'number' && Number.isFinite(requestedMs) ? requestedMs : (policy.defaultMs ?? UNDO_DEFAULT_WINDOW_MS);
  return Math.floor(Math.min(max, Math.max(min, want)));
}
