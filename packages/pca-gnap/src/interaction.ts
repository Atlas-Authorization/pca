/**
 * GNAP INTERACTION MODES (RFC 9635 sections 2.5, 3.3, 4, 5.1): the four start modes (`redirect`, `app`, `user_code`,
 * `user_code_uri`), the two finish methods (`redirect`, `push`), the interaction hash, one-time interaction references,
 * and an authorization-server state machine (pending -> approved -> finalized). The approved interaction then continues
 * through the existing PCA step-up continuation (`beginGnapContinuation` / `completeGnapContinuation`).
 * Source: https://www.rfc-editor.org/rfc/rfc9635 (fetched). The interaction-hash example in the RFC is a test vector.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const START_MODES = ['redirect', 'app', 'user_code', 'user_code_uri'] as const;
export type StartMode = (typeof START_MODES)[number];
export const FINISH_METHODS = ['redirect', 'push'] as const;
export type FinishMethod = (typeof FINISH_METHODS)[number];
/** Named Information hash names (IANA) this implementation computes. */
export const HASH_METHODS = { 'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512', 'sha3-256': 'sha3-256', 'sha3-512': 'sha3-512' } as const;
export type HashMethod = keyof typeof HASH_METHODS;

export type StartEntry = string | { mode: string; [k: string]: unknown };
export interface InteractFinish {
  method: string;
  uri: string;
  nonce: string;
  hash_method?: string;
}
export interface InteractRequestFull {
  start: StartEntry[];
  finish?: InteractFinish;
  hints?: Record<string, unknown>;
}
export interface InteractResponse {
  redirect?: string;
  app?: string;
  user_code?: string;
  user_code_uri?: { code: string; uri: string };
  /** The AS nonce for the interaction hash. */
  finish?: string;
  expires_in?: number;
}

export type InteractionErrorCode =
  | 'invalid_interaction' | 'unknown_interaction' | 'too_many_attempts' | 'invalid_request' | 'expired' | 'wrong_state' | 'unsupported_hash';
export class InteractionError extends Error {
  constructor(readonly code: InteractionErrorCode, message: string) {
    super(message);
    this.name = 'InteractionError';
  }
}

const startName = (e: StartEntry): string | undefined => (typeof e === 'string' ? e : typeof e === 'object' && e !== null && typeof e.mode === 'string' ? e.mode : undefined);

/** RFC 9635 2.5.2: absolute URI, no fragment; HTTPS, loopback, or an application-specific scheme (not plain http to a remote host). */
export function callbackUriOk(uri: unknown): boolean {
  if (typeof uri !== 'string' || uri.length > 2048) return false;
  let u: URL;
  try {
    u = new URL(uri);
  } catch {
    return false;
  }
  if (u.hash !== '' || uri.includes('#')) return false;
  if (u.protocol === 'https:') return true;
  if (u.protocol === 'http:') return u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  return u.protocol !== 'javascript:' && u.protocol !== 'data:' && u.protocol !== 'file:' && u.protocol !== 'blob:';
}

/** Validate an `interact` request; returns the problems (empty = valid). Unknown start modes are tolerated (registry is open). */
export function validateInteractRequest(r: unknown): string[] {
  const e: string[] = [];
  if (typeof r !== 'object' || r === null || Array.isArray(r)) return ['interact must be an object'];
  const o = r as Partial<InteractRequestFull>;
  if (!Array.isArray(o.start) || o.start.length === 0 || o.start.length > 16) e.push('start must be a non-empty array of modes');
  else for (const s of o.start) if (startName(s) === undefined) e.push('each start entry is a mode name or an object with a mode');
  if (o.finish !== undefined) {
    const f = o.finish;
    if (typeof f !== 'object' || f === null) e.push('finish must be an object');
    else {
      if (!(FINISH_METHODS as readonly string[]).includes(f.method)) e.push('finish.method must be redirect or push');
      if (!callbackUriOk(f.uri)) e.push('finish.uri must be an absolute https, loopback or app-scheme URI without a fragment');
      if (typeof f.nonce !== 'string' || f.nonce.length < 8 || f.nonce.length > 256 || !/^[\x21-\x7e]+$/.test(f.nonce)) e.push('finish.nonce must be 8..256 printable ASCII characters');
      if (f.hash_method !== undefined && !(f.hash_method in HASH_METHODS)) e.push('finish.hash_method is not a supported Named Information hash');
    }
  }
  return e;
}

/** RFC 9635 4.2.3: base64url(no padding) of HASH(clientNonce \n asNonce \n interactRef \n grantEndpointUri). */
export function interactionHash(a: { clientNonce: string; asNonce: string; interactRef: string; grantEndpoint: string; hashMethod?: string }): string {
  const m = a.hashMethod ?? 'sha-256';
  if (!(m in HASH_METHODS)) throw new InteractionError('unsupported_hash', `hash_method ${m} is not supported`);
  return createHash(HASH_METHODS[m as HashMethod]).update(`${a.clientNonce}\n${a.asNonce}\n${a.interactRef}\n${a.grantEndpoint}`, 'ascii').digest('base64url');
}

/** Client side: does the callback's `hash` match? Constant time; a non-validating hash means the interact_ref MUST NOT be sent. */
export function verifyInteractionHash(received: unknown, a: Parameters<typeof interactionHash>[0]): boolean {
  if (typeof received !== 'string') return false;
  const want = Buffer.from(interactionHash(a));
  const got = Buffer.from(received);
  return want.length === got.length && timingSafeEqual(want, got);
}

/** 6..8 chars from an alphabet without look-alikes; compared case-insensitively (RFC 9635 3.3.3). */
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export function newUserCode(len = 8): string {
  if (len < 6 || len > 12) throw new RangeError('user code length 6..12');
  const b = randomBytes(len);
  let s = '';
  // 32-symbol alphabet, 256 % 32 === 0: no modulo bias.
  for (let i = 0; i < len; i++) s += CODE_ALPHABET[b[i]! % 32];
  return s;
}
const normCode = (c: string): string => c.replace(/[\s-]/g, '').toUpperCase();

export type InteractionState = 'pending' | 'approved' | 'finalized';
export interface Interaction {
  id: string;
  state: InteractionState;
  grantEndpoint: string;
  modes: StartMode[];
  finish?: { method: FinishMethod; uri: string; clientNonce: string; asNonce: string; hashMethod: string };
  userCode?: string;
  /** Set when the resource owner approves; single use. */
  interactRef?: string;
  refUsed: boolean;
  expiresAt: number;
}

export interface InteractionServerOptions {
  grantEndpoint: string;
  /** Modes this AS supports. */
  supports: StartMode[];
  /** Build the (unique, non-sensitive) interaction URIs. */
  redirectUri: (id: string) => string;
  appUri?: (id: string) => string;
  userCodeUri?: string;
  ttlSec?: number;
  now: () => number;
}

/**
 * AS side. The response never includes a mode the client did not ask for nor one the AS does not support (RFC 9635 3.3),
 * and each interaction's `interact_ref` is single use: a second presentation is `too_many_attempts` and finalizes the grant.
 */
export class InteractionServer {
  private readonly byId = new Map<string, Interaction>();
  private readonly byCode = new Map<string, string>();
  private readonly byRef = new Map<string, string>();
  constructor(private readonly o: InteractionServerOptions) {}

  start(req: InteractRequestFull): { interaction: Interaction; response: InteractResponse } {
    const problems = validateInteractRequest(req);
    if (problems.length) throw new InteractionError('invalid_request', problems.join('; '));
    const asked = new Set(req.start.map(startName));
    const modes = this.o.supports.filter((m) => asked.has(m) && (m !== 'app' || this.o.appUri) && (m !== 'user_code_uri' || this.o.userCodeUri));
    if (modes.length === 0 && !req.finish) throw new InteractionError('invalid_interaction', 'no requested interaction mode is supported');
    const id = randomBytes(16).toString('base64url');
    const ttl = this.o.ttlSec ?? 600;
    const it: Interaction = { id, state: 'pending', grantEndpoint: this.o.grantEndpoint, modes, refUsed: false, expiresAt: this.o.now() + ttl };
    const res: InteractResponse = { expires_in: ttl };
    if (modes.includes('redirect')) res.redirect = this.o.redirectUri(id);
    if (modes.includes('app')) res.app = this.o.appUri!(id);
    if (modes.includes('user_code') || modes.includes('user_code_uri')) {
      it.userCode = newUserCode();
      this.byCode.set(it.userCode, id);
      if (modes.includes('user_code')) res.user_code = it.userCode;
      if (modes.includes('user_code_uri')) res.user_code_uri = { code: it.userCode, uri: this.o.userCodeUri! };
    }
    if (req.finish) {
      const asNonce = randomBytes(24).toString('base64url');
      it.finish = { method: req.finish.method as FinishMethod, uri: req.finish.uri, clientNonce: req.finish.nonce, asNonce, hashMethod: req.finish.hash_method ?? 'sha-256' };
      res.finish = asNonce;
    }
    this.byId.set(id, it);
    return { interaction: it, response: res };
  }

  /** The resource owner typed a code. Case-insensitive. A 32^8 code space is only safe behind a per-source rate limit on this lookup: the caller MUST apply one. */
  lookupUserCode(code: string): Interaction | undefined {
    const id = this.byCode.get(normCode(code));
    const it = id ? this.byId.get(id) : undefined;
    if (!it || it.state !== 'pending' || this.o.now() > it.expiresAt) return undefined;
    return it;
  }

  get(id: string): Interaction | undefined {
    return this.byId.get(id);
  }

  /** The resource owner approved. Returns the finish message to deliver (redirect URL or push body), or none without a finish method. */
  approve(id: string): { interactRef: string; finish?: { method: 'redirect'; url: string } | { method: 'push'; uri: string; body: { hash: string; interact_ref: string } } } {
    const it = this.live(id);
    if (it.state !== 'pending') throw new InteractionError('wrong_state', `interaction is ${it.state}`);
    it.state = 'approved';
    it.interactRef = randomBytes(18).toString('base64url');
    this.byRef.set(it.interactRef, id);
    if (it.userCode) this.byCode.delete(it.userCode);
    if (!it.finish) return { interactRef: it.interactRef };
    const hash = interactionHash({ clientNonce: it.finish.clientNonce, asNonce: it.finish.asNonce, interactRef: it.interactRef, grantEndpoint: it.grantEndpoint, hashMethod: it.finish.hashMethod });
    if (it.finish.method === 'push') return { interactRef: it.interactRef, finish: { method: 'push', uri: it.finish.uri, body: { hash, interact_ref: it.interactRef } } };
    const u = new URL(it.finish.uri);
    u.searchParams.set('hash', hash);
    u.searchParams.set('interact_ref', it.interactRef);
    return { interactRef: it.interactRef, finish: { method: 'redirect', url: u.toString() } };
  }

  /** Continuation (RFC 9635 5.1): present the interact_ref once. A replay finalizes the grant and is `too_many_attempts`. */
  consume(interactRef: string): Interaction {
    const id = this.byRef.get(interactRef);
    const it = id ? this.byId.get(id) : undefined;
    if (!it) throw new InteractionError('unknown_interaction', 'no such interaction reference');
    if (it.refUsed || it.state === 'finalized') {
      it.state = 'finalized';
      throw new InteractionError('too_many_attempts', 'the interaction reference was already used');
    }
    if (this.o.now() > it.expiresAt) throw new InteractionError('expired', 'the interaction expired');
    if (it.state !== 'approved') throw new InteractionError('wrong_state', `interaction is ${it.state}`);
    it.refUsed = true;
    return it;
  }
  finalize(id: string): void {
    const it = this.byId.get(id);
    if (it) it.state = 'finalized';
  }
  private live(id: string): Interaction {
    const it = this.byId.get(id);
    if (!it) throw new InteractionError('unknown_interaction', 'no such interaction');
    if (this.o.now() > it.expiresAt) throw new InteractionError('expired', 'the interaction expired');
    return it;
  }
}

/** Client side: validate a finish callback (query for redirect, JSON body for push). Returns the interact_ref to send, or throws unknown_interaction. */
export function acceptFinish(cb: { hash?: unknown; interact_ref?: unknown }, ctx: { clientNonce: string; asNonce: string; grantEndpoint: string; hashMethod?: string }): string {
  if (typeof cb.interact_ref !== 'string' || cb.interact_ref === '' || typeof cb.hash !== 'string') throw new InteractionError('unknown_interaction', 'hash and interact_ref are required');
  if (!verifyInteractionHash(cb.hash, { ...ctx, interactRef: cb.interact_ref })) throw new InteractionError('unknown_interaction', 'the callback hash does not validate');
  return cb.interact_ref;
}

// ---- GNAP access[] <-> typed needs (grant management, incremental authorization) -----------------------------------

/** Structurally the `Need` of the grant management resource. */
export interface AccessNeed {
  verb: string;
  resource: string;
}
/**
 * One need per (action, location) pair, resource namespaced as `gnap:<type>:<location>` exactly like {@link gnapActionResource}.
 * An access right with no `actions` or no `locations` is a wildcard and is REFUSED here (a need must be explicit; ask for `*` on purpose).
 */
export function accessToNeeds(access: ReadonlyArray<{ type: string; actions?: string[]; locations?: string[] }>): AccessNeed[] {
  const out: AccessNeed[] = [];
  for (const a of access) {
    if (!a.actions?.length || !a.locations?.length) throw new InteractionError('invalid_request', `access "${a.type}" needs explicit actions and locations to become a need`);
    for (const verb of a.actions) for (const loc of a.locations) out.push({ verb, resource: `gnap:${a.type}:${loc}` });
  }
  return out;
}
