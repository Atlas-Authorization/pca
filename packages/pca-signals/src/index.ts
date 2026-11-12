/**
 * Shared Signals Framework (SSF / CAEP) for Proof-Carrying Authority — the ACTIVE revocation and
 * mid-run kill-switch channel.
 *
 * Honest framing (compose, don't replace):
 *   PCA's native enforcement is PASSIVE. A verifier (`@atlasauth/pca` `requirePCA`) checks a signed
 *   PCActn default-deny, and the grant's own counter / budget / revocation-epoch bound how much a valid
 *   proof may do. That is a PULL model: the resource server decides from what it already holds. What it
 *   does NOT give you is a PUSH: a way for the issuer to say, mid-run, "stop — this grant is dead" to a
 *   resource server that is holding a PCActn which is still cryptographically valid and still inside its
 *   budget.
 *
 *   The OpenID **Shared Signals Framework (SSF)** and its **Continuous Access Evaluation Profile (CAEP)**
 *   are the industry-standard push channel for exactly that. A transmitter emits a **Security Event Token
 *   (SET, RFC 8417)** — a JWT carrying an `events` claim — and subscribers fold those events into local
 *   state they consult on every request. This package implements that channel for PCA: it builds and
 *   verifies SETs for CAEP `session-revoked` / `credential-change` plus two PCA-specific event types
 *   (`grant-revoked`, `kill-switch`), and it maintains the subscriber-side revocation state a resource
 *   server consults ALONGSIDE `requirePCA`. A revoked grant denies the action even when the PCActn is
 *   valid and in-budget. SSF/CAEP is the active channel; the budget/counter remain the passive floor.
 *   Neither replaces the other — they compose.
 *
 * Specs implemented (cited per export):
 *   - OpenID **Shared Signals Framework (SSF)** 1.0 — the stream/transmitter/receiver model and the SET
 *     delivery envelope.            https://openid.net/specs/openid-sharedsignals-framework-1_0.html
 *   - OpenID **CAEP** 1.0 — Continuous Access Evaluation Profile; defines `session-revoked`,
 *     `credential-change` and the CAEP event-payload shape (`event_timestamp`, `subject`, reasons).
 *                                   https://openid.net/specs/openid-caep-1_0.html
 *   - **RFC 8417** — Security Event Token (SET): a JWT with an `events` claim; `typ` SHOULD be
 *     `secevent+jwt`; `iss`, `iat`, `jti`, `aud` apply; `events` is a JSON object keyed by event-type URI.
 *                                   https://www.rfc-editor.org/rfc/rfc8417
 *   - **RFC 9493** — Subject Identifiers for SETs (the structured `sub_id` / per-event `subject`).
 *                                   https://www.rfc-editor.org/rfc/rfc9493
 *
 * Signing: EdDSA (Ed25519) via `jose`. The transmitter signs; subscribers verify with the transmitter's
 * public key. Pure data + crypto — no I/O, no framework.
 */

import { SignJWT, jwtVerify, type KeyLike, type JWTPayload } from 'jose';
import { assertCanonicalCompactJws } from '@atlasauth/pca';
import type { Capability, Hook, PCActn, VerifyContext } from '@atlasauth/pca';
import { randomUUID } from 'node:crypto';

/** RFC 8417 §2.3: a SET SHOULD carry `typ: "secevent+jwt"` so it cannot be confused with an access/ID token. */
export const SET_TYP = 'secevent+jwt';

/** The JWS algorithm this package signs/verifies SETs with (CAEP transmitters commonly use EdDSA). */
export const SET_ALG = 'EdDSA';

/**
 * Event-type URIs carried as keys of the SET `events` map (RFC 8417 §1.2, §2.2).
 *   - the two CAEP standard types (OpenID CAEP 1.0 §3) live under `schemas.openid.net`;
 *   - the two PCA-specific types live under `atlasauth.net/caep` (a collision-resistant URI, as the SET
 *     spec requires for profile extensions).
 */
export const EVENT_TYPES = {
  /** CAEP 1.0 §3.4 — a session for the subject has been revoked. */
  sessionRevoked: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  /** CAEP 1.0 §3.5 — a credential for the subject changed (created/revoked/updated/deleted). */
  credentialChange: 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
  /** PCA — a single grant (by `grant_ref`) is revoked; a held PCActn under it must now be denied. */
  grantRevoked: 'https://atlasauth.net/caep/grant-revoked',
  /** PCA — a mid-run kill-switch for an agent: revoke EVERY grant that agent holds, now. */
  killSwitch: 'https://atlasauth.net/caep/kill-switch',
  /**
   * PCA Intent Layer v2 (§3.9) — intent artifacts revoked by the principal: session ids, map digests, delta-grant ids,
   * profile versions, as the namespaced revocation ids of `@atlasauth/pca` (`pca-intent:session:<σ>`, ...). Push is
   * best effort: the signed-epoch pull bound (T22) is the guarantee.
   */
  intentRevoked: 'https://atlasauth.net/caep/intent-revoked',
  /** SSF 1.0 §8.1.4.1 — stream verification (`state` echoed back). */
  verification: 'https://schemas.openid.net/secevent/ssf/event-type/verification',
  /** CAEP 1.0 — the risk level of a principal changed (emitted from the immune system). */
  riskLevelChange: 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change',
  /** CAEP 1.0 — the assurance level of a principal changed (emitted on discharge changes). */
  assuranceLevelChange: 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
} as const;

/** A CAEP/SSF Subject Identifier (RFC 9493). Opaque to this package; carried verbatim. */
export interface SubjectIdentifier {
  /** RFC 9493 §3 — the subject identifier format (e.g. `opaque`, `email`, `iss_sub`). */
  format: string;
  [member: string]: unknown;
}

/** PCA `grant-revoked` event payload: `{ grant_ref, agent?, reason, event_timestamp }`. */
export interface GrantRevokedEvent {
  /** The PCA grant reference (matches a PCActn's `grant_ref`). */
  grant_ref: string;
  /** Optional agent id this grant belonged to (informational on a per-grant revoke). */
  agent?: string;
  /** Why the grant was revoked. */
  reason: string;
  /** CAEP `event_timestamp`: integer seconds since the epoch at which the event occurred. */
  event_timestamp: number;
  /** Optional CAEP/RFC 9493 subject identifier. */
  subject?: SubjectIdentifier;
}

/** PCA `kill-switch` event payload: revoke everything the named agent holds. */
export interface KillSwitchEvent {
  /** The agent whose grants are all revoked. */
  agent: string;
  /** Optionally also name one grant explicitly (still revokes the whole agent). */
  grant_ref?: string;
  /** Why the kill-switch fired. */
  reason: string;
  /** CAEP `event_timestamp`: integer seconds since the epoch. */
  event_timestamp: number;
  /** Optional CAEP/RFC 9493 subject identifier. */
  subject?: SubjectIdentifier;
}

/** PCA `intent-revoked` payload: `{ ids, session?, reason, event_timestamp }`. */
export interface IntentRevokedEvent {
  /** Namespaced intent revocation ids (`pca-intent:session:…`, `pca-intent:map:…`, `pca-intent:delta:…`, `pca-intent:profile:…@v`). */
  ids: string[];
  /** The session the revocation is about, when there is one. */
  session?: string;
  reason: string;
  /** CAEP `event_timestamp`: integer seconds since the epoch. */
  event_timestamp: number;
  subject?: SubjectIdentifier;
}

/** CAEP 1.0 §3.4 `session-revoked` payload. */
export interface CaepSessionRevokedEvent {
  /** RFC 9493 subject whose session was revoked. */
  subject?: SubjectIdentifier;
  /** Integer seconds since the epoch. */
  event_timestamp: number;
  /** CAEP admin-facing reason. */
  reason_admin?: string;
  /** CAEP user-facing reason. */
  reason_user?: string;
}

/** CAEP 1.0 §3.5 `credential-change` payload. */
export interface CaepCredentialChangeEvent {
  /** RFC 9493 subject whose credential changed. */
  subject?: SubjectIdentifier;
  /** Integer seconds since the epoch. */
  event_timestamp: number;
  /** CAEP `credential_type` (e.g. `password`, `pin`, `fido2-platform`). */
  credential_type?: string;
  /** CAEP `change_type`. */
  change_type?: 'create' | 'revoke' | 'update' | 'delete';
  /** CAEP admin-facing reason. */
  reason_admin?: string;
}

/** SSF 1.0 §8.1.4.1 verification event payload: the receiver's opaque `state`, echoed. */
export interface SsfVerificationEvent {
  state?: string;
  /** Not defined for verification events; typed so payload readers can treat the union uniformly. */
  event_timestamp?: number;
}
/** CAEP 1.0 `risk-level-change`. */
export interface CaepRiskLevelChangeEvent {
  /** `USER`, `DEVICE`, `SESSION`, `TENANT`, `ORG_UNIT`, `GROUP` (or another SSF entity). */
  principal: string;
  current_level: 'LOW' | 'MEDIUM' | 'HIGH';
  previous_level?: 'LOW' | 'MEDIUM' | 'HIGH';
  risk_reason?: string;
  event_timestamp: number;
  subject?: SubjectIdentifier;
}
/** CAEP 1.0 `assurance-level-change`. */
export interface CaepAssuranceLevelChangeEvent {
  namespace: string;
  current_level: string;
  previous_level?: string;
  change_direction?: 'increase' | 'decrease';
  event_timestamp: number;
  subject?: SubjectIdentifier;
}

/** The union of every event payload this package understands. */
export type SetEventPayload =
  | SsfVerificationEvent
  | CaepRiskLevelChangeEvent
  | CaepAssuranceLevelChangeEvent
  | GrantRevokedEvent
  | KillSwitchEvent
  | IntentRevokedEvent
  | CaepSessionRevokedEvent
  | CaepCredentialChangeEvent;

/**
 * The SET `events` claim (RFC 8417 §2.2): a JSON object keyed by event-type URI. The four known types
 * are named for ergonomics; the open index signature keeps the map faithful to the spec (a SET MAY carry
 * event types a given receiver does not recognise).
 */
export interface SetEvents {
  'https://schemas.openid.net/secevent/caep/event-type/session-revoked'?: CaepSessionRevokedEvent;
  'https://schemas.openid.net/secevent/caep/event-type/credential-change'?: CaepCredentialChangeEvent;
  'https://atlasauth.net/caep/grant-revoked'?: GrantRevokedEvent;
  'https://atlasauth.net/caep/kill-switch'?: KillSwitchEvent;
  'https://atlasauth.net/caep/intent-revoked'?: IntentRevokedEvent;
  [eventTypeUri: string]: SetEventPayload | undefined;
}

/** A private key able to sign an EdDSA JWS (jose `KeyLike`, or a raw key as `Uint8Array`). */
export type SigningKey = KeyLike | Uint8Array;
/** A public key able to verify an EdDSA JWS. */
export type VerifyKey = KeyLike | Uint8Array;

/** Arguments to {@link buildSET}. */
export interface BuildSetArgs {
  /** The `events` map (RFC 8417 §2.2); at least one entry is required. */
  events: SetEvents;
  /** The SET issuer — the transmitter (`iss`). */
  issuer: string;
  /** The intended receiver(s) (`aud`). */
  audience: string | string[];
  /**
   * Optional SET-level subject. Emitted both as the RFC 8417 `sub` claim and, per RFC 9493 / SSF, as a
   * structured `sub_id` (opaque format). Per-event subjects live in each event's own `subject` field.
   */
  subject?: string;
  /** The transmitter's EdDSA private key. */
  key: SigningKey;
}

/**
 * Build a signed Security Event Token (RFC 8417). Sets `typ: secevent+jwt`, `iss`, `iat`, a random `jti`,
 * `aud`, the `events` map, and (if given) `sub` + `sub_id`. Signs EdDSA via `jose`.
 */
export async function buildSET(args: BuildSetArgs): Promise<string> {
  const { events, issuer, audience, subject, key } = args;
  if (events === null || typeof events !== 'object' || Object.keys(events).length === 0) {
    throw new Error('buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)');
  }
  const payload: JWTPayload & { events: SetEvents; sub_id?: SubjectIdentifier } = { events };
  if (subject !== undefined) {
    payload.sub_id = { format: 'opaque', id: subject };
  }
  const signer = new SignJWT(payload)
    .setProtectedHeader({ alg: SET_ALG, typ: SET_TYP })
    .setIssuer(issuer)
    .setIssuedAt()
    .setJti(randomUUID())
    .setAudience(audience);
  if (subject !== undefined) {
    signer.setSubject(subject);
  }
  return signer.sign(key);
}

/** Options for {@link verifySET}. Forwarded to `jose` `jwtVerify` (algorithm is pinned to EdDSA). */
export interface VerifySetOptions {
  /** Require this issuer (`iss`). */
  issuer?: string | string[];
  /** Require this audience (`aud`). */
  audience?: string | string[];
  /** Clock skew tolerance for `iat`/`exp`. */
  clockTolerance?: string | number;
  /** Pin "now" (testing). */
  currentDate?: Date;
  /** Override the required `typ` header (default `secevent+jwt`). */
  typ?: string;
  /** Set `false` to skip the `typ` check entirely. */
  requireTyp?: boolean;
}

/** The parsed result of a verified SET. */
export interface ParsedSet {
  /** The validated `events` map. */
  events: SetEvents;
  /** The issuer (`iss`). */
  iss: string;
  /** The SET id (`jti`) — RFC 8417 requires it; de-dup replays on this. */
  jti: string;
  /** The SET-level subject (`sub`), if present. */
  sub?: string;
  /** The full verified JWT payload, for callers that need other claims. */
  payload: JWTPayload;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function parseEvents(raw: unknown): SetEvents {
  if (!isRecord(raw)) {
    throw new Error('SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)');
  }
  const keys = Object.keys(raw);
  if (keys.length === 0) {
    throw new Error('SET invalid: `events` claim is empty (RFC 8417 §2.2)');
  }
  for (const k of keys) {
    if (!isRecord(raw[k])) {
      throw new Error(`SET invalid: event payload for \`${k}\` is not a JSON object (RFC 8417 §2.2)`);
    }
  }
  return raw as SetEvents;
}

/**
 * Verify a SET's signature (EdDSA) and standard claims, then parse it. Throws on any invalid signature,
 * wrong key, failed claim check (`iss`/`aud`/`typ`), or a malformed/empty `events` map.
 */
export async function verifySET(
  set: string,
  verifyKey: VerifyKey,
  opts: VerifySetOptions = {},
): Promise<ParsedSet> {
  assertCanonicalCompactJws(set); // canonical-spelling gate BEFORE jose (one accepted string form)
  const { payload } = await jwtVerify(set, verifyKey, {
    algorithms: [SET_ALG],
    ...(opts.issuer !== undefined ? { issuer: opts.issuer } : {}),
    ...(opts.audience !== undefined ? { audience: opts.audience } : {}),
    ...(opts.clockTolerance !== undefined ? { clockTolerance: opts.clockTolerance } : {}),
    ...(opts.currentDate !== undefined ? { currentDate: opts.currentDate } : {}),
    ...(opts.requireTyp === false ? {} : { typ: opts.typ ?? SET_TYP }),
  });
  if (typeof payload.iss !== 'string') {
    throw new Error('SET invalid: missing or non-string `iss`');
  }
  if (typeof payload.jti !== 'string') {
    throw new Error('SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)');
  }
  const events = parseEvents(payload.events);
  return {
    events,
    iss: payload.iss,
    jti: payload.jti,
    sub: typeof payload.sub === 'string' ? payload.sub : undefined,
    payload,
  };
}

/**
 * Subscriber-side revocation state. A resource server holds one of these and consults {@link isRevoked}
 * on every request, alongside `requirePCA`. Both maps store the `event_timestamp` (seconds) of the
 * revoking event; revocation is MONOTONE — a key, once present, is never removed.
 */
export interface RevocationState {
  /** grant_ref → event_timestamp of the revoking event. */
  revokedGrants: Map<string, number>;
  /** agent id → event_timestamp of the kill-switch that revoked all of its grants. */
  killedAgents: Map<string, number>;
  /** intent revocation id → event_timestamp of the `intent-revoked` event that named it (created on first use). */
  revokedIntentIds?: Map<string, number>;
}

/** A fresh, empty revocation state. */
export function createRevocationState(): RevocationState {
  return { revokedGrants: new Map(), killedAgents: new Map() };
}

function recordMax(m: Map<string, number>, key: string, ts: number): void {
  const prev = m.get(key);
  if (prev === undefined || ts > prev) {
    m.set(key, ts);
  }
}

/**
 * Fold one verified SET into the state. A `grant-revoked` adds its `grant_ref` to the revoked set; a
 * `kill-switch` revokes every grant of its `agent` (and any explicit `grant_ref`). `event_timestamp` is
 * respected: each key keeps the MAX timestamp seen, so a stale (older) event never regresses the state,
 * and — revocation being monotone — never un-revokes. The two CAEP standard events are validated and
 * folded but do not by themselves revoke a PCA grant (they are session/credential-scoped). Returns the
 * same (mutated) state for chaining.
 */
export function applySET(state: RevocationState, parsed: ParsedSet): RevocationState {
  for (const [type, ev] of Object.entries(parsed.events)) {
    if (ev === undefined) {
      continue;
    }
    const ts = typeof ev.event_timestamp === 'number' ? ev.event_timestamp : 0;
    if (type === EVENT_TYPES.grantRevoked) {
      const { grant_ref: grantRef } = ev as GrantRevokedEvent;
      if (typeof grantRef === 'string' && grantRef.length > 0) {
        recordMax(state.revokedGrants, grantRef, ts);
      }
    } else if (type === EVENT_TYPES.killSwitch) {
      const { agent, grant_ref: grantRef } = ev as KillSwitchEvent;
      if (typeof agent === 'string' && agent.length > 0) {
        recordMax(state.killedAgents, agent, ts);
      }
      if (typeof grantRef === 'string' && grantRef.length > 0) {
        recordMax(state.revokedGrants, grantRef, ts);
      }
    } else if (type === EVENT_TYPES.intentRevoked) {
      const { ids } = ev as IntentRevokedEvent;
      if (Array.isArray(ids)) {
        for (const id of ids) {
          if (typeof id === 'string' && id.startsWith('pca-intent:')) recordMax((state.revokedIntentIds ??= new Map()), id, ts);
        }
      }
    }
  }
  return state;
}

/** Has a pushed `intent-revoked` event named this intent revocation id? (Best effort; the epoch pull bound decides.) */
export function isIntentRevoked(state: RevocationState, id: string): boolean {
  return state.revokedIntentIds?.has(id) === true;
}

/**
 * Is this grant revoked? True if the grant_ref was revoked directly, or (when `agent` is supplied) a
 * kill-switch revoked that agent. This is the check a resource server runs next to `requirePCA`: a
 * revoked grant is denied even with a valid, in-budget PCActn.
 */
export function isRevoked(state: RevocationState, grantRef: string, agent?: string): boolean {
  if (state.revokedGrants.has(grantRef)) {
    return true;
  }
  if (agent !== undefined && state.killedAgents.has(agent)) {
    return true;
  }
  return false;
}

function setTimestamp(p: ParsedSet): number {
  let min = Number.POSITIVE_INFINITY;
  for (const ev of Object.values(p.events)) {
    if (ev !== undefined && typeof ev.event_timestamp === 'number' && ev.event_timestamp < min) {
      min = ev.event_timestamp;
    }
  }
  return Number.isFinite(min) ? min : 0;
}

/**
 * Fold a sequence of verified SETs into one state, applying them in `event_timestamp` order (ascending).
 * Because {@link applySET} is itself order-independent (max-timestamp, monotone), ordering makes the fold
 * deterministic and replay-safe regardless of the delivery order a push stream happens to use. Returns
 * the (optionally supplied) state.
 */
export function streamProcessor(
  parsedSets: ParsedSet[],
  state: RevocationState = createRevocationState(),
): RevocationState {
  const ordered = [...parsedSets].sort((a, b) => setTimestamp(a) - setTimestamp(b));
  for (const p of ordered) {
    applySET(state, p);
  }
  return state;
}

// ================================================================================================
// Receiver: verify + replay-guard + fold, fail-closed (additive; `verifySET` / `applySET` are unchanged).
// ================================================================================================

/**
 * A durable `jti` replay store for received SETs. `addIfAbsent` MUST be atomic: of N concurrent calls with the
 * same `jti` exactly one returns `true`. An entry may be dropped once `nowSec >= expiresAtSec`. Back it with a
 * shared store (SQL unique key, Redis `SET NX EX`) when more than one process receives SETs; check yours with
 * {@link runSetReplayStoreConformance}.
 */
export interface SetReplayStore {
  addIfAbsent(jti: string, expiresAtSec: number, nowSec: number): boolean | Promise<boolean>;
}

/** Default capacity of {@link createInMemorySetReplayStore}. */
export const SET_INMEMORY_MAX_ENTRIES = 100_000;

/** A misconfiguration or malformed input to the revocation adapters. `code` names the check. */
export class SignalsError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'SignalsError';
    this.code = code;
  }
}

/**
 * Single-process store, explicitly bounded: state is lost on restart and not shared across processes. When `maxEntries`
 * live (unexpired) entries are held, a further new `jti` makes `addIfAbsent` THROW (`receiveSET` then refuses with
 * `replay_store_error`) instead of evicting a live entry, so a flood can never reopen a replay window.
 */
export function createInMemorySetReplayStore(opts: { maxEntries?: number } = {}): SetReplayStore {
  const max = opts.maxEntries ?? SET_INMEMORY_MAX_ENTRIES;
  if (!Number.isInteger(max) || max < 1) throw new SignalsError('misconfigured', 'maxEntries must be a positive integer');
  const seen = new Map<string, number>();
  return {
    addIfAbsent(jti, expiresAtSec, nowSec) {
      const held = seen.get(jti);
      if (held !== undefined && nowSec < held) return false;
      if (held === undefined && seen.size >= max) {
        for (const [k, exp] of seen) if (nowSec >= exp) seen.delete(k);
        if (seen.size >= max) throw new Error('replay store is full');
      }
      seen.set(jti, expiresAtSec);
      return true;
    },
  };
}

/**
 * Conformance suite for a {@link SetReplayStore}. Returns the list of failed checks (empty = conformant). Pass a
 * factory that returns a FRESH, empty store on each call.
 */
export async function runSetReplayStoreConformance(make: () => SetReplayStore): Promise<string[]> {
  const failures: string[] = [];
  const check = (ok: boolean, name: string): void => {
    if (!ok) failures.push(name);
  };
  const s = make();
  check((await s.addIfAbsent('a', 200, 100)) === true, 'first sight of a jti returns true');
  check((await s.addIfAbsent('a', 200, 101)) === false, 'second sight of the same jti returns false');
  check((await s.addIfAbsent('b', 200, 101)) === true, 'a different jti is independent');
  check((await s.addIfAbsent('a', 200, 199)) === false, 'still seen one second before expiry');
  const t = make();
  await t.addIfAbsent('c', 200, 100);
  check((await t.addIfAbsent('c', 400, 200)) === true, 'an expired entry may be added again (nowSec >= expiresAtSec)');
  const u = make();
  const wins = (await Promise.all(Array.from({ length: 16 }, () => u.addIfAbsent('race', 200, 100)))).filter(Boolean).length;
  check(wins === 1, `16 concurrent adds of one jti: exactly one wins (got ${wins})`);
  return failures;
}

/** Why {@link receiveSET} refused a token. Every refusal is a value, never a throw. */
export type ReceiveSetCode =
  | 'misconfigured'
  | 'oversize'
  | 'malformed'
  | 'verify_failed'
  | 'iat_missing'
  | 'iat_future'
  | 'iat_stale'
  | 'unmapped_subject'
  | 'replay'
  | 'replay_store_error';

export type ReceiveSetResult = { ok: true; parsed: ParsedSet } | { ok: false; code: ReceiveSetCode; reason: string };

/** Options for {@link receiveSET}. Every field except the clock ones is REQUIRED; a missing one is `misconfigured`. */
export interface ReceiveSetOptions {
  issuer: string | string[];
  audience: string | string[];
  /** Required replay store; there is no default. */
  replayStore: SetReplayStore;
  /** Revocation state to fold the verified events into. */
  state: RevocationState;
  /** Oldest acceptable `iat` age in seconds. Required: it also bounds how long the replay store must remember a `jti`. */
  maxAgeSec: number;
  /** Seconds a SET's `iat` may be ahead of the receiver (default 60). */
  clockSkewSec?: number;
  /** Pin "now" (epoch seconds), for tests. */
  nowSec?: number;
  /** Reject a SET string longer than this (default 16384). */
  maxBytes?: number;
  /**
   * Also turn the standard CAEP / RISC revocation events in the SET into `killedAgents` entries (see
   * {@link applyStandardRevocations}). Absent: only the PCA event types are applied. Planned BEFORE the `jti` is recorded,
   * so an event whose subject cannot be mapped under `failOnUnmapped` is refused without burning the id.
   */
  standardRevocations?: StandardRevocationOptions;
}

const fails = (code: ReceiveSetCode, reason: string): ReceiveSetResult => ({ ok: false, code, reason });

/**
 * The recommended receive path: size cap, canonical spelling, EdDSA signature, `typ`, required `iss` and `aud`,
 * `iat` freshness window, atomic `jti` replay guard, then fold into `state`. Order matters: the `jti` is recorded
 * only after every other check passed, so a forged token cannot burn a real SET's id. Fails closed on every error,
 * including a replay store that throws (the SET is NOT applied).
 */
export async function receiveSET(set: string, verifyKey: VerifyKey, opts: ReceiveSetOptions): Promise<ReceiveSetResult> {
  if (
    !opts ||
    opts.issuer === undefined ||
    opts.audience === undefined ||
    typeof opts.replayStore?.addIfAbsent !== 'function' ||
    !opts.state ||
    !Number.isFinite(opts.maxAgeSec) ||
    opts.maxAgeSec <= 0
  ) {
    return fails('misconfigured', 'issuer, audience, replayStore, state and a positive maxAgeSec are all required');
  }
  if (typeof set !== 'string' || set.length > (opts.maxBytes ?? 16384)) return fails('oversize', 'SET is not a string or exceeds maxBytes');
  try {
    assertCanonicalCompactJws(set);
  } catch (e) {
    return fails('malformed', e instanceof Error ? e.message : 'not a canonical compact JWS');
  }
  const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
  let parsed: ParsedSet;
  try {
    parsed = await verifySET(set, verifyKey, { issuer: opts.issuer, audience: opts.audience, currentDate: new Date(nowSec * 1000) });
  } catch (e) {
    return fails('verify_failed', e instanceof Error ? e.message : 'verification failed');
  }
  const iat = parsed.payload.iat;
  if (typeof iat !== 'number' || !Number.isFinite(iat)) return fails('iat_missing', 'SET has no numeric iat');
  const skew = opts.clockSkewSec ?? 60;
  if (iat > nowSec + skew) return fails('iat_future', 'SET iat is in the future');
  if (nowSec - iat > opts.maxAgeSec) return fails('iat_stale', `SET is older than ${opts.maxAgeSec}s`);
  let plan: StandardRevocationPlan | undefined;
  if (opts.standardRevocations !== undefined) {
    try {
      plan = planStandardRevocations(parsed, opts.standardRevocations);
    } catch (e) {
      return fails('unmapped_subject', e instanceof Error ? e.message : 'a revocation event could not be mapped to an agent');
    }
  }
  let fresh: boolean;
  try {
    fresh = await opts.replayStore.addIfAbsent(parsed.jti, iat + opts.maxAgeSec + skew, nowSec);
  } catch (e) {
    return fails('replay_store_error', e instanceof Error ? e.message : 'replay store failed');
  }
  if (fresh !== true) return fails('replay', `jti '${parsed.jti}' has already been received`);
  applySET(opts.state, parsed);
  if (plan !== undefined) applyStandardPlan(opts.state, plan);
  return { ok: true, parsed };
}

// ================================================================================================
// Standard (CAEP / RISC) revocation events -> revocation entries, and the adapters for authorize().
// ================================================================================================

/** RISC event types (OpenID RISC 1.0) that end an account's standing: treated as revoking every grant of the mapped agent. */
export const RISC_EVENT_TYPES = {
  sessionsRevoked: 'https://schemas.openid.net/secevent/risc/event-type/sessions-revoked',
  accountDisabled: 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
  accountPurged: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
  credentialCompromise: 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
} as const;

/** How standard events become revocation entries. */
export interface StandardRevocationOptions {
  /**
   * Map an event's RFC 9493 subject to the agent id a PCActn's `agentOf` yields. Default: an `opaque` subject's `id`.
   * Return `undefined` when the subject names no agent you know.
   */
  subjectToAgent?: (subject: SubjectIdentifier) => string | undefined;
  /** Throw (`unmapped_subject`) instead of reporting when a revoking event's subject cannot be mapped. Default false. */
  failOnUnmapped?: boolean;
}

/** What {@link planStandardRevocations} decided; applying it is a separate, infallible step. */
export interface StandardRevocationPlan {
  /** `[agent, event_timestamp]` pairs to add to `killedAgents`. */
  agents: Array<[string, number]>;
  /** Event types that revoke but whose subject named no known agent (nothing was revoked for them). */
  unmapped: string[];
}

function defaultSubjectToAgent(subject: SubjectIdentifier): string | undefined {
  const id = subject['id'];
  return subject.format === 'opaque' && typeof id === 'string' && id.length > 0 ? id : undefined;
}

function isRevokingStandardEvent(type: string, ev: SetEventPayload): boolean {
  if (type === EVENT_TYPES.sessionRevoked) return true;
  if (type === EVENT_TYPES.credentialChange) return (ev as CaepCredentialChangeEvent).change_type !== 'create'; // unknown/absent => revoke (fail closed)
  return (Object.values(RISC_EVENT_TYPES) as string[]).includes(type);
}

/**
 * Decide, without touching any state, which agents a verified SET's standard events revoke: CAEP `session-revoked`,
 * CAEP `credential-change` (every `change_type` except `create`; an absent or unknown one counts as a change) and the RISC
 * types in {@link RISC_EVENT_TYPES}. The subject is the event's own `subject`, else the SET-level `sub_id`. A revoking
 * event with no subject, or one `subjectToAgent` cannot map, is listed in `unmapped` (or throws under `failOnUnmapped`).
 */
export function planStandardRevocations(parsed: ParsedSet, opts: StandardRevocationOptions = {}): StandardRevocationPlan {
  const toAgent = opts.subjectToAgent ?? defaultSubjectToAgent;
  const plan: StandardRevocationPlan = { agents: [], unmapped: [] };
  const setSubject = isRecord(parsed.payload['sub_id']) ? parsed.payload['sub_id'] : undefined;
  for (const [type, ev] of Object.entries(parsed.events)) {
    if (ev === undefined || !isRevokingStandardEvent(type, ev)) continue;
    const evSubject = (ev as { subject?: unknown }).subject;
    const own = isRecord(evSubject) ? evSubject : setSubject;
    let agent: string | undefined;
    if (own !== undefined && typeof own['format'] === 'string') {
      try {
        agent = toAgent(own as SubjectIdentifier);
      } catch {
        agent = undefined;
      }
    }
    if (typeof agent !== 'string' || agent.length === 0) {
      if (opts.failOnUnmapped === true) throw new SignalsError('unmapped_subject', `event '${type}' names no mappable agent`);
      plan.unmapped.push(type);
      continue;
    }
    plan.agents.push([agent, typeof ev.event_timestamp === 'number' ? ev.event_timestamp : 0]);
  }
  return plan;
}

function applyStandardPlan(state: RevocationState, plan: StandardRevocationPlan): void {
  for (const [agent, ts] of plan.agents) recordMax(state.killedAgents, agent, ts);
}

/** {@link planStandardRevocations} then apply: monotone, max-timestamp, like {@link applySET}. Returns the plan that was applied. */
export function applyStandardRevocations(state: RevocationState, parsed: ParsedSet, opts: StandardRevocationOptions = {}): StandardRevocationPlan {
  assertRevocationState(state);
  const plan = planStandardRevocations(parsed, opts);
  applyStandardPlan(state, plan);
  return plan;
}

function assertRevocationState(state: unknown): asserts state is RevocationState {
  if (!isRecord(state) || !(state['revokedGrants'] instanceof Map) || !(state['killedAgents'] instanceof Map)) {
    throw new SignalsError('misconfigured', 'state must come from createRevocationState()');
  }
}

/** Options shared by the authorize() adapters. */
export interface RevocationAdapterOptions {
  /** The agent id a kill-switch names, for a verification context. Default: the PCActn's leaf holder key (b64u). */
  agentOf?: (ctx: VerifyContext) => string | undefined;
}

function leafHolderAgent(ctx: VerifyContext): string | undefined {
  const chain = ctx.pcactn.cap_chain;
  return chain[chain.length - 1]?.holder;
}

/** The reason a PCActn under `grant` is revoked by `state`, or `undefined` when it is not. Anything undecidable is a reason. */
function revocationReason(state: RevocationState, pcactn: PCActn, grant: Capability, agentOf: (ctx: VerifyContext) => string | undefined): string | undefined {
  try {
    const ref = pcactn.grant_ref;
    if (typeof ref !== 'string' || ref.length === 0) return 'grant_ref is missing';
    if (state.revokedGrants.has(ref)) return 'grant revoked by signal';
    if (typeof grant?.id === 'string' && state.revokedGrants.has(grant.id)) return 'grant revoked by signal';
    const agent = agentOf({ pcactn, grant });
    if (typeof agent !== 'string' || agent.length === 0) return 'agent could not be determined';
    if (state.killedAgents.has(agent)) return 'agent killed by signal';
    return undefined;
  } catch {
    return 'revocation check error (fail closed)';
  }
}

/**
 * A revocation hook for `@atlasauth/pca`: pass it as `hooks.revocation` to `authorize()` / `requirePCA()` / `verifyPCActn`.
 * It reads `state` LIVE on every call, so SETs folded in by {@link receiveSET} take effect on the next request. It always
 * reports `enforced: true`; a revoked grant, a revoked or undeterminable agent, or any error denies.
 */
export function createRevocationHook(state: RevocationState, opts: RevocationAdapterOptions = {}): Hook {
  assertRevocationState(state);
  const agentOf = opts.agentOf ?? leafHolderAgent;
  return (ctx) => {
    const reason = revocationReason(state, ctx.pcactn, ctx.grant, agentOf);
    return reason === undefined ? { enforced: true, ok: true } : { enforced: true, ok: false, reason };
  };
}

/**
 * The same decision in the shape `authorizeExecution` takes as `isRevoked(grant, pcactn)`: true when revoked or when the
 * answer cannot be determined (fail closed).
 */
export function createIsRevoked(state: RevocationState, opts: RevocationAdapterOptions = {}): (grant: Capability, pcactn: PCActn) => boolean {
  assertRevocationState(state);
  const agentOf = opts.agentOf ?? leafHolderAgent;
  return (grant, pcactn) => revocationReason(state, pcactn, grant, agentOf) !== undefined;
}

/** A serialisable copy of a revocation state, for you to persist across restarts. */
export interface RevocationSnapshot {
  v: 1;
  grants: Array<[string, number]>;
  agents: Array<[string, number]>;
  intents: Array<[string, number]>;
}

/** Copy `state` into a plain JSON-safe snapshot. Persist it after every accepted SET: an empty state after a restart revokes nothing. */
export function snapshotRevocationState(state: RevocationState): RevocationSnapshot {
  assertRevocationState(state);
  return { v: 1, grants: [...state.revokedGrants], agents: [...state.killedAgents], intents: [...(state.revokedIntentIds ?? [])] };
}

function pairs(v: unknown, what: string): Array<[string, number]> {
  if (!Array.isArray(v)) throw new SignalsError('bad_snapshot', `${what} is not an array`);
  return v.map((p: unknown) => {
    if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== 'string' || p[0].length === 0 || typeof p[1] !== 'number' || !Number.isFinite(p[1])) {
      throw new SignalsError('bad_snapshot', `${what} holds an entry that is not [string, number]`);
    }
    return [p[0] as string, p[1] as number] as [string, number];
  });
}

/**
 * Merge a snapshot into `into` (a fresh state by default). Strict: any shape error throws `bad_snapshot` and `into` is not
 * touched. Merging is monotone (max timestamp), so restoring never un-revokes anything already in `into`.
 */
export function restoreRevocationState(snapshot: unknown, into: RevocationState = createRevocationState()): RevocationState {
  assertRevocationState(into);
  if (!isRecord(snapshot) || snapshot['v'] !== 1) throw new SignalsError('bad_snapshot', 'snapshot is not a version 1 object');
  const extra = Object.keys(snapshot).filter((k) => !['v', 'grants', 'agents', 'intents'].includes(k));
  if (extra.length > 0) throw new SignalsError('bad_snapshot', `snapshot has unknown member '${extra[0]}'`);
  const grants = pairs(snapshot['grants'], 'grants');
  const agents = pairs(snapshot['agents'], 'agents');
  const intents = pairs(snapshot['intents'], 'intents');
  for (const [k, t] of grants) recordMax(into.revokedGrants, k, t);
  for (const [k, t] of agents) recordMax(into.killedAgents, k, t);
  for (const [k, t] of intents) recordMax((into.revokedIntentIds ??= new Map()), k, t);
  return into;
}
export * from './ssf-stream';
export * from './ssf-manage';
