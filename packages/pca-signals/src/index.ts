/**
 * Shared Signals Framework (SSF / CAEP) for Proof-Carrying Authority — the ACTIVE revocation and
 * mid-run kill-switch channel.
 *
 * Honest framing (compose, don't replace):
 *   PCA's native enforcement is PASSIVE. A verifier (`@atlasauth/backend` `requirePCA`) checks a signed
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

/** The union of every event payload this package understands. */
export type SetEventPayload =
  | GrantRevokedEvent
  | KillSwitchEvent
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
    }
  }
  return state;
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
