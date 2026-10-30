/**
 * `@atlasauth/pca-revoke` — realtime revocation + a mid-run KILL-SWITCH for Proof-Carrying Authority.
 *
 * WHY THIS EXISTS (compose, don't replace). The PCA core verifier (`verifyPCActnCore`, `@atlasauth/pca`)
 * is a PULL check: given a signed PCActn it decides default-deny from what it already holds — the
 * capability chain, the plan commitment, the leaf signature, the freshness window, the grant's own
 * counter/budget. All of that is PASSIVE: a captured PCActn stays acceptable until it expires or the
 * budget drains. What the core cannot express is an ACTIVE boundary — "stop, this authority is dead,
 * NOW" — pushed in mid-run by the principal/operator against a chain that is still cryptographically
 * valid and still in-budget. A passive counter/budget can never cover that case.
 *
 * This package is that active boundary, layered strictly ON TOP of the core (no core edit). It keeps a
 * pluggable {@link RevocationRegistry} of revocations keyed by a specific capability id, an agent holder
 * key, a principal/root issuer, or a delegation-subtree prefix. {@link checkRevocation} walks EVERY hop of a
 * PCActn's `cap_chain` against the registry; {@link verifyWithRevocation} ANDs the core outcome with the
 * revocation gate and fails closed. {@link RevocationRegistry.killAgent} / `.killSubtree` are the
 * instant kill-switch. {@link ingestCaepEvent} bridges an OpenID Shared-Signals / CAEP revocation event
 * (the industry-standard push channel; mirrors `@atlasauth/pca-signals`) into registry entries.
 *
 * It is the companion to the core's cryptographic revocation accumulator (`@atlasauth/pca` revocation.ts):
 * that proves non-membership offline against a signed epoch root; this is the live, mutable, push-fed
 * registry a resource server consults on every action.
 */

import type { Capability, CapabilityChain, PCActn, VerifyResult } from '@atlasauth/pca';

// ---------------------------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------------------------

/**
 * What a revocation is keyed on:
 *  - `cap`    — a specific capability id (`Capability.id`). Because {@link checkRevocation} checks EVERY hop,
 *               revoking a mid-chain cap id denies that cap AND its whole delegation subtree (a content-
 *               addressed id only ever appears in chains that descend through it).
 *  - `holder` — an agent holder key (`Capability.holder`, b64u): denies any action whose chain includes a
 *               capability that agent holds. The kill-switch's primary key.
 *  - `issuer` — a principal / root-issuer key (`Capability.issuer`, b64u): denies any action rooted at (or
 *               delegated by) that key. Revoking the root principal kills everything under it.
 *  - `prefix` — a delegation-subtree identified by an ordered cap-id PATH from the root; a chain matches
 *               when its hop ids begin with that path.
 */
export type RevocationTargetKind = 'cap' | 'holder' | 'issuer' | 'prefix';

/** A stored revocation. `value` is the canonical key (cap id / holder / issuer, or the serialized prefix path). */
export interface RevocationEntry {
  kind: RevocationTargetKind;
  /** Canonical string key. For `prefix` this is the serialized `prefix` path; for the rest it is the id/key. */
  value: string;
  /** For `kind: 'prefix'` only: the ordered cap-id path this subtree is rooted at. */
  prefix?: string[];
  /** Human-readable reason this authority was revoked. */
  reason: string;
  /** Epoch ms the revocation was recorded (metadata; does NOT gate when it bites). */
  revokedAt: number;
  /** Optional epoch ms before which the revocation does NOT yet bite (a scheduled/future revocation). */
  notBefore?: number;
}

/** What {@link RevocationRegistry.revoke} accepts (a discriminated, point-or-subtree target). */
export type RevocationInput =
  | { kind: 'cap'; value: string; reason?: string; revokedAt?: number; notBefore?: number }
  | { kind: 'holder'; value: string; reason?: string; revokedAt?: number; notBefore?: number }
  | { kind: 'issuer'; value: string; reason?: string; revokedAt?: number; notBefore?: number }
  | { kind: 'prefix'; prefix: string[]; reason?: string; revokedAt?: number; notBefore?: number };

/** A point target for {@link RevocationRegistry.unrevoke}. */
export type RevocationKey =
  | { kind: 'cap'; value: string }
  | { kind: 'holder'; value: string }
  | { kind: 'issuer'; value: string }
  | { kind: 'prefix'; prefix: string[] };

/** The outcome of a revocation check. `matched` / `reason` are present only when `revoked` is true. */
export interface IsRevokedResult {
  revoked: boolean;
  /** The entry that caused the revocation (the first active match, root→leaf, cap→issuer→holder, then prefix). */
  matched?: RevocationEntry;
  /** A human-readable explanation of the match. */
  reason?: string;
}

/** The combined core-verify + revocation-gate outcome. */
export interface VerifyWithRevocationResult {
  /** True ONLY when the core verified AND nothing in the chain is revoked (fail closed). */
  allow: boolean;
  /** Did the core verifier allow? */
  coreAllow: boolean;
  /** The revocation-gate outcome. */
  revocation: IsRevokedResult;
  /** Why the action was denied (the core's reason, or the revocation reason); absent when allowed. */
  reason?: string;
}

const PREFIX_SEP = ',';

function serializePrefix(prefix: string[]): string {
  return prefix.join(PREFIX_SEP);
}

/** True when a revocation is in effect at `now` (a future `notBefore` has not yet been reached). */
export function isActiveAt(entry: RevocationEntry, now: number): boolean {
  if (entry.notBefore === undefined) return true;
  // Fail closed: a non-finite clock or schedule can never be shown to be "in the future", so it bites.
  if (!Number.isFinite(now) || !Number.isFinite(entry.notBefore)) return true;
  return now >= entry.notBefore;
}

// ---------------------------------------------------------------------------------------------
// Pluggable store
// ---------------------------------------------------------------------------------------------

/**
 * The pluggable backing store for a {@link RevocationRegistry}. Point kinds (`cap`/`holder`/`issuer`) are
 * addressed by `(kind, value)`; `prefix` entries are scanned via {@link all}. Implement this over Redis,
 * a database, or a distributed cache; the in-memory default below is the reference implementation.
 */
export interface RevocationStore {
  /** Insert or replace the entry at its `(kind, value)` key. Must be atomic: after it resolves every reader sees the entry. */
  add(entry: RevocationEntry): Promise<void>;
  /** Remove the entry at `(kind, value)`. Resolves true when something was removed. */
  remove(kind: RevocationTargetKind, value: string): Promise<boolean>;
  /** The entry at `(kind, value)`, or undefined. */
  get(kind: RevocationTargetKind, value: string): Promise<RevocationEntry | undefined>;
  /** Every stored entry (a snapshot copy). */
  all(): Promise<RevocationEntry[]>;
  /** Drop every entry. */
  clear(): Promise<void>;
}

function storeKey(kind: RevocationTargetKind, value: string): string {
  // kind is a fixed enum and value is a b64u id/key or a comma-joined b64u path; '\u0000' never occurs in either.
  return `${kind}\u0000${value}`;
}

/** In-memory {@link RevocationStore} (the default). Single-process; swap in a shared store for a fleet. */
export class InMemoryRevocationStore implements RevocationStore {
  private readonly entries = new Map<string, RevocationEntry>();

  async add(entry: RevocationEntry): Promise<void> {
    this.entries.set(storeKey(entry.kind, entry.value), entry);
  }

  async remove(kind: RevocationTargetKind, value: string): Promise<boolean> {
    return this.entries.delete(storeKey(kind, value));
  }

  async get(kind: RevocationTargetKind, value: string): Promise<RevocationEntry | undefined> {
    return this.entries.get(storeKey(kind, value));
  }

  async all(): Promise<RevocationEntry[]> {
    return [...this.entries.values()];
  }

  async clear(): Promise<void> {
    this.entries.clear();
  }
}

// ---------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------

/**
 * A live, mutable registry of revocations. Mint it with the in-memory store (default) or any
 * {@link RevocationStore}. A resource server holds one and consults {@link checkRevocation} /
 * {@link verifyWithRevocation} on every action, next to the core verifier.
 */
export class RevocationRegistry {
  constructor(private readonly store: RevocationStore = new InMemoryRevocationStore()) {}

  /** Revoke a capability id, holder key, issuer key, or subtree prefix. Returns the stored entry. */
  async revoke(input: RevocationInput): Promise<RevocationEntry> {
    const revokedAt = input.revokedAt ?? Date.now();
    const reason = input.reason ?? '';
    if (typeof revokedAt !== 'number' || !Number.isFinite(revokedAt)) throw new TypeError('revoke: revokedAt must be a finite number');
    if (input.notBefore !== undefined && (typeof input.notBefore !== 'number' || !Number.isFinite(input.notBefore))) {
      throw new TypeError('revoke: notBefore must be a finite number');
    }
    if (typeof reason !== 'string') throw new TypeError('revoke: reason must be a string');
    let entry: RevocationEntry;
    if (input.kind === 'prefix') {
      if (!Array.isArray(input.prefix) || input.prefix.length === 0) {
        throw new TypeError('revoke: a prefix revocation requires a non-empty cap-id path');
      }
      // The path is serialized with ',' as separator: an element holding one would alias a different path.
      if (input.prefix.some((id) => typeof id !== 'string' || id.length === 0 || id.includes(PREFIX_SEP))) {
        throw new TypeError("revoke: every prefix element must be a non-empty string without ','");
      }
      entry = { kind: 'prefix', value: serializePrefix(input.prefix), prefix: [...input.prefix], reason, revokedAt };
    } else {
      if (typeof input.value !== 'string' || input.value.length === 0) {
        throw new TypeError(`revoke: a ${input.kind} revocation requires a non-empty value`);
      }
      entry = { kind: input.kind, value: input.value, reason, revokedAt };
    }
    if (input.notBefore !== undefined) entry.notBefore = input.notBefore;
    await this.store.add(entry);
    return entry;
  }

  /**
   * Revoke an entire delegation subtree. A `rootCapId` (string) revokes every chain that passes through
   * that capability (a `cap` revocation — content addressing makes that exactly the subtree). A
   * `chainPrefix` (ordered cap-id path) revokes every chain whose hops begin with that path.
   */
  revokeSubtree(
    target: string | string[],
    opts: { reason?: string; revokedAt?: number; notBefore?: number } = {},
  ): Promise<RevocationEntry> {
    if (Array.isArray(target)) {
      return this.revoke({ kind: 'prefix', prefix: target, ...opts });
    }
    return this.revoke({ kind: 'cap', value: target, ...opts });
  }

  /** Remove a revocation. Returns true when one was removed. */
  async unrevoke(key: RevocationKey): Promise<boolean> {
    if (key.kind === 'prefix') {
      if (!Array.isArray(key.prefix) || key.prefix.length === 0) return false;
      return this.store.remove('prefix', serializePrefix(key.prefix));
    }
    return this.store.remove(key.kind, key.value);
  }

  /** Every active-or-scheduled revocation (a snapshot). */
  list(): Promise<RevocationEntry[]> {
    return this.store.all();
  }

  /** Point lookup of a `cap`/`holder`/`issuer` revocation (used by {@link checkRevocation}). */
  lookup(kind: 'cap' | 'holder' | 'issuer', value: string): Promise<RevocationEntry | undefined> {
    return this.store.get(kind, value);
  }

  /** Every subtree-`prefix` revocation (used by {@link checkRevocation}). */
  async prefixes(): Promise<RevocationEntry[]> {
    return (await this.store.all()).filter((e) => e.kind === 'prefix');
  }

  /** Drop every revocation. */
  clear(): Promise<void> {
    return this.store.clear();
  }

  // -- kill-switch (instant: no notBefore, so it bites any in-flight action immediately) --

  /** KILL-SWITCH: instantly revoke an agent by its holder key — denies EVERY in-flight action by it. */
  killAgent(holder: string, opts: { reason?: string; revokedAt?: number } = {}): Promise<RevocationEntry> {
    return this.revoke({ kind: 'holder', value: holder, reason: opts.reason ?? 'kill-switch: agent killed', revokedAt: opts.revokedAt });
  }

  /** KILL-SWITCH: instantly revoke an entire delegation subtree rooted at `rootCapId`. */
  killSubtree(rootCapId: string, opts: { reason?: string; revokedAt?: number } = {}): Promise<RevocationEntry> {
    return this.revoke({ kind: 'cap', value: rootCapId, reason: opts.reason ?? 'kill-switch: subtree killed', revokedAt: opts.revokedAt });
  }
}

// ---------------------------------------------------------------------------------------------
// The revocation check
// ---------------------------------------------------------------------------------------------

function matchReason(entry: RevocationEntry): string {
  const base = `${entry.kind} ${entry.value} is revoked`;
  return entry.reason.length > 0 ? `${base}: ${entry.reason}` : base;
}

function startsWith(ids: string[], prefix: string[]): boolean {
  if (prefix.length === 0 || ids.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (ids[i] !== prefix[i]) return false;
  }
  return true;
}

/**
 * Is any authority in this PCActn's `cap_chain` revoked at `now`? Walks EVERY hop: its cap id (`cap`),
 * its issuer (`issuer`) and its holder (`holder`), root→leaf, then every subtree `prefix`. Returns the
 * FIRST active match. A revocation whose `notBefore` is still in the future does not yet bite.
 */
async function scanRevoked(p: PCActn, registry: RevocationRegistry, opts: { now?: number } = {}): Promise<IsRevokedResult> {
  const now = opts.now ?? Date.now();
  const chain: CapabilityChain | undefined = p?.cap_chain;
  if (!Array.isArray(chain) || chain.length === 0) return { revoked: false };

  // Point kinds: a direct lookup per hop (root -> leaf), checking cap id, then issuer, then holder.
  const ids: string[] = [];
  for (const hop of chain) {
    const hop_: Capability = hop;
    for (const [kind, key] of [
      ['cap', hop_.id],
      ['issuer', hop_.issuer],
      ['holder', hop_.holder],
    ] as const) {
      if (typeof key !== 'string' || key.length === 0) continue;
      const entry = await registry.lookup(kind, key);
      if (entry && isActiveAt(entry, now)) return { revoked: true, matched: entry, reason: matchReason(entry) };
    }
    if (typeof hop_.id === 'string') ids.push(hop_.id);
  }

  // Subtree prefixes: scan the prefix entries and test the chain's id path against each.
  for (const entry of await registry.prefixes()) {
    if (entry.prefix && startsWith(ids, entry.prefix) && isActiveAt(entry, now)) {
      return { revoked: true, matched: entry, reason: matchReason(entry) };
    }
  }

  return { revoked: false };
}

/**
 * The revocation check: it never throws and never reports "not revoked" because it could
 * not look. A missing or malformed PCActn / `cap_chain`, a hop whose id, issuer or holder is not a
 * non-empty string, a non-finite `now`, or a store that throws all yield `revoked: true` with a reason that
 * starts `revocation check failed closed`. Use this wherever the answer gates an action.
 */
export async function checkRevocation(p: PCActn, registry: RevocationRegistry, opts: { now?: number } = {}): Promise<IsRevokedResult> {
  const closed = (why: string): IsRevokedResult => ({ revoked: true, reason: `revocation check failed closed: ${why}` });
  const now = opts.now ?? Date.now();
  if (typeof now !== 'number' || !Number.isFinite(now)) return closed('clock is not a finite number');
  const chain: unknown = p?.cap_chain;
  if (!Array.isArray(chain) || chain.length === 0) return closed('the action carries no capability chain');
  for (const hop of chain) {
    const h = hop as Partial<Capability> | null;
    for (const k of ['id', 'issuer', 'holder'] as const) {
      const v = h?.[k];
      if (typeof v !== 'string' || v.length === 0) return closed(`a chain hop has no ${k}`);
    }
  }
  try {
    return await scanRevoked(p, registry, { now });
  } catch (e) {
    return closed(`the revocation store failed (${e instanceof Error ? e.name : typeof e})`);
  }
}

/**
 * Combine the core verify outcome with the revocation gate. Allow ONLY if the core verified AND nothing
 * in the chain is revoked. Fails closed: a core result that did not allow denies regardless of the
 * registry, and any revocation match denies regardless of the core result.
 */
export async function verifyWithRevocation(
  p: PCActn,
  coreVerifyResult: VerifyResult,
  registry: RevocationRegistry,
  opts: { now?: number } = {},
): Promise<VerifyWithRevocationResult> {
  const coreAllow = coreVerifyResult !== null && typeof coreVerifyResult === 'object' && coreVerifyResult.allow === true;
  const revocation = await checkRevocation(p, registry, opts);
  const allow = coreAllow && !revocation.revoked;
  if (allow) return { allow, coreAllow, revocation };
  const reason = !coreAllow
    ? (coreVerifyResult?.reason ?? 'core verification failed')
    : (revocation.reason ?? 'revoked');
  return { allow, coreAllow, revocation, reason };
}

// ---------------------------------------------------------------------------------------------
// Shared-Signals / CAEP bridge
// ---------------------------------------------------------------------------------------------

/**
 * CAEP / PCA event-type URIs, mirrored from `@atlasauth/pca-signals` (not a dependency here, so the values
 * are duplicated verbatim — they are stable spec/registry URIs). A SET `events` map is keyed by these.
 */
export const CAEP_EVENT_TYPES = {
  /** CAEP 1.0 §3.4 — a session for the subject was revoked. */
  sessionRevoked: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  /** PCA — a single grant (by `grant_ref`, which is the root grant's cap id) is revoked. */
  grantRevoked: 'https://atlasauth.net/caep/grant-revoked',
  /** PCA — a mid-run kill-switch: revoke every grant the named agent holds. */
  killSwitch: 'https://atlasauth.net/caep/kill-switch',
} as const;

/** An RFC 9493 subject identifier (opaque; structurally compatible with `@atlasauth/pca-signals`). */
export interface SubjectIdentifier {
  format: string;
  [member: string]: unknown;
}

/** PCA `grant-revoked` payload (structurally compatible with `@atlasauth/pca-signals`). */
export interface CaepGrantRevokedEvent {
  grant_ref: string;
  agent?: string;
  reason?: string;
  event_timestamp?: number;
  subject?: SubjectIdentifier;
}

/** PCA `kill-switch` payload (structurally compatible with `@atlasauth/pca-signals`). */
export interface CaepKillSwitchEvent {
  agent: string;
  grant_ref?: string;
  reason?: string;
  event_timestamp?: number;
  subject?: SubjectIdentifier;
}

/** CAEP 1.0 §3.4 `session-revoked` payload (structurally compatible with `@atlasauth/pca-signals`). */
export interface CaepSessionRevokedEvent {
  subject?: SubjectIdentifier;
  event_timestamp?: number;
  reason_admin?: string;
  reason_user?: string;
}

/** A single CAEP/PCA event tagged with its event-type URI — what {@link ingestCaepEvent} consumes. */
export type IngestableCaepEvent =
  | { type: typeof CAEP_EVENT_TYPES.grantRevoked; payload: CaepGrantRevokedEvent }
  | { type: typeof CAEP_EVENT_TYPES.killSwitch; payload: CaepKillSwitchEvent }
  | { type: typeof CAEP_EVENT_TYPES.sessionRevoked; payload: CaepSessionRevokedEvent };

function stringField(subject: SubjectIdentifier | undefined, key: string): string | undefined {
  if (subject === undefined) return undefined;
  const v = subject[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/** CAEP `event_timestamp` is integer SECONDS; our registry records epoch MS. */
function revokedAtFrom(event_timestamp: number | undefined): number {
  return typeof event_timestamp === 'number' && Number.isFinite(event_timestamp) ? Math.round(event_timestamp * 1000) : Date.now();
}

/**
 * Bridge an OpenID Shared-Signals / CAEP revocation event into {@link RevocationRegistry} entries — the
 * active push channel that makes a held, still-valid PCActn deny mid-run. Returns the entries added.
 *
 *  - `grant-revoked`  → revoke the grant's cap id (`grant_ref`, a cap id): denies the whole subtree under it.
 *  - `kill-switch`    → kill the agent's holder key (`agent`); if a `grant_ref` is named, also revoke that cap.
 *  - `session-revoked`→ when the subject carries an agent/holder key (`holder`/`agent`/`id` field), kill it.
 */
export async function ingestCaepEvent(event: IngestableCaepEvent, registry: RevocationRegistry): Promise<RevocationEntry[]> {
  const added: RevocationEntry[] = [];
  if (event.type === CAEP_EVENT_TYPES.grantRevoked) {
    const ev = event.payload;
    if (typeof ev.grant_ref === 'string' && ev.grant_ref.length > 0) {
      added.push(
        await registry.revoke({
          kind: 'cap',
          value: ev.grant_ref,
          reason: ev.reason ?? 'CAEP grant-revoked',
          revokedAt: revokedAtFrom(ev.event_timestamp),
        }),
      );
    }
  } else if (event.type === CAEP_EVENT_TYPES.killSwitch) {
    const ev = event.payload;
    const revokedAt = revokedAtFrom(ev.event_timestamp);
    if (typeof ev.agent === 'string' && ev.agent.length > 0) {
      added.push(await registry.killAgent(ev.agent, { reason: ev.reason ?? 'CAEP kill-switch', revokedAt }));
    }
    if (typeof ev.grant_ref === 'string' && ev.grant_ref.length > 0) {
      added.push(await registry.revoke({ kind: 'cap', value: ev.grant_ref, reason: ev.reason ?? 'CAEP kill-switch', revokedAt }));
    }
  } else {
    const ev = event.payload;
    const holder = stringField(ev.subject, 'holder') ?? stringField(ev.subject, 'agent') ?? stringField(ev.subject, 'id');
    if (holder !== undefined) {
      added.push(
        await registry.killAgent(holder, {
          reason: ev.reason_admin ?? ev.reason_user ?? 'CAEP session-revoked',
          revokedAt: revokedAtFrom(ev.event_timestamp),
        }),
      );
    }
  }
  return added;
}
