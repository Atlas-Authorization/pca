/**
 * Guardian high-availability control logic (spec Part 2.6 "resilience/HA is non-negotiable").
 *
 * The guardian / Policy-VM that co-signs tier-2/3 actions is a fast-path SPOF. This is the pure control
 * logic for running it as a quorum: given each guardian's health, decide whether a co-sign quorum is
 * AVAILABLE, which guardians to ask, how to fail over, and — when the quorum is lost — how to DEGRADE
 * GRACEFULLY (fall back to read-only / human-only instead of failing open or hard-halting).
 *
 * Pure + offline: it computes decisions from health facts. Actual process deployment, health probing and
 * the signing wire are ops/runtime concerns; this is the logic they drive, so it can be unit-tested and
 * reasoned about independently. It never fails OPEN: losing quorum restricts authority, never widens it.
 */

export interface GuardianHealth {
  id: string;
  healthy: boolean;
  /** Last successful heartbeat (epoch ms). A stale heartbeat counts as unhealthy regardless of `healthy`. */
  lastSeen: number;
  /** Optional preference weight for signer selection (higher = preferred). Default 0. */
  weight?: number;
}

export interface GuardianSet {
  guardians: GuardianHealth[];
  /** Co-sign quorum size (t of n). Must be ≥1 and ≤ guardians.length. */
  quorum: number;
}

export interface QuorumOptions {
  /** A heartbeat older than this (ms) is treated as down. Default 30_000. */
  staleMs?: number;
}

/** Guardians that are both flagged healthy AND have a fresh heartbeat at `now`. */
export function liveGuardians(set: GuardianSet, now: number, opts: QuorumOptions = {}): GuardianHealth[] {
  const staleMs = opts.staleMs ?? 30_000;
  return set.guardians.filter((g) => g.healthy && now - g.lastSeen <= staleMs);
}

export interface QuorumStatus {
  total: number;
  live: number;
  quorum: number;
  /** A co-sign quorum is reachable right now. */
  available: boolean;
  /** Some guardians are live but below quorum (degraded, not dead). */
  degraded: boolean;
}

export function quorumStatus(set: GuardianSet, now: number, opts: QuorumOptions = {}): QuorumStatus {
  const live = liveGuardians(set, now, opts).length;
  return {
    total: set.guardians.length,
    live,
    quorum: set.quorum,
    available: live >= set.quorum,
    degraded: live > 0 && live < set.quorum,
  };
}

export type DegradeMode =
  /** Quorum available — full operation (tier-2/3 co-signs proceed). */
  | 'normal'
  /** Below quorum but some guardians live — reversible/auto (t=1) only; no new co-signed authority. */
  | 'read-only'
  /** No live guardians — refuse everything that needs a guardian; fail CLOSED. */
  | 'halt';

export interface DegradePolicy {
  /** If false, below-quorum goes straight to `halt` instead of `read-only`. Default true. */
  allowReadOnly?: boolean;
}

/** The degradation mode implied by the current quorum status. Never fails open. */
export function degradeMode(status: QuorumStatus, policy: DegradePolicy = {}): DegradeMode {
  if (status.available) return 'normal';
  if (status.live > 0 && policy.allowReadOnly !== false) return 'read-only';
  return 'halt';
}

/**
 * Select the guardians to ask for a co-sign: the `quorum` freshest+highest-weight live guardians. Empty
 * when quorum is not available (the caller must not attempt a co-sign below quorum).
 */
export function selectSigners(set: GuardianSet, now: number, opts: QuorumOptions = {}): string[] {
  const live = liveGuardians(set, now, opts);
  if (live.length < set.quorum) return [];
  return [...live]
    .sort((a, b) => (b.weight ?? 0) - (a.weight ?? 0) || b.lastSeen - a.lastSeen || a.id.localeCompare(b.id))
    .slice(0, set.quorum)
    .map((g) => g.id);
}

export interface FailoverPlan {
  /** The preferred live guardian (highest weight / freshest), or null if none live. */
  primary: string | null;
  /** The remaining live guardians, in preference order, as standbys. */
  standbys: string[];
}

/** A primary + ordered standbys for the single-signer fast path (with quorum as the backstop). */
export function failoverPlan(set: GuardianSet, now: number, opts: QuorumOptions = {}): FailoverPlan {
  const live = [...liveGuardians(set, now, opts)].sort(
    (a, b) => (b.weight ?? 0) - (a.weight ?? 0) || b.lastSeen - a.lastSeen || a.id.localeCompare(b.id),
  );
  return { primary: live[0]?.id ?? null, standbys: live.slice(1).map((g) => g.id) };
}

/** Validate a guardian set is well-formed (quorum in range, unique ids). Returns an error string or null. */
export function validateGuardianSet(set: GuardianSet): string | null {
  if (!Array.isArray(set.guardians) || set.guardians.length === 0) return 'guardian set is empty';
  if (!Number.isInteger(set.quorum) || set.quorum < 1) return 'quorum must be an integer ≥ 1';
  if (set.quorum > set.guardians.length) return 'quorum exceeds guardian count';
  const ids = new Set(set.guardians.map((g) => g.id));
  if (ids.size !== set.guardians.length) return 'duplicate guardian ids';
  return null;
}
