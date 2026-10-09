/**
 * Input detection + normalization.
 *
 * `lintPolicy` accepts anything a principal might hand a CI gate: a bare predicate/caveat set, a
 * compiled policy, a signed `Envelope`, or a minted `grant` (`Capability`). They all reduce to the
 * same effective authority — a predicate set plus the runtime caveat (gate) set, and (when known) the
 * risk policy. The grant/chain reduction is the subtle part and is documented on {@link fromGrant}.
 */

import { readEnvelope, type Capability, type Caveat, type Envelope, type Predicate, type RiskPolicy } from '@atlasauth/pca';
import { ENVELOPE_CAVEAT_TYPE } from './util';

export type PolicyKind = 'bare' | 'compiled' | 'envelope' | 'grant' | 'chain-hop';

/** The effective authority of one policy (or one chain hop), ready for the static analyzer. */
export interface NormalizedPolicy {
  predicates: Predicate[];
  /** Runtime gate caveats (expires / rate / max_blast_radius / reversibility_max / ...). */
  caveats: Caveat[];
  /** The risk policy, when the input carried one (envelope / grant / compiled). */
  riskPolicy?: RiskPolicy;
  kind: PolicyKind;
}

export type NormalizeResult = { ok: true; policy: NormalizedPolicy } | { ok: false; reason: string };

function isRecord(x: unknown): x is Record<string, unknown> {
  return x !== null && typeof x === 'object' && !Array.isArray(x);
}

/** A minted grant / delegation hop: has the content-addressed, signed shape of a `Capability`. */
export function isCapability(x: unknown): x is Capability {
  if (!isRecord(x)) return false;
  return (
    typeof x.id === 'string' &&
    typeof x.issuer === 'string' &&
    typeof x.holder === 'string' &&
    typeof x.body_digest === 'string' &&
    typeof x.sig === 'string' &&
    Array.isArray(x.caveats)
  );
}

/** A signed policy envelope (the Root Intent Grant payload). */
export function isEnvelope(x: unknown): x is Envelope {
  if (!isRecord(x)) return false;
  return (
    typeof x.goal_commit === 'string' &&
    Array.isArray(x.predicates) &&
    Array.isArray(x.caveats) &&
    isRecord(x.agent_binding) &&
    isRecord(x.risk_policy)
  );
}

/** A `compilePolicy` result. */
function isCompiledPolicy(x: unknown): x is { predicates: Predicate[]; caveats: Caveat[]; riskPolicy: RiskPolicy } {
  if (!isRecord(x)) return false;
  return Array.isArray(x.predicates) && Array.isArray(x.caveats) && isRecord(x.riskPolicy) && Array.isArray(x.actions);
}

/** A bare `{ predicates, caveats? }` policy. */
function isBarePolicy(x: unknown): x is { predicates: Predicate[]; caveats?: Caveat[] } {
  return isRecord(x) && Array.isArray(x.predicates);
}

/** Drop the envelope-carrying caveat; keep the runtime gate caveats (and any appended attenuation). */
function runtimeCaveats(caveats: Caveat[]): Caveat[] {
  return caveats.filter((c) => c !== null && typeof c === 'object' && c.type !== ENVELOPE_CAVEAT_TYPE);
}

/**
 * Reduce a grant to its effective authority. The grant's predicates and baseline gate caveats live
 * INSIDE its first `envelope` caveat (signed into the grant). Delegation then APPENDS further gate
 * caveats to the grant's top-level `caveats` array. So the effective gates are the envelope's own
 * caveats PLUS the appended (non-envelope) top-level caveats, and the predicates come from the
 * envelope. A malformed / unreadable envelope is a hard failure the caller surfaces as a finding.
 */
export function fromGrant(grant: Capability): NormalizeResult {
  const env = readEnvelope(grant);
  if (env === null) {
    return { ok: false, reason: 'grant has no readable `envelope` caveat (malformed or unsigned payload)' };
  }
  const appended = runtimeCaveats(Array.isArray(grant.caveats) ? grant.caveats : []);
  return {
    ok: true,
    policy: {
      predicates: env.predicates,
      caveats: [...env.caveats, ...appended],
      riskPolicy: env.risk_policy,
      kind: 'grant',
    },
  };
}

/** Normalize any single-policy input to its effective authority. */
export function normalizePolicyInput(input: unknown): NormalizeResult {
  if (isCapability(input)) return fromGrant(input);
  if (isEnvelope(input)) {
    return { ok: true, policy: { predicates: input.predicates, caveats: input.caveats, riskPolicy: input.risk_policy, kind: 'envelope' } };
  }
  if (isCompiledPolicy(input)) {
    return { ok: true, policy: { predicates: input.predicates, caveats: input.caveats, riskPolicy: input.riskPolicy, kind: 'compiled' } };
  }
  if (isBarePolicy(input)) {
    const caveats = Array.isArray(input.caveats) ? input.caveats : [];
    return { ok: true, policy: { predicates: input.predicates, caveats, kind: 'bare' } };
  }
  return { ok: false, reason: 'unrecognized policy shape (expected an envelope, grant, compiled policy, or { predicates, caveats })' };
}

export type ChainNormalizeResult = { ok: true; hops: NormalizedPolicy[] } | { ok: false; reason: string };

/**
 * Normalize a delegation chain to one {@link NormalizedPolicy} per hop (root -> leaf). A chain of
 * `Capability`s uses the grant reduction: the predicates are shared (from the root envelope) and each
 * hop's effective gate caveats are the envelope's caveats plus that hop's appended caveats, so a
 * well-formed (append-only) chain yields a monotonically narrowing authority. A chain of already
 * effective `{ predicates, caveats }` hops is taken as-is (useful for testing an escalation directly).
 */
export function normalizeChain(chain: readonly unknown[]): ChainNormalizeResult {
  if (chain.length === 0) return { ok: false, reason: 'empty chain' };

  if (chain.every((c): c is Capability => isCapability(c))) {
    const caps = chain;
    const root = caps[0];
    if (root === undefined) return { ok: false, reason: 'empty chain' };
    const env = readEnvelope(root);
    if (env === null) return { ok: false, reason: 'root grant has no readable `envelope` caveat' };
    const hops: NormalizedPolicy[] = caps.map((cap) => ({
      predicates: env.predicates,
      caveats: [...env.caveats, ...runtimeCaveats(Array.isArray(cap.caveats) ? cap.caveats : [])],
      riskPolicy: env.risk_policy,
      kind: 'chain-hop',
    }));
    return { ok: true, hops };
  }

  const hops: NormalizedPolicy[] = [];
  for (let i = 0; i < chain.length; i++) {
    const r = normalizePolicyInput(chain[i]);
    if (!r.ok) return { ok: false, reason: `hop ${i}: ${r.reason}` };
    hops.push({ ...r.policy, kind: 'chain-hop' });
  }
  return { ok: true, hops };
}
