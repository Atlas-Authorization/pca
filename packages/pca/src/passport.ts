/**
 * Agent passport — portable attested identity (spec Part 2.5 "SPIFFE-for-agents").
 *
 * "Which agent" is more than a key: it is the model, its weights, its operator, its system prompt and
 * its tool manifest. A passport is the portable, content-addressed statement of that identity; a grant's
 * `AgentBinding` (envelope.ts) is the policy that says which passports it accepts. `matchesBinding`
 * decides, with the SAME allowlist semantics the attestation verifier uses — so you can check a
 * passport against a binding offline, before you ever mint or dispatch.
 *
 * HONEST: a passport is a CLAIM. `hardware_rooted` means "a hardware verifier validated the attestation
 * this passport was issued from" — the passport itself is not proof; it records the result of one.
 * `matchesBinding` fails closed whenever a required-but-absent field or an unmet hardware demand would
 * otherwise pass silently.
 */

import type { AgentBinding } from './envelope';
import { hashCanonical } from './hash';

export interface AgentPassport {
  /** Content-addressed id = fingerprint of the identity fields. */
  id: string;
  model_id: string;
  /** Digest of the loaded model weights (fp16/quantized), if measured. */
  weights_digest?: string;
  /** Digest of the agent's system prompt / instructions. */
  system_prompt_digest?: string;
  /** Digest of the agent's available-tool manifest. */
  tool_manifest_digest?: string;
  /** Launch/runtime measurement — an opaque digest or an integer SVN as a string. */
  runtime_measurement?: string;
  operator: string;
  /** True iff the attestation this passport was issued from was validated by a HARDWARE verifier. */
  hardware_rooted: boolean;
  /** True iff `weights_digest` came from a hardware-MEASURED identity (not host/self-asserted). */
  weights_measured?: boolean;
  issued_at: number;
}

export type PassportIdentity = Omit<AgentPassport, 'id'>;

/** Content fingerprint over the identity fields (stable id; excludes `id` itself). */
export function passportFingerprint(p: PassportIdentity): string {
  return hashCanonical({
    d: 'atlas-pca/passport/v1',
    model_id: p.model_id,
    weights_digest: p.weights_digest ?? null,
    system_prompt_digest: p.system_prompt_digest ?? null,
    tool_manifest_digest: p.tool_manifest_digest ?? null,
    runtime_measurement: p.runtime_measurement ?? null,
    operator: p.operator,
    hardware_rooted: p.hardware_rooted,
  });
}

/** Issue a passport: fill `id` from the fingerprint of the identity. */
export function issuePassport(identity: PassportIdentity): AgentPassport {
  return { ...identity, id: passportFingerprint(identity) };
}

export interface BindingMatch {
  ok: boolean;
  reasons: string[];
}

/**
 * Does this passport satisfy a grant's AgentBinding? Mirrors attestation.matchAgentBinding:
 *  - each *_allowlist, when present, requires the matching digest to be present AND listed (fail-closed);
 *  - operator, when pinned, must equal;
 *  - require_hardware demands hardware_rooted;
 *  - require_measured_weights demands weights_measured (a self/host-asserted digest fails even if listed);
 *  - min_measurement: a string matches runtime_measurement for EQUALITY; `{ svn }` is a MONOTONE lower
 *    bound on the integer SVN parsed from runtime_measurement.
 */
export function matchesBinding(p: AgentPassport, b: AgentBinding): BindingMatch {
  const reasons: string[] = [];
  const need = (list: string[] | undefined, value: string | undefined, label: string) => {
    if (!list || list.length === 0) return;
    if (value === undefined) reasons.push(`${label} required by binding but absent from passport`);
    else if (!list.includes(value)) reasons.push(`${label} '${value}' not in allowlist`);
  };

  if (b.model_allowlist && b.model_allowlist.length > 0 && !b.model_allowlist.includes(p.model_id)) {
    reasons.push(`model_id '${p.model_id}' not in allowlist`);
  }
  need(b.weights_allowlist, p.weights_digest, 'weights_digest');
  need(b.system_prompt_allowlist, p.system_prompt_digest, 'system_prompt_digest');
  need(b.tool_manifest_allowlist, p.tool_manifest_digest, 'tool_manifest_digest');

  if (b.operator !== undefined && p.operator !== b.operator) reasons.push(`operator '${p.operator}' != required '${b.operator}'`);
  if (b.require_hardware && !p.hardware_rooted) reasons.push('binding requires a hardware-rooted attestation');
  if (b.require_measured_weights && !p.weights_measured) reasons.push('binding requires hardware-measured weights');

  if (b.min_measurement !== undefined) {
    if (typeof b.min_measurement === 'string') {
      if (p.runtime_measurement !== b.min_measurement) reasons.push('runtime_measurement does not equal the pinned measurement');
    } else {
      const svn = Number(p.runtime_measurement);
      if (!Number.isFinite(svn) || svn < b.min_measurement.svn) reasons.push(`runtime SVN ${String(p.runtime_measurement)} < required ${b.min_measurement.svn}`);
    }
  }

  return { ok: reasons.length === 0, reasons };
}

// ---- registry + reputation-free trust score -------------------------------------------------------

export interface PassportRegistry {
  get(id: string): AgentPassport | undefined;
  has(id: string): boolean;
  all(): AgentPassport[];
}

export function buildRegistry(passports: AgentPassport[]): PassportRegistry {
  const byId = new Map<string, AgentPassport>();
  for (const p of passports) byId.set(p.id, p);
  return { get: (id) => byId.get(id), has: (id) => byId.has(id), all: () => [...byId.values()] };
}

/**
 * A coarse identity-assurance score in [0,1] from the passport's own completeness (NOT behavioral
 * reputation — that is reputation.ts). Hardware root dominates; measured provenance + a known operator
 * add confidence.
 */
export function trustScore(p: AgentPassport, opts: { knownOperators?: string[] } = {}): number {
  let s = 0;
  if (p.hardware_rooted) s += 0.4;
  if (p.weights_digest) s += p.weights_measured ? 0.2 : 0.1;
  if (p.system_prompt_digest) s += 0.1;
  if (p.tool_manifest_digest) s += 0.1;
  if (opts.knownOperators?.includes(p.operator)) s += 0.2;
  return Math.max(0, Math.min(1, s));
}
