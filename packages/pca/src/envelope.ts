import { randomBytes } from '@noble/hashes/utils';
import { b64u, canonicalizeStrict, hashCanonical } from './hash';
import { mintRoot, type Capability, type Caveat } from './capability';
import type { Predicate } from './predicates';
import { validateRiskPolicy, type RiskPolicy } from './risk';

/**
 * Policy envelope + Root Intent Grant (spec §5.1). The grant is a plain M0 root Capability whose
 * first caveat of type `envelope` carries the whole envelope, so it is covered by the root
 * signature and plugs straight into `verifyChain`; tampering with it breaks the signature.
 */

export interface AgentBinding {
  model_allowlist?: string[];
  /**
   * Accepted launch/runtime measurement. Two shapes (see attestation.matchAgentBinding):
   *   - a `string`: an exact opaque digest, matched for EQUALITY (the pinned acceptable measurement).
   *     Opaque hashes have no natural order, so this stays the required-value semantics it always had.
   *   - `{ svn: number }`: a MONOTONE lower bound on an integer Security Version Number. The attested
   *     `runtime_measurement` (parsed as an integer SVN) must be `>= svn`, so a legitimately-upgraded
   *     enclave at a higher SVN passes WITHOUT re-minting the grant, while a downgrade is rejected.
   * Omitted => the runtime measurement is not gated.
   */
  min_measurement?: string | { svn: number };
  operator?: string;
  /**
   * Optional L0 (M5/M6) pin on the attested model WEIGHTS digest: the set of acceptable
   * `weights_digest` values. A model swap or malicious fine-tune changes the weights digest, so this
   * is what the attestation verifier gates on (see attestation.matchAgentBinding). Omitted => the
   * weights digest is attested and action-bound but not allowlist-gated.
   */
  weights_allowlist?: string[];
  /**
   * Optional L0 pin on the agent's SYSTEM PROMPT — "provenance beyond weights". "Which agent" is more
   * than its silicon + weights: the same model and weights running under different INSTRUCTIONS is a
   * different agent (e.g. a prompt-injected or re-instructed one). This is the set of acceptable
   * `system_prompt_digest` values (a digest of the agent's system prompt / instructions, measured into
   * the attestation document). A changed system prompt yields a different digest, so this is gated
   * exactly like `weights_allowlist` (see attestation.matchAgentBinding), and fails closed if the
   * attestation carries no system-prompt digest at all. Omitted => the system prompt is attested (when
   * present) but not allowlist-gated.
   */
  system_prompt_allowlist?: string[];
  /**
   * Optional L0 pin on the agent's TOOL MANIFEST — the other half of "provenance beyond weights": the
   * set of tools/functions the agent can invoke is part of its identity. This is the set of acceptable
   * `tool_manifest_digest` values (a digest of the agent's available-tool manifest, measured into the
   * attestation document). Granting, revoking or redefining a tool changes the digest, so this is
   * gated exactly like `weights_allowlist` and fails closed if the attestation carries no tool-manifest
   * digest. Omitted => the tool manifest is attested (when present) but not allowlist-gated.
   */
  tool_manifest_allowlist?: string[];
  /**
   * Optional fail-closed demand for a HARDWARE-rooted (TEE) attestation. When `true`, verification
   * REQUIRES the document to be validated by a hardware verifier and rooted in silicon: a software-mode
   * document, or the absence of a `hardwareVerifier`, FAILS regardless of any trusted software attestor
   * keys (see attestation.verifyAttestation). Omitted / `false` => behaviour is unchanged: whether
   * hardware is enforced depends purely on whether a `hardwareVerifier` is configured.
   */
  require_hardware?: boolean;
  /**
   * Optional fail-closed demand that the attested `weights_digest` be HARDWARE-MEASURED (spec §15,
   * "Standardizing weights-level attestation for hosted models"). `require_hardware` roots the whole
   * DOCUMENT in silicon, but a hardware verifier may legitimately not MEASURE the loaded weights at all
   * (SEV-SNP/TDX attest the launch measurement, not the fp16 weights), and a host-asserted field such as
   * SEV-SNP HOST_DATA is not silicon-measured even in hardware mode. When `require_measured_weights` is
   * `true`, the `weights_digest` the `weights_allowlist` is matched against MUST come from a
   * hardware-measured identity (the verifier set `MeasuredIdentity.weights_measured === true`); a
   * self-asserted (software) or host-asserted weights digest — even one naming an allowlisted value —
   * FAILS CLOSED (see attestation.matchAgentBinding). Omitted / `false` => behaviour is unchanged: the
   * `weights_allowlist` is matched by value regardless of how the digest was obtained.
   */
  require_measured_weights?: boolean;
}

export interface Envelope {
  goal_commit: string;
  predicates: Predicate[];
  caveats: Caveat[];
  agent_binding: AgentBinding;
  risk_policy: RiskPolicy;
  /**
   * Optional committed objective-risk facts (see `objective-binding.ts`, `ObjectiveRiskCommitment`). Lives in
   * the signed envelope, never in the PCActn. Absent = heuristic risk.
   */
  objective_risk?: unknown;
  /**
   * Optional committed proof-of-progress goal (`{ v:1, goal: GoalCommitment, initial_state, ... }`, read by the
   * server's admission path). Lives in the signed envelope, never in the PCActn: tampering breaks the grant signature.
   */
  progress?: unknown;
}

export const ENVELOPE_CAVEAT = 'envelope';
const GOAL_DOMAIN = 'atlas-pca/goal/v1\0';

/** Salted commitment to the plaintext goal: base64url(sha256(canonical({d, goal, salt}))). */
export function goalCommitOf(goal: string, salt: string): string {
  return hashCanonical({ d: GOAL_DOMAIN, goal, salt });
}

/** Check that a revealed (goal, salt) opens `commit`. */
export function verifyGoalCommit(commit: string, goal: string, salt: string): boolean {
  return goalCommitOf(goal, salt) === commit;
}

/** JSON-normalize (drops undefined fields) so the envelope is canonicalizable. */
function plain<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export function mintGrant(args: {
  principalSecret: Uint8Array;
  /** b64u */
  principalPublic: string;
  /** b64u holder (agent) key */
  holder: string;
  envelope: Omit<Envelope, 'goal_commit'>;
  /** plaintext goal; only its salted hash goes in the grant */
  goal: string;
  /** optional b64u salt (random 16 bytes if omitted) */
  salt?: string;
}): { grant: Capability; goalCommit: string; goalSalt: string } {
  if (typeof args.goal !== 'string' || args.goal.length === 0) throw new Error('mintGrant: goal required');
  const bad = validateRiskPolicy(args.envelope.risk_policy);
  if (bad) throw new Error(`mintGrant: ${bad}`);
  const goalSalt = args.salt ?? b64u(randomBytes(16));
  const goalCommit = goalCommitOf(args.goal, goalSalt);
  const env: Envelope = plain({
    goal_commit: goalCommit,
    predicates: args.envelope.predicates,
    caveats: args.envelope.caveats,
    agent_binding: args.envelope.agent_binding ?? {},
    risk_policy: args.envelope.risk_policy,
    ...(args.envelope.objective_risk !== undefined ? { objective_risk: args.envelope.objective_risk } : {}),
    ...(args.envelope.progress !== undefined ? { progress: args.envelope.progress } : {}),
  });
  canonicalizeStrict(env); // throws if not STRICT-canonical-encodable (every PCActn embeds the grant in its signed body)
  const grant = mintRoot({
    principalSecret: args.principalSecret,
    principalPublic: args.principalPublic,
    holder: args.holder,
    caveats: [{ type: ENVELOPE_CAVEAT, ...env }],
  });
  return { grant, goalCommit, goalSalt };
}

/**
 * Extract the envelope: the FIRST `envelope` caveat (the root's; later attenuation can only add
 * caveats, never replace it). Returns null if absent or structurally malformed. Does not verify
 * signatures — run `verifyChain` first.
 */
export function readEnvelope(grant: Capability): Envelope | null {
  try {
    const cv = grant?.caveats?.find((c) => c?.type === ENVELOPE_CAVEAT);
    if (!cv) return null;
    const { type: _t, ...rest } = cv;
    void _t;
    const e = rest as Partial<Envelope>;
    if (typeof e.goal_commit !== 'string') return null;
    if (!Array.isArray(e.predicates) || !Array.isArray(e.caveats)) return null;
    if (e.agent_binding === null || typeof e.agent_binding !== 'object') return null;
    if (validateRiskPolicy(e.risk_policy)) return null;
    return e as Envelope;
  } catch {
    return null;
  }
}
