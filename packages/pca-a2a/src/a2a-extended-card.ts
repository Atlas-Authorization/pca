/**
 * EXTENDED AGENT CARD FROM A RESIDUAL POLICY (A2A 3.1.11, 13.3). The extended card lists the skills a caller may attempt. Which
 * those are is computed by the policy analyzer (`whatMayIDo` of `@atlasauth/pca-analyzer`, which partially evaluates the policy
 * against what the caller's chain already fixes): this module takes its envelopes (structurally typed, no import) and derives
 * the card. Rules: the caller must be authenticated (A2A 13.3); a hidden skill is revealed only when its verb's envelope is
 * `autonomous` or `needs-approval`; a verb with no envelope, or `denied`, reveals nothing (unconfirmed = not shown), and the
 * absent skill looks the same whether it does not exist or is denied; all envelopes must have been computed against one policy,
 * whose digest is recorded in the PCA extension params. The derived card is unsigned: re-sign it with `issueSignedAgentCard`.
 * This is discovery, not authorization: attempting a skill still needs its PCActn.
 */
import type { AgentCard } from './index';
import { PCA_A2A_EXTENSION_URI } from './ext-uri';

export interface EnvelopeLike {
  verb: string;
  status: 'autonomous' | 'needs-approval' | 'denied';
  policyDigest: string;
}

export interface CardSkill {
  id: string;
  tags?: string[];
  [k: string]: unknown;
}

export interface ExtendedCardOptions {
  /** The caller authenticated per the card's `securitySchemes` (A2A 13.3). Anything but `true` throws. */
  authenticated: boolean;
  /** Skills only the extended card may list. */
  hiddenSkills: readonly CardSkill[];
  /** Output of `whatMayIDo` for the caller's chain. */
  envelopes: readonly EnvelopeLike[];
  /** The PCA verb a skill maps to. Default: the skill's tag `pca-verb:<verb>`. */
  verbOf?: (skill: CardSkill) => string | undefined;
}

const defaultVerbOf = (s: CardSkill): string | undefined => {
  const t = (s.tags ?? []).find((x) => typeof x === 'string' && x.startsWith('pca-verb:'));
  return t === undefined ? undefined : t.slice('pca-verb:'.length);
};

export function extendedAgentCard(publicCard: AgentCard, o: ExtendedCardOptions): AgentCard {
  if (o.authenticated !== true) throw new Error('extendedAgentCard: the caller must be authenticated (A2A 13.3)');
  const digests = new Set(o.envelopes.map((e) => e.policyDigest));
  if (digests.size > 1) throw new RangeError('extendedAgentCard: envelopes were computed against different policies');
  const byVerb = new Map(o.envelopes.map((e) => [e.verb, e] as const));
  const verbOf = o.verbOf ?? defaultVerbOf;
  const revealed: CardSkill[] = [];
  for (const s of o.hiddenSkills) {
    const verb = verbOf(s);
    const env = verb === undefined ? undefined : byVerb.get(verb);
    if (env === undefined || env.status === 'denied') continue;
    revealed.push({ ...s, tags: [...(s.tags ?? []), env.status === 'autonomous' ? 'pca:autonomous' : 'pca:needs-approval'] });
  }
  const { signatures: _drop, ...rest } = publicCard;
  const caps = (rest.capabilities ?? {}) as Record<string, unknown>;
  const exts = Array.isArray(caps.extensions) ? (caps.extensions as Array<Record<string, unknown>>) : [];
  const policyDigest = [...digests][0];
  const nextExts = policyDigest === undefined ? exts : exts.map((e) => (e.uri === PCA_A2A_EXTENSION_URI ? { ...e, params: { ...(e.params as object), policy_digest: policyDigest } } : e));
  const skills = Array.isArray(rest.skills) ? (rest.skills as unknown[]) : [];
  return { ...rest, capabilities: { ...caps, extensions: nextExts }, skills: [...skills, ...revealed] } as AgentCard;
}
