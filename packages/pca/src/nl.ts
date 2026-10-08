/**
 * NL → policy (spec Part 2.3 "NL→policy uses the semantic-judgment layer").
 *
 * Turn a plain-English instruction ("let the support bot refund up to $200/day and email customers")
 * into a REAL, grounded policy. The language model is INJECTED as a `complete(prompt) => string`
 * function — this module has no model dependency — and, crucially, its output is never trusted: it is
 * parsed strictly, every proposed verb is checked against the connector catalog (hallucinated verbs are
 * dropped and reported), limits are parsed by the same `parseLimit`, and the result compiles through the
 * SAME facade path the verifier enforces. So the model can only PROPOSE structured intent inside the
 * catalog's vocabulary; it can never widen authority beyond what the grant actually grants.
 */

import { type Catalog, DEFAULT_CATALOG } from './catalog';
import { type Agent, type Limits, type PermissionMap, agent, compilePolicy, parseLimit } from './facade';
import type { KeyPair } from './keys';
import { type Lint, lintPolicy } from './policy-sim';

export type Completion = (prompt: string) => Promise<string> | string;

/** Build the grounding prompt: the model may only use verbs the catalog actually defines. */
export function nlPrompt(instruction: string, catalog: Catalog = DEFAULT_CATALOG): string {
  const verbs = catalog
    .all()
    .map((s) => `  - ${s.verb} (${s.reversibility}${s.amountField ? `, amount field "${s.amountField}"` : ''}): ${s.description}`)
    .join('\n');
  return [
    'You translate an instruction into a strict JSON agent policy. Output ONLY JSON, no prose, no code fence.',
    'Shape: {"permissions":{"<connector>":["<action>",...]},"limits":{"<action-or-verb>":"$<amount>/<period>"|"<count>/<period>"}}',
    'Rules: use ONLY the verbs below (connector.action). A limit key is a bare action (e.g. "refund") or a full verb (e.g. "stripe.refund").',
    'Monetary limits start with "$"; plain numbers are counts. Periods: hour, day, week, month. Omit limits you are unsure about.',
    '',
    'Available verbs:',
    verbs,
    '',
    `Instruction: ${instruction}`,
    'JSON:',
  ].join('\n');
}

export interface ParsedNLPolicy {
  permissions: PermissionMap;
  limits: Limits;
  /** connector.action pairs the model proposed that are NOT in the catalog — dropped (not granted). */
  unknownVerbs: string[];
  /** limit keys that were dropped because they were unparseable or matched no granted action. */
  droppedLimits: string[];
}

/** Strictly parse + GROUND the model's JSON against the catalog. Never throws on model garbage. */
export function parseNLPolicy(raw: string, catalog: Catalog = DEFAULT_CATALOG): ParsedNLPolicy {
  const permissions: PermissionMap = {};
  const limits: Limits = {};
  const unknownVerbs: string[] = [];
  const droppedLimits: string[] = [];

  let obj: unknown;
  try {
    obj = JSON.parse(stripFence(raw));
  } catch {
    return { permissions, limits, unknownVerbs, droppedLimits };
  }
  if (obj === null || typeof obj !== 'object') return { permissions, limits, unknownVerbs, droppedLimits };

  const perms = (obj as Record<string, unknown>).permissions;
  if (perms && typeof perms === 'object') {
    for (const [connector, actions] of Object.entries(perms as Record<string, unknown>)) {
      if (!Array.isArray(actions)) continue;
      for (const action of actions) {
        if (typeof action !== 'string') continue;
        const verb = `${connector}.${action}`;
        if (catalog.get(verb)) (permissions[connector] ??= []).push(action);
        else unknownVerbs.push(verb);
      }
    }
  }

  // dedupe actions per connector
  for (const c of Object.keys(permissions)) permissions[c] = [...new Set(permissions[c])];

  const grantedNames = new Set(
    Object.entries(permissions).flatMap(([c, acts]) => acts.flatMap((a) => [`${c}.${a}`, a])),
  );
  const lims = (obj as Record<string, unknown>).limits;
  if (lims && typeof lims === 'object') {
    for (const [key, spec] of Object.entries(lims as Record<string, unknown>)) {
      if (typeof spec !== 'string') {
        droppedLimits.push(key);
        continue;
      }
      try {
        parseLimit(spec); // validate
      } catch {
        droppedLimits.push(key);
        continue;
      }
      if (!grantedNames.has(key)) {
        droppedLimits.push(key);
        continue;
      }
      limits[key] = spec;
    }
  }
  return { permissions, limits, unknownVerbs, droppedLimits };
}

function stripFence(raw: string): string {
  // Extract the outermost brace span, which drops any code fence and/or prose on either side.
  const t = raw.trim();
  const i = t.indexOf('{');
  const j = t.lastIndexOf('}');
  return i >= 0 && j >= i ? t.slice(i, j + 1) : t;
}

export interface NLPolicyResult extends ParsedNLPolicy {
  raw: string;
  /** Lints over the compiled policy (empty permissions => the single 'empty' note). */
  lints: Lint[];
}

export interface PolicyFromNLRequest {
  instruction: string;
  complete: Completion;
  catalog?: Catalog;
}

/** Ask the model for a policy, ground it against the catalog, and lint the compiled result. */
export async function policyFromNL(req: PolicyFromNLRequest): Promise<NLPolicyResult> {
  const catalog = req.catalog ?? DEFAULT_CATALOG;
  const raw = await req.complete(nlPrompt(req.instruction, catalog));
  const parsed = parseNLPolicy(raw, catalog);
  let lints: Lint[] = [];
  if (Object.keys(parsed.permissions).length > 0) {
    lints = lintPolicy(compilePolicy({ permissions: parsed.permissions, limits: parsed.limits, catalog }), { catalog });
  }
  return { ...parsed, raw, lints };
}

export interface AgentFromNLRequest extends PolicyFromNLRequest {
  principal: KeyPair;
  goal: string;
  aud?: string;
  holder?: KeyPair;
  now?: number;
}

/** End-to-end: NL instruction → grounded policy → minted agent. Throws if nothing valid was granted. */
export async function agentFromNL(req: AgentFromNLRequest): Promise<{ agent: Agent; result: NLPolicyResult }> {
  const result = await policyFromNL(req);
  if (Object.keys(result.permissions).length === 0) {
    throw new Error(`agentFromNL: the instruction yielded no grantable permissions (unknown verbs: ${result.unknownVerbs.join(', ') || 'none'})`);
  }
  const a = agent({
    principal: req.principal,
    goal: req.goal,
    permissions: result.permissions,
    limits: result.limits,
    ...(req.catalog ? { catalog: req.catalog } : {}),
    ...(req.aud !== undefined ? { aud: req.aud } : {}),
    ...(req.holder ? { holder: req.holder } : {}),
    ...(req.now !== undefined ? { now: req.now } : {}),
  });
  return { agent: a, result };
}
