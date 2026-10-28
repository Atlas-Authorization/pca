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
 *
 * GENERATE-THEN-REVIEW. The model's output is only ever a DRAFT. It becomes loadable policy only after a
 * reviewer whose key YOU pinned signs the exact compiled policy (`approveDraft`), and `loadApprovedPolicy` /
 * `agentFromApprovedNL` re-derive everything from the draft contents (they trust nothing the draft says about itself).
 * GUARANTEED: no model output is enforced without a pinned reviewer's unexpired signature over the exact
 * permissions, limits, catalog AND (approval v2, 0.5) the instruction text, the model id and the prompt that produced
 * the draft (closes W4: a reviewer-signed draft cannot be attached to another goal text, and a model or prompt change
 * changes the digest); every verb is in the catalog; the static analyzer has no error finding. A v1 approval (signed
 * before 0.5) still loads for one release, flagged `legacy_unbound_instruction`. The typed successor, which signs the
 * whole Goal IR and the compiled policy, is `GoalApproval` / `loadApprovedGoal` in @atlasauth/pca-goal.
 * NOT GUARANTEED: that the model understood the instruction, or that the reviewer read the draft.
 */

import { type Catalog, DEFAULT_CATALOG } from './catalog';
import { type Agent, type Limits, type PermissionMap, agent, compilePolicy, parseLimit } from './facade';
import { type KeyPair, encodeSig, sign, verifyB64u, publicKeyOf } from './keys';
import { b64u, canonicalBytesLenient, hashCanonicalLenient, utf8 } from './hash';
import { type Lint, lintPolicy } from './policy-sim';

export type Completion = (prompt: string) => Promise<string> | string;

/** Build the grounding prompt: the model may only use verbs the catalog actually defines. */
export function nlPrompt(instruction: string, catalog: Catalog = DEFAULT_CATALOG): string {
  const verbs = catalog
    .all()
    .map((s) => `  - ${s.verb} (${s.reversibility}${s.amountField ? `, amount field "${s.amountField}"` : ''}${s.aliases?.length ? `, also called: ${s.aliases.join(', ')}` : ''}): ${s.description}`)
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
        // grounded on the definitions: the exact verb, or an alias of exactly one action of this connector (stored canonically)
        const spec = catalog.get(verb) ?? catalog.resolve?.(connector, action);
        if (spec) (permissions[connector] ??= []).push(spec.connector === connector ? spec.action : action);
        else unknownVerbs.push(verb);
      }
    }
  }

  // dedupe actions per connector
  for (const c of Object.keys(permissions)) permissions[c] = [...new Set(permissions[c])];

  const grantedNames = new Set(
    Object.entries(permissions).flatMap(([c, acts]) => acts.flatMap((a) => [`${c}.${a}`, a, ...(catalog.get(`${c}.${a}`)?.aliases ?? [])])),
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
  /** Identifier of the model behind `complete`; pinned by the draft digest (a different model is a different draft). */
  model?: string;
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

// ---- generate-then-review ---------------------------------------------------------------------------

export const NL_APPROVAL_DOMAIN = 'atlas-pca/nl-approval/v1\0';
/** Domain of an approval v2 (binds the instruction, model and prompt). */
export const NL_APPROVAL_DOMAIN_V2 = 'atlas-pca/nl-approval/v2\0';
/** Model output larger than this (UTF-8 bytes) is refused outright. */
export const MAX_NL_OUTPUT_BYTES = 16_384;
/** An approval may not be valid for longer than this. */
export const MAX_NL_APPROVAL_TTL_MS = 24 * 3_600_000;
const DEFAULT_NL_APPROVAL_TTL_MS = 3_600_000;

/** Digest of the catalog vocabulary a draft was grounded against (verbs, reversibility, amount field). */
export function catalogDigest(catalog: Catalog): string {
  const rows = catalog
    .all()
    .map((s) => [s.verb, s.reversibility, s.amountField ?? null])
    .sort((a, b) => (a[0]! < b[0]! ? -1 : a[0]! > b[0]! ? 1 : 0));
  return hashCanonicalLenient({ v: 1, rows });
}

/** What approval v2 adds to a draft digest: the instruction text, the model id and the exact prompt. */
export interface DraftBinding {
  instruction_digest: string;
  model: string | null;
  prompt_digest: string;
}

/** The binding a draft for `instruction` has: all three recomputed from public inputs (the prompt is deterministic). */
export function draftBinding(instruction: string, catalog: Catalog, model?: string | null): DraftBinding {
  return { instruction_digest: hashCanonicalLenient({ d: 'atlas-pca/nl-instruction/v1', text: instruction }), model: model ?? null, prompt_digest: hashCanonicalLenient({ d: 'atlas-pca/nl-prompt/v1', text: nlPrompt(instruction, catalog) }) };
}

/** Digest an approval v2 signs: the v1 content PLUS {instruction_digest, model, prompt_digest}. */
export function draftDigestV2(permissions: PermissionMap, limits: Limits, catalog_digest: string, binding: DraftBinding): string {
  const perms: PermissionMap = {};
  for (const c of Object.keys(permissions).sort()) perms[c] = [...permissions[c]!].sort();
  return hashCanonicalLenient({ v: 2, permissions: perms, limits, catalog_digest, instruction_digest: binding.instruction_digest, model: binding.model, prompt_digest: binding.prompt_digest });
}

/** Digest a v1 (pre-0.5) reviewer signed: {permissions, limits, catalog digest}. Kept so old approvals still load. */
export function draftDigest(permissions: PermissionMap, limits: Limits, catalog_digest: string): string {
  const perms: PermissionMap = {};
  for (const c of Object.keys(permissions).sort()) perms[c] = [...permissions[c]!].sort();
  return hashCanonicalLenient({ v: 1, permissions: perms, limits, catalog_digest });
}

/** An UNAPPROVED policy proposal. Not loadable: only `loadApprovedPolicy` turns it into policy. */
export interface DraftPolicy {
  status: 'draft';
  instruction: string;
  permissions: PermissionMap;
  limits: Limits;
  catalog_digest: string;
  /** Digest of the instruction text, the model id and the prompt (approval v2 signs them). */
  binding: DraftBinding;
  /** Digest of {permissions, limits, catalog_digest, binding}: what a reviewer signs (v2). */
  digest: string;
  unknownVerbs: string[];
  droppedLimits: string[];
  lints: Lint[];
  /** No error-level lint and at least one permission. Informational: the loader recomputes it. */
  analyzerOk: boolean;
}

function lintsOf(permissions: PermissionMap, limits: Limits, catalog: Catalog): Lint[] {
  return Object.keys(permissions).length > 0 ? lintPolicy(compilePolicy({ permissions, limits, catalog }), { catalog }) : [];
}

/** Ask the model for a DRAFT. Throws if the model output is oversize. Never enforces anything. */
export async function draftPolicyFromNL(req: PolicyFromNLRequest): Promise<DraftPolicy> {
  const catalog = req.catalog ?? DEFAULT_CATALOG;
  const raw = await req.complete(nlPrompt(req.instruction, catalog));
  if (typeof raw !== 'string' || utf8(raw).length > MAX_NL_OUTPUT_BYTES) throw new Error(`draftPolicyFromNL: model output exceeds ${MAX_NL_OUTPUT_BYTES} bytes or is not a string`);
  const p = parseNLPolicy(raw, catalog);
  const lints = lintsOf(p.permissions, p.limits, catalog);
  const catalog_digest = catalogDigest(catalog);
  const binding = draftBinding(req.instruction, catalog, req.model);
  return {
    status: 'draft',
    instruction: req.instruction,
    permissions: p.permissions,
    limits: p.limits,
    catalog_digest,
    binding,
    digest: draftDigestV2(p.permissions, p.limits, catalog_digest, binding),
    unknownVerbs: p.unknownVerbs,
    droppedLimits: p.droppedLimits,
    lints,
    analyzerOk: Object.keys(p.permissions).length > 0 && !lints.some((l) => l.level === 'error'),
  };
}

export interface NLApproval {
  /** 1: pre-0.5 (digest excludes the instruction: loads flagged legacy). 2: binds instruction, model and prompt. */
  v: 1 | 2;
  digest: string;
  catalog_digest: string;
  /** b64u Ed25519 public key of the reviewer. */
  reviewer: string;
  approved_at: number;
  expires_at: number;
  sig: string;
}

function approvalMessage(a: Omit<NLApproval, 'sig'>): Uint8Array {
  const pre = utf8(a.v === 2 ? NL_APPROVAL_DOMAIN_V2 : NL_APPROVAL_DOMAIN);
  const body = canonicalBytesLenient({ v: a.v, digest: a.digest, catalog_digest: a.catalog_digest, reviewer: a.reviewer, approved_at: a.approved_at, expires_at: a.expires_at });
  const m = new Uint8Array(pre.length + body.length);
  m.set(pre);
  m.set(body, pre.length);
  return m;
}

/** The human step: sign the exact draft. Refuses a draft the analyzer rejects (the loader would refuse it anyway). */
export function approveDraft(draft: DraftPolicy, reviewerSecret: Uint8Array, opts: { now?: number; ttlMs?: number } = {}): NLApproval {
  if (!draft.analyzerOk) throw new Error('approveDraft: the draft did not pass the static analyzer');
  if (draft.unknownVerbs.length > 0) throw new Error('approveDraft: the draft proposed verbs that are not in the catalog');
  const now = opts.now ?? Date.now();
  const ttl = opts.ttlMs ?? DEFAULT_NL_APPROVAL_TTL_MS;
  if (!Number.isFinite(now) || !Number.isFinite(ttl) || ttl <= 0 || ttl > MAX_NL_APPROVAL_TTL_MS) throw new Error('approveDraft: invalid time or ttl');
  const body = { v: 2 as const, digest: draft.digest, catalog_digest: draft.catalog_digest, reviewer: b64u(publicKeyOf(reviewerSecret)), approved_at: now, expires_at: now + ttl };
  return { ...body, sig: encodeSig(sign(reviewerSecret, approvalMessage(body))) };
}

export type NLRejection =
  | 'no_reviewers_pinned'
  | 'not_a_draft'
  | 'catalog_mismatch'
  | 'tampered_draft'
  | 'goal_mismatch'
  | 'unknown_verbs'
  | 'empty_permissions'
  | 'analyzer_error'
  | 'malformed_approval'
  | 'digest_mismatch'
  | 'reviewer_not_pinned'
  | 'ttl_too_long'
  | 'not_yet_valid'
  | 'expired'
  | 'bad_signature';

export type LoadedNLPolicy =
  | {
      ok: true;
      permissions: PermissionMap;
      limits: Limits;
      reviewer: string;
      /** The instruction the reviewer's signature covers (v2). For a legacy v1 approval it is the draft's UNSIGNED claim. */
      instruction: string;
      /** True for a v1 approval: its signature does NOT cover the instruction, so the instruction is unbound. Removed next release. */
      legacy_unbound_instruction: boolean;
    }
  | { ok: false; reason: NLRejection };

export interface LoadApprovedOptions {
  /** b64u public keys allowed to approve. Empty or absent: everything is refused. */
  reviewers: string[];
  catalog?: Catalog;
  now?: number;
}

const fail = (reason: NLRejection): LoadedNLPolicy => ({ ok: false, reason });
const isInt = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n);

/** The only door from a draft to policy. Recomputes digest, grounding and lints from the draft contents; never throws. */
export function loadApprovedPolicy(draft: DraftPolicy, approval: NLApproval, opts: LoadApprovedOptions): LoadedNLPolicy {
  try {
    const catalog = opts.catalog ?? DEFAULT_CATALOG;
    const now = opts.now ?? Date.now();
    if (!Array.isArray(opts.reviewers) || opts.reviewers.length === 0) return fail('no_reviewers_pinned');
    if (!draft || draft.status !== 'draft' || typeof draft.permissions !== 'object' || draft.permissions === null || typeof draft.limits !== 'object' || draft.limits === null) return fail('not_a_draft');
    const cd = catalogDigest(catalog);
    if (draft.catalog_digest !== cd) return fail('catalog_mismatch');
    if (typeof draft.instruction !== 'string') return fail('not_a_draft');
    // A pre-0.5 draft carries no `binding` and a v1 digest: it can only ever match a v1 approval (flagged legacy below).
    const legacyDraft = draft.binding === undefined;
    if (!legacyDraft && (draft.binding === null || typeof draft.binding !== 'object')) return fail('not_a_draft');
    if (legacyDraft) {
      if (draftDigest(draft.permissions, draft.limits, cd) !== draft.digest) return fail('tampered_draft');
    } else {
      // The binding is recomputed from the draft's own instruction; only the model id is taken from the draft.
      const binding = draftBinding(draft.instruction, catalog, typeof draft.binding.model === 'string' ? draft.binding.model : null);
      if (draft.binding.instruction_digest !== binding.instruction_digest || draft.binding.prompt_digest !== binding.prompt_digest || draft.binding.model !== binding.model) return fail('tampered_draft');
      if (draftDigestV2(draft.permissions, draft.limits, cd, binding) !== draft.digest) return fail('tampered_draft');
    }
    // Re-ground: every verb must be in the catalog and every limit parse, regardless of what the draft claims.
    for (const [c, acts] of Object.entries(draft.permissions)) {
      if (!Array.isArray(acts) || acts.some((a) => typeof a !== 'string' || !catalog.get(`${c}.${a}`))) return fail('unknown_verbs');
    }
    if (Array.isArray(draft.unknownVerbs) && draft.unknownVerbs.length > 0) return fail('unknown_verbs');
    if (Object.keys(draft.permissions).length === 0) return fail('empty_permissions');
    if (lintsOf(draft.permissions, draft.limits, catalog).some((l) => l.level === 'error')) return fail('analyzer_error');
    const a = approval;
    if (!a || (a.v !== 1 && a.v !== 2) || typeof a.sig !== 'string' || typeof a.reviewer !== 'string' || typeof a.digest !== 'string' || typeof a.catalog_digest !== 'string' || !isInt(a.approved_at) || !isInt(a.expires_at)) return fail('malformed_approval');
    const legacy = a.v === 1;
    if (legacyDraft && !legacy) return fail('digest_mismatch'); // a v2 approval promises the instruction is bound; a binding-less draft cannot honor that
    // v1 signed the digest without the binding: recompute it from the (already verified) contents.
    if (a.digest !== (legacy ? draftDigest(draft.permissions, draft.limits, cd) : draft.digest) || a.catalog_digest !== cd) return fail('digest_mismatch');
    if (!opts.reviewers.includes(a.reviewer)) return fail('reviewer_not_pinned');
    if (a.expires_at - a.approved_at <= 0 || a.expires_at - a.approved_at > MAX_NL_APPROVAL_TTL_MS) return fail('ttl_too_long');
    if (a.approved_at > now) return fail('not_yet_valid');
    if (now >= a.expires_at) return fail('expired');
    if (!verifyB64u(a.reviewer, approvalMessage(a), a.sig)) return fail('bad_signature');
    return { ok: true, permissions: draft.permissions, limits: draft.limits, reviewer: a.reviewer, instruction: draft.instruction, legacy_unbound_instruction: legacy };
  } catch {
    return fail('malformed_approval');
  }
}

export interface AgentFromApprovedNLRequest extends LoadApprovedOptions {
  draft: DraftPolicy;
  approval: NLApproval;
  principal: KeyPair;
  /** The grant's goal text. Must equal the approved instruction (v2 approvals); a legacy v1 approval cannot check it. */
  goal: string;
  aud?: string;
  holder?: KeyPair;
}

/** The ONLY NL-to-agent path: mints an agent from a draft a pinned reviewer signed. Throws with the rejection reason otherwise. */
export function agentFromApprovedNL(req: AgentFromApprovedNLRequest): { agent: Agent; reviewer: string; legacy_unbound_instruction: boolean } {
  const loaded = loadApprovedPolicy(req.draft, req.approval, req);
  if (!loaded.ok) throw new Error(`agentFromApprovedNL: ${loaded.reason}`);
  if (!loaded.legacy_unbound_instruction && req.goal !== loaded.instruction) throw new Error('agentFromApprovedNL: goal_mismatch');
  const a = agent({
    principal: req.principal,
    goal: req.goal,
    permissions: loaded.permissions,
    limits: loaded.limits,
    ...(req.catalog ? { catalog: req.catalog } : {}),
    ...(req.aud !== undefined ? { aud: req.aud } : {}),
    ...(req.holder ? { holder: req.holder } : {}),
    ...(req.now !== undefined ? { now: req.now } : {}),
  });
  return { agent: a, reviewer: loaded.reviewer, legacy_unbound_instruction: loaded.legacy_unbound_instruction };
}

/** @deprecated Pre-0.5 approval (v1): signs the draft WITHOUT the instruction, model or prompt. Only for the legacy-load compatibility window. */
export function approveDraftLegacyV1(draft: DraftPolicy, reviewerSecret: Uint8Array, opts: { now?: number; ttlMs?: number } = {}): NLApproval {
  const v2 = approveDraft(draft, reviewerSecret, opts);
  const body = { v: 1 as const, digest: draftDigest(draft.permissions, draft.limits, draft.catalog_digest), catalog_digest: draft.catalog_digest, reviewer: v2.reviewer, approved_at: v2.approved_at, expires_at: v2.expires_at };
  return { ...body, sig: encodeSig(sign(reviewerSecret, approvalMessage(body))) };
}
