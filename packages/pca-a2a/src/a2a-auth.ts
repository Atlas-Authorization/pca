/**
 * PCA binding for A2A authorization (A2A protocol specification, main at 98279d62, 2026-10-20; sections 3.1.7, 3.1.11, 3.3.2,
 * 4.3, 4.4, 4.6, 7.4 to 7.6, 8.4, 13.1 to 13.3, and `specification/a2a.proto`).
 *
 * What A2A gives: it authenticates the caller (section 7.3 and 7.4), gates the extended Agent Card (3.1.11), and lets an agent
 * park a Task in `TASK_STATE_AUTH_REQUIRED` (7.6). It does not authorize a task's arguments or a delegation: section 7.5 leaves
 * authorization to the implementation and 7.6.4 says AUTH_REQUIRED, by itself, authorizes nothing and a credential obtained
 * while a Task is in that state must not be assumed to authorize later messages. The PCA binding is the extension those
 * sections ask for (section 4.6, declared in `capabilities.extensions`, opted into by the `A2A-Extensions` service parameter):
 *
 *  - the Agent Card declares the extension and, in its `params`, the audience, accepted suites and (optionally) the
 *    `pca_grant` pointers the agent holds ({@link pcaExtensionDeclaration}, {@link readPcaExtension});
 *  - an agent that needs authority parks the Task in AUTH_REQUIRED with a typed `pca_need` in the status message
 *    ({@link authRequiredStatus}); INPUT_REQUIRED stays a clarification and grants nothing;
 *  - the client answers with a message carrying a fresh PCActn for exactly that need ({@link resumeAuthRequired}); the
 *    transition itself authorizes nothing, the proof does;
 *  - every hop of a delegation chain of Tasks verifies its own PCActn for its own audience, and the chain must extend the
 *    previous hop's ({@link verifyA2ADelegation});
 *  - push-notification tokens are bound to the task and the chain ({@link pcaPushToken}).
 */

import {
  decodePcaNeed,
  encodePcaNeed,
  hashCanonical,
  parsePcaGrantDetails,
  pcaChainDigest,
  pcaNeedDigest,
  type PcaGrantDetail,
  type PcaNeed,
  type PcaNeedResult,
} from '@atlasauth/pca';
import { PCA_A2A_EXTENSION_URI } from './ext-uri';
import {
  extractPca,
  extractPcaFromMessage,
  verifyA2ATask,
  type A2AMessage,
  type A2ATask,
  type A2AVerification,
  type AgentCard,
  type PcaVerifyOptions,
} from './index';

// ---- task states ---------------------------------------------------------------------------------

export const TASK_STATE_AUTH_REQUIRED = 'TASK_STATE_AUTH_REQUIRED';
export const TASK_STATE_INPUT_REQUIRED = 'TASK_STATE_INPUT_REQUIRED';
/** Key under which a status or answer message carries the PCA binding data (the extension URI, A2A 4.6.2). */
const NEED_KEY = `${PCA_A2A_EXTENSION_URI}#need`;

/** AUTH_REQUIRED in the 1.0 enum spelling. The pre-1.0 `auth-required` is also read, never written. */
export function isAuthRequired(state: unknown): boolean {
  return state === TASK_STATE_AUTH_REQUIRED || state === 'auth-required';
}

// ---- Agent Card extension declaration --------------------------------------------------------------

export interface PcaA2AExtensionParams {
  /** The audience this agent's PCActns must carry (its own identifier). */
  aud: string;
  /** Signature suites accepted for the leaf and every hop. */
  suites?: string[];
  /** `pca_grant` pointers for grants this agent holds or accepts (RFC 9396 profile). */
  grants?: PcaGrantDetail[];
  /** Digest of the policy an extended card's skill list was computed against. */
  policy_digest?: string;
}

export interface AgentExtensionDecl {
  uri: string;
  description: string;
  required: boolean;
  params: PcaA2AExtensionParams;
}

const PARAM_KEYS = new Set(['aud', 'suites', 'grants', 'policy_digest']);

/** The `AgentExtension` object (A2A 4.4.4) to put in `capabilities.extensions`. `required` makes a client without the extension fail with `ExtensionSupportRequiredError`. */
export function pcaExtensionDeclaration(params: PcaA2AExtensionParams, required = true): AgentExtensionDecl {
  return { uri: PCA_A2A_EXTENSION_URI, description: 'Per-action proofs of authority (PCActn) on tasks and messages', required, params };
}

export type PcaExtensionResult =
  | { ok: true; required: boolean; params: PcaA2AExtensionParams; grants: PcaGrantDetail[] }
  | { ok: false; code: 'not_declared' | 'bad_declaration' | 'bad_params' | 'bad_grants' };

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

/** Read and validate the PCA extension from an Agent Card. A malformed declaration is a refusal, never a guess. */
export function readPcaExtension(card: unknown): PcaExtensionResult {
  const exts = isObj(card) && isObj(card.capabilities) ? card.capabilities.extensions : undefined;
  if (!Array.isArray(exts)) return { ok: false, code: 'not_declared' };
  const found = exts.filter((e) => isObj(e) && e.uri === PCA_A2A_EXTENSION_URI);
  if (found.length === 0) return { ok: false, code: 'not_declared' };
  if (found.length > 1) return { ok: false, code: 'bad_declaration' }; // two declarations disagree: refuse
  const e = found[0] as Record<string, unknown>;
  if (e.required !== undefined && typeof e.required !== 'boolean') return { ok: false, code: 'bad_declaration' };
  const p = e.params;
  if (!isObj(p) || Object.keys(p).some((k) => !PARAM_KEYS.has(k)) || typeof p.aud !== 'string' || p.aud.length === 0 || p.aud.length > 512) {
    return { ok: false, code: 'bad_params' };
  }
  if (p.suites !== undefined && !(Array.isArray(p.suites) && p.suites.length <= 16 && p.suites.every((s) => typeof s === 'string' && s.length > 0 && s.length <= 64))) {
    return { ok: false, code: 'bad_params' };
  }
  if (p.policy_digest !== undefined && !(typeof p.policy_digest === 'string' && p.policy_digest.length > 0 && p.policy_digest.length <= 128)) return { ok: false, code: 'bad_params' };
  let grants: PcaGrantDetail[] = [];
  if (p.grants !== undefined) {
    const g = parsePcaGrantDetails(p.grants);
    if (!g.ok) return { ok: false, code: 'bad_grants' };
    grants = g.details;
  }
  return { ok: true, required: e.required === true, params: p as unknown as PcaA2AExtensionParams, grants };
}

/** True iff the `A2A-Extensions` service parameter lists the PCA extension (exact URI match in a comma-separated list). */
export function clientOptsIntoPca(a2aExtensionsHeader: unknown): boolean {
  return typeof a2aExtensionsHeader === 'string' && a2aExtensionsHeader.split(',').some((u) => u.trim() === PCA_A2A_EXTENSION_URI);
}

// ---- AUTH_REQUIRED mapping ---------------------------------------------------------------------------

export interface AuthRequiredStatus {
  state: typeof TASK_STATE_AUTH_REQUIRED;
  message: A2AMessage & { messageId: string };
  timestamp: string;
}

/**
 * The TaskStatus an agent sets to ask for authority (A2A 7.6.1: a Task, state AUTH_REQUIRED, and a message explaining the
 * requirement). The typed need rides in the message metadata under the extension key; the text is for people. Throws on a
 * need the codec would refuse.
 */
export function authRequiredStatus(need: PcaNeed, o: { messageId: string; now: number; text?: string }): AuthRequiredStatus {
  encodePcaNeed(need); // validates and bounds
  return {
    state: TASK_STATE_AUTH_REQUIRED,
    timestamp: new Date(o.now).toISOString(),
    message: {
      messageId: o.messageId,
      role: 'agent',
      parts: [{ kind: 'text', text: o.text ?? `Authority needed: ${need.verb} on ${need.resource}` }],
      extensions: [PCA_A2A_EXTENSION_URI],
      metadata: { [NEED_KEY]: encodePcaNeed(need) },
    } as A2AMessage & { messageId: string },
  };
}

/** The need parked in a task status message, decoded (null when there is none). */
export function readAuthRequiredNeed(task: unknown): PcaNeedResult | null {
  const status = isObj(task) ? task.status : undefined;
  const msg = isObj(status) ? status.message : undefined;
  const md = isObj(msg) ? msg.metadata : undefined;
  const v = isObj(md) ? md[NEED_KEY] : undefined;
  return v === undefined ? null : decodePcaNeed(v);
}

/** The answer message to put on the Task: a PCActn for exactly the parked need, plus the need's digest. */
export function answerMessage(need: PcaNeed, pcActn: unknown, messageId: string): A2AMessage {
  return {
    role: 'user',
    messageId,
    parts: [{ kind: 'text', text: 'authority provided' }],
    metadata: { [PCA_A2A_EXTENSION_URI]: pcActn, [NEED_KEY]: pcaNeedDigest(need) },
  } as A2AMessage;
}

export type ResumeGateCode = 'task_not_auth_required' | 'no_valid_need' | 'answer_not_bound_to_need' | 'no_proof' | 'action_mismatch';

/**
 * The pure part of {@link resumeAuthRequired}, in the order the checks run: the task state, the parked need (`needEncoded` is the
 * value under `<uri>#need` in the status message), the answer's need digest, the presence of a proof and the proof's action.
 * Returns the first refusal, or null when the full verifier may now be asked. Shared with the native verifiers by vectors.
 */
export function resumeGate(o: { state: unknown; needEncoded: unknown; answerNeedDigest: unknown; proofAction: { verb?: unknown; resource?: unknown } | undefined }): ResumeGateCode | null {
  if (!isAuthRequired(o.state)) return 'task_not_auth_required';
  const need = o.needEncoded === undefined ? null : decodePcaNeed(o.needEncoded);
  if (need === null || !need.ok) return 'no_valid_need';
  if (o.answerNeedDigest !== pcaNeedDigest(need.need)) return 'answer_not_bound_to_need';
  if (o.proofAction === undefined) return 'no_proof';
  if (o.proofAction.verb !== need.need.verb || o.proofAction.resource !== need.need.resource) return 'action_mismatch';
  return null;
}

/** Does `next` (capability ids, root first) extend `prev`? Attenuation only appends hops, so the earlier chain must be a prefix. */
export const chainExtends = (prev: readonly string[], next: readonly string[]): boolean => next.length >= prev.length && prev.every((id, k) => next[k] === id);

export type ChainExtensionResult = { ok: true } | { ok: false; failedHop: number; reason: 'no_chain' | 'chain_does_not_extend_previous_hop' };

/** The chain rule of {@link verifyA2ADelegation} on its own: every hop has a chain and each extends the one before it. */
export function checkChainExtension(chains: ReadonlyArray<readonly string[]>): ChainExtensionResult {
  for (let i = 0; i < chains.length; i++) {
    const ids = chains[i] as readonly string[];
    if (!Array.isArray(ids) || ids.length === 0) return { ok: false, failedHop: i, reason: 'no_chain' };
    const prev = chains[i - 1];
    if (prev !== undefined && !chainExtends(prev, ids)) return { ok: false, failedHop: i, reason: 'chain_does_not_extend_previous_hop' };
  }
  return { ok: true };
}

export type ResumeResult = { ok: true; verification: A2AVerification } | { ok: false; reason: string };

/**
 * Resume a Task parked in AUTH_REQUIRED. Allowed only when: the Task is in AUTH_REQUIRED (an INPUT_REQUIRED Task never
 * resumes on a proof); its status carries a decodable need; the answer cites that need's digest; the answer carries a PCActn
 * for the need's exact verb and resource; and that PCActn passes the full verifier for THIS agent. The state change alone,
 * or a proof for another action, resumes nothing (A2A 7.6.4).
 */
export async function resumeAuthRequired(task: A2ATask, answer: A2AMessage, opts: PcaVerifyOptions): Promise<ResumeResult> {
  const statusMd = isObj(task?.status) && isObj(task.status.message) && isObj(task.status.message.metadata) ? task.status.message.metadata : {};
  const md = isObj(answer) && isObj(answer.metadata) ? answer.metadata : {};
  const p = extractPcaFromMessage(answer);
  const refusal = resumeGate({ state: task?.status?.state, needEncoded: statusMd[NEED_KEY], answerNeedDigest: md[NEED_KEY], proofAction: p === undefined ? undefined : p.action });
  if (refusal !== null) return { ok: false, reason: refusal };
  const v = await verifyA2ATask({ id: task.id, status: { state: 'TASK_STATE_WORKING' }, metadata: { [PCA_A2A_EXTENSION_URI]: p } }, opts);
  return v.ok ? { ok: true, verification: v } : { ok: false, reason: v.reason ?? 'proof_rejected' };
}

// ---- per-hop delegation verification -------------------------------------------------------------------

export interface HopResult {
  ok: boolean;
  /** Index of the hop that failed (absent when all passed). */
  failedHop?: number;
  reason?: string;
  /** Capability ids of each verified hop's chain, root first. */
  chains: string[][];
}

const chainIdsOf = (t: A2ATask): string[] | undefined => {
  const p = extractPca(t);
  return p && Array.isArray(p.cap_chain) ? p.cap_chain.map((c) => c.id) : undefined;
};

/**
 * Verify a chain of delegated Tasks, one per A2A hop (client agent to server agent, which as a client sends the next).
 * Every hop is verified on its own: its own PCActn, its own audience and authority (`opts` per hop), the full verifier. The
 * chain of capabilities must EXTEND the previous hop's (attenuation only appends hops, so the earlier chain is a prefix):
 * a hop that presents an unrelated chain, or drops hops, is refused. Stops at the first failure. Fail closed on empty input.
 */
export async function verifyA2ADelegation(hops: ReadonlyArray<{ task: A2ATask; opts: PcaVerifyOptions }>): Promise<HopResult> {
  const chains: string[][] = [];
  if (hops.length === 0) return { ok: false, reason: 'no_hops', chains };
  for (let i = 0; i < hops.length; i++) {
    const h = hops[i] as { task: A2ATask; opts: PcaVerifyOptions };
    const v = await verifyA2ATask(h.task, h.opts);
    if (!v.ok) return { ok: false, failedHop: i, reason: v.reason ?? 'rejected', chains };
    const ids = chainIdsOf(h.task);
    if (ids === undefined) return { ok: false, failedHop: i, reason: 'no_chain', chains };
    const prev = chains[i - 1];
    if (prev !== undefined && !chainExtends(prev, ids)) {
      return { ok: false, failedHop: i, reason: 'chain_does_not_extend_previous_hop', chains };
    }
    chains.push(ids);
  }
  return { ok: true, chains };
}

// ---- push notifications --------------------------------------------------------------------------------

/**
 * The per-task push token (A2A 3.1.7 / 4.3.1 `token`): a hash of the task id, the digest of the chain that authorized the task
 * and a secret salt only the client and agent know. A spoofed webhook cannot produce it, and a token minted for one task or
 * chain does not validate for another.
 */
export function pcaPushToken(taskId: string, chainIds: readonly string[], salt: string): string {
  if (typeof salt !== 'string' || salt.length < 16) throw new RangeError('pcaPushToken: the salt must be a secret of at least 16 characters');
  return hashCanonical({ d: 'atlas-pca/a2a-push/v1', task_id: taskId, chain: pcaChainDigest(chainIds), salt });
}

export type PushCheck = { ok: true } | { ok: false; reason: 'no_token' | 'token_mismatch' | 'task_mismatch' };

function constantTimeEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/**
 * Receiver-side check of a delivered push notification (A2A 13.2: validate authenticity, check the task id). The presented
 * token must equal the one recomputed from the task, the chain and the salt, and the payload must be about that task. A
 * notification that passes is authentic; it is still only a report: a "completed" update must not by itself start the next
 * step of a workflow that needs authority (that needs its own PCActn).
 */
export function checkPushNotification(
  expected: { taskId: string; chainIds: readonly string[]; salt: string },
  delivered: { token: string | undefined; payload: unknown },
): PushCheck {
  if (typeof delivered.token !== 'string' || delivered.token.length === 0) return { ok: false, reason: 'no_token' };
  if (!constantTimeEq(delivered.token, pcaPushToken(expected.taskId, expected.chainIds, expected.salt))) return { ok: false, reason: 'token_mismatch' };
  const p = isObj(delivered.payload) ? delivered.payload : {};
  const task = isObj(p.task) ? p.task : undefined;
  const su = isObj(p.statusUpdate) ? p.statusUpdate : undefined;
  const au = isObj(p.artifactUpdate) ? p.artifactUpdate : undefined;
  const id = task?.id ?? su?.taskId ?? au?.taskId;
  return id === expected.taskId ? { ok: true } : { ok: false, reason: 'task_mismatch' };
}

// ---- anti-enumeration ----------------------------------------------------------------------------------

/**
 * The one error A2A servers return for "no such task" and "not yours" alike (A2A 3.3.2: SHOULD NOT distinguish; 13.1: no
 * existence leak). Build it here so both paths produce identical bytes.
 */
export function uniformTaskNotFound(): { code: 'TaskNotFoundError'; message: string } {
  return { code: 'TaskNotFoundError', message: 'task not found' };
}

export type { AgentCard };
