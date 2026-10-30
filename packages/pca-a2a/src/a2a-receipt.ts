/**
 * SIGNED TASK-UPDATE RECEIPTS for the A2A binding. A push notification or stream event says what an agent claims happened; a
 * receipt is the agent's signature over that claim, chained to the previous one, bound to the task and to the capability chain
 * that authorized it. A spoofed "completed" cannot start the next step of a workflow: {@link mayTriggerNext} is true only for a
 * verified, unbroken chain of receipts whose last state is COMPLETED and whose chain digest is the one the next step expects.
 *
 * Body (signed under domain `atlas-pca/a2a-receipt/v1` + NUL, strict canonical JSON):
 *   { v: 1, task_id, state, seq (0, 1, 2 ...), prev (digest of the previous receipt, null at seq 0), chain (pcaChainDigest of the
 *     authorizing chain), issued_at, signer }
 * The signer is a key the receiver pinned (an Agent Card key, a passport key); a key named inside the receipt is never trusted.
 */
import {
  b64u,
  canonicalBytesStrict,
  decodeB64uStrict,
  hashCanonical,
  pcaChainDigest,
  publicKeyOf,
  sign,
  utf8,
  verifyB64u,
} from '@atlasauth/pca';
import { PCA_A2A_EXTENSION_URI } from './ext-uri';

export const A2A_RECEIPT_DOMAIN = 'atlas-pca/a2a-receipt/v1\0';
const REF_DOMAIN = 'atlas-pca/a2a-receipt-ref/v1';
export const RECEIPT_KEY = `${PCA_A2A_EXTENSION_URI}#receipt`;
const TERMINAL = new Set(['TASK_STATE_COMPLETED', 'TASK_STATE_FAILED', 'TASK_STATE_CANCELED', 'TASK_STATE_REJECTED']);
const STATES = new Set([...TERMINAL, 'TASK_STATE_SUBMITTED', 'TASK_STATE_WORKING', 'TASK_STATE_INPUT_REQUIRED', 'TASK_STATE_AUTH_REQUIRED']);

export interface TaskReceipt {
  v: 1;
  task_id: string;
  state: string;
  seq: number;
  prev: string | null;
  chain: string;
  issued_at: number;
  signer: string;
  sig: string;
}

const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);
const isSafe = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
const msg = (body: unknown): Uint8Array => {
  const d = utf8(A2A_RECEIPT_DOMAIN);
  const b = canonicalBytesStrict(body);
  const o = new Uint8Array(d.length + b.length);
  o.set(d);
  o.set(b, d.length);
  return o;
};
const bodyOf = (r: Omit<TaskReceipt, 'sig'>) => ({ v: r.v, task_id: r.task_id, state: r.state, seq: r.seq, prev: r.prev, chain: r.chain, issued_at: r.issued_at, signer: r.signer });

/** The content address the next receipt cites as `prev`. */
export const receiptDigest = (r: TaskReceipt): string => hashCanonical({ d: REF_DOMAIN, r });

/** Sign a receipt. `prev` is the previous receipt of the same task (omit for the first). Throws on malformed input or a task id mismatch. */
export function signTaskReceipt(secret: Uint8Array, o: { taskId: string; state: string; chainIds: readonly string[]; issuedAt: number; prev?: TaskReceipt }): TaskReceipt {
  if (typeof o.taskId !== 'string' || o.taskId.length === 0 || o.taskId.length > 256 || !STATES.has(o.state) || !isSafe(o.issuedAt) || o.chainIds.length === 0) {
    throw new RangeError('signTaskReceipt: malformed input');
  }
  if (o.prev && (o.prev.task_id !== o.taskId || TERMINAL.has(o.prev.state))) throw new RangeError('signTaskReceipt: prev is for another task or already terminal');
  const base = {
    v: 1 as const,
    task_id: o.taskId,
    state: o.state,
    seq: o.prev ? o.prev.seq + 1 : 0,
    prev: o.prev ? receiptDigest(o.prev) : null,
    chain: pcaChainDigest(o.chainIds),
    issued_at: o.issuedAt,
    signer: b64u(publicKeyOf(secret)),
  };
  return { ...base, sig: b64u(sign(secret, msg(bodyOf(base)))) };
}

/** Well formed and signed by `signer` (the key the receiver pinned) over exactly its content. Never throws. */
export function verifyTaskReceipt(r: unknown, signer: string): r is TaskReceipt {
  try {
    if (!isObj(r) || r.v !== 1 || r.signer !== signer || typeof r.task_id !== 'string' || r.task_id.length === 0 || !STATES.has(r.state as string)) return false;
    if (!isSafe(r.seq) || !isSafe(r.issued_at) || typeof r.chain !== 'string' || decodeB64uStrict(r.chain, 32) === null) return false;
    if (!(r.prev === null || (typeof r.prev === 'string' && decodeB64uStrict(r.prev, 32) !== null)) || (r.seq === 0) !== (r.prev === null)) return false;
    if (typeof r.sig !== 'string' || decodeB64uStrict(r.sig, 64) === null) return false;
    const { sig, ...rest } = r as unknown as TaskReceipt;
    return verifyB64u(signer, msg(bodyOf(rest)), sig);
  } catch {
    return false;
  }
}

export type ReceiptChainCode = 'empty' | 'bad_receipt' | 'wrong_task' | 'wrong_chain' | 'broken_link' | 'after_terminal' | 'bad_start';
export type ReceiptChainResult = { ok: true; last: TaskReceipt; terminal: boolean } | { ok: false; code: ReceiptChainCode; at?: number };

/**
 * Check an ordered list of receipts for one task: each verifies under the pinned signer, is about this task and this chain, starts
 * at seq 0, links to the previous by digest, and nothing follows a terminal state. Returns the last receipt.
 */
export function checkReceiptChain(receipts: readonly unknown[], o: { signer: string; taskId: string; chainIds: readonly string[] }): ReceiptChainResult {
  if (!Array.isArray(receipts) || receipts.length === 0) return { ok: false, code: 'empty' };
  const chain = pcaChainDigest(o.chainIds);
  let prev: TaskReceipt | undefined;
  for (let i = 0; i < receipts.length; i++) {
    const r = receipts[i];
    if (!verifyTaskReceipt(r, o.signer)) return { ok: false, code: 'bad_receipt', at: i };
    if (r.task_id !== o.taskId) return { ok: false, code: 'wrong_task', at: i };
    if (r.chain !== chain) return { ok: false, code: 'wrong_chain', at: i };
    if (prev === undefined) {
      if (r.seq !== 0) return { ok: false, code: 'bad_start', at: i };
    } else {
      if (TERMINAL.has(prev.state)) return { ok: false, code: 'after_terminal', at: i };
      if (r.seq !== prev.seq + 1 || r.prev !== receiptDigest(prev)) return { ok: false, code: 'broken_link', at: i };
    }
    prev = r;
  }
  const last = prev as TaskReceipt;
  return { ok: true, last, terminal: TERMINAL.has(last.state) };
}

/**
 * May a workflow start its next step because of this task? Only on a verified, unbroken receipt chain for this task and chain that
 * ends in COMPLETED. A push payload, a status update or an unsigned "completed" is never enough. The next step still needs its own PCActn.
 */
export function mayTriggerNext(receipts: readonly unknown[], o: { signer: string; taskId: string; chainIds: readonly string[] }): boolean {
  const r = checkReceiptChain(receipts, o);
  return r.ok && r.last.state === 'TASK_STATE_COMPLETED';
}

/** Put a receipt on a status update or message metadata (returns a copy). */
export function attachReceipt<T extends { metadata?: Record<string, unknown> }>(carrier: T, r: TaskReceipt): T {
  return { ...carrier, metadata: { ...(carrier.metadata ?? {}), [RECEIPT_KEY]: r } };
}

/** The receipt carried by a push/stream payload (`statusUpdate.metadata`, `task.metadata`), or undefined. Unverified. */
export function receiptOfPayload(payload: unknown): unknown {
  if (!isObj(payload)) return undefined;
  for (const k of ['statusUpdate', 'task', 'message']) {
    const c = payload[k];
    const md = isObj(c) ? c.metadata : undefined;
    if (isObj(md) && md[RECEIPT_KEY] !== undefined) return md[RECEIPT_KEY];
  }
  return undefined;
}
