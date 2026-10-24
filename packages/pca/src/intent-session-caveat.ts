import { decodeB64uStrict } from './hash';
import type { Caveat } from './capability';

/**
 * The root-level grant caveat that binds G_0 and every delta grant D_k to an Intent Layer v2 session (rule 13):
 *   {type: "intent_session", session, seq, root, prev?}      prev present exactly when seq > 0.
 * It imposes NO per-action constraint: the policy layer's caveat evaluator treats a WELL-FORMED one as satisfied
 * (like `budget_alloc`), and the `intent_session` check (intent-v2.ts) enforces the binding. A malformed one is
 * unsatisfied (fail closed). Kept dependency-free so the predicate evaluator can import it.
 */
export const INTENT_SESSION_CAVEAT = 'intent_session';
/** Largest delta sequence number (2^31 - 1). */
export const MAX_SESSION_SEQ = 2_147_483_647;

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const isNonNeg = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0);
const b32 = (v: unknown): boolean => decodeB64uStrict(v, 32) !== null;

export interface IntentSessionCaveat extends Caveat {
  type: typeof INTENT_SESSION_CAVEAT;
  session: string;
  seq: number;
  root: string;
  prev?: string;
}

/** Shape of an `intent_session` grant caveat: exactly {type, session, seq, root, prev?}, prev present iff seq > 0. */
export function intentSessionCaveatError(c: unknown): string | null {
  if (!isObj(c) || c.type !== INTENT_SESSION_CAVEAT) return 'not an intent_session caveat';
  for (const k of Object.keys(c)) if (!['type', 'session', 'seq', 'root', 'prev'].includes(k)) return `intent_session caveat: unknown member '${k}'`;
  if (!b32(c.session) || !b32(c.root)) return 'intent_session caveat: session and root must be canonical base64url (32 bytes)';
  if (!isNonNeg(c.seq) || c.seq > MAX_SESSION_SEQ) return 'intent_session caveat: seq must be a safe integer in [0, 2147483647]';
  if ((c.seq === 0) !== (c.prev === undefined)) return 'intent_session caveat: prev is present exactly when seq > 0';
  if (c.prev !== undefined && !b32(c.prev)) return 'intent_session caveat: prev must be canonical base64url (32 bytes)';
  return null;
}

