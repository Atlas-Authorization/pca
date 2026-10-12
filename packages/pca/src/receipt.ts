/**
 * Action receipts — a tamper-evident client-side record (spec Part 2.2/2.6, the principal's own log).
 *
 * The transparency ledger is the server's authoritative, witnessed record. A receipt log is the
 * PRINCIPAL's local, hash-chained copy of what their agents did and how each action was verified — so
 * they hold their own evidence, independently checkable, without trusting the server to replay history.
 * Each receipt commits to the previous one (a hash chain), so a dropped or altered entry is detectable.
 * Pure (hashing only).
 */

import { hashCanonical } from './hash';
import { type PCActn, type VerifyResult, pcactnDigest } from './pcactn';

export interface Receipt {
  seq: number;
  at: number;
  actionDigest: string;
  verb: string;
  resource: string;
  outcome: 'allow' | 'deny';
  /** The verifier's per-check map at the time (optional, for drill-down). */
  checks?: Record<string, string>;
  /** Hash of the previous receipt (`''` for the first). */
  prev: string;
  /** Hash of this receipt's body (everything above). */
  hash: string;
}

function receiptBody(r: Omit<Receipt, 'hash'>) {
  return {
    d: 'atlas-pca/receipt/v1',
    seq: r.seq,
    at: r.at,
    actionDigest: r.actionDigest,
    verb: r.verb,
    resource: r.resource,
    outcome: r.outcome,
    checks: r.checks ?? null,
    prev: r.prev,
  };
}

/** Build the next receipt in a chain for a verified action. */
export function receiptFor(
  prevHash: string,
  seq: number,
  p: PCActn,
  verify: Pick<VerifyResult, 'allow' | 'checks'>,
  at?: number,
): Receipt {
  const body: Omit<Receipt, 'hash'> = {
    seq,
    at: at ?? p.iat,
    actionDigest: pcactnDigest(p),
    verb: p.action.verb,
    resource: p.action.resource,
    outcome: verify.allow ? 'allow' : 'deny',
    ...(verify.checks ? { checks: verify.checks } : {}),
    prev: prevHash,
  };
  return { ...body, hash: hashCanonical(receiptBody(body)) };
}

/** Append a verified action to a receipt log, chaining to the last entry. */
export function appendReceipt(
  log: Receipt[],
  p: PCActn,
  verify: Pick<VerifyResult, 'allow' | 'checks'>,
  at?: number,
): Receipt[] {
  const last = log[log.length - 1];
  return [...log, receiptFor(last?.hash ?? '', (last?.seq ?? -1) + 1, p, verify, at)];
}

export interface ChainCheck {
  ok: boolean;
  /** The seq of the first broken link, if any. */
  brokenAt?: number;
  reason?: string;
}

/** Verify a receipt log is an intact hash chain (sequential, correctly linked, each hash matches). */
export function verifyReceiptChain(log: Receipt[]): ChainCheck {
  let prev = '';
  for (let i = 0; i < log.length; i++) {
    const r = log[i]!;
    if (r.seq !== i) return { ok: false, brokenAt: r.seq, reason: `seq ${r.seq} out of order (expected ${i})` };
    if (r.prev !== prev) return { ok: false, brokenAt: r.seq, reason: `prev link mismatch at seq ${r.seq}` };
    const { hash, ...body } = r;
    if (hashCanonical(receiptBody(body)) !== hash) return { ok: false, brokenAt: r.seq, reason: `hash mismatch at seq ${r.seq} (tampered body)` };
    prev = hash;
  }
  return { ok: true };
}

/** The head hash of a log — a single value that commits to the entire history. */
export function receiptHead(log: Receipt[]): string {
  return log[log.length - 1]?.hash ?? '';
}
