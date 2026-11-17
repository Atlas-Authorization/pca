/**
 * The audit log: hash-chained receipts (`receiptFor` / `verifyReceiptChain` of `@atlasauth/pca`), one per decision, written
 * BEFORE the call is forwarded. Each receipt commits to the proof of the action (or to an audit proof for a call that never
 * reached one), the verb, the resource, the outcome and the reason, and to the receipt before it, so a dropped or edited line
 * breaks the chain. A log that cannot be written refuses the call (fail closed): an action nobody can account for does not run.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { receiptFor, verifyReceiptChain, type PCActn, type Receipt } from '@atlasauth/pca';
import { redactSecrets } from '@atlasauth/pca-otel';

const clip = (v: string): string => redactSecrets(v).slice(0, 200);

/** Read a receipt file (one JSON receipt per line). Throws on a line that is not a receipt. */
export function readReceipts(path: string): Receipt[] {
  const out: Receipt[] = [];
  const text = readFileSync(path, 'utf8');
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue;
    out.push(JSON.parse(line) as Receipt);
  }
  return out;
}

/** Verify a receipt file: an intact chain, and how many receipts it holds. */
export function verifyAuditFile(path: string): { ok: boolean; count: number; head: string; reason?: string; brokenAt?: number } {
  const log = readReceipts(path);
  const c = verifyReceiptChain(log);
  return { ok: c.ok, count: log.length, head: log[log.length - 1]?.hash ?? '', ...(c.reason !== undefined ? { reason: c.reason } : {}), ...(c.brokenAt !== undefined ? { brokenAt: c.brokenAt } : {}) };
}

export class AuditLog {
  private prev = '';
  private seq = 0;
  /** In-memory tail for tests and the status endpoint; the file is the record. */
  readonly tail: Receipt[] = [];

  constructor(private readonly path?: string) {
    if (path !== undefined) {
      if (existsSync(path)) {
        const log = readReceipts(path);
        const c = verifyReceiptChain(log);
        if (!c.ok) throw new Error(`audit log ${path} is not an intact chain (${c.reason ?? 'broken'}); refusing to append to it`);
        const last = log[log.length - 1];
        if (last !== undefined) {
          this.prev = last.hash;
          this.seq = last.seq + 1;
        }
      } else mkdirSync(dirname(path), { recursive: true });
    }
  }

  /** The seq the next receipt will have. */
  get nextSeq(): number {
    return this.seq;
  }

  get head(): string {
    return this.prev;
  }

  /** Append one receipt. Throws when it cannot be written; the caller then refuses the call. */
  append(p: PCActn, allow: boolean, facts: Record<string, string>, at: number): Receipt {
    const checks: Record<string, string> = {};
    for (const [k, v] of Object.entries(facts)) checks[k.slice(0, 32)] = clip(v);
    const r = receiptFor(this.prev, this.seq, p, { allow, checks } as never, at);
    if (this.path !== undefined) appendFileSync(this.path, `${JSON.stringify(r)}\n`, { mode: 0o600 });
    this.prev = r.hash;
    this.seq += 1;
    this.tail.push(r);
    if (this.tail.length > 256) this.tail.shift();
    return r;
  }
}
