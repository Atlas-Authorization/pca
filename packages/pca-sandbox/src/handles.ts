import { hashCanonical, isAuthorizedFor } from '@atlasauth/pca';
import type { AuthorizeResult, PcaGuardResult, PcaOperation } from '@atlasauth/pca';
import { ReceiptLog, satisfiesRuntimeClass, type RuntimeClass } from './receipts';

/** What a tool may do with a handle: run the one authorized operation. The executor gets the signed params, never the guest's. */
export type Executor = (op: Readonly<{ verb: string; resource: string; params: Readonly<Record<string, unknown>> }>) => Uint8Array | Promise<Uint8Array>;

/** Negative return codes of a handle use (the WASM ABI returns them as i32). */
export const USE_ERR = { unknown_handle: -1, spent: -2, out_too_small: -3, bad_memory: -4, executor_error: -5, no_executor: -6 } as const;
export type UseFailure = keyof typeof USE_ERR;
export type UseResult = { ok: true; result: Uint8Array } | { ok: false; reason: UseFailure };

export interface MintOptions {
  /** How many times the handle may be used. Default 1: one authorization is one action. */
  uses?: number;
  /** Epoch ms after which the handle is spent. */
  expiresAt?: number;
  /** Refuse to mint into a table below this class (a grant can demand `wasi_no_ambient`). */
  requires?: RuntimeClass;
}

interface Slot {
  op: { verb: string; resource: string; params: Record<string, unknown> };
  params_digest: string;
  op_id: string;
  uses: number;
  expiresAt: number;
  revoked: boolean;
  children: number[];
}

/**
 * A per-sandbox capability table (a CSpace): indices are small integers meaningful only inside one table, like file
 * descriptors. A slot exists only because a verified PCActn authorized exactly that operation (`isAuthorizedFor`), so the
 * authority a tool holds is the set of operations someone with the right to approve them approved. Derivation is
 * monotone: a child can only hold what the parent gave up. Revoking a slot revokes everything derived from it.
 */
export class HandleTable {
  private readonly slots: Slot[] = [];
  constructor(
    readonly runtimeClass: RuntimeClass,
    private readonly log: ReceiptLog,
    private readonly executors: Readonly<Record<string, Executor>>,
    private readonly now: () => number = Date.now,
  ) {}

  /** Mint a handle for the operation `result` allowed. Throws (fail closed) if `result` does not allow exactly `operation`. */
  mint(result: AuthorizeResult | PcaGuardResult, operation: PcaOperation, opts: MintOptions = {}): number {
    if (opts.requires !== undefined && !satisfiesRuntimeClass(this.runtimeClass, opts.requires)) throw new Error(`runtime_class_too_weak: table is ${this.runtimeClass}, grant requires ${opts.requires}`);
    if (!isAuthorizedFor(result, operation)) throw new Error('not_authorized: result does not allow exactly this operation');
    const bound = (result as { operation?: { id: string } }).operation;
    const uses = opts.uses ?? 1;
    if (!Number.isInteger(uses) || uses < 1 || uses > 1_000_000) throw new Error('bad_uses');
    const op = JSON.parse(JSON.stringify({ verb: operation.verb, resource: operation.resource, params: operation.params })) as Slot['op'];
    return this.push({ op, params_digest: hashCanonical(op.params), op_id: bound?.id ?? '', uses, expiresAt: opts.expiresAt ?? Infinity, revoked: false, children: [] });
  }

  /** Derive a narrower handle: takes `uses` from the parent (never more than it has) and an expiry no later than the parent's. */
  attenuate(index: number, narrower: { uses?: number; expiresAt?: number } = {}): number {
    const p = this.live(index);
    if (!p) throw new Error('unknown_handle');
    const uses = narrower.uses ?? p.uses;
    if (!Number.isInteger(uses) || uses < 1 || uses > p.uses) throw new Error('attenuate_widens');
    const expiresAt = narrower.expiresAt ?? p.expiresAt;
    if (!(expiresAt <= p.expiresAt)) throw new Error('attenuate_widens');
    p.uses -= uses;
    const child = this.push({ ...p, op: structuredClone(p.op), uses, expiresAt, revoked: false, children: [] });
    p.children.push(child);
    return child;
  }

  /** Revoke a handle and, transitively, every handle derived from it. */
  revoke(index: number): void {
    const s = this.slots[index - 1];
    if (!s || s.revoked) return;
    s.revoked = true;
    s.children.forEach((c) => this.revoke(c));
  }

  get size(): number {
    return this.slots.length;
  }

  /** The verb a handle carries, for a tool deciding which handle to use. */
  verbOf(index: number): string | null {
    return this.slots[index - 1]?.op.verb ?? null;
  }

  /**
   * Use a handle: run the executor on the authorized operation and record a receipt. A use is consumed before the executor
   * runs and stays consumed if it throws (a failed side effect needs a new authorization, not a retry on the old one).
   * `use` takes a synchronous executor; `useAsync` also takes one that returns a promise.
   */
  use(index: number): UseResult {
    const b = this.begin(index);
    if ('ok' in b) return b;
    try {
      const result = b.exec(deepFreeze(structuredClone(b.s.op)));
      if (!(result instanceof Uint8Array)) {
        if (result instanceof Promise) result.catch(() => undefined); // a promise on the sync path is an error; its use is already spent
        return this.finish(b.s, { ok: false, reason: 'executor_error' });
      }
      return this.finish(b.s, { ok: true, result });
    } catch {
      return this.finish(b.s, { ok: false, reason: 'executor_error' });
    }
  }

  async useAsync(index: number): Promise<UseResult> {
    const b = this.begin(index);
    if ('ok' in b) return b;
    try {
      const result = await b.exec(deepFreeze(structuredClone(b.s.op)));
      return this.finish(b.s, result instanceof Uint8Array ? { ok: true, result } : { ok: false, reason: 'executor_error' });
    } catch {
      return this.finish(b.s, { ok: false, reason: 'executor_error' });
    }
  }

  /** Checks, then spends one use. Returns the slot and executor, or the (receipted) refusal. */
  private begin(index: number): { s: Slot; exec: Executor } | UseResult {
    const s = this.slots[index - 1];
    if (!s) {
      this.log.append(this.runtimeClass, { kind: 'handle_use', subject: { op_id: '', verb: '', resource: '', params_digest: '' }, outcome: 'refused', reason: 'unknown_handle' });
      return { ok: false, reason: 'unknown_handle' };
    }
    const live = this.live(index);
    if (!live) return this.finish(s, { ok: false, reason: 'spent' });
    const exec = this.executors[s.op.verb];
    if (!exec) return this.finish(s, { ok: false, reason: 'no_executor' });
    live.uses -= 1;
    return { s, exec };
  }

  private finish(s: Slot, r: UseResult): UseResult {
    const outcome = r.ok ? 'ok' : r.reason === 'executor_error' ? 'error' : 'refused';
    this.log.append(this.runtimeClass, { kind: 'handle_use', subject: this.subject(s), outcome, reason: r.ok ? 'used' : r.reason });
    return r;
  }

  private live(index: number): Slot | null {
    const s = this.slots[index - 1];
    return s && !s.revoked && s.uses > 0 && this.now() < s.expiresAt ? s : null;
  }

  private subject(s: Slot) {
    return { op_id: s.op_id, verb: s.op.verb, resource: s.op.resource, params_digest: s.params_digest };
  }

  private push(s: Slot): number {
    this.slots.push(s);
    return this.slots.length;
  }
}

function deepFreeze<T>(v: T): T {
  if (v && typeof v === 'object') Object.values(v).forEach(deepFreeze);
  return Object.freeze(v);
}
