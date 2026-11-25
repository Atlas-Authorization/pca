import { hashCanonical } from '@atlasauth/pca';

/**
 * Runtime classes, weakest first. A grant (or a resource server) can require a minimum; the host states the class it
 * actually enforces. `wasi_no_ambient`: the tool is WebAssembly whose only imports are the capability handles.
 * `egress_default_deny`: a non-WASM tool whose outbound traffic can only leave through the admitting proxy.
 * `os_confined`: an OS profile (seccomp / Landlock / macOS) generated from the grant is applied.
 * The class is a claim by the host operator, recorded in every receipt; nothing here proves the OS profile was applied.
 */
export const RUNTIME_CLASSES = ['none', 'os_confined', 'egress_default_deny', 'wasi_no_ambient'] as const;
export type RuntimeClass = (typeof RUNTIME_CLASSES)[number];

/** True only when both names are known and `attested` is at least `required`. An unknown name never satisfies. */
export function satisfiesRuntimeClass(attested: string, required: string): boolean {
  const a = (RUNTIME_CLASSES as readonly string[]).indexOf(attested);
  const r = (RUNTIME_CLASSES as readonly string[]).indexOf(required);
  return a >= 0 && r >= 0 && a >= r;
}

export const GENESIS = 'genesis';

export interface ReceiptSubject {
  /** Digest of the authorizing PCActn (`AuthorizedOperation.id`). */
  op_id: string;
  verb: string;
  resource: string;
  params_digest: string;
}

export interface Receipt {
  v: 1;
  seq: number;
  /** Digest of the previous receipt, or `genesis`. */
  prev: string;
  /** Milliseconds since the epoch, from the host clock. */
  at: number;
  kind: 'handle_use' | 'egress';
  runtime_class: RuntimeClass;
  subject: ReceiptSubject;
  outcome: 'ok' | 'refused' | 'error';
  reason: string;
  /** hashCanonical of this receipt without `digest` and `sig`. */
  digest: string;
  /** Optional host signature over `digest` (the `sign` callback's output). */
  sig?: string;
}

export type ReceiptBody = Omit<Receipt, 'v' | 'seq' | 'prev' | 'at' | 'digest' | 'sig' | 'runtime_class'>;

/** Append-only hash chain of use receipts: every handle use and every egress decision, refusals included. */
export class ReceiptLog {
  readonly entries: Receipt[] = [];
  constructor(private readonly opts: { now?: () => number; sign?: (digest: string) => string } = {}) {}

  append(runtime_class: RuntimeClass, body: ReceiptBody): Receipt {
    const unsigned = {
      v: 1 as const,
      seq: this.entries.length,
      prev: this.entries.at(-1)?.digest ?? GENESIS,
      at: (this.opts.now ?? Date.now)(),
      runtime_class,
      ...body,
    };
    const digest = hashCanonical(unsigned);
    const r: Receipt = { ...unsigned, digest, ...(this.opts.sign ? { sig: this.opts.sign(digest) } : {}) };
    this.entries.push(r);
    return r;
  }
}

/** Recompute the chain. Fails on a bad digest, a broken link, a gap, a reorder, or (with `verifySig`) a bad signature. */
export function verifyReceiptChain(receipts: readonly Receipt[], verifySig?: (digest: string, sig: string) => boolean): { ok: true } | { ok: false; at: number; reason: string } {
  let prev = GENESIS;
  for (const [i, r] of receipts.entries()) {
    if (r.v !== 1 || r.seq !== i) return { ok: false, at: i, reason: 'bad_seq' };
    if (r.prev !== prev) return { ok: false, at: i, reason: 'broken_link' };
    const { digest, sig, ...rest } = r;
    if (hashCanonical(rest) !== digest) return { ok: false, at: i, reason: 'bad_digest' };
    if (verifySig && (typeof sig !== 'string' || !verifySig(digest, sig))) return { ok: false, at: i, reason: 'bad_sig' };
    prev = digest;
  }
  return { ok: true };
}
