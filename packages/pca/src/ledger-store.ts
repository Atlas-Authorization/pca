/**
 * Durable transparency ledger: the `LedgerStore` contract, a reference store, and `StoredLedger`.
 *
 * WHAT IS CLAIMED. TAMPER EVIDENCE, given at least one honest independent witness. The ledger is an append-only Merkle
 * log with guardian-signed checkpoints. A party holding a checkpoint (or a witness that cosigned one) can later demand a
 * consistency proof and catch a log that was rewritten, truncated or forked. Without an independent witness the operator can
 * still show different logs to different readers, and an operator can refuse to log something at all (censorship is not
 * detectable). Witness operation is the operator's job: run the reference witness service, or recruit independent ones.
 *
 * WHAT THE STORE GUARANTEES. `append` and `appendCheckpoint` are compare-and-swap on the current length: they succeed only
 * at the exact position the caller saw, all entries of a batch or none, so two writers can never assign one index twice and
 * a log never has holes. Committing the same batch again at the same position is a replay (idempotent, nothing written).
 * Acknowledged writes survive a crash or restart; a write in flight at the crash is applied entirely or not at all.
 *
 * WHAT `StoredLedger` ADDS. On `open` it rebuilds the Merkle tree from the stored commits and checks it against EVERY stored
 * checkpoint: the guardian signature, the signed `prev_root` chain, the RFC 9162 consistency proof at each boundary, and that
 * the commits reproduce each checkpoint root. A store that lost entries after a checkpoint (rollback), edited an entry
 * (tamper) or holds a forged checkpoint FAILS CLOSED with a typed error instead of serving a log that looks fine.
 * `checkpoint` refuses to sign a head that is not consistent with the previous one.
 */
import { b64u, hashCanonicalLenient } from './hash';
import { publicKeyOf } from './keys';
import { type PqPinPolicy, resolveSigAlg } from './pq';
import type { DurableKv } from './durable-state';
import {
  type Checkpoint,
  type ConsistencyProof,
  type LedgerSuiteOpts,
  type SignedTreeHead,
  TransparencyLedger,
  signTreeHead,
  verifyCheckpointChain,
} from './ledger';
import type { InclusionProof } from './merkle';

export type LedgerStoreErrorCode = 'store_missing' | 'guardian_key_missing' | 'pin_missing' | 'clock_invalid' | 'store_unavailable' | 'store_corrupt' | 'rollback' | 'tamper' | 'forged_checkpoint' | 'inconsistent' | 'conflict' | 'invalid_commit';

/** The typed failure of every store-backed ledger operation. */
export class LedgerStoreError extends Error {
  constructor(
    readonly code: LedgerStoreErrorCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(`${code}: ${message}`, options);
    this.name = 'LedgerStoreError';
  }
}

export type LedgerAppendOutcome =
  | { outcome: 'appended'; size: number }
  /** The very same batch was already stored at that position (a retry or a lost acknowledgement). Nothing was written. */
  | { outcome: 'replayed'; size: number }
  /** The log is not at `expectedSize` (or holds other entries there). `size` is its current length. Nothing was written. */
  | { outcome: 'conflict'; size: number };

export type LedgerCheckpointOutcome =
  | { outcome: 'appended'; count: number }
  | { outcome: 'replayed'; count: number }
  | { outcome: 'conflict'; count: number; reason: string };

/**
 * The persistence contract of a transparency log. Implement it over a database (an append-only table with a unique index on
 * the position gives `append` for free) or use {@link KvLedgerStore}. Run `runLedgerStoreConformance`
 * (`@atlasauth/pca-store-conformance`) against it.
 */
export interface LedgerStore {
  /** Current number of entries. */
  size(): Promise<number>;
  /** Commits `[from, to)`. Throws `RangeError` when the range is not inside the log. */
  read(from: number, to: number): Promise<string[]>;
  /**
   * Atomically append `commits` iff the log has exactly `expectedSize` entries (all or none). A batch that is already
   * stored at `expectedSize` is a `replayed`. Every commit must be a non-empty string (throws `RangeError` otherwise).
   */
  append(expectedSize: number, commits: readonly string[]): Promise<LedgerAppendOutcome>;
  /** Number of checkpoints. */
  checkpointCount(): Promise<number>;
  /** Checkpoints `[from, count)` in order. */
  checkpoints(from?: number): Promise<Checkpoint[]>;
  /**
   * Atomically append a checkpoint iff exactly `expectedCount` exist. A store also enforces what needs no cryptography:
   * the checkpoint's `size` is within the log, and not below the previous checkpoint's (equal only with the same root).
   * The same checkpoint at the same position is a `replayed`.
   */
  appendCheckpoint(expectedCount: number, cp: Checkpoint): Promise<LedgerCheckpointOutcome>;
}

// ---- the pure transition functions (every reference store is these plus a lock) ---------------------------------------

export interface LedgerDoc {
  v: 1;
  commits: string[];
  checkpoints: Checkpoint[];
}
export const emptyLedgerDoc = (): LedgerDoc => ({ v: 1, commits: [], checkpoints: [] });

const isCommit = (c: unknown): c is string => typeof c === 'string' && c.length > 0;

export function appendToLedgerDoc(doc: LedgerDoc, expectedSize: number, commits: readonly string[]): LedgerAppendOutcome {
  if (!Number.isSafeInteger(expectedSize) || expectedSize < 0) throw new RangeError('append: expectedSize must be a non-negative safe integer');
  if (!Array.isArray(commits) || commits.length === 0 || !commits.every(isCommit)) throw new RangeError('append: commits must be a non-empty array of non-empty strings');
  const size = doc.commits.length;
  if (expectedSize < size) {
    const same = commits.every((c, i) => doc.commits[expectedSize + i] === c);
    return same ? { outcome: 'replayed', size } : { outcome: 'conflict', size };
  }
  if (expectedSize > size) return { outcome: 'conflict', size };
  doc.commits.push(...commits);
  return { outcome: 'appended', size: doc.commits.length };
}

export function checkpointToLedgerDoc(doc: LedgerDoc, expectedCount: number, cp: Checkpoint): LedgerCheckpointOutcome {
  if (!Number.isSafeInteger(expectedCount) || expectedCount < 0) throw new RangeError('appendCheckpoint: expectedCount must be a non-negative safe integer');
  const count = doc.checkpoints.length;
  const same = (a: Checkpoint, b: Checkpoint): boolean => hashCanonicalLenient(a) === hashCanonicalLenient(b);
  if (expectedCount < count) return same(doc.checkpoints[expectedCount]!, cp) ? { outcome: 'replayed', count } : { outcome: 'conflict', count, reason: 'another checkpoint holds that position' };
  if (expectedCount > count) return { outcome: 'conflict', count, reason: 'the checkpoint position is ahead of the log' };
  const sth = cp?.sth;
  if (!sth || !Number.isSafeInteger(sth.size) || sth.size < 0 || typeof sth.root !== 'string') return { outcome: 'conflict', count, reason: 'malformed checkpoint' };
  if (sth.size > doc.commits.length) return { outcome: 'conflict', count, reason: 'the checkpoint is beyond the end of the log' };
  const last = doc.checkpoints[count - 1]?.sth;
  if (last && (sth.size < last.size || (sth.size === last.size && sth.root !== last.root))) return { outcome: 'conflict', count, reason: 'the checkpoint does not extend the previous one' };
  doc.checkpoints.push(structuredClone(cp));
  return { outcome: 'appended', count: doc.checkpoints.length };
}

// ---- the reference store ------------------------------------------------------------------------------------------------

const DOC_KEY = 'pca-ledger-store/v1';
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

function decodeLedgerDoc(raw: unknown): LedgerDoc {
  if (raw === undefined) return emptyLedgerDoc();
  if (!isObj(raw) || raw.v !== 1 || !Array.isArray(raw.commits) || !Array.isArray(raw.checkpoints) || !raw.commits.every(isCommit)) throw new LedgerStoreError('store_corrupt', 'ledger document has the wrong shape');
  if (!raw.checkpoints.every((c) => isObj(c) && isObj(c.sth))) throw new LedgerStoreError('store_corrupt', 'malformed checkpoint entry');
  return raw as unknown as LedgerDoc;
}

/**
 * The reference {@link LedgerStore}: the whole log is one document in any {@link DurableKv}, so every write is one atomic
 * read-modify-write. Over `openDurableState({ dir })` it is crash-safe, hash-chained and multi-process safe on one host.
 *
 * LIMIT: the document is rewritten on every write and bounded by the kv's `maxValueBytes` (1 MiB by default: roughly 20 000
 * commits). Past that the kv refuses the write and the operation fails closed. It is a reference for the contract; a
 * production log lives in a database with a unique index on the position.
 */
export class KvLedgerStore implements LedgerStore {
  constructor(
    private readonly kv: DurableKv,
    private readonly key: string = DOC_KEY,
  ) {
    if (!kv || typeof kv.get !== 'function' || typeof kv.update !== 'function') throw new LedgerStoreError('store_missing', 'KvLedgerStore needs a DurableKv');
  }

  private async doc(): Promise<LedgerDoc> {
    return decodeLedgerDoc(await this.kv.get(this.key));
  }
  async size(): Promise<number> {
    return (await this.doc()).commits.length;
  }
  async read(from: number, to: number): Promise<string[]> {
    const d = await this.doc();
    if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || from > to || to > d.commits.length) throw new RangeError('read: range is not inside the log');
    return d.commits.slice(from, to);
  }
  async append(expectedSize: number, commits: readonly string[]): Promise<LedgerAppendOutcome> {
    let out: LedgerAppendOutcome | undefined;
    await this.kv.update(this.key, (prev) => {
      const d = decodeLedgerDoc(prev);
      out = appendToLedgerDoc(d, expectedSize, commits);
      return out.outcome === 'appended' ? d : undefined;
    });
    return out as LedgerAppendOutcome;
  }
  async checkpointCount(): Promise<number> {
    return (await this.doc()).checkpoints.length;
  }
  async checkpoints(from = 0): Promise<Checkpoint[]> {
    const d = await this.doc();
    if (!Number.isSafeInteger(from) || from < 0 || from > d.checkpoints.length) throw new RangeError('checkpoints: from is not inside the list');
    return structuredClone(d.checkpoints.slice(from));
  }
  async appendCheckpoint(expectedCount: number, cp: Checkpoint): Promise<LedgerCheckpointOutcome> {
    let out: LedgerCheckpointOutcome | undefined;
    await this.kv.update(this.key, (prev) => {
      const d = decodeLedgerDoc(prev);
      out = checkpointToLedgerDoc(d, expectedCount, cp);
      return out.outcome === 'appended' ? d : undefined;
    });
    return out as LedgerCheckpointOutcome;
  }
}

// ---- the ledger ----------------------------------------------------------------------------------------------------------

export interface StoredLedgerOpts {
  /** REQUIRED: there is no in-memory default. */
  store: LedgerStore;
  /** REQUIRED: the guardian key that signs checkpoints; its public half is the pin every stored checkpoint must verify under. */
  guardianSecret: Uint8Array;
  /** The log's instance and principal (the grant_ref), signed into every checkpoint. */
  instanceId: string;
  principal: string;
  /** Epoch-ms clock for checkpoint timestamps (default `Date.now`). */
  clock?: () => number;
  /** Signature suite for checkpoints (default ed25519). A post-quantum or hybrid suite needs `pin`. */
  suite?: LedgerSuiteOpts;
  /** PQ pins for the guardian identity (`{ pqPins: { [ed25519 b64u]: pq_pk } }`): required with a non-ed25519 `suite`, used to verify every stored checkpoint. */
  pin?: PqPinPolicy;
}

const unavailable = (e: unknown): LedgerStoreError => (e instanceof LedgerStoreError ? e : new LedgerStoreError('store_unavailable', e instanceof Error ? e.message : 'store failed', { cause: e }));

/**
 * A transparency log over a {@link LedgerStore}. Open it with {@link StoredLedger.open}; the constructor is private so that no
 * instance exists whose state was not verified against the stored checkpoints.
 */
export class StoredLedger {
  /** Operations of one handle run one at a time: the in-memory tree must follow the store in order. */
  private queue: Promise<unknown> = Promise.resolve();
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private constructor(
    private readonly opts: StoredLedgerOpts,
    private readonly guardianPublic: string,
    private log: TransparencyLedger,
    private cps: Checkpoint[],
  ) {}

  /**
   * Load the log and verify it against every stored checkpoint (see the module comment). Throws `store_missing`,
   * `guardian_key_missing`, `rollback` (fewer entries than the last checkpoint), `tamper` (the commits do not reproduce a
   * checkpoint root), `forged_checkpoint` (a checkpoint's signature, hash chain or witness link fails) or `inconsistent`
   * (the RFC 9162 proof between two checkpoints fails), `pin_missing` (a post-quantum suite without a PQ pin), `store_corrupt` or
   * `store_unavailable`.
   */
  static async open(opts: StoredLedgerOpts): Promise<StoredLedger> {
    if (!opts || !opts.store || typeof opts.store.append !== 'function' || typeof opts.store.read !== 'function' || typeof opts.store.appendCheckpoint !== 'function') {
      throw new LedgerStoreError('store_missing', 'a LedgerStore is required (there is no in-memory default)');
    }
    if (!(opts.guardianSecret instanceof Uint8Array) || opts.guardianSecret.length === 0) throw new LedgerStoreError('guardian_key_missing', 'a guardian secret key is required');
    const guardianPublic = b64u(publicKeyOf(opts.guardianSecret));
    const alg = opts.suite?.alg;
    if (alg !== undefined && (resolveSigAlg(alg) === null || (alg !== 'ed25519' && !opts.pin))) {
      throw new LedgerStoreError('pin_missing', 'a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)');
    }
    try {
      const size = await opts.store.size();
      const commits = await opts.store.read(0, size);
      const cps = await opts.store.checkpoints(0);
      const log = TransparencyLedger.fromEntries(commits.map((commit) => ({ commit })), opts.principal);
      const self = new StoredLedger(opts, guardianPublic, log, cps);
      self.verifyAgainstCheckpoints();
      return self;
    } catch (e) {
      throw unavailable(e);
    }
  }

  /** The checkpoint chain, the log and the stored commits must tell one story. */
  private verifyAgainstCheckpoints(): void {
    const attested = Math.max(0, ...this.cps.map((c) => (Number.isSafeInteger(c.sth.size) ? c.sth.size : 0)));
    if (this.log.size < attested) throw new LedgerStoreError('rollback', `the log has ${this.log.size} entries but a checkpoint attests ${attested}`);
    this.cps.forEach((cp, i) => {
      if (cp.sth.instance_id !== this.opts.instanceId || cp.sth.principal !== this.opts.principal) throw new LedgerStoreError('forged_checkpoint', `checkpoint ${i} belongs to another log`);
      if (this.log.rootAt(cp.sth.size) !== cp.sth.root) throw new LedgerStoreError('tamper', `the stored entries do not reproduce the root of checkpoint ${i} (size ${cp.sth.size})`);
    });
    if (this.cps.length === 0) return;
    const v = verifyCheckpointChain(this.cps, this.guardianPublic, undefined, this.opts.pin);
    if (!v.ok) throw new LedgerStoreError(v.reason === 'inconsistent' ? 'inconsistent' : 'forged_checkpoint', `checkpoint ${v.at}: ${v.reason}`);
  }

  get size(): number {
    return this.log.size;
  }
  /** The guardian public key (b64u) every checkpoint verifies under. */
  get guardian(): string {
    return this.guardianPublic;
  }
  /** The latest signed checkpoint, if any. */
  latestCheckpoint(): SignedTreeHead | undefined {
    return this.cps[this.cps.length - 1]?.sth;
  }
  checkpointChain(): Checkpoint[] {
    return structuredClone(this.cps);
  }
  head(): { size: number; root: string } {
    return this.log.head();
  }
  inclusionProof(index: number): InclusionProof {
    return this.log.inclusionProof(index);
  }
  /** RFC 9162 proof from a size the caller already pinned (a checkpoint, or a witness's) to the current log. */
  consistencyProofFrom(oldSize: number): ConsistencyProof {
    return this.log.consistencyProof(oldSize, this.log.size);
  }
  commits(): string[] {
    return this.log.commits();
  }

  /**
   * Append an opaque commitment leaf (the `TransparencyLedger.appendCommitment` model: the opening lives off-log). Idempotent
   * under retry at the position the caller read: if another writer took that position, the ledger reloads and appends at the
   * new tail (a distinct entry), so use a unique, salted commit per event. Returns the entry's index.
   */
  append(commit: string): Promise<{ index: number; commit: string }> {
    if (!isCommit(commit)) return Promise.reject(new LedgerStoreError('invalid_commit', 'a commit must be a non-empty string'));
    return this.serial(() => this.appendLocked(commit));
  }

  private async appendLocked(commit: string): Promise<{ index: number; commit: string }> {
    for (let attempt = 0; attempt < 16; attempt++) {
      const index = this.log.size;
      let out: LedgerAppendOutcome;
      try {
        out = await this.opts.store.append(index, [commit]);
      } catch (e) {
        throw unavailable(e);
      }
      if (out.outcome === 'appended' || out.outcome === 'replayed') {
        this.log.appendCommitment(commit);
        return { index, commit };
      }
      await this.catchUpLocked(); // another writer advanced the log: pick up its entries, then try the new tail
    }
    throw new LedgerStoreError('conflict', 'the log kept moving; could not append');
  }

  /** Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints). */
  catchUp(): Promise<void> {
    return this.serial(() => this.catchUpLocked());
  }

  private async catchUpLocked(): Promise<void> {
    try {
      const size = await this.opts.store.size();
      if (size < this.log.size) throw new LedgerStoreError('rollback', `the store shrank from ${this.log.size} to ${size} entries`);
      for (const c of await this.opts.store.read(this.log.size, size)) this.log.appendCommitment(c);
      this.cps.push(...(await this.opts.store.checkpoints(this.cps.length)));
      this.verifyAgainstCheckpoints();
    } catch (e) {
      throw unavailable(e);
    }
  }

  /** A checkpoint signs what THIS handle holds, so first prove the store still holds exactly that (another writer may have rewritten it). */
  private async assertStoreMatchesMemory(): Promise<void> {
    let stored: string[];
    try {
      stored = await this.opts.store.read(0, this.log.size);
    } catch (e) {
      throw unavailable(e);
    }
    const mine = this.log.commits();
    if (stored.length !== mine.length || stored.some((c, i) => c !== mine[i])) throw new LedgerStoreError('tamper', 'the stored entries no longer match this handle; refusing to sign a checkpoint over them');
  }

  /**
   * Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent
   * with the previous checkpoint (signed `prev_root` link and RFC 9162 proof), so a log that was rewritten under this handle
   * is refused (`inconsistent`) instead of being blessed. An unchanged head returns the existing checkpoint.
   */
  checkpoint(): Promise<SignedTreeHead> {
    return this.serial(() => this.checkpointLocked());
  }

  private async checkpointLocked(): Promise<SignedTreeHead> {
    await this.catchUpLocked();
    await this.assertStoreMatchesMemory();
    const prev = this.cps[this.cps.length - 1];
    const { size, root } = this.log.head();
    if (prev && prev.sth.size === size) return prev.sth;
    const t = (this.opts.clock ?? Date.now)();
    if (!Number.isFinite(t)) throw new LedgerStoreError('clock_invalid', 'the clock returned a non-finite time');
    const sth = signTreeHead(this.opts.guardianSecret, { instance_id: this.opts.instanceId, principal: this.opts.principal, size, root, prev_root: prev?.sth.root ?? '', timestamp: t }, this.opts.suite);
    const cp: Checkpoint = prev ? { sth, proof: this.log.consistencyProof(prev.sth.size, size) } : { sth };
    const v = verifyCheckpointChain([...this.cps, cp], this.guardianPublic, undefined, this.opts.pin);
    if (!v.ok) {
      if (v.reason === 'head') throw new LedgerStoreError('forged_checkpoint', 'the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)');
      throw new LedgerStoreError('inconsistent', `the new head is not consistent with checkpoint ${v.at - 1}`);
    }
    let out: LedgerCheckpointOutcome;
    try {
      out = await this.opts.store.appendCheckpoint(this.cps.length, cp);
    } catch (e) {
      throw unavailable(e);
    }
    if (out.outcome === 'conflict') throw new LedgerStoreError('conflict', out.reason);
    this.cps.push(cp);
    return sth;
  }
}
