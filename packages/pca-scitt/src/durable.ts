/**
 * A durable SCITT Transparency Service. The log keeps the hash of every complete aligned subtree in a store, so an append
 * is O(log n) store reads and writes (no recomputation of the tree), the root is O(log n), and an inclusion or
 * consistency proof is O(log^2 n) reads. State lives entirely in the {@link ScittLogStore} you supply (a database, an
 * object store, a file): a restart loses nothing and the service holds no log state of its own. There is no in-memory
 * default; `MemoryScittLogStore` (the `/testing` entry) is for tests.
 */
import type { KeyObject } from 'node:crypto';
import { type InclusionProof, type ProofStep, b64u } from '@atlasauth/pca';
import {
  type ConsistencyProofResult,
  type CoseAlg,
  type ReceiptSignerOpts,
  type SignStatementOpts,
  buildReceipt,
  decodeCoseSign1,
  encode,
  signStatement,
  siblingSides,
} from './core';
import { emptyRoot, leafHash, nodeHash } from './rfc9162';

/** The hash of the complete subtree at `level` covering leaves [index * 2^level, (index + 1) * 2^level). */
export interface StoredNode {
  level: number;
  index: number;
  hash: Uint8Array;
}

/**
 * Durable, append-only storage for a transparency log. `append` is atomic: it succeeds only when the log still has
 * exactly `expectedSize` entries (a compare-and-set, so two writers cannot both take the same index) and stores the entry
 * and the new subtree hashes together, or none of them. Entries and nodes are immutable once written.
 */
export interface ScittLogStore {
  size(): Promise<number>;
  getEntry(index: number): Promise<Uint8Array | undefined>;
  getNode(level: number, index: number): Promise<Uint8Array | undefined>;
  append(expectedSize: number, entry: Uint8Array, nodes: readonly StoredNode[]): Promise<boolean>;
}

export class ScittLogError extends Error {
  constructor(
    readonly code: 'store_required' | 'store_corrupt' | 'append_contention' | 'out_of_range' | 'bad_statement',
    message: string,
  ) {
    super(message);
    this.name = 'ScittLogError';
  }
}

const MAX_APPEND_ATTEMPTS = 16;

const largestPow2Below = (n: number): number => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};
const isPow2 = (n: number): boolean => n > 0 && (n & (n - 1)) === 0 && Number.isSafeInteger(n);
const log2 = (n: number): number => Math.round(Math.log2(n));

/** Read-side algorithms over a store (hashes of arbitrary ranges, root, proofs). */
class LogReader {
  constructor(private readonly store: ScittLogStore) {}

  private async node(level: number, index: number): Promise<Uint8Array> {
    const h = await this.store.getNode(level, index);
    if (h === undefined || h.length !== 32) throw new ScittLogError('store_corrupt', `missing or malformed subtree hash (${level}, ${index})`);
    return h;
  }

  /** MTH over leaves [lo, lo + n): lo must be a multiple of the split points, which every caller guarantees. */
  async range(lo: number, n: number): Promise<Uint8Array> {
    if (n === 1) return this.node(0, lo);
    if (isPow2(n) && lo % n === 0) return this.node(log2(n), lo / n);
    const k = largestPow2Below(n);
    return nodeHash(await this.range(lo, k), await this.range(lo + k, n - k));
  }

  async root(size: number): Promise<Uint8Array> {
    return size === 0 ? emptyRoot() : this.range(0, size);
  }

  async inclusion(index: number, size: number): Promise<Uint8Array[]> {
    const walk = async (lo: number, n: number, idx: number): Promise<Uint8Array[]> => {
      if (n === 1) return [];
      const k = largestPow2Below(n);
      if (idx < k) return [...(await walk(lo, k, idx)), await this.range(lo + k, n - k)];
      return [...(await walk(lo + k, n - k, idx - k)), await this.range(lo, k)];
    };
    return walk(0, size, index);
  }

  async consistency(m: number, size: number): Promise<Uint8Array[]> {
    const sub = async (lo: number, n: number, mm: number, complete: boolean): Promise<Uint8Array[]> => {
      if (mm === n) return complete ? [] : [await this.range(lo, n)];
      const k = largestPow2Below(n);
      if (mm <= k) return [...(await sub(lo, k, mm, complete)), await this.range(lo + k, n - k)];
      return [...(await sub(lo + k, n - k, mm - k, false)), await this.range(lo, k)];
    };
    return sub(0, size, m, true);
  }
}

export interface DurableTransparencyServiceOpts {
  /** Where the log lives. Required: there is no in-memory default. */
  store: ScittLogStore;
  alg: CoseAlg;
  /** The Transparency Service PRIVATE signing key. */
  key: KeyObject;
  issuer?: string;
}

export interface DurableRegistration {
  index: number;
  receipt: Uint8Array;
  root: string;
}

export class DurableTransparencyService {
  private readonly store: ScittLogStore;
  private readonly reader: LogReader;
  private readonly signer: ReceiptSignerOpts;

  constructor(opts: DurableTransparencyServiceOpts) {
    const s = opts?.store;
    if (!s || typeof s.size !== 'function' || typeof s.getEntry !== 'function' || typeof s.getNode !== 'function' || typeof s.append !== 'function') {
      throw new ScittLogError('store_required', 'a ScittLogStore (size, getEntry, getNode, append) is required; there is no in-memory default');
    }
    this.store = s;
    this.reader = new LogReader(s);
    this.signer = { alg: opts.alg, key: opts.key, ...(opts.issuer !== undefined ? { issuer: opts.issuer } : {}) };
  }

  async size(): Promise<number> {
    const n = await this.store.size();
    if (!Number.isSafeInteger(n) || n < 0) throw new ScittLogError('store_corrupt', 'the store reported an invalid size');
    return n;
  }

  /** The current tree root (b64u). */
  async root(): Promise<string> {
    return b64u(await this.reader.root(await this.size()));
  }

  private async receiptFor(index: number, size: number): Promise<DurableRegistration> {
    const root = await this.reader.root(size);
    const sides = siblingSides(index, size);
    const path = (await this.reader.inclusion(index, size)).map((h, i): ProofStep => ({ side: sides[i]!, hash: b64u(h) }));
    const proof: InclusionProof = { index, size, path };
    return { index, receipt: buildReceipt(b64u(root), proof, this.signer), root: b64u(root) };
  }

  /** Append a Signed Statement (validated structurally first) and return its receipt against the new root. */
  async register(statement: Uint8Array): Promise<DurableRegistration> {
    try {
      const cose = decodeCoseSign1(statement);
      if (cose.payload === null) throw new TypeError('detached payload');
    } catch (e) {
      throw new ScittLogError('bad_statement', `cannot register: ${(e as Error).message}`);
    }
    for (let attempt = 0; attempt < MAX_APPEND_ATTEMPTS; attempt++) {
      const n = await this.size();
      const nodes: StoredNode[] = [{ level: 0, index: n, hash: leafHash(statement) }];
      // Completing a subtree at level l: the new leaf is its last leaf, so its left sibling is already stored.
      let hash = nodes[0]!.hash;
      for (let level = 1; (n + 1) % 2 ** level === 0; level++) {
        const idx = (n + 1) / 2 ** level - 1;
        const left = await this.store.getNode(level - 1, 2 * idx);
        if (left === undefined || left.length !== 32) throw new ScittLogError('store_corrupt', `missing subtree hash (${level - 1}, ${2 * idx})`);
        hash = nodeHash(left, hash);
        nodes.push({ level, index: idx, hash });
      }
      if (await this.store.append(n, statement, nodes)) return this.receiptFor(n, n + 1);
    }
    throw new ScittLogError('append_contention', 'could not append: the log kept changing');
  }

  async appendAndReceipt(payload: unknown, stmt: SignStatementOpts): Promise<DurableRegistration & { statement: Uint8Array }> {
    const statement = signStatement(payload, stmt);
    return { statement, ...(await this.register(statement)) };
  }

  /** A receipt for an entry, against the CURRENT root. */
  async getReceipt(index: number): Promise<DurableRegistration> {
    const size = await this.size();
    if (!Number.isInteger(index) || index < 0 || index >= size) throw new ScittLogError('out_of_range', 'getReceipt: index out of range');
    return this.receiptFor(index, size);
  }

  async getEntry(index: number): Promise<Uint8Array> {
    const size = await this.size();
    if (!Number.isInteger(index) || index < 0 || index >= size) throw new ScittLogError('out_of_range', 'getEntry: index out of range');
    const e = await this.store.getEntry(index);
    if (e === undefined) throw new ScittLogError('store_corrupt', `entry ${index} is missing`);
    return e;
  }

  /** An RFC 9162 consistency proof that the first `oldSize` entries are a prefix of the current log. */
  async consistencyProof(oldSize: number): Promise<ConsistencyProofResult> {
    const size = await this.size();
    if (!Number.isInteger(oldSize) || oldSize < 1 || oldSize > size) throw new ScittLogError('out_of_range', 'consistencyProof: size out of range');
    const path = await this.reader.consistency(oldSize, size);
    return {
      oldSize,
      newSize: size,
      oldRoot: b64u(await this.reader.root(oldSize)),
      newRoot: b64u(await this.reader.root(size)),
      proof: encode([oldSize, size, path]),
    };
  }
}

/**
 * Check a store implementation against the contract the service relies on. Returns the failures (empty = conforms). Run it
 * in your test suite against your real store: it exercises compare-and-set, atomic entry-plus-nodes, immutability and a
 * 100-entry log whose root, proofs and consistency proofs must match the RFC 9162 reference algorithms.
 */
export async function checkScittLogStore(makeStore: () => Promise<ScittLogStore> | ScittLogStore): Promise<string[]> {
  const failures: string[] = [];
  const fail = (m: string) => failures.push(m);
  try {
    const s = await makeStore();
    if ((await s.size()) !== 0) fail('a new store is not empty');
    const h = (b: number): Uint8Array => new Uint8Array(32).fill(b);
    if (!(await s.append(0, Uint8Array.of(1), [{ level: 0, index: 0, hash: h(1) }]))) fail('append at the right size was refused');
    if (await s.append(0, Uint8Array.of(2), [{ level: 0, index: 1, hash: h(2) }])) fail('append at a stale size was accepted (no compare-and-set)');
    if ((await s.size()) !== 1) fail('a refused append changed the size');
    if ((await s.getNode(0, 1)) !== undefined) fail('a refused append left a node behind (not atomic)');
    if ((await s.getEntry(1)) !== undefined) fail('a refused append left an entry behind');
    const e0 = await s.getEntry(0);
    if (!e0 || e0.length !== 1 || e0[0] !== 1) fail('the stored entry does not read back');
    if (e0) e0[0] = 9;
    const again = await s.getEntry(0);
    if (!again || again[0] !== 1) fail('a returned entry aliases the stored one (mutable)');
    const racers = await Promise.all([1, 2, 3, 4].map((i) => s.append(1, Uint8Array.of(10 + i), [{ level: 0, index: 1, hash: h(10 + i) }])));
    if (racers.filter(Boolean).length !== 1) fail('concurrent appends at the same size did not produce exactly one winner');
    if ((await s.size()) !== 2) fail('the size after a race is not 2');
  } catch (e) {
    fail(`the store threw: ${(e as Error).message}`);
  }
  return failures;
}
