/**
 * Test doubles. `TransparencyService` is an in-memory reference log (it recomputes the Merkle tree on every
 * registration and loses everything on restart): use it to produce receipts for tests and demos, never as a
 * production transparency service. The production log is `DurableTransparencyService` (main entry), over a
 * `ScittLogStore` you provide; `MemoryScittLogStore` is the in-memory store for its tests.
 */
import type { KeyObject } from 'node:crypto';
import { type InclusionProof, type ProofStep, b64u } from '@atlasauth/pca';
import {
  type CoseAlg,
  type ConsistencyProofResult,
  type ReceiptSignerOpts,
  type SignStatementOpts,
  buildReceipt,
  decodeCoseSign1,
  encode,
  signStatement,
  siblingSides,
} from './core';
import { consistencyPath, inclusionPath, leafHash, treeHash } from './rfc9162';
import type { ScittLogStore, StoredNode } from './durable';

export interface TransparencyServiceOpts {
  /** Receipt-signing algorithm. */
  alg: CoseAlg;
  /** The Transparency Service PRIVATE signing key. */
  key: KeyObject;
  /** Optional TS issuer id, stamped into every receipt's CWT Claims header. */
  issuer?: string;
}

export interface RegistrationResult {
  index: number;
  receipt: Uint8Array;
  root: string;
}

export interface AppendResult extends RegistrationResult {
  statement: Uint8Array;
}

export class TransparencyService {
  private readonly statements: Uint8Array[] = []; // the registered Signed Statements (the log entries)
  private readonly leafHashes: Uint8Array[] = []; // SHA-256(0x00 || statement), RFC 9162 section 2.1.1
  private readonly signer: ReceiptSignerOpts;

  constructor(opts: TransparencyServiceOpts) {
    this.signer = { alg: opts.alg, key: opts.key, ...(opts.issuer !== undefined ? { issuer: opts.issuer } : {}) };
  }

  /** Current number of registered statements. */
  get size(): number {
    return this.statements.length;
  }

  /** The current Merkle tree root (b64u); the empty-log root (SHA-256 of nothing) for an empty service. */
  get root(): string {
    return b64u(treeHash(this.leafHashes));
  }

  /** The statement leaves (b64u of each Signed Statement) currently in the log, in order. */
  snapshot(): string[] {
    return this.statements.map((st) => b64u(st));
  }

  private receiptFor(index: number): RegistrationResult {
    const root = treeHash(this.leafHashes);
    const sides = siblingSides(index, this.leafHashes.length);
    const path = inclusionPath(this.leafHashes, index).map((h, i): ProofStep => ({ side: sides[i]!, hash: b64u(h) }));
    const proof: InclusionProof = { index, size: this.leafHashes.length, path };
    return { index, receipt: buildReceipt(b64u(root), proof, this.signer), root: b64u(root) };
  }

  /** Register an already-signed Signed Statement; append it and return a signed inclusion Receipt. */
  register(statement: Uint8Array): RegistrationResult {
    // Structurally validate the statement before it enters the log (fail closed on garbage).
    const cose = decodeCoseSign1(statement);
    if (cose.payload === null) throw new TypeError('scitt: cannot register a statement with a detached payload');
    const index = this.statements.length;
    this.statements.push(new Uint8Array(statement));
    this.leafHashes.push(leafHash(statement));
    return this.receiptFor(index);
  }

  /** Sign `payload` as a Signed Statement, register it, and return the statement plus its Receipt. */
  appendAndReceipt(payload: unknown, stmt: SignStatementOpts): AppendResult {
    const statement = signStatement(payload, stmt);
    return { statement, ...this.register(statement) };
  }

  /** Re-issue a Receipt for an already-registered statement, against the CURRENT ledger root. */
  getReceipt(index: number): RegistrationResult {
    if (!Number.isInteger(index) || index < 0 || index >= this.statements.length) throw new RangeError('getReceipt: index out of range');
    return this.receiptFor(index);
  }

  /**
   * An RFC 9162 consistency proof that the log at `oldSize` entries is a prefix of the current log. The
   * result carries both roots and the proof in the RFC 9942 `consistency-proof-content` CBOR encoding.
   */
  consistencyProof(oldSize: number): ConsistencyProofResult {
    if (!Number.isInteger(oldSize) || oldSize < 1 || oldSize > this.statements.length) throw new RangeError('consistencyProof: size out of range');
    const path = consistencyPath(this.leafHashes, oldSize);
    return {
      oldSize,
      newSize: this.statements.length,
      oldRoot: b64u(treeHash(this.leafHashes.slice(0, oldSize))),
      newRoot: this.root,
      proof: encode([oldSize, this.statements.length, path]),
    };
  }
}

/** Register a Signed Statement into a Transparency Service (RFC 9943 register-signed-statement). */
export function registerStatement(statement: Uint8Array, service: TransparencyService): RegistrationResult {
  return service.register(statement);
}

/** In-memory {@link ScittLogStore}: single process, forgets everything on restart. For tests only. */
export class MemoryScittLogStore implements ScittLogStore {
  private readonly entries: Uint8Array[] = [];
  private readonly nodes = new Map<string, Uint8Array>();
  async size(): Promise<number> {
    return this.entries.length;
  }
  async getEntry(index: number): Promise<Uint8Array | undefined> {
    const e = this.entries[index];
    return e === undefined ? undefined : new Uint8Array(e);
  }
  async getNode(level: number, index: number): Promise<Uint8Array | undefined> {
    const h = this.nodes.get(`${level}:${index}`);
    return h === undefined ? undefined : new Uint8Array(h);
  }
  async append(expectedSize: number, entry: Uint8Array, nodes: readonly StoredNode[]): Promise<boolean> {
    if (this.entries.length !== expectedSize) return false;
    this.entries.push(new Uint8Array(entry));
    for (const n of nodes) this.nodes.set(`${n.level}:${n.index}`, new Uint8Array(n.hash));
    return true;
  }
}
