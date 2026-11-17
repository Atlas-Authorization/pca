/**
 * The directory log engine: an append-only Merkle log of passport registrations, updates and revocations.
 *
 * Tree math, signed tree heads (STH) and witness cosignatures are the PCA transparency ledger's (`TransparencyLedger`,
 * `signTreeHead`, `verifyWitnessCosignature`), so proofs are ordinary RFC 9162 proofs and cosignatures are the existing C2SP
 * witness format. This module adds what a directory needs on top: who may be listed (a verified passport and a proof of
 * possession of its subject key), per-submitter flood limits, revocation, and storage behind a small interface.
 *
 * Pure: no node-only imports, so it runs in a browser, a worker or a server.
 */
import { b64u, type InclusionProof } from '@atlasauth/pca';
import {
  TransparencyLedger,
  signTreeHead,
  verifyWitnessCosignature,
  type ConsistencyProof,
  type SignedTreeHead,
  type WitnessCosignature,
  type LedgerSuiteOpts,
} from '@atlasauth/pca/ext/ledger';
import { verifyPassport, type SignedPassport, type VerifyPassportOptions } from '@atlasauth/pca/ext/attestation';
import { publicKeyOf } from '@atlasauth/pca';
import { TRANSITION_PRINCIPAL_PREFIX, signKeyTransition, verifyKeyTransition, transitionHead, type SignedKeyTransition } from './rotation';
import {
  DIRECTORY_ENTRY_TYP,
  DIRECTORY_VERSION,
  entryCommit,
  isDirectoryEntry,
  issuerRef,
  passportDigest,
  revocationDigest,
  subjectRef,
  verifyPop,
  verifyRevocation,
  type DirectoryEntry,
  type EntryMode,
  type SignedRevocation,
} from './entry';

/** An entry as stored: the leaf, where it sits, and (public mode only) the signed document it commits to. */
export interface StoredEntry {
  index: number;
  commit: string;
  entry: DirectoryEntry;
  /** The signed passport or revocation. Kept only for `public` entries; a hashed entry has no body here. */
  body?: SignedPassport | SignedRevocation;
  /** Who submitted it (an opaque id used for flood accounting). Never served. */
  submitter: string;
}

export interface CosignedHead {
  size: number;
  root: string;
  cosigs: WitnessCosignature[];
}

/** Persistence. `append` must be a compare-and-set on the index so two writers cannot fork the log. */
export interface DirectoryStore {
  size(): Promise<number>;
  /** Append at exactly `index`; resolves `false` (and writes nothing) when that index is already taken. */
  append(row: StoredEntry): Promise<boolean>;
  commits(): Promise<string[]>;
  get(index: number): Promise<StoredEntry | undefined>;
  range(from: number, limit: number): Promise<StoredEntry[]>;
  /** Entries for a subject reference, oldest first (bounded). */
  bySubject(subject: string, limit: number): Promise<StoredEntry[]>;
  /** The register/update entry for a passport digest. */
  byDigest(digest: string): Promise<StoredEntry | undefined>;
  /** The revoke entry that revokes a passport digest. */
  byRevoked(digest: string): Promise<StoredEntry | undefined>;
  /** Add a cosignature to the head `(size, root)`; one per witness key (a re-submission replaces it). */
  addCosignature(size: number, root: string, cosig: WitnessCosignature): Promise<void>;
  /** The most recent heads that carry cosignatures, newest (largest size) first. */
  cosignedHeads(limit: number): Promise<CosignedHead[]>;
  /** Key transitions, oldest first. */
  transitions(): Promise<SignedKeyTransition[]>;
  addTransition(t: SignedKeyTransition): Promise<void>;
}

export class MemoryDirectoryStore implements DirectoryStore {
  private readonly rows: StoredEntry[] = [];
  private readonly cosigs = new Map<string, Map<string, WitnessCosignature>>();

  async size(): Promise<number> {
    return this.rows.length;
  }
  async append(row: StoredEntry): Promise<boolean> {
    if (row.index !== this.rows.length) return false;
    // the same uniqueness a database index gives: one row per passport digest, one revocation per revoked digest
    const e = row.entry;
    if (e.kind === 'revoke' ? this.rows.some((r) => r.entry.kind === 'revoke' && r.entry.revokes === e.revokes) : this.rows.some((r) => r.entry.kind !== 'revoke' && r.entry.digest === e.digest)) return false;
    this.rows.push(row);
    return true;
  }
  async commits(): Promise<string[]> {
    return this.rows.map((r) => r.commit);
  }
  async get(index: number): Promise<StoredEntry | undefined> {
    return this.rows[index];
  }
  async range(from: number, limit: number): Promise<StoredEntry[]> {
    return this.rows.slice(from, from + limit);
  }
  async bySubject(subject: string, limit: number): Promise<StoredEntry[]> {
    return this.rows.filter((r) => r.entry.subject === subject).slice(0, limit);
  }
  async byDigest(digest: string): Promise<StoredEntry | undefined> {
    return this.rows.find((r) => r.entry.kind !== 'revoke' && r.entry.digest === digest);
  }
  async byRevoked(digest: string): Promise<StoredEntry | undefined> {
    return this.rows.find((r) => r.entry.kind === 'revoke' && r.entry.revokes === digest);
  }
  async addCosignature(size: number, root: string, cosig: WitnessCosignature): Promise<void> {
    const k = `${size}\0${root}`;
    const m = this.cosigs.get(k) ?? new Map<string, WitnessCosignature>();
    m.set(cosig.key, cosig);
    this.cosigs.set(k, m);
  }
  private readonly keyTransitions: SignedKeyTransition[] = [];
  async transitions(): Promise<SignedKeyTransition[]> {
    return [...this.keyTransitions].sort((a, b) => a.seq - b.seq);
  }
  async addTransition(t: SignedKeyTransition): Promise<void> {
    if (!this.keyTransitions.some((x) => x.seq === t.seq)) this.keyTransitions.push(t);
  }
  async cosignedHeads(limit: number): Promise<CosignedHead[]> {
    return [...this.cosigs.entries()]
      .map(([k, m]) => {
        const [size, root] = k.split('\0');
        return { size: Number(size), root: root!, cosigs: [...m.values()] };
      })
      .sort((a, b) => b.size - a.size)
      .slice(0, limit);
  }
}

// ---- configuration -------------------------------------------------------------------------------------------------

export interface FloodLimit {
  /** Accepted submissions per submitter per window. */
  max: number;
  windowMs: number;
}

export interface DirectoryLogOptions {
  /** Stable id of this log, written into every leaf. */
  id: string;
  /** The log's signing key (Ed25519 secret). */
  secret: Uint8Array;
  /** `instance_id` / `principal` written into every STH (they scope witness cosignatures to this one log). */
  instanceId?: string;
  principal?: string;
  store?: DirectoryStore;
  /** Which passport issuers may be listed: `'any'` (open log; relying parties pick the issuers they trust) or an allow-list of issuer keys. */
  issuers?: 'any' | readonly string[];
  /** Entry modes this log accepts (default both). */
  modes?: readonly EntryMode[];
  /** Hardware verifier used to admit `hardware_rooted` passports. Without it such passports are refused. */
  attestationVerifier?: VerifyPassportOptions['attestationVerifier'];
  /** Flood control per submitter (default 60 per hour). `false` disables it. */
  flood?: FloodLimit | false;
  /** Entries one subject may hold (default 64). */
  maxEntriesPerSubject?: number;
  /** Hard cap on the log size; submissions beyond it are refused. */
  maxEntries?: number;
  /** Trusted witness keys that may post cosignatures. With none configured, cosignatures are refused. */
  witnessKeys?: readonly string[];
  /** Distinct trusted witnesses that must cosign a key transition (default 1; never 0: a rotation is always witnessed). */
  rotationThreshold?: number;
  suite?: LedgerSuiteOpts;
  now?: () => number;
}

export type SubmitRequest =
  | { passport: SignedPassport; pop: string; mode?: EntryMode }
  | { revocation: SignedRevocation; mode?: EntryMode };

export type SubmitReason =
  | 'malformed'
  | 'rate_limited'
  | 'log_full'
  | 'mode_not_allowed'
  | 'issuer_not_allowed'
  | 'passport_invalid'
  | 'bad_pop'
  | 'revoked'
  | 'too_many_entries'
  | 'bad_revocation'
  | 'unknown_passport'
  | 'revocation_mismatch'
  | 'conflict';

export type SubmitResult =
  | { ok: true; created: boolean; index: number; commit: string; entry: DirectoryEntry }
  | { ok: false; reason: SubmitReason; detail?: string };

const MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_FLOOD: FloodLimit = { max: 60, windowMs: 3_600_000 };
const MAX_FLOOD_KEYS = 50_000;
const fail = (reason: SubmitReason, detail?: string): SubmitResult => ({ ok: false, reason, ...(detail ? { detail } : {}) });

export class DirectoryLog {
  readonly id: string;
  private secret: Uint8Array;
  private pending: { transition: SignedKeyTransition; newSecret: Uint8Array } | undefined;
  readonly store: DirectoryStore;
  private readonly o: DirectoryLogOptions;
  private ledger = new TransparencyLedger('');
  private chain: Promise<unknown> = Promise.resolve();
  private readonly hits = new Map<string, number[]>();

  constructor(o: DirectoryLogOptions) {
    if (!o.id || typeof o.id !== 'string') throw new Error('DirectoryLog: id is required');
    this.o = o;
    this.id = o.id;
    if ((o.principal ?? o.id).startsWith(TRANSITION_PRINCIPAL_PREFIX)) throw new Error('DirectoryLog: principal may not name a key transition');
    this.secret = o.secret;
    this.store = o.store ?? new MemoryDirectoryStore();
    this.ledger = new TransparencyLedger(o.principal ?? o.id);
  }

  /** The key heads are signed with now. */
  get publicKey(): string {
    return b64u(publicKeyOf(this.secret));
  }

  private now(): number {
    return (this.o.now ?? Date.now)();
  }

  /** Serialise writers inside one process; the store's compare-and-set arbitrates between processes. */
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.then(fn, fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  /** Bring the in-memory tree up to date with the store (another process may have appended). */
  private async sync(): Promise<void> {
    const n = await this.store.size();
    if (n === this.ledger.size) return;
    const commits = await this.store.commits();
    this.ledger = TransparencyLedger.fromEntries(commits.map((commit) => ({ commit })), this.o.principal ?? this.id);
  }

  private flooded(submitter: string): boolean {
    const f = this.o.flood === undefined ? DEFAULT_FLOOD : this.o.flood;
    if (f === false) return false;
    const now = this.now();
    if (this.hits.size > MAX_FLOOD_KEYS) for (const [k, v] of this.hits) if (v.every((t) => now - t >= f.windowMs)) this.hits.delete(k);
    const recent = (this.hits.get(submitter) ?? []).filter((t) => now - t < f.windowMs);
    if (recent.length >= f.max) {
      this.hits.set(submitter, recent);
      return true;
    }
    recent.push(now);
    this.hits.set(submitter, recent);
    return false;
  }

  /** Submit a registration (a passport + proof of possession) or a revocation. Never throws on bad input. */
  submit(req: SubmitRequest, submitter: string): Promise<SubmitResult> {
    if (this.flooded(submitter)) return Promise.resolve(fail('rate_limited'));
    return this.serial(async () => {
      try {
        return await this.submitLocked(req, submitter);
      } catch (e) {
        return fail('malformed', e instanceof Error ? e.message : 'error');
      }
    });
  }

  private async submitLocked(req: SubmitRequest, submitter: string): Promise<SubmitResult> {
    if (req === null || typeof req !== 'object') return fail('malformed');
    if (JSON.stringify(req).length > MAX_BODY_BYTES) return fail('malformed', 'too large');
    const mode: EntryMode = req.mode ?? 'public';
    if (mode !== 'public' && mode !== 'hashed') return fail('malformed', 'mode');
    if ((req.mode !== undefined || !('revocation' in req)) && !(this.o.modes ?? ['public', 'hashed']).includes(mode)) return fail('mode_not_allowed');
    if (this.pending) return fail('conflict', 'key rotation in progress');
    await this.sync();
    // a full log still takes revocations: refusing one would keep a revoked agent trusted
    if (this.o.maxEntries !== undefined && this.ledger.size >= this.o.maxEntries && !('revocation' in req)) return fail('log_full');
    return 'revocation' in req ? this.revoke(req.revocation, req.mode, submitter) : this.register(req, mode, submitter);
  }

  private async register(req: { passport: SignedPassport; pop: string }, mode: EntryMode, submitter: string): Promise<SubmitResult> {
    const sp = req.passport;
    const now = this.now();
    if (!sp || typeof sp !== 'object' || typeof sp.iss !== 'string' || typeof sp.sub !== 'string') return fail('malformed', 'passport');
    const allowed = this.o.issuers ?? 'any';
    if (allowed !== 'any' && !allowed.includes(sp.iss)) return fail('issuer_not_allowed');
    const digest = passportDigest(sp);
    if (await this.store.byRevoked(digest)) return fail('revoked');
    const v = await verifyPassport(sp, {
      // an open log checks the passport against its own issuer: the signature and window must hold, trust in the issuer is the relying party's call
      trustedIssuers: allowed === 'any' ? [sp.iss] : allowed,
      now,
      revocation: () => false,
      ...(this.o.attestationVerifier ? { attestationVerifier: this.o.attestationVerifier } : {}),
    });
    if (!v.ok) return fail('passport_invalid', v.reason);
    if (!verifyPop(sp.sub, this.id, digest, req.pop)) return fail('bad_pop');
    const existing = await this.store.byDigest(digest);
    if (existing) {
      if (existing.entry.mode !== mode) return fail('conflict', 'already listed in the other mode');
      return { ok: true, created: false, index: existing.index, commit: existing.commit, entry: existing.entry };
    }
    const subject = subjectRef(sp.sub, mode);
    const issuer = issuerRef(sp.iss, mode);
    const prior = await this.store.bySubject(subject, (this.o.maxEntriesPerSubject ?? 64) + 1);
    if (prior.length >= (this.o.maxEntriesPerSubject ?? 64)) return fail('too_many_entries');
    const kind = prior.some((r) => r.entry.kind !== 'revoke' && r.entry.issuer === issuer) ? 'update' : 'register';
    const entry: DirectoryEntry = { typ: DIRECTORY_ENTRY_TYP, ver: DIRECTORY_VERSION, log: this.id, kind, mode, subject, issuer, digest, exp: sp.exp, iat: now };
    return this.append(entry, mode === 'public' ? sp : undefined, submitter);
  }

  private async revoke(rev: SignedRevocation, requested: EntryMode | undefined, submitter: string): Promise<SubmitResult> {
    if (!verifyRevocation(rev)) return fail('bad_revocation');
    const target = await this.store.byDigest(rev.passport_digest);
    if (!target) return fail('unknown_passport');
    const e = target.entry;
    const mode = requested ?? e.mode;
    // the statement names the keys; they must be the ones this entry was made for, in the mode it was made in
    if (e.mode !== mode || e.subject !== subjectRef(rev.sub, e.mode) || e.issuer !== issuerRef(rev.iss, e.mode)) return fail('revocation_mismatch');
    const done = await this.store.byRevoked(rev.passport_digest);
    if (done) return { ok: true, created: false, index: done.index, commit: done.commit, entry: done.entry };
    const entry: DirectoryEntry = {
      typ: DIRECTORY_ENTRY_TYP,
      ver: DIRECTORY_VERSION,
      log: this.id,
      kind: 'revoke',
      mode,
      subject: e.subject,
      issuer: e.issuer,
      digest: revocationDigest(rev),
      revokes: rev.passport_digest,
      iat: this.now(),
    };
    return this.append(entry, mode === 'public' ? rev : undefined, submitter);
  }

  private async append(entry: DirectoryEntry, body: StoredEntry['body'], submitter: string): Promise<SubmitResult> {
    const index = this.ledger.size;
    const commit = entryCommit(entry);
    const ok = await this.store.append({ index, commit, entry, ...(body ? { body } : {}), submitter });
    if (!ok) {
      await this.sync();
      return fail('conflict', 'concurrent append, retry');
    }
    this.ledger.appendCommitment(commit);
    return { ok: true, created: true, index, commit, entry };
  }

  // ---- reads ---------------------------------------------------------------------------------------------------------

  async head(): Promise<{ size: number; root: string }> {
    await this.sync();
    return this.ledger.head();
  }

  /**
   * A signed tree head for the current head (or, with `size`, for that earlier size), with every stored witness cosignature
   * that verifies for it. Signed on every call: the signed timestamp is what a relying party's freshness check reads.
   */
  async sth(size?: number): Promise<SignedTreeHead> {
    await this.sync();
    const n = size ?? this.ledger.size;
    if (!Number.isInteger(n) || n < 0 || n > this.ledger.size) throw new RangeError('sth: size out of range');
    const root = this.ledger.rootAt(n);
    const base = signTreeHead(
      this.secret,
      {
        instance_id: this.o.instanceId ?? this.id,
        principal: this.o.principal ?? this.id,
        size: n,
        root,
        prev_root: n === 0 ? '' : this.ledger.rootAt(n - 1),
        timestamp: this.now(),
      },
      this.o.suite,
    );
    const heads = await this.store.cosignedHeads(256);
    const cosigs = heads.find((h) => h.size === n && h.root === root)?.cosigs ?? [];
    const valid = cosigs.filter((c) => verifyWitnessCosignature(base, c, c.key));
    return valid.length > 0 ? { ...base, witnesses: valid } : base;
  }

  /** The newest head that carries at least `minCosigs` cosignatures and covers `minSize` entries; falls back to the plain head. */
  async cosignedSth(minCosigs: number, minSize = 0): Promise<SignedTreeHead> {
    await this.sync();
    for (const h of await this.store.cosignedHeads(256)) {
      if (h.size < minSize || h.size > this.ledger.size || h.cosigs.length < minCosigs) continue;
      if (this.ledger.rootAt(h.size) !== h.root) continue;
      const s = await this.sth(h.size);
      if ((s.witnesses?.length ?? 0) >= minCosigs) return s;
    }
    return this.sth();
  }

  async entry(index: number): Promise<StoredEntry | undefined> {
    return Number.isSafeInteger(index) && index >= 0 ? this.store.get(index) : undefined;
  }

  async entries(from: number, limit: number): Promise<StoredEntry[]> {
    if (!Number.isSafeInteger(from) || from < 0 || !Number.isSafeInteger(limit) || limit < 1) return [];
    return this.store.range(from, Math.min(limit, 500));
  }

  /** Inclusion proof for `index` in the tree of `size` entries (default: current). */
  async inclusion(index: number, size?: number): Promise<InclusionProof | null> {
    await this.sync();
    const n = size ?? this.ledger.size;
    if (!Number.isSafeInteger(index) || index < 0 || index >= n || n > this.ledger.size) return null;
    const commits = this.ledger.commits().slice(0, n);
    return TransparencyLedger.fromEntries(commits.map((commit) => ({ commit }))).inclusionProof(index);
  }

  async consistency(from: number, to?: number): Promise<ConsistencyProof | null> {
    await this.sync();
    const t = to ?? this.ledger.size;
    if (!Number.isSafeInteger(from) || from < 0 || from > t || t > this.ledger.size) return null;
    return this.ledger.consistencyProof(from, t);
  }

  async lookup(subject: string, limit = 64): Promise<StoredEntry[]> {
    return this.store.bySubject(subject, Math.min(limit, 256));
  }

  async byDigest(digest: string): Promise<StoredEntry | undefined> {
    return this.store.byDigest(digest);
  }

  // ---- key rotation -----------------------------------------------------------------------------------------------

  /** The transitions this log has published, oldest first. */
  transitions(): Promise<SignedKeyTransition[]> {
    return this.store.transitions();
  }

  /**
   * Start a rotation to `newSecret`: the log stops accepting submissions (so the head it hands over cannot move), and returns the
   * transition for witnesses to cosign and the final head under the old key. Witnesses must first cosign that final head, then the
   * transition (`Witness.cosignTransition`); feed their cosignatures to `rotationCosign` and call `completeRotation`.
   */
  proposeRotation(newSecret: Uint8Array): Promise<{ transition: SignedKeyTransition; finalHead: SignedTreeHead }> {
    return this.serial(async () => {
      if (this.pending) throw new Error('a rotation is already in progress');
      await this.sync();
      const finalHead = await this.sth();
      const prior = await this.store.transitions();
      const transition = signKeyTransition({
        log: this.id,
        instanceId: finalHead.instance_id,
        principal: finalHead.principal,
        seq: prior.length + 1,
        oldSecret: this.secret,
        newSecret,
        atSize: finalHead.size,
        atRoot: finalHead.root,
        iat: this.now(),
      });
      this.pending = { transition, newSecret };
      return { transition, finalHead };
    });
  }

  /** The transition witnesses are being asked to cosign, with the cosignatures it has so far. */
  pendingTransition(): SignedKeyTransition | undefined {
    return this.pending?.transition;
  }

  /** Give up a rotation that did not get its quorum; submissions resume. */
  abortRotation(): void {
    this.pending = undefined;
  }

  /** Add a witness cosignature of the pending transition. Only configured witnesses count; false for anything else. */
  async rotationCosign(cosig: WitnessCosignature): Promise<boolean> {
    const p = this.pending;
    if (!p || !(this.o.witnessKeys ?? []).includes(cosig?.key)) return false;
    const probe: SignedKeyTransition = { ...p.transition, witnesses: [cosig] };
    if (!verifyKeyTransition(probe, { witnessKeys: [cosig.key], threshold: 1 })) return false;
    p.transition = { ...p.transition, witnesses: [...(p.transition.witnesses ?? []).filter((w) => w.key !== cosig.key), cosig] };
    return true;
  }

  /**
   * Finish the rotation once the trusted witnesses have cosigned: publishes the transition and switches to the new key. Refuses
   * (and keeps the old key) when the quorum is short, so a rotation can never skip the witnesses.
   */
  completeRotation(): Promise<SignedKeyTransition> {
    return this.serial(async () => {
      const p = this.pending;
      if (!p) throw new Error('no rotation in progress');
      const need = Math.max(1, this.o.rotationThreshold ?? 1);
      if (!verifyKeyTransition(p.transition, { witnessKeys: [...(this.o.witnessKeys ?? [])], threshold: need })) throw new Error(`rotation needs ${need} witness cosignature(s) of the transition`);
      await this.sync();
      if (this.ledger.size !== p.transition.at_size || this.ledger.head().root !== p.transition.at_root) throw new Error('the log moved since the rotation was proposed');
      await this.store.addTransition(p.transition);
      this.secret = p.newSecret;
      this.pending = undefined;
      return p.transition;
    });
  }

  /**
   * Accept a witness cosignature for the head `(size, root)`. Only configured witness keys, only for a head this log
   * actually has, and only if the signature verifies against that head. Returns false otherwise.
   */
  async addCosignature(size: number, root: string, cosig: WitnessCosignature): Promise<boolean> {
    if (!(this.o.witnessKeys ?? []).includes(cosig?.key)) return false;
    await this.sync();
    if (!Number.isSafeInteger(size) || size < 0 || size > this.ledger.size || this.ledger.rootAt(size) !== root) return false;
    const base = await this.sth(size);
    if (!verifyWitnessCosignature(base, cosig, cosig.key)) return false;
    await this.store.addCosignature(size, root, cosig);
    return true;
  }
}
