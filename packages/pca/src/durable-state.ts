/**
 * Crash-safe, tamper-evident, multi-process-safe persistent key/value state for Node
 * (NODE ONLY: imports node:fs; deliberately not re-exported from the package index so browser bundles stay clean).
 *
 * WHY: rollback protection for signed allowlist manifests and MAA key sets (attest-allowlist, attest-maa-keys)
 * is only as good as the persistence of "the highest thing I ever accepted". This module is that persistence.
 *
 * LAYOUT (a directory you own, mode 0700): `state.journal` (hash-chained records, one JSON object per line),
 * `state.head` (seq + hash of the last record, written AFTER the journal), `state.lock` (advisory lock).
 *
 * WHAT IS GUARANTEED
 *   - CRASH SAFETY: every mutation is write-temp -> fsync(file) -> rename -> fsync(directory). A crash (SIGKILL,
 *     power loss on a filesystem honouring fsync) leaves either the old or the new journal, never a torn one. The
 *     head file trails the journal by at most ONE record and is repaired by the next writer.
 *   - NO LOST UPDATES across processes: every mutation (`set` / `update`) runs under an exclusive lock made of
 *     immutable numbered generation files (created atomically with link(2); the holder is the process named in the
 *     highest generation; a lock is taken over only from a provably dead holder, never by age; the generation is
 *     re-checked right before the journal rename AND right before every head rename). `update(key, fn)` is an atomic
 *     read-modify-write, so "monotone max" semantics hold under concurrency.
 *   - FENCING AGAINST A PAUSED HOLDER (R6-CORE-01): operator recovery (`recoverDurableState`) can release a holder that
 *     is only PAUSED (SIGSTOP, `docker pause`, cgroup freeze, VM suspend), and a re-check followed by rename(2) always
 *     leaves a window: a holder paused after its re-check and before its rename still renames when it resumes. Safety
 *     therefore does not rest on timing. Every journal record and the head carry the writer's lock generation `gen`
 *     (covered by the record hash / head MAC), and recovery first writes `state.fence` ("records after journal seq S
 *     must come from generation >= G", G above the released generation). On load a record whose generation is below a
 *     fence that covers it, below an earlier record's generation, or below the generation that wrote the head is
 *     REFUSED ('corrupt', never silently accepted). A stale late head (lower generation, behind a journal that newer
 *     generations extended past the fence) is recognised and repaired. What a stale journal rename DOES cost: it
 *     replaces the journal, so the newer holder's records after the cut are no longer on disk; the store then fails
 *     closed (detected, not silent) and `recoverFromCorruption` quarantines the files for forensics. A holder paused
 *     anywhere else (the overwhelmingly likely case) gets 'lock-lost' and writes nothing. RECOVERY THAT ITSELF CRASHES
 *     midway is safe too: its lock is marked `recovering`, and whoever takes it over from the dead recovery (a same-namespace
 *     waiter) cuts and fences first; otherwise the operator re-runs recovery. Model: formal/tla/DurableFence.tla.
 *   - Fences are append-only: one immutable file per fence (`state.fence.<gen>-<rand>`, see DurableFence), never a shared
 *     list rewritten by read-add-rename, so a late fence writer cannot drop another's fence.
 *   - THREAT MODEL OF THE LOCK AND FENCE FILES: `state.fence*` and `state.lock.N` are NOT signed or MACed (even with
 *     `hmacKey`). They defend against a paused or late process of this library, not against someone with write access to
 *     the directory: that party can already break the store more simply (delete journal + head = a first run; kill the
 *     holder). Editing the fence cannot forge a record (records/head stay hash-chained and MACed). Automatic takeover
 *     deliberately NEVER breaks a lock recorded under another hostname (or another PID namespace): there kill(pid, 0) proves
 *     nothing, and a wrong break lets two writers in; only an operator's recoverDurableState releases it.
 *   - TAMPER / TRUNCATION EVIDENCE: records are hash-chained (sha256 over seq, prev hash, op, payload, time).
 *     Editing, reordering, inserting or deleting a record in the middle breaks the chain; truncating the tail or
 *     replacing the journal with an OLDER valid copy is caught by the head file (journal.seq < head.seq) and, in a
 *     running process, by the highest (seq, hash) this instance has already observed. Deleting ONLY the journal
 *     while the head survives is caught too. With `hmacKey`, every record and the head are HMAC-SHA256 tagged so
 *     an attacker without the key cannot forge or re-chain either.
 *   - FAIL CLOSED: corrupt, truncated or rolled-back state makes `openDurableState` / every operation throw a
 *     `DurableStateError`. It never silently starts empty. The ONLY way past is the explicit
 *     `recoverFromCorruption: true` option, which quarantines the bad files (kept for forensics, never deleted)
 *     and starts from genesis with `recovered === true` so the caller can re-establish trust.
 *
 * WHAT IS NOT GUARANTEED
 *   - An attacker who can write BOTH the journal and the head file AND has no HMAC key to defeat can restore an
 *     older consistent (journal, head) pair; without `hmacKey` that is undetectable locally. Deleting the whole
 *     directory is likewise indistinguishable from a first run. That residual gap is what the transparency-anchored
 *     check (attest-allowlist-anchor) exists for: it needs no local state at all.
 *   - fsync durability is whatever the OS/filesystem delivers (macOS fsync does not force the drive cache; use a
 *     filesystem/mount that honours it for power-loss guarantees). Process crash safety does not depend on this.
 *   - REQUIREMENTS, LOUDLY: (1) ONE HOST. The lock coordinates processes on a single machine; it judges a holder dead by
 *     kill(pid, 0) / process start time, which is meaningless across hosts, and a holder recorded on another host is never
 *     taken over. Do not share the directory between hosts. CONTAINERS COUNT AS HOSTS (R4-09): two containers that mount one
 *     volume are two PID namespaces even when they share a hostname, so each lock generation records the holder's PID
 *     namespace id (`/proc/self/ns/pid`), a per-process random boot id, pid and start time, and a holder in a different
 *     namespace is never judged dead (a waiter times out, fail closed). Run ONE container (or one pod sharing a PID
 *     namespace) per state volume. (2) A LOCAL filesystem with working hard links, link(2) with
 *     atomic exclusive-create semantics (ext4, xfs, btrfs, tmpfs, APFS). NFS (especially v2/v3 or any mount with attribute
 *     caching), SMB/CIFS, FUSE and some overlay/union mounts can return success twice, fail with EPERM/ENOTSUP, or show stale
 *     directory listings; on those, mutual exclusion is not guaranteed. `openDurableState` PROBES link(2) and the observed
 *     link count at open time and FAILS CLOSED with DurableStateError code 'link-unsupported' when it cannot; it cannot detect
 *     a filesystem that links correctly in the probe but caches directory listings across hosts, hence rule (1).
 *   - A STALLED HOLDER BLOCKS UNTIL IT DIES. A live holder is never robbed, however long it stalls (blocked fsync, SIGSTOP, a
 *     debugger); other processes wait up to `lockTimeoutMs` and then fail with 'lock-timeout' (fail closed). The previous
 *     age-based takeover is gone because it silently lost updates. Operators must restart or kill a wedged holder.
 *   - (Legacy) a single-file `state.lock` written by an older version is honoured as a holder (waited for unless its owner is
 *     provably dead) so a host mid-upgrade never runs old and new writers concurrently; it is never deleted or renamed
 *     automatically (operator recovery with `legacyLock: true` moves it aside). Do not run old and new versions on one directory.
 *   - FORMAT: records and the head written by this version carry `gen`; records/heads without it (older versions) are read as
 *     generation 0 and stay valid. An OLDER version cannot read a journal written by this one (it fails closed with a hash
 *     mismatch), so do not downgrade a directory.
 *   - Model-checked in formal/tla/DurableLockGen.tla (mutual exclusion with a stalled owner, two concurrent breakers
 *     and a third process); the previous age-based break protocol violated it (DurableLock.tla). Operator recovery of a
 *     paused holder, the re-checks and the generation fence: formal/tla/DurableFence.tla.
 *   - The journal is rewritten whole per mutation (it is for small state: versions, digests, key sets) and is
 *     compacted into a checkpoint record every `compactEvery` records.
 */
import { closeSync, constants, existsSync, fsyncSync, linkSync, readlinkSync, writeFileSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeSync, chmodSync } from 'node:fs';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { hostname } from 'node:os';
import { join } from 'node:path';

export type DurableStateErrorCode = 'corrupt' | 'rollback' | 'lock-timeout' | 'lock-lost' | 'link-unsupported' | 'key-mismatch' | 'invalid' | 'too-large';

export class DurableStateError extends Error {
  constructor(
    readonly code: DurableStateErrorCode,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = 'DurableStateError';
  }
}

/** The persistence interface the allowlist / key-trust modules use. Values must be JSON-serialisable. */
export interface DurableKv {
  get(key: string): Promise<unknown | undefined>;
  /** Unconditional write (still serialised and hash-chained). Prefer `update` for monotone state. */
  set(key: string, value: unknown): Promise<void>;
  /**
   * Atomic read-modify-write. `fn` receives the current value (or undefined) and returns the next value, or
   * `undefined` to leave the key unchanged. Returns the value now stored. `fn` runs under the cross-process lock
   * and must be synchronous and quick.
   */
  update(key: string, fn: (prev: unknown | undefined) => unknown | undefined): Promise<unknown | undefined>;
  keys(): Promise<string[]>;
}

/** In-memory implementation (tests / single process). Same semantics, no durability. */
export function createMemoryDurableKv(): DurableKv & { snapshot(): Map<string, unknown> } {
  const m = new Map<string, string>();
  const dec = (s: string | undefined): unknown | undefined => (s === undefined ? undefined : (JSON.parse(s) as unknown));
  return {
    async get(k) {
      return dec(m.get(k));
    },
    async set(k, v) {
      const s = JSON.stringify(v);
      if (s === undefined) throw new DurableStateError('invalid', 'value is not JSON-serialisable');
      m.set(k, s);
    },
    async update(k, fn) {
      const next = fn(dec(m.get(k)));
      if (next !== undefined) {
        const s = JSON.stringify(next);
        if (s === undefined) throw new DurableStateError('invalid', 'value is not JSON-serialisable');
        m.set(k, s);
      }
      return dec(m.get(k));
    },
    async keys() {
      return [...m.keys()].sort();
    },
    snapshot: () => new Map([...m].map(([k, v]) => [k, JSON.parse(v) as unknown])),
  };
}

export interface DurableStateOptions {
  /** Directory holding the state (created 0700 if missing). */
  dir: string;
  /** Optional >= 32-byte HMAC key: records and head are tagged; forging/re-chaining then needs the key. */
  hmacKey?: Uint8Array;
  /** Explicit recovery: quarantine corrupt/rolled-back files and start from genesis. Default false (fail closed). */
  recoverFromCorruption?: boolean;
  /** Give up acquiring the lock after this long (default 10 s). */
  lockTimeoutMs?: number;
  /** Compact the journal into a checkpoint every N records (default 256). */
  compactEvery?: number;
  /** Max serialised value size (default 1 MiB). */
  maxValueBytes?: number;
  /** Clock for record timestamps (default Date.now). */
  now?: () => number;
  /** TEST ONLY: SIGKILL this process at the named point of a commit, to prove crash safety. */
  testCrashAt?: 'after-temp-write' | 'after-journal-rename';
}

/** The holder record of the lock file an operator has confirmed dead (copy it from the lock-timeout error / the `state.lock.N` file). */
export interface ExpectedLockHolder {
  host: string;
  pid: number;
  /** The per-acquisition nonce in the lock file: unique to one lock acquisition, so a match proves the operator looked at THIS lock. */
  nonce: string;
}

export interface RecoverDurableStateOptions {
  dir: string;
  /** Must be literally `true`: this is an out-of-band operator action, never automatic. */
  force: true;
  /**
   * The holder the operator attests is gone: `{ host, pid, nonce }` copied EXACTLY from a complete holder record, or
   * `'unreadable'` for a top lock file that is unreadable (empty/garbage) or INCOMPLETE (readable but missing a numeric pid,
   * a host or a non-empty nonce: `{}`, `[]`, `{"st":"held"}`, a string pid, ...). A complete record never accepts
   * `'unreadable'`, an unreadable/incomplete one never accepts copied fields (R6-CORE-03).
   */
  expectedHolder: ExpectedLockHolder | 'unreadable';
  /**
   * R6-CORE-03: release the LEGACY single-file `state.lock` written by an older version (it blocks every writer while its
   * holder is not provably dead, e.g. a dead holder in another PID namespace). Must be passed explicitly; the file is moved
   * aside to `state.lock.legacy-recovered-<time>-<rand>` (kept for forensics), never deleted. Refused when the blocker is a
   * generation lock `state.lock.N`.
   */
  legacyLock?: boolean;
}

export interface RecoverDurableStateResult {
  released: boolean;
  /** `not-held`: nothing to do. `released`: the dead holder's generation was superseded (or the legacy lock moved aside). */
  reason: 'not-held' | 'released';
  /** The lock file that was superseded. */
  lockFile?: string;
}

/**
 * A fence: records after journal `seq` must come from lock generation >= `gen`. Written by operator recovery, by the taker of
 * a crashed recovery's lock, and (from genesis) by quarantine.
 *
 * STORAGE (append-only, never lost): each fence is its OWN immutable file `state.fence.<gen>-<random>` (written once with
 * temp + rename under a unique name), plus the list file `state.fence` (fences written by older versions, and the genesis
 * fence quarantine writes). A fence is never rewritten into a shared file: with read-the-list, add, rename-the-list, a
 * fence writer paused between its read and its rename (a taker superseded by a recovery, a recovery attested dead while
 * paused) would drop every fence written in between when it resumed (formal/tla DurableFence df_bad_fence_rmw).
 */
export interface DurableFence {
  gen: number;
  seq: number;
  /**
   * Hash of the journal record at `seq` when the cut was taken (all zeros for seq 0). The journal must still contain THAT
   * record (or have been compacted past it by a later generation): a cut taken over a journal whose tail was itself a stale,
   * refused record must not let another stale journal of the same length through (formal/tla DurableFence, df_bad_no_pin).
   */
  h: string;
}
const FENCE_FILE = 'state.fence';
/** One fence per file: `state.fence.<gen>-<random hex>` (temp files and quarantined copies carry a further suffix). */
const FENCE_ENTRY = /^state\.fence\.(\d+)-([0-9a-f]+)$/;

function parseFence(f: unknown, where: string): DurableFence {
  const x = f as Record<string, unknown>;
  if (
    typeof f !== 'object' || f === null || !Number.isSafeInteger(x['gen']) || (x['gen'] as number) < 1 || !Number.isSafeInteger(x['seq']) || (x['seq'] as number) < 0 ||
    typeof x['h'] !== 'string' || !/^[0-9a-f]{64}$/.test(x['h'])
  ) {
    throw new DurableStateError('corrupt', `${where} has an invalid entry`);
  }
  return { gen: x['gen'] as number, seq: x['seq'] as number, h: x['h'] };
}

/** Every fence: the list in `state.fence` (absent = none) then each `state.fence.<gen>-<rand>` by generation. Malformed = 'corrupt' (fail closed). */
function readFences(dir: string): DurableFence[] {
  const out: DurableFence[] = [];
  const p = join(dir, FENCE_FILE);
  if (existsSync(p)) {
    let o: unknown;
    try {
      o = JSON.parse(readFileSync(p, 'utf8'));
    } catch {
      throw new DurableStateError('corrupt', 'state.fence is not valid JSON');
    }
    const r = o as { v?: unknown; fences?: unknown };
    if (typeof o !== 'object' || o === null || r.v !== 1 || !Array.isArray(r.fences)) throw new DurableStateError('corrupt', 'state.fence has an invalid shape');
    for (const f of r.fences) out.push(parseFence(f, 'state.fence'));
  }
  const entries = fenceEntryFiles(dir).sort((a, b) => a.gen - b.gen || (a.name < b.name ? -1 : 1));
  for (const { name, gen } of entries) {
    let o: unknown;
    try {
      o = JSON.parse(readFileSync(join(dir, name), 'utf8'));
    } catch {
      throw new DurableStateError('corrupt', `${name} is not valid JSON`);
    }
    const r = o as { v?: unknown; fence?: unknown };
    if (typeof o !== 'object' || o === null || r.v !== 1) throw new DurableStateError('corrupt', `${name} has an invalid shape`);
    const f = parseFence(r.fence, name);
    if (f.gen !== gen) throw new DurableStateError('corrupt', `${name} names generation ${gen} but holds ${f.gen}`);
    out.push(f);
  }
  return out;
}
function fenceEntryFiles(dir: string): { name: string; gen: number }[] {
  return readdirSync(dir).flatMap((name) => {
    const m = FENCE_ENTRY.exec(name);
    return m ? [{ name, gen: Number(m[1]) }] : [];
  });
}

/**
 * (seq, hash) of the last journal record as it is on disk right now. Absent or unparsable gives (0, zeros): every record
 * then needs the new generation, so an already-broken journal stays refused (fails closed, never opens a gap).
 */
function journalTail(dir: string): { seq: number; h: string } {
  const none = { seq: 0, h: '0'.repeat(64) };
  try {
    const lines = readFileSync(join(dir, 'state.journal'), 'utf8').split('\n').filter((l) => l.length > 0);
    const o = JSON.parse(lines[lines.length - 1] ?? 'null') as { seq?: unknown; h?: unknown } | null;
    return o !== null && typeof o === 'object' && Number.isSafeInteger(o.seq) && (o.seq as number) >= 1 && typeof o.h === 'string' && /^[0-9a-f]{64}$/.test(o.h) ? { seq: o.seq as number, h: o.h } : none;
  } catch {
    return none;
  }
}

/**
 * The operator's CUT (R6-CORE-01). Called while recovery itself HOLDS generation g+1 (so the released holder can no
 * longer pass a re-check and no newer holder exists yet): record that every journal record after the tail seen NOW must
 * come from a generation above `g`. A holder of `g` (or older) that is merely paused and renames its journal late is then
 * refused on load whatever the timing; a record it renamed before this point overwrote nobody and stays. Written before the
 * release, so no new holder can commit ahead of it. Never removed.
 */
function writeFence(dir: string, g: number, beforeRename?: () => void): void {
  readFences(dir); // an unreadable fence set fails closed here too, before anything new is written
  const fence = { gen: g + 1, ...journalTail(dir), from: g, t: Date.now() };
  // its own file under a unique name: no other fence can be lost by this write, whatever the timing (see DurableFence)
  atomicWrite(join(dir, `${FENCE_FILE}.${g + 1}-${randomBytes(6).toString('hex')}`), `${JSON.stringify({ v: 1, fence })}\n`, false, beforeRename);
}

/**
 * TEST ONLY: SIGKILL this process at a named step of operator recovery (or of the takeover of a crashed recovery), to prove
 * that a recovery which itself dies midway is safe and that progress resumes (durable-state-recover-crash.test.ts,
 * formal/tla/DurableFence.tla ROpCrash). Honoured only with NODE_ENV=test; it can only kill the calling process.
 *   recovery: before-lock | after-lock-temp | after-lock | after-fence-temp | after-fence | after-release-temp | after-release
 *   takeover: takeover-after-lock | takeover-after-fence-temp
 */
export const RECOVER_CRASH_ENV = 'PCA_DURABLE_TEST_RECOVER_CRASH_AT';
function testCrashPoint(point: string): void {
  // Stryker disable next-line all: test-only SIGKILL hook; a mutant that fires it kills the test runner itself
  if (process.env['NODE_ENV'] === 'test' && process.env[RECOVER_CRASH_ENV] === point) process.kill(process.pid, 'SIGKILL');
}

type ClassifiedBody =
  | { kind: 'unreadable' }
  | { kind: 'free' }
  | { kind: 'incomplete'; raw: Record<string, unknown> }
  | { kind: 'complete'; body: LockBodyShape };
/** R6-CORE-03: a holder record is COMPLETE only with a numeric pid, a host and a non-empty nonce; JSON that is not a plain object is unreadable. */
function classifyLockFile(path: string): ClassifiedBody {
  let o: unknown;
  try {
    o = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return { kind: 'unreadable' };
  }
  if (typeof o !== 'object' || o === null) return { kind: 'unreadable' };
  if (Array.isArray(o)) return { kind: 'incomplete', raw: o as unknown as Record<string, unknown> }; // readable JSON, no holder fields
  const r = o as Record<string, unknown>;
  if (r['st'] === 'free') return { kind: 'free' };
  if (typeof r['pid'] === 'number' && typeof r['host'] === 'string' && typeof r['nonce'] === 'string' && r['nonce'] !== '') return { kind: 'complete', body: r as unknown as LockBodyShape };
  return { kind: 'incomplete', raw: r };
}

/**
 * R6-CORE-02: is the recorded holder demonstrably ALIVE here? Liveness is judged by PID-namespace identity, not hostname:
 * when the record names a PID namespace and it is ours, kill(pid, 0) and /proc/<pid>/stat are meaningful whatever the
 * hostname says (a UTS namespace, `--pid=host`, a renamed host). Without a namespace in the record (older versions,
 * non-Linux) the hostname is the only evidence. A recycled pid (start time changed) is not the holder.
 */
function holderAliveHere(b: { pid?: unknown; host?: unknown; ns?: unknown; start?: unknown }): boolean {
  if (typeof b.pid !== 'number') return false;
  let myNsNow: string | undefined;
  try {
    myNsNow = readlinkSync('/proc/self/ns/pid');
  } catch {
    myNsNow = undefined;
  }
  const judgeable = typeof b.ns === 'string' ? myNsNow !== undefined && b.ns === myNsNow : b.host === hostname();
  if (!judgeable || !pidAlive(b.pid)) return false;
  if (typeof b.start === 'string') {
    try {
      const st = readFileSync(`/proc/${b.pid}/stat`, 'utf8');
      const cur = st.slice(st.lastIndexOf(')') + 2).split(' ')[19];
      if (cur !== undefined && cur !== b.start) return false; // the pid was reused by a different process
    } catch {
      /* cannot read: treat as alive (refuse) */
    }
  }
  return true;
}

/** Check the operator's attestation against the lock file; throws DurableStateError 'invalid' (nothing changed) on any mismatch. */
function confirmHolder(c: ClassifiedBody, exp: ExpectedLockHolder | 'unreadable', path: string): void {
  if (c.kind === 'unreadable') {
    if (exp !== 'unreadable') throw new DurableStateError('invalid', `${path} is unreadable; pass expectedHolder: 'unreadable' to release it`);
    return;
  }
  if (c.kind === 'incomplete') {
    if (exp !== 'unreadable') {
      throw new DurableStateError('invalid', `${path} has an incomplete holder record (${JSON.stringify(c.raw).slice(0, 160)}); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it`);
    }
    if (holderAliveHere(c.raw)) throw new DurableStateError('invalid', `the holder of ${path} (pid ${String(c.raw['pid'])}) is alive in this PID namespace; refusing to release a live holder`);
    return;
  }
  if (c.kind === 'free') return;
  const body = c.body;
  if (exp === 'unreadable') throw new DurableStateError('invalid', `${path} is readable (holder pid=${body.pid} host=${body.host}); expectedHolder 'unreadable' does not match`);
  if (body.host !== exp.host || body.pid !== exp.pid || body.nonce !== exp.nonce) {
    throw new DurableStateError('invalid', `expectedHolder does not match the holder recorded in ${path} (recorded pid=${body.pid} host=${body.host} nonce=${body.nonce}); nothing was changed`);
  }
  if (holderAliveHere(body)) throw new DurableStateError('invalid', `the holder of ${path} (pid ${body.pid}) is alive in this PID namespace; refusing to release a live holder`);
}

/**
 * Operator recovery for a lock whose holder cannot be judged dead automatically (a holder in ANOTHER PID namespace or
 * under a changed hostname, an unreadable or incomplete top lock file, or a legacy single-file `state.lock`), which
 * otherwise gives `lock-timeout` forever.
 *
 * Out of band: the lock protocol is unchanged. Recovery takes the lock itself (generation g+1), cuts and FENCES the
 * released generation (writes `state.fence`, see writeFence), then appends a "free" generation g+2, exactly like a
 * release. A late-resuming old holder that is anywhere
 * before its pre-rename re-check fails with `lock-lost` and writes nothing; one paused exactly between its re-check and its
 * rename (an unavoidable window with rename(2)) still renames, and that late journal is REFUSED on load by the fence
 * (fail closed, 'corrupt'; the newer holder's records after the cut are then lost from the live journal, which is
 * detected, never silent). A late head from it is recognised and repaired. So recovery is safe against a PAUSED holder by
 * construction; it is still the operator's attestation that the holder is gone, and attesting a running holder costs
 * availability (fail closed), never integrity.
 * The caller proves it looked at the right lock by passing the recorded `{host, pid, nonce}` EXACTLY (or `'unreadable'`
 * for an unreadable/incomplete record); any difference is refused. A holder that is demonstrably alive in this PID
 * namespace (whatever its hostname) is never released.
 * Throws DurableStateError 'invalid' on a mismatch / live holder / bad arguments.
 */
export function recoverDurableState(opts: RecoverDurableStateOptions): RecoverDurableStateResult {
  if (typeof opts !== 'object' || opts === null || opts.force !== true) throw new DurableStateError('invalid', 'recoverDurableState requires force: true');
  const exp = opts.expectedHolder;
  if (exp !== 'unreadable' && (typeof exp !== 'object' || exp === null || typeof exp.host !== 'string' || typeof exp.pid !== 'number' || typeof exp.nonce !== 'string' || exp.nonce === '')) {
    throw new DurableStateError('invalid', "expectedHolder must be { host, pid, nonce } as recorded in the lock file, or 'unreadable'");
  }
  const dir = opts.dir;
  let g = 0;
  for (const f of readdirSync(dir)) {
    const m = /^state\.lock\.(\d+)$/.exec(f);
    if (m && Number(m[1]) > g) g = Number(m[1]);
  }
  const path = join(dir, `state.lock.${g}`);
  const top: ClassifiedBody | undefined = g === 0 ? undefined : classifyLockFile(path);
  const legacyPath = join(dir, 'state.lock');
  if (opts.legacyLock === true) {
    if (top !== undefined && top.kind !== 'free') {
      throw new DurableStateError('invalid', `legacyLock: true, but the blocking lock is the generation lock ${path}; call recoverDurableState without legacyLock`);
    }
    if (!existsSync(legacyPath)) return { released: false, reason: 'not-held' };
    const legacy = classifyLockFile(legacyPath);
    if (legacy.kind === 'free') return { released: false, reason: 'not-held', lockFile: legacyPath };
    confirmHolder(legacy, exp, legacyPath);
    // A legacy (older-version) writer stamps no generation (reads as 0): every record after the cut needs >= g + 1 >= 1.
    writeFence(dir, g);
    renameSync(legacyPath, join(dir, `state.lock.legacy-recovered-${Date.now()}-${randomBytes(3).toString('hex')}`));
    fsyncDir(dir);
    return { released: true, reason: 'released', lockFile: legacyPath };
  }
  if (top === undefined || top.kind === 'free') {
    if (existsSync(legacyPath)) {
      const lb = classifyLockFile(legacyPath);
      const who = lb.kind === 'complete' ? `holder pid=${lb.body.pid} host=${lb.body.host} nonce=${lb.body.nonce}` : `${lb.kind} holder record`;
      throw new DurableStateError('invalid', `the blocking lock is the legacy single-file ${legacyPath} (${who}); after confirming that holder is gone, pass legacyLock: true with its expectedHolder (or 'unreadable')`);
    }
    return top === undefined ? { released: false, reason: 'not-held' } : { released: false, reason: 'not-held', lockFile: path };
  }
  confirmHolder(top, exp, path);
  // R6-CORE-01, in this order (formal/tla/DurableFence.tla; the other orders fail there):
  //   1. TAKE the lock: generation g+1, held by this recovery. From here the released holder's re-checks fail, and no
  //      newer holder can exist until step 4. EEXIST = the holder released (it was alive after all): abort, nothing written.
  //   2. CUT: read the journal tail S under that lock. Anything the released holder renamed before this point is a
  //      complete commit nobody has built past (accepted, as if it committed just before recovery); anything after is late.
  //   3. FENCE: records after S must come from generation >= g+1 (the released one and older are refused on load).
  //   4. RELEASE: generation g+2 "free".
  // RECOVERY ITSELF MAY CRASH after any of these steps (formal/tla/DurableFence.tla ROpCrash: Safe and the liveness
  // properties hold). Before 1 nothing changed. From 1 on, generation g+1 is held by this (now dead) process and is marked
  // `recovering`: a waiter in the same PID namespace judges it dead and takes it over, and because of the mark it first
  // cuts and fences under its OWN generation, before it loads (its lock carries the mark on, so a taker that dies before its
  // fence lands passes the duty to the next one). A waiter in another PID namespace cannot judge it and times out; the
  // operator runs recovery again on it (its lock-timeout names this process). Either way the paused holder of g stays fenced
  // whether or not this process got to write its own fence: a crashed cut is simply retaken later.
  const linkBody = (gen: number, body: Record<string, unknown>, crashPoint: string): void => {
    const tmp = join(dir, `state.lock.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
    const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    try {
      writeSync(fd, JSON.stringify(body));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    testCrashPoint(crashPoint);
    try {
      linkSync(tmp, join(dir, `state.lock.${gen}`));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EEXIST') throw new DurableStateError('invalid', `${path} was superseded while recovering; re-read the lock state and retry`);
      throw e;
    } finally {
      try {
        unlinkSync(tmp);
      } catch {
        /* best effort */
      }
    }
  };
  let ns: string | undefined;
  try {
    ns = readlinkSync('/proc/self/ns/pid');
  } catch {
    ns = undefined;
  }
  testCrashPoint('before-lock');
  // `start` lets a waiter tell this process from a later one that reuses its pid (else the crashed recovery would look alive).
  const start = procStartOf(process.pid);
  linkBody(g + 1, { st: 'held', pid: process.pid, host: hostname(), nonce: randomBytes(12).toString('hex'), boot: BOOT_ID, ...(ns !== undefined ? { ns } : {}), ...(start !== undefined ? { start } : {}), recovering: g, t: Date.now() }, 'after-lock-temp');
  testCrashPoint('after-lock');
  writeFence(dir, g, () => testCrashPoint('after-fence-temp'));
  testCrashPoint('after-fence');
  linkBody(g + 2, { st: 'free', t: Date.now(), recoveredFrom: g }, 'after-release-temp');
  testCrashPoint('after-release');
  return { released: true, reason: 'released', lockFile: path };
}
interface LockBodyShape {
  st: 'held' | 'free';
  pid: number;
  host: string;
  nonce: string;
  start: string;
  ns: string;
}

export interface DurableState extends DurableKv {
  /** True when this open quarantined corrupt state (see `recoverFromCorruption`). */
  readonly recovered: boolean;
  /** Highest chain position this handle has observed. */
  position(): { seq: number; hash: string };
  /** Verify the chain from disk now; throws DurableStateError on any problem. */
  verify(): Promise<{ seq: number; hash: string }>;
}

const DOMAIN = 'pca-durable-state/v1\n';
const GENESIS = '0'.repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const MAX_KEY = 256;

interface Rec {
  seq: number;
  prev: string;
  op: 'set' | 'checkpoint';
  payload: string;
  ts: number;
  /** R6-CORE-01: the writer's lock generation (>= 1). Absent in records written by older versions (read as 0). */
  gen?: number;
  h: string;
  mac?: string;
}
interface Head {
  seq: number;
  h: string;
  /** R6-CORE-01: the lock generation of the process that wrote this head (absent = older version, read as 0). */
  gen?: number;
  mac?: string;
}

const sha = (s: string): string => createHash('sha256').update(s).digest('hex');
// The generation is inside the hash (and so under the record MAC): it cannot be edited without breaking the chain. A record
// without `gen` hashes exactly as older versions did, so existing journals stay valid.
const recHash = (r: Pick<Rec, 'seq' | 'prev' | 'op' | 'payload' | 'ts' | 'gen'>): string =>
  sha(DOMAIN + JSON.stringify(r.gen === undefined ? [r.seq, r.prev, r.op, r.payload, r.ts] : [r.seq, r.prev, r.op, r.payload, r.ts, r.gen]));
const macOf = (key: Uint8Array, msg: string): string => createHmac('sha256', key).update(msg).digest('hex');
const macEq = (a: string, b: string): boolean => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const headMsg = (seq: number, h: string, gen?: number): string => (gen === undefined ? `head\n${seq}\n${h}` : `head\n${seq}\n${h}\n${gen}`);
const isGen = (x: unknown): boolean => Number.isSafeInteger(x) && (x as number) >= 1;

function fsyncDir(dir: string): void {
  const fd = openSync(dir, constants.O_RDONLY);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function atomicWrite(path: string, data: string, crashAfterTemp: boolean, beforeRename?: () => void): void {
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  // Stryker disable next-line all: test-only SIGKILL hook; a mutant that fires it kills the test runner itself
  if (crashAfterTemp) process.kill(process.pid, 'SIGKILL');
  if (beforeRename) {
    try {
      beforeRename();
    } catch (e) {
      try {
        unlinkSync(tmp);
      } catch {
        /* best effort: the orphan temp is harmless */
      }
      throw e;
    }
  }
  renameSync(tmp, path);
  fsyncDir(join(path, '..'));
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Random per-process id recorded in every lock generation this process creates (R4-09). */
const BOOT_ID = randomBytes(12).toString('hex');

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** Process start time (field 22 of /proc/<pid>/stat), undefined off Linux or when gone. */
function procStartOf(pid: number): string | undefined {
  try {
    const st = readFileSync(`/proc/${pid}/stat`, 'utf8');
    return st.slice(st.lastIndexOf(')') + 2).split(' ')[19];
  } catch {
    return undefined;
  }
}

interface Loaded {
  recs: Rec[];
  state: Map<string, string>;
  head: Head | undefined;
}

/** Open (creating if needed) a durable state directory. THROWS DurableStateError on corrupt/rolled-back state unless recovering. */
export async function openDurableState(opts: DurableStateOptions): Promise<DurableState> {
  if (typeof opts?.dir !== 'string' || opts.dir.length === 0) throw new DurableStateError('invalid', 'dir is required');
  if (opts.hmacKey !== undefined && opts.hmacKey.length < 32) throw new DurableStateError('invalid', 'hmacKey must be at least 32 bytes');
  const dir = opts.dir;
  const key = opts.hmacKey;
  const lockTimeout = opts.lockTimeoutMs ?? 10_000;
  const compactEvery = Math.max(2, opts.compactEvery ?? 256);
  const maxValue = opts.maxValueBytes ?? 1_048_576;
  const now = opts.now ?? Date.now;
  const journalPath = join(dir, 'state.journal');
  const headPath = join(dir, 'state.head');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    /* not ours to chmod (e.g. a shared parent); keep going */
  }

  let seen: { seq: number; hash: string } = { seq: 0, hash: GENESIS };
  let recovered = false;
  /** Nonce of the lock this handle currently holds (set by withLock; the critical sections are synchronous, so one slot suffices). */
  let heldNonce: string | undefined;

  const readHead = (): Head | undefined => {
    if (!existsSync(headPath)) return undefined;
    let o: unknown;
    try {
      o = JSON.parse(readFileSync(headPath, 'utf8'));
    } catch {
      throw new DurableStateError('corrupt', 'state.head is not valid JSON');
    }
    const r = o as Record<string, unknown>;
    if (typeof o !== 'object' || o === null || !Number.isSafeInteger(r['seq']) || (r['seq'] as number) < 0 || typeof r['h'] !== 'string' || !HEX64.test(r['h']) || (r['gen'] !== undefined && !isGen(r['gen']))) {
      throw new DurableStateError('corrupt', 'state.head has an invalid shape');
    }
    const head: Head = { seq: r['seq'] as number, h: r['h'], ...(r['gen'] !== undefined ? { gen: r['gen'] as number } : {}) };
    if (typeof r['mac'] === 'string') head.mac = r['mac'];
    if (key) {
      if (head.mac === undefined || !macEq(head.mac, macOf(key, headMsg(head.seq, head.h, head.gen)))) throw new DurableStateError('key-mismatch', 'state.head MAC does not verify (wrong key or forged head)');
    }
    return head;
  };

  const load = (): Loaded => {
    const head = readHead();
    const fences = readFences(dir);
    const jExists = existsSync(journalPath);
    if (!jExists) {
      if (head !== undefined && head.seq > 0) throw new DurableStateError('rollback', `state.journal is missing but state.head records seq ${head.seq}`);
      const cut = fences.find((f) => f.seq > 0);
      if (cut !== undefined) throw new DurableStateError('rollback', `state.journal is missing but operator recovery cut it at seq ${cut.seq}`);
      if (seen.seq > 0) throw new DurableStateError('rollback', 'state was deleted while open');
      return { recs: [], state: new Map(), head };
    }
    const text = readFileSync(journalPath, 'utf8');
    const lines = text.split('\n');
    if (lines[lines.length - 1] !== '') throw new DurableStateError('corrupt', 'journal does not end with a newline (torn or truncated)');
    lines.pop();
    const recs: Rec[] = [];
    const state = new Map<string, string>();
    let prevHash = GENESIS;
    let prevSeq = 0;
    let prevGen = 0;
    for (const [i, line] of lines.entries()) {
      let o: unknown;
      try {
        o = JSON.parse(line);
      } catch {
        throw new DurableStateError('corrupt', `journal line ${i + 1} is not valid JSON`);
      }
      const r = o as Record<string, unknown>;
      if (
        typeof o !== 'object' || o === null || !Number.isSafeInteger(r['seq']) || typeof r['prev'] !== 'string' || !HEX64.test(r['prev']) ||
        (r['op'] !== 'set' && r['op'] !== 'checkpoint') || typeof r['payload'] !== 'string' || !Number.isSafeInteger(r['ts']) || typeof r['h'] !== 'string' || !HEX64.test(r['h']) ||
        (r['gen'] !== undefined && !isGen(r['gen']))
      ) {
        throw new DurableStateError('corrupt', `journal line ${i + 1} has an invalid shape`);
      }
      const rec: Rec = {
        seq: r['seq'] as number, prev: r['prev'], op: r['op'], payload: r['payload'], ts: r['ts'] as number,
        ...(r['gen'] !== undefined ? { gen: r['gen'] as number } : {}),
        h: r['h'], ...(typeof r['mac'] === 'string' ? { mac: r['mac'] } : {}),
      };
      if (i === 0) {
        if (rec.op === 'set' && (rec.seq !== 1 || rec.prev !== GENESIS)) throw new DurableStateError('corrupt', 'journal does not start at genesis');
        if (rec.op === 'checkpoint' && rec.seq < 1) throw new DurableStateError('corrupt', 'bad checkpoint seq');
      } else {
        if (rec.seq !== prevSeq + 1) throw new DurableStateError('corrupt', `journal line ${i + 1}: sequence gap`);
        if (rec.prev !== prevHash) throw new DurableStateError('corrupt', `journal line ${i + 1}: hash chain broken`);
      }
      if (recHash(rec) !== rec.h) throw new DurableStateError('corrupt', `journal line ${i + 1}: record hash mismatch (edited)`);
      if (key) {
        if (rec.mac === undefined || !macEq(rec.mac, macOf(key, rec.h))) throw new DurableStateError('key-mismatch', `journal line ${i + 1}: MAC does not verify (wrong key or forged record)`);
      } else if (rec.mac !== undefined) {
        throw new DurableStateError('key-mismatch', 'journal is MAC-tagged but no hmacKey was supplied');
      }
      // R6-CORE-01 generation fencing (the record is authentic here: hash and MAC verified above). Legitimate writers hold
      // strictly increasing lock generations, so generations never decrease along the chain; a record from a generation
      // that operator recovery fenced off, after the journal position the operator cut at, is a paused holder's late write.
      const rg = rec.gen ?? 0;
      if (rg < prevGen) {
        throw new DurableStateError('corrupt', `journal line ${i + 1} (seq ${rec.seq}) was written by lock generation ${rg}, older than generation ${prevGen} of an earlier record: a stale writer's record (refused)`);
      }
      for (const f of fences) {
        if (rec.seq > f.seq && rg < f.gen) {
          throw new DurableStateError(
            'corrupt',
            `journal line ${i + 1} (seq ${rec.seq}) was written by lock generation ${rg}, but operator recovery fenced generations below ${f.gen} after seq ${f.seq}: a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)`,
          );
        }
      }
      prevGen = rg;
      if (rec.op === 'checkpoint') {
        let entries: unknown;
        try {
          entries = JSON.parse(rec.payload);
        } catch {
          throw new DurableStateError('corrupt', 'checkpoint payload is not JSON');
        }
        if (!Array.isArray(entries)) throw new DurableStateError('corrupt', 'checkpoint payload is not an array');
        state.clear();
        for (const e of entries) {
          if (!Array.isArray(e) || e.length !== 2 || typeof e[0] !== 'string' || typeof e[1] !== 'string') throw new DurableStateError('corrupt', 'checkpoint entry is malformed');
          state.set(e[0], e[1]);
        }
      } else {
        const nl = rec.payload.indexOf('\n');
        if (nl < 1) throw new DurableStateError('corrupt', `journal line ${i + 1}: malformed payload`);
        state.set(rec.payload.slice(0, nl), rec.payload.slice(nl + 1));
      }
      recs.push(rec);
      prevHash = rec.h;
      prevSeq = rec.seq;
    }
    const last = recs[recs.length - 1];
    const lastSeq = last?.seq ?? 0;
    // R6-CORE-01: the journal must EXTEND the exact journal each recovery cut at (it reaches the cut, and the record at the
    // cut is the one the operator saw, unless a later generation compacted past it).
    for (const f of fences) {
      if (lastSeq < f.seq) throw new DurableStateError('rollback', `journal is at seq ${lastSeq} but operator recovery cut it at seq ${f.seq} (truncation, or a stale writer replaced it)`);
      const atCut = recs.find((r) => r.seq === f.seq);
      if (f.seq > 0 && atCut !== undefined && atCut.h !== f.h) {
        throw new DurableStateError('corrupt', `journal record at seq ${f.seq} is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)`);
      }
    }
    if (head !== undefined) {
      const hg = head.gen ?? 0;
      if (lastSeq < head.seq) throw new DurableStateError('rollback', `journal is at seq ${lastSeq} but state.head recorded seq ${head.seq} (truncation or older copy)`);
      // R6-CORE-01: the head is written by the lock holder of generation `hg`; any record AFTER it, or a different record
      // AT its position, from a LOWER generation was written by a writer that had already lost the lock to `hg`.
      if (last !== undefined && (last.gen ?? 0) < hg && (lastSeq === head.seq + 1 || (lastSeq === head.seq && last.h !== head.h))) {
        throw new DurableStateError('corrupt', `journal tail (seq ${lastSeq}) was written by lock generation ${last.gen ?? 0}, older than generation ${hg} that wrote state.head: a stale writer replaced the journal (refused)`);
      }
      // R6-CORE-01 stale LATE head: a holder paused between its journal rename and its head rename resumes after operator
      // recovery and writes a head for ITS record while newer generations have extended the journal past the cut. Exactly
      // that shape is recognised and the head is repaired by the next writer: the head's generation is below a fence, its
      // position is at or before that fence's cut (its record was committed before the recovery), newer generations wrote
      // past the cut (the fence check above already proved every record after the cut is theirs), and the journal still
      // holds the very record the head names. Anything else more than one record ahead stays 'corrupt'.
      const staleHead =
        lastSeq > head.seq + 1 &&
        fences.some((f) => hg < f.gen && head.seq <= f.seq && lastSeq > f.seq) &&
        recs.some((r) => r.seq === head.seq && r.h === head.h);
      if (lastSeq > head.seq + 1 && !staleHead) throw new DurableStateError('corrupt', `journal (seq ${lastSeq}) is more than one record ahead of state.head (seq ${head.seq})`);
      if (last !== undefined) {
        if (lastSeq === head.seq && last.h !== head.h) throw new DurableStateError('corrupt', 'journal tail does not match state.head');
        if (lastSeq === head.seq + 1 && last.prev !== head.h) throw new DurableStateError('corrupt', 'journal tail is not chained from state.head');
      }
    } else if (lastSeq > 1) {
      throw new DurableStateError('rollback', `state.head is missing but the journal is at seq ${lastSeq}`);
    }
    if (last !== undefined) {
      if (last.seq < seen.seq) throw new DurableStateError('rollback', `state moved backwards from seq ${seen.seq} to ${last.seq} while open`);
      if (last.seq === seen.seq && last.h !== seen.hash) throw new DurableStateError('rollback', `state forked at seq ${last.seq} while open`);
    } else if (seen.seq > 0) {
      throw new DurableStateError('rollback', 'state was emptied while open');
    }
    return { recs, state, head };
  };

  const quarantine = (): void => {
    const tag = `${now()}-${randomBytes(3).toString('hex')}`;
    assertLockHeld(); // a writer that lost the lock must not move a newer holder's files aside
    // After an operator recovery the journal restarts from genesis, so the old cuts no longer describe it. The fence is
    // replaced (old one kept aside) by "every record from genesis on needs generation >= mine": a paused holder of ANY
    // older generation stays refused. Without a prior recovery there is no fence and none is created.
    // Order: the genesis fence lands BEFORE the old fences are moved aside, so no instant is left without a fence. A crash in
    // between leaves old cuts that the (not yet quarantined) old journal still satisfies or fails: fail closed, run again.
    const fencePath = join(dir, FENCE_FILE);
    const oldEntries = fenceEntryFiles(dir);
    if (existsSync(fencePath) || oldEntries.length > 0) {
      if (existsSync(fencePath)) linkSync(fencePath, `${fencePath}.quarantine-${tag}`); // keep the old one; the list file itself is never absent
      atomicWrite(fencePath, `${JSON.stringify({ v: 1, fences: [{ gen: myGen, seq: 0, h: GENESIS, from: myGen - 1, t: now() }] })}\n`, false);
      for (const { name } of oldEntries) renameSync(join(dir, name), join(dir, `${name}.quarantine-${tag}`));
    }
    for (const p of [journalPath, headPath]) {
      if (existsSync(p)) renameSync(p, `${p}.quarantine-${tag}`);
    }
    fsyncDir(dir);
    seen = { seq: 0, hash: GENESIS };
    recovered = true;
  };

  const loadOrRecover = (): Loaded => {
    try {
      return load();
    } catch (e) {
      if (opts.recoverFromCorruption === true && e instanceof DurableStateError) {
        quarantine();
        return load();
      }
      throw e;
    }
  };

  const observe = (l: Loaded): void => {
    const last = l.recs[l.recs.length - 1];
    if (last && last.seq >= seen.seq) seen = { seq: last.seq, hash: last.h };
  };

  // ---- the lock: immutable, numbered generation files (see formal/tla/DurableLockGen.tla) ----
  //   state.lock.<g>  g >= 1, created atomically WITH its body by link(2) (never torn, never renamed, never rewritten).
  //   The lock belongs to the process named in the highest-numbered file ("held") or is free ("free"). The only way to
  //   take it is to create generation g+1, and link(2) lets exactly one creator win (a creator re-checks that its generation
  //   is still the highest: garbage collection could otherwise let a stale creator re-create a removed one). A live holder is NEVER superseded:
  //   a lock is breakable only when its holder is provably dead on this host (kill(pid,0) fails, or the pid's start time
  //   changed). A stalled-but-alive holder keeps the lock; waiters time out (fail closed) instead of stealing it, so
  //   there is no stale-lock theft, no rename of a fresh lock, and no stalled owner resuming inside a lock given away.
  //   A legacy single file state.lock (older versions) is honoured as an additional holder but never touched.
  interface LockBody {
    st: 'held' | 'free';
    pid?: number;
    host?: string;
    nonce?: string;
    start?: string;
    /** R4-09: the holder's PID namespace id (Linux `/proc/self/ns/pid`); liveness is judged only inside the same one. */
    ns?: string;
    /** R4-09: a per-process random boot id (distinguishes two processes that share pid, host and namespace over time). */
    boot?: string;
    /** Set on a lock taken by operator recovery (the generation it recovers), and carried on by whoever takes such a lock over
     *  from a dead holder: the taker must cut and fence first (the recovery may have died before its own fence landed). */
    recovering?: number;
    t?: number;
  }
  const lockFile = (g: number): string => join(dir, `state.lock.${g}`);
  const legacyLock = join(dir, 'state.lock');
  const procStart = (pid: number): string | undefined => {
    try {
      const st = readFileSync(`/proc/${pid}/stat`, 'utf8');
      return st.slice(st.lastIndexOf(')') + 2).split(' ')[19];
    } catch {
      return undefined; // not Linux (macOS: pid reuse after a crash holds the lock until timeout, i.e. fails closed), or gone
    }
  };
  // R4-09: containers that share this directory AND a hostname live in different PID namespaces, where kill(pid, 0) and the
  // start time of "that pid" describe an unrelated process or none. Liveness is therefore judged only inside one PID namespace.
  const myNs = ((): string | undefined => {
    try {
      return readlinkSync('/proc/self/ns/pid');
    } catch {
      return undefined; // not Linux
    }
  })();
  const myStart = procStart(process.pid);
  const readBody = (path: string): LockBody | undefined => {
    try {
      const o = JSON.parse(readFileSync(path, 'utf8')) as Partial<LockBody>;
      if (typeof o !== 'object' || o === null) return undefined;
      return { st: o.st === 'free' ? 'free' : 'held', ...(typeof o.pid === 'number' ? { pid: o.pid } : {}), ...(typeof o.host === 'string' ? { host: o.host } : {}), ...(typeof o.nonce === 'string' ? { nonce: o.nonce } : {}), ...(typeof o.start === 'string' ? { start: o.start } : {}), ...(typeof o.ns === 'string' ? { ns: o.ns } : {}), ...(typeof o.boot === 'string' ? { boot: o.boot } : {}), ...(Number.isSafeInteger(o.recovering) ? { recovering: o.recovering as number } : {}) };
    } catch {
      return undefined;
    }
  };
  /** Highest numbered generation: { g, body } (g = 0 and no body when there is none). body undefined = unreadable. */
  const topLock = (): { g: number; body: LockBody | undefined } => {
    let g = -1;
    for (const f of readdirSync(dir)) {
      const m = /^state\.lock\.(\d+)$/.exec(f);
      if (m && Number(m[1]) > g) g = Number(m[1]);
    }
    return g >= 1 ? { g, body: readBody(lockFile(g)) } : { g: 0, body: undefined };
  };
  const holderDead = (b: LockBody | undefined, legacyAgeMs: number): boolean => {
    if (b === undefined) return legacyAgeMs > 1000; // an unreadable legacy file (torn by an old version) older than 1 s
    if (b.host !== hostname() || typeof b.pid !== 'number') return false; // another host: cannot judge, never break
    if (b.ns !== undefined && b.ns !== myNs) return false; // another PID namespace (container) or unknowable: cannot judge, never break
    if (!pidAlive(b.pid)) return true;
    if (b.start !== undefined) {
      const now = procStart(b.pid);
      if (now !== undefined && now !== b.start) return true; // the pid was reused by a different process
    }
    return false;
  };
  /** Create generation g atomically with its body. false = somebody else created it first. */
  const createGen = (g: number, body: LockBody): boolean => {
    const tmp = join(dir, `state.lock.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
    const fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    try {
      writeSync(fd, JSON.stringify({ ...body, t: Date.now() }));
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      linkSync(tmp, lockFile(g));
      return true;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'EEXIST') return false;
      throw new DurableStateError('invalid', `the state directory's filesystem cannot create the lock atomically (link: ${code ?? 'error'})`);
    } finally {
      try {
        unlinkSync(tmp);
      } catch {
        /* best effort */
      }
    }
  };
  const gcLocks = (keepFrom: number): void => {
    try {
      for (const f of readdirSync(dir)) {
        const m = /^state\.lock\.(\d+)$/.exec(f);
        if (m && Number(m[1]) < keepFrom) unlinkSync(join(dir, f));
        else if (/^state\.lock\.tmp-/.test(f)) {
          const pid = Number(/^state\.lock\.tmp-(\d+)-/.exec(f)?.[1]);
          if (pid && !pidAlive(pid)) unlinkSync(join(dir, f));
        }
      }
    } catch {
      /* best effort */
    }
  };
  let myGen = -1;

  /** Fail closed at open time when this filesystem cannot give the lock its atomic hard-link semantics. */
  const probeLinks = (): void => {
    const a = join(dir, `state.probe-${process.pid}-${randomBytes(6).toString('hex')}`);
    const b = `${a}.lnk`;
    try {
      writeFileSync(a, 'probe', { mode: 0o600, flag: 'wx' });
      linkSync(a, b);
      let second = false;
      try {
        linkSync(a, b); // must fail with EEXIST: exclusive create
      } catch (e) {
        second = (e as NodeJS.ErrnoException).code === 'EEXIST';
      }
      if (!second || statSync(a).nlink !== 2) throw new Error('link(2) is not atomic/exclusive here');
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      throw new DurableStateError('link-unsupported', `the state directory's filesystem does not provide working hard links with exclusive-create semantics (${code ?? (e as Error).message}); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE`);
    } finally {
      for (const f of [a, b]) {
        try {
          unlinkSync(f);
        } catch {
          /* best effort */
        }
      }
    }
  };

  async function withLock<T>(fn: () => T): Promise<T> {
    const nonce = randomBytes(12).toString('hex');
    let mustFence = false;
    const deadline = Date.now() + lockTimeout;
    for (;;) {
      const top = topLock();
      // A single-file state.lock left by (or still used by) an older version counts as a holder too: wait for it unless
      // its owner is provably dead. We never delete or rename it (do not mix versions on one directory).
      let legacyBlocks = false;
      if (existsSync(legacyLock)) {
        let age = 0;
        try {
          age = Date.now() - statSync(legacyLock).mtimeMs;
        } catch {
          /* vanished */
        }
        legacyBlocks = !holderDead(readBody(legacyLock), age);
      }
      const free = top.g === 0 || top.body?.st === 'free';
      if (!legacyBlocks && (free || holderDead(top.body, 0))) {
        // Taking over a DEAD holder whose lock is marked `recovering` (an operator recovery, or a taker of one, that died
        // midway): carry the mark and cut + fence before loading (formal/tla/DurableFence.tla TakeoverFence, Inherit).
        const recovering = !free ? top.body?.recovering : undefined;
        if (createGen(top.g + 1, { st: 'held', pid: process.pid, host: hostname(), nonce, boot: BOOT_ID, ...(myNs !== undefined ? { ns: myNs } : {}), ...(myStart !== undefined ? { start: myStart } : {}), ...(recovering !== undefined ? { recovering } : {}) })) {
          // The generation must still be the HIGHEST one. A creator working from a stale directory view can re-create a
          // generation that garbage collection already removed (ABA); that grab is buried below the real top and is not a lock.
          if (topLock().g !== top.g + 1) continue;
          myGen = top.g + 1;
          mustFence = recovering !== undefined;
          break;
        }
        continue; // lost the race for that generation: look again immediately
      }
      if (Date.now() > deadline) {
        const desc = (b: LockBody | undefined): string =>
          b === undefined
            ? 'an unreadable holder record'
            : typeof b.pid !== 'number' || b.host === undefined || b.nonce === undefined || b.nonce === ''
              ? `an incomplete holder record (pid=${b.pid ?? '?'} host=${b.host ?? '?'} nonce=${b.nonce || '?'}); release it with expectedHolder: 'unreadable'`
              : `holder pid=${b.pid} host=${b.host} nonce=${b.nonce}${b.ns !== undefined && b.ns !== myNs ? ' (another PID namespace)' : ''}`;
        // R6-CORE-03: name the file that actually blocks (the legacy single-file lock is not a generation).
        if (legacyBlocks && (free || holderDead(top.body, 0))) {
          throw new DurableStateError('lock-timeout', `could not acquire the state lock in ${dir} within ${lockTimeout} ms; blocked by ${legacyLock} (legacy single-file lock of an older version; ${desc(readBody(legacyLock))}). If that holder is provably gone, an operator can release it with recoverDurableState({ dir, force: true, legacyLock: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs`);
        }
        throw new DurableStateError('lock-timeout', `could not acquire the state lock in ${dir} within ${lockTimeout} ms; blocked by ${lockFile(top.g)} (${desc(top.body)}). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({ dir, force: true, expectedHolder }) after confirming the holder is dead; see the durable-state docs`);
      }
      await sleep(5 + Math.floor(Math.random() * 15));
    }
    heldNonce = nonce;
    gcLocks(myGen - 16);
    try {
      if (mustFence) {
        // The recovery we took over may have died before (or after) writing its fence; either way the holder it was
        // releasing may be merely paused. Cut and fence now, under OUR generation, before anything is loaded: every record
        // after the journal tail seen now needs generation >= myGen, so that holder's late journal is refused. (A late
        // rename that landed before this cut overwrote nobody: it is part of the state we cut at, as in recovery.)
        testCrashPoint('takeover-after-lock');
        writeFence(dir, myGen - 1, () => testCrashPoint('takeover-after-fence-temp'));
      }
      return fn();
    } finally {
      heldNonce = undefined;
      try {
        createGen(myGen + 1, { st: 'free' }); // release; a live holder is never superseded, so this cannot lose a race
        gcLocks(myGen - 15);
      } catch {
        /* the lock stays "held" by a process that is about to be judged dead or alive by its pid: still safe */
      }
    }
  }

  /**
   * Immediately before EVERY rename this writer makes (journal, head, quarantine): this handle's generation must still be
   * the highest and must still name us. Without operator recovery it cannot fail (a live holder is never superseded). After
   * recoverDurableState released a holder that was only PAUSED, it is what makes the resumed holder fail with 'lock-lost'.
   * It is NOT sufficient alone: a holder paused between this check and its rename(2) still renames when it resumes. That
   * residual window is closed on the READ side, by construction: every record and head carries `myGen`, and the fence
   * recovery wrote makes load() refuse a late record from a released generation (see load()).
   */
  const assertLockHeld = (outcome = 'nothing was written'): void => {
    const top = topLock();
    if (heldNonce === undefined || top.g !== myGen || top.body?.st !== 'held' || top.body.nonce !== heldNonce) {
      throw new DurableStateError('lock-lost', `the state lock is no longer held by this writer (generation ${myGen}, highest ${top.g} ${top.body?.st ?? 'unreadable'}); ${outcome}`);
    }
  };

  const commit = (l: Loaded, key_: string, valueJson: string): void => {
    const last = l.recs[l.recs.length - 1];
    const seq = (last?.seq ?? 0) + 1;
    const prev = last?.h ?? GENESIS;
    const base = { seq, prev, op: 'set' as const, payload: `${key_}\n${valueJson}`, ts: now(), gen: myGen };
    const rec: Rec = { ...base, h: recHash(base) };
    if (key) rec.mac = macOf(key, rec.h);
    let all = [...l.recs, rec];
    if (all.length > compactEvery) {
      // Compact: ONE checkpoint at the same seq the new record would have, chained from the current tail and
      // carrying the full state (including the new value). Head lag stays at most one record.
      const next = new Map(l.state);
      next.set(key_, valueJson);
      const cb = { seq, prev, op: 'checkpoint' as const, payload: JSON.stringify([...next.entries()].sort((x, y) => (x[0] < y[0] ? -1 : 1))), ts: now(), gen: myGen };
      const cp: Rec = { ...cb, h: recHash(cb) };
      if (key) cp.mac = macOf(key, cp.h);
      all = [cp];
    }
    const tail = all[all.length - 1]!;
    // Journal first (atomic), head second (atomic). A crash between leaves head one record behind: repaired below.
    // The lock re-check runs AFTER the temp file is written and fsynced, i.e. as close to the rename as possible.
    // Stryker disable next-line all: test-only SIGKILL hook; a mutant that fires it kills the test runner itself
    const crashAfterTemp = opts.testCrashAt === 'after-temp-write';
    atomicWrite(journalPath, `${all.map((r) => JSON.stringify(r)).join('\n')}\n`, crashAfterTemp, assertLockHeld);
    // Stryker disable next-line all: test-only SIGKILL hook; a mutant that fires it kills the test runner itself
    if (opts.testCrashAt === 'after-journal-rename') process.kill(process.pid, 'SIGKILL');
    writeHead(tail, `the journal record (seq ${tail.seq}) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)`);
    seen = { seq: tail.seq, hash: tail.h };
  };

  /** Head write, stamped with this writer's generation and guarded by the same lock re-check as the journal (R6-CORE-01). */
  const writeHead = (tail: Rec, outcome = 'nothing was written'): void => {
    const head: Head = { seq: tail.seq, h: tail.h, gen: myGen };
    if (key) head.mac = macOf(key, headMsg(head.seq, head.h, head.gen));
    atomicWrite(headPath, `${JSON.stringify(head)}\n`, false, () => assertLockHeld(outcome));
  };

  const encode = (value: unknown): string => {
    const s = JSON.stringify(value);
    if (s === undefined) throw new DurableStateError('invalid', 'value is not JSON-serialisable');
    if (s.length > maxValue) throw new DurableStateError('too-large', `value exceeds maxValueBytes=${maxValue}`);
    return s;
  };
  const checkKey = (k: string): void => {
    if (typeof k !== 'string' || k.length === 0 || k.length > MAX_KEY || k.includes('\n')) throw new DurableStateError('invalid', 'key must be 1..256 chars without newlines');
  };

  probeLinks();
  // Initial open: verify under the lock (so a half-finished writer is not mistaken for corruption), repair the head.
  await withLock(() => {
    const l = loadOrRecover();
    observe(l);
    const last = l.recs[l.recs.length - 1];
    if (last && (l.head === undefined || l.head.seq !== last.seq)) writeHead(last);
  });

  const self: DurableState = {
    get recovered() {
      return recovered;
    },
    position: () => ({ ...seen }),
    // Reads take the same lock so they see a consistent (journal, head) pair, never a mid-commit mix.
    async verify() {
      return withLock(() => {
        observe(load());
        return { ...seen };
      });
    },
    async get(k) {
      checkKey(k);
      return withLock(() => {
        const l = load();
        observe(l);
        const v = l.state.get(k);
        return v === undefined ? undefined : (JSON.parse(v) as unknown);
      });
    },
    async keys() {
      return withLock(() => {
        const l = load();
        observe(l);
        return [...l.state.keys()].sort();
      });
    },
    async set(k, value) {
      checkKey(k);
      const vj = encode(value);
      await withLock(() => {
        const l = load();
        const last = l.recs[l.recs.length - 1];
        if (last && (l.head === undefined || l.head.seq !== last.seq)) writeHead(last);
        commit(l, k, vj);
      });
    },
    async update(k, fn) {
      checkKey(k);
      return withLock(() => {
        const l = load();
        const last = l.recs[l.recs.length - 1];
        if (last && (l.head === undefined || l.head.seq !== last.seq)) writeHead(last);
        const curJson = l.state.get(k);
        const next = fn(curJson === undefined ? undefined : (JSON.parse(curJson) as unknown));
        if (next === undefined) return curJson === undefined ? undefined : (JSON.parse(curJson) as unknown);
        const vj = encode(next);
        if (vj !== curJson) commit(l, k, vj);
        return JSON.parse(vj) as unknown;
      });
    },
  };
  return self;
}
