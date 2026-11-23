/**
 * Durable round-1 nonce persistence for a FROST signer, built so a restart can neither lose a session nor reuse a nonce.
 *
 * Reusing one nonce pair across two messages reveals the signing share. The rule that prevents it across restarts is
 * ORDER: the nonce is durably marked spent BEFORE the signature share is computed. A crash after the mark loses that
 * session (liveness cost, the coordinator opens a new one); a crash before it leaves an unspent nonce that can still be
 * used exactly once. The store never has to be trusted to forget a nonce: `spend` removes the secret bytes and keeps
 * only the marker.
 *
 * Contract every implementation must meet (checked by {@link assertNonceStoreContract}):
 *  - `create` is durable before it returns and throws if the session id exists in ANY state (live or spent);
 *  - `load` returns the live record or undefined (spent, dropped and unknown ids all give undefined);
 *  - `spend` is atomic and durable: it throws unless the session is live, deletes the secret nonces, and records the id
 *    as spent forever; a second `spend` throws;
 *  - `isSpent` is true for every spent id, including after a restart;
 *  - every method throws on failure. The signer treats any throw as a refusal (fail closed): no commitment is released
 *    when `create` fails and no share is released when `spend` fails.
 * The records hold SECRET nonces: a durable store must encrypt them at rest (the interface is synchronous so an
 * implementation can sit on SQLite, an fsynced file or an HSM-backed counter).
 */
export interface NonceRecord {
  /** 32-byte LE hiding nonce scalar (secret). */
  hiding: Uint8Array;
  /** 32-byte LE binding nonce scalar (secret). */
  binding: Uint8Array;
  /** Public commitments emitted in round 1 (32-byte points). */
  hidingCommitment: Uint8Array;
  bindingCommitment: Uint8Array;
  /** Wall-clock ms at which round 1 opened the session. */
  createdAt: number;
}

export interface NonceStore {
  create(sessionId: string, record: NonceRecord): void;
  load(sessionId: string): NonceRecord | undefined;
  spend(sessionId: string): void;
  drop(sessionId: string): void;
  isSpent(sessionId: string): boolean;
}

const copy = (r: NonceRecord): NonceRecord => ({
  hiding: r.hiding.slice(),
  binding: r.binding.slice(),
  hidingCommitment: r.hidingCommitment.slice(),
  bindingCommitment: r.bindingCommitment.slice(),
  createdAt: r.createdAt,
});

/** Reference implementation: correct, not durable (a process restart loses it, which fails closed). Use it as the model. */
export class MemoryNonceStore implements NonceStore {
  readonly #live = new Map<string, NonceRecord>();
  readonly #spent = new Set<string>();
  create(sessionId: string, record: NonceRecord): void {
    if (typeof sessionId !== 'string' || sessionId.length === 0) throw new Error('nonce-store: session id must be a non-empty string');
    if (this.#live.has(sessionId) || this.#spent.has(sessionId)) throw new Error('nonce-store: session already exists');
    this.#live.set(sessionId, copy(record));
  }
  load(sessionId: string): NonceRecord | undefined {
    const r = this.#live.get(sessionId);
    return r ? copy(r) : undefined;
  }
  spend(sessionId: string): void {
    const r = this.#live.get(sessionId);
    if (!r) throw new Error('nonce-store: cannot spend a session that is not live');
    r.hiding.fill(0);
    r.binding.fill(0);
    this.#live.delete(sessionId);
    this.#spent.add(sessionId);
  }
  drop(sessionId: string): void {
    const r = this.#live.get(sessionId);
    if (r) {
      r.hiding.fill(0);
      r.binding.fill(0);
      this.#live.delete(sessionId);
    }
  }
  isSpent(sessionId: string): boolean {
    return this.#spent.has(sessionId);
  }
}

/**
 * Conformance check for a {@link NonceStore}. `reopen` must return a store over the SAME durable state (a simulated
 * restart); for the in-memory reference it returns the same instance. Throws on the first violation.
 */
export function assertNonceStoreContract(make: () => NonceStore, reopen: (s: NonceStore) => NonceStore = (s) => s): void {
  const rec = (n: number): NonceRecord => ({
    hiding: new Uint8Array(32).fill(n),
    binding: new Uint8Array(32).fill(n + 1),
    hidingCommitment: new Uint8Array(32).fill(n + 2),
    bindingCommitment: new Uint8Array(32).fill(n + 3),
    createdAt: n,
  });
  const must = (ok: boolean, what: string) => {
    if (!ok) throw new Error(`nonce-store contract: ${what}`);
  };
  const throws = (f: () => void) => {
    try {
      f();
    } catch {
      return true;
    }
    return false;
  };
  let s = make();
  must(s.load('a') === undefined && !s.isSpent('a'), 'an unknown id is neither live nor spent');
  s.create('a', rec(1));
  must(throws(() => s.create('a', rec(9))), 'create must refuse an existing live id');
  s.create('b', rec(5));
  s = reopen(s);
  const got = s.load('a');
  must(!!got && got.hiding[0] === 1 && got.createdAt === 1, 'a live record survives a restart');
  got!.hiding.fill(0xee);
  must(s.load('a')!.hiding[0] === 1, 'load returns a copy');
  s.spend('a');
  must(s.load('a') === undefined && s.isSpent('a'), 'spend removes the secret and records the marker');
  must(throws(() => s.spend('a')), 'a second spend must throw');
  must(throws(() => s.create('a', rec(2))), 'create must refuse a spent id');
  must(throws(() => s.spend('zzz')), 'spend of an unknown id must throw');
  s = reopen(s);
  must(s.isSpent('a') && s.load('a') === undefined, 'a spent marker survives a restart');
  must(!!s.load('b'), 'the other live record survives');
  s.drop('b');
  must(s.load('b') === undefined && !s.isSpent('b'), 'drop removes a live record without marking it spent');
  s.drop('never-existed');
}
