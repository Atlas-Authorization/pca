/**
 * Mutation kills for the 0.5.0 flagship gate survivors: frost-nonce-store.ts (each later contract step of
 * assertNonceStoreContract refuses its own broken store with the exact violation), frost-pq.ts (the signPqQuorum block,
 * every early refusal of verifyPqQuorum with its exact reason, the entry cap and the per-entry shape checks, including
 * entries whose members are read more than once) and frost.ts (scalar reduction at L and at negative multiples of L, the
 * empty scalar).
 */
import { describe, expect, it } from 'vitest';
import { L, bytesToScalar, scalarToBytes } from './frost';
import { assertNonceStoreContract, type NonceRecord, type NonceStore } from './frost-nonce-store';
import { MAX_PQ_QUORUM_ENTRIES, PQ_QUORUM_ALG, PQ_QUORUM_VERSION, normalizePqQuorumPool, signPqQuorum, verifyPqQuorum } from './frost-pq';
import { b64u, utf8 } from './hash';
import { mlDsa65Keygen } from './pq';

// ---- frost-nonce-store.ts ------------------------------------------------------------------------------

const violation = (what: string) => new Error(`nonce-store contract: ${what}`);

type Flaw =
  | 'spend-keeps-secret'
  | 'spend-no-marker'
  | 'spend-keeps-secret-and-marks'
  | 'spend-twice-ok'
  | 'create-over-spent'
  | 'spend-unknown-ok'
  | 'drop-keeps'
  | 'drop-marks'
  | 'drop-unknown-throws';

/** A store with public state so `reopen` can model a restart that loses or resurrects part of it. */
class FlawedStore implements NonceStore {
  live = new Map<string, NonceRecord>();
  spent = new Set<string>();
  constructor(readonly flaw?: Flaw) {}
  create(id: string, r: NonceRecord): void {
    if (typeof id !== 'string' || id.length === 0) throw new Error('bad id');
    if (this.live.has(id) || (this.spent.has(id) && this.flaw !== 'create-over-spent')) throw new Error('exists');
    this.live.set(id, { ...r, hiding: r.hiding.slice(), binding: r.binding.slice() });
  }
  load(id: string): NonceRecord | undefined {
    const r = this.live.get(id);
    return r ? { ...r, hiding: r.hiding.slice(), binding: r.binding.slice() } : undefined;
  }
  spend(id: string): void {
    if (typeof id !== 'string' || id.length === 0) throw new Error('bad id');
    if (!this.live.has(id)) {
      if (this.flaw === 'spend-twice-ok' && this.spent.has(id)) return;
      if (this.flaw === 'spend-unknown-ok' && !this.spent.has(id)) return;
      throw new Error('not live');
    }
    if (this.flaw !== 'spend-keeps-secret' && this.flaw !== 'spend-keeps-secret-and-marks') this.live.delete(id);
    if (this.flaw !== 'spend-no-marker' && this.flaw !== 'spend-keeps-secret') this.spent.add(id);
  }
  drop(id: string): void {
    if (this.flaw === 'drop-unknown-throws' && id.length > 0 && !this.live.has(id)) throw new Error('unknown id');
    if (this.flaw !== 'drop-keeps') this.live.delete(id);
    if (this.flaw === 'drop-marks') this.spent.add(id);
  }
  isSpent(id: string): boolean {
    return this.spent.has(id);
  }
}

describe('assertNonceStoreContract: the spend, restart and drop steps', () => {
  it.each([
    ['spend-keeps-secret', 'spend removes the secret and records the marker'],
    ['spend-no-marker', 'spend removes the secret and records the marker'],
    ['spend-keeps-secret-and-marks', 'spend removes the secret and records the marker'],
    ['spend-twice-ok', 'a second spend must throw'],
    ['create-over-spent', 'create must refuse a spent id'],
    ['spend-unknown-ok', 'spend of an unknown id must throw'],
    ['drop-keeps', 'drop removes a live record without marking it spent'],
    ['drop-marks', 'drop removes a live record without marking it spent'],
  ] as const)('a store with flaw %s is refused with "%s"', (flaw, what) => {
    expect(() => assertNonceStoreContract(() => new FlawedStore(flaw))).toThrow(violation(what));
  });

  it('a drop of a never-existing id is made with that id (a store that throws on it fails the check)', () => {
    expect(() => assertNonceStoreContract(() => new FlawedStore('drop-unknown-throws'))).toThrow(new Error('unknown id'));
  });

  it('the reference flawless store passes', () => {
    expect(() => assertNonceStoreContract(() => new FlawedStore())).not.toThrow();
  });

  it('a restart that forgets the spent marker is refused', () => {
    const reopen = (s: NonceStore): NonceStore => {
      const n = new FlawedStore();
      n.live = new Map((s as FlawedStore).live);
      return n;
    };
    // the first restart has no spent ids yet, so only the second one loses state
    expect(() => assertNonceStoreContract(() => new FlawedStore(), reopen)).toThrow(violation('a spent marker survives a restart'));
  });

  it('a restart that resurrects a spent secret is refused', () => {
    const reopen = (s: NonceStore): NonceStore => {
      const f = s as FlawedStore;
      const n = new FlawedStore();
      n.spent = new Set(f.spent);
      n.live = new Map(f.live);
      if (f.spent.has('a')) n.live.set('a', { hiding: new Uint8Array(32), binding: new Uint8Array(32), hidingCommitment: new Uint8Array(32), bindingCommitment: new Uint8Array(32), createdAt: 0 });
      return n;
    };
    expect(() => assertNonceStoreContract(() => new FlawedStore(), reopen)).toThrow(violation('a spent marker survives a restart'));
  });

  it('a restart that loses the other live record is refused', () => {
    const reopen = (s: NonceStore): NonceStore => {
      const f = s as FlawedStore;
      const n = new FlawedStore();
      n.spent = new Set(f.spent);
      n.live = new Map(f.live);
      if (f.spent.has('a')) n.live.delete('b');
      return n;
    };
    expect(() => assertNonceStoreContract(() => new FlawedStore(), reopen)).toThrow(violation('the other live record survives'));
  });
});

// ---- frost-pq.ts ------------------------------------------------------------------------------------------

describe('signPqQuorum / verifyPqQuorum exact outcomes', () => {
  const MSG = utf8('pq quorum kill message');
  const kA = mlDsa65Keygen(new Uint8Array(32).fill(11));
  const kB = mlDsa65Keygen(new Uint8Array(32).fill(12));
  const pool = normalizePqQuorumPool([kA.publicKey, kB.publicKey]);
  const signed = signPqQuorum(MSG, [kA, kB]);
  const [sA, sB] = signed.signers as unknown as [{ pk: string; sig: string }, { pk: string; sig: string }];
  const no = (reason: string, need: number) => ({ ok: false, count: 0, need, reason });

  it('signPqQuorum builds the versioned block with one entry per key and pqT defaulting to the signer count', () => {
    // built inside the test, so the signer itself is exercised here and not only while the suite is collected
    const fresh = signPqQuorum(MSG, [kA, kB]);
    expect(fresh).toEqual({ v: PQ_QUORUM_VERSION, alg: PQ_QUORUM_ALG, pqT: 2, signers: [{ pk: b64u(kA.publicKey), sig: expect.any(String) }, { pk: b64u(kB.publicKey), sig: expect.any(String) }] });
    expect(verifyPqQuorum(fresh, MSG, pool, 2)).toEqual({ ok: true, count: 2, need: 2 });
    expect(signPqQuorum(MSG, [kA, kB], 1).pqT).toBe(1);
  });

  it.each([0, -1, 1.5, Number.NaN])('pqT %s is refused before anything else', (pqT) => {
    expect(verifyPqQuorum(signed, MSG, pool, pqT)).toEqual(no('pqT must be a positive integer', pqT));
  });

  it('pqT = 1 is accepted', () => {
    expect(verifyPqQuorum(signed, MSG, pool, 1)).toEqual({ ok: true, count: 2, need: 1 });
  });

  it.each([null, 'block', 7])('block %j is a malformed pq block', (block) => {
    expect(verifyPqQuorum(block, MSG, pool, 1)).toEqual(no('malformed pq block', 1));
  });

  it('a wrong alg or a non-array signer list is a malformed pq block', () => {
    expect(verifyPqQuorum({ ...signed, alg: 'ml-dsa-87' }, MSG, pool, 1)).toEqual(no('malformed pq block', 1));
    expect(verifyPqQuorum({ ...signed, signers: 'x' }, MSG, pool, 1)).toEqual(no('malformed pq block', 1));
    expect(verifyPqQuorum({ ...signed, signers: { length: 1, 0: sA } }, MSG, pool, 1)).toEqual(no('malformed pq block', 1));
  });

  it('only the first MAX_PQ_QUORUM_ENTRIES entries are looked at', () => {
    const junk = Array.from({ length: MAX_PQ_QUORUM_ENTRIES }, () => 0);
    expect(verifyPqQuorum({ ...signed, signers: [...junk, sA] }, MSG, pool, 1)).toMatchObject({ ok: false, count: 0 });
    expect(verifyPqQuorum({ ...signed, signers: [...junk.slice(1), sA] }, MSG, pool, 1)).toEqual({ ok: true, count: 1, need: 1 });
  });

  it('null and non-object entries are skipped without throwing', () => {
    const fnEntry = Object.assign(() => undefined, { pk: sA.pk, sig: sA.sig });
    expect(verifyPqQuorum({ ...signed, signers: [null, sB] }, MSG, pool, 1)).toEqual({ ok: true, count: 1, need: 1 });
    expect(verifyPqQuorum({ ...signed, signers: [fnEntry, sB] }, MSG, pool, 2)).toMatchObject({ ok: false, count: 1 });
  });

  it('each member is type-checked on its own read (a member that changes between reads is not trusted)', () => {
    // sig reads a valid signature first and garbage afterwards: the type check takes the first read, the verify the second
    const flakySig = () => {
      let n = 0;
      return { pk: sA.pk, get sig() { return n++ === 0 ? sA.sig : 'AAAA'; } };
    };
    expect(verifyPqQuorum({ ...signed, signers: [flakySig()] }, MSG, pool, 1)).toMatchObject({ ok: false, count: 0 });
    // pk reads kA's key four times, then kB's: the counted key is kB, so kB's own entry is a repeat and counts nothing
    const shiftedPk = () => {
      let n = 0;
      return { get pk() { return n++ < 4 ? sA.pk : sB.pk; }, sig: sA.sig };
    };
    expect(verifyPqQuorum({ ...signed, signers: [shiftedPk(), sB] }, MSG, pool, 2)).toMatchObject({ ok: false, count: 1 });
  });

  it('non-string members count for nothing', () => {
    expect(verifyPqQuorum({ ...signed, signers: [{ pk: 5, sig: sA.sig }, { pk: sB.pk, sig: 5 }] }, MSG, pool, 1)).toMatchObject({ ok: false, count: 0 });
  });
});

// ---- frost.ts ------------------------------------------------------------------------------------------------

describe('frost scalar helpers at the edges', () => {
  const zero = Array.from(new Uint8Array(32));
  it('scalarToBytes reduces L and negative multiples of L to zero', () => {
    expect(Array.from(scalarToBytes(L))).toEqual(zero);
    expect(Array.from(scalarToBytes(-L))).toEqual(zero);
    expect(Array.from(scalarToBytes(-2n * L))).toEqual(zero);
    expect(Array.from(scalarToBytes(L + 1n))).toEqual(Array.from(scalarToBytes(1n)));
    expect(Array.from(scalarToBytes(-1n))).toEqual(Array.from(scalarToBytes(L - 1n)));
  });
  it('bytesToScalar of no bytes is zero (not a reduction error)', () => {
    expect(bytesToScalar(new Uint8Array(0))).toBe(0n);
  });
});
