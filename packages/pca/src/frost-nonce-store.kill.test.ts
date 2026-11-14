import { describe, expect, it } from 'vitest';
import { frostTrustedDealerKeygen } from './frost';
import { b64u } from './hash';
import { generateKeyPair } from './keys';
import { GuardianSignerService, MAX_FROST_SIGNING_SET, decodeCommitment, decodeVerificationShares } from './frost-net';
import { assertNonceStoreContract, MemoryNonceStore, type NonceRecord, type NonceStore } from './frost-nonce-store';

const rec = (n: number): NonceRecord => ({
  hiding: new Uint8Array(32).fill(n),
  binding: new Uint8Array(32).fill(n + 1),
  hidingCommitment: new Uint8Array(32).fill(n + 2),
  bindingCommitment: new Uint8Array(32).fill(n + 3),
  createdAt: n,
});
const violation = (what: string) => new Error(`nonce-store contract: ${what}`);

describe('assertNonceStoreContract refuses each broken store with the exact violation', () => {
  it('refuses a store where an unknown id is already live', () => {
    class PreLive extends MemoryNonceStore {
      constructor() {
        super();
        this.create('a', rec(3));
      }
    }
    expect(() => assertNonceStoreContract(() => new PreLive())).toThrow(violation('an unknown id is neither live nor spent'));
  });

  it('refuses a store where an unknown id is already spent', () => {
    class PreSpent extends MemoryNonceStore {
      constructor() {
        super();
        this.create('a', rec(3));
        this.spend('a');
      }
    }
    expect(() => assertNonceStoreContract(() => new PreSpent())).toThrow(violation('an unknown id is neither live nor spent'));
  });

  it('refuses a store that accepts a duplicate live id', () => {
    class Dup extends MemoryNonceStore {
      override create(id: string, r: NonceRecord): void {
        if (this.load(id) || this.isSpent(id)) return;
        super.create(id, r);
      }
    }
    expect(() => assertNonceStoreContract(() => new Dup())).toThrow(violation('create must refuse an existing live id'));
  });

  it('refuses a store that loses a live record on restart', () => {
    expect(() => assertNonceStoreContract(() => new MemoryNonceStore(), () => new MemoryNonceStore())).toThrow(
      violation('a live record survives a restart'),
    );
  });

  it('refuses a store that returns a wrong hiding nonce', () => {
    class BadHiding extends MemoryNonceStore {
      override load(id: string): NonceRecord | undefined {
        const r = super.load(id);
        if (r) r.hiding.fill(7);
        return r;
      }
    }
    expect(() => assertNonceStoreContract(() => new BadHiding())).toThrow(violation('a live record survives a restart'));
  });

  it('refuses a store that returns a wrong creation time', () => {
    class BadTime extends MemoryNonceStore {
      override load(id: string): NonceRecord | undefined {
        const r = super.load(id);
        return r ? { ...r, createdAt: 2 } : r;
      }
    }
    expect(() => assertNonceStoreContract(() => new BadTime())).toThrow(violation('a live record survives a restart'));
  });

  it('refuses a store whose load hands out its internal record', () => {
    class NoCopy implements NonceStore {
      readonly #live = new Map<string, NonceRecord>();
      readonly #spent = new Set<string>();
      create(id: string, r: NonceRecord): void {
        if (this.#live.has(id) || this.#spent.has(id)) throw new Error('exists');
        this.#live.set(id, r);
      }
      load(id: string): NonceRecord | undefined {
        return this.#live.get(id);
      }
      spend(id: string): void {
        if (!this.#live.has(id)) throw new Error('not live');
        this.#live.delete(id);
        this.#spent.add(id);
      }
      drop(id: string): void {
        this.#live.delete(id);
      }
      isSpent(id: string): boolean {
        return this.#spent.has(id);
      }
    }
    expect(() => assertNonceStoreContract(() => new NoCopy())).toThrow(violation('load returns a copy'));
  });

  it('builds each probe record with distinct fills for every field', () => {
    class Rec extends MemoryNonceStore {
      readonly log: NonceRecord[] = [];
      override create(id: string, r: NonceRecord): void {
        this.log.push(r);
        super.create(id, r);
      }
    }
    const s = new Rec();
    assertNonceStoreContract(() => s);
    for (const n of [1, 5]) {
      const r = s.log.find((x) => x.createdAt === n)!;
      expect(Array.from(r.hiding)).toEqual(new Array(32).fill(n));
      expect(Array.from(r.binding)).toEqual(new Array(32).fill(n + 1));
      expect(Array.from(r.hidingCommitment)).toEqual(new Array(32).fill(n + 2));
      expect(Array.from(r.bindingCommitment)).toEqual(new Array(32).fill(n + 3));
    }
  });
});

describe('MemoryNonceStore exact behaviour', () => {
  it('refuses a non-string or empty session id with the exact message', () => {
    const s = new MemoryNonceStore();
    expect(() => s.create(5 as never, rec(1))).toThrow(new Error('nonce-store: session id must be a non-empty string'));
    expect(() => s.create('', rec(1))).toThrow(new Error('nonce-store: session id must be a non-empty string'));
  });

  it('refuses a duplicate live id and a spent id with the exact message', () => {
    const s = new MemoryNonceStore();
    s.create('a', rec(1));
    expect(() => s.create('a', rec(2))).toThrow(new Error('nonce-store: session already exists'));
    s.spend('a');
    expect(() => s.create('a', rec(2))).toThrow(new Error('nonce-store: session already exists'));
  });

  it('refuses to spend a session that is not live with the exact message', () => {
    const s = new MemoryNonceStore();
    expect(() => s.spend('nope')).toThrow(new Error('nonce-store: cannot spend a session that is not live'));
  });

  it('copies every field on create and on load', () => {
    const s = new MemoryNonceStore();
    const r = rec(1);
    s.create('a', r);
    r.hidingCommitment.fill(0xaa);
    r.bindingCommitment.fill(0xbb);
    const got = s.load('a')!;
    expect(Array.from(got.hidingCommitment)).toEqual(new Array(32).fill(3));
    expect(Array.from(got.bindingCommitment)).toEqual(new Array(32).fill(4));
    got.hidingCommitment.fill(0xcc);
    got.bindingCommitment.fill(0xdd);
    const again = s.load('a')!;
    expect(Array.from(again.hidingCommitment)).toEqual(new Array(32).fill(3));
    expect(Array.from(again.bindingCommitment)).toEqual(new Array(32).fill(4));
  });

  it.each(['spend', 'drop'] as const)('%s zeroes the stored secret nonces', (op) => {
    const orig = Uint8Array.prototype.slice;
    const made: Uint8Array[] = [];
    Uint8Array.prototype.slice = function (this: Uint8Array, ...a: [number?, number?]) {
      const out = orig.apply(this, a);
      made.push(out);
      return out;
    };
    const s = new MemoryNonceStore();
    try {
      s.create('a', rec(1));
    } finally {
      Uint8Array.prototype.slice = orig;
    }
    const [hiding, binding] = made;
    expect(Array.from(hiding!)).toEqual(new Array(32).fill(1));
    expect(Array.from(binding!)).toEqual(new Array(32).fill(2));
    s[op]('a');
    expect(Array.from(hiding!)).toEqual(new Array(32).fill(0));
    expect(Array.from(binding!)).toEqual(new Array(32).fill(0));
  });
});

describe('frost-net decoders and signer recovery, exact outcomes', () => {
  const P = b64u(new Uint8Array(32).fill(1));

  it.each([7, 'x', true])('decodeCommitment(%j) refuses with the bare message', (x) => {
    expect(() => decodeCommitment(x as never)).toThrow(new Error('bad commitment'));
  });

  it.each([7, 'x', true])('decodeVerificationShares refuses entry %j with the bare message', (x) => {
    expect(() => decodeVerificationShares([x as never])).toThrow(new Error('bad verification share'));
  });

  it('decodeVerificationShares accepts exactly the maximum signing set', () => {
    const list = Array.from({ length: MAX_FROST_SIGNING_SET }, () => ({ identifier: 1, publicKey: P }));
    expect(decodeVerificationShares(list)).toHaveLength(MAX_FROST_SIGNING_SET);
  });

  function signerOver(store: NonceStore) {
    const kg = frostTrustedDealerKeygen(2, 3);
    const policy = generateKeyPair();
    const make = () =>
      new GuardianSignerService({
        identifier: kg.participantShares[0]!.identifier,
        share: kg.participantShares[0]!.share,
        groupPublicKey: kg.groupPublicKey,
        threshold: 2,
        policyAuthorityPublicKey: policy.publicKey,
        nonceStore: store,
      });
    return { make, group: b64u(kg.groupPublicKey) };
  }

  it('round 2 for an unknown session with a store refuses with the exact reason', () => {
    const { make, group } = signerOver(new MemoryNonceStore());
    const out = make().round2({ typ: 'pca.frost.round2.v1', session_id: 'nobody', message: b64u(new Uint8Array(4)), group_pk: group } as never);
    expect(out).toMatchObject({ ok: false, refused: true, reason: 'no round-1 state for this session' });
  });

  it('a recovered session is cached, so the durable store is read once', () => {
    class Counting extends MemoryNonceStore {
      loads = 0;
      override load(id: string): NonceRecord | undefined {
        this.loads++;
        return super.load(id);
      }
    }
    const store = new Counting();
    const { make, group } = signerOver(store);
    const first = make();
    const r1 = first.round1({ typ: 'pca.frost.round1.v1', session_id: 's1' });
    expect(r1.ok).toBe(true);
    const restarted = make();
    store.loads = 0;
    const req = { typ: 'pca.frost.round2.v1', session_id: 's1', message: '*', group_pk: group } as never;
    expect(restarted.round2(req)).toMatchObject({ ok: false, reason: 'message not canonical base64url' });
    expect(restarted.round2(req)).toMatchObject({ ok: false, reason: 'message not canonical base64url' });
    expect(store.loads).toBe(1);
  });
});
