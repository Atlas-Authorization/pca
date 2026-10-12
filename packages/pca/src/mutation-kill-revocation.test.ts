/**
 * Mutation-kill tests for revocation.ts: proof-shape guards of the sorted Merkle set (each defect on an otherwise VALID
 * proof so the guard fires alone), size-bound root layout, the signed revocation epoch (every refusal with its exact reason
 * and boundary), the signed-message layout, and the revocation checker hook.
 */
import { describe, expect, it } from 'vitest';
import type { Capability } from './capability';
import { b64u, canonicalBytes, sha256, utf8 } from './hash';
import { encodeKey, generateKeyPair, verifyB64u } from './keys';
import { leafHash, merkleRoot } from './merkle';
import type { PCActn, VerifyContext } from './pcactn';
import {
  checkRevocationEpoch,
  createRevocationChecker,
  REVEPOCH_DOMAIN,
  REVOCATION_EPOCH_REFRESH_MS,
  REVOCATION_EPOCH_VALIDITY_MS,
  type RevocationEpoch,
  RevocationSet,
  revokeMessage,
  signRevocationEpoch,
  verifyMembership,
  verifyNonMembership,
} from './revocation';

const cat = (a: Uint8Array, b: Uint8Array) => {
  const m = new Uint8Array(a.length + b.length);
  m.set(a);
  m.set(b, a.length);
  return m;
};
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const emptyTree = b64u(sha256(new Uint8Array(0)));
const bind = (size: number, tree: string) => b64u(sha256(cat(utf8('pca-revset/v1\0'), canonicalBytes({ size, tree }))));

// ---------------------------------------------------------------------------------------------
describe('RevocationSet', () => {
  it('root is H("pca-revset/v1\\0" || canonical{size, tree}) - exact layout, empty and non-empty', () => {
    expect(new RevocationSet().root).toBe(bind(0, emptyTree));
    const ids = ['a', 'b', 'c'];
    expect(new RevocationSet(ids).root).toBe(bind(3, merkleRoot(ids)));
    expect(new RevocationSet(['c', 'a', 'b']).root).toBe(bind(3, merkleRoot(ids)));
    expect(new RevocationSet(['a']).root).not.toBe(new RevocationSet(['a', 'b']).root);
  });
  it('revoke: true when new, false when repeated; refuses non-strings with the exact message', () => {
    const s = new RevocationSet();
    expect(s.revoke('x')).toBe(true);
    expect(s.revoke('x')).toBe(false);
    expect(s.revoke('y')).toBe(true);
    expect(s.size).toBe(2);
    expect(() => s.revoke(5 as never)).toThrow(TypeError);
    expect(() => s.revoke(5 as never)).toThrow('revoke: id must be a string');
    expect(() => new RevocationSet([1 as never])).toThrow('revoke: id must be a string');
    expect(s.size).toBe(2);
  });
  it('keeps ids in UTF-8 byte order; has / list reflect it', () => {
    const s = new RevocationSet(['b', 'a', 'c', 'a']);
    expect(s.list()).toEqual(['a', 'b', 'c']);
    expect(s.has('b')).toBe(true);
    expect(s.has('bb')).toBe(false);
    const l = s.list();
    l.push('z');
    expect(s.list()).toEqual(['a', 'b', 'c']);
  });
  it('membershipProof: verifies for members; exact error for non-members', () => {
    const s = new RevocationSet(['a', 'b', 'c']);
    expect(verifyMembership(s.root, s.membershipProof('b'), 'b')).toBe(true);
    expect(() => s.membershipProof('zz')).toThrow('membershipProof: id is not revoked');
    expect(() => s.membershipProof('zz')).toThrow(Error);
  });
  it('nonMembershipProof: brackets by neighbours, refuses revoked ids', () => {
    const s = new RevocationSet(['b', 'd']);
    const mid = s.nonMembershipProof('c');
    expect(mid.size).toBe(2);
    expect(mid.lo!.id).toBe('b');
    expect(mid.hi!.id).toBe('d');
    const below = s.nonMembershipProof('a');
    expect('lo' in below).toBe(false);
    expect(below.hi!.id).toBe('b');
    const above = s.nonMembershipProof('e');
    expect('hi' in above).toBe(false);
    expect(above.lo!.id).toBe('d');
    expect(s.nonMembershipProof('x').size).toBe(2);
    expect(() => s.nonMembershipProof('b')).toThrow('nonMembershipProof: id is revoked');
    // bytes order, not UTF-16 order
    const u = new RevocationSet(['\u{1F600}', '～']);
    expect(u.nonMembershipProof('｟').hi!.id).toBe('\u{1F600}');
  });
});

// ---------------------------------------------------------------------------------------------
describe('verifyMembership: every guard on a valid proof, alone', () => {
  const ids = ['a', 'b', 'c', 'd', 'e'];
  const s = new RevocationSet(ids);
  const mem = (id: string) => s.membershipProof(id);
  const ok = (id: string, over: Record<string, unknown> = {}) => verifyMembership(s.root, { ...mem(id), ...over } as never, id);

  it('the unmodified proof verifies for each id', () => {
    for (const id of ids) expect(ok(id), id).toBe(true);
  });
  it('proof.size must equal the bound size', () => {
    expect(ok('b', { size: 6 })).toBe(false);
    expect(ok('b', { size: 4 })).toBe(false);
  });
  it('index must be a non-negative integer below the size', () => {
    expect(ok('b', { index: 1.5 })).toBe(false);
    expect(ok('a', { index: -1 })).toBe(false);
    expect(ok('e', { index: 5 })).toBe(false); // == size
    expect(ok('b', { index: NaN })).toBe(false);
    expect(ok('b', { index: '1' })).toBe(false);
    const one = new RevocationSet(['only']);
    expect(verifyMembership(one.root, { ...one.membershipProof('only'), index: 1 } as never, 'only')).toBe(false);
    expect(verifyMembership(one.root, { ...one.membershipProof('only'), index: 0 } as never, 'only')).toBe(true);
  });
  it('path must be an array of exactly the expected length', () => {
    const p = mem('c');
    expect(ok('c', { path: [...p.path, p.path[0]] })).toBe(false);
    expect(ok('c', { path: p.path.slice(1) })).toBe(false);
    expect(ok('c', { path: {} })).toBe(false);
    expect(verifyMembership(new RevocationSet(['only']).root, { index: 0, size: 1, path: { length: 0 } } as never, 'only')).toBe(false);
    expect(verifyMembership(new RevocationSet(['only']).root, { index: 0, size: 1, path: [] }, 'only')).toBe(true);
  });
  it('each step\'s side must be exactly the expected "L"/"R"', () => {
    const p = mem('c');
    const flip = (i: number, side: string) => ({ path: p.path.map((st, j) => (j === i ? { ...st, side } : st)) });
    for (let i = 0; i < p.path.length; i++) {
      const other = p.path[i]!.side === 'L' ? 'R' : 'L';
      expect(ok('c', flip(i, other)), `flip ${i}`).toBe(false);
      expect(ok('c', flip(i, 'X')), `junk ${i}`).toBe(false);
    }
  });
  it('wrong id, wrong root, null / hostile proofs are false and never throw', () => {
    expect(verifyMembership(s.root, mem('b'), 'c')).toBe(false);
    expect(verifyMembership('x', mem('b'), 'b')).toBe(false);
    expect(verifyMembership(s.root, null as never, 'b')).toBe(false);
    expect(verifyMembership(s.root, undefined as never, 'b')).toBe(false);
    expect(verifyMembership(s.root, { ...mem('b'), path: [null] } as never, 'b')).toBe(false);
    expect(verifyMembership(s.root, { ...mem('b'), path: [{ side: 'L', hash: 5 }, ...mem('b').path.slice(1)] } as never, 'b')).toBe(false);
    const hostile = { size: 5, get index(): number { throw new Error('boom'); }, path: [] };
    expect(verifyMembership(s.root, hostile as never, 'b')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('verifyNonMembership', () => {
  const s = new RevocationSet(['b', 'd', 'f']);
  const nm = (id: string) => s.nonMembershipProof(id);

  it('valid brackets verify (middle, below, above); the empty set verifies with a bare size-0 proof', () => {
    expect(verifyNonMembership(s.root, nm('c'), 'c')).toBe(true);
    expect(verifyNonMembership(s.root, nm('a'), 'a')).toBe(true);
    expect(verifyNonMembership(s.root, nm('g'), 'g')).toBe(true);
    const e = new RevocationSet();
    expect(verifyNonMembership(e.root, e.nonMembershipProof('x'), 'x')).toBe(true);
    expect(verifyNonMembership(e.root, { size: 0 }, 'x')).toBe(true);
  });
  it('size-0 proofs: no leaves allowed, root must be the empty-set root', () => {
    const e = new RevocationSet();
    const leaf = nm('c').lo!;
    expect(verifyNonMembership(e.root, { size: 0, lo: leaf }, 'x')).toBe(false);
    expect(verifyNonMembership(e.root, { size: 0, hi: leaf }, 'x')).toBe(false);
    expect(verifyNonMembership(e.root, { size: 0, lo: leaf, hi: leaf }, 'x')).toBe(false);
    expect(verifyNonMembership(s.root, { size: 0 }, 'x')).toBe(false); // a non-empty set cannot be claimed empty
    expect(verifyNonMembership('bogus', { size: 0 }, 'x')).toBe(false);
  });
  it('a non-empty proof needs at least one bracketing leaf', () => {
    expect(verifyNonMembership(s.root, { size: 3 }, 'c')).toBe(false);
  });
  it('one-sided brackets must sit at the extreme position', () => {
    // lo only: the id must be above the LAST leaf. Claiming "above b" without hi when b is not last is a forgery.
    expect(verifyNonMembership(s.root, { size: 3, lo: nm('c').lo! }, 'c')).toBe(false);
    expect(verifyNonMembership(s.root, { size: 3, lo: nm('e').lo! }, 'e')).toBe(false); // d is not last either
    // hi only: the id must be below the FIRST leaf
    expect(verifyNonMembership(s.root, { size: 3, hi: nm('c').hi! }, 'c')).toBe(false);
    expect(verifyNonMembership(s.root, { size: 3, hi: nm('e').hi! }, 'e')).toBe(false);
    expect(verifyNonMembership(s.root, { size: 3, lo: nm('g').lo! }, 'g')).toBe(true);
    expect(verifyNonMembership(s.root, { size: 3, hi: nm('a').hi! }, 'a')).toBe(true);
  });
  it('the id must be strictly between the brackets', () => {
    expect(verifyNonMembership(s.root, nm('c'), 'b')).toBe(false); // equals lo
    expect(verifyNonMembership(s.root, nm('c'), 'd')).toBe(false); // equals hi
    expect(verifyNonMembership(s.root, nm('c'), 'a')).toBe(false); // below lo
    expect(verifyNonMembership(s.root, nm('c'), 'e')).toBe(false); // above hi
    expect(verifyNonMembership(s.root, nm('a'), 'b')).toBe(false); // revoked id vs hi-only proof
    expect(verifyNonMembership(s.root, nm('g'), 'f')).toBe(false); // revoked id vs lo-only proof
  });
  it('the brackets must be ADJACENT', () => {
    const wide = { size: 3, lo: nm('a').hi!, hi: nm('g').lo! }; // b and f, not adjacent
    expect(verifyNonMembership(s.root, wide, 'c')).toBe(false);
    const swapped = { size: 3, lo: nm('c').hi!, hi: nm('c').lo! };
    expect(verifyNonMembership(s.root, swapped, 'c')).toBe(false);
  });
  it('leaves must be bound to the root: wrong size / foreign tree / tampered path', () => {
    expect(verifyNonMembership(s.root, { ...nm('c'), size: 4 }, 'c')).toBe(false);
    expect(verifyNonMembership(new RevocationSet(['b', 'd', 'g']).root, nm('c'), 'c')).toBe(false);
    const p = clone(nm('c'));
    p.lo!.proof.path[0]!.hash = p.hi!.proof.path[0]!.hash;
    expect(verifyNonMembership(s.root, p, 'c')).toBe(false);
  });
  it('size must be a non-negative integer', () => {
    for (const bad of [-1, 1.5, NaN, Infinity, '3', undefined]) expect(verifyNonMembership(s.root, { ...nm('c'), size: bad } as never, 'c'), String(bad)).toBe(false);
    expect(verifyNonMembership(s.root, null as never, 'c')).toBe(false);
    expect(verifyNonMembership(s.root, undefined as never, 'c')).toBe(false);
  });
  it('a bracketing leaf\'s own proof.size must equal the proof size', () => {
    const p = clone(nm('c'));
    p.lo!.proof.size = 4;
    expect(verifyNonMembership(s.root, p, 'c')).toBe(false);
    const q = clone(nm('c'));
    q.hi!.proof.size = 2;
    expect(verifyNonMembership(s.root, q, 'c')).toBe(false);
  });
  it('a fractional size is refused even against a root that (hypothetically) commits to it', () => {
    // root = bind(1.5, tree) where the tree folds consistently for leaf 0 (sides [R]) and leaf 1 (sides [R, L]) of "size 1.5"
    const nodeH = (l: Uint8Array, r: Uint8Array) => sha256(cat(new Uint8Array([1]), cat(l, r)));
    const lLo = leafHash('a');
    const lHi = leafHash('c');
    const s1 = sha256(utf8('s1'));
    const sib0 = nodeH(lHi, s1);
    const tree = nodeH(lLo, sib0);
    const root = bind(1.5, b64u(tree));
    const proof = {
      size: 1.5,
      lo: { id: 'a', proof: { index: 0, size: 1.5, path: [{ side: 'R' as const, hash: b64u(sib0) }] } },
      hi: { id: 'c', proof: { index: 1, size: 1.5, path: [{ side: 'R' as const, hash: b64u(s1) }, { side: 'L' as const, hash: b64u(lLo) }] } },
    };
    // control: both leaves DO fold to the root (leaf-level checks have no integrality rule), so only the size rule refuses
    expect(verifyMembership(root, proof.lo.proof, 'a')).toBe(true);
    expect(verifyMembership(root, proof.hi.proof, 'c')).toBe(true);
    expect(verifyNonMembership(root, proof, 'b')).toBe(false);
  });
  it('hostile input is false, not an exception (and never true)', () => {
    expect(verifyNonMembership(s.root, { size: 3, lo: { id: Symbol('x'), proof: nm('c').lo!.proof } } as never, 'c')).toBe(false);
    expect(verifyNonMembership(s.root, { get size(): number { throw new Error('boom'); } } as never, 'c')).toBe(false);
    expect(verifyNonMembership(s.root, { size: 3, lo: { id: 'b', proof: null } } as never, 'c')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------
describe('signed revocation epoch', () => {
  const G = generateKeyPair();
  const gPub = encodeKey(G.publicKey);
  const NOW = 1_000_000;
  const body = (over: Record<string, unknown> = {}) => ({ instance_id: 'inst', grant_ref: 'g1', epoch: 3, set_size: 2, root: 'rootX', issued_at: NOW - 100, not_after: NOW + 1000, ...over });
  const mk = (over: Record<string, unknown> = {}): RevocationEpoch => signRevocationEpoch(G.secretKey, body(over) as never);
  const chk = (ep: unknown, o: Record<string, unknown> = {}) => checkRevocationEpoch(ep as RevocationEpoch, { guardianPublic: gPub, now: NOW, ...o } as never);
  const unsigned = { ok: false, reason: 'revocation epoch not signed by the pinned guardian' };

  it('constants', () => {
    expect(REVOCATION_EPOCH_REFRESH_MS).toBe(60_000);
    expect(REVOCATION_EPOCH_VALIDITY_MS).toBe(300_000);
    expect(REVEPOCH_DOMAIN).toBe('atlas-pca/revepoch/v1\0');
  });
  it('signRevocationEpoch: exact fields and a signature over the domain-separated canonical body', () => {
    const ep = mk();
    expect(Object.keys(ep).sort()).toEqual(['epoch', 'grant_ref', 'guardian', 'instance_id', 'issued_at', 'not_after', 'root', 'set_size', 'sig']);
    expect(ep).toMatchObject({ instance_id: 'inst', grant_ref: 'g1', epoch: 3, set_size: 2, root: 'rootX', issued_at: NOW - 100, not_after: NOW + 1000, guardian: gPub });
    const message = cat(utf8('atlas-pca/revepoch/v1\0'), canonicalBytes({ instance_id: 'inst', grant_ref: 'g1', epoch: 3, set_size: 2, root: 'rootX', issued_at: NOW - 100, not_after: NOW + 1000 }));
    expect(verifyB64u(gPub, message, ep.sig)).toBe(true);
    expect(verifyB64u(gPub, canonicalBytes({ instance_id: 'inst', grant_ref: 'g1', epoch: 3, set_size: 2, root: 'rootX', issued_at: NOW - 100, not_after: NOW + 1000 }), ep.sig)).toBe(false);
  });
  it('the unsigned guardian_epoch annotation is not part of the signed body', () => {
    const ep = signRevocationEpoch(G.secretKey, { ...body(), guardian_epoch: 9 } as never);
    expect(chk(ep)).toEqual({ ok: true });
    expect(chk({ ...ep, guardian_epoch: 10 })).toEqual({ ok: true });
  });
  it('accepts a good epoch with exactly {ok:true}', () => {
    const r = chk(mk());
    expect(r).toEqual({ ok: true });
    expect('reason' in r).toBe(false);
    expect(chk(mk(), { grantRef: 'g1' })).toEqual({ ok: true });
  });
  it('not signed by the pinned guardian: missing epoch, wrong guardian, unknown suite - each alone', () => {
    expect(chk(null)).toEqual(unsigned);
    expect(chk(undefined)).toEqual(unsigned);
    expect(chk({ ...mk(), guardian: encodeKey(generateKeyPair().publicKey) })).toEqual(unsigned);
    expect(chk({ ...mk(), alg: 'rot13' })).toEqual(unsigned);
    expect(chk(mk(), { guardianPublic: encodeKey(generateKeyPair().publicKey) })).toEqual(unsigned);
  });
  it('malformed epoch / set_size: negative and fractional, each alone, checked before the signature', () => {
    const m = { ok: false, reason: 'malformed revocation epoch' };
    for (const bad of [-1, 1.5, NaN, Infinity, 2 ** 53, '3']) {
      expect(chk({ ...mk(), epoch: bad }), `epoch ${String(bad)}`).toEqual(m);
      expect(chk({ ...mk(), set_size: bad }), `set_size ${String(bad)}`).toEqual(m);
    }
    expect(chk(mk({ epoch: 0, set_size: 0 }))).toEqual({ ok: true });
  });
  it('signature: any tampered body field breaks it', () => {
    const bad = { ok: false, reason: 'revocation epoch signature invalid' };
    const ep = mk();
    for (const t of [{ instance_id: 'other' }, { grant_ref: 'g2' }, { epoch: 4 }, { set_size: 3 }, { root: 'rootY' }, { issued_at: NOW - 99 }, { not_after: NOW + 1001 }]) {
      expect(chk({ ...ep, ...t }), JSON.stringify(t)).toEqual(bad);
    }
    expect(chk({ ...ep, sig: mk({ epoch: 4 }).sig })).toEqual(bad);
    const other = signRevocationEpoch(generateKeyPair().secretKey, body() as never);
    expect(chk({ ...other, guardian: gPub })).toEqual(bad);
  });
  it('grant binding is only enforced when a grantRef is supplied', () => {
    expect(chk(mk(), { grantRef: 'g2' })).toEqual({ ok: false, reason: 'revocation epoch is for a different grant' });
    expect(chk(mk(), { grantRef: 'g1' })).toEqual({ ok: true });
    expect(chk(mk())).toEqual({ ok: true });
  });
  it('expiry boundary: now <= not_after', () => {
    const ep = mk();
    expect(chk(ep, { now: ep.not_after })).toEqual({ ok: true });
    expect(chk(ep, { now: ep.not_after + 1 })).toEqual({ ok: false, reason: 'revocation epoch expired (stale revocation root)' });
    expect(chk(ep, { now: NaN })).toEqual({ ok: false, reason: 'revocation epoch expired (stale revocation root)' });
  });
  it('issued in the future: allowed up to 60 s of skew, inclusive', () => {
    const at = (issued: number) => mk({ issued_at: issued, not_after: issued + 10_000_000 });
    expect(chk(at(NOW + 60_000))).toEqual({ ok: true });
    expect(chk(at(NOW + 60_001))).toEqual({ ok: false, reason: 'revocation epoch issued in the future' });
    expect(chk(at(NOW - 60_000))).toEqual({ ok: true });
  });
  it('rollback: an older epoch than the last accepted is refused; equal / newer is fine', () => {
    expect(chk(mk(), { lastAcceptedEpoch: 3 })).toEqual({ ok: true });
    expect(chk(mk(), { lastAcceptedEpoch: 2 })).toEqual({ ok: true });
    expect(chk(mk(), { lastAcceptedEpoch: 4 })).toEqual({ ok: false, reason: 'revocation epoch 3 is older than the last accepted 4 (rollback)' });
    expect(chk(mk({ epoch: 0 }), { lastAcceptedEpoch: 0 })).toEqual({ ok: true });
  });
  it('PCActn freshness: the signed epoch must be <= the epoch the action signed', () => {
    expect(chk(mk(), { pcactnEpoch: 3 })).toEqual({ ok: true });
    expect(chk(mk(), { pcactnEpoch: 9 })).toEqual({ ok: true });
    expect(chk(mk(), { pcactnEpoch: 2 })).toEqual({ ok: false, reason: 'PCActn freshness.epoch 2 predates the revocation epoch 3' });
    expect(chk(mk(), { pcactnEpoch: 0 })).toEqual({ ok: false, reason: 'PCActn freshness.epoch 0 predates the revocation epoch 3' });
    expect(chk(mk(), { pcactnEpoch: NaN })).toEqual({ ok: false, reason: 'PCActn freshness.epoch NaN predates the revocation epoch 3' });
  });
  it('check order: guardian, shape, signature, grant, expiry, future, rollback, freshness', () => {
    const ep = mk();
    const all = { grantRef: 'other', lastAcceptedEpoch: 9, pcactnEpoch: 0, now: ep.not_after + 5 };
    expect(chk({ ...ep, epoch: -1 }, all).reason).toBe('malformed revocation epoch');
    expect(chk({ ...ep, root: 'z' }, all).reason).toBe('revocation epoch signature invalid');
    expect(chk(ep, all).reason).toBe('revocation epoch is for a different grant');
    expect(chk(ep, { ...all, grantRef: 'g1' }).reason).toBe('revocation epoch expired (stale revocation root)');
    expect(chk(ep, { ...all, grantRef: 'g1', now: NOW }).reason).toMatch(/rollback/);
    expect(chk(ep, { ...all, grantRef: 'g1', now: NOW, lastAcceptedEpoch: 1 }).reason).toMatch(/predates/);
  });
  it('never throws: a hostile epoch is "revocation epoch check error"', () => {
    const hostile = { guardian: gPub, get epoch(): number { throw new Error('boom'); } };
    expect(chk(hostile)).toEqual({ ok: false, reason: 'revocation epoch check error' });
  });
  it('revokeMessage: domain prefix + canonical {grant_ref, revoked_cap_id}', () => {
    const m = revokeMessage('G', 'C');
    expect(Array.from(m)).toEqual(Array.from(cat(utf8('atlas-pca/revoke/v1\0'), canonicalBytes({ grant_ref: 'G', revoked_cap_id: 'C' }))));
    expect(Array.from(revokeMessage('G', 'D'))).not.toEqual(Array.from(m));
  });
});

// ---------------------------------------------------------------------------------------------
describe('createRevocationChecker', () => {
  const G = generateKeyPair();
  const gPub = encodeKey(G.publicKey);
  const NOW = 1_000_000;
  const capA = { id: 'cap-a' } as Capability;
  const capB = { id: 'cap-b' } as Capability;
  const ctx = (extra: Record<string, unknown> = {}, fresh?: number): VerifyContext =>
    ({ pcactn: { grant_ref: 'g1', ...(fresh !== undefined ? { freshness: { epoch: fresh } } : {}), cap_chain: [capA, capB] } as unknown as PCActn, grant: capA, nowEpoch: NOW, ...extra }) as VerifyContext;
  const epochFor = (set: RevocationSet, epoch = 1, over: Record<string, unknown> = {}) =>
    signRevocationEpoch(G.secretKey, { instance_id: 'i', grant_ref: 'g1', epoch, set_size: set.size, root: set.root, issued_at: NOW, not_after: NOW + 1000, ...over } as never);
  const proofFor = (set: RevocationSet) => (id: string) => (set.has(id) ? undefined : set.nonMembershipProof(id));

  it('root mode: passes with proofs for every chain id', async () => {
    const set = new RevocationSet(['other']);
    expect(await createRevocationChecker({ root: () => set.root, proofFor: proofFor(set) })(ctx())).toEqual({ enforced: true, ok: true });
  });
  it('root mode: no root (undefined or empty) -> "no revocation root"', async () => {
    const r = { enforced: true, ok: false, reason: 'no revocation root' };
    expect(await createRevocationChecker({ proofFor: () => undefined })(ctx())).toEqual(r);
    expect(await createRevocationChecker({ root: () => undefined, proofFor: () => undefined })(ctx())).toEqual(r);
    expect(await createRevocationChecker({ root: () => '', proofFor: () => undefined })(ctx())).toEqual(r);
  });
  it('missing proof / revoked / bad proof: exact reasons naming the id, enforced stays true', async () => {
    const set = new RevocationSet(['other']);
    expect(await createRevocationChecker({ root: () => set.root, proofFor: () => undefined })(ctx())).toEqual({ enforced: true, ok: false, reason: 'no non-membership proof for cap-a' });
    expect(await createRevocationChecker({ root: () => set.root, proofFor: (id) => (id === 'cap-a' ? set.nonMembershipProof(id) : undefined) })(ctx())).toEqual({ enforced: true, ok: false, reason: 'no non-membership proof for cap-b' });
    const bad = new RevocationSet(['cap-b', 'zzz']);
    expect(await createRevocationChecker({ root: () => bad.root, proofFor: () => new RevocationSet(['x']).nonMembershipProof('cap-b') })(ctx())).toEqual({ enforced: true, ok: false, reason: 'capability cap-a is revoked or proof invalid' });
    // second id fails
    const s2 = new RevocationSet(['cap-b']);
    expect(await createRevocationChecker({ root: () => s2.root, proofFor: (id) => (id === 'cap-a' ? s2.nonMembershipProof(id) : new RevocationSet(['x']).nonMembershipProof('cap-b')) })(ctx())).toEqual({ enforced: true, ok: false, reason: 'capability cap-b is revoked or proof invalid' });
  });
  it('ids selector narrows the checked ids; proofFor receives (id, ctx)', async () => {
    const set = new RevocationSet(['cap-a']);
    const seen: [string, VerifyContext][] = [];
    const c = ctx();
    const checker = createRevocationChecker({ root: () => set.root, ids: () => ['cap-b'], proofFor: (id, cx) => { seen.push([id, cx]); return set.nonMembershipProof(id); } });
    expect(await checker(c)).toEqual({ enforced: true, ok: true });
    expect(seen).toEqual([['cap-b', c]]);
  });
  it('epoch mode: needs both an epoch and a pinned guardian', async () => {
    const set = new RevocationSet();
    const r = { enforced: true, ok: false, reason: 'no signed revocation epoch' };
    expect(await createRevocationChecker({ epoch: () => undefined, guardianPublic: gPub, proofFor: proofFor(set) })(ctx())).toEqual(r);
    expect(await createRevocationChecker({ epoch: () => epochFor(set), proofFor: proofFor(set) })(ctx())).toEqual(r);
    expect(await createRevocationChecker({ epoch: () => epochFor(set), guardianPublic: '', proofFor: proofFor(set) })(ctx())).toEqual(r);
    expect(await createRevocationChecker({ epoch: () => epochFor(set), guardianPublic: gPub, proofFor: proofFor(set) })(ctx())).toEqual({ enforced: true, ok: true });
  });
  it('epoch mode: check failures surface the epoch reason (enforced, not ok)', async () => {
    const set = new RevocationSet();
    const mk = (e: RevocationEpoch, extra: object = {}) => createRevocationChecker({ epoch: () => e, guardianPublic: gPub, proofFor: proofFor(set), ...extra });
    expect(await mk(epochFor(set, 1, { grant_ref: 'other' }))(ctx())).toEqual({ enforced: true, ok: false, reason: 'revocation epoch is for a different grant' });
    expect(await mk(epochFor(set))(ctx({ nowEpoch: NOW + 5000 }))).toEqual({ enforced: true, ok: false, reason: 'revocation epoch expired (stale revocation root)' });
    expect(await mk(epochFor(set, 1), { lastAcceptedEpoch: () => 2 })(ctx())).toEqual({ enforced: true, ok: false, reason: 'revocation epoch 1 is older than the last accepted 2 (rollback)' });
    expect(await mk(epochFor(set, 5))(ctx({}, 4))).toEqual({ enforced: true, ok: false, reason: 'PCActn freshness.epoch 4 predates the revocation epoch 5' });
  });
  it('epoch mode: the action carries no freshness -> not an exception, no freshness constraint', async () => {
    const set = new RevocationSet();
    const checker = createRevocationChecker({ epoch: () => epochFor(set, 7), guardianPublic: gPub, proofFor: proofFor(set) });
    expect(await checker(ctx())).toEqual({ enforced: true, ok: true });
    expect(await checker(ctx({}, 7))).toEqual({ enforced: true, ok: true });
  });
  it('epoch mode: the clock comes from ctx.nowEpoch; lastAcceptedEpoch / pqPins / allowUnboundPq are forwarded', async () => {
    const set = new RevocationSet();
    const seen: unknown[] = [];
    const checker = createRevocationChecker({ epoch: () => epochFor(set), guardianPublic: gPub, proofFor: proofFor(set), lastAcceptedEpoch: (c) => { seen.push(c); return 1; } });
    const c = ctx();
    expect(await checker(c)).toEqual({ enforced: true, ok: true });
    expect(seen).toEqual([c]);
  });
  it('epoch + root: a supplied root must equal the epoch root; the epoch root is what proofs are checked against', async () => {
    const set = new RevocationSet(['x']);
    const other = new RevocationSet(['y']);
    const mk = (root: string) => createRevocationChecker({ root: () => root, epoch: () => epochFor(set), guardianPublic: gPub, proofFor: proofFor(set) });
    expect(await mk(set.root)(ctx())).toEqual({ enforced: true, ok: true });
    expect(await mk(other.root)(ctx())).toEqual({ enforced: true, ok: false, reason: 'revocation root does not match the signed epoch' });
    expect(await mk('')(ctx())).toEqual({ enforced: true, ok: false, reason: 'revocation root does not match the signed epoch' });
    // proofs are checked against the epoch root even when root() is undefined
    expect(await createRevocationChecker({ root: () => undefined, epoch: () => epochFor(set), guardianPublic: gPub, proofFor: proofFor(set) })(ctx())).toEqual({ enforced: true, ok: true });
  });
  it('onEpochAccepted fires only for an accepted epoch, with (epoch, ctx), and only on full success', async () => {
    const set = new RevocationSet();
    const calls: unknown[][] = [];
    const ep = epochFor(set, 2);
    const c = ctx();
    const ok = createRevocationChecker({ epoch: () => ep, guardianPublic: gPub, proofFor: proofFor(set), onEpochAccepted: (...a) => calls.push(a) });
    expect(await ok(c)).toEqual({ enforced: true, ok: true });
    expect(calls).toEqual([[ep, c]]);
    // a failing proof => not accepted
    const failing = createRevocationChecker({ epoch: () => ep, guardianPublic: gPub, proofFor: () => undefined, onEpochAccepted: (...a) => calls.push(a) });
    expect(await failing(c)).toMatchObject({ enforced: true, ok: false });
    expect(calls).toHaveLength(1);
    // root mode never reports an accepted epoch
    const rs = new RevocationSet();
    const rootOnly = createRevocationChecker({ root: () => rs.root, proofFor: proofFor(rs), onEpochAccepted: (...a) => calls.push(a) });
    expect(await rootOnly(c)).toEqual({ enforced: true, ok: true });
    expect(calls).toHaveLength(1);
  });
  it('without an onEpochAccepted hook an accepted epoch is fine', async () => {
    const set = new RevocationSet();
    expect(await createRevocationChecker({ epoch: () => epochFor(set), guardianPublic: gPub, proofFor: proofFor(set) })(ctx())).toEqual({ enforced: true, ok: true });
  });
  it('defaults the checked ids to the chain\'s cap ids; clock falls back to Date.now when ctx has none', async () => {
    const set = new RevocationSet();
    const ids: string[] = [];
    const fresh = signRevocationEpoch(G.secretKey, { instance_id: 'i', grant_ref: 'g1', epoch: 1, set_size: 0, root: set.root, issued_at: Date.now(), not_after: Date.now() + 60_000 } as never);
    const checker = createRevocationChecker({ epoch: () => fresh, guardianPublic: gPub, proofFor: (id) => { ids.push(id); return set.nonMembershipProof(id); } });
    expect(await checker(ctx({ nowEpoch: undefined }))).toEqual({ enforced: true, ok: true });
    expect(ids).toEqual(['cap-a', 'cap-b']);
  });
});
