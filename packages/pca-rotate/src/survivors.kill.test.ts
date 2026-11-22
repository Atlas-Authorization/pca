import { describe, expect, it } from 'vitest';
import { type Capability, type CapabilityChain, delegate, encodeKey, generateKeyPair, mintRoot } from '@atlasauth/pca';
import { type RevocationRecord, type RevocationSink, applyRotation, compromisedKeyFlow, revokeAndReissueSubtree, rotateAgentKey, rotatePrincipalKey } from './index';

const pubOf = (k: { publicKey: Uint8Array }) => encodeKey(k.publicKey);

function build() {
  const P = generateKeyPair(), A = generateKeyPair(), B = generateKeyPair(), C = generateKeyPair(), N = generateKeyPair();
  const root = mintRoot({ principalSecret: P.secretKey, principalPublic: pubOf(P), holder: pubOf(A), caveats: [{ type: 'ttl', secs: 3600 }] });
  const c1 = delegate(root, pubOf(B), [{ type: 'resource', prefix: '/a' }], A.secretKey);
  const c2 = delegate(c1, pubOf(C), [{ type: 'resource', prefix: '/a/b' }], B.secretKey);
  return { P, A, B, C, N, root, c1, c2 };
}
const hole = (...xs: (Capability | undefined)[]) => xs as unknown as CapabilityChain;

describe('chain validation', () => {
  it('requires a non-empty array chain in every entry point', () => {
    const { A, N, B } = build();
    expect(() => rotateAgentKey([], { oldHolderSecret: A.secretKey, newKeyPair: N })).toThrow(new Error('rotateAgentKey: empty chain'));
    expect(() => rotateAgentKey(null as never, { oldHolderSecret: A.secretKey, newKeyPair: N })).toThrow(new Error('rotateAgentKey: empty chain'));
    expect(() => rotatePrincipalKey({ oldPrincipalSecret: A.secretKey, newPrincipalKeyPair: N })).toThrow(new Error('rotatePrincipalKey: empty chain'));
    expect(() => revokeAndReissueSubtree([], 'x', { newKeyPair: N, ancestorSecret: A.secretKey })).toThrow(new Error('revokeAndReissueSubtree: empty chain'));
    expect(() => revokeAndReissueSubtree(null as never, 'x', { newKeyPair: N, ancestorSecret: A.secretKey })).toThrow(new Error('revokeAndReissueSubtree: empty chain'));
    expect(() => compromisedKeyFlow([], 'x', { newKeyPair: N, ancestorSecret: B.secretKey })).toThrow(new Error('compromisedKeyFlow: empty chain'));
  });

  it('names the missing capability and the ctx', () => {
    const { A, N, root, c1, P } = build();
    const o = { oldHolderSecret: A.secretKey, newKeyPair: N };
    expect(() => rotateAgentKey(hole(undefined, c1), o)).toThrow(new RangeError('rotateAgentKey: no capability at index 0 (chain length 2)'));
    expect(() => rotateAgentKey(hole(root, undefined), o)).toThrow(new RangeError('rotateAgentKey: no capability at index 1 (chain length 2)'));
    expect(() => rotatePrincipalKey({ chain: hole(undefined, c1), oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: N })).toThrow(
      new RangeError('rotatePrincipalKey: no capability at index 0 (chain length 2)'),
    );
    expect(() => rotatePrincipalKey({ chain: hole(root, undefined), oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: N, holderSecrets: [A.secretKey] })).toThrow(
      new RangeError('rotatePrincipalKey: no capability at index 1 (chain length 2)'),
    );
    expect(() => revokeAndReissueSubtree(hole(undefined), 'x', { newKeyPair: N, ancestorSecret: A.secretKey })).toThrow(
      new RangeError('revokeAndReissueSubtree: no capability at index 0 (chain length 1)'),
    );
    const c = build();
    expect(() => revokeAndReissueSubtree(hole(c.root, c.c1, undefined), pubOf(c.B), { newKeyPair: c.N, ancestorSecret: c.A.secretKey })).toThrow(
      new RangeError('revokeAndReissueSubtree: no capability at index 2 (chain length 3)'),
    );
  });

  it('rejects a secret that is not a Uint8Array', () => {
    const { N, root, c1 } = build();
    expect(() => rotateAgentKey([root, c1], { oldHolderSecret: 'abc' as never, newKeyPair: N })).toThrow(new TypeError('expected a Uint8Array secret key'));
  });

  it('rejects malformed caveat lists and non-attenuating children', () => {
    const { A, N, root, c1, P } = build();
    const o = { oldHolderSecret: A.secretKey, newKeyPair: N };
    expect(() => rotateAgentKey([root, { ...c1, caveats: 'x' as never }], o)).toThrow(new TypeError('malformed capability: caveats must be arrays'));
    expect(() => rotateAgentKey([{ ...root, caveats: undefined as never }, c1], o)).toThrow(new TypeError('malformed capability: caveats must be arrays'));
    expect(() => rotateAgentKey([root, { ...c1, caveats: [] }], o)).toThrow(
      new Error('malformed chain: a child carries fewer caveats than its parent (not an attenuation)'),
    );
    // equal length is fine (no appended caveats)
    const same = delegate(root, pubOf(build().B), [], A.secretKey);
    const r = rotateAgentKey([root, same], o);
    expect(r.chain[1]?.caveats).toEqual(root.caveats);
    void P;
  });

  it('rejects a non-finite now with the calling function name', () => {
    const { A, P, B, N, root, c1 } = build();
    expect(() => rotateAgentKey([root, c1], { oldHolderSecret: A.secretKey, newKeyPair: N, now: Number.NaN })).toThrow(new TypeError('rotateAgentKey: now must be a finite number'));
    expect(() => rotateAgentKey([root, c1], { oldHolderSecret: A.secretKey, newKeyPair: N, now: '5' as never })).toThrow(new TypeError('rotateAgentKey: now must be a finite number'));
    expect(() => rotatePrincipalKey({ chain: [root], oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: N, now: Infinity })).toThrow(
      new TypeError('rotatePrincipalKey: now must be a finite number'),
    );
    expect(() => revokeAndReissueSubtree([root, c1], pubOf(B), { newKeyPair: N, ancestorSecret: A.secretKey, now: Number.NaN })).toThrow(
      new TypeError('revokeAndReissueSubtree: now must be a finite number'),
    );
  });
});

describe('rotateAgentKey', () => {
  it('names the mismatching secret exactly', () => {
    const { A, B, N, root, c1 } = build();
    expect(() => rotateAgentKey([root, c1], { oldHolderSecret: B.secretKey, newKeyPair: N })).toThrow(
      new Error(
        `rotateAgentKey: oldHolderSecret (pub ${pubOf(B)}) is not the leaf's issuer ${pubOf(A)}; ` + 'the leaf is re-signed by its parent holder (the leaf issuer)',
      ),
    );
  });
  it('defaults the reason and the time, and honours explicit ones', () => {
    const { A, N, root, c1 } = build();
    const before = Date.now();
    const d = rotateAgentKey([root, c1], { oldHolderSecret: A.secretKey, newKeyPair: N }).revocation;
    expect(d.reason).toBe('agent key rotated');
    expect(d.revokedAt).toBeGreaterThanOrEqual(before);
    expect(rotateAgentKey([root, c1], { oldHolderSecret: A.secretKey, newKeyPair: N, reason: 'why', now: 7 }).revocation).toEqual({
      capId: c1.id, holder: c1.holder, issuer: c1.issuer, capIds: [c1.id], reason: 'why', revokedAt: 7,
    });
  });
});

describe('rotatePrincipalKey', () => {
  it('refuses a chain whose first element has a parent', () => {
    const { A, N, c1 } = build();
    expect(() => rotatePrincipalKey({ chain: [c1], oldPrincipalSecret: A.secretKey, newPrincipalKeyPair: N })).toThrow(
      new Error('rotatePrincipalKey: chain[0] is not a root (it has a parent)'),
    );
  });
  it('refuses a missing or wrong holder secret per hop, with the exact message', () => {
    const { P, A, B, N, root, c1 } = build();
    const base = { chain: [root, c1] as CapabilityChain, oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: N };
    expect(() => rotatePrincipalKey({ ...base, holderSecrets: [undefined as never] })).toThrow(new RangeError('rotatePrincipalKey: missing holderSecret for hop 1'));
    expect(() => rotatePrincipalKey({ ...base, holderSecrets: [B.secretKey] })).toThrow(
      new Error(`rotatePrincipalKey: holderSecret for hop 1 (pub ${pubOf(B)}) is not that hop's issuer ${pubOf(A)}`),
    );
  });
  it('defaults the reason and honours explicit reason and time; oldRoot alone works', () => {
    const { P, N, root } = build();
    const d = rotatePrincipalKey({ oldRoot: root, oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: N }).revocation;
    expect(d.reason).toBe('principal key rotated (re-root)');
    expect(typeof d.revokedAt).toBe('number');
    expect(rotatePrincipalKey({ oldRoot: root, oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: N, reason: 'r', now: 9 }).revocation).toEqual({
      capId: root.id, issuer: root.issuer, holder: root.holder, subtreeRoot: root.id, capIds: [root.id], reason: 'r', revokedAt: 9,
    });
  });
});

describe('revokeAndReissueSubtree / compromisedKeyFlow', () => {
  it('refuses the root holder with the exact message', () => {
    const { A, N, root, c1 } = build();
    expect(() => revokeAndReissueSubtree([root, c1], pubOf(A), { newKeyPair: N, ancestorSecret: A.secretKey })).toThrow(
      new Error('revokeAndReissueSubtree: the compromised holder is the root holder (no safe delegation ancestor); rotate the root with rotatePrincipalKey'),
    );
  });
  it('allows re-issuing onto a key held only above the compromised subtree', () => {
    const { A, B, root, c1, c2 } = build();
    const r = revokeAndReissueSubtree([root, c1, c2], pubOf(B), { newKeyPair: A, ancestorSecret: A.secretKey });
    expect(r.chain).toHaveLength(2);
    expect(r.chain[1]?.holder).toBe(pubOf(A));
  });
  it('defaults the reason and honours explicit ones', () => {
    const { A, B, N, root, c1, c2 } = build();
    const o = { newKeyPair: N, ancestorSecret: A.secretKey };
    expect(revokeAndReissueSubtree([root, c1, c2], pubOf(B), o).revocation.reason).toBe('delegation subtree compromised');
    expect(revokeAndReissueSubtree([root, c1, c2], pubOf(B), { ...o, reason: 'x', now: 3 }).revocation).toEqual({
      capId: c1.id, holder: pubOf(B), issuer: c1.issuer, subtreeRoot: c1.id, capIds: [c1.id, c2.id], reason: 'x', revokedAt: 3,
    });
  });
  it('compromisedKeyFlow reports an unknown holder under its own name and still refuses the root holder', () => {
    const { A, B, N, root, c1, c2 } = build();
    const o = { newKeyPair: N, ancestorSecret: A.secretKey };
    expect(() => compromisedKeyFlow([root, c1, c2], 'nobody', o)).toThrow(new Error('compromisedKeyFlow: holder nobody is not in the chain'));
    expect(() => compromisedKeyFlow([root, c1, c2], pubOf(A), o)).toThrow(/is the root holder/);
    const f = compromisedKeyFlow([root, c1, c2], pubOf(B), { ...o, now: 5 });
    expect(f.revocations).toEqual([
      { capId: c1.id, holder: c1.holder, issuer: c1.issuer, subtreeRoot: c1.id, capIds: [c1.id], reason: 'delegation subtree compromised', revokedAt: 5 },
      { capId: c2.id, holder: c2.holder, issuer: c2.issuer, subtreeRoot: c1.id, capIds: [c2.id], reason: 'delegation subtree compromised', revokedAt: 5 },
    ]);
    expect(compromisedKeyFlow([root, c1, c2], pubOf(B), { ...o, reason: 'z', now: 5 }).revocations[0]?.reason).toBe('z');
  });
});

describe('applyRotation', () => {
  class Rec implements RevocationSink {
    log: unknown[][] = [];
    seen = new Map<string, unknown>();
    failAt: number | undefined;
    async revoke(i: { kind: 'cap'; value: string; reason?: string; revokedAt?: number }) {
      this.log.push(['revoke', i]);
      if (this.failAt !== undefined && this.log.filter((l) => l[0] === 'revoke').length === this.failAt) throw new Error('down');
      this.seen.set(i.value, i);
    }
    async unrevoke(k: { kind: 'cap'; value: string }) {
      this.log.push(['unrevoke', k]);
      return this.seen.delete(k.value);
    }
    async lookup(kind: 'cap', v: string) {
      this.log.push(['lookup', kind, v]);
      return this.seen.get(v);
    }
  }
  const rec = (capIds: string[] | undefined, extra: Partial<RevocationRecord> = {}): RevocationRecord => ({ ...(capIds ? { capIds } : {}), reason: 'r', revokedAt: 1, ...extra });

  it('rejects a non-string id, an empty id and a record with no id', async () => {
    const s = new Rec();
    await expect(applyRotation(s, rec([5 as never]))).rejects.toThrow(new TypeError('applyRotation: a record names an invalid capability id'));
    await expect(applyRotation(s, rec(['']))).rejects.toThrow(new TypeError('applyRotation: a record names an invalid capability id'));
    await expect(applyRotation(s, rec(undefined))).rejects.toThrow(new Error('applyRotation: the record names no capability to revoke'));
    expect(s.log).toEqual([]);
  });
  it('an id shared by two records is revoked once, with the first record', async () => {
    const s = new Rec();
    const out = await applyRotation(s, [rec(['a'], { reason: 'first' }), rec(['a', 'b'], { reason: 'second' })]);
    expect(out).toEqual(['a', 'b']);
    expect(s.log).toEqual([
      ['lookup', 'cap', 'a'],
      ['revoke', { kind: 'cap', value: 'a', reason: 'first', revokedAt: 1 }],
      ['lookup', 'cap', 'b'],
      ['revoke', { kind: 'cap', value: 'b', reason: 'second', revokedAt: 1 }],
    ]);
  });
  it('a capId alone is enough', async () => {
    const s = new Rec();
    expect(await applyRotation(s, { capId: 'solo', reason: 'r', revokedAt: 2 })).toEqual(['solo']);
  });
  it('on failure it removes exactly the ids this call added', async () => {
    const s = new Rec();
    s.seen.set('old', {});
    s.failAt = 3;
    await expect(applyRotation(s, rec(['x', 'old', 'y']))).rejects.toThrow('down');
    expect(s.log.filter((l) => l[0] === 'unrevoke')).toEqual([['unrevoke', { kind: 'cap', value: 'x' }], ['unrevoke', { kind: 'cap', value: 'y' }]]);
  });
  it('refuses a re-issued chain that shares an id before touching the sink', async () => {
    const s = new Rec();
    const { c1 } = build();
    await expect(applyRotation(s, rec([c1.id]), [c1])).rejects.toThrow(new Error('applyRotation: the re-issued chain contains a capability that is being revoked'));
    expect(s.log).toEqual([]);
  });
});
