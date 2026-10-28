import { describe, expect, it } from 'vitest';
import { attenuate, delegate, encodeKey, generateKeyPair, mintRoot, verifyChain, type CapabilityChain } from '@atlasauth/pca';
import { type RevocationRecord, type RevocationSink, applyRotation, revokeAndReissueSubtree, rotateAgentKey, rotatePrincipalKey } from './index';

function agentChain() {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const root = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [{ type: 'ttl', secs: 3600 }] });
  const leaf = attenuate(root, [{ type: 'resource', prefix: '/acct' }], A.secretKey);
  return { P, A, root, leaf, chain: [root, leaf] as CapabilityChain };
}

class Sink implements RevocationSink {
  m = new Map<string, unknown>();
  calls: string[] = [];
  failOn: number | undefined;
  async revoke(i: { kind: 'cap'; value: string; reason?: string; revokedAt?: number }) {
    this.calls.push(i.value);
    if (this.failOn !== undefined && this.calls.length === this.failOn) throw new Error('sink down');
    this.m.set(i.value, i);
  }
  async unrevoke(k: { kind: 'cap'; value: string }) {
    return this.m.delete(k.value);
  }
  async lookup(_k: 'cap', v: string) {
    return this.m.get(v);
  }
}
const rec = (capIds: string[], extra: Partial<RevocationRecord> = {}): RevocationRecord => ({ capIds, reason: 'why', revokedAt: 42, ...extra });

describe('same-key rotation is refused', () => {
  it('agent key', async () => {
    const { A, chain } = agentChain();
    expect(() => rotateAgentKey(chain, { oldHolderSecret: A.secretKey, newKeyPair: A })).toThrow('rotateAgentKey: newKeyPair is the key being rotated out');
  });
  it('principal key', async () => {
    const { P, A, chain } = agentChain();
    expect(() => rotatePrincipalKey({ chain, oldPrincipalSecret: P.secretKey, newPrincipalKeyPair: P, holderSecrets: [A.secretKey] })).toThrow(
      'rotatePrincipalKey: newPrincipalKeyPair is the key being rotated out',
    );
  });
  it('subtree re-issue onto a key already inside the subtree', async () => {
    const P = generateKeyPair(), A = generateKeyPair(), B = generateKeyPair(), C = generateKeyPair();
    const root = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [] });
    const c1 = delegate(root, encodeKey(B.publicKey), [], A.secretKey);
    const c2 = delegate(c1, encodeKey(C.publicKey), [], B.secretKey);
    expect(() => revokeAndReissueSubtree([root, c1, c2], encodeKey(B.publicKey), { newKeyPair: C, ancestorSecret: A.secretKey })).toThrow(
      'revokeAndReissueSubtree: newKeyPair is a key held inside the compromised subtree',
    );
  });
});

describe('now must be finite', () => {
  it('rotateAgentKey', async () => {
    const { A, chain } = agentChain();
    expect(() => rotateAgentKey(chain, { oldHolderSecret: A.secretKey, newKeyPair: generateKeyPair(), now: Number.NaN })).toThrow('rotateAgentKey: now must be a finite number');
  });
});

describe('errors never carry key material', () => {
  it('a wrong-secret error names public keys only', async () => {
    const { chain } = agentChain();
    const wrong = generateKeyPair();
    let msg = '';
    try {
      rotateAgentKey(chain, { oldHolderSecret: wrong.secretKey, newKeyPair: generateKeyPair() });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toContain('is not the leaf');
    expect(msg).not.toContain(encodeKey(wrong.secretKey));
  });
});

describe('applyRotation', () => {
  it('revokes every capability id, once, and returns them', async () => {
    const s = new Sink();
    expect(await applyRotation(s, [rec(['a', 'b']), rec(['b', 'c'])])).toEqual(['a', 'b', 'c']);
    expect(s.calls).toEqual(['a', 'b', 'c']);
    expect(s.m.get('a')).toEqual({ kind: 'cap', value: 'a', reason: 'why', revokedAt: 42 });
  });
  it('uses capId when capIds is absent', async () => {
    const s = new Sink();
    expect(await applyRotation(s, { capId: 'x', reason: 'r', revokedAt: 1 })).toEqual(['x']);
  });
  it('a record that names nothing is an error and touches nothing', async () => {
    const s = new Sink();
    await expect(applyRotation(s, { reason: 'r', revokedAt: 1 })).rejects.toThrow('applyRotation: the record names no capability to revoke');
    expect(s.calls).toEqual([]);
  });
  it('an invalid id is refused before any write', async () => {
    const s = new Sink();
    await expect(applyRotation(s, rec(['a', '']))).rejects.toThrow('applyRotation: a record names an invalid capability id');
    expect(s.calls).toEqual([]);
  });
  it('a failure part-way rolls back what this call added, and keeps what was already revoked', async () => {
    const s = new Sink();
    s.m.set('pre', { kind: 'cap', value: 'pre' });
    s.failOn = 3;
    await expect(applyRotation(s, rec(['pre', 'a', 'b']))).rejects.toThrow('sink down');
    expect([...s.m.keys()]).toEqual(['pre']);
  });
  it('refuses a re-issued chain that shares a capability with the revoked set, before any write', async () => {
    const { root, chain } = agentChain();
    const s = new Sink();
    await expect(applyRotation(s, rec([root.id]), chain)).rejects.toThrow('applyRotation: the re-issued chain contains a capability that is being revoked');
    expect(s.calls).toEqual([]);
  });
  it('after an agent rotation, the old leaf is revoked and the new chain still verifies', async () => {
    const { P, A, chain, leaf } = agentChain();
    const out = rotateAgentKey(chain, { oldHolderSecret: A.secretKey, newKeyPair: generateKeyPair(), now: 7 });
    const s = new Sink();
    expect(await applyRotation(s, out.revocation, out.chain)).toEqual([leaf.id]);
    expect(verifyChain(out.chain, encodeKey(P.publicKey))).toEqual({ ok: true });
    expect(out.chain.map((c) => c.id)).not.toContain(leaf.id);
  });
});
