import { describe, expect, it } from 'vitest';
import {
  type AbeCiphertext,
  type Policy,
  decrypt,
  decryptText,
  encryptForPolicy,
  keygenForAttributes,
  normalizePolicy,
  parseCiphertext,
  satisfies,
  setup,
} from './index';

const PT = new TextEncoder().encode('top-secret tool result \u{1f510}');

function keyFor(msk: ReturnType<typeof setup>['msk'], attrs: string[]) {
  return keygenForAttributes(msk, attrs);
}

function normTree(policy: Policy) {
  const n = normalizePolicy(policy);
  if (!n.ok) throw new Error(n.reason);
  return n.tree;
}

describe('ABE core: single attribute', () => {
  it('a key WITH the attribute decrypts; a key WITHOUT it cannot', () => {
    const { mpk, msk } = setup();
    const policy: Policy = { attr: 'verb:read' };
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);

    const good = keyFor(msk, ['verb:read']);
    const bad = keyFor(msk, ['verb:write', 'holder:xyz']);

    expect(decrypt(good, ciphertext)).toEqual(PT);
    expect(decrypt(bad, ciphertext)).toBeNull();
  });
});

describe('ABE core: AND (allOf)', () => {
  const policy: Policy = { allOf: [{ attr: 'verb:read' }, { attr: 'holder:agentA' }] };

  it('requires EVERY attribute', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);

    expect(decrypt(keyFor(msk, ['verb:read', 'holder:agentA']), ciphertext)).toEqual(PT);
    // Missing either conjunct => cannot recover the secret => null.
    expect(decrypt(keyFor(msk, ['verb:read']), ciphertext)).toBeNull();
    expect(decrypt(keyFor(msk, ['holder:agentA']), ciphertext)).toBeNull();
    expect(decrypt(keyFor(msk, []), ciphertext)).toBeNull();
  });

  it('a key missing a conjunct GENUINELY cannot recover the symmetric key / plaintext', () => {
    const { mpk, msk } = setup();
    // Encrypt many fresh ciphertexts; a partial key must fail EVERY time (not just probabilistically).
    const partial = keyFor(msk, ['verb:read']);
    for (let i = 0; i < 20; i++) {
      const { ciphertext } = encryptForPolicy(mpk, policy, PT);
      expect(decrypt(partial, ciphertext)).toBeNull();
      expect(decryptText(partial, ciphertext)).toBeNull();
    }
    // Control: the full key recovers the exact plaintext, so the failure above is the missing attribute,
    // not a broken scheme.
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);
    expect(decrypt(keyFor(msk, ['verb:read', 'holder:agentA']), ciphertext)).toEqual(PT);
  });
});

describe('ABE core: OR (anyOf)', () => {
  const policy: Policy = { anyOf: [{ attr: 'scope:read:tickets' }, { attr: 'holder:admin' }] };

  it('any single branch suffices; an unrelated attribute does not', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);

    expect(decrypt(keyFor(msk, ['scope:read:tickets']), ciphertext)).toEqual(PT);
    expect(decrypt(keyFor(msk, ['holder:admin']), ciphertext)).toEqual(PT);
    expect(decrypt(keyFor(msk, ['scope:read:tickets', 'holder:admin']), ciphertext)).toEqual(PT);
    expect(decrypt(keyFor(msk, ['scope:write:tickets']), ciphertext)).toBeNull();
  });
});

describe('ABE core: threshold (k-of-n)', () => {
  const policy: Policy = {
    threshold: 2,
    of: [{ attr: 'verb:read' }, { attr: 'scope:pii' }, { attr: 'holder:agentA' }],
  };

  it('needs at least k of the n attributes', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);

    expect(decrypt(keyFor(msk, ['verb:read']), ciphertext)).toBeNull(); // 1 of 3
    expect(decrypt(keyFor(msk, ['verb:read', 'scope:pii']), ciphertext)).toEqual(PT); // 2 of 3
    expect(decrypt(keyFor(msk, ['scope:pii', 'holder:agentA']), ciphertext)).toEqual(PT); // 2 of 3
    expect(decrypt(keyFor(msk, ['verb:read', 'scope:pii', 'holder:agentA']), ciphertext)).toEqual(PT); // 3 of 3
    expect(decrypt(keyFor(msk, ['scope:unrelated']), ciphertext)).toBeNull();
  });
});

describe('ABE core: nested access structures', () => {
  // (verb:read AND resource:/t/1) OR holder:breakglass
  const policy: Policy = {
    anyOf: [{ allOf: [{ attr: 'verb:read' }, { attr: 'resource:/t/1' }] }, { attr: 'holder:breakglass' }],
  };

  it('enforces the nested boolean formula', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);

    expect(decrypt(keyFor(msk, ['verb:read', 'resource:/t/1']), ciphertext)).toEqual(PT);
    expect(decrypt(keyFor(msk, ['holder:breakglass']), ciphertext)).toEqual(PT);
    // Only half of the AND branch, and not the break-glass identity => denied.
    expect(decrypt(keyFor(msk, ['verb:read']), ciphertext)).toBeNull();
    expect(decrypt(keyFor(msk, ['resource:/t/1']), ciphertext)).toBeNull();
  });

  it('satisfies() is a faithful oracle for the cryptographic outcome', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);
    const tree = normTree(policy);
    const cases = [
      ['verb:read', 'resource:/t/1'],
      ['holder:breakglass'],
      ['verb:read'],
      ['resource:/t/1'],
      ['scope:nope'],
    ];
    for (const attrs of cases) {
      const predicted = satisfies(tree, new Set(attrs));
      const actual = decrypt(keyFor(msk, attrs), ciphertext) !== null;
      expect(actual).toBe(predicted);
    }
  });
});

describe('ABE core: AEAD integrity (tamper)', () => {
  const policy: Policy = { attr: 'verb:read' };

  function fresh(): { good: ReturnType<typeof keygenForAttributes>; ct: AbeCiphertext } {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, policy, PT);
    return { good: keyFor(msk, ['verb:read']), ct: ciphertext };
  }

  function flip(b64: string): string {
    const bytes = Buffer.from(b64, 'base64url');
    bytes[0] = bytes[0] === undefined ? 0 : bytes[0] ^ 0x01;
    return bytes.toString('base64url');
  }

  it('baseline decrypts', () => {
    const { good, ct } = fresh();
    expect(decrypt(good, ct)).toEqual(PT);
  });

  it('a tampered payload fails the GCM tag', () => {
    const { good, ct } = fresh();
    expect(decrypt(good, { ...ct, ct: flip(ct.ct) })).toBeNull();
  });

  it('a tampered tag fails', () => {
    const { good, ct } = fresh();
    expect(decrypt(good, { ...ct, tag: flip(ct.tag) })).toBeNull();
  });

  it('a tampered KEM header (AAD) fails even before the payload', () => {
    const { good, ct } = fresh();
    if (ct.kem.kind !== 'leaf') throw new Error('expected leaf');
    const tampered: AbeCiphertext = { ...ct, kem: { ...ct.kem, wrap: flip(ct.kem.wrap) } };
    expect(decrypt(good, tampered)).toBeNull();
  });
});

describe('ABE core: cross-master isolation', () => {
  it('a key from a different master cannot decrypt', () => {
    const a = setup();
    const b = setup();
    const { ciphertext } = encryptForPolicy(a.mpk, { attr: 'verb:read' }, PT);
    // Same attribute name, different master secret => decapsulation yields a wrong share => AEAD rejects.
    expect(decrypt(keygenForAttributes(b.msk, ['verb:read']), ciphertext)).toBeNull();
  });
});

describe('ABE core: malformed input is rejected (fail-closed)', () => {
  it('parseCiphertext returns null on garbage', () => {
    expect(parseCiphertext(null)).toBeNull();
    expect(parseCiphertext({})).toBeNull();
    expect(parseCiphertext({ v: 1, alg: 'nope' })).toBeNull();
    expect(parseCiphertext({ v: 1, alg: 'bf-ibe-bls12381/lsss/aes-256-gcm', salt: '!', iv: 'a', ct: 'a', tag: 'a', kem: {} })).toBeNull();
  });

  it('decrypt returns null (never throws) on garbage ciphertext', () => {
    const { msk } = setup();
    expect(decrypt(keygenForAttributes(msk, ['verb:read']), { not: 'a ciphertext' })).toBeNull();
    expect(decrypt(keygenForAttributes(msk, ['verb:read']), 42)).toBeNull();
  });

  it('invalid / empty policies are rejected', () => {
    const { mpk } = setup();
    // Type-valid shapes that are semantically invalid throw at encrypt time.
    expect(() => encryptForPolicy(mpk, { allOf: [] }, PT)).toThrow();
    expect(() => encryptForPolicy(mpk, { threshold: 3, of: [{ attr: 'a' }] }, PT)).toThrow();
    // Structurally malformed input is rejected by the normaliser (fail-closed), without a cast.
    expect(normalizePolicy({}).ok).toBe(false);
    expect(normalizePolicy({ allOf: [] }).ok).toBe(false);
    expect(normalizePolicy({ attr: '' }).ok).toBe(false);
    expect(normalizePolicy({ threshold: 0, of: [{ attr: 'a' }] }).ok).toBe(false);
  });
});
