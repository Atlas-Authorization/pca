/** 0.4.2 mutation kills: memoryNonceStore boundaries, attestationRegistry lookups, createDevAttestor defaults. */
import { describe, expect, it } from 'vitest';
import { attestationRegistry, createDevAttestor, memoryNonceStore } from './attestation';
import { generateKeyPair } from './keys';

describe('memoryNonceStore', () => {
  it('a non-string nonce is refused and not remembered', () => {
    const s = memoryNonceStore(10, { now: () => 5 });
    expect(s.consume(5 as never)).toBe(false);
    expect(s.consume(undefined as never)).toBe(false);
    expect(s.consume('5')).toBe(true);
  });
  it('a replay is refused strictly inside the retention window and the nonce is new again at exactly retention', () => {
    let t = 100;
    const s = memoryNonceStore(10, { retentionMs: 50, now: () => t });
    expect(s.consume('a')).toBe(true);
    t = 149;
    expect(s.consume('a')).toBe(false);
    t = 150;
    expect(s.consume('a')).toBe(true); // aged out: new again (and re-stamped at 150)
    t = 199;
    expect(s.consume('a')).toBe(false);
  });
  it('an aged-out replay frees its slot before the capacity check', () => {
    let t = 0;
    const s = memoryNonceStore(1, { retentionMs: 10, now: () => t });
    expect(s.consume('a')).toBe(true);
    t = 10;
    expect(s.consume('a')).toBe(true); // the only slot belonged to the expired 'a' itself
    expect(s.consume('b')).toBe(false); // full of one live nonce
  });
  it('a full store makes room from aged-out entries only, oldest first, and never evicts a live one', () => {
    let t = 0;
    const s = memoryNonceStore(2, { retentionMs: 10, now: () => t });
    expect(s.consume('a')).toBe(true);
    t = 5;
    expect(s.consume('b')).toBe(true);
    t = 9;
    expect(s.consume('c')).toBe(false);
    t = 10; // 'a' aged out, 'b' is live
    expect(s.consume('c')).toBe(true);
    expect(s.consume('b')).toBe(false);
    expect(s.consume('d')).toBe(false); // c and b live
  });
  it('a non-integer or non-numeric clock fails closed', () => {
    let t: unknown = 1.5;
    const s = memoryNonceStore(10, { now: () => t as number });
    expect(s.consume('a')).toBe(false);
    t = '5';
    expect(s.consume('a')).toBe(false);
    t = Number.NaN;
    expect(s.consume('a')).toBe(false);
    t = 7;
    expect(s.consume('a')).toBe(true);
  });
  it('construction refuses a bad capacity or retention with the exact messages', () => {
    for (const max of [0, -1, 1.5, Number.NaN, '3', Infinity]) expect(() => memoryNonceStore(max as never)).toThrow('memoryNonceStore: max must be a positive integer (a store that retains nothing gives no replay protection)');
    for (const retentionMs of [0, -5, 2.5, Number.NaN, '9', Infinity]) expect(() => memoryNonceStore(1, { retentionMs: retentionMs as never })).toThrow('memoryNonceStore: retentionMs must be a positive integer (ms)');
  });
});

describe('attestationRegistry', () => {
  const d = (nonce: unknown, tag: string) => ({ nonce, tag }) as never;
  it('indexes documents with a string nonce (later ones win); skips falsy / non-string-nonce entries; tolerates a non-array', () => {
    const r = attestationRegistry([d('n1', 'a'), null as never, d(5, 'x'), d('n1', 'b'), d('n2', 'c')]);
    const at = (q: unknown) => (r({ pcactn: { attestation: { quote_digest: q } } } as never) as unknown as { tag?: string } | undefined)?.tag;
    expect(at('n1')).toBe('b');
    expect(at('n2')).toBe('c');
    expect(at('5')).toBeUndefined();
    expect(at(5)).toBeUndefined();
    expect(at(undefined)).toBeUndefined();
    expect(r({} as never)).toBeUndefined();
    expect(r(undefined as never)).toBeUndefined();
    expect(attestationRegistry('nope' as never)({ pcactn: { attestation: { quote_digest: 'n1' } } } as never)).toBeUndefined();
  });
});

describe('createDevAttestor', () => {
  it('works with no suite (ed25519 default) and refuses an unknown suite alg', () => {
    expect(() => createDevAttestor(generateKeyPair().secretKey)).not.toThrow();
    expect(() => createDevAttestor(generateKeyPair().secretKey, { alg: 'nope' } as never)).toThrow("createDevAttestor: unknown signature alg 'nope'");
  });
});
