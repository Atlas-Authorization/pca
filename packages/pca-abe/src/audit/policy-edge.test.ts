import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  type Policy,
  MAX_POLICY_DEPTH,
  MAX_POLICY_NODES,
  PcaEncryptionError,
  decrypt,
  encryptForPolicy,
  keygenForAttributes,
  normalizePolicy,
  parseCiphertext,
  policyAttributes,
  satisfies,
  setup,
} from '../index';
import { firstRepeatedAttribute } from '../fame';

const PT = new TextEncoder().encode('edge');

function roundTrips(policy: Policy, have: string[]): boolean {
  const { mpk, msk } = setup();
  const { ciphertext } = encryptForPolicy(mpk, policy, PT);
  const out = decrypt(keygenForAttributes(msk, have), ciphertext);
  return out !== null && Buffer.from(out).equals(Buffer.from(PT));
}

describe('policy validation: malformed and empty structures fail closed', () => {
  const bad: [string, unknown][] = [
    ['null', null],
    ['array', []],
    ['string', 'verb:read'],
    ['empty object', {}],
    ['empty attr', { attr: '' }],
    ['numeric attr', { attr: 5 }],
    ['empty allOf', { allOf: [] }],
    ['empty anyOf', { anyOf: [] }],
    ['empty threshold set', { threshold: 1, of: [] }],
    ['threshold 0', { threshold: 0, of: [{ attr: 'a' }] }],
    ['threshold negative', { threshold: -1, of: [{ attr: 'a' }] }],
    ['threshold fractional', { threshold: 1.5, of: [{ attr: 'a' }] }],
    ['threshold NaN', { threshold: Number.NaN, of: [{ attr: 'a' }] }],
    ['threshold Infinity', { threshold: Number.POSITIVE_INFINITY, of: [{ attr: 'a' }] }],
    ['threshold string', { threshold: '1', of: [{ attr: 'a' }] }],
    ['threshold > n', { threshold: 3, of: [{ attr: 'a' }, { attr: 'b' }] }],
    ['threshold without of', { threshold: 1 }],
    ['of without threshold', { of: [{ attr: 'a' }] }],
    ['leaf mixed with gate', { attr: 'a', allOf: [{ attr: 'b' }] }],
    ['non-array allOf', { allOf: { attr: 'a' } }],
    ['hole in children', { allOf: [{ attr: 'a' }, undefined] }],
    ['unknown node kind', { not: { attr: 'a' } }],
  ];
  for (const [name, p] of bad) {
    it(`rejects: ${name}`, () => {
      expect(normalizePolicy(p).ok).toBe(false);
      expect(() => encryptForPolicy(setup().mpk, p as Policy, PT)).toThrow();
    });
  }

  it('rejects a gate node that carries more than one gate keyword (no silent precedence between allOf/anyOf/threshold)', () => {
    expect(normalizePolicy({ allOf: [{ attr: 'a' }, { attr: 'b' }], anyOf: [{ attr: 'c' }] }).ok).toBe(false);
    expect(normalizePolicy({ anyOf: [{ attr: 'a' }], threshold: 1, of: [{ attr: 'b' }] }).ok).toBe(false);
    expect(normalizePolicy({ allOf: [{ attr: 'a' }], threshold: 1, of: [{ attr: 'b' }] }).ok).toBe(false);
  });

  it('enforces the node cap exactly at the boundary', () => {
    const mk = (n: number): Policy => ({ anyOf: Array.from({ length: n - 1 }, (_, i) => ({ attr: `a${i}` })) });
    expect(normalizePolicy(mk(MAX_POLICY_NODES)).ok).toBe(true);
    expect(normalizePolicy(mk(MAX_POLICY_NODES + 1)).ok).toBe(false);
  });

  it('is not tricked by inherited properties or a hostile prototype', () => {
    const evil = Object.create({ attr: 'inherited' }) as Record<string, unknown>;
    // 'attr' in evil is true via the prototype but it is not an own string leaf: must not produce a usable leaf for a different attr.
    const r = normalizePolicy(evil);
    if (r.ok) expect(r.tree.kind === 'leaf' ? r.tree.attr : '').toBe('inherited');
    expect(normalizePolicy(JSON.parse('{"__proto__":{"attr":"x"}}')).ok).toBe(false);
  });
});

describe('policy depth: anything encryptable is decryptable (no silent data loss)', () => {
  const nest = (d: number): Policy => {
    let p: Policy = { attr: 'leaf' };
    for (let i = 0; i < d; i++) p = { allOf: [p] };
    return p;
  };

  it('a policy at exactly MAX_POLICY_DEPTH gate levels round-trips; one more level is refused with PcaEncryptionError (not a raw TypeError)', () => {
    expect(roundTrips(nest(MAX_POLICY_DEPTH), ['leaf'])).toBe(true);
    expect(normalizePolicy(nest(MAX_POLICY_DEPTH + 1)).ok).toBe(false);
    expect(() => encryptForPolicy(setup().mpk, nest(MAX_POLICY_DEPTH + 1), PT)).toThrow(PcaEncryptionError);
  });

  it('for every depth: if encryptForPolicy accepts the policy then an authorised key decrypts it', () => {
    for (const d of [60, 63, 64, 65, 66, 100, 200]) {
      const { mpk, msk } = setup();
      let ct;
      try {
        ct = encryptForPolicy(mpk, nest(d), PT).ciphertext;
      } catch {
        continue; // rejecting at encrypt time is the safe outcome
      }
      expect(parseCiphertext(ct), `depth ${d} parse`).not.toBeNull();
      expect(decrypt(keygenForAttributes(msk, ['leaf']), ct), `depth ${d} decrypt`).not.toBeNull();
    }
  });
});

describe('duplicated attributes and thresholds (LSSS leaf semantics)', () => {
  it('FAME needs single-use attributes: an attribute named by two leaves is refused at encrypt time, never approximated', () => {
    const { mpk } = setup();
    for (const p of [
      { threshold: 2, of: [{ attr: 'a' }, { attr: 'a' }, { attr: 'b' }] },
      { allOf: [{ attr: 'a' }, { attr: 'a' }] },
      { anyOf: [{ attr: 'a' }, { allOf: [{ attr: 'b' }, { attr: 'a' }] }] },
    ] as Policy[]) {
      expect(() => encryptForPolicy(mpk, p, PT)).toThrow(/more than one leaf/);
    }
  });

  it('degenerate gates behave: 1-of-1, n-of-n with n=1, anyOf of one, nested singletons', () => {
    expect(roundTrips({ threshold: 1, of: [{ attr: 'a' }] }, ['a'])).toBe(true);
    expect(roundTrips({ anyOf: [{ attr: 'a' }] }, [])).toBe(false);
    expect(roundTrips({ allOf: [{ anyOf: [{ allOf: [{ attr: 'a' }] }] }] }, ['a'])).toBe(true);
  });

  it('n-of-n threshold equals AND and 1-of-n equals OR', () => {
    const at = ['a', 'b', 'c'].map((attr) => ({ attr }));
    expect(roundTrips({ threshold: 3, of: at }, ['a', 'b'])).toBe(false);
    expect(roundTrips({ threshold: 3, of: at }, ['a', 'b', 'c'])).toBe(true);
    expect(roundTrips({ threshold: 1, of: at }, ['c'])).toBe(true);
  });

  it('exact boundary of k-of-n for every k', () => {
    const at = ['a', 'b', 'c', 'd'].map((attr) => ({ attr }));
    const { mpk, msk } = setup();
    for (let k = 1; k <= 4; k++) {
      const { ciphertext } = encryptForPolicy(mpk, { threshold: k, of: at }, PT);
      for (let have = 0; have <= 4; have++) {
        const ok = decrypt(keygenForAttributes(msk, ['a', 'b', 'c', 'd'].slice(0, have)), ciphertext) !== null;
        expect(ok, `k=${k} have=${have}`).toBe(have >= k);
      }
    }
  });

  it('an extra, irrelevant key does not prevent decryption and a huge key set is fine', () => {
    const extras = Array.from({ length: 40 }, (_, i) => `noise:${i}`);
    expect(roundTrips({ attr: 'a' }, ['a', ...extras])).toBe(true);
  });
});

describe('attribute canonicalisation and unicode confusion', () => {
  it('attribute strings are matched byte-exactly: case, whitespace, NFC/NFD and homoglyphs are all DIFFERENT attributes (fail closed)', () => {
    const variants = [
      ['verb:read', 'verb:Read'],
      ['verb:read', 'verb:read '],
      ['verb:read', ' verb:read'],
      ['scope:café', 'scope:café'], // NFC vs NFD
      ['scope:a', 'scope:а'], // Latin a vs Cyrillic a
      ['scope:admin', 'scope:adm​in'], // zero-width space
      ['scope:x', 'scope:x\u0000'],
    ];
    for (const [want, have] of variants) {
      expect(roundTrips({ attr: want as string }, [have as string]), `${JSON.stringify(want)} vs ${JSON.stringify(have)}`).toBe(false);
      expect(roundTrips({ attr: want as string }, [want as string])).toBe(true);
    }
  });

  it('ill-formed UTF-16 attributes cannot alias each other: distinct lone surrogates must not share a key (TextEncoder maps all of them to U+FFFD)', () => {
    const { mpk, msk } = setup();
    const wanted = 'scope:\ud801'; // encrypt to this
    let ct;
    try {
      ct = encryptForPolicy(mpk, { attr: wanted }, PT).ciphertext;
    } catch {
      return; // refusing ill-formed attributes at encrypt time is the correct outcome
    }
    // Attacker holds a legitimately issued key for a DIFFERENT lone surrogate and relabels it.
    const k = keygenForAttributes(msk, ['scope:\ud800']);
    const stolen = Object.values(k.attrs)[0];
    if (stolen === undefined) return; // keygen refused to issue it: also fine
    expect(decrypt({ ...k, attrs: { [wanted]: stolen } }, ct)).toBeNull();
  });

  it('keygen never silently drops an attribute that the policy can name (the "__proto__" attribute is issuable)', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, { attr: '__proto__' }, PT);
    expect(decrypt(keygenForAttributes(msk, ['__proto__']), ciphertext)).toEqual(PT);
  });

  it('keygen with prototype-ish names is own-property safe (constructor, toString, hasOwnProperty)', () => {
    const { mpk, msk } = setup();
    for (const a of ['constructor', 'toString', 'hasOwnProperty', 'valueOf']) {
      const { ciphertext } = encryptForPolicy(mpk, { attr: a }, PT);
      expect(decrypt(keygenForAttributes(msk, [a]), ciphertext)).toEqual(PT);
      expect(decrypt(keygenForAttributes(msk, ['other']), ciphertext)).toBeNull();
    }
  });

  it('a key object with no own attrs but inherited ones does not decrypt', () => {
    const { mpk, msk } = setup();
    const { ciphertext } = encryptForPolicy(mpk, { attr: 'a' }, PT);
    const real = keygenForAttributes(msk, ['a']);
    const inherited = { v: 1, curve: 'bls12-381', attrs: Object.create(real.attrs) } as never;
    expect(decrypt(inherited, ciphertext)).toBeNull();
  });
});

describe('property: cryptographic outcome equals the boolean satisfaction oracle', () => {
  const attrNames = ['a', 'b', 'c', 'd'];
  const leaf = fc.constantFrom(...attrNames).map((attr) => ({ attr }) as Policy);
  const policyArb: fc.Arbitrary<Policy> = fc.letrec((tie) => ({
    node: fc.oneof(
      { depthSize: 'small', maxDepth: 3 },
      leaf,
      fc.array(tie('node') as fc.Arbitrary<Policy>, { minLength: 1, maxLength: 3 }).map((allOf) => ({ allOf }) as Policy),
      fc.array(tie('node') as fc.Arbitrary<Policy>, { minLength: 1, maxLength: 3 }).map((anyOf) => ({ anyOf }) as Policy),
      fc
        .array(tie('node') as fc.Arbitrary<Policy>, { minLength: 1, maxLength: 4 })
        .chain((of) => fc.integer({ min: 1, max: of.length }).map((threshold) => ({ threshold, of }) as Policy)),
    ),
  })).node;

  it('decrypt(key, encrypt(policy)) succeeds iff satisfies(policy, attrs)', () => {
    const { mpk, msk } = setup();
    fc.assert(
      fc.property(policyArb, fc.subarray(attrNames), (policy, have) => {
        const n = normalizePolicy(policy);
        if (!n.ok) return true;
        if (firstRepeatedAttribute(n.tree) !== null) {
          expect(() => encryptForPolicy(mpk, policy, PT)).toThrow(PcaEncryptionError);
          return true;
        }
        const { ciphertext } = encryptForPolicy(mpk, policy, PT);
        const out = decrypt(keygenForAttributes(msk, have), ciphertext);
        const expected = satisfies(n.tree, new Set(have));
        return expected ? out !== null && Buffer.from(out).equals(Buffer.from(PT)) : out === null;
      }),
      { numRuns: 60 },
    );
  });

  it('policyAttributes lists exactly the attributes a policy names', () => {
    fc.assert(
      fc.property(policyArb, (policy) => {
        const n = normalizePolicy(policy);
        if (!n.ok) return true;
        const names = new Set(JSON.stringify(policy).match(/"attr":"([^"]+)"/g)?.map((m) => m.slice(8, -1)));
        return [...policyAttributes(n.tree)].sort().join() === [...names].sort().join();
      }),
      { numRuns: 100 },
    );
  });
});
