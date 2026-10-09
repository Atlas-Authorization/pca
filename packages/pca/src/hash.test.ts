import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  __canonicalizeLenientServerOnly,
  b64u,
  canonicalize,
  canonicalizeStrict,
  hashCanonical,
  hashWithSuite,
  isHashSuite,
  sha256,
  sha384,
  unb64u,
  utf8,
  type HashSuite,
} from './hash';
import { strictParse } from './strict-json';

describe('hash', () => {
  it('the deprecated `canonicalize` alias is exactly the lenient server-only canonicalizer', () => {
    expect(canonicalize).toBe(__canonicalizeLenientServerOnly);
    expect(__canonicalizeLenientServerOnly({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });
  it('canonicalization is key-order independent and compact', () => {
    const a = { b: 1, a: { y: [1, 'x', null, true], x: 2 } };
    const b = { a: { x: 2, y: [1, 'x', null, true] }, b: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(canonicalize(a)).toBe('{"a":{"x":2,"y":[1,"x",null,true]},"b":1}');
    expect(hashCanonical(a)).toBe(hashCanonical(b));
  });
  it('array order matters; tamper changes digest', () => {
    expect(hashCanonical([1, 2])).not.toBe(hashCanonical([2, 1]));
    expect(hashCanonical({ a: 1 })).not.toBe(hashCanonical({ a: 2 }));
  });
  it('rejects unencodable values', () => {
    expect(() => canonicalize({ a: undefined })).toThrow();
    expect(() => canonicalize({ a: () => 1 })).toThrow();
    expect(() => canonicalize(NaN)).toThrow();
    expect(() => canonicalize(1n)).toThrow();
    const c: Record<string, unknown> = {};
    c.self = c;
    expect(() => canonicalize(c)).toThrow();
  });
  it('sha256 known vector and b64u roundtrip', () => {
    expect(Buffer.from(sha256(utf8('abc'))).toString('hex')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    const x = new Uint8Array([0, 255, 128, 7]);
    expect(unb64u(b64u(x))).toEqual(x);
    expect(b64u(x)).not.toMatch(/[+/=]/);
  });
});

// ---------------------------------------------------------------------------------------------------------
// SHA-384 hash-suite agility (P4): optional, NON-BREAKING stronger-margin variant for canonical digests.
// SHA-256 (the default) is already PQ-adequate; SHA-384 is extra margin, NOT a fix for any SHA-256 weakness.
describe('hashCanonical sha384 suite (P4 agility)', () => {
  it('sha384 is a correct 48-byte FIPS 180-4 digest (known vector)', () => {
    expect(Buffer.from(sha384(utf8('abc'))).toString('hex')).toBe(
      'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    );
    expect(sha384(utf8('abc')).length).toBe(48);
    expect(hashWithSuite(utf8('abc'))).toEqual(sha256(utf8('abc'))); // default suite == sha256
    expect(hashWithSuite(utf8('abc'), 'sha384')).toEqual(sha384(utf8('abc')));
  });

  it('isHashSuite narrows only the two known suites; everything else fails closed', () => {
    expect(isHashSuite('sha256')).toBe(true);
    expect(isHashSuite('sha384')).toBe(true);
    for (const x of ['sha512', 'SHA256', '', 0, null, undefined, {}]) expect(isHashSuite(x)).toBe(false);
  });

  it('default arg is byte-identical to the original one-argument hashCanonical (non-breaking)', () => {
    for (const v of [{ b: 1, a: 2 }, [1, 'x', null], { n: 1.5 }, 'café']) {
      expect(hashCanonical(v, 'sha256')).toBe(hashCanonical(v));
    }
  });

  it('sha384 digests are distinct, reproducible, 48-byte, over suite-independent canonical bytes', () => {
    for (const v of [{ b: 1, a: 2 }, { a: { x: 2, y: [1, 'x', null, true] }, b: 1 }, { n: [0, -1, 1.5] }]) {
      const d384 = hashCanonical(v, 'sha384');
      expect(d384).toBe(hashCanonical(v, 'sha384')); // reproducible
      expect(d384).not.toBe(hashCanonical(v)); // distinct from sha256
      expect(unb64u(d384).length).toBe(48); // SHA-384 width
      // the canonical SERIALIZATION does not depend on the suite — only the digest does
      expect(hashCanonical(v, 'sha384')).toBe(b64u(sha384(utf8(canonicalizeStrict(v)))));
    }
    // key-order independence holds under sha384 too
    expect(hashCanonical({ b: 1, a: 2 }, 'sha384')).toBe(hashCanonical({ a: 2, b: 1 }, 'sha384'));
  });
});

// Companion re-verification of the committed SHA-384 canonical corpus against the live reference.
interface Sha384CanonCorpus {
  primitives: { canonical: { value: unknown; suite: HashSuite; expect: string; hash: string; sha256_hash: string }[] };
}
const SHA384_CANON: Sha384CanonCorpus = JSON.parse(
  readFileSync(join(__dirname, '..', 'conformance', 'sha384-vectors.json'), 'utf8'),
) as Sha384CanonCorpus;

describe('sha384 canonical corpus (conformance/sha384-vectors.json)', () => {
  it('every vector: canonical bytes are suite-independent; sha384 digest matches and is distinct from sha256', () => {
    expect(SHA384_CANON.primitives.canonical.length).toBeGreaterThan(0);
    for (const c of SHA384_CANON.primitives.canonical) {
      expect(c.suite).toBe('sha384');
      expect(canonicalizeStrict(c.value)).toBe(c.expect); // serialization unchanged by the suite
      expect(hashCanonical(c.value, 'sha384')).toBe(c.hash);
      expect(hashCanonical(c.value)).toBe(c.sha256_hash); // sha256 default still byte-identical
      expect(c.hash).not.toBe(c.sha256_hash);
      expect(unb64u(c.hash).length).toBe(48);
    }
  });
});

// ---------------------------------------------------------------------------------------------------------
// Adversarial canonical-form regression gate (crypto-audit "float-canonicalization cross-language" stone).
//
// The cross-LANGUAGE convergence proof lives in tools/pca-canon-fuzz (differential fuzz: TS vs Go/Python/
// Ruby/PHP/.NET drivers, byte-identical canonical output over ~81k adversarial cases). This in-suite gate is
// the fast OFFLINE guard that the TS reference's canonical bytes never DRIFT: it replays a frozen, curated
// slice of that adversarial corpus and asserts the exact canonical bytes + hash the audit measured. If the
// TS formatter ever changes shape on these inputs, a signature minted by another SDK would stop verifying
// here — so this test failing means the "0 divergence" claim is at risk and the cross-language audit must
// be re-run.  Frozen vectors are produced by `tools/pca-canon-fuzz/run.sh` (deterministic seed).
interface FrozenVec {
  id: string;
  cls: string;
  raw: string;
  expect: { error?: true; canon?: string; hash?: string; reproducesLexeme?: boolean };
}
const FROZEN: FrozenVec[] = JSON.parse(
  readFileSync(join(__dirname, '../../../tools/pca-canon-fuzz/corpus/frozen-vectors.json'), 'utf8'),
);

describe('canonical-form adversarial regression gate (frozen cross-language vectors)', () => {
  it('loads a non-trivial frozen corpus with both accepted and rejected cases', () => {
    expect(FROZEN.length).toBeGreaterThan(400);
    expect(FROZEN.filter((v) => v.expect.error).length).toBeGreaterThan(50);
    expect(FROZEN.filter((v) => !v.expect.error).length).toBeGreaterThan(200);
  });

  it('every in-profile vector canonicalizes to the exact frozen bytes + hash (and is idempotent)', () => {
    for (const v of FROZEN) {
      if (v.expect.error) continue;
      const canon = canonicalizeStrict(strictParse(v.raw));
      expect(canon, `canon drift on ${v.id} (${v.cls}) raw=${v.raw}`).toBe(v.expect.canon);
      expect(hashCanonical(strictParse(v.raw)), `hash drift on ${v.id}`).toBe(v.expect.hash);
      // idempotence: re-parsing the canonical bytes reproduces them exactly (fixed point)
      expect(canonicalizeStrict(strictParse(canon)), `non-idempotent canon on ${v.id}`).toBe(canon);
    }
  });

  it('every out-of-profile vector is rejected (strict parse or strict canonicalize throws)', () => {
    for (const v of FROZEN) {
      if (!v.expect.error) continue;
      expect(() => canonicalizeStrict(strictParse(v.raw)), `expected ${v.id} (${v.cls}) raw=${v.raw} to be rejected`).toThrow();
    }
  });

  it('INVARIANT: every in-profile numeric lexeme IS its own canonical form (lexeme == shortest round-trip)', () => {
    // This is the heart of the number-side proof: because the strict 15-significant-digit profile forces
    // each canonical lexeme to already be its double's unique shortest round-trip decimal, the lexeme-
    // preserving SDKs (Go/PHP/.NET/Java keep the source lexeme) and the round-tripping SDKs (TS/Python/Ruby/
    // Rust reparse to a double and reformat) necessarily emit the same bytes. If this ever fails, String(v)
    // diverged from the source lexeme and a pinned formatter would be required.
    const numeric = FROZEN.filter((v) => v.expect.reproducesLexeme !== undefined);
    expect(numeric.length).toBeGreaterThan(100);
    for (const v of numeric) {
      expect(v.expect.reproducesLexeme, `frozen vector ${v.id} was not lexeme-stable at freeze time`).toBe(true);
      expect(canonicalizeStrict(strictParse(v.raw)), `String(v) != source lexeme on ${v.id} raw=${v.raw}`).toBe(v.raw);
    }
  });

  it('string escaper spot-checks: named escapes, lowercase \\u00xx, raw solidus / U+2028 / DEL / non-BMP', () => {
    // These mirror what every language SDK must reproduce (and did, in the cross-language audit).
    const cx = (raw: string) => canonicalizeStrict(strictParse(raw));
    expect(cx('"a\\/b"')).toBe('"a/b"'); //            \/  -> raw /
    expect(cx('"\u2028\u2029"')).toBe('"\u2028\u2029"'); // line/para separators stay raw
    expect(cx('"x\\u2028y"')).toBe('"x\u2028y"'); //    escaped -> raw
    expect(cx('"\\u007f"')).toBe('"\u007f"'); //         DEL (>=0x20) -> raw
    expect(cx('"\\u000b\\u001f"')).toBe('"\\u000b\\u001f"'); // non-named controls -> lowercase \u00xx
    expect(cx('"\\b\\t\\n\\f\\r"')).toBe('"\\b\\t\\n\\f\\r"'); // named escapes preserved
    expect(cx('"\\u00AB"')).toBe('"\u00ab"'); //         input hex case does not leak; char emitted raw
    expect(cx('"\\ud83d\\ude00"')).toBe('"\u{1F600}"'); // surrogate pair -> raw non-BMP
    expect(() => cx('"\\ud800"')).toThrow(); //          lone surrogate rejected
  });
});
