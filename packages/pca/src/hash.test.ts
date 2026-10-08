import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { __canonicalizeLenientServerOnly, b64u, canonicalize, canonicalizeStrict, hashCanonical, sha256, unb64u, utf8 } from './hash';
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
