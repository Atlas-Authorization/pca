import { describe, expect, it } from 'vitest';
import {
  MAX_JSON_DEPTH,
  b64u,
  canonicalize,
  canonicalizeStrict,
  compareUtf8,
  decodeB64uStrict,
  hashCanonical,
  strictParse,
} from './index';

const rejects = (text: string) => expect(() => strictParse(text)).toThrow(/strict JSON/);

describe('strict base64url', () => {
  const bytes = new Uint8Array(32).fill(7);
  const good = b64u(bytes);
  it('accepts canonical, rejects non-canonical tails / whitespace / padding / alphabet / length', () => {
    expect(decodeB64uStrict(good, 32)).toEqual(bytes);
    // 32 bytes => last char carries 4 spare bits: flip them
    const last = good[good.length - 1]!;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const other = alphabet[(alphabet.indexOf(last) + 1) % 64]!;
    expect(decodeB64uStrict(good.slice(0, -1) + other, 32)).toBeNull();
    expect(decodeB64uStrict(good + '\n', 32)).toBeNull();
    expect(decodeB64uStrict(' ' + good, 32)).toBeNull();
    expect(decodeB64uStrict(good + '=', 32)).toBeNull();
    expect(decodeB64uStrict(good.replace(/[-_]|./, '+'), 32)).toBeNull();
    expect(decodeB64uStrict(good, 31)).toBeNull();
    expect(decodeB64uStrict(good.slice(0, -1), 32)).toBeNull();
    expect(decodeB64uStrict(5)).toBeNull();
  });
});

describe('canonical key order is bytewise UTF-8 (== code point order)', () => {
  it('astral keys sort AFTER BMP keys above the surrogate range (UTF-16 order would differ)', () => {
    // U+FF5E (EF BD 9E) < U+1F600 (F0 9F 98 80) in UTF-8; in UTF-16 the pair D83D DE00 < FF5E.
    expect(canonicalize({ '\u{1F600}': 2, '～': 1 })).toBe('{"～":1,"\u{1F600}":2}');
    expect(compareUtf8('～', '\u{1F600}')).toBeLessThan(0);
    expect(compareUtf8('a', 'ab')).toBeLessThan(0);
  });
});

describe('canonicalizeStrict numbers / strings', () => {
  it('safe integers and short decimals only', () => {
    expect(canonicalizeStrict({ a: 0, b: -3, c: 9007199254740991, d: 0.5, e: -0.25, f: 0.1 })).toBe(
      '{"a":0,"b":-3,"c":9007199254740991,"d":0.5,"e":-0.25,"f":0.1}',
    );
    for (const bad of [9007199254740992, 2 ** 53 + 2, 1e21, 1e-7, 0.1 + 0.2, NaN, Infinity, -0]) {
      expect(() => canonicalizeStrict({ x: bad })).toThrow();
    }
  });
  it('rejects lone surrogates in values and keys, and over-deep nesting', () => {
    expect(() => canonicalizeStrict({ s: '\ud800' })).toThrow(/surrogate/);
    expect(() => canonicalizeStrict({ '\udc00': 1 })).toThrow(/surrogate/);
    expect(canonicalizeStrict({ s: '\u{1F600}' })).toBe('{"s":"\u{1F600}"}');
    let deep: unknown = 1;
    for (let i = 0; i < MAX_JSON_DEPTH + 1; i++) deep = [deep];
    expect(() => canonicalizeStrict(deep)).toThrow(/deep/);
    let ok: unknown = 1;
    for (let i = 0; i < MAX_JSON_DEPTH; i++) ok = [ok];
    expect(() => canonicalizeStrict(ok)).not.toThrow();
  });
});

describe('strictParse (independent of native JSON.parse)', () => {
  it('parses valid JSON to the canonical value', () => {
    const v = strictParse(' {"b":[1,-2,0.5,true,null,"x\\u00e9\\n"],"a":{"z":"\\/"}} ');
    expect(canonicalizeStrict(v)).toBe('{"a":{"z":"/"},"b":[1,-2,0.5,true,null,"xé\\n"]}');
  });
  it('rejects comments, duplicate keys, lone surrogates, deep nesting, non-canonical numbers, junk', () => {
    rejects('{"a":1}/*c*/');
    rejects('/*c*/{"a":1}');
    rejects('{"a":1 // c\n}');
    rejects('{"a":1,"a":2}');
    rejects('{"a":{"b":1,"b":1}}');
    rejects('{"s":"\\ud800"}');
    rejects('{"s":"\\udc00x"}');
    rejects('{"s":"\\ud800\\u0041"}');
    rejects('{"s":"\ud800"}');
    rejects('{"\\ud800":1}');
    rejects('[' .repeat(MAX_JSON_DEPTH + 1) + ']'.repeat(MAX_JSON_DEPTH + 1));
    rejects('{"a":1.0}');
    rejects('{"a":7e0}');
    rejects('{"a":1E2}');
    rejects('{"a":1.50}');
    rejects('{"a":-0}');
    rejects('{"a":9007199254740993}');
    rejects('{"a":01}');
    rejects('{"a":+1}');
    rejects('{"a":.5}');
    rejects('{"a":0.1234567890123456}'); // 16 significant digits
    rejects('{"a":1,}');
    rejects("{'a':1}");
    rejects('{"a":NaN}');
    rejects('﻿{"a":1}');
    rejects('{"a":1} ');
    rejects('{"a":"tab\there"}');
    rejects('{"a":"\\x"}');
    rejects('{"a":1} {"b":2}');
    rejects('');
  });
  it('accepts max depth, and "__proto__" is just a key', () => {
    expect(() => strictParse('['.repeat(MAX_JSON_DEPTH) + ']'.repeat(MAX_JSON_DEPTH))).not.toThrow();
    const v = strictParse('{"__proto__":{"polluted":true}}') as Record<string, unknown>;
    expect(Object.keys(v)).toEqual(['__proto__']);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(canonicalizeStrict(v)).toBe('{"__proto__":{"polluted":true}}');
  });
  it('is idempotent and deterministic: parse -> canonical -> parse -> canonical never drifts (JSON.parse regression guard)', () => {
    // The audit found native JSON.parse non-idempotent on Node v26 for escaped keys (parse X, parse Y, parse X
    // again drops a property). strictParse must never exhibit that: interleave escaped-key documents.
    const docs = [
      '{"a\\u0062":1,"\\u0061bc":2,"abd":3,"\\"q\\"":4,"\\ud83d\\ude00":5,"k\\\\":6}',
      '{"abc":1,"abd":2,"ab\\u0063":3}',
      '{"\\u0041":1,"A":null}',
    ].filter((d) => {
      try {
        strictParse(d);
        return true;
      } catch {
        return false; // dup-key docs are rejected, which is also correct
      }
    });
    const first = docs.map((d) => canonicalizeStrict(strictParse(d)));
    for (let round = 0; round < 50; round++) {
      docs.forEach((d, i) => {
        const v = strictParse(d);
        expect(canonicalizeStrict(v)).toBe(first[i]);
        expect(canonicalizeStrict(strictParse(canonicalizeStrict(v)))).toBe(first[i]);
        expect(hashCanonical(v)).toBe(hashCanonical(strictParse(first[i]!)));
      });
    }
    expect(first[0]).toBe('{"\\"q\\"":4,"ab":1,"abc":2,"abd":3,"k\\\\":6,"\u{1F600}":5}');
  });

  it('parse and canonicalize agree: every accepted number lexeme is reproduced byte-for-byte', () => {
    let seed = 12345;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    let accepted = 0;
    for (let i = 0; i < 3000; i++) {
      const digits = 1 + Math.floor(rnd() * 17);
      let mant = '';
      for (let k = 0; k < digits; k++) mant += Math.floor(rnd() * 10);
      const dot = Math.floor(rnd() * (digits + 1));
      const lex = (rnd() < 0.3 ? '-' : '') + (dot === 0 ? '0.' + mant : dot === digits ? mant : mant.slice(0, dot) + '.' + mant.slice(dot));
      let v: unknown;
      try {
        v = strictParse(lex);
      } catch {
        continue;
      }
      accepted++;
      expect(canonicalizeStrict(v)).toBe(lex);
    }
    expect(accepted).toBeGreaterThan(100);
  });
});
