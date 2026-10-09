import { MAX_DECIMAL_DIGITS, MAX_JSON_DEPTH, hasLoneSurrogate } from './hash';

/**
 * STRICT JSON profile for signed bytes (PCActn wire v2). A hand-written RFC 8259 parser, deliberately
 * INDEPENDENT of native `JSON.parse` (whose behaviour differs across engines and is not idempotent on some
 * Node builds), so every verifier reaches the same value from the same bytes. It rejects:
 *  - comments, trailing commas, NaN/Infinity, single quotes, a BOM, any non-JSON whitespace;
 *  - duplicate object keys (anywhere);
 *  - lone surrogates (raw or as `\uD800`-style escapes);
 *  - raw control characters (< U+0020) inside strings, and unknown escapes;
 *  - nesting deeper than {@link MAX_JSON_DEPTH} containers;
 *  - numbers that are not in the canonical wire form: no exponent, no leading `+`/zeros, no `-0`, no trailing
 *    fractional zero (`1.0`, `1.50`), integers outside the safe range (|n| > 2^53-1), and non-integers with
 *    more than 15 significant digits or magnitude below 1e-6 (the plain-decimal limit of ECMAScript
 *    `Number::toString`);
 *  - input longer than {@link MAX_JSON_BYTES} UTF-16 units.
 * Object keys are materialised as plain own data properties (so `"__proto__"` is just a key).
 */
export const MAX_JSON_BYTES = 1 << 20;

export class StrictJsonError extends Error {
  constructor(message: string, public readonly offset: number) {
    super(`strict JSON: ${message} (at offset ${offset})`);
    this.name = 'StrictJsonError';
  }
}

const NUM = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

export function strictParse(text: string): unknown {
  if (typeof text !== 'string') throw new StrictJsonError('input is not a string', 0);
  // NORMATIVE: the input-size bound is in UTF-8 BYTES (portable; bounds storage), not UTF-16 units.
  if (new TextEncoder().encode(text).length > MAX_JSON_BYTES) throw new StrictJsonError('input too large', 0);
  let i = 0;
  const err = (m: string): never => {
    throw new StrictJsonError(m, i);
  };
  const ws = () => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  const parseString = (): string => {
    // text[i] === '"'
    i++;
    let out = '';
    let start = i;
    for (;;) {
      if (i >= text.length) err('unterminated string');
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        break;
      }
      if (c < 0x20) err('raw control character in string');
      if (c === 0x5c) {
        out += text.slice(start, i);
        i++;
        const e = text[i];
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const h = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(h)) err('bad \\u escape');
            out += String.fromCharCode(parseInt(h, 16));
            i += 4;
            break;
          }
          default:
            err('unknown escape');
        }
        i++;
        start = i;
        continue;
      }
      i++;
    }
    if (hasLoneSurrogate(out)) err('lone surrogate in string');
    return out;
  };

  const parseNumber = (): number => {
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (!m) return err('bad number');
    const lex = m[0];
    i += lex.length;
    if (/[eE]/.test(lex)) err('exponent form is not allowed (use a plain decimal)');
    if (lex === '-0') err('negative zero is not allowed');
    if (lex.includes('.')) {
      if (lex.endsWith('0')) err('trailing fractional zero is not canonical');
      const digits = lex.replace('-', '').replace('.', '').replace(/^0+/, '');
      if (digits.length > MAX_DECIMAL_DIGITS) err(`more than ${MAX_DECIMAL_DIGITS} significant digits`);
      const v = Number(lex);
      if (v !== 0 && Math.abs(v) < 1e-6) err('non-integer magnitude below 1e-6 is not allowed');
      return v;
    }
    const abs = lex.startsWith('-') ? lex.slice(1) : lex;
    if (abs.length > 16 || BigInt(abs) > 9007199254740991n) err('integer outside the safe range (|n| > 2^53-1)');
    return Number(lex);
  };

  const parseValue = (depth: number): unknown => {
    ws();
    if (i >= text.length) err('unexpected end of input');
    const ch = text[i]!;
    if (ch === '{') {
      if (depth > MAX_JSON_DEPTH) err('nesting too deep');
      i++;
      const o: Record<string, unknown> = {};
      const seen = new Set<string>();
      ws();
      if (text[i] === '}') {
        i++;
        return o;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') err('expected a string key');
        const k = parseString();
        if (seen.has(k)) err(`duplicate key ${JSON.stringify(k)}`);
        seen.add(k);
        ws();
        if (text[i] !== ':') err('expected ":"');
        i++;
        const v = parseValue(depth + 1);
        Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === '}') {
          i++;
          return o;
        }
        err('expected "," or "}"');
      }
    }
    if (ch === '[') {
      if (depth > MAX_JSON_DEPTH) err('nesting too deep');
      i++;
      const a: unknown[] = [];
      ws();
      if (text[i] === ']') {
        i++;
        return a;
      }
      for (;;) {
        a.push(parseValue(depth + 1));
        ws();
        if (text[i] === ',') {
          i++;
          continue;
        }
        if (text[i] === ']') {
          i++;
          return a;
        }
        err('expected "," or "]"');
      }
    }
    if (ch === '"') return parseString();
    if (ch === '-' || (ch >= '0' && ch <= '9')) return parseNumber();
    if (text.startsWith('true', i)) {
      i += 4;
      return true;
    }
    if (text.startsWith('false', i)) {
      i += 5;
      return false;
    }
    if (text.startsWith('null', i)) {
      i += 4;
      return null;
    }
    return err('unexpected token');
  };

  const v = parseValue(1);
  ws();
  if (i < text.length) err('trailing characters after the JSON value');
  return v;
}

/** Decode UTF-8 bytes (fatal on invalid sequences, no BOM stripping) then {@link strictParse}. */
export function strictParseBytes(bytes: Uint8Array): unknown {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  return strictParse(text);
}
