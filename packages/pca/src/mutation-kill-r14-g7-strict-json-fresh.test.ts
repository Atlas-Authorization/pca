/**
 * r14 static-mutant kills for strict-json.ts (fresh module): the NUM lexer. Every number form (sign, multi-digit
 * integer, fraction, every exponent variant) is pinned by its exact outcome: the parsed value, or the exact
 * StrictJsonError message (which names the offset where the lexed number ended).
 */
import { describe, expect, it, vi } from 'vitest';

const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: { name: (e as Error)?.name, message: (e as Error)?.message } };
  }
};
const TABLE: [string, unknown][] = [
 [
  "5",
  {
   "ok": true,
   "value": 5
  }
 ],
 [
  "-5",
  {
   "ok": true,
   "value": -5
  }
 ],
 [
  "0",
  {
   "ok": true,
   "value": 0
  }
 ],
 [
  "-0",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: negative zero is not allowed (at offset 2)"
   }
  }
 ],
 [
  "123",
  {
   "ok": true,
   "value": 123
  }
 ],
 [
  "-123",
  {
   "ok": true,
   "value": -123
  }
 ],
 [
  "9007199254740991",
  {
   "ok": true,
   "value": 9007199254740991
  }
 ],
 [
  "1.5",
  {
   "ok": true,
   "value": 1.5
  }
 ],
 [
  "1.25",
  {
   "ok": true,
   "value": 1.25
  }
 ],
 [
  "-0.5",
  {
   "ok": true,
   "value": -0.5
  }
 ],
 [
  "10.75",
  {
   "ok": true,
   "value": 10.75
  }
 ],
 [
  "1e5",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 3)"
   }
  }
 ],
 [
  "1E5",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 3)"
   }
  }
 ],
 [
  "1e+5",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 4)"
   }
  }
 ],
 [
  "1e-5",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 4)"
   }
  }
 ],
 [
  "1e10",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 4)"
   }
  }
 ],
 [
  "1.5e2",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: exponent form is not allowed (use a plain decimal) (at offset 5)"
   }
  }
 ],
 [
  "01",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: trailing characters after the JSON value (at offset 1)"
   }
  }
 ],
 [
  "1.",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: trailing characters after the JSON value (at offset 1)"
   }
  }
 ],
 [
  ".5",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: unexpected token (at offset 0)"
   }
  }
 ],
 [
  "-",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: bad number (at offset 0)"
   }
  }
 ],
 [
  "1e",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: trailing characters after the JSON value (at offset 1)"
   }
  }
 ],
 [
  "1ex",
  {
   "ok": false,
   "error": {
    "name": "StrictJsonError",
    "message": "strict JSON: trailing characters after the JSON value (at offset 1)"
   }
  }
 ],
 [
  "[1,23]",
  {
   "ok": true,
   "value": [
    1,
    23
   ]
  }
 ],
 [
  "{\"a\":12.5}",
  {
   "ok": true,
   "value": {
    "a": 12.5
   }
  }
 ]
];

describe('strict-json.ts NUM (fresh module)', () => {
  it('every number form has its exact outcome', async () => {
    vi.resetModules();
    const m = await import('./strict-json');
    expect(TABLE.map(([t]) => [t, settle(() => m.strictParse(t))])).toEqual(TABLE);
  });
});
