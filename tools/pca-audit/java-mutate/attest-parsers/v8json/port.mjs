// faithful JS port of AttestV8Json.java (after the dead-guard deletions)
export function v8JsonError(src) {
  let pos = 0, err = "";
  const len = src.length;
  const isHi = c => c >= 0xd800 && c <= 0xdbff, isLo = c => c >= 0xdc00 && c <= 0xdfff, isSur = c => c >= 0xd800 && c <= 0xdfff;
  function dec(a, b) { let s = ""; for (let i = a; i < b; i++) { const c = src.charCodeAt(i);
    if (isHi(c) && i + 1 < b && isLo(src.charCodeAt(i + 1))) { s += src[i] + src[++i]; } else if (isSur(c)) s += "�"; else s += src[i]; } return s; }
  function location(position) { let line = 1, last = -1; for (let i = 0; i < position && i < len; i++) { const c = src[i];
    if (c === "\n" || (c === "\r" && !(i + 1 < len && src[i + 1] === "\n"))) { line++; last = i; } } return [line, position - last]; }
  function fail(fmt, position) { if (err !== "") return; const [l, c] = location(position); err = fmt.replace("%d", position).replace("%d", l).replace("%d", c); }
  const failExpected = (w, p) => fail(w + " in JSON at position %d (line %d column %d)", p);
  function unexpectedEnd() { err = "Unexpected end of JSON input"; }
  function unexpectedToken(position) { const whole = dec(0, len);
    if (["NaN","Infinity","undefined","[object Object]"].includes(whole)) { err = '"' + whole + '" is not valid JSON'; return; }
    const ctx = 10, tok = dec(position, position + 1), n = len;
    if (n < ctx * 2 + 1) err = "Unexpected token '" + tok + "', \"" + whole + "\" is not valid JSON";
    else if (position < ctx) err = "Unexpected token '" + tok + "', \"" + dec(0, position + ctx) + "\"... is not valid JSON";
    else if (position < n - ctx) err = "Unexpected token '" + tok + "', ...\"" + dec(position - ctx, position + ctx) + "\"... is not valid JSON";
    else err = "Unexpected token '" + tok + "', ...\"" + dec(position - ctx, n) + "\" is not valid JSON"; }
  function ws() { while (pos < len) { const c = src[pos]; if (c === " " || c === "\t" || c === "\n" || c === "\r") pos++; else return; } }
  const peek = () => pos >= len ? -1 : src.charCodeAt(pos);
  const isDigit = c => c >= 48 && c <= 57;
  const ch = s => s.charCodeAt(0);
  function value() { ws(); const c = peek();
    if (c < 0) unexpectedEnd(); else if (c === 34) str(); else if (c === 123) object(); else if (c === 91) array();
    else if (c === 45 || isDigit(c)) number(); else if (c === ch("t")) literal("true"); else if (c === ch("f")) literal("false");
    else if (c === ch("n")) literal("null"); else unexpectedToken(pos); }
  function literal(w) { for (let i = 0; i < w.length; i++) { if (pos >= len) { unexpectedEnd(); return; } if (src[pos] !== w[i]) { const c = src.charCodeAt(pos); if (c === 34) fail("Unexpected string in JSON at position %d (line %d column %d)", pos); else if (c === 45 || isDigit(c)) fail("Unexpected number in JSON at position %d (line %d column %d)", pos); else unexpectedToken(pos); return; } pos++; } }
  function number() {
    if (peek() === 45) { pos++; if (!isDigit(peek())) { failExpected("No number after minus sign", pos); return; } }
    if (peek() === 48) { pos++; if (isDigit(peek())) { fail("Unexpected number in JSON at position %d (line %d column %d)", pos); return; } }
    else { while (isDigit(peek())) pos++; }
    if (peek() === 46) { pos++; if (!isDigit(peek())) { failExpected("Unterminated fractional number", pos); return; } while (isDigit(peek())) pos++; }
    const c = peek();
    if (c === ch("e") || c === ch("E")) { pos++; const s = peek(); if (s === 43 || s === 45) pos++;
      if (!isDigit(peek())) { failExpected("Exponent part is missing a number", pos); return; } while (isDigit(peek())) pos++; } }
  function str() { pos++; while (true) { const c = peek();
    if (c < 0) { failExpected("Unterminated string", pos); return; }
    else if (c === 34) { pos++; return; }
    else if (c < 0x20) { failExpected("Bad control character in string literal", pos); return; }
    else if (c === 92) { pos++; const e = peek();
      if ([34,92,47,ch("b"),ch("f"),ch("n"),ch("r"),ch("t")].includes(e)) pos++;
      else if (e === ch("u")) { pos++; for (let i = 0; i < 4; i++) { const h = peek();
          if (!(isDigit(h) || (h >= 97 && h <= 102) || (h >= 65 && h <= 70))) { failExpected("Bad Unicode escape", pos); return; } pos++; } }
      else if (e === -1) { unexpectedEnd(); return; } else if (e > 0xff) { unexpectedToken(pos); return; }
      else { failExpected("Bad escaped character", pos); return; } }
    else pos++; } }
  function object() { pos++; ws(); if (peek() === 125) { pos++; return; }
    if (peek() !== 34) { failExpected("Expected property name or '}'", pos); return; }
    while (true) { str(); if (err !== "") return; ws(); if (peek() !== 58) { failExpected("Expected ':' after property name", pos); return; }
      pos++; value(); if (err !== "") return; ws(); const c = peek();
      if (c === 44) { pos++; ws(); if (peek() !== 34) { failExpected("Expected double-quoted property name", pos); return; } }
      else if (c === 125) { pos++; return; } else { failExpected("Expected ',' or '}' after property value", pos); return; } } }
  function array() { pos++; ws(); if (peek() === 93) { pos++; return; }
    while (true) { value(); if (err !== "") return; ws(); const c = peek();
      if (c === 44) pos++; else if (c === 93) { pos++; return; } else { failExpected("Expected ',' or ']' after array element", pos); return; } } }
  value();
  ws();
  if (pos < len) fail("Unexpected non-whitespace character after JSON at position %d (line %d column %d)", pos);
  return err;
}
