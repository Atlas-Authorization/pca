// Literal-preserving JSON AST: keeps number literals, duplicate keys and key order verbatim, so
// metamorphic transforms can rewrite FORMAT without touching VALUE.
export type Node =
  | { t: 'obj'; kv: [string, Node][] } // key = decoded key string
  | { t: 'arr'; items: Node[] }
  | { t: 'str'; v: string }
  | { t: 'lit'; s: string }; // number/true/false/null literal text

export function parse(text: string): Node {
  let i = 0;
  const ws = () => { while (' \t\n\r'.includes(text[i] ?? 'x')) i++; };
  const val = (): Node => {
    ws();
    const c = text[i];
    if (c === '{') {
      i++; const kv: [string, Node][] = []; ws();
      if (text[i] === '}') { i++; return { t: 'obj', kv }; }
      for (;;) {
        ws(); const k = strTok(); ws();
        if (text[i++] !== ':') throw new Error('colon');
        kv.push([JSON.parse(k), val()]); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i++] === '}') return { t: 'obj', kv };
        throw new Error('obj');
      }
    }
    if (c === '[') {
      i++; const items: Node[] = []; ws();
      if (text[i] === ']') { i++; return { t: 'arr', items }; }
      for (;;) {
        items.push(val()); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i++] === ']') return { t: 'arr', items };
        throw new Error('arr');
      }
    }
    if (c === '"') return { t: 'str', v: JSON.parse(strTok()) };
    const m = /^[^,\]\}\s]+/.exec(text.slice(i));
    if (!m) throw new Error('lit');
    i += m[0].length;
    return { t: 'lit', s: m[0] };
  };
  const strTok = (): string => {
    const s = i; i++;
    while (text[i] !== '"') { if (i >= text.length) throw new Error('unterminated'); if (text[i] === '\\') i++; i++; }
    i++;
    return text.slice(s, i);
  };
  const r = val(); ws();
  if (i !== text.length) throw new Error('trailing');
  return r;
}

export interface EmitOpts {
  rng: () => number;
  ws: boolean; // random whitespace between tokens
  escapeStrings: boolean; // randomly \uXXXX-escape characters (value-preserving)
  shuffleKeys: boolean; // only safe when no duplicate keys
  numRepr: boolean; // rewrite integer literal N as N.0 / Ne0 (value-equal as a double)
}

export function emit(n: Node, o: EmitOpts): string {
  const sp = () => (o.ws ? [' ', '', '\n', '\t', '  ', '\r\n'][Math.floor(o.rng() * 6)] : '');
  const str = (s: string) => {
    if (!o.escapeStrings) return JSON.stringify(s);
    let out = '"';
    for (let k = 0; k < s.length; k++) {
      const u = s.charCodeAt(k);
      const ch = s[k]!;
      const hex = u.toString(16).padStart(4, '0');
      if (u >= 0xd800 && u <= 0xdfff) out += '\\u' + (o.rng() < 0.5 ? hex : hex.toUpperCase());
      else if (ch !== '"' && ch !== '\\' && o.rng() < 0.3) out += '\\u' + (o.rng() < 0.5 ? hex : hex.toUpperCase());
      else if (ch === '/' && o.rng() < 0.3) out += '\\/';
      else out += JSON.stringify(ch).slice(1, -1);
    }
    return out + '"';
  };
  const go = (x: Node): string => {
    switch (x.t) {
      case 'lit': {
        if (o.numRepr && /^-?(0|[1-9]\d*)$/.test(x.s) && o.rng() < 0.5) return x.s + (o.rng() < 0.5 ? '.0' : 'e0');
        return x.s;
      }
      case 'str': return str(x.v);
      case 'arr': return '[' + sp() + x.items.map((y) => go(y)).join(sp() + ',' + sp()) + sp() + ']';
      case 'obj': {
        let kv = x.kv;
        if (o.shuffleKeys) {
          kv = [...kv];
          for (let k = kv.length - 1; k > 0; k--) { const j = Math.floor(o.rng() * (k + 1)); [kv[k], kv[j]] = [kv[j]!, kv[k]!]; }
        }
        return '{' + sp() + kv.map(([k, v]) => str(k) + sp() + ':' + sp() + go(v)).join(sp() + ',' + sp()) + sp() + '}';
      }
    }
  };
  return go(n);
}

export function hasDupKeys(n: Node): boolean {
  if (n.t === 'arr') return n.items.some(hasDupKeys);
  if (n.t === 'obj') {
    const seen = new Set<string>();
    for (const [k, v] of n.kv) { if (seen.has(k)) return true; seen.add(k); if (hasDupKeys(v)) return true; }
  }
  return false;
}
