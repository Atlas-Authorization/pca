// A JSON.parse replacement for the ORACLE side. Some V8 builds (e.g. Node v26.0.0) have a JSON.parse
// bug where re-parsing the same text can drop properties (see repro/node-jsonparse-escaped-keys.mjs),
// which would make the TS oracle non-deterministic. Validity is still decided by JSON.parse (a syntax
// error is a syntax error); VALUES are rebuilt from our literal-preserving parser. Semantics match
// JSON.parse exactly: numbers -> IEEE-754 double via Number(), duplicate keys last-wins, own "__proto__".
import { parse as astParse, type Node } from './jsonast';

export const stats = { fallbacks: 0, calls: 0, mismatches: 0 };

function build(n: Node): unknown {
  switch (n.t) {
    case 'lit': return n.s === 'true' ? true : n.s === 'false' ? false : n.s === 'null' ? null : Number(n.s);
    case 'str': return n.v;
    case 'arr': return n.items.map(build);
    case 'obj': {
      const o: Record<string, unknown> = {};
      for (const [k, v] of n.kv) Object.defineProperty(o, k, { value: build(v), enumerable: true, writable: true, configurable: true });
      return o;
    }
  }
}

export function safeParse(text: string): unknown {
  stats.calls++;
  const native = JSON.parse(text); // throws on invalid JSON (authoritative for syntax)
  try {
    return build(astParse(text));
  } catch (e) {
    if (e instanceof RangeError) { stats.fallbacks++; return native; } // too deep for the AST parser
    throw e;
  }
}
