/**
 * Duplicate-member check for JSON received from outside (signed or digested). `JSON.parse` keeps the LAST duplicate, so
 * the signer and a verifier could read different claims from the same bytes. This checks ONLY duplicates (any depth, keys
 * compared after unescaping, so "a" and "a" collide); numbers and everything else stay as the sender wrote them.
 * Use `strictParse` instead for formats we define.
 */
export function duplicateKey(text: string): string | undefined {
  const stack: (Set<string> | null)[] = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i] as string;
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (expectKey && top) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.has(key)) return key;
        top.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c === '{') {
      stack.push(new Set());
      expectKey = true;
    } else if (c === '[') {
      stack.push(null);
      expectKey = false;
    } else if (c === '}' || c === ']') {
      stack.pop();
      expectKey = false;
    } else if (c === ',') {
      expectKey = stack[stack.length - 1] instanceof Set;
    }
  }
  return undefined;
}

/** `JSON.parse` that refuses a duplicate member (message `duplicate key "k"`). */
export function parseNoDuplicates(text: string): unknown {
  const v = JSON.parse(text);
  const k = duplicateKey(text);
  if (k !== undefined) throw new SyntaxError(`duplicate key ${JSON.stringify(k)}`);
  return v;
}
