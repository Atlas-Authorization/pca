/** Remove credentials from text the doctor prints: URL userinfo, `token=` / `password=` pairs, bearer credentials, JWTs and long token runs. */
export function scrubText(text: string): string {
  let t = String(text);
  t = t.replace(/\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]*/g, '[redacted]');
  t = t.replace(/\b(authorization["']?\s*[:=]\s*)[^\n"']*/gi, '$1[redacted]');
  t = t.replace(/\b(Bearer|Basic|Token)\s+[\w.~+/=-]{6,}/gi, '$1 [redacted]');
  t = t.replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]*:[^\s/@]*@/gi, '$1[redacted]@');
  t = t.replace(/\b((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth|sslpassword)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s"'&,;]+)/gi, '$1[redacted]');
  t = t.replace(/[A-Za-z0-9_-]{40,}/g, '[redacted]');
  return t.length > 600 ? `${t.slice(0, 600)}...` : t;
}

/** Scrub every string inside a JSON-like value. */
export function scrubDeep<T>(v: T, depth = 0): T {
  if (typeof v === 'string') return scrubText(v) as unknown as T;
  if (depth > 8 || v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map((x) => scrubDeep(x, depth + 1)) as unknown as T;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) out[k] = scrubDeep(x, depth + 1);
  return out as T;
}
