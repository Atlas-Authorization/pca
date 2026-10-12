/**
 * Construction-time snapshots of verifier configuration.
 *
 * Every verifier factory validates its policy when it is built (non-empty allowlists, known fields, ...). If it then
 * kept the caller's arrays and objects by reference, a later mutation (an allowlist emptied to "revoke everything", an
 * optional gate cleared, a pin list edited) would silently change what the BUILT verifier enforces, typically turning
 * an empty list into "not gated" (accept-all). `snapshotConfig` returns a deep, frozen copy of the DATA in a value:
 *
 *   - arrays and plain objects (prototype Object.prototype or null) are copied recursively and frozen;
 *   - typed arrays / ArrayBuffers are copied (they cannot be frozen, but the copy is unshared);
 *   - Map / Set are copied (entries snapshotted); Date is copied;
 *   - functions and class instances (KeyObject, X509Certificate, stores, verifiers) are kept by reference: they are
 *     behaviour, not data, and may rely on their own identity / internal state.
 *
 * Cycles are preserved. Never throws for ordinary configuration values.
 */
export function snapshotConfig<T>(value: T, opts: { keep?: readonly string[] } = {}): T {
  const seen = new WeakMap<object, unknown>();
  const keep = opts.keep ?? [];
  if (keep.length === 0 || value === null || typeof value !== 'object' || Array.isArray(value) || !isPlainObject(value)) return snap(value, seen) as T;
  // `keep`: top-level members that are BEHAVIOUR / STATE (stores, verifiers, backends) and must stay the caller's object.
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) out[k] = keep.includes(k) ? v : snap(v, seen);
  return Object.freeze(out) as T;
}

function isPlainObject(v: object): boolean {
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function snap(v: unknown, seen: WeakMap<object, unknown>): unknown {
  if (v === null || (typeof v !== 'object' && typeof v !== 'function')) return v;
  if (typeof v === 'function') return v;
  const o = v as object;
  if (seen.has(o)) return seen.get(o);
  if (ArrayBuffer.isView(o)) {
    const c = (o as Uint8Array).slice();
    seen.set(o, c);
    return c;
  }
  if (o instanceof ArrayBuffer) {
    const c = o.slice(0);
    seen.set(o, c);
    return c;
  }
  if (o instanceof Date) {
    const c = new Date(o.getTime());
    seen.set(o, c);
    return c;
  }
  if (o instanceof Map) {
    const c = new Map();
    seen.set(o, c);
    for (const [k, val] of o) c.set(snap(k, seen), snap(val, seen));
    return c;
  }
  if (o instanceof Set) {
    const c = new Set();
    seen.set(o, c);
    for (const val of o) c.add(snap(val, seen));
    return c;
  }
  if (Array.isArray(o)) {
    const c: unknown[] = [];
    seen.set(o, c);
    for (const val of o) c.push(snap(val, seen));
    return Object.freeze(c);
  }
  if (!isPlainObject(o)) return o;
  const c: Record<PropertyKey, unknown> = Object.getPrototypeOf(o) === null ? Object.create(null) : {};
  seen.set(o, c);
  for (const k of Reflect.ownKeys(o)) {
    const d = Object.getOwnPropertyDescriptor(o, k);
    if (!d || !d.enumerable) continue;
    c[k as string] = 'value' in d ? snap(d.value, seen) : snap((o as Record<PropertyKey, unknown>)[k as string], seen);
  }
  return Object.freeze(c);
}
