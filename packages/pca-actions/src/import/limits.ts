// limits.ts - the bounds every importer enforces before it believes a byte of foreign input (spec section 5.1: "bounded:
// size, depth, ref-expansion limits"). A source that exceeds a hard bound is REFUSED as a whole (ActionKitError
// 'import_limit'); a recoverable shortfall (an unresolvable reference, a union) is a Todo and the def fails closed.

import { ActionKitError } from '../def';

export interface ImportLimits {
  /** Source size: UTF-8 bytes of a text source, serialized length of a parsed one. */
  max_bytes: number;
  /** Operations (defs) one import may produce. */
  max_ops: number;
  /** Nesting depth of the parsed source. */
  max_json_depth: number;
  /** Nodes (objects, arrays, scalars) of the parsed source. */
  max_nodes: number;
  /** Schema nodes one operation may expand through `$ref`/`allOf`/`anyOf` (the ref-bomb bound). */
  max_ref_nodes: number;
  /** Reference chain / schema nesting depth. */
  max_ref_depth: number;
}

export const DEFAULT_IMPORT_LIMITS: Readonly<ImportLimits> = Object.freeze({
  max_bytes: 64 * 1024 * 1024,
  max_ops: 20_000,
  max_json_depth: 64,
  max_nodes: 6_000_000,
  max_ref_nodes: 20_000,
  max_ref_depth: 8,
});

/** Ceilings no caller may raise past: a caller-supplied limit is clamped to these. */
export const HARD_IMPORT_LIMITS: Readonly<ImportLimits> = Object.freeze({
  max_bytes: 256 * 1024 * 1024,
  max_ops: 50_000,
  max_json_depth: 128,
  max_nodes: 20_000_000,
  max_ref_nodes: 200_000,
  max_ref_depth: 16,
});

export function resolveLimits(over?: Partial<ImportLimits>): ImportLimits {
  const out = { ...DEFAULT_IMPORT_LIMITS };
  for (const k of Object.keys(out) as (keyof ImportLimits)[]) {
    const v = over?.[k];
    if (v === undefined) continue;
    if (!Number.isSafeInteger(v) || v < 1) throw new ActionKitError('bad_limit', `limit ${k} must be a positive safe integer`);
    out[k] = Math.min(v, HARD_IMPORT_LIMITS[k]);
  }
  return out;
}

const enc = new TextEncoder();

/** Size check of a text source (UTF-8 bytes). */
export function textSizeCheck(text: string, lim: ImportLimits): void {
  if (typeof text !== 'string') throw new ActionKitError('bad_source', 'the source must be text');
  // 3 bytes per UTF-16 unit is an upper bound: only encode when that bound could exceed the limit
  if (text.length * 3 > lim.max_bytes && enc.encode(text).length > lim.max_bytes) throw new ActionKitError('import_limit', `the source is larger than ${lim.max_bytes} bytes`);
}

/**
 * Walk a parsed source iteratively (no recursion, so a hostile depth cannot overflow the stack) and refuse it when it is
 * not plain JSON data, is deeper or larger than the limits, or has a cycle. Returns the node count.
 */
export function checkParsed(root: unknown, lim: ImportLimits): number {
  let nodes = 0;
  let bytes = 0;
  const stack: { v: unknown; d: number }[] = [{ v: root, d: 0 }];
  while (stack.length > 0) {
    const { v, d } = stack.pop()!;
    if (++nodes > lim.max_nodes) throw new ActionKitError('import_limit', `the source has more than ${lim.max_nodes} nodes`);
    if (d > lim.max_json_depth) throw new ActionKitError('import_limit', `the source nests deeper than ${lim.max_json_depth}`);
    if (v === null || typeof v === 'boolean') {
      bytes += 4;
    } else if (typeof v === 'number') {
      if (!Number.isFinite(v)) throw new ActionKitError('bad_source', 'the source holds a non-finite number');
      bytes += 8;
    } else if (typeof v === 'string') {
      bytes += v.length;
    } else if (Array.isArray(v)) {
      bytes += 2 + v.length;
      for (const x of v) stack.push({ v: x, d: d + 1 });
    } else if (typeof v === 'object') {
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw new ActionKitError('bad_source', 'the source holds a non-plain object');
      for (const k of Object.keys(v as object)) {
        bytes += k.length + 4;
        stack.push({ v: (v as Record<string, unknown>)[k], d: d + 1 });
      }
    } else {
      throw new ActionKitError('bad_source', `the source holds a ${typeof v}`);
    }
    // a cycle is an unbounded depth: the depth bound above stops it; the byte bound stops a wide DAG
    if (bytes > lim.max_bytes) throw new ActionKitError('import_limit', `the source is larger than ${lim.max_bytes} bytes`);
  }
  return nodes;
}
