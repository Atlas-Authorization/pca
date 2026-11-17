/**
 * The closed-world argument check. An action definition lists every parameter it accepts; a call is allowed through only when
 * every argument it carries is one of them, every required one is present, and each value is inside its declared domain.
 * Anything else is refused before a proof is ever built, so a tool that grew an argument, a model that invented one, or a payload
 * that hides one inside a nested object never reaches the upstream.
 *
 * The definitions come from the importers in `@atlasauth/pca-actions`, which are lossy by design (a JSON `number` is declared as a
 * string, an object with no declared members is a string placeholder). The check is therefore strict where the definition is
 * precise (integers, booleans, enums, sets, bounds, undeclared and missing members) and accepts a scalar or a bounded structure for
 * a string placeholder. Values must also be inside the strict canonical JSON domain, because that is what the proof signs.
 */

import { hashCanonical } from '@atlasauth/pca';
import type { ParamDef } from '@atlasauth/pca-actions';

const BAD_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_DEPTH = 8;

const isPlain = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && [Object.prototype, null].includes(Object.getPrototypeOf(v));
const utf8 = (s: string): number => Buffer.byteLength(s, 'utf8');

function leaf(d: ParamDef, v: unknown, path: string): string | undefined {
  const num = (x: unknown): x is number => typeof x === 'number' && Number.isSafeInteger(x) && !Object.is(x, -0);
  switch (d.type) {
    case 'integer':
      if (!num(v)) return `'${path}' must be a safe integer`;
      if ((d.min !== undefined && v < d.min) || (d.max !== undefined && v > d.max)) return `'${path}' is outside ${d.min ?? '-inf'}..${d.max ?? 'inf'}`;
      return undefined;
    case 'boolean':
      return typeof v === 'boolean' ? undefined : `'${path}' must be a boolean`;
    case 'date':
    case 'datetime':
    case 'duration':
    case 'object_ref':
      return typeof v === 'string' && v.length > 0 && utf8(v) <= 256 ? undefined : `'${path}' must be a short string`;
    case 'string': {
      if (typeof v === 'string') {
        if (d.max_len !== undefined && utf8(v) > d.max_len) return `'${path}' is longer than ${d.max_len} bytes`;
        if (d.values !== undefined && !d.values.includes(v)) return `'${path}' is not one of the allowed values`;
        return undefined;
      }
      // an importer placeholder (number, object without declared members): accepted only where no enum pins the value
      if (d.values !== undefined) return `'${path}' must be one of the allowed values`;
      if (typeof v === 'number' || typeof v === 'boolean' || Array.isArray(v) || isPlain(v)) return undefined;
      return `'${path}' has no usable value`;
    }
    case 'set':
    case 'array': {
      if (!Array.isArray(v)) return `'${path}' must be an array`;
      if (d.min_items !== undefined && v.length < d.min_items) return `'${path}' has fewer than ${d.min_items} items`;
      if (d.max_items !== undefined && v.length > d.max_items) return `'${path}' has more than ${d.max_items} items`;
      if (d.type === 'set' && new Set(v.map((x) => JSON.stringify(x))).size !== v.length) return `'${path}' has a repeated item`;
      for (const x of v) {
        if (d.type === 'set') {
          if (typeof x !== 'string' || (d.values !== undefined && !d.values.includes(x))) return `'${path}' has an item that is not allowed`;
        } else if (d.items === 'integer') {
          if (!num(x)) return `'${path}' items must be safe integers`;
        } else if (d.items === 'string') {
          if (typeof x !== 'string') return `'${path}' items must be strings`;
        } else if (d.items === 'boolean') {
          if (typeof x !== 'boolean') return `'${path}' items must be booleans`;
        } else if (x !== null && typeof x === 'object') return `'${path}' items must be scalars`;
      }
      return undefined;
    }
    default:
      return `'${path}' has an unknown declared type`;
  }
}

/**
 * Check `args` against the definition's parameters. Returns the first problem as text, or `undefined` when the call conforms.
 * Never throws.
 */
export function checkArgs(params: Readonly<Record<string, ParamDef>>, args: unknown, maxBytes: number): string | undefined {
  try {
    if (!isPlain(args)) return 'the arguments must be a JSON object';
    const text = JSON.stringify(args);
    if (utf8(text) > maxBytes) return `the arguments exceed ${maxBytes} bytes`;
    const declared = new Set(Object.keys(params));
    const prefixes = new Set<string>();
    for (const name of declared) {
      const parts = name.split('.');
      for (let i = 1; i < parts.length; i++) prefixes.add(parts.slice(0, i).join('.'));
    }
    const seen = new Set<string>();
    const walk = (o: Record<string, unknown>, prefix: string, depth: number): string | undefined => {
      if (depth > MAX_DEPTH) return 'the arguments are nested too deeply';
      for (const k of Object.keys(o)) {
        if (BAD_KEYS.has(k) || k.includes('.') || k.length === 0 || k.length > 128) return `the argument name '${k.slice(0, 40)}' is not allowed`;
        const path = prefix === '' ? k : `${prefix}.${k}`;
        const v = o[k];
        if (declared.has(path)) {
          const bad = leaf(params[path]!, v, path);
          if (bad !== undefined) return bad;
          seen.add(path);
        } else if (prefixes.has(path)) {
          if (!isPlain(v)) return `'${path}' must be an object`;
          const bad = walk(v, path, depth + 1);
          if (bad !== undefined) return bad;
        } else return `'${path}' is not a declared parameter`;
      }
      return undefined;
    };
    const bad = walk(args, '', 0);
    if (bad !== undefined) return bad;
    for (const [name, d] of Object.entries(params)) if (d.required !== false && !seen.has(name)) return `the required parameter '${name}' is missing`;
    // the proof signs the strict canonical form: refuse here, with a reason, what it could not sign
    try {
      hashCanonical(args);
    } catch (e) {
      return `the arguments are outside the canonical JSON profile the proof signs (${e instanceof Error ? e.message.slice(0, 120) : 'rejected'})`;
    }
    return undefined;
  } catch (e) {
    return `the arguments could not be checked (${e instanceof Error ? e.message.slice(0, 120) : 'error'})`;
  }
}
