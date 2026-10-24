/** Load a store adapter from a module path (`./my-adapter.mjs`) or a built-in reference (`builtin:<name>`). */
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { REFERENCE_ADAPTERS } from './reference';
import type { StoreAdapter } from './types';

const isAdapterLike = (x: unknown): boolean =>
  typeof x === 'function' || (!!x && typeof x === 'object' && typeof (x as { open?: unknown }).open === 'function');

/**
 * The module may export the adapter (or a factory `(options) => adapter`) as its default export, as `adapter`, or as
 * `createAdapter`; a CommonJS module's `module.exports` may be any of these too.
 */
export function pickExport(mod: Record<string, unknown>): unknown {
  const d = mod.default as Record<string, unknown> | undefined;
  return [mod.default, mod.adapter, mod.createAdapter, d?.adapter, d?.createAdapter].find(isAdapterLike);
}

export async function loadAdapter(spec: string, options: Record<string, string> = {}): Promise<StoreAdapter> {
  let exported: unknown;
  if (spec.startsWith('builtin:')) {
    const name = spec.slice('builtin:'.length);
    if (!Object.prototype.hasOwnProperty.call(REFERENCE_ADAPTERS, name)) {
      throw new Error(`unknown built-in adapter '${name}' (known: ${Object.keys(REFERENCE_ADAPTERS).join(', ')})`);
    }
    exported = REFERENCE_ADAPTERS[name];
  } else {
    exported = pickExport((await import(pathToFileURL(resolve(spec)).href)) as Record<string, unknown>);
  }
  const a = (typeof exported === 'function' ? await (exported as (o: Record<string, string>) => unknown)(options) : exported) as StoreAdapter | undefined;
  if (!a || typeof a.open !== 'function' || typeof a.name !== 'string') {
    throw new TypeError(`${spec}: does not export a store adapter (an object with a string 'name' and an 'open()' method, or a factory returning one)`);
  }
  return a;
}
