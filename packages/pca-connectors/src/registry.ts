/**
 * The connector registry: an in-memory map of provider id → {@link ProviderManifest}. A manifest is
 * validated on the way in, so nothing malformed can ever be looked up. A process-wide {@link defaultRegistry}
 * is seeded with the built-in catalog; callers who want isolation build their own with {@link createDefaultRegistry}.
 */

import { ConnectorError, type ProviderManifest, UnknownProviderError, assertManifest, manifestDigest } from './manifest';
import { hashCanonical } from '@atlasauth/pca';
import { BUILTIN_MANIFESTS } from './providers';

/** A mutable collection of provider manifests, keyed by id. */
export class ProviderRegistry {
  private readonly byId = new Map<string, ProviderManifest>();

  /**
   * Validate and register a manifest. Throws `ManifestValidationError` on a malformed input, and refuses to replace a
   * provider that is already registered: silently swapping the manifest of `google` would send its tokens to a different
   * endpoint. Pass `replace: true` to do it on purpose; pass `expectedDigest` (see `manifestDigest`) to accept only
   * the manifest you reviewed.
   */
  register(manifest: ProviderManifest | unknown, opts: { replace?: boolean; expectedDigest?: string } = {}): ProviderManifest {
    const valid = assertManifest(manifest);
    if (opts.expectedDigest !== undefined && manifestDigest(valid) !== opts.expectedDigest) {
      throw new ConnectorError(`manifest '${valid.id}' does not match the pinned digest`);
    }
    if (this.byId.has(valid.id) && opts.replace !== true) {
      throw new ConnectorError(`provider '${valid.id}' is already registered; pass { replace: true } to replace it deliberately`);
    }
    this.byId.set(valid.id, Object.freeze(valid));
    return valid;
  }

  /** The manifest for `id`, or `undefined` when none is registered. */
  get(id: string): ProviderManifest | undefined {
    return this.byId.get(id);
  }

  /** The manifest for `id`, or throw {@link UnknownProviderError}. */
  require(id: string): ProviderManifest {
    const m = this.byId.get(id);
    if (m === undefined) throw new UnknownProviderError(id);
    return m;
  }

  /** Whether a manifest is registered for `id`. */
  has(id: string): boolean {
    return this.byId.has(id);
  }

  /** Every registered manifest, in ascending id order. */
  list(): ProviderManifest[] {
    return [...this.byId.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  /** The registered provider ids, in ascending order. */
  ids(): string[] {
    return this.list().map((m) => m.id);
  }
}

/** A fresh registry seeded with the full built-in connector catalog. */
export function createDefaultRegistry(): ProviderRegistry {
  const r = new ProviderRegistry();
  for (const m of BUILTIN_MANIFESTS) r.register(m);
  return r;
}

/** The process-wide registry the top-level `registerProvider` / `getProvider` / `listProviders` operate on. */
export const defaultRegistry: ProviderRegistry = createDefaultRegistry();

/** Validate and register a custom manifest onto the {@link defaultRegistry}. */
export function registerProvider(manifest: ProviderManifest | unknown, opts?: { replace?: boolean; expectedDigest?: string }): ProviderManifest {
  return defaultRegistry.register(manifest, opts);
}

/** A digest of the whole registry (every manifest, by id). Pin it to detect any change to the catalog. */
export function catalogDigest(registry: ProviderRegistry = defaultRegistry): string {
  return hashCanonical(registry.list().map((m) => [m.id, manifestDigest(m)]));
}

/** The manifest for `id` in the {@link defaultRegistry}, or `undefined`. */
export function getProvider(id: string): ProviderManifest | undefined {
  return defaultRegistry.get(id);
}

/** Every manifest in the {@link defaultRegistry}, in ascending id order. */
export function listProviders(): ProviderManifest[] {
  return defaultRegistry.list();
}
