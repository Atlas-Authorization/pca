/**
 * Carrying a bundle: as a `PCA-Directory` header next to a Web Bot Auth signature, and as an optional extension of an A2A agent card.
 *
 * Both are structural: this package does not import `@atlasauth/pca-webbotauth` or the card package, so you can use either one alone.
 */
import { httpLogClient } from './client';
import type { TrustedLog } from './check';
import {
  DIRECTORY_EXTENSION_URI,
  DIRECTORY_HEADER,
  MAX_HEADER_VALUE,
  decodeBundle,
  encodeBundle,
  parseBundle,
  type StapledBundle,
} from './bundle';

/** The lowercase component name to cover in an RFC 9421 signature. */
export const DIRECTORY_COMPONENT = DIRECTORY_HEADER.toLowerCase();

/** `{ 'PCA-Directory': <value> }`. Throws when the value would be too large for a header (use the agent card then). */
export function directoryHeaders(bundle: StapledBundle): Record<string, string> {
  const v = encodeBundle(bundle);
  if (v.length > MAX_HEADER_VALUE) throw new RangeError('directoryHeaders: bundle too large for a header; publish it in the agent card instead');
  return { [DIRECTORY_HEADER]: v };
}

/**
 * Add the bundle to a `@atlasauth/pca-webbotauth` `signRequest` input: the header is set AND listed in `coverHeaders`, so the
 * signature covers it and it cannot be swapped by an intermediary.
 *
 *   signRequest(withDirectoryHeader({ method, url, key, keyid }, bundle))
 */
export function withDirectoryHeader<T extends { headers?: Record<string, string | string[]>; coverHeaders?: string[] }>(input: T, bundle: StapledBundle): T {
  return {
    ...input,
    headers: { ...(input.headers ?? {}), ...directoryHeaders(bundle) },
    coverHeaders: [...(input.coverHeaders ?? []).filter((h) => h.toLowerCase() !== DIRECTORY_COMPONENT), DIRECTORY_HEADER],
  };
}

/**
 * Read the bundle from request headers. Pass `covered` (the verified signature's covered components, as
 * `verifySignedRequest` returns them) to require that the signature covered the header; an uncovered header is refused.
 * Returns null when there is no header, and throws on a malformed one.
 */
export function bundleFromHeaders(headers: Record<string, string | string[] | undefined>, covered?: readonly string[]): StapledBundle | null {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === DIRECTORY_COMPONENT);
  const raw = key === undefined ? undefined : headers[key];
  if (raw === undefined) return null;
  if (covered !== undefined && !covered.some((c) => c.toLowerCase() === DIRECTORY_COMPONENT)) throw new Error('PCA-Directory header is not covered by the request signature');
  if (Array.isArray(raw)) {
    if (raw.length !== 1) throw new Error('PCA-Directory must appear once');
    return decodeBundle(raw[0]!);
  }
  return decodeBundle(raw);
}

interface CardLike {
  capabilities?: { extensions?: Array<Record<string, unknown>> } & Record<string, unknown>;
}

/**
 * Add the bundle to an A2A agent card as an optional extension (`required: false`, so agents that do not know it ignore it).
 * Do this BEFORE signing the card: the extension is then covered by the card signature.
 */
export function withDirectoryExtension<C extends CardLike>(card: C, bundle: StapledBundle): C {
  const caps = card.capabilities ?? {};
  const others = (caps.extensions ?? []).filter((e) => e?.uri !== DIRECTORY_EXTENSION_URI);
  return {
    ...card,
    capabilities: {
      ...caps,
      extensions: [
        ...others,
        { uri: DIRECTORY_EXTENSION_URI, description: 'Agent trust directory proofs: passport, log inclusion proofs, signed tree heads, witness cosignatures.', required: false, params: { bundle } },
      ],
    },
  };
}

/** The bundle an agent card carries, or null. Throws on a malformed extension. */
export function bundleFromCard(card: unknown): StapledBundle | null {
  const exts = (card as CardLike | null)?.capabilities?.extensions;
  if (!Array.isArray(exts)) return null;
  const e = exts.find((x) => x?.uri === DIRECTORY_EXTENSION_URI) as { params?: { bundle?: unknown } } | undefined;
  return e?.params?.bundle === undefined ? null : parseBundle(e.params.bundle);
}

/**
 * The directory block of a `.well-known/pca-configuration` document, as `checkAgent` inputs. Discovery comes from the site itself, so this
 * only bootstraps: it is as trustworthy as the channel you fetched the document over. For an independent root of trust pin the keys out
 * of band instead. Returns undefined when the document has no usable block.
 */
export function trustedLogFromDiscovery(doc: { directory?: { id?: string; url: string; log_keys: string[]; witnesses?: { keys: string[]; threshold: number } } }): { log: TrustedLog; witnesses?: { keys: string[]; threshold: number } } | undefined {
  const d = doc?.directory;
  if (!d || !d.id || !d.log_keys?.[0]) return undefined;
  return { log: { id: d.id, guardian: d.log_keys[0], client: httpLogClient(d.url) }, ...(d.witnesses ? { witnesses: d.witnesses } : {}) };
}
