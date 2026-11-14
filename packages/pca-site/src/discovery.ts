import { parseDiscoveryIntent, resolveSigAlg, type PcaDiscoveryDocument, type SigAlg } from '@atlasauth/pca';
import { type ActionSchemaKey } from '@atlasauth/pca/ext/intent';
import { isB64u32 } from '@atlasauth/pca-wallet';
import { isAccessTier, type AccessTier } from './tiers';

/**
 * The `intent` block of `/.well-known/pca-configuration` (docs/specs/pca-intent-layer-v2.md §4.1 M1, §8 "Discovery
 * document"). The official field is the core's `PcaDiscoveryDocument.intent` (`parseDiscoveryIntent`, V1). This module
 * DELEGATES to that parser and adds the stricter checks a site publishing the block should pass before serving it:
 * absolute http(s) URLs, schema keys with a registered signature suite, a canonical 32-byte `pk` and unique `kid`s,
 * at least one key for a v2 site, and tiers 0..4. The result is a fully-populated block (defaults filled).
 */

export interface IntentDiscoveryBlock {
  /** Intent Layer versions the site verifies (1 = v1 `envelope.intent`; 2 = v2 `intent_session`). */
  versions: number[];
  /** URL of the signed action schema (`/.well-known/pca-actions.json`). */
  actions_uri?: string;
  /** Site keys that sign the action schema and `intent_required` bodies (the core `ActionSchemaKey`). */
  schema_keys: ActionSchemaKey[];
  /** The site delivers `intent_required` to the wallet's question endpoint itself. */
  question_relay: boolean;
  /** Required access tier per verb (§3.15). */
  tiers: Record<string, AccessTier>;
  /** Where dispute evidence bundles are exported. */
  evidence_uri?: string;
}

export interface BuildIntentBlockOptions {
  versions: number[];
  actionsUri?: string;
  schemaKeys: ActionSchemaKey[];
  questionRelay?: boolean;
  tiers?: Record<string, AccessTier>;
  evidenceUri?: string;
}

function isHttpUrl(s: unknown): s is string {
  if (typeof s !== 'string') return false;
  try {
    const u = new URL(s);
    return (u.protocol === 'https:' || u.protocol === 'http:') && u.hash === '';
  } catch {
    return false;
  }
}

/** Validate an untrusted `intent` block: the core parser, then the site-side checks. Throws on anything malformed. */
export function parseIntentDiscoveryBlock(v: unknown): IntentDiscoveryBlock {
  const core = parseDiscoveryIntent(v);
  if (new Set(core.versions).size !== core.versions.length) throw new TypeError('intent block: versions repeats a value');
  if (core.actions_uri !== undefined && !isHttpUrl(core.actions_uri)) throw new TypeError('intent block: actions_uri must be an absolute http(s) URL');
  if (core.evidence_uri !== undefined && !isHttpUrl(core.evidence_uri)) throw new TypeError('intent block: evidence_uri must be an absolute http(s) URL');
  const kids = new Set<string>();
  const keys: ActionSchemaKey[] = (core.schema_keys ?? []).map((k, i) => {
    if (k.kid.length === 0 || k.kid.length > 128) throw new TypeError(`intent block: schema_keys[${i}].kid must be a non-empty string`);
    if (kids.has(k.kid)) throw new TypeError(`intent block: duplicate kid ${k.kid}`);
    kids.add(k.kid);
    const suite = resolveSigAlg(k.alg);
    if (suite === null) throw new TypeError(`intent block: schema_keys[${i}].alg is not a registered signature suite`);
    if (!isB64u32(k.pk)) throw new TypeError(`intent block: schema_keys[${i}].pk must be canonical base64url (32 bytes)`);
    if (suite.alg !== 'ed25519' && k.pq_pk === undefined) throw new TypeError(`intent block: schema_keys[${i}] needs pq_pk for suite ${suite.alg}`);
    if (suite.alg === 'ed25519' && k.pq_pk !== undefined) throw new TypeError(`intent block: schema_keys[${i}] is ed25519 and must not carry pq_pk`);
    return { kid: k.kid, alg: suite.alg as SigAlg, pk: k.pk, ...(k.pq_pk !== undefined ? { pq_pk: k.pq_pk } : {}) };
  });
  if (core.versions.includes(2) && keys.length === 0) throw new TypeError('intent block: a v2 site must publish at least one schema key');
  const tiers: Record<string, AccessTier> = {};
  for (const [verb, t] of Object.entries(core.tiers ?? {})) {
    if (verb.length === 0 || !isAccessTier(t)) throw new TypeError(`intent block: tiers.${verb} must be 0..4`);
    tiers[verb] = t;
  }
  return {
    versions: [...core.versions].sort((a, b) => a - b),
    ...(core.actions_uri !== undefined ? { actions_uri: core.actions_uri } : {}),
    schema_keys: keys,
    question_relay: core.question_relay ?? false,
    tiers,
    ...(core.evidence_uri !== undefined ? { evidence_uri: core.evidence_uri } : {}),
  };
}

/** Build the M1 `intent` member (validated). */
export function buildIntentDiscoveryBlock(o: BuildIntentBlockOptions): IntentDiscoveryBlock {
  return parseIntentDiscoveryBlock({
    versions: o.versions,
    ...(o.actionsUri !== undefined ? { actions_uri: o.actionsUri } : {}),
    schema_keys: o.schemaKeys,
    question_relay: o.questionRelay ?? false,
    tiers: o.tiers ?? {},
    ...(o.evidenceUri !== undefined ? { evidence_uri: o.evidenceUri } : {}),
  });
}

export type IntentDiscoveryDocument = PcaDiscoveryDocument & { intent: IntentDiscoveryBlock };

/** The discovery document with its official `intent` member set (validated with the site-side checks). */
export function withIntentBlock(doc: PcaDiscoveryDocument, block: IntentDiscoveryBlock): IntentDiscoveryDocument {
  return { ...doc, intent: parseIntentDiscoveryBlock(block) };
}

/** Read the `intent` member of a raw discovery document: null when absent, throws when present but malformed. */
export function intentBlockOf(raw: unknown): IntentDiscoveryBlock | null {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const i = (raw as Record<string, unknown>).intent;
  return i === undefined ? null : parseIntentDiscoveryBlock(i);
}
