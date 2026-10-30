/**
 * Connector action catalog (spec Part 2.1 "connector action catalog").
 *
 * A small, pure-data registry that resolves a human `permissions` shorthand
 * (`{ stripe: ['refund'], gmail: ['send'] }`) into the real policy primitives the facade compiles a
 * grant from: a PCA verb, a resource matcher, a reversibility class and a blast-radius preset, plus
 * (for money-moving actions) the params field that carries the monetary amount so a `$X` limit can
 * be turned into a hard per-call ceiling predicate.
 *
 * The built-in rows are DERIVED from the reviewed action definitions (`@atlasauth/pca-actions`, one `ActionDef` per action):
 * `catalog-builtin.generated.ts` is written by that package's generator, so the class, blast and amount field here can never
 * disagree with the signed schema, the operation binding or the Goal IR ontology built from the same definition.
 *
 * This is DATA, not policy enforcement. Nothing here authorizes anything — the catalog only tells the
 * facade how a named action maps onto predicates/caveats/risk so the grant it mints is well-formed.
 * The resource server's verifier (`requirePCA` / the adjudicator) remains authoritative.
 *
 * Reversibility presets follow the §2.5 ordering `reversible < rate_limited < irreversible`. The
 * blast-radius presets are coarse [0,1] seeds for the risk functional's γ term (see risk.ts); a caller
 * can always override them. They are intentionally conservative: when unsure, an action is treated as
 * higher blast-radius / less reversible, never lower.
 */

import { hashCanonical } from './hash';
import { BUILTIN_ACTIONS } from './catalog-builtin.generated';
import { REVERSIBILITY_ORDER } from './predicates';

/** A reversibility class (spec §2.5 ordering reversible < rate_limited < irreversible). */
export type Reversibility = (typeof REVERSIBILITY_ORDER)[number];

export interface ActionSpec {
  /** Connector namespace, e.g. `stripe`. */
  connector: string;
  /** Action within the connector, e.g. `refund`. */
  action: string;
  /** The PCA verb this action maps to: `${connector}.${action}`. */
  verb: string;
  /** §2.5 reversibility class used for the `reversibility_max` caveat + risk β term. */
  reversibility: Reversibility;
  /** Coarse blast-radius preset in [0,1] (risk γ seed). */
  blastRadius: number;
  /**
   * For money-moving actions, the dotted params field (under `action.params`) that carries the
   * monetary amount. Lets a `$X` limit compile to a hard per-call ceiling `amount <= X` AND lets the
   * facade's dollar budget model denominate cost in the currency unit. Absent => not money-moving.
   */
  amountField?: string;
  /** Default resource matcher (predicate `resource`); omitted => any resource (`*`). */
  resource?: string;
  /** One-line human description (surfaced in approval UX / docs). */
  description: string;
  /** Other names the definition answers to (`refund` for `stripe.refund`); the NL layer and `permissions` resolve them. */
  aliases?: string[];
  /** The trait closure of the definition (`pca.money_moving`, ...), sorted. Informational: the verifier recomputes it. */
  traits?: string[];
}

/** Blast-radius presets by shape of action — conservative, overridable. */
export const BLAST = {
  read: 0.05,
  reversibleWrite: 0.2,
  rateLimitedWrite: 0.5,
  irreversibleWrite: 0.8,
  moneyMovement: 0.9,
} as const;

/**
 * The built-in catalog (the 21 reviewed connector actions), derived from their definitions. Deliberately small and additive: a
 * caller can register their own actions via `defineAction` / `buildCatalog` / `extendCatalog` without editing anything here.
 */
export { BUILTIN_ACTIONS } from './catalog-builtin.generated';

/** A catalog is an immutable lookup over action specs, keyed by verb and by connector. */
export interface Catalog {
  /** Look up a single action spec by its PCA verb (`connector.action`). */
  get(verb: string): ActionSpec | undefined;
  /** All actions for a connector namespace. */
  forConnector(connector: string): ActionSpec[];
  /** Every action in the catalog. */
  all(): ActionSpec[];
  /**
   * Resolve `connector` + `action` as written by a human or a model: the exact verb, else an alias of exactly one action of that
   * connector (`stripe` + `issue_refund` is `stripe.refund`). Absent or ambiguous: undefined (never a guess).
   */
  resolve?(connector: string, action: string): ActionSpec | undefined;
}

/** Define a single action spec (validates shape); use with `buildCatalog` to extend the built-ins. */
export function defineAction(s: Omit<ActionSpec, 'verb'> & { verb?: string }): ActionSpec {
  if (typeof s.connector !== 'string' || typeof s.action !== 'string' || !s.connector || !s.action) throw new Error('defineAction: connector and action are required');
  if (/[\s.]/.test(s.connector)) throw new Error('defineAction: connector must not contain whitespace or a dot');
  if (s.amountField !== undefined && (typeof s.amountField !== 'string' || s.amountField.length === 0)) throw new Error('defineAction: amountField must be a non-empty string');
  if (!['reversible', 'rate_limited', 'irreversible'].includes(s.reversibility)) {
    throw new Error(`defineAction: bad reversibility '${String(s.reversibility)}'`);
  }
  if (!(typeof s.blastRadius === 'number' && s.blastRadius >= 0 && s.blastRadius <= 1)) {
    throw new Error('defineAction: blastRadius must be in [0,1]');
  }
  return { ...s, verb: s.verb ?? `${s.connector}.${s.action}` };
}

/** Build a catalog from a set of action specs (later specs override earlier ones by verb). */
export function buildCatalog(actions: ActionSpec[] = BUILTIN_ACTIONS): Catalog {
  const byVerb = new Map<string, ActionSpec>();
  for (const a of actions) byVerb.set(a.verb, a);
  return {
    get: (verb) => byVerb.get(verb),
    forConnector: (connector) => [...byVerb.values()].filter((a) => a.connector === connector),
    all: () => [...byVerb.values()],
    resolve: (connector, action) => {
      const exact = byVerb.get(`${connector}.${action}`);
      if (exact) return exact;
      const hits = [...byVerb.values()].filter((a) => a.connector === connector && a.aliases?.includes(action));
      return hits.length === 1 ? hits[0] : undefined;
    },
  };
}

/** The default catalog over the built-in actions. */
export const DEFAULT_CATALOG: Catalog = buildCatalog();

// ---- fail-closed lookup, schema pin, and no-downgrade extension -------------------------------------

/** What a verb is treated as when the catalog does not know it: irreversible, maximum blast radius. */
export function uncataloguedSpec(verb: string): ActionSpec {
  const [connector, ...rest] = verb.split('.');
  return {
    connector: connector ?? verb,
    action: rest.join('.') || verb,
    verb,
    reversibility: 'irreversible',
    blastRadius: 1,
    description: `(uncatalogued) ${verb}`,
  };
}

/** Resolve a verb, failing closed: an unknown verb comes back as {@link uncataloguedSpec} with `catalogued: false`. */
export function resolveAction(catalog: Catalog, verb: string): { spec: ActionSpec; catalogued: boolean } {
  const spec = catalog.get(verb);
  return spec ? { spec, catalogued: true } : { spec: uncataloguedSpec(verb), catalogued: false };
}

/**
 * A digest of the whole catalog (SHA-256 over canonical JSON, sorted by verb). Pin it: a deployment that
 * records the digest of the catalog it reviewed can refuse to start when the catalog has since changed.
 */
export function catalogDigest(catalog: Catalog): string {
  const specs = [...catalog.all()].sort((a, b) => (a.verb < b.verb ? -1 : a.verb > b.verb ? 1 : 0));
  return hashCanonical(specs);
}

/** Throws unless `catalog` hashes to `expected`. */
export function assertCatalogPinned(catalog: Catalog, expected: string): void {
  if (catalogDigest(catalog) !== expected) throw new Error('catalog does not match the pinned digest');
}

/**
 * Extend a catalog with more actions. Unlike `buildCatalog([...a, ...b])`, an extra action may not replace an
 * existing verb with a less cautious one (lower reversibility class or lower blast radius): that would let
 * a plugin quietly relabel `gmail.send` as reversible.
 */
export function extendCatalog(base: Catalog, extra: ActionSpec[]): Catalog {
  const sevOf = (c: string) => REVERSIBILITY_ORDER.indexOf(c as Reversibility);
  for (const e of extra) {
    const old = base.get(e.verb);
    if (old && (sevOf(e.reversibility) < sevOf(old.reversibility) || e.blastRadius < old.blastRadius)) {
      throw new Error(`extendCatalog: '${e.verb}' would be less cautious than the existing entry`);
    }
  }
  return buildCatalog([...base.all(), ...extra]);
}
