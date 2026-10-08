/**
 * Connector action catalog (spec Part 2.1 "connector action catalog").
 *
 * A small, pure-data registry that resolves a human `permissions` shorthand
 * (`{ stripe: ['refund'], gmail: ['send'] }`) into the real policy primitives the facade compiles a
 * grant from: a PCA verb, a resource matcher, a reversibility class and a blast-radius preset, plus
 * (for money-moving actions) the params field that carries the monetary amount so a `$X` limit can
 * be turned into a hard per-call ceiling predicate.
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
}

/** Blast-radius presets by shape of action — conservative, overridable. */
export const BLAST = {
  read: 0.05,
  reversibleWrite: 0.2,
  rateLimitedWrite: 0.5,
  irreversibleWrite: 0.8,
  moneyMovement: 0.9,
} as const;

function spec(
  connector: string,
  action: string,
  reversibility: Reversibility,
  blastRadius: number,
  description: string,
  extra: Partial<Pick<ActionSpec, 'amountField' | 'resource'>> = {},
): ActionSpec {
  return { connector, action, verb: `${connector}.${action}`, reversibility, blastRadius, description, ...extra };
}

/**
 * The built-in catalog. Deliberately small and additive — a caller can register their own actions
 * via `defineAction` / `registerActions` (merged into a per-facade catalog) without editing this file.
 */
export const BUILTIN_ACTIONS: ActionSpec[] = [
  // --- Stripe (payments) ---
  spec('stripe', 'charge', 'reversible', BLAST.moneyMovement, 'Charge a customer (reversible via refund).', { amountField: 'amount' }),
  spec('stripe', 'refund', 'rate_limited', BLAST.moneyMovement, 'Refund a charge (hard to undo; rate-limit).', { amountField: 'amount' }),
  spec('stripe', 'payout', 'irreversible', BLAST.moneyMovement, 'Pay out funds to a bank account (irreversible).', { amountField: 'amount' }),
  spec('stripe', 'create_customer', 'reversible', BLAST.reversibleWrite, 'Create a customer record.'),

  // --- Email ---
  spec('gmail', 'send', 'irreversible', BLAST.irreversibleWrite, 'Send an email (cannot be unsent).'),
  spec('gmail', 'draft', 'reversible', BLAST.reversibleWrite, 'Create a draft (not sent).'),
  spec('gmail', 'delete', 'irreversible', BLAST.irreversibleWrite, 'Permanently delete a message.'),

  // --- GitHub ---
  spec('github', 'read', 'reversible', BLAST.read, 'Read repository contents.', { resource: '*' }),
  spec('github', 'create_pr', 'reversible', BLAST.reversibleWrite, 'Open a pull request.'),
  spec('github', 'comment', 'reversible', BLAST.reversibleWrite, 'Comment on an issue or PR.'),
  spec('github', 'merge_pr', 'rate_limited', BLAST.rateLimitedWrite, 'Merge a pull request.'),
  spec('github', 'delete_repo', 'irreversible', BLAST.irreversibleWrite, 'Delete a repository (irreversible).'),

  // --- Slack ---
  spec('slack', 'post_message', 'rate_limited', BLAST.rateLimitedWrite, 'Post a message to a channel.'),
  spec('slack', 'read', 'reversible', BLAST.read, 'Read channel history.'),

  // --- Calendar ---
  spec('calendar', 'create_event', 'reversible', BLAST.reversibleWrite, 'Create a calendar event.'),
  spec('calendar', 'delete_event', 'rate_limited', BLAST.rateLimitedWrite, 'Delete a calendar event.'),

  // --- Files / storage ---
  spec('files', 'read', 'reversible', BLAST.read, 'Read a file.', { resource: '*' }),
  spec('files', 'write', 'rate_limited', BLAST.rateLimitedWrite, 'Write/overwrite a file.'),
  spec('files', 'delete', 'irreversible', BLAST.irreversibleWrite, 'Delete a file (irreversible).'),

  // --- Generic HTTP ---
  spec('http', 'get', 'reversible', BLAST.read, 'HTTP GET (read-only).', { resource: '*' }),
  spec('http', 'post', 'rate_limited', BLAST.rateLimitedWrite, 'HTTP POST (side-effecting).'),
];

/** A catalog is an immutable lookup over action specs, keyed by verb and by connector. */
export interface Catalog {
  /** Look up a single action spec by its PCA verb (`connector.action`). */
  get(verb: string): ActionSpec | undefined;
  /** All actions for a connector namespace. */
  forConnector(connector: string): ActionSpec[];
  /** Every action in the catalog. */
  all(): ActionSpec[];
}

/** Define a single action spec (validates shape); use with `buildCatalog` to extend the built-ins. */
export function defineAction(s: Omit<ActionSpec, 'verb'> & { verb?: string }): ActionSpec {
  if (!s.connector || !s.action) throw new Error('defineAction: connector and action are required');
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
  };
}

/** The default catalog over the built-in actions. */
export const DEFAULT_CATALOG: Catalog = buildCatalog();
