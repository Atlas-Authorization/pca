// facade-spec.ts - the facade's view of an ActionDef: the `ActionSpec` rows `@atlasauth/pca` compiles `permissions`/`limits`
// from (reversibility class, blast preset, the amount parameter, the resource matcher), DERIVED from the effective profile of
// the def instead of written by hand. `scripts/gen-catalog.ts` writes the built-in rows into `packages/pca/src` from here
// (the facade cannot import this package: this package imports it) and a test pins the generated file to this derivation.

import type { ActionDef, Rev } from './def';
import { CORE_REGISTRY } from './core-traits';
import { paramByRole } from './derive';
import { effective, type ReviewOpts } from './effective';
import type { Registry } from './traits';

/** Structural twin of `ActionSpec` in `@atlasauth/pca` (plus the aliases and trait closure the facade and the NL layer use). */
export interface FacadeSpec {
  connector: string;
  action: string;
  verb: string;
  reversibility: Rev;
  blastRadius: number;
  amountField?: string;
  resource?: string;
  description: string;
  aliases?: string[];
  traits?: string[];
}

export interface FacadeOpts extends ReviewOpts {
  /** Price the def as REVIEWED (its declared + implied traits), not as unconfirmed. Only for the release-attested built-in catalog. */
  reviewed?: boolean;
}

/**
 * One def to one facade row. `reversibility` and `blastRadius` are the EFFECTIVE values (declared joined with the floor of the
 * trait closure), so no trait can make the facade price an action below what the signed schema says. `amountField` is the
 * single `money.amount` parameter (absent when the def has none or, ambiguously, several: a `$` limit then refuses to compile).
 * The resource matcher stays the catalog's wildcard (`*`): the facade's resource strings are connector-specific.
 */
export function specOfDef(d: ActionDef, reg: Registry = CORE_REGISTRY, opts: FacadeOpts = {}): FacadeSpec {
  const full = effective(d, reg, opts);
  // `reviewed`: the generator for the shipped built-in catalog, whose defs the release process attests (scripts/sign-builtins.ts);
  // everything else (an unattested def) is priced at the top of the registry.
  const e = opts.reviewed === true ? full.hint : full;
  const [connector, ...rest] = d.verb.split('.');
  let amountField: string | undefined;
  try { amountField = paramByRole(d, 'money.amount'); } catch { amountField = undefined; }
  return {
    connector: connector!,
    action: rest.join('.'),
    verb: d.verb,
    reversibility: e.eff.rev,
    blastRadius: e.eff.blast_ppm / 1_000_000,
    ...(amountField !== undefined ? { amountField } : {}),
    description: d.description ?? d.title,
    ...(d.aliases && d.aliases.length > 0 ? { aliases: [...d.aliases].sort() } : {}),
    traits: e.closure,
  };
}

/** The facade rows of a pack, in the pack's own order (the order the generated catalog file is written in, and `forConnector` serves). */
export const facadeSpecs = (defs: readonly ActionDef[], reg: Registry = CORE_REGISTRY, opts: FacadeOpts = {}): FacadeSpec[] => defs.map((d) => specOfDef(d, reg, opts));
