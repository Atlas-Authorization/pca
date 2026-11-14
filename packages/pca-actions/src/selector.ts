// selector.ts - trait selectors and the registry-growth semantics (spec T6, T7). A selector is a positive predicate over the
// trait closure of an action. Prohibit selectors FLOAT (they cover every present and future action that matches); allow
// selectors are PINNED to a set of verbs (the pack digest the grant names) and may not use negation (absence of a trait is
// never a safety claim). The full policy compiler is track A5; this module is the checked semantic core it must preserve.

import type { TraitId, Verb } from './def';
import type { Decision } from './traits';

export type Selector =
  | { k: 'trait'; id: TraitId }
  | { k: 'all_of'; ids: TraitId[] }
  | { k: 'any_of'; ids: TraitId[] }
  | { k: 'not'; s: Selector }
  | { k: 'and'; a: Selector; b: Selector };

/** Does the selector match an action whose trait closure is `closure`? Monotone in `closure` unless the selector contains `not`. */
export function selectorMatches(s: Selector, closure: ReadonlySet<TraitId>): boolean {
  switch (s.k) {
    case 'trait': return closure.has(s.id);
    case 'all_of': return s.ids.every((i) => closure.has(i));
    case 'any_of': return s.ids.some((i) => closure.has(i));
    case 'not': return !selectorMatches(s.s, closure);
    case 'and': return selectorMatches(s.a, closure) && selectorMatches(s.b, closure);
  }
}

/**
 * Does a selector of the given mode match an action? For a CONFIRMED action it is {@link selectorMatches} over its closure. An
 * UNCONFIRMED action (no valid signed review) is maximally dangerous: every forbid/cap selector ('prohibit') matches it, whatever
 * the selector says (even a negation), and no allow selector ever does. Fail-closed by construction: the closure of an unconfirmed
 * action is not consulted, so a classifier miss cannot make a prohibit skip it or an allow cover it.
 */
export function selectorMatchesFor(s: Selector, mode: 'allow' | 'prohibit', closure: ReadonlySet<TraitId>, confirmed: boolean): boolean {
  if (!confirmed) return mode === 'prohibit';
  return selectorMatches(s, closure);
}

export const selectorHasNot = (s: Selector): boolean => (s.k === 'not' ? true : s.k === 'and' ? selectorHasNot(s.a) || selectorHasNot(s.b) : false);

/**
 * T7 typing rule for an ALLOW selector: no negation anywhere, and `any_of` only inside a pinned allow (`pinned: true`).
 * Null = allowed. (Prohibit selectors may use `not`.)
 */
export function allowSelectorError(s: Selector, pinned: boolean): string | null {
  if (selectorHasNot(s)) return 'an allow selector must not use negation: the absence of a trait is never a safety claim';
  const anyOf = (x: Selector): boolean => (x.k === 'any_of' ? true : x.k === 'and' ? anyOf(x.a) || anyOf(x.b) : false);
  if (!pinned && anyOf(s)) return 'any_of in an allow selector requires the grant to be pinned to a pack digest';
  return null;
}

export interface TraitPolicy {
  /** Verbs the grant is pinned to (the contents of the pinned pack digest). */
  pinned: readonly Verb[];
  allow: readonly Selector[];
  prohibit: readonly Selector[];
  /** What happens to a verb outside `pinned`: deny (default) or escalate. Never allow. */
  on_new_action?: 'deny' | 'escalate';
}

/**
 * The policy component of the decision for one action (its verb, trait closure and whether it is human-confirmed): a matching prohibit denies; otherwise a
 * pinned verb with a matching allow is allowed; an unpinned verb is deny/escalate; a pinned verb with no allow is deny.
 */
export function policyDecision(p: TraitPolicy, verb: Verb, closure: ReadonlySet<TraitId>, confirmed: boolean): Decision {
  if (p.prohibit.some((s) => selectorMatchesFor(s, 'prohibit', closure, confirmed))) return 'deny';
  if (!p.pinned.includes(verb)) return p.on_new_action === 'escalate' ? 'escalate' : 'deny';
  return p.allow.some((s) => selectorMatchesFor(s, 'allow', closure, confirmed)) ? 'allow' : 'deny';
}
