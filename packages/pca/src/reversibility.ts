/**
 * Severity of a reversibility class, over BOTH vocabularies the verifier sees: the RS strictness enum (`costly`) and the
 * caveat enum (`rate_limited`, see predicates.REVERSIBILITY_ORDER), which sit on the same middle tier. `rate_limited` used to
 * be missing here, so it ranked as an unknown (most restrictive) class: a declared `rate_limited` then counted as STRICTER
 * than an authoritative `costly` and replaced it as the effective class (which `reversibility_max` caveats read), and passed
 * against an authoritative `irreversible`.
 */
export const CLASS_RANK: Readonly<Record<string, number>> = { reversible: 0, rate_limited: 1, costly: 1, irreversible: 2 };
/** Unknown class strings are the most restrictive (fail closed). */
export const classRank = (c: unknown): number => (typeof c === 'string' && Object.prototype.hasOwnProperty.call(CLASS_RANK, c) ? CLASS_RANK[c]! : 2);
