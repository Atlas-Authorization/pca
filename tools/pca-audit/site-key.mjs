// Shared mutation-site keying for the equivalent-mutant ledgers (native-check-equivalents.mjs, stryker/check-equivalents.mjs).
//
// A ledger entry names ONE mutation site, not a line of text: (file, mutator/mutant, normalised line text, occurrence) where
// `occurrence` is the 1-based index of that text among the identical lines of the file (the Nth `return false`), plus the
// enclosing function (`fn`) when the mutation tool reports it. `lineno` is stored as a hint only (it drifts with edits elsewhere
// and is never required to match). An entry whose text appears more than once in the file must carry `occurrence`.
//
// The checker rules (enforced by the two checkers through checkSites below):
//   - every survivor in a report matches exactly one entry;
//   - every entry (of a unit the report covers) matches exactly one survivor site, otherwise it is STALE;
//   - an entry whose text is not unique in its file and has no occurrence is AMBIGUOUS (an error even in the static check).

export const norm = (s) => String(s ?? '').trim();

/** Line numbers (1-based) of every line whose trimmed text equals `text`. */
export function linesWithText(lines, text) {
  const t = norm(text);
  const out = [];
  for (let i = 0; i < lines.length; i++) if (norm(lines[i]) === t) out.push(i + 1);
  return out;
}

/** occurrence (1-based) of the line at `lineno` among the identical lines of `lines`, or 0 when lineno is out of range. */
export function occurrenceAt(lines, lineno) {
  if (!(lineno >= 1 && lineno <= lines.length)) return 0;
  return linesWithText(lines, lines[lineno - 1]).indexOf(lineno) + 1;
}

/**
 * Place a reported site (text + optional run-time occurrence + optional line hint) in `lines` (the current source).
 * Returns { occurrence, lineno, how } or { error }.
 *   - a run-time occurrence is authoritative when the producer computed one against the source it mutated;
 *   - otherwise a unique text is occurrence 1; otherwise the hint must sit on that text (exact) or nearest to one copy of it.
 */
export function place(lines, text, { occurrence, hint } = {}) {
  const at = linesWithText(lines, text);
  if (at.length === 0) return { error: 'text not in current source (report predates a code change)' };
  if (occurrence) {
    if (occurrence > at.length) return { error: `occurrence ${occurrence} but only ${at.length} identical line(s) now` };
    return { occurrence, lineno: at[occurrence - 1], how: 'occurrence' };
  }
  if (at.length === 1) return { occurrence: 1, lineno: at[0], how: 'unique' };
  if (!hint) return { error: `text occurs ${at.length} times and the report gives neither occurrence nor line` };
  const exact = at.indexOf(hint);
  if (exact >= 0) return { occurrence: exact + 1, lineno: hint, how: 'hint' };
  const d = at.map((l) => Math.abs(l - hint));
  const best = Math.min(...d);
  if (d.filter((x) => x === best).length > 1) return { error: `line hint ${hint} is equidistant from two copies of the text` };
  const i = d.indexOf(best);
  return { occurrence: i + 1, lineno: at[i], how: `nearest (hint ${hint}, drift ${at[i] - hint})` };
}

/** Static validation of one entry's site against the current source. Returns { errors: [], lineno }. */
export function checkEntrySite(lines, e, label) {
  const errors = [];
  const at = linesWithText(lines, e.line);
  if (at.length === 0) return { errors: [`STALE (source line gone): ${label}`] };
  if (e.occurrence === undefined) {
    if (at.length > 1) errors.push(`AMBIGUOUS (text occurs ${at.length} times at lines ${at.join(',')}; add occurrence): ${label}`);
    return { errors, lineno: at[0] };
  }
  if (!Number.isInteger(e.occurrence) || e.occurrence < 1) return { errors: [`bad occurrence ${e.occurrence}: ${label}`] };
  if (e.occurrence > at.length) return { errors: [`STALE (occurrence ${e.occurrence} but the text now occurs ${at.length} time(s)): ${label}`] };
  if (e.multiplicity !== undefined && !(Number.isInteger(e.multiplicity) && e.multiplicity >= 2)) errors.push(`bad multiplicity ${e.multiplicity}: ${label}`);
  return { errors, lineno: at[e.occurrence - 1] };
}

/**
 * Core matcher.
 *   entries:   [{ key, fn?, multiplicity?, label, unit }]       (key already includes the occurrence)
 *   survivors: [{ key, fn?, label, unit }]                      (one per reported mutant, already placed)
 *   units:     Set of units the reports cover (an entry outside them is not checked for staleness)
 * Returns errors[].
 */
// `timedOut` (optional): site key -> how many mutants at that site ended in Timeout this run. A timeout counts as a kill in
// the score, but an equivalent mutant that only slows the code down (a removed memo, an extra loop pass) times out on a loaded
// runner and survives on a quiet one: its entry is neither STALE nor short of its multiplicity because of a timeout.
export function checkSites(entries, survivors, units, timedOut = new Map()) {
  const errors = [];
  const groups = new Map();
  for (const s of survivors) {
    const g = groups.get(s.key) ?? { list: [], fn: new Set() };
    g.list.push(s);
    if (s.fn) g.fn.add(s.fn);
    groups.set(s.key, g);
  }
  const byKey = new Map();
  for (const e of entries) byKey.set(e.key, [...(byKey.get(e.key) ?? []), e]);
  const matched = new Map();
  for (const [k, g] of groups) {
    const cand = (byKey.get(k) ?? []).filter((e) => !e.fn || g.fn.size === 0 || g.fn.has(e.fn));
    if (cand.length === 0) { for (const s of g.list) errors.push(`UNLISTED SURVIVOR ${s.label}`); continue; }
    if (cand.length > 1) { errors.push(`survivor site matches ${cand.length} ledger entries: ${g.list[0].label}`); continue; }
    const e = cand[0];
    const want = e.multiplicity ?? 1;
    if (g.list.length !== want && g.list.length + (timedOut.get(k) ?? 0) !== want) errors.push(`multiplicity: ${g.list.length} identical survivor(s) at this site, entry covers ${want}: ${e.label}`);
    matched.set(e, (matched.get(e) ?? 0) + 1);
  }
  for (const e of entries) {
    if (!units.has(e.unit)) continue;
    const n = matched.get(e) ?? 0;
    if (n === 0 && !timedOut.has(e.key)) errors.push(`STALE (no survivor at this site; killed or changed, remove it): ${e.label}`);
  }
  return errors;
}
