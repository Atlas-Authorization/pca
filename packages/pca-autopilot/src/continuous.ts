/**
 * Continuous mode. A grant drifts: a legitimate new action gets denied, other authority is never used. Both produce a new
 * PROPOSAL (an amendment that widens by the minimum, or a tightening), and a proposal is never authority: it goes through
 * `verifyProposal` and a signed approval exactly like the first one.
 */
import { REVERSIBILITY_ORDER, evaluatePredicates, type Caveat, type Condition, type Predicate } from '@atlasauth/pca';
import { cleanText } from '@atlasauth/pca-explain';
import { DAY_MS, buildRules, clean, maxOf, minOf, peakInWindow, resolve, reversibilityCap, seal, type Resolved } from './synth';
import type { Proposal, RuleExplanation, SynthOptions, Trace, TraceSet } from './types';

const sameTenant = (set: TraceSet, p: Proposal): Trace[] => set.traces.filter((t) => t.tenant === p.tenant);
const admits = (preds: Predicate[], t: Trace): boolean => evaluatePredicates(preds, { action: { verb: t.verb, resource: t.resource, params: t.params } }).allowed;

/** Does resource matcher `e` admit everything resource matcher `n` admits? (exact, `*`, trailing-`*` prefix only; `re:` never.) */
function covers(e: string | undefined, n: string | undefined): boolean {
  if (e === undefined || e === '*') return true;
  if (n === undefined) return false;
  if (e.startsWith('re:') || n.startsWith('re:')) return e === n;
  if (e.endsWith('*')) return n.startsWith(e.slice(0, -1));
  return e === n;
}

const leaf = (c: Condition): c is Extract<Condition, { field: string }> => typeof (c as { field?: unknown }).field === 'string';

/** Widen predicate `e` by the least amount that also admits `n` (same verb, `e`'s resource covers `n`'s). */
function widen(e: Predicate, n: Predicate): Predicate {
  const nw = (n.where ?? []).filter(leaf);
  const where: Condition[] = [];
  for (const c of (e.where ?? [])) {
    if (!leaf(c)) { continue; } // a group condition is dropped when widening: wider, never narrower than needed
    const m = nw.filter((x) => x.field === c.field);
    if (m.length === 0) continue; // the new rule is unconstrained there, so the merged one is too
    if (c.op === 'lte') { const v = maxOf([c.value as number, ...m.filter((x) => x.op === 'lte').map((x) => x.value as number)]); where.push({ ...c, value: v }); }
    else if (c.op === 'gte') { const v = minOf([c.value as number, ...m.filter((x) => x.op === 'gte').map((x) => x.value as number)]); where.push({ ...c, value: v }); }
    else if (c.op === 'eq' || c.op === 'in') {
      const have = new Set<unknown>(c.op === 'eq' ? [c.value] : (c.value as unknown[]));
      for (const x of m) for (const v of x.op === 'eq' ? [x.value] : x.op === 'in' ? (x.value as unknown[]) : []) have.add(v);
      const vals = [...have].sort();
      where.push(vals.length === 1 ? { field: c.field, op: 'eq', value: vals[0] } : { field: c.field, op: 'in', value: vals });
    }
  }
  return { ...e, ...(where.length ? { where } : { where: undefined }) } as Predicate;
}

const strip = (p: Predicate): Predicate => { const { where, ...r } = p; return where === undefined ? (r as Predicate) : p; };

/**
 * Propose the minimal amendment for actions that were DENIED but look legitimate: repeated at least `minRepeats` times, none of
 * the sensitivity flags, within the tenant, and not already admitted. A sensitive denied action is admitted only when its id is
 * in `confirmed`. Other denied actions are listed as held back.
 */
export function amend(base: Proposal, observed: TraceSet, o: SynthOptions & { minRepeats?: number } = {}): Proposal {
  const r = resolve({ ...o, margin: o.margin ?? base.margin });
  const minRepeats = o.minRepeats ?? 3;
  if (!Number.isInteger(minRepeats) || minRepeats < 1) throw new RangeError('minRepeats must be a positive integer');
  const others = new Set(observed.traces.map((t) => t.tenant).filter((x): x is string => x !== undefined && x !== base.tenant));
  const mine = sameTenant(observed, base);
  const denied = mine.filter((t) => t.outcome === 'deny' && !admits(base.policy.predicates, t));
  const groups = new Map<string, Trace[]>();
  for (const t of denied) (groups.get(t.id) ?? groups.set(t.id, []).get(t.id)!).push(t);
  const confirmed = new Set(o.confirmed ?? []);
  const admit: Trace[] = [];
  const admitIds: string[] = [];
  const conf: string[] = [];
  const held: Proposal['heldBack'] = [];
  for (const [id, ts] of [...groups].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const t0 = ts[0]!;
    const crossed = ts.some((t) => t.resource.split(/[/:]/).some((s) => others.has(s)));
    const reasons = [...new Set(ts.flatMap((t) => t.sensitive)), ...(crossed ? ['cross-tenant-resource'] : [])].sort();
    if (crossed) held.push({ id, verb: t0.verb, resource: cleanText(t0.resource), count: ts.length, reasons, kind: 'sensitive' });
    else if (reasons.length === 0 && ts.length >= minRepeats) { admit.push(...ts); admitIds.push(id); }
    else if (reasons.length > 0 && confirmed.has(id)) { admit.push(...ts); admitIds.push(id); conf.push(id); }
    else held.push({ id, verb: t0.verb, resource: cleanText(t0.resource), count: ts.length, reasons: reasons.length ? reasons : [`denied only ${ts.length} time(s), need ${minRepeats}`], kind: reasons.length ? 'sensitive' : 'blocked' });
  }
  for (const id of confirmed) if (!conf.includes(id)) throw new Error(`confirmed id ${cleanText(String(id)).slice(0, 40)} is not a denied sensitive action in these traces`);
  if (admit.length === 0) throw new Error('no denied-but-legitimate actions to amend');

  const fresh = buildRules(admit.map((t) => ({ ...t, outcome: 'allow' as const })), r);
  const preds: Predicate[] = base.policy.predicates.map((p) => ({ ...p }));
  const rules: RuleExplanation[] = [...base.rules];
  for (const b of fresh) {
    const i = preds.findIndex((e) => typeof e.verb === 'string' && e.verb === b.predicate.verb && covers(e.resource, b.predicate.resource));
    if (i >= 0) preds[i] = strip(widen(preds[i]!, b.predicate)); else preds.push(b.predicate);
    rules.push({ ...b.explanation, why: `amendment: ${b.explanation.observed} denied attempt(s) that look legitimate. ${b.explanation.why}` });
  }
  if (preds.length > r.maxRules) throw new RangeError(`${preds.length} rules exceeds maxRules ${r.maxRules}`);
  const need = reversibilityCap(admit.map((t) => t.verb));
  const all = [...mine.filter((t) => t.outcome === 'allow'), ...admit].sort((a, b) => a.at - b.at);
  // the rate only ever rises here, and only as far as the admitted traffic needs
  const caveats: Caveat[] = base.policy.caveats.map((c) => {
    if (c.type === 'reversibility_max' && REVERSIBILITY_ORDER.indexOf(need as never) > REVERSIBILITY_ORDER.indexOf(String(c.class) as never)) return { ...c, class: need };
    if (c.type === 'rate') return { ...c, max: Math.max(c.max as number, Math.ceil(peakInWindow(all.map((t) => t.at), c.per_secs as number) * (1 + r.margin))) };
    return c;
  });
  return seal({
    ...stripDigest(base), createdAt: r.now, policy: { predicates: preds, caveats }, rules, heldBack: held,
    basis: { traceSetDigest: observed.digest, included: all.length, from: all[0]!.at, to: all[all.length - 1]!.at },
    confirmedSensitive: [...new Set([...base.confirmedSensitive, ...conf])].sort(), admitDenied: [...new Set([...base.admitDenied, ...admitIds])].sort(), amends: base.digest,
    notes: [...base.notes.filter((n) => !n.startsWith('amendment:')), `amendment: widened by the minimum to admit ${admitIds.length} denied action group(s); the budget is unchanged and the rate rises only as far as the admitted traffic needs`],
  });
}

function stripDigest(p: Proposal): Omit<Proposal, 'digest'> { const { digest: _d, ...rest } = p; void _d; return rest; }

/**
 * Propose tightening when authority went unused for `unusedDays`: rules no action matched in the window are dropped, caps and
 * value sets shrink to what was used (plus the margin) and the rate to the observed peak. Never widens anything. Refuses to say
 * "unused" about a window the observation does not cover.
 */
export function tighten(base: Proposal, observed: TraceSet, o: { unusedDays: number; now: number; observedFrom?: number; margin?: number }): Proposal {
  if (!Number.isFinite(o.unusedDays) || o.unusedDays <= 0) throw new RangeError('unusedDays must be a positive number');
  const r: Resolved = resolve({ margin: o.margin ?? base.margin, now: o.now });
  const from = o.now - o.unusedDays * DAY_MS;
  const mine = sameTenant(observed, base);
  const start = o.observedFrom ?? (mine.length ? mine[0]!.at : undefined);
  if (start === undefined || start > from) throw new Error(`the observation does not cover the last ${o.unusedDays} day(s): it starts ${start === undefined ? 'nowhere (no traces)' : new Date(start).toISOString()}; refusing to call authority unused`);
  const used = mine.filter((t) => t.outcome === 'allow' && t.at >= from && t.at <= o.now);
  const keep: { pred: Predicate; ts: Trace[] }[] = [];
  const dropped: string[] = [];
  for (const p of base.policy.predicates) {
    const ts = used.filter((t) => admits([p], t));
    if (ts.length === 0) dropped.push(`${Array.isArray(p.verb) ? p.verb.join(',') : p.verb} on ${p.resource ?? '*'}`); else keep.push({ pred: p, ts });
  }
  if (keep.length === 0) throw new Error('no authority was used in the window: revoke the grant instead of tightening it');
  const preds = keep.map(({ pred, ts }): Predicate => {
    const where: Condition[] = [];
    for (const c of pred.where ?? []) {
      if (!leaf(c)) { where.push(c); continue; }
      const key = c.field.replace(/^action\.params\./, '');
      const vals = ts.map((t) => t.params[key]);
      if (vals.some((v) => v === undefined)) { where.push(c); continue; }
      if (c.op === 'lte' && vals.every((v) => typeof v === 'number')) { const xs = vals as number[]; const m = maxOf(xs); let cap = m >= 0 ? m * (1 + r.margin) : m * (1 - r.margin); if (xs.every(Number.isInteger)) cap = Math.ceil(cap); where.push({ ...c, value: Math.min(c.value as number, clean(cap)) }); }
      else if (c.op === 'gte' && vals.every((v) => typeof v === 'number')) { const xs = vals as number[]; const m = minOf(xs); let fl = m >= 0 ? 0 : m * (1 + r.margin); if (xs.every(Number.isInteger)) fl = Math.floor(fl); where.push({ ...c, value: Math.max(c.value as number, clean(fl)) }); }
      else if (c.op === 'in' && vals.every((v) => typeof v === 'string')) { const seen = new Set(vals as string[]); const old = (c.value as string[]).filter((x) => seen.has(x)); where.push(old.length === 1 ? { field: c.field, op: 'eq', value: old[0]! } : { field: c.field, op: 'in', value: old }); }
      else where.push(c);
    }
    return strip({ ...pred, ...(where.length ? { where } : { where: undefined }) } as Predicate);
  });
  const peak = peakInWindow(used.map((t) => t.at), Number((base.policy.caveats.find((c) => c.type === 'rate')?.per_secs as number | undefined) ?? 3600));
  const caveats: Caveat[] = base.policy.caveats.map((c) => (c.type === 'rate' ? { ...c, max: Math.min(c.max as number, Math.max(1, Math.ceil(peak * (1 + r.margin)))) } : c));
  const kept = new Set(keep.map((k) => `${Array.isArray(k.pred.verb) ? k.pred.verb.join(',') : k.pred.verb}\0${k.pred.resource ?? '*'}`));
  const rules = base.rules.filter((x) => kept.has(`${x.verb}\0${x.resource}`));
  return seal({
    ...stripDigest(base), createdAt: o.now, policy: { predicates: preds, caveats }, rules,
    basis: { traceSetDigest: observed.digest, included: used.length, from, to: o.now }, amends: base.digest,
    notes: [...base.notes.filter((n) => !n.startsWith('tightening:')), `tightening: ${dropped.length} rule(s) unused for ${o.unusedDays} day(s) removed${dropped.length ? ` (${dropped.map((d) => cleanText(d)).join('; ')})` : ''}; caps, value sets and the rate shrunk to what was used`],
  });
}
