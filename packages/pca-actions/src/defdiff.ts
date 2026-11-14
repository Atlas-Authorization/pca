// defdiff.ts - the semantic diff of two versions of one def for the authoring CLI (spec section 7.3): equal | narrow | widen |
// incomparable, with the reasons. Conservative: anything it cannot show to be no wider is widening. The registry track
// (pack evolution, the brute-force soundness oracle) owns the pinned/signed form of this; this is the author-facing tool.

import { PROVENANCE_LEVELS, SENSITIVITY_RANK, type ActionDef, type ParamDef } from './def';
import { ROLE_SENSITIVITY_FLOOR } from './core-traits';
import { defDigest } from './digest';
import { effective } from './effective';
import { idPatternContains } from './idpattern';
import { effectiveParamSensitivity, normalize, worstReversibility } from './normalize';
import { leq, profileEq, type Registry } from './traits';
import { REV_RANK } from './def';

export type DiffClass = 'equal' | 'narrow' | 'widen' | 'incomparable';
export interface DefDiff { class: DiffClass; breaking: boolean; reasons: string[] }

const SCOPE_RANK = { one: 0, set: 1, tenant: 2, global: 3 } as const;

export function diffDefs(a: ActionDef, b: ActionDef, reg: Registry): DefDiff {
  if (a.verb !== b.verb) return { class: 'widen', breaking: true, reasons: ['verb renamed: removed + added (grants on the old verb do not follow)'] };
  const wide: string[] = [];
  const narrow: string[] = [];
  const incomp: string[] = [];
  let breaking = false;
  const na = normalize(a);
  const nb = normalize(b);

  // authoring diff: compare the defs as written (their hint view); enforcement of an unconfirmed def is the registry top either way
  const ea = effective(a, reg).hint;
  const eb = effective(b, reg).hint;
  if (!leq(ea.eff, eb.eff)) wide.push('the effective profile is not at least the old one');
  else if (!profileEq(ea.eff, eb.eff)) narrow.push('the effective profile rose');

  for (const e of na.effects) if (!nb.effects.includes(e)) wide.push(`effect ${e} removed`);
  for (const e of nb.effects) if (!na.effects.includes(e)) narrow.push(`effect ${e} added`);
  for (const t of na.traits) if (!nb.traits.includes(t)) wide.push(`declared trait ${t} removed`);
  for (const t of nb.traits) if (!na.traits.includes(t)) narrow.push(`declared trait ${t} added`);
  const ra = worstReversibility(na.reversibility, na.params);
  const rb = worstReversibility(nb.reversibility, nb.params);
  if (REV_RANK[rb] < REV_RANK[ra]) wide.push(`reversibility lowered (${ra} to ${rb})`);
  else if (REV_RANK[rb] > REV_RANK[ra]) narrow.push(`reversibility raised (${ra} to ${rb})`);
  if (nb.blast.ppm < na.blast.ppm) wide.push('blast lowered');
  else if (nb.blast.ppm > na.blast.ppm) narrow.push('blast raised');
  const idem = (m: string): number => (m === 'none' ? 0 : 1);
  if (idem(nb.idempotency.mode) < idem(na.idempotency.mode)) wide.push('idempotency loosened');
  else if (idem(nb.idempotency.mode) > idem(na.idempotency.mode)) narrow.push('idempotency added');

  // resource
  if (na.resource.type !== nb.resource.type) incomp.push('resource type changed');
  if (SCOPE_RANK[nb.resource.scope] > SCOPE_RANK[na.resource.scope]) wide.push('resource scope widened');
  else if (SCOPE_RANK[nb.resource.scope] < SCOPE_RANK[na.resource.scope]) narrow.push('resource scope narrowed');
  const inOld = idPatternContains(na.resource.id, nb.resource.id);
  const inNew = idPatternContains(nb.resource.id, na.resource.id);
  if (!inOld) wide.push('the resource id pattern is not contained in the old one');
  else if (!inNew) narrow.push('the resource id pattern is narrower');

  // params
  for (const k of Object.keys(na.params)) {
    const x = na.params[k]!;
    const y = nb.params[k];
    if (!y) { narrow.push(`param ${k} removed`); breaking = true; continue; }
    paramDiff(k, x, y, wide, narrow, incomp);
    if (x.required === false && y.required === true) breaking = true;
  }
  for (const k of Object.keys(nb.params)) {
    if (na.params[k]) continue;
    if (nb.params[k]!.required) { narrow.push(`required param ${k} added`); breaking = true; } else wide.push(`optional param ${k} added`);
  }
  if (a.review.state === 'confirmed' && b.review.state !== 'confirmed') narrow.push('review state left confirmed');

  const cls: DiffClass = incomp.length > 0 || (wide.length > 0 && narrow.length > 0) ? 'incomparable' : wide.length > 0 ? 'widen' : narrow.length > 0 ? 'narrow' : 'equal';
  const cmpEq = cls === 'equal' && defDigest(a) !== defDigest(b);
  return { class: cls, breaking, reasons: [...wide.map((r) => `widen: ${r}`), ...narrow.map((r) => `narrow: ${r}`), ...incomp.map((r) => `incomparable: ${r}`), ...(cmpEq ? ['equal: only title or description changed'] : [])] };
}

function paramDiff(k: string, x: ParamDef & { required: boolean }, y: ParamDef & { required: boolean }, wide: string[], narrow: string[], incomp: string[]): void {
  const num = (f: 'min' | 'max' | 'max_len' | 'max_items' | 'min_items', lowerIsWider: boolean): void => {
    const o = x[f];
    const n = y[f];
    if (o === n) return;
    // an absent bound is unbounded: the widest
    const rank = (v: number | undefined): number => (v === undefined ? (lowerIsWider ? -Infinity : Infinity) : v);
    const widerNew = lowerIsWider ? rank(n) < rank(o) : rank(n) > rank(o);
    (widerNew ? wide : narrow).push(`param ${k}: ${f} ${String(o)} to ${String(n)}`);
  };
  if (x.type !== y.type) incomp.push(`param ${k}: type changed`);
  num('min', true); num('max', false); num('max_len', false); num('max_items', false); num('min_items', true);
  if (JSON.stringify(x.unit ?? null) !== JSON.stringify(y.unit ?? null)) incomp.push(`param ${k}: unit changed`);
  const vo = x.values;
  const vn = y.values;
  if (vo !== undefined || vn !== undefined) {
    if (vo === undefined) narrow.push(`param ${k}: values restricted`);
    else if (vn === undefined) wide.push(`param ${k}: values unrestricted`);
    else {
      const added = vn.filter((v) => !vo.includes(v));
      const removed = vo.filter((v) => !vn.includes(v));
      if (added.length > 0) wide.push(`param ${k}: values added (${added.join(', ')})`);
      if (removed.length > 0) narrow.push(`param ${k}: values removed (${removed.join(', ')})`);
    }
  }
  if (x.required === true && y.required === false) wide.push(`param ${k}: required to optional`);
  if (x.required === false && y.required === true) narrow.push(`param ${k}: optional to required`);
  const pl = (v: string | undefined): number => (v === undefined ? PROVENANCE_LEVELS.length : PROVENANCE_LEVELS.indexOf(v as never));
  if (pl(y.provenance_min) > pl(x.provenance_min)) wide.push(`param ${k}: provenance_min loosened`);
  else if (pl(y.provenance_min) < pl(x.provenance_min)) narrow.push(`param ${k}: provenance_min tightened`);
  const sx = SENSITIVITY_RANK[effectiveParamSensitivity(x)];
  const sy = SENSITIVITY_RANK[effectiveParamSensitivity(y)];
  if (sy < sx) wide.push(`param ${k}: sensitivity lowered`);
  else if (sy > sx) narrow.push(`param ${k}: sensitivity raised`);
  if (x.role !== y.role) {
    const f = (r: string | undefined): number => (r !== undefined && Object.prototype.hasOwnProperty.call(ROLE_SENSITIVITY_FLOOR, r) ? SENSITIVITY_RANK[ROLE_SENSITIVITY_FLOOR[r]!] : 0);
    if (f(y.role) < f(x.role)) wide.push(`param ${k}: role changed to a lower-floor role`);
    else if (f(y.role) > f(x.role)) narrow.push(`param ${k}: role changed to a higher-floor role`);
    else incomp.push(`param ${k}: role changed`);
  }
}

export interface PackDiffEntry { verb: string; class: DiffClass | 'added' | 'removed'; breaking: boolean; reasons: string[] }

/** Per-verb diff of two sets of defs. A removed verb is `removed`; a new verb is `added`. */
export function diffPacks(olds: readonly ActionDef[], news: readonly ActionDef[], reg: Registry): PackDiffEntry[] {
  const o = new Map(olds.map((d) => [d.verb, d]));
  const n = new Map(news.map((d) => [d.verb, d]));
  const out: PackDiffEntry[] = [];
  for (const v of [...new Set([...o.keys(), ...n.keys()])].sort()) {
    const x = o.get(v);
    const y = n.get(v);
    if (!x) out.push({ verb: v, class: 'added', breaking: false, reasons: [] });
    else if (!y) out.push({ verb: v, class: 'removed', breaking: true, reasons: ['verb removed'] });
    else { const d = diffDefs(x, y, reg); out.push({ verb: v, ...d }); }
  }
  return out;
}
