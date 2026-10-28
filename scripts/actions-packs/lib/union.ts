// union.ts - fail strict. For the high-risk traits a pack def carries the trait when EITHER the pack's own inference OR the suggestion rules
// flag it, unless a person adjudicated (corpus/adjudication.tsv) that the operation lacks it. The rules see what an importer sees (labels
// stripped). A def that cannot take the trait because a required parameter rule would fail is left `unreviewed` (the maximal floor) instead.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CORE_REGISTRY, DEFAULT_RULES, applySuggestion, closure, effective, requiredPrulesViolated, suggestWithRules, hintTraits, validateDef, type ActionDef } from '@atlasauth/pca-actions';

export const HIGH_RISK = ['money_moving', 'external_communication', 'code_execution', 'privilege_change', 'destructive', 'data_export', 'financial_data_read', 'credential_access'].map((t) => `pca.${t}`);
export const ADJ_FILE = join(__dirname, '../../../packages/pca-actions/corpus/adjudication.tsv');

let notTrait: Set<string> | undefined;
/** `pack:verb:trait` triples a person judged NOT to have the trait. */
function adjudicatedNo(): Set<string> {
  if (!notTrait) {
    notTrait = new Set();
    for (const l of readFileSync(ADJ_FILE, 'utf8').trim().split('\n').slice(1)) { const c = l.split('\t'); if (c[8] === 'n') notTrait.add(`${c[3]}:${c[4]}:pca.${c[1]}`); }
  }
  return notTrait;
}

function blank(d: ActionDef): ActionDef {
  const b = JSON.parse(JSON.stringify(d)) as ActionDef & { traits?: unknown };
  delete b.traits;
  b.effects = d.effects.every((e) => e === 'read') ? ['read'] : ['update'];
  b.review = { state: 'unreviewed' };
  for (const p of Object.values(b.params)) { delete p.role; delete p.tags; delete p.sensitivity; }
  return b;
}

const carried = (d: ActionDef): Set<string> => new Set(closure(CORE_REGISTRY, hintTraits(d)));

export function unionHighRisk(pack: string, d: ActionDef): ActionDef {
  const b = blank(d);
  const flagged = new Set(closure(CORE_REGISTRY, hintTraits(applySuggestion(b, suggestWithRules(b, DEFAULT_RULES, CORE_REGISTRY), {}))));
  const have = carried(d), no = adjudicatedNo();
  const flaggedNew = HIGH_RISK.filter((t) => flagged.has(t) && !have.has(t));
  const add = flaggedNew.filter((t) => !no.has(`${pack}:${d.verb}:${t}`));
  const judged = flaggedNew.filter((t) => no.has(`${pack}:${d.verb}:${t}`));
  if (add.length === 0 && judged.length === 0) return d;
  if (add.length === 0) return { ...d, review: { ...d.review, provenance: { ...d.review.provenance, adjudicated: [...new Set([...(d.review.provenance?.adjudicated ?? []), ...judged])].sort() } } };
  let next: ActionDef = { ...d, traits: [...new Set([...(d.traits ?? []), ...add])].sort(), review: { ...d.review, provenance: { union: [...add].sort(), ...(judged.length ? { adjudicated: [...judged].sort() } : {}) } } };
  // lint LD-004: a money-moving action needs an idempotency key; give it the same optional key parameter a `pay` def gets
  if (add.includes('pca.money_moving') && (!d.idempotency || d.idempotency.mode === 'none')) {
    next = { ...next, params: { ...next.params, ...(next.params.idempotency_key ? {} : { idempotency_key: { type: 'string' as const, max_len: 255, required: false } }) }, idempotency: { mode: 'key_param' as const, param: 'idempotency_key' } };
  }
  const ok = validateDef(next) === null && requiredPrulesViolated(next, effective(next, CORE_REGISTRY).eff).length === 0;
  return ok ? next : { ...d, reversibility: 'irreversible', review: { state: 'unreviewed' } };
}
