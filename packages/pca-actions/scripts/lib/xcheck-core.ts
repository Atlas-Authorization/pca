// xcheck-core.ts - shared by xcheck-packs.ts and adjudicate.ts: load pack defs and label each one twice (the pack's own traits; the suggestion
// rules run on the def with every label removed).
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { CORE_REGISTRY, DEFAULT_RULES, applySuggestion, closure, suggestWithRules, hintTraits, type ActionDef } from '../../src';

export const TRAITS = ['money_moving', 'destructive', 'external_communication', 'privilege_change', 'code_execution', 'public_exposure', 'financial_data_read', 'scheduled', 'bulk', 'pii_access', 'credential_access', 'data_export'].map((t) => `pca.${t}`);

export interface PackDef { pack: string; def: ActionDef }

export function loadPackDefs(dir: string): PackDef[] {
  const out: PackDef[] = [];
  for (const pack of readdirSync(dir, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort()) {
    for (const v of readdirSync(join(dir, pack)).sort()) {
      const dd = join(dir, pack, v, 'defs');
      if (!existsSync(dd)) continue;
      for (const f of readdirSync(dd).filter((x) => x.endsWith('.jsonl')).sort()) {
        for (const line of readFileSync(join(dd, f), 'utf8').split('\n')) if (line.trim()) out.push({ pack, def: JSON.parse(line) as ActionDef });
      }
    }
  }
  return out;
}

/** The pack's side: the closure of everything it carries (declared traits plus what effects, roles and tags imply), review marker excluded. */
export const packTraits = (d: ActionDef): Set<string> =>
  new Set(closure(CORE_REGISTRY, hintTraits(d)).filter((t) => t !== 'pca.unreviewed'));

/** Strip every label (declared traits, roles, tags, sensitivity; a write becomes a neutral update) so the rules see what an importer sees. */
export function blankOf(d: ActionDef): ActionDef & { traits?: unknown } {
  const blank = JSON.parse(JSON.stringify(d)) as ActionDef & { traits?: unknown };
  delete blank.traits;
  blank.effects = d.effects.every((e) => e === 'read') ? ['read'] : ['update'];
  blank.review = { state: 'unreviewed' };
  for (const p of Object.values(blank.params)) { delete p.role; delete p.tags; delete p.sensitivity; }
  return blank;
}

export function rulesTraits(d: ActionDef): Set<string> {
  const blank = blankOf(d);
  const sg = suggestWithRules(blank, DEFAULT_RULES, CORE_REGISTRY);
  return new Set(closure(CORE_REGISTRY, hintTraits(applySuggestion(blank, sg, {}))).filter((t) => t !== 'pca.unreviewed'));
}

/** Deterministic tune/hold-out split of the adjudicated pack defs (by `pack:verb`), so a rule edit can learn from one half and be checked on the other. */
export const adjSplit = (key: string): 'tune' | 'holdout' => {
  let h = 2166136261;
  for (const ch of key) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
  return (h >>> 11) % 2 === 0 ? 'tune' : 'holdout';
};
if (require.main !== module) { /* imported for adjSplit only */ }
