// Differential: the TypeScript selector expansion against the compiled Dafny model (formal/dafny/GoalSelect.dfy). Runs where
// generated/pca_goalselect.js exists (CI sets PCA_GOALSELECT_REQUIRE=1: a missing file is a failure there).
import { REVIEWED_PACK, REVIEW, reviewed } from './reviewed';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { CORE_PACK_DEFS, CORE_REGISTRY } from '@atlasauth/pca-actions';
import { describe, expect, it } from 'vitest';
import type { Ontology } from '../src/ir';
import { allowClassVerbs, classVerbs, floatClassVerbs, selCatalogOfDefs, type SelCatalog, type SelGoal } from '../src/selectors';

const have = existsSync(resolve(__dirname, '../../pca-verified-core/generated/pca_goalselect.js'));
if (process.env.PCA_GOALSELECT_REQUIRE === '1' && !have) throw new Error('generated/pca_goalselect.js is missing but PCA_GOALSELECT_REQUIRE=1');

describe.skipIf(!have)('selector expansion: TypeScript equals the compiled Dafny model', () => {
  it('class verbs and role paths agree on 2000 seeded cases over the core pack', async () => {
    const { selClassVerbs, selFloatClassVerbs, selAllowClassVerbs, selRolePath } = await import('@atlasauth/pca-verified-core');
    // half the pack is unsigned, so the catalog mixes confirmed verbs and unconfirmed ones (top closure with pca.unreviewed)
    const cat = selCatalogOfDefs(REVIEWED_PACK.map((d, i) => (i % 2 === 0 ? d : CORE_PACK_DEFS[i]!)), CORE_REGISTRY, REVIEW);
    const entries = cat.verbs.map((v) => [v.verb, ...v.traits]);
    const roles = cat.verbs.map((v) => [v.verb, ...Object.entries(v.roles).flatMap(([r, ps]) => ps.flatMap((p) => [r, p]))]);
    const roleNames = [...new Set(cat.verbs.flatMap((v) => Object.keys(v.roles))), 'no.such'];
    let s = 7;
    const n = (m: number): number => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s % m; };
    const pick = <T,>(xs: readonly T[]): T => xs[n(xs.length)]!;
    for (let i = 0; i < 2000; i++) {
      const all = Array.from({ length: n(3) }, () => pick(cat.known)), none = Array.from({ length: n(3) }, () => pick(cat.known));
      expect(selClassVerbs(entries, all, none), `${all}|${none}`).toEqual(classVerbs(cat, all, none));
      expect(selFloatClassVerbs(entries, all, none), `float ${all}|${none}`).toEqual(floatClassVerbs(cat, all, none));
      expect(selAllowClassVerbs(entries, all, none), `allow ${all}|${none}`).toEqual(allowClassVerbs(cat, all, none));
      const v = pick(cat.verbs), r = pick(roleNames);
      const ps = v.roles[r] ?? [];
      expect(selRolePath(roles, v.verb, r)).toBe(ps.length === 1 ? ps[0] : '');
    }
  });
});

// The whole expansion: the extracted model expands each selector goal (and each broken variant) exactly as the TypeScript does.
describe.skipIf(!have)('selector expansion: the whole expansion equals the compiled Dafny model', () => {
  it('48 vectors, their mutations and seeded random goals: same expanded Goal, same selector-layer reasons', async () => {
    const { selExpandTape } = await import('@atlasauth/pca-verified-core');
    const { readdirSync, readFileSync } = await import('node:fs');
    const { decodeGoal, encodeGoal, encodeOntology } = await import('../src/codec');
    const { canonicalPolicy } = await import('../src/compiler');
    const { expandSelGoal, selCarrier, encodeSelCatalog, selReasons } = await import('../src/selectors');
    const dir = resolve(__dirname, '../../pca-conformance/vectors/goal-select');
    const cases: { sg: SelGoal; ont: Ontology; cat: SelCatalog; id: string }[] = [];
    for (const f of readdirSync(dir)) {
      const v = JSON.parse(readFileSync(resolve(dir, f), 'utf8'));
      cases.push({ sg: v.sel.goal, ont: v.ontology, cat: v.sel.catalog, id: f });
    }
    // mutations: every one must be refused or expanded identically
    let s = 11;
    const n = (m: number): number => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s % m; };
    const base = [...cases];
    for (let i = 0; i < 200; i++) {
      const c = structuredClone(base[n(base.length)]!);
      const k = n(6);
      if (k === 0 && c.sg.grants[0]) c.sg.grants[0].sel = { k: 'class', all_of: [c.cat.known[n(c.cat.known.length)]!, 'pca.nope'], none_of: [] };
      else if (k === 1 && c.sg.grants[0]) c.sg.grants[0].sel = { k: 'class', all_of: ['pca.bulk'], none_of: ['pca.destructive'] };
      else if (k === 2 && c.sg.bounds[0]) c.sg.bounds[0].value = { k: 'role', role: 'party.payee' };
      else if (k === 3) c.sg.prohibits.push({ pid: `m${i}`, target: { k: 'trait', all_of: [c.cat.known[n(c.cat.known.length)]!], none_of: [c.cat.known[n(c.cat.known.length)]!] }, res: { k: 'any', reason: 't' }, cond: { k: 'true' } });
      else if (k === 4 && c.sg.bounds[0]) c.sg.bounds[0].sel = { k: 'trait', all_of: ['pca.external_communication'], none_of: [] };
      else if (k === 5) c.cat.verbs = c.cat.verbs.filter(() => n(8) !== 0);
      cases.push({ ...c, id: `mut-${i}` });
    }
    let expanded = 0, refused = 0;
    for (const c of cases) {
      const out = selExpandTape(encodeGoal(selCarrier(c.sg)), encodeOntology(c.ont as never), encodeSelCatalog(c.cat));
      const tsReasons = selReasons(c.sg, c.ont, c.cat).filter((r) => r !== 'catalog_digest_mismatch' && r !== 'bad_id');
      if (out[0]![1] === 1) {
        refused++;
        const k = (out[1] as readonly ['i', number])[1];
        expect(out.slice(2, 2 + k).map((t) => t[1]), c.id).toEqual(tsReasons);
      } else {
        expanded++;
        expect(out[0]![1], c.id).toBe(0);
        expect(tsReasons, c.id).toEqual([]);
        expect(canonicalPolicy(decodeGoal(out.slice(1)) as never), c.id).toBe(canonicalPolicy(expandSelGoal(c.sg, c.ont, c.cat).goal as never));
      }
    }
    expect(expanded).toBeGreaterThan(48);
    expect(refused).toBeGreaterThan(20);
  });
});
