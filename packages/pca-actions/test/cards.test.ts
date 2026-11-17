// Policy-card golden files, one per core trait: a read-less minimal def tagged only with that trait, its card, and the card of
// a trait selector over it. UPDATE_GOLDEN=1 rewrites them; CI compares byte for byte.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CORE_REGISTRY, CORE_TRAIT_IDS, cardOf, type ActionDef } from '../src';
import { hinted } from './reviewed';

const dir = join(__dirname, 'golden', 'cards');
const defFor = (trait: string): ActionDef => ({
  v: 1, kind: 'pca-action-def', verb: `golden.${trait.slice(4)}`, title: `Do the ${trait.slice(4).replace(/_/g, ' ')} thing`,
  effects: ['update'], resource: { type: 'golden.item', id: { prefix: 'g_', class: 'any_safe', len: [1, 32] }, scope: 'one' },
  params: {}, reversibility: 'reversible', traits: [trait], review: { state: 'authored' },
});
const body = (trait: string): string => {
  const d = defFor(trait);
  const e = hinted(d);
  return JSON.stringify({ trait, card: cardOf(d, e, CORE_REGISTRY), closure: e.closure, floor: e.floor }, null, 1) + '\n';
};

describe('policy card golden files (one per core trait)', () => {
  it('there are 22 core traits', () => expect(CORE_TRAIT_IDS).toHaveLength(22));
  for (const t of CORE_TRAIT_IDS) {
    it(`${t}`, () => {
      const f = join(dir, `${t.slice(4)}.json`);
      if (process.env.UPDATE_GOLDEN === '1') { mkdirSync(dir, { recursive: true }); writeFileSync(f, body(t)); }
      expect(existsSync(f), `missing golden ${f} (run with UPDATE_GOLDEN=1)`).toBe(true);
      expect(readFileSync(f, 'utf8')).toBe(body(t));
    });
  }
});
