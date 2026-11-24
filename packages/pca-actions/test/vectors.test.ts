// Replays every shared action-kit vector against the reference implementation, and checks that the committed files are
// byte-identical to a fresh deterministic generation (so a vector can never silently drift from the code).
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { generate, generateProfiles, replay, type VectorCase } from './vectors-gen';

const dir = resolve(__dirname, '../../pca-conformance/vectors/actions');
const files = readdirSync(dir).filter((f) => f.endsWith('.json')).sort();

describe('approval profile vectors (PSD2 linking, batch)', () => {
  const pdir = resolve(__dirname, '../../pca-conformance/vectors/approval-profiles');
  it('the committed files are byte-identical to a fresh generation and replay to their expectation', () => {
    const fresh = generateProfiles();
    expect(readdirSync(pdir).filter((f) => f.endsWith('.json')).sort()).toEqual(fresh.map((c) => `${c.id}.json`).sort());
    for (const c of fresh) {
      const text = readFileSync(join(pdir, `${c.id}.json`), 'utf8');
      expect(text).toBe(JSON.stringify(c) + '\n');
      expect(replay(JSON.parse(text) as VectorCase), c.id).toEqual(c.expect);
    }
    expect(fresh.length).toBeGreaterThanOrEqual(12);
  });
});

describe('action-kit shared vectors', () => {
  it('the committed vectors are byte-identical to a fresh generation', () => {
    const fresh = generate();
    expect(files).toEqual(fresh.map((c) => `${c.id}.json`).sort());
    for (const c of fresh) expect(readFileSync(join(dir, `${c.id}.json`), 'utf8')).toBe(JSON.stringify(c) + '\n');
  });
  it('there are enough of each required kind', () => {
    const kinds = new Map<string, number>();
    for (const f of files) {
      const c = JSON.parse(readFileSync(join(dir, f), 'utf8')) as VectorCase;
      kinds.set(c.kind, (kinds.get(c.kind) ?? 0) + 1);
    }
    for (const k of ['digest', 'parse', 'expand', 'floor', 'conform', 'pack', 'effective', 'schema_verb', 'rule22_schema', 'rule22', 'pack_verify', 'evolution_verify', 'reapproval_verify', 'pin', 'pack_proof_verify', 'approval_render', 'approval_digest', 'approval_escalation']) expect(kinds.get(k) ?? 0, k).toBeGreaterThanOrEqual(8);
    expect(kinds.get('tracker') ?? 0).toBeGreaterThanOrEqual(8);
    expect(files.length).toBeGreaterThanOrEqual(600);
  });
  it('the reference replay reproduces every expected result', () => {
    for (const f of files) {
      const c = JSON.parse(readFileSync(join(dir, f), 'utf8')) as VectorCase;
      expect(replay(c), c.id).toEqual(c.expect);
    }
  });
});
