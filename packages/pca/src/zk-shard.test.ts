import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { circuitSelected, myShard, parseShard, runsControls, shardItems, ZK_CIRCUITS } from './test-support/zk-shard';

const CIRC = join(__dirname, '..', 'circuits');
const PUBLIC = ['allow', 'now', 'blast', 'delegationDepth', 'recentCount', 'allocChild'];
const policyPrivate = Object.keys(JSON.parse(readFileSync(join(CIRC, 'policyvm_sample_input.json'), 'utf8')) as object).filter((k) => !PUBLIC.includes(k));
const compliancePrivate = ['verb', 'resource', 'planVerb', 'policySalt', 'planSalt', 'actionSalt', 'risk', 'budget'];
// the shard counts the workflow matrix uses
const MATRIX: Record<string, { items: string[]; n: number }> = {
  compliance: { items: compliancePrivate, n: 1 },
  policyvm: { items: policyPrivate, n: 6 },
  policyvm_bound: { items: policyPrivate, n: 6 },
};

describe('witness-perturbation sharding', () => {
  it('the shards of every circuit cover each private input exactly once', () => {
    for (const [c, { items, n }] of Object.entries(MATRIX)) {
      const got = Array.from({ length: n }, (_, i) => myShard(c as never, items, { PCA_ZK_CIRCUIT: c, PCA_ZK_SHARD: `${i + 1}/${n}` } as never)).flat();
      expect([...got].sort(), c).toEqual([...items].sort());
      expect(new Set(got).size, c).toBe(items.length);
    }
  });
  it('no shard of the matrix is empty or holds more than ceil(items/n) inputs', () => {
    for (const [c, { items, n }] of Object.entries(MATRIX)) {
      for (let k = 1; k <= n; k++) {
        const s = shardItems(items, k, n);
        expect(s.length, `${c} ${k}/${n}`).toBeGreaterThan(0);
        expect(s.length).toBeLessThanOrEqual(Math.ceil(items.length / n));
      }
    }
  });
  it('unset means everything; another circuit means nothing', () => {
    expect(myShard('policyvm', policyPrivate, {} as never)).toEqual(policyPrivate);
    expect(myShard('policyvm', policyPrivate, { PCA_ZK_CIRCUIT: 'compliance' } as never)).toEqual([]);
    expect(runsControls({} as never)).toBe(true);
    expect(runsControls({ PCA_ZK_CIRCUIT: 'policyvm_bound', PCA_ZK_SHARD: '1/6' } as never)).toBe(true);
    expect(runsControls({ PCA_ZK_CIRCUIT: 'policyvm_bound', PCA_ZK_SHARD: '2/6' } as never)).toBe(false);
    expect(runsControls({ PCA_ZK_CIRCUIT: 'policyvm', PCA_ZK_SHARD: '1/6' } as never)).toBe(false);
  });
  it('malformed selectors throw instead of silently running nothing', () => {
    for (const bad of ['0/3', '4/3', '1', 'a/b', '1/0', '-1/2']) expect(() => parseShard(bad), bad).toThrow();
    expect(() => circuitSelected('policyvm', 'policyvm2')).toThrow();
    expect(ZK_CIRCUITS).toEqual(['compliance', 'policyvm', 'policyvm_bound']);
  });
});
