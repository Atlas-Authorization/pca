// T-500: the committed catalog packs verify offline (shard digests, Merkle roots, def validation, lint subset, licence ledger).
import { describe, expect, it } from 'vitest';
import { packDirs, readPack, verifyAll } from '../../../scripts/actions-packs/lib/verify';

describe('catalog packs', () => {
  it('every committed pack verifies and the ledger is current', async () => {
    expect(await verifyAll()).toEqual([]);
  }, 600_000);
  it('ships the planned packs and at least 2,500 defs', () => {
    const packs = packDirs().map((p) => readPack(p.dir).m);
    expect(packs.map((m) => m.name)).toEqual(expect.arrayContaining(['core', 'db', 'stripe', 'github', 'gitlab', 'slack', 'google-workspace', 'm365', 'aws-core', 'k8s', 'payments-rails', 'travel']));
    expect(packs.reduce((n, m) => n + m.count, 0)).toBeGreaterThanOrEqual(2500);
  });
});
