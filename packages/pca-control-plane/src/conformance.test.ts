import { describe, expect, it } from 'vitest';
import { InMemoryControlPlaneStore, STORE_CHECKS, runStoreConformance } from './index';

describe('in-memory store conformance', () => {
  it('passes every check; the durability check is skipped for an in-process store', async () => {
    const results = await runStoreConformance({
      name: 'memory',
      durable: false,
      async create() {
        const store = new InMemoryControlPlaneStore();
        return { store, reopen: async () => store };
      },
    });
    expect(results.filter((r) => r.status === 'fail')).toEqual([]);
    expect(results.filter((r) => r.status === 'skipped').map((r) => r.name)).toEqual(['acknowledged-writes-survive-reopen']);
    expect(results.length).toBe(STORE_CHECKS.length);
  });

  it('the suite catches a store that lets two freezes live on one subject', async () => {
    class Broken extends InMemoryControlPlaneStore {
      override async putDirective(d: Parameters<InMemoryControlPlaneStore['putDirective']>[0]) {
        return d.kind === 'freeze' ? ({ created: true } as const) : super.putDirective(d);
      }
    }
    const results = await runStoreConformance({
      name: 'broken',
      durable: false,
      async create() {
        const store = new Broken();
        return { store, reopen: async () => store };
      },
    });
    expect(results.find((r) => r.name === 'one-live-freeze-per-subject')?.status).toBe('fail');
  });

  it('the suite catches a store whose sequence repeats', async () => {
    class Broken extends InMemoryControlPlaneStore {
      override async nextSeq() {
        return 1;
      }
    }
    const results = await runStoreConformance({ name: 'broken', durable: false, async create() { const store = new Broken(); return { store, reopen: async () => store }; } });
    expect(results.find((r) => r.name === 'sequence-never-repeats')?.status).toBe('fail');
  });
});
