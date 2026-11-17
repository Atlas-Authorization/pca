import { describe, expect, it } from 'vitest';
import { DIRECTORY_STORE_CHECKS, MemoryDirectoryStore, runDirectoryStoreConformance } from './index';

describe('in-memory directory store conformance', () => {
  it('passes every check; durability is skipped for an in-process store', async () => {
    const results = await runDirectoryStoreConformance({
      name: 'memory',
      durable: false,
      async create() {
        const store = new MemoryDirectoryStore();
        return { store, reopen: async () => store };
      },
    });
    expect(results.filter((r) => r.status === 'fail')).toEqual([]);
    expect(results.filter((r) => r.status === 'skipped').map((r) => r.name)).toEqual(['acknowledged-writes-survive-reopen']);
    expect(results.length).toBe(DIRECTORY_STORE_CHECKS.length);
  });

  it('catches a store whose append is not a compare-and-set', async () => {
    class Broken extends MemoryDirectoryStore {
      override async append(row: Parameters<MemoryDirectoryStore['append']>[0]) {
        await super.append(row);
        return true;
      }
    }
    const results = await runDirectoryStoreConformance({
      name: 'broken',
      durable: false,
      async create() {
        const store = new Broken();
        return { store, reopen: async () => store };
      },
    });
    expect(results.some((r) => r.status === 'fail')).toBe(true);
  });
});
