import { existsSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  ApprovalStoreError,
  createDirectoryKv,
  createFileApprovalStore,
  createKvApprovalStore,
  type ApprovalStore,
  type Versioned,
} from './index';
import { createMemoryApprovalStore, createMemoryKv } from './testing';
import { approvalBrokerCases, approvalStoreCases, type ApprovalStoreCase } from './store-conformance';

const tmp = (): string => mkdtempSync(join(tmpdir(), 'ciba-store-'));

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return e instanceof ApprovalStoreError ? e.code : 'other';
  }
  return 'none';
}

/** Run every case; return the names of the ones that threw. */
async function failures(cases: ApprovalStoreCase[]): Promise<string[]> {
  const bad: string[] = [];
  for (const c of cases) {
    try {
      await c.run();
    } catch {
      bad.push(c.name);
    }
  }
  return bad;
}

describe('the reference stores pass the conformance suite', () => {
  const targets: Array<[string, () => { make: () => ApprovalStore; reopen?: (p: ApprovalStore) => ApprovalStore }]> = [
    ['memory store', () => ({ make: () => createMemoryApprovalStore() })],
    [
      'file store',
      () => {
        let last = '';
        return {
          make: () => createFileApprovalStore((last = join(tmp(), 'a.json'))),
          reopen: () => createFileApprovalStore(last),
        };
      },
    ],
    ['KV store over the memory KV', () => ({ make: () => createKvApprovalStore(createMemoryKv()) })],
    [
      'KV store over the directory KV',
      () => {
        let last = '';
        return {
          make: () => createKvApprovalStore(createDirectoryKv((last = tmp()))),
          reopen: () => createKvApprovalStore(createDirectoryKv(last)),
        };
      },
    ],
  ];
  for (const [name, t] of targets) {
    it(`${name}: store cases`, async () => {
      const { make, reopen } = t();
      const cases = approvalStoreCases(make, reopen);
      expect(await failures(cases)).toEqual([]);
    });
    it(`${name}: broker cases`, async () => {
      expect(await failures(approvalBrokerCases(t().make))).toEqual([]);
    });
  }

  it('the directory KV store is shared by two objects over the same directory', async () => {
    const dir = tmp();
    // durability on a real directory: write through one object, read through another
    const a = createKvApprovalStore(createDirectoryKv(dir));
    await a.cas('k', 0, { v: 1 });
    const b = createKvApprovalStore(createDirectoryKv(dir));
    expect(await b.get('k')).toEqual({ version: 1, value: { v: 1 } });
    expect(await b.cas('k', 1, { v: 2 })).toBe(true);
    expect(await a.cas('k', 1, { v: 3 })).toBe(false);
  });

  it('the suite has the durability case only when a reopen is given', () => {
    const without = approvalStoreCases(() => createMemoryApprovalStore()).map((c) => c.name);
    const withIt = approvalStoreCases(() => createMemoryApprovalStore(), (p) => p).map((c) => c.name);
    expect(withIt.length - without.length).toBe(1);
    expect(without).not.toContain('records and their versions survive reopening the store');
  });
});

describe('the suite flags defective stores', () => {
  const base = (): ApprovalStore => {
    const m = new Map<string, Versioned>();
    return {
      get: (k) => {
        const v = m.get(k);
        return v === undefined ? undefined : { version: v.version, value: structuredClone(v.value) };
      },
      cas: (k, e, value) => {
        if ((m.get(k)?.version ?? 0) !== e) return false;
        m.set(k, { version: e + 1, value: structuredClone(value) });
        return true;
      },
    };
  };
  it('the baseline used for the defective variants is itself clean', async () => {
    expect(await failures(approvalStoreCases(base))).toEqual([]);
  });

  it('a store whose cas ignores the version', async () => {
    const make = (): ApprovalStore => {
      const m = new Map<string, Versioned>();
      return {
        get: (k) => m.get(k),
        cas: (k, _e, value) => {
          m.set(k, { version: (m.get(k)?.version ?? 0) + 1, value });
          return true;
        },
      };
    };
    const bad = await failures(approvalStoreCases(make));
    expect(bad).toContain('cas at version 0 on an existing key is refused and changes nothing');
    expect(bad).toContain('exactly one of many concurrent creates wins');
    expect(bad).toContain('exactly one of many concurrent updates at the same version wins');
  });

  it('a store that does not bump the version', async () => {
    const make = (): ApprovalStore => {
      const m = new Map<string, Versioned>();
      return {
        get: (k) => m.get(k),
        cas: (k, e, value) => {
          if ((m.get(k)?.version ?? 0) !== e) return false;
          m.set(k, { version: Math.max(1, e), value });
          return true;
        },
      };
    };
    const bad = await failures(approvalStoreCases(make));
    expect(bad).toContain('cas succeeds only at the current version and bumps it by exactly one');
  });

  it('a non-atomic check-then-write (an await between the check and the write)', async () => {
    const make = (): ApprovalStore => {
      const m = new Map<string, Versioned>();
      return {
        get: (k) => m.get(k),
        cas: async (k, e, value) => {
          if ((m.get(k)?.version ?? 0) !== e) return false;
          await Promise.resolve(); // a microtask yield: every concurrent caller has checked before any writes, with no timer race
          m.set(k, { version: e + 1, value });
          return true;
        },
      };
    };
    const bad = await failures(approvalStoreCases(make));
    expect(bad).toContain('exactly one of many concurrent creates wins');
    expect(bad).toContain('exactly one of many concurrent updates at the same version wins');
    expect(bad).toContain('a retry loop over concurrent writers loses no increment');
    const brokerBad = await failures(approvalBrokerCases(make));
    expect(brokerBad).toContain('concurrent resolves through separate brokers: exactly one wins and its decision stands');
  });

  it('a store that hands out its internal objects', async () => {
    const make = (): ApprovalStore => {
      const m = new Map<string, Versioned>();
      return {
        get: (k) => m.get(k),
        cas: (k, e, value) => {
          if ((m.get(k)?.version ?? 0) !== e) return false;
          m.set(k, { version: e + 1, value });
          return true;
        },
      };
    };
    const bad = await failures(approvalStoreCases(make));
    expect(bad).toContain('a read is a snapshot: changing the returned value does not change the store');
    expect(bad).toContain('a written value is a snapshot: changing it after cas does not change the store');
  });

  it('a store that forgets everything on restart', async () => {
    const bad = await failures(approvalStoreCases(base, () => base()));
    expect(bad).toEqual(['records and their versions survive reopening the store']);
  });
});

describe('createKvApprovalStore', () => {
  it('requires a kv', () => {
    expect(() => createKvApprovalStore(undefined as never)).toThrow(TypeError);
    expect(() => createKvApprovalStore({ get: () => undefined } as never)).toThrow(TypeError);
  });

  it('refuses a stored record that is not valid JSON or has no valid version, on get and on cas', async () => {
    const bad = ['not json', '{"value":1}', '{"version":0,"value":1}', '{"version":1.5,"value":1}', '{"version":"1","value":1}', '{"version":1}', 'null', '[]'];
    for (const raw of bad) {
      const kv = createMemoryKv();
      await kv.putIfEquals('k', undefined, raw);
      const s = createKvApprovalStore(kv);
      await expect(Promise.resolve().then(() => s.get('k'))).rejects.toBeInstanceOf(ApprovalStoreError);
      await expect(Promise.resolve().then(() => s.cas('k', 1, 'x'))).rejects.toMatchObject({ code: 'corrupt_record' });
      expect(await kv.get('k')).toBe(raw); // nothing overwritten
    }
    const kv = createMemoryKv();
    await kv.putIfEquals('k', undefined, 'not json');
    await expect(Promise.resolve().then(() => createKvApprovalStore(kv).get('k'))).rejects.toMatchObject({
      code: 'corrupt_record',
      message: 'ciba: stored approval record is not valid JSON',
    });
  });

  it('a kv that loses the swap race makes cas report false', async () => {
    const kv = createMemoryKv();
    const racing = { get: kv.get, putIfEquals: () => false };
    expect(await createKvApprovalStore(racing).cas('k', 0, 'x')).toBe(false);
  });

  it('only an exact true from putIfEquals counts as a write', async () => {
    const odd = { get: () => undefined, putIfEquals: () => 'yes' as never };
    expect(await createKvApprovalStore(odd).cas('k', 0, 'x')).toBe(false);
  });

  it('a kv that throws surfaces the error (no silent success)', async () => {
    const boom = { get: () => undefined, putIfEquals: () => { throw new Error('disk full'); } };
    await expect(Promise.resolve().then(() => createKvApprovalStore(boom).cas('k', 0, 'x'))).rejects.toThrow('disk full');
  });
});

describe('createDirectoryKv', () => {
  it('rejects a bad lock timeout and empty keys', () => {
    for (const t of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) expect(() => createDirectoryKv(tmp(), { lockTimeoutMs: t })).toThrow(TypeError);
    const kv = createDirectoryKv(tmp());
    expect(() => kv.get('')).toThrow(ApprovalStoreError);
    expect(codeOf(() => kv.putIfEquals('', undefined, 'x'))).toBe('bad_key');
  });

  it('keys cannot escape the directory and leave no lock behind', () => {
    const dir = tmp();
    const kv = createDirectoryKv(dir);
    expect(kv.putIfEquals('../../escape', undefined, 'v')).toBe(true);
    expect(kv.get('../../escape')).toBe('v');
    expect(readdirSync(dir).every((f) => /^[0-9a-f]{64}$/.test(f))).toBe(true);
    expect(existsSync(join(dir, '..', '..', 'escape'))).toBe(false);
  });

  it('compare-and-swap semantics on raw strings', () => {
    const kv = createDirectoryKv(tmp());
    expect(kv.putIfEquals('k', 'x', 'y')).toBe(false); // absent but x expected
    expect(kv.putIfEquals('k', undefined, 'a')).toBe(true);
    expect(kv.putIfEquals('k', undefined, 'b')).toBe(false);
    expect(kv.putIfEquals('k', 'a', 'b')).toBe(true);
    expect(kv.get('k')).toBe('b');
  });

  it('fails closed with lock_timeout when a stale lock is present, and changes nothing', async () => {
    const dir = tmp();
    const kv = createDirectoryKv(dir, { lockTimeoutMs: 30 });
    // a valid versioned record, as the broker store writes it (a bare value would be a corrupt_record before the lock is even tried)
    const rec = JSON.stringify({ version: 1, value: 'a' });
    kv.putIfEquals('k', undefined, rec);
    const file = readdirSync(dir).find((f) => !f.endsWith('.lock'))!;
    writeFileSync(join(dir, `${file}.lock`), '');
    expect(codeOf(() => kv.putIfEquals('k', rec, JSON.stringify({ version: 2, value: 'b' })))).toBe('lock_timeout');
    expect(kv.get('k')).toBe(rec);
    // and through the broker store, the error reaches the caller instead of an approval
    await expect(Promise.resolve().then(() => createKvApprovalStore(kv).cas('k', 1, 'z'))).rejects.toMatchObject({ code: 'lock_timeout' });
  });
});
