import { AssertionError } from 'node:assert';
import { describe, expect, it } from 'vitest';
import { encodeKey, mintRoot, publicKeyOf } from '@atlasauth/pca';
import { mesh } from '@atlasauth/pca/ext/research';
import { meshWitnessStoreCases, type MeshWitnessStoreAdapter } from './mesh-witness';

const { MeshDomain, MeshWitness, MemoryMeshWitnessStore } = mesh;
type Store = mesh.MeshWitnessStore;
type State = mesh.MeshWitnessState;

// An independent copy of the fixtures the cases use, so their exact values are pinned.
const seedI = (label: string): Uint8Array => new Uint8Array(32).map((_, i) => (label.charCodeAt(i % label.length) + i) & 0xff);
const PI = seedI('principal');
const capI = (label: string) => mintRoot({ principalSecret: PI, principalPublic: encodeKey(publicKeyOf(PI)), holder: encodeKey(publicKeyOf(seedI('holder'))), caveats: [{ type: 'scope', actions: [label] }] });
const stI = (n: number): State => ({ seen: [{ head: { domain: `d${n}`, size: 0, root: '', rev_root: 'r', rev_size: 0, timestamp: n }, rev_ids: [] }] });

interface Rec {
  adapter: MeshWitnessStoreAdapter;
  events: string[];
  saves: unknown[];
}

/** A correct in-memory store that logs every call and every state it was asked to save. */
function recording(damageable = false): Rec {
  const events: string[] = [];
  const saves: unknown[] = [];
  type Wrapped = Store & { inner: Store; broken: boolean };
  const wrap = (inner: Store): Wrapped => {
    const w: Wrapped = {
      inner,
      broken: false,
      load() {
        events.push('load');
        if (w.broken) throw new Error('damaged');
        return inner.load();
      },
      save(s: State) {
        events.push('save');
        saves.push(JSON.parse(JSON.stringify(s)));
        inner.save(s);
      },
    };
    return w;
  };
  const adapter: MeshWitnessStoreAdapter = {
    name: 'recording',
    make: () => {
      events.push('make');
      return wrap(new MemoryMeshWitnessStore());
    },
    reopen: (prev) => {
      events.push('reopen');
      return wrap((prev as Wrapped).inner);
    },
    ...(damageable
      ? {
          damage: (s: Store) => {
            events.push('damage');
            (s as Wrapped).broken = true;
          },
        }
      : {}),
  };
  return { adapter, events, saves };
}

const find = (a: MeshWitnessStoreAdapter, prefix: string) => meshWitnessStoreCases(a).find((c) => c.name.startsWith(prefix))!;

describe('what each case does to the store', () => {
  it('a fresh store is only loaded', async () => {
    const r = recording();
    await find(r.adapter, 'a fresh store').run();
    expect(r.events).toEqual(['make', 'load']);
  });

  it('save then load saves the fixed state once and loads once', async () => {
    const r = recording();
    await find(r.adapter, 'save then load').run();
    expect(r.events).toEqual(['make', 'save', 'load']);
    expect(r.saves).toEqual([stI(1)]);
  });

  it('a later save replaces: two saves then one load', async () => {
    const r = recording();
    await find(r.adapter, 'a later save').run();
    expect(r.events).toEqual(['make', 'save', 'save', 'load']);
    expect(r.saves).toEqual([stI(1), stI(2)]);
  });

  it('the copy cases save once and load the expected number of times', async () => {
    const a = recording();
    await find(a.adapter, 'load returns a copy').run();
    expect(a.events).toEqual(['make', 'save', 'load', 'load']);
    expect(a.saves).toEqual([stI(1)]);
    const b = recording();
    await find(b.adapter, 'save keeps its own copy').run();
    expect(b.events).toEqual(['make', 'save', 'load']);
    expect(b.saves).toEqual([stI(1)]);
  });

  it('reopening: save, reopen, load', async () => {
    const r = recording();
    await find(r.adapter, 'state survives reopening').run();
    expect(r.events).toEqual(['make', 'save', 'reopen', 'load']);
    expect(r.saves).toEqual([stI(3)]);
  });

  it('a witness persists its exact cosigned head', async () => {
    const r = recording();
    await find(r.adapter, 'a witness persists every cosignature').run();
    expect(r.events).toEqual(['make', 'load', 'save', 'load', 'load']);
    const d = new MeshDomain('d', seedI('domain'));
    d.record(capI('a'));
    const ref = new MeshWitness(seedI('w'));
    d.publishHead([ref], 1_000);
    expect(r.saves).toEqual([ref.exportState()]);
  });

  it('a failed save: persisted heads are exactly the two that succeeded, and the store is read back once', async () => {
    const r = recording();
    await find(r.adapter, 'a failed save').run();
    expect(r.events).toEqual(['make', 'load', 'save', 'load', 'save']);
    const d = new MeshDomain('d', seedI('domain'));
    d.record(capI('a'));
    const ref = new MeshWitness(seedI('w'));
    d.publishHead([ref], 1_000);
    const first = ref.exportState();
    d.record(capI('b'));
    d.publishHead([ref], 2_000);
    expect(r.saves).toEqual([first, ref.exportState()]);
  });

  it('a restarted witness: two cosigns, a reopen, then the honest head again', async () => {
    const r = recording();
    await find(r.adapter, 'a restarted witness').run();
    expect(r.events).toEqual(['make', 'load', 'save', 'save', 'reopen', 'load', 'save']);
    const d = new MeshDomain('d', seedI('domain'));
    d.record(capI('a'));
    const ref = new MeshWitness(seedI('w'));
    d.publishHead([ref], 1_000);
    const s1 = ref.exportState();
    d.record(capI('b'));
    d.publishHead([ref], 2_000);
    const s2 = ref.exportState();
    d.publishHead([ref], 3_000);
    expect(r.saves).toEqual([s1, s2, ref.exportState()]);
  });

  it('damaged storage: damage, then two failing loads', async () => {
    const r = recording(true);
    await find(r.adapter, 'damaged storage').run();
    expect(r.events).toEqual(['make', 'save', 'damage', 'load', 'load']);
    const d = new MeshDomain('d', seedI('domain'));
    d.record(capI('a'));
    const ref = new MeshWitness(seedI('w'));
    d.publishHead([ref], 1_000);
    expect(r.saves).toEqual([ref.exportState()]);
    const m = new MemoryMeshWitnessStore();
    m.save(r.saves[0] as State);
    expect(() => new MeshWitness(seedI('w'), { store: m })).not.toThrow();
  });
});

describe('which cases an adapter gets', () => {
  const base = [
    'a fresh store loads nothing',
    'save then load returns the same state',
    'a later save replaces the earlier one',
    'load returns a copy: changing it does not change the store',
    'save keeps its own copy: changing the argument afterwards does not change the store',
    'a witness persists every cosignature before returning it',
    'a failed save refuses the cosignature and leaves the witness unchanged',
  ];
  const reopenCases = ['state survives reopening the store', 'a restarted witness remembers what it cosigned: it refuses a fork and a rollback'];
  const damageCase = 'damaged storage makes load throw, so a witness never starts empty over it';
  const make = () => new MemoryMeshWitnessStore();
  const names = (a: MeshWitnessStoreAdapter) => meshWitnessStoreCases(a).map((c) => c.name);

  it('no reopen and no damage hook: only the store-level and witness cases', () => {
    expect(names({ name: 'x', make })).toEqual(base);
  });

  it('a reopen hook adds exactly the two restart cases', () => {
    expect(names({ name: 'x', make, reopen: (p) => p })).toEqual([...base, ...reopenCases]);
  });

  it('a damage hook adds exactly the damage case', () => {
    expect(names({ name: 'x', make, damage: () => {} })).toEqual([...base, damageCase]);
  });
});

describe('the cases reject defective stores', () => {
  const memory = () => new MemoryMeshWitnessStore();

  it('a load that hands out its internal state', async () => {
    let held: State | undefined;
    const aliasing = (): Store => ({ load: () => held, save: (s) => void (held = JSON.parse(JSON.stringify(s))) });
    await expect(find({ name: 'x', make: aliasing }, 'load returns a copy').run()).rejects.toThrow();
  });

  it('a save that keeps the caller object', async () => {
    let held: State | undefined;
    const aliasing = (): Store => ({ load: () => (held === undefined ? undefined : JSON.parse(JSON.stringify(held))), save: (s) => void (held = s) });
    await expect(find({ name: 'x', make: aliasing }, 'save keeps its own copy').run()).rejects.toThrow();
  });

  it('a store whose later read is empty fails on the comparison, not with a type error', async () => {
    const make = (): Store => {
      const inner = memory();
      let n = 0;
      return { load: () => (++n === 3 ? undefined : inner.load()), save: (s) => inner.save(s) };
    };
    await expect(find({ name: 'x', make }, 'a witness persists every cosignature').run()).rejects.toBeInstanceOf(AssertionError);
  });

  it('a store that forgets on reopen fails on the comparison, not with a type error', async () => {
    await expect(find({ name: 'x', make: memory, reopen: () => memory() }, 'a restarted witness').run()).rejects.toBeInstanceOf(AssertionError);
  });

  it('a store that does not detect damage fails the load check first', async () => {
    await expect(find({ name: 'x', make: memory, damage: () => {} }, 'damaged storage').run()).rejects.toThrow('load must throw on damaged storage');
  });

  it('a store that fails once on damage still fails the witness check', async () => {
    const make = (): Store & { bad?: boolean } => {
      const inner = memory();
      const s: Store & { bad?: boolean } = {
        load: () => {
          if (s.bad) {
            s.bad = false;
            throw new Error('damaged');
          }
          return inner.load();
        },
        save: (st) => inner.save(st),
      };
      return s;
    };
    const damage = (s: Store) => void ((s as { bad?: boolean }).bad = true);
    await expect(find({ name: 'x', make, damage }, 'damaged storage').run()).rejects.toThrow('constructing a witness over damaged storage must throw');
  });

  it('a store that restores the remembered size but a root the issuer of a fork can extend lets the fork through', async () => {
    const fork2 = new MeshDomain('d', seedI('domain'));
    fork2.record(capI('x'));
    fork2.record(capI('y'));
    const forkRoot = fork2.publishHead([], 0).head.root;
    const reopen = (prev: Store): Store => ({
      load: () => {
        const s = prev.load();
        if (s === undefined) return s;
        return { seen: s.seen.map((e) => ({ ...e, head: { ...e.head, root: forkRoot } })) };
      },
      save: (s) => prev.save(s),
    });
    await expect(find({ name: 'x', make: memory, reopen }, 'a restarted witness').run()).rejects.toThrow('a fork that grew past the remembered size must be refused');
  });
});
