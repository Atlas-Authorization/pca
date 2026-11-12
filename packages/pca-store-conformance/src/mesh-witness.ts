/**
 * Conformance cases for a {@link MeshWitnessStore}: the durable memory of a mesh log witness.
 *
 * A witness cosigns a head only if it extends the last head THIS witness cosigned. A store that forgets across a
 * restart, or that loses a save and still lets the cosignature out, lets a domain walk the witness back and show two
 * verifiers different histories. The cases check the store by itself (round trip, replace, copy semantics, atomicity,
 * reopen) and through a real `MeshWitness` (every cosignature is persisted first; a restarted witness refuses rollback
 * and forks; a failed save refuses the cosignature and changes nothing; damaged storage is not read as empty).
 */
import { deepStrictEqual, notStrictEqual, ok, strictEqual } from 'node:assert';
import { encodeKey, mintRoot, publicKeyOf } from '@atlasauth/pca';
import { mesh } from '@atlasauth/pca/ext/research';

const { MeshDomain, MeshWitness } = mesh;
type MeshWitnessState = mesh.MeshWitnessState;
type MeshWitnessStore = mesh.MeshWitnessStore;

export interface MeshWitnessStoreAdapter {
  name: string;
  /** A fresh, empty store. */
  make(): MeshWitnessStore;
  /** A new store object over the same backing storage as `previous` (a restart). Omit for stores that cannot persist. */
  reopen?(previous: MeshWitnessStore): MeshWitnessStore;
  /** Damage the backing storage of `store` so that `load` must fail. Omit if the store cannot detect damage. */
  damage?(store: MeshWitnessStore): void;
}

export interface MeshWitnessStoreCase {
  name: string;
  run(): Promise<void>;
}

const seed = (label: string): Uint8Array => new Uint8Array(32).map((_, i) => (label.charCodeAt(i % label.length) + i) & 0xff);
const P = seed('principal');
const cap = (label: string) =>
  mintRoot({ principalSecret: P, principalPublic: encodeKey(publicKeyOf(P)), holder: encodeKey(publicKeyOf(seed('holder'))), caveats: [{ type: 'scope', actions: [label] }] });

function twoLogs() {
  // Same domain key, different history: the second is a fork of the first from entry 0 on.
  const honest = new MeshDomain('d', seed('domain'));
  const fork = new MeshDomain('d', seed('domain'));
  honest.record(cap('a'));
  fork.record(cap('x'));
  return { honest, fork };
}

export function meshWitnessStoreCases(a: MeshWitnessStoreAdapter): MeshWitnessStoreCase[] {
  const state = (n: number): MeshWitnessState => ({
    seen: [{ head: { domain: `d${n}`, size: 0, root: '', rev_root: 'r', rev_size: 0, timestamp: n }, rev_ids: [] }],
  });
  const cases: MeshWitnessStoreCase[] = [
    {
      name: 'a fresh store loads nothing',
      run: async () => strictEqual(a.make().load(), undefined),
    },
    {
      name: 'save then load returns the same state',
      run: async () => {
        const s = a.make();
        s.save(state(1));
        deepStrictEqual(s.load(), state(1));
      },
    },
    {
      name: 'a later save replaces the earlier one',
      run: async () => {
        const s = a.make();
        s.save(state(1));
        s.save(state(2));
        deepStrictEqual(s.load(), state(2));
      },
    },
    {
      name: 'load returns a copy: changing it does not change the store',
      run: async () => {
        const s = a.make();
        s.save(state(1));
        const got = s.load() as MeshWitnessState;
        got.seen.pop();
        deepStrictEqual(s.load(), state(1));
      },
    },
    {
      name: 'save keeps its own copy: changing the argument afterwards does not change the store',
      run: async () => {
        const s = a.make();
        const st = state(1);
        s.save(st);
        st.seen.length = 0;
        deepStrictEqual(s.load(), state(1));
      },
    },
    {
      name: 'a witness persists every cosignature before returning it',
      run: async () => {
        const s = a.make();
        const w = new MeshWitness(seed('w'), { store: s });
        const { honest } = twoLogs();
        const ch = honest.publishHead([w], 1_000);
        deepStrictEqual(s.load(), w.exportState());
        deepStrictEqual(s.load()?.seen.map((x) => x.head), [ch.head]);
      },
    },
    {
      name: 'a failed save refuses the cosignature and leaves the witness unchanged',
      run: async () => {
        const inner = a.make();
        let failing = false;
        const flaky: MeshWitnessStore = {
          load: () => inner.load(),
          save: (st) => {
            if (failing) throw new Error('disk full');
            inner.save(st);
          },
        };
        const w = new MeshWitness(seed('w'), { store: flaky });
        const { honest } = twoLogs();
        honest.publishHead([w], 1_000);
        const before = JSON.stringify(w.exportState());
        honest.record(cap('b'));
        failing = true;
        let threw = '';
        try {
          honest.publishHead([w], 2_000);
        } catch (e) {
          threw = (e as Error).message;
        }
        strictEqual(threw, 'witness: could not persist state; refusing to cosign');
        strictEqual(JSON.stringify(w.exportState()), before);
        deepStrictEqual(inner.load(), JSON.parse(before));
        failing = false;
        ok(honest.publishHead([w], 2_000).cosigs.length === 1, 'the same head is cosigned once the disk recovers');
      },
    },
  ];
  if (a.reopen) {
    const reopen = a.reopen;
    cases.push(
      {
        name: 'state survives reopening the store',
        run: async () => {
          const s = a.make();
          s.save(state(3));
          deepStrictEqual(reopen(s).load(), state(3));
        },
      },
      {
        name: 'a restarted witness remembers what it cosigned: it refuses a fork and a rollback',
        run: async () => {
          const s = a.make();
          const w1 = new MeshWitness(seed('w'), { store: s });
          const { honest, fork } = twoLogs();
          honest.publishHead([w1], 1_000);
          honest.record(cap('b'));
          honest.publishHead([w1], 2_000);
          const w2 = new MeshWitness(seed('w'), { store: reopen(s) });
          deepStrictEqual(w2.lastSeen(honest.id)?.size, 2);
          fork.record(cap('y'));
          fork.record(cap('z'));
          let forkErr = '';
          try {
            fork.publishHead([w2], 3_000);
          } catch (e) {
            forkErr = (e as Error).message;
          }
          notStrictEqual(forkErr, '', 'a fork that grew past the remembered size must be refused');
          const rollback = new MeshDomain('d', seed('domain'));
          rollback.record(cap('a'));
          let rbErr = '';
          try {
            rollback.publishHead([w2], 3_000);
          } catch (e) {
            rbErr = (e as Error).message;
          }
          notStrictEqual(rbErr, '', 'a rollback to the first head must be refused');
          ok(honest.publishHead([w2], 3_000).cosigs.length === 1, 'the honest log is still cosigned');
        },
      },
    );
  }
  if (a.damage) {
    const damage = a.damage;
    cases.push({
      name: 'damaged storage makes load throw, so a witness never starts empty over it',
      run: async () => {
        const s = a.make();
        s.save(state(4));
        damage(s);
        let threw = false;
        try {
          s.load();
        } catch {
          threw = true;
        }
        ok(threw, 'load must throw on damaged storage');
        let ctor = false;
        try {
          new MeshWitness(seed('w'), { store: s });
        } catch {
          ctor = true;
        }
        ok(ctor, 'constructing a witness over damaged storage must throw');
      },
    });
  }
  return cases;
}
