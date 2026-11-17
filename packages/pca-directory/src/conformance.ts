/**
 * Conformance for directory stores. A store holds what the log's integrity rests on: an append that is a compare-and-set on the
 * index (so two writers can never fork the log), lookups by subject / passport digest / revoked digest, one cosignature per witness
 * per head, key transitions, and durability. Each check is one such claim, driven against YOUR store through a `DirectoryStoreAdapter`.
 */
import { b64u, sha256, utf8 } from '@atlasauth/pca';
import type { WitnessCosignature } from '@atlasauth/pca/ext/ledger';
import { DIRECTORY_ENTRY_TYP, DIRECTORY_VERSION, entryCommit, type DirectoryEntry } from './entry';
import type { DirectoryStore, StoredEntry } from './log';
import type { SignedKeyTransition } from './rotation';

export interface DirectoryStoreHandle {
  store: DirectoryStore;
  /** Another client on the SAME backend (the first stays usable). */
  reopen(): Promise<DirectoryStore>;
  close?(): Promise<void>;
}
export interface DirectoryStoreAdapter {
  name: string;
  /** Default true. Declare false ONLY for an in-process store; the durability check is then skipped and reported. */
  durable?: boolean;
  /** Must return a store that shares no state with any earlier one (a fresh instance, schema or database). */
  create(): Promise<DirectoryStoreHandle>;
}
export interface DirectoryStoreCheck {
  name: string;
  claim: string;
  needs?: 'durable';
  run(h: DirectoryStoreHandle): Promise<void>;
}
export interface DirectoryStoreCheckResult {
  name: string;
  claim: string;
  status: 'pass' | 'fail' | 'skipped';
  error?: string;
}

const ok = (cond: unknown, msg: string): void => {
  if (!cond) throw new Error(msg);
};
const h = (s: string): string => b64u(sha256(utf8(s)));
const SUBJECT = h('subject');

function row(index: number, o: Partial<DirectoryEntry> & { subject?: string } = {}): StoredEntry {
  const entry: DirectoryEntry = {
    typ: DIRECTORY_ENTRY_TYP,
    ver: DIRECTORY_VERSION,
    log: 'conformance',
    kind: 'register',
    mode: 'public',
    subject: SUBJECT,
    issuer: h('issuer'),
    digest: h(`digest-${index}`),
    exp: 1_900_000_000_000,
    iat: 1_800_000_000_000 + index,
    ...o,
  };
  const clean = JSON.parse(JSON.stringify(entry)) as DirectoryEntry; // no explicit `undefined` members
  return { index, commit: entryCommit(clean), entry: clean, submitter: 'conformance' };
}

const cosig = (key: string, sig = 's'): WitnessCosignature => ({ key, sig });

const transition = (seq: number): SignedKeyTransition => ({
  typ: 'atlas-pca/directory-key-transition',
  ver: 1,
  log: 'conformance',
  instance_id: 'i',
  principal: 'p',
  seq,
  from: h(`k${seq - 1}`),
  to: h(`k${seq}`),
  at_size: seq,
  at_root: h(`root${seq}`),
  iat: 1,
  sig_old: 'a',
  sig_new: 'b',
});

export const DIRECTORY_STORE_CHECKS: DirectoryStoreCheck[] = [
  {
    name: 'append-is-a-compare-and-set-on-the-index',
    claim: 'An append succeeds only at the next free index; an occupied or skipped index writes nothing.',
    async run({ store }) {
      ok((await store.size()) === 0, 'a new store is empty');
      ok((await store.append(row(0))) === true, 'index 0 appends');
      ok((await store.append(row(0, { digest: h('other') }))) === false, 'index 0 cannot be taken twice');
      ok((await store.append(row(2))) === false, 'index 2 cannot be taken before 1');
      ok((await store.append(row(1))) === true, 'index 1 appends');
      ok((await store.size()) === 2, 'size counts what was written');
      ok((await store.get(0))?.entry.digest === h('digest-0'), 'the first writer kept index 0');
    },
  },
  {
    name: 'racing-appends-have-one-winner',
    claim: 'Of many writers appending at one index, exactly one wins, so the log cannot fork.',
    async run({ store, reopen }) {
      const other = await reopen();
      const results = await Promise.all(Array.from({ length: 8 }, (_, i) => (i % 2 ? store : other).append(row(0, { digest: h(`racer-${i}`) }))));
      ok(results.filter(Boolean).length === 1, `exactly one of 8 racing appends wins, got ${results.filter(Boolean).length}`);
      ok((await store.size()) === 1, 'one row');
    },
  },
  {
    name: 'reads-return-what-was-written-in-order',
    claim: 'commits, get and range return the stored rows in index order, including the body and entry JSON unchanged.',
    async run({ store }) {
      for (let i = 0; i < 5; i++) ok(await store.append(row(i)), `append ${i}`);
      const commits = await store.commits();
      ok(commits.length === 5 && commits.every((c, i) => c === row(i).commit), 'commits in order');
      const r = await store.range(1, 3);
      ok(r.map((x) => x.index).join() === '1,2,3', 'range is [from, from+limit)');
      ok(JSON.stringify((await store.get(4))?.entry) === JSON.stringify(row(4).entry), 'the entry round-trips');
      ok((await store.get(9)) === undefined, 'a missing index is undefined');
      const withBody = { ...row(5), body: { typ: 'x', note: 'body' } as unknown as StoredEntry['body'] };
      ok(await store.append(withBody), 'append with a body');
      ok(JSON.stringify((await store.get(5))?.body) === JSON.stringify(withBody.body), 'the body round-trips');
      ok((await store.get(4))?.body === undefined, 'a hashed row has no body');
    },
  },
  {
    name: 'lookups-by-subject-digest-and-revoked',
    claim: 'bySubject lists a subject oldest first; byDigest finds register/update rows only; byRevoked finds the revoke row of a digest.',
    async run({ store }) {
      const a = h('subject-a');
      ok(await store.append(row(0, { subject: a, digest: 'D0' })), 'append');
      ok(await store.append(row(1, { subject: SUBJECT, digest: 'D1' })), 'append');
      ok(await store.append(row(2, { subject: a, kind: 'update', digest: 'D2' })), 'append');
      ok(await store.append(row(3, { subject: a, kind: 'revoke', digest: 'R3', revokes: 'D0', exp: undefined })), 'append');
      ok((await store.bySubject(a, 10)).map((x) => x.index).join() === '0,2,3', 'bySubject oldest first, only that subject');
      ok((await store.bySubject(a, 2)).length === 2, 'bySubject honours the limit');
      ok((await store.byDigest('D2'))?.index === 2, 'byDigest finds an update');
      ok((await store.byDigest('R3')) === undefined, 'byDigest never returns a revoke row');
      ok((await store.byRevoked('D0'))?.index === 3, 'byRevoked finds the revoke of D0');
      ok((await store.byRevoked('D1')) === undefined, 'a digest nobody revoked');
    },
  },
  {
    name: 'one-row-per-passport-digest-and-per-revoked-digest',
    claim: 'The same passport digest cannot be stored twice, nor the same digest revoked twice (the index decides, not the caller).',
    async run({ store }) {
      ok(await store.append(row(0, { digest: 'SAME' })), 'first');
      ok(!(await store.append(row(1, { digest: 'SAME' }))), 'a second row for one passport digest is refused');
      ok(await store.append(row(1, { kind: 'revoke', digest: 'R1', revokes: 'SAME', exp: undefined })), 'a revoke');
      ok(!(await store.append(row(2, { kind: 'revoke', digest: 'R2', revokes: 'SAME', exp: undefined }))), 'a second revoke of one digest is refused');
      ok((await store.size()) === 2, 'only the two valid rows exist');
    },
  },
  {
    name: 'one-cosignature-per-witness-per-head',
    claim: 'A re-submitted cosignature replaces the old one; heads group by (size, root) and list newest size first.',
    async run({ store }) {
      await store.addCosignature(3, 'R3', cosig('w1', 'first'));
      await store.addCosignature(3, 'R3', cosig('w2'));
      await store.addCosignature(3, 'R3', cosig('w1', 'second'));
      await store.addCosignature(5, 'R5', cosig('w1'));
      await store.addCosignature(3, 'OTHER', cosig('w3'));
      const heads = await store.cosignedHeads(10);
      ok(heads[0]?.size === 5, 'newest size first');
      const three = heads.find((x) => x.size === 3 && x.root === 'R3')!;
      ok(three.cosigs.length === 2, 'one cosignature per witness');
      ok(three.cosigs.find((c) => c.key === 'w1')?.sig === 'second', 'the re-submission replaced the first');
      ok(heads.find((x) => x.root === 'OTHER')?.cosigs.length === 1, 'a different root is a different head');
    },
  },
  {
    name: 'key-transitions-in-order-without-duplicates',
    claim: 'Transitions are returned oldest first and a sequence number is stored once.',
    async run({ store }) {
      await store.addTransition(transition(2));
      await store.addTransition(transition(1));
      await store.addTransition(transition(1));
      const t = await store.transitions();
      ok(t.map((x) => x.seq).join() === '1,2', `transitions oldest first, once each; got ${t.map((x) => x.seq).join()}`);
    },
  },
  {
    name: 'acknowledged-writes-survive-reopen',
    claim: 'What an append, a cosignature and a transition acknowledged is visible to a new client on the same backend.',
    needs: 'durable',
    async run({ store, reopen }) {
      ok(await store.append(row(0)), 'append');
      await store.addCosignature(1, 'R', cosig('w'));
      await store.addTransition(transition(1));
      const again = await reopen();
      ok((await again.size()) === 1 && (await again.get(0))?.commit === row(0).commit, 'the row is there');
      ok((await again.cosignedHeads(5)).length === 1, 'the cosignature is there');
      ok((await again.transitions()).length === 1, 'the transition is there');
    },
  },
];

export async function runDirectoryStoreConformance(adapter: DirectoryStoreAdapter): Promise<DirectoryStoreCheckResult[]> {
  const out: DirectoryStoreCheckResult[] = [];
  for (const c of DIRECTORY_STORE_CHECKS) {
    if (c.needs === 'durable' && adapter.durable === false) {
      out.push({ name: c.name, claim: c.claim, status: 'skipped' });
      continue;
    }
    let handle: DirectoryStoreHandle | undefined;
    try {
      handle = await adapter.create();
      await c.run(handle);
      out.push({ name: c.name, claim: c.claim, status: 'pass' });
    } catch (e) {
      out.push({ name: c.name, claim: c.claim, status: 'fail', error: e instanceof Error ? e.message : String(e) });
    } finally {
      await handle?.close?.().catch(() => undefined);
    }
  }
  return out;
}
