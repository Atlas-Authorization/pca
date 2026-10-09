import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createMemoryDurableKv, DurableStateError, openDurableState, type DurableState } from './durable-state';
import { signAllowlistManifest, verifyAllowlistDurable, type AllowlistIssuerKey } from './attest-allowlist';
import { createMemoryMaaKeyStateStore, durableMaaKeyStateStore, type MaaKeyState } from './attest-maa-keys';
import { generateKeyPair } from './keys';
import { b64u } from './hash';

const PKG = resolve(__dirname, '..');
const WORKER = join(__dirname, 'test-support', 'durable-worker.ts');
const dirs: string[] = [];
const tmp = (): string => {
  const d = mkdtempSync(join(tmpdir(), 'pca-durable-'));
  dirs.push(d);
  return d;
};
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const J = (d: string) => join(d, 'state.journal');
const H = (d: string) => join(d, 'state.head');
const lines = (d: string) => readFileSync(J(d), 'utf8').split('\n').filter((l) => l.length > 0);
const rejectsWith = async (p: Promise<unknown>, code: string) => {
  await expect(p).rejects.toBeInstanceOf(DurableStateError);
  await expect(p).rejects.toMatchObject({ code });
};
const KEY = new Uint8Array(32).fill(7);

function runWorker(dir: string, mode: string, id: number, n: number, crashAt?: string): Promise<{ code: number | null; signal: NodeJS.Signals | null; err: string }> {
  return new Promise((res) => {
    const c = spawn(process.execPath, ['--import', 'tsx', WORKER, dir, mode, String(id), String(n), ...(crashAt ? [crashAt] : [])], { cwd: PKG, env: { ...process.env, PATH: `/usr/local/bin:${process.env['PATH'] ?? ''}` } });
    let err = '';
    c.stderr.on('data', (b: Buffer) => (err += b.toString()));
    c.on('close', (code, signal) => res({ code, signal, err }));
  });
}

describe('durable-state: basics', () => {
  it('persists across reopen, update is read-modify-write, and the chain verifies', async () => {
    const d = tmp();
    const a = await openDurableState({ dir: d });
    await a.set('k', { a: 1 });
    expect(await a.update('k', (p) => ({ ...(p as object), b: 2 }))).toEqual({ a: 1, b: 2 });
    expect(await a.update('k', () => undefined)).toEqual({ a: 1, b: 2 }); // no-op keeps value
    const pos = await a.verify();
    const b = await openDurableState({ dir: d });
    expect(await b.get('k')).toEqual({ a: 1, b: 2 });
    expect(await b.keys()).toEqual(['k']);
    expect(b.position()).toEqual(pos);
    expect(lines(d)).toHaveLength(2); // the no-op did not write
    expect(JSON.parse(readFileSync(H(d), 'utf8')).seq).toBe(2);
  });

  it('creates the directory 0700 and files 0600; rejects bad keys / non-serialisable / oversize values', async () => {
    const d = join(tmp(), 'sub');
    const s = await openDurableState({ dir: d, maxValueBytes: 64 });
    await s.set('x', 1);
    const { statSync } = await import('node:fs');
    expect(statSync(d).mode & 0o777).toBe(0o700);
    expect(statSync(J(d)).mode & 0o777).toBe(0o600);
    await rejectsWith(s.set('', 1), 'invalid');
    await rejectsWith(s.set('a\nb', 1), 'invalid');
    await rejectsWith(s.set('x', undefined), 'invalid');
    await rejectsWith(s.set('x', 'y'.repeat(100)), 'too-large');
    await expect(openDurableState({ dir: tmp(), hmacKey: new Uint8Array(8) })).rejects.toMatchObject({ code: 'invalid' });
  });

  it('compacts into a checkpoint without losing state or breaking the chain', async () => {
    const d = tmp();
    const s = await openDurableState({ dir: d, compactEvery: 4 });
    for (let i = 1; i <= 11; i++) await s.set(`k${i % 3}`, i);
    expect(lines(d).length).toBeLessThanOrEqual(4);
    const re = await openDurableState({ dir: d, compactEvery: 4 });
    expect([await re.get('k0'), await re.get('k1'), await re.get('k2')]).toEqual([9, 10, 11]);
    expect(re.position().seq).toBe(11);
  });

  it('the in-memory implementation has the same update/get semantics', async () => {
    const m = createMemoryDurableKv();
    await m.set('a', { n: 1 });
    expect(await m.update('a', (p) => ({ n: (p as { n: number }).n + 1 }))).toEqual({ n: 2 });
    expect(await m.update('a', () => undefined)).toEqual({ n: 2 });
    expect(await m.get('zz')).toBeUndefined();
    expect(await m.keys()).toEqual(['a']);
    await expect(m.set('a', undefined)).rejects.toBeInstanceOf(DurableStateError);
  });
});

describe('durable-state: tamper, truncation, rollback, corruption (fail closed)', () => {
  async function seeded(opts: { hmacKey?: Uint8Array } = {}): Promise<{ d: string; s: DurableState }> {
    const d = tmp();
    const s = await openDurableState({ dir: d, ...opts });
    for (let i = 1; i <= 5; i++) await s.set('v', i);
    return { d, s };
  }

  it('an edited record is detected', async () => {
    const { d } = await seeded();
    const ls = lines(d);
    const o = JSON.parse(ls[2]!) as { payload: string };
    o.payload = 'v\n999';
    ls[2] = JSON.stringify(o);
    writeFileSync(J(d), `${ls.join('\n')}\n`);
    await rejectsWith(openDurableState({ dir: d }), 'corrupt');
  });

  it('a deleted / reordered middle record is detected', async () => {
    const { d } = await seeded();
    const ls = lines(d);
    writeFileSync(J(d), `${[ls[0], ls[2], ls[3], ls[4]].join('\n')}\n`);
    await rejectsWith(openDurableState({ dir: d }), 'corrupt');
    writeFileSync(J(d), `${[ls[0], ls[2], ls[1], ls[3], ls[4]].join('\n')}\n`);
    await rejectsWith(openDurableState({ dir: d }), 'corrupt');
  });

  it('tail truncation (whole records) is detected via the head file', async () => {
    const { d } = await seeded();
    const ls = lines(d);
    writeFileSync(J(d), `${ls.slice(0, 3).join('\n')}\n`);
    await rejectsWith(openDurableState({ dir: d }), 'rollback');
  });

  it('a torn / partial last line is detected', async () => {
    const { d } = await seeded();
    const text = readFileSync(J(d), 'utf8');
    writeFileSync(J(d), text.slice(0, text.length - 20));
    await rejectsWith(openDurableState({ dir: d }), 'corrupt');
  });

  it('replacing the journal with an OLDER valid copy is detected by the head, and deleting the journal while the head survives too', async () => {
    const { d } = await seeded();
    const old = readFileSync(J(d), 'utf8').split('\n').slice(0, 2).join('\n') + '\n';
    writeFileSync(J(d), old);
    await rejectsWith(openDurableState({ dir: d }), 'rollback');
    rmSync(J(d));
    await rejectsWith(openDurableState({ dir: d }), 'rollback');
  });

  it('a RUNNING handle notices the journal being swapped for an older (head-consistent) copy', async () => {
    const d = tmp();
    const s = await openDurableState({ dir: d });
    await s.set('v', 1);
    const snapJ = readFileSync(J(d));
    const snapH = readFileSync(H(d));
    await s.set('v', 2);
    await s.set('v', 3);
    // attacker restores BOTH files from the older snapshot: undetectable at open, but not by a handle that has seen seq 3
    writeFileSync(J(d), snapJ);
    writeFileSync(H(d), snapH);
    await rejectsWith(s.get('v'), 'rollback');
    // while a FRESH handle (no memory) cannot tell: this is the documented residual gap that the transparency anchor covers
    const fresh = await openDurableState({ dir: d });
    expect(await fresh.get('v')).toBe(1);
  });

  it('a state deleted while open is detected; a never-written directory is a clean first run', async () => {
    const d = tmp();
    const s = await openDurableState({ dir: d });
    expect(await s.keys()).toEqual([]);
    await s.set('v', 1);
    rmSync(J(d));
    rmSync(H(d));
    await rejectsWith(s.get('v'), 'rollback');
  });

  it('refuses to start on corrupt state; the explicit recovery flag quarantines (never deletes) and starts empty', async () => {
    const { d } = await seeded();
    writeFileSync(J(d), 'garbage\n');
    await rejectsWith(openDurableState({ dir: d }), 'corrupt');
    const r = await openDurableState({ dir: d, recoverFromCorruption: true });
    expect(r.recovered).toBe(true);
    expect(await r.get('v')).toBeUndefined();
    expect(readdirSync(d).some((f) => f.includes('.quarantine-'))).toBe(true);
    await r.set('v', 1);
    expect((await openDurableState({ dir: d })).recovered).toBe(false);
  });

  it('a corrupt head file fails closed', async () => {
    const { d } = await seeded();
    writeFileSync(H(d), '{not json');
    await rejectsWith(openDurableState({ dir: d }), 'corrupt');
    writeFileSync(H(d), JSON.stringify({ seq: 5, h: 'nothex' }));
    await rejectsWith(openDurableState({ dir: d }), 'corrupt');
  });
});

describe('durable-state: HMAC key', () => {
  it('round-trips with the key; a wrong / missing key and a forged re-chain are rejected', async () => {
    const d = tmp();
    const s = await openDurableState({ dir: d, hmacKey: KEY });
    await s.set('v', 1);
    await s.set('v', 2);
    expect(await (await openDurableState({ dir: d, hmacKey: KEY })).get('v')).toBe(2);
    await rejectsWith(openDurableState({ dir: d, hmacKey: new Uint8Array(32).fill(9) }), 'key-mismatch');
    await rejectsWith(openDurableState({ dir: d }), 'key-mismatch');
    // an attacker without the key rewrites the journal AND head with a self-consistent unkeyed chain
    const forged = tmp();
    const f = await openDurableState({ dir: forged });
    await f.set('v', 1);
    copyFileSync(J(forged), J(d));
    copyFileSync(H(forged), H(d));
    await rejectsWith(openDurableState({ dir: d, hmacKey: KEY }), 'key-mismatch');
  });

  it('the keyed head defeats restoring an older (journal, head) pair only when the head MAC no longer matches the key', async () => {
    const d = tmp();
    const s = await openDurableState({ dir: d, hmacKey: KEY });
    await s.set('v', 1);
    const j1 = readFileSync(J(d));
    const h1 = readFileSync(H(d));
    await s.set('v', 2);
    // truncating the journal alone is caught (head says seq 2)
    writeFileSync(J(d), j1);
    await rejectsWith(openDurableState({ dir: d, hmacKey: KEY }), 'rollback');
    // an attacker without the key cannot make a head for the old journal that has a valid MAC at a lower seq...
    writeFileSync(H(d), JSON.stringify({ seq: 1, h: JSON.parse(h1.toString()).h, mac: '00'.repeat(32) }));
    await rejectsWith(openDurableState({ dir: d, hmacKey: KEY }), 'key-mismatch');
  });
});

describe('durable-state: crash safety (real SIGKILL)', () => {
  it('killed between temp write and rename: old state intact, no torn file, stale lock from the dead pid is taken over', async () => {
    const d = tmp();
    const s = await openDurableState({ dir: d });
    await s.set('victim', { v: 1 });
    const r = await runWorker(d, 'crash', 1, 1, 'after-temp-write');
    expect(r.signal).toBe('SIGKILL');
    expect(readdirSync(d).some((f) => f.includes('.tmp-'))).toBe(true); // the orphan temp is left behind...
    expect(existsSync(join(d, 'state.lock'))).toBe(true); // ...and so is the dead owner's lock
    const re = await openDurableState({ dir: d, lockTimeoutMs: 15_000 });
    expect(await re.get('victim')).toEqual({ v: 1 });
    await re.verify();
    await re.set('victim', { v: 3 });
    expect(await (await openDurableState({ dir: d })).get('victim')).toEqual({ v: 3 });
  }, 60_000);

  it('killed after the journal rename but before the head: the new value is durable and the head is repaired', async () => {
    const d = tmp();
    const s = await openDurableState({ dir: d });
    await s.set('victim', { v: 1 });
    const r = await runWorker(d, 'crash', 1, 1, 'after-journal-rename');
    expect(r.signal).toBe('SIGKILL');
    expect(JSON.parse(readFileSync(H(d), 'utf8')).seq).toBe(1); // head lags by one
    const re = await openDurableState({ dir: d, lockTimeoutMs: 15_000 });
    expect(await re.get('victim')).toEqual({ v: 2 });
    expect(JSON.parse(readFileSync(H(d), 'utf8')).seq).toBe(2); // repaired
    expect(re.position().seq).toBe(2);
  }, 60_000);
});

describe('durable-state: REAL multi-process concurrency', () => {
  it('N racing writer processes: no lost update, high-water mark only rises, chain intact, observer never sees a decrease', async () => {
    const d = tmp();
    const parent = await openDurableState({ dir: d, compactEvery: 12 });
    const N = 4;
    const M = 12;
    const seenHwm: number[] = [];
    const seenCounter: number[] = [];
    let stop = false;
    const observer = (async () => {
      while (!stop) {
        const h = await parent.get('hwm');
        const c = await parent.get('counter');
        if (typeof h === 'number') seenHwm.push(h);
        if (typeof c === 'number') seenCounter.push(c);
        await new Promise((r) => setTimeout(r, 15));
      }
    })();
    const results = await Promise.all(Array.from({ length: N }, (_, i) => runWorker(d, 'race', i + 1, M)));
    stop = true;
    await observer;
    for (const r of results) {
      expect(r.err).toBe('');
      expect(r.code).toBe(0);
    }
    const fin = await openDurableState({ dir: d });
    expect(await fin.get('counter')).toBe(N * M); // exact: a lost update would make this smaller
    expect(await fin.get('hwm')).toBe(N * 1000 + M); // max over all writers' values
    expect(seenHwm.length).toBeGreaterThan(0);
    expect([...seenHwm]).toEqual([...seenHwm].sort((a, b) => a - b)); // monotone as observed
    expect([...seenCounter]).toEqual([...seenCounter].sort((a, b) => a - b));
    const pos = await fin.verify(); // full hash-chain + head check after N processes + compactions
    expect(pos.seq).toBeGreaterThanOrEqual(N * M); // counter writes + hwm writes, all sequenced
    expect(readdirSync(d).filter((f) => f.includes('.tmp-'))).toEqual([]);
    expect(existsSync(join(d, 'state.lock'))).toBe(false);
  }, 120_000);

  it('a second process cannot open while a live process holds the lock (times out) but proceeds once released', async () => {
    const d = tmp();
    await openDurableState({ dir: d });
    writeFileSync(join(d, 'state.lock'), JSON.stringify({ pid: process.pid, host: (await import('node:os')).hostname(), nonce: 'x', t: Date.now() }), { mode: 0o600 });
    await expect(openDurableState({ dir: d, lockTimeoutMs: 150 })).rejects.toMatchObject({ code: 'lock-timeout' });
    rmSync(join(d, 'state.lock'));
    await expect(openDurableState({ dir: d, lockTimeoutMs: 150 })).resolves.toBeDefined();
  });
});

describe('durable-state: wired into the allowlist and key-trust modules', () => {
  const ed = generateKeyPair();
  const keys: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(ed.publicKey) } } };
  const NOW = Date.parse('2026-10-09T00:00:00Z');
  const mk = (version: number, label = 'x') =>
    signAllowlistManifest(
      { version, issuedAt: NOW, notBefore: NOW - 1000, expiresAt: NOW + 10_000_000, entries: [{ kind: 'tdx-mrtd', value: 'ab'.repeat(48), label }] },
      { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: ed.secretKey } },
    );

  it('a durable high-water mark survives restart: an old manifest is a rollback after reopen (but only because the state survived)', async () => {
    const d = tmp();
    const kv1 = await openDurableState({ dir: d });
    expect(await verifyAllowlistDurable(mk(1), { issuerKeys: keys, nowMs: NOW }, kv1)).toMatchObject({ ok: true });
    expect((await verifyAllowlistDurable(mk(3), { issuerKeys: keys, nowMs: NOW }, kv1)).ok).toBe(true);
    const kv2 = await openDurableState({ dir: d }); // "restart"
    const old = await verifyAllowlistDurable(mk(2), { issuerKeys: keys, nowMs: NOW }, kv2);
    expect(old).toMatchObject({ ok: false, code: 'rollback' });
    expect((await verifyAllowlistDurable(mk(3), { issuerKeys: keys, nowMs: NOW }, kv2)).ok).toBe(true); // idempotent
    expect(await verifyAllowlistDurable(mk(3, 'other'), { issuerKeys: keys, nowMs: NOW }, kv2)).toMatchObject({ ok: false, code: 'conflict' });
    // deleting the state resets it - the documented gap the anchor closes
    rmSync(d, { recursive: true, force: true });
    const kv3 = await openDurableState({ dir: d });
    expect((await verifyAllowlistDurable(mk(2), { issuerKeys: keys, nowMs: NOW }, kv3)).ok).toBe(true);
  });

  it('a corrupt persisted high-water mark fails closed', async () => {
    const kv = createMemoryDurableKv();
    await kv.set('allowlist/ops', { version: 'nope' });
    expect(await verifyAllowlistDurable(mk(1), { issuerKeys: keys, nowMs: NOW }, kv)).toMatchObject({ ok: false, code: 'malformed' });
  });

  it('the MAA key state adapter is monotone in fetchedAtMs and shared across handles', async () => {
    const d = tmp();
    const issuer = 'https://sharedwus.wus.attest.azure.net';
    const st = (t: number): MaaKeyState => ({ v: 1, issuer, fetchedAtMs: t, anchors: [{ spki: 'ab'.repeat(32), kind: 'self-signed', notBeforeMs: 1, notAfterMs: 2, firstSeenMs: t }] });
    const a = durableMaaKeyStateStore(await openDurableState({ dir: d }));
    await a.set(issuer, st(100));
    await a.set(issuer, st(50)); // stale writer
    const b = durableMaaKeyStateStore(await openDurableState({ dir: d }));
    expect((await b.get(issuer))?.fetchedAtMs).toBe(100);
    await b.set(issuer, st(200));
    expect((await a.get(issuer))?.fetchedAtMs).toBe(200);
    expect(createMemoryMaaKeyStateStore).toBeDefined();
  });
});
