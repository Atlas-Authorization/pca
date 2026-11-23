import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { EncryptedConnectionStore, LocalKeyWrapper, type KeyWrapper } from './encrypted-store';
import { InMemoryConnectionStore, type ConnectionKey, type ConnectionStore, type StoredConnection } from './store';

const key32 = () => new Uint8Array(randomBytes(32));
const K: ConnectionKey = { agentId: 'ag', provider: 'google', connectionId: 'default' };
const conn = (over: Partial<StoredConnection> = {}): StoredConnection => ({
  ...K, accessToken: 'AT-1', refreshToken: 'RT-1', expiresAt: 5, scopes: ['read'],
  authority: { provider: 'google', principal: 'P', scopes: ['read'] }, createdAt: 1, useCount: 0, ...over,
});
const aad = new Uint8Array([1, 2, 3]);
const reason = async (p: Promise<unknown>): Promise<string> => { try { await p; return 'no error'; } catch (e) { return (e as Error).message; } };

/** Delegates to a real wrapper while keeping a handle on every data key and AAD the store hands over. */
class SpyWrapper implements KeyWrapper {
  readonly wrapped: Uint8Array[] = [];
  readonly unwrapped: Uint8Array[] = [];
  readonly aads: string[] = [];
  constructor(private readonly inner: LocalKeyWrapper) {}
  async wrap(dek: Uint8Array, a: Uint8Array) {
    this.wrapped.push(dek);
    this.aads.push(Buffer.from(a).toString());
    return this.inner.wrap(dek, a);
  }
  async unwrap(keyId: string, w: Uint8Array, a: Uint8Array) {
    const d = await this.inner.unwrap(keyId, w, a);
    this.unwrapped.push(d);
    return d;
  }
}

describe('LocalKeyWrapper', () => {
  it('unwrap refuses an unknown key id and a short ciphertext with distinct reasons', async () => {
    const w = new LocalKeyWrapper({ k1: key32() }, 'k1');
    expect(await reason(w.unwrap('nope', new Uint8Array(40), aad))).toBe('unknown key id');
    expect(await reason(w.unwrap('k1', new Uint8Array(27), aad))).toBe('short ciphertext');
    expect(await reason(w.unwrap('k1', new Uint8Array(5), aad))).toBe('short ciphertext');
  });

  it('a sealed empty value (exactly iv + tag) still opens', async () => {
    const w = new LocalKeyWrapper({ k1: key32() }, 'k1');
    const { keyId, wrapped } = await w.wrap(new Uint8Array(0), aad);
    expect(wrapped.length).toBe(28);
    expect((await w.unwrap(keyId, wrapped, aad)).length).toBe(0);
  });

  it('wrap after destroy says there is no active key', async () => {
    const w = new LocalKeyWrapper({ k1: key32() }, 'k1');
    w.destroy();
    expect(await reason(w.wrap(new Uint8Array(32), aad))).toBe('no active key');
  });

  it('setActive refuses an id that is not in the ring and keeps the old one', async () => {
    const w = new LocalKeyWrapper({ k1: key32() }, 'k1');
    expect(() => w.setActive('missing')).toThrow('LocalKeyWrapper: the active key id is not in the key ring');
    expect((await w.wrap(new Uint8Array(32), aad)).keyId).toBe('k1');
  });

  it('removeKey forgets the key, zeroes its bytes, and tolerates an unknown id', async () => {
    const w = new LocalKeyWrapper({ k1: key32(), k2: key32() }, 'k1');
    const ring = Reflect.get(w, 'keys') as Map<string, Uint8Array>;
    const k2 = ring.get('k2')!;
    expect(k2.some((b) => b !== 0)).toBe(true);
    w.setActive('k2');
    const { keyId, wrapped } = await w.wrap(new Uint8Array(32), aad);
    w.setActive('k1');
    w.removeKey('k2');
    expect(k2.every((b) => b === 0)).toBe(true);
    expect(ring.has('k2')).toBe(false);
    expect(await reason(w.unwrap(keyId, wrapped, aad))).toBe('unknown key id');
    expect(() => w.removeKey('never-existed')).not.toThrow();
  });

  it('destroy zeroes every key and empties the ring', () => {
    const w = new LocalKeyWrapper({ k1: key32(), k2: key32() }, 'k1');
    const ring = Reflect.get(w, 'keys') as Map<string, Uint8Array>;
    const all = [...ring.values()];
    w.destroy();
    for (const k of all) expect(k.every((b) => b === 0)).toBe(true);
    expect(ring.size).toBe(0);
  });
});

describe('EncryptedConnectionStore', () => {
  const mk = () => {
    const inner = new InMemoryConnectionStore();
    const spy = new SpyWrapper(new LocalKeyWrapper({ k1: key32() }, 'k1'));
    return { inner, spy, store: new EncryptedConnectionStore(inner, spy) };
  };

  it('binds each wrapped key to a length-prefixed, field-specific context', async () => {
    const { spy, store } = mk();
    await store.set(conn());
    expect(spy.aads).toEqual(['14:pca-connect/v1|6:access|2:ag|6:google|7:default', '14:pca-connect/v1|7:refresh|2:ag|6:google|7:default']);
  });

  it('zeroes the data keys it generates and the ones it unwraps', async () => {
    const { spy, store } = mk();
    await store.set(conn());
    expect(spy.wrapped).toHaveLength(2);
    for (const d of spy.wrapped) expect(d.every((b) => b === 0)).toBe(true);
    expect((await store.get(K))?.accessToken).toBe('AT-1');
    expect(spy.unwrapped).toHaveLength(2);
    for (const d of spy.unwrapped) expect(d.every((b) => b === 0)).toBe(true);
  });

  it('round-trips a record that has no refresh token, and stores none', async () => {
    const { inner, store } = mk();
    await store.set(conn({ refreshToken: undefined }));
    expect(Object.keys((await inner.get(K))!)).not.toContain('refreshToken');
    const got = await store.get(K);
    expect(got?.accessToken).toBe('AT-1');
    expect(Object.keys(got!)).not.toContain('refreshToken');
  });

  it('round-trips non-ASCII tokens and key ids', async () => {
    const inner = new InMemoryConnectionStore();
    const store = new EncryptedConnectionStore(inner, new LocalKeyWrapper({ 'clé-ключ': key32() }, 'clé-ключ'));
    await store.set(conn({ accessToken: 'tökén-日本', refreshToken: 'rëfresh-🔑' }));
    const sealed = await inner.get(K);
    expect(sealed?.accessToken.split('.')[1]).toBe(Buffer.from('clé-ключ', 'utf8').toString('base64url'));
    const got = await store.get(K);
    expect(got?.accessToken).toBe('tökén-日本');
    expect(got?.refreshToken).toBe('rëfresh-🔑');
  });

  it('refuses an envelope with a character outside the base64url alphabet, even if it would decode', async () => {
    for (const idx of [2, 3]) {
      const { inner, store } = mk();
      await store.set(conn());
      const sealed = (await inner.get(K))!;
      const parts = sealed.accessToken.split('.');
      parts[idx] = `${parts[idx]}=`;
      await inner.set({ ...sealed, accessToken: parts.join('.') });
      await expect(store.get(K)).rejects.toMatchObject({ code: 'store_error', message: 'a stored token could not be decrypted' });
    }
  });

  it('refuses a malformed envelope shape', async () => {
    for (const bad of ['plain', 'pca1.a.b', 'pca1.a.b.c.d', 'pca2.a.b.c']) {
      const { inner, store } = mk();
      await store.set(conn());
      const sealed = (await inner.get(K))!;
      await inner.set({ ...sealed, accessToken: bad });
      await expect(store.get(K)).rejects.toMatchObject({ code: 'store_error' });
    }
    // right shape and prefix, but the parts are not an envelope this store sealed
    const { inner, store } = mk();
    await store.set(conn());
    const sealed = (await inner.get(K))!;
    const parts = sealed.accessToken.split('.');
    await inner.set({ ...sealed, accessToken: ['pca1', parts[1], parts[2], parts[3]].join('.') });
    expect((await store.get(K))?.accessToken).toBe('AT-1');
    await inner.set({ ...sealed, accessToken: ['xxxx', parts[1], parts[2], parts[3]].join('.') });
    await expect(store.get(K)).rejects.toMatchObject({ code: 'store_error' });
    await inner.set({ ...sealed, accessToken: ['pca1', parts[1], parts[2]].join('.') });
    await expect(store.get(K)).rejects.toMatchObject({ code: 'store_error' });
    await inner.set({ ...sealed, accessToken: `${sealed.accessToken}.extra` });
    await expect(store.get(K)).rejects.toMatchObject({ code: 'store_error' });
  });

  it('refuses a record the inner store returns for a different key, on each key component', async () => {
    const w = new LocalKeyWrapper({ k1: key32() }, 'k1');
    const written = new InMemoryConnectionStore();
    const store = new EncryptedConnectionStore(written, w);
    await store.set(conn());
    const raw = (await written.get(K))!;
    const lying: ConnectionStore = { get: async () => raw, set: async () => {}, delete: async () => {} };
    const asked = new EncryptedConnectionStore(lying, w);
    expect((await asked.get(K))?.accessToken).toBe('AT-1');
    for (const other of [{ ...K, agentId: 'other' }, { ...K, provider: 'slack' }, { ...K, connectionId: 'other' }]) {
      await expect(asked.get(other)).rejects.toMatchObject({ code: 'store_error', message: 'a stored token could not be decrypted' });
    }
  });

  it('delete removes the record from the inner store', async () => {
    const { inner, store } = mk();
    await store.set(conn());
    await store.delete(K);
    expect(await inner.get(K)).toBeUndefined();
  });
});
