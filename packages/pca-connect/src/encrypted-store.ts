import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { StoreError } from './errors';
import { type ConnectionKey, type ConnectionStore, type StoredConnection, cloneConnection } from './store';

/**
 * Envelope encryption for stored OAuth tokens. Every secret gets its own random data key (DEK); the DEK is
 * wrapped by a {@link KeyWrapper}: a local key ring ({@link LocalKeyWrapper}) or your KMS (AWS KMS, GCP KMS,
 * Vault transit) behind the same two methods. `aad` binds the wrapped key to the exact connection and field,
 * so a ciphertext copied to another connection or field fails to open.
 */
export interface KeyWrapper {
  wrap(dek: Uint8Array, aad: Uint8Array): Promise<{ keyId: string; wrapped: Uint8Array }>;
  unwrap(keyId: string, wrapped: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
}

const ALG = 'aes-256-gcm';
const PREFIX = 'pca1';
const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
const unb64u = (s: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('bad encoding');
  return new Uint8Array(Buffer.from(s, 'base64url'));
};

function seal(key: Uint8Array, aad: Uint8Array, plain: Uint8Array): Uint8Array {
  const iv = randomBytes(12);
  const c = createCipheriv(ALG, key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return new Uint8Array(Buffer.concat([iv, ct, c.getAuthTag()]));
}

function open(key: Uint8Array, aad: Uint8Array, sealed: Uint8Array): Uint8Array {
  if (sealed.length < 12 + 16) throw new Error('short ciphertext');
  const d = createDecipheriv(ALG, key, sealed.subarray(0, 12));
  d.setAAD(aad);
  d.setAuthTag(sealed.subarray(sealed.length - 16));
  return new Uint8Array(Buffer.concat([d.update(sealed.subarray(12, sealed.length - 16)), d.final()]));
}

/**
 * A key ring held in process memory. Rotation: add the new key under a new id and make it `activeId`;
 * records written under old ids still open until you remove the old key. For production keys, implement
 * {@link KeyWrapper} over a KMS instead. {@link destroy} overwrites the key bytes.
 */
export class LocalKeyWrapper implements KeyWrapper {
  private keys = new Map<string, Uint8Array>();
  private active: string;

  constructor(keys: Record<string, Uint8Array>, activeId: string) {
    for (const [id, k] of Object.entries(keys)) this.addKey(id, k);
    if (!this.keys.has(activeId)) throw new Error('LocalKeyWrapper: the active key id is not in the key ring');
    this.active = activeId;
  }

  addKey(id: string, key: Uint8Array): void {
    if (id.length === 0) throw new Error('LocalKeyWrapper: key id must not be empty');
    if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('LocalKeyWrapper: keys must be 32 bytes');
    this.keys.set(id, new Uint8Array(key));
  }

  setActive(id: string): void {
    if (!this.keys.has(id)) throw new Error('LocalKeyWrapper: the active key id is not in the key ring');
    this.active = id;
  }

  removeKey(id: string): void {
    if (id === this.active) throw new Error('LocalKeyWrapper: cannot remove the active key');
    this.keys.get(id)?.fill(0);
    this.keys.delete(id);
  }

  destroy(): void {
    for (const k of this.keys.values()) k.fill(0);
    this.keys.clear();
  }

  async wrap(dek: Uint8Array, aad: Uint8Array): Promise<{ keyId: string; wrapped: Uint8Array }> {
    const k = this.keys.get(this.active);
    if (!k) throw new Error('no active key');
    return { keyId: this.active, wrapped: seal(k, aad, dek) };
  }

  async unwrap(keyId: string, wrapped: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    const k = this.keys.get(keyId);
    if (!k) throw new Error('unknown key id');
    return open(k, aad, wrapped);
  }
}

function aadFor(key: ConnectionKey, field: string): Uint8Array {
  const parts = ['pca-connect/v1', field, key.agentId, key.provider, key.connectionId];
  return new Uint8Array(Buffer.from(parts.map((p) => `${Buffer.byteLength(p)}:${p}`).join('|')));
}

async function encryptField(w: KeyWrapper, key: ConnectionKey, field: string, plain: string): Promise<string> {
  const aad = aadFor(key, field);
  const dek = new Uint8Array(randomBytes(32));
  try {
    const { keyId, wrapped } = await w.wrap(dek, aad);
    const sealed = seal(dek, aad, new Uint8Array(Buffer.from(plain, 'utf8')));
    return [PREFIX, b64u(new Uint8Array(Buffer.from(keyId, 'utf8'))), b64u(wrapped), b64u(sealed)].join('.');
  } finally {
    dek.fill(0);
  }
}

async function decryptField(w: KeyWrapper, key: ConnectionKey, field: string, value: string): Promise<string> {
  const parts = value.split('.');
  if (parts.length !== 4 || parts[0] !== PREFIX) throw new Error('not an envelope');
  const [, kid, wrapped, sealed] = parts as [string, string, string, string];
  const aad = aadFor(key, field);
  const dek = await w.unwrap(Buffer.from(unb64u(kid)).toString('utf8'), unb64u(wrapped), aad);
  try {
    return Buffer.from(open(dek, aad, unb64u(sealed))).toString('utf8');
  } finally {
    dek.fill(0);
  }
}

/**
 * Wraps any {@link ConnectionStore} so `accessToken` and `refreshToken` are encrypted before they reach it.
 * Everything else in a record (agent, provider, scopes, expiry, authority) stays readable so the inner store
 * can index and expire it. Fails closed: a stored token that is not an envelope (a plaintext record, a
 * downgrade), fails authentication, or was sealed under an unknown key makes `get` throw a {@link StoreError}.
 * The error carries no detail from the failure.
 */
export class EncryptedConnectionStore implements ConnectionStore {
  /** Marks the store as encrypting; `TokenVault` requires it in `strict` mode. */
  readonly encrypted = true as const;

  constructor(
    private readonly inner: ConnectionStore,
    private readonly wrapper: KeyWrapper,
  ) {}

  async get(key: ConnectionKey): Promise<StoredConnection | undefined> {
    const raw = await this.inner.get(key);
    if (raw === undefined) return undefined;
    try {
      const out = cloneConnection(raw);
      const k: ConnectionKey = { agentId: raw.agentId, provider: raw.provider, connectionId: raw.connectionId };
      if (k.agentId !== key.agentId || k.provider !== key.provider || k.connectionId !== key.connectionId) throw new Error('record key mismatch');
      out.accessToken = await decryptField(this.wrapper, k, 'access', raw.accessToken);
      if (raw.refreshToken !== undefined) out.refreshToken = await decryptField(this.wrapper, k, 'refresh', raw.refreshToken);
      return out;
    } catch {
      throw new StoreError('a stored token could not be decrypted');
    }
  }

  async set(connection: StoredConnection): Promise<void> {
    const k: ConnectionKey = { agentId: connection.agentId, provider: connection.provider, connectionId: connection.connectionId };
    const sealed = cloneConnection(connection);
    try {
      sealed.accessToken = await encryptField(this.wrapper, k, 'access', connection.accessToken);
      if (connection.refreshToken !== undefined) sealed.refreshToken = await encryptField(this.wrapper, k, 'refresh', connection.refreshToken);
    } catch {
      throw new StoreError('a token could not be encrypted; nothing was stored');
    }
    await this.inner.set(sealed);
  }

  delete(key: ConnectionKey): Promise<void> {
    return this.inner.delete(key);
  }

  /** Re-encrypt one record under the wrapper's active key (run after rotating the key ring). */
  async reencrypt(key: ConnectionKey): Promise<boolean> {
    const c = await this.get(key);
    if (c === undefined) return false;
    await this.set(c);
    return true;
  }
}
