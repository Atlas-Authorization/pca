import { describe, expect, it } from 'vitest';
import { InMemoryConnectionStore, cloneConnection, type StoredConnection } from './store';

const conn = (over: Partial<StoredConnection> = {}): StoredConnection => ({
  agentId: 'ag', provider: 'google', connectionId: 'default', accessToken: 'AT', expiresAt: 5, scopes: ['read'],
  authority: { provider: 'google', principal: 'P', scopes: ['read'] }, createdAt: 1, useCount: 0, ...over,
});

describe('InMemoryConnectionStore', () => {
  it('keys on agent, provider and connection id separately', async () => {
    const s = new InMemoryConnectionStore();
    await s.set(conn());
    expect((await s.get({ agentId: 'ag', provider: 'google', connectionId: 'default' }))?.accessToken).toBe('AT');
    expect(await s.get({ agentId: 'ag2', provider: 'google', connectionId: 'default' })).toBeUndefined();
    expect(await s.get({ agentId: 'ag', provider: 'slack', connectionId: 'default' })).toBeUndefined();
    expect(await s.get({ agentId: 'ag', provider: 'google', connectionId: 'other' })).toBeUndefined();
  });

  it('cannot be confused by keys that concatenate to the same text', async () => {
    const s = new InMemoryConnectionStore();
    await s.set(conn({ agentId: 'a', provider: 'bc', connectionId: 'd', accessToken: 'ONE' }));
    expect(await s.get({ agentId: 'ab', provider: 'c', connectionId: 'd' })).toBeUndefined();
    expect(await s.get({ agentId: 'a', provider: 'b', connectionId: 'cd' })).toBeUndefined();
  });

  it('delete removes exactly that record', async () => {
    const s = new InMemoryConnectionStore();
    await s.set(conn());
    await s.set(conn({ connectionId: 'keep' }));
    await s.delete({ agentId: 'ag', provider: 'google', connectionId: 'default' });
    expect(await s.get({ agentId: 'ag', provider: 'google', connectionId: 'default' })).toBeUndefined();
    expect(await s.get({ agentId: 'ag', provider: 'google', connectionId: 'keep' })).toBeDefined();
  });

  it('stores and returns copies', async () => {
    const s = new InMemoryConnectionStore();
    const c = conn();
    await s.set(c);
    c.scopes.push('mutated');
    const got = await s.get({ agentId: 'ag', provider: 'google', connectionId: 'default' });
    expect(got?.scopes).toEqual(['read']);
    got?.scopes.push('x');
    expect((await s.get({ agentId: 'ag', provider: 'google', connectionId: 'default' }))?.scopes).toEqual(['read']);
  });
});

describe('cloneConnection', () => {
  it('copies optional fields only when present', () => {
    const bare = cloneConnection(conn());
    expect(Object.keys(bare).sort()).toEqual(['accessToken', 'agentId', 'authority', 'connectionId', 'createdAt', 'expiresAt', 'provider', 'scopes', 'useCount']);
    expect(Object.keys(bare.authority).sort()).toEqual(['principal', 'provider', 'scopes']);
    const full = cloneConnection(conn({ refreshToken: 'RT', lastUsedAt: 9, authority: { provider: 'google', principal: 'P', scopes: ['read'], audience: 'rs' } }));
    expect(full.refreshToken).toBe('RT');
    expect(full.lastUsedAt).toBe(9);
    expect(full.authority).toEqual({ provider: 'google', principal: 'P', scopes: ['read'], audience: 'rs' });
  });
});
