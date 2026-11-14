import { describe, expect, it } from 'vitest';
import {
  BearerReleaseDisabledError,
  ExpiredNoRefreshError,
  NotAuthorizedError,
  ProxyFailedError,
  RefreshFailedError,
  RequestMismatchError,
  ScopeExceededError,
  StoreError,
  UnconfirmedActionError,
  UnknownActionError,
  UnknownConnectionError,
  VaultError,
} from './errors';

describe('typed refusals carry exact names, codes and messages', () => {
  it('VaultError', () => {
    const e = new VaultError('store_error', 'm');
    expect(e.name).toBe('VaultError');
    expect(e.code).toBe('store_error');
    expect(e.message).toBe('m');
    expect(e).toBeInstanceOf(Error);
  });

  it('NotAuthorizedError', () => {
    const e = new NotAuthorizedError('nope');
    expect(e.name).toBe('NotAuthorizedError');
    expect(e.code).toBe('not_authorized');
    expect(e.message).toBe('nope');
    const withChecks = new NotAuthorizedError('x', { sig: 'pass' } as never);
    expect(withChecks.checks).toEqual({ sig: 'pass' });
  });

  it('ScopeExceededError', () => {
    const e = new ScopeExceededError('google', ['a', 'b', 'c'], ['a'], ['b', 'c']);
    expect(e.name).toBe('ScopeExceededError');
    expect(e.code).toBe('scope_exceeded');
    expect(e.message).toBe("requested scopes exceed the capability's grant for 'google': not granted [b, c]");
    expect(e.provider).toBe('google');
    expect(e.requested).toEqual(['a', 'b', 'c']);
    expect(e.granted).toEqual(['a']);
    expect(e.missing).toEqual(['b', 'c']);
  });

  it('ExpiredNoRefreshError', () => {
    const e = new ExpiredNoRefreshError('google', 'work');
    expect(e.name).toBe('ExpiredNoRefreshError');
    expect(e.code).toBe('expired_no_refresh');
    expect(e.message).toBe("connection 'google/work' token is expired and has no refresh token");
    expect(e.provider).toBe('google');
    expect(e.connectionId).toBe('work');
  });

  it('RefreshFailedError', () => {
    const e = new RefreshFailedError('google', 'boom', 503);
    expect(e.name).toBe('RefreshFailedError');
    expect(e.code).toBe('refresh_failed');
    expect(e.message).toBe("refresh for 'google' failed: boom");
    expect(e.provider).toBe('google');
    expect(e.status).toBe(503);
    expect(new RefreshFailedError('google', 'boom').status).toBeUndefined();
  });

  it('UnknownConnectionError', () => {
    const e = new UnknownConnectionError('agent1', 'google', 'work');
    expect(e.name).toBe('UnknownConnectionError');
    expect(e.code).toBe('unknown_connection');
    expect(e.message).toBe("no connection for agent 'agent1' provider 'google' id 'work'");
    expect(e.agentId).toBe('agent1');
    expect(e.provider).toBe('google');
    expect(e.connectionId).toBe('work');
  });

  it('StoreError', () => {
    const e = new StoreError();
    expect(e.name).toBe('StoreError');
    expect(e.code).toBe('store_error');
    expect(e.message).toBe('the connection store failed');
    expect(new StoreError('custom').message).toBe('custom');
  });

  it('UnknownActionError', () => {
    const e = new UnknownActionError('bank.send');
    expect(e.name).toBe('UnknownActionError');
    expect(e.code).toBe('unknown_action');
    expect(e.message).toBe("no pinned action definition for verb 'bank.send': refusing to release a credential");
  });

  it('UnconfirmedActionError', () => {
    const e = new UnconfirmedActionError('bank.send');
    expect(e.name).toBe('UnconfirmedActionError');
    expect(e.code).toBe('unconfirmed_action');
    expect(e.message).toBe("the definition of 'bank.send' has no valid signed confirmation: refusing to release a credential");
  });

  it('RequestMismatchError', () => {
    const e = new RequestMismatchError('bad');
    expect(e.name).toBe('RequestMismatchError');
    expect(e.code).toBe('request_mismatch');
    expect(e.message).toBe('bad');
  });

  it('BearerReleaseDisabledError', () => {
    const e = new BearerReleaseDisabledError();
    expect(e.name).toBe('BearerReleaseDisabledError');
    expect(e.code).toBe('bearer_release_disabled');
    expect(e.message).toBe('this vault does not release bearer tokens to callers; use proxyCall(), or construct it with insecureBearerRelease: true (insecure: the caller can use the token for anything inside its scopes until it expires)');
  });

  it('ProxyFailedError', () => {
    const e = new ProxyFailedError('down');
    expect(e.name).toBe('ProxyFailedError');
    expect(e.code).toBe('proxy_failed');
    expect(e.message).toBe('down');
  });
});
