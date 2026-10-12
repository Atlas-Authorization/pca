/**
 * A network client for a real OpenID Provider's CIBA endpoints (OpenID CIBA Core 1.0): start a
 * backchannel authentication request and wait for the human's decision by POLL or PING. It is the
 * relying-party side that `createCibaBroker` (in-memory, test-double) models.
 *
 * Poll discipline follows CIBA Core 7.3 / 11: the client never polls faster than the `interval` the OP
 * returned, adds at least 5 seconds to it on every `slow_down`, and stops at `expires_in`. A terminal
 * answer (approved / denied / expired) is cached, so a settled flow is never re-sent to the token
 * endpoint (an approved `auth_req_id` is single-use at real providers).
 *
 * The client authenticates with `client_secret_basic`. The returned tokens are the OP's response, not
 * verified here: a caller that relies on the ID token must verify it with its own JOSE library.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { toCibaAuthRequest, type CibaAuthRequest, type CibaRequestOptions } from './index';
import type { StepUpRequest } from '@atlasauth/pca';

const CIBA_GRANT = 'urn:openid:params:grant-type:ciba';
/** CIBA Core 11: on `slow_down` the interval grows by at least 5 seconds. */
const SLOW_DOWN_STEP_SEC = 5;

export type CibaDelivery = 'poll' | 'ping';

/** An error response from the OP (RFC 6749 5.2 / CIBA Core 13), or a malformed reply. */
export class CibaProviderError extends Error {
  readonly error: string;
  readonly errorDescription: string | undefined;
  readonly status: number;
  /** True for failures worth retrying (network error, timeout, 5xx, non-JSON reply); not for a definitive OP answer. */
  readonly retryable: boolean;
  constructor(status: number, error: string, errorDescription?: string, retryable = false) {
    super(`ciba: provider returned ${String(status)} ${error}${errorDescription !== undefined ? ` (${errorDescription})` : ''}`);
    this.name = 'CibaProviderError';
    this.status = status;
    this.error = error;
    this.errorDescription = errorDescription;
    this.retryable = retryable;
  }
}

export interface CibaClientConfig {
  backchannelAuthenticationEndpoint: string;
  tokenEndpoint: string;
  clientId: string;
  clientSecret: string;
  /** Injectable for tests. Default global `fetch`. */
  fetch?: typeof fetch;
  /** Injectable for tests. Default `setTimeout`. */
  sleep?: (ms: number) => Promise<void>;
  /** Clock in ms. Default `Date.now`. */
  now?: () => number;
  /** Per-request timeout in ms for every call to the OP. Default 30000. */
  timeoutMs?: number;
  /**
   * Permit `http://` endpoints. The client secret and the `auth_req_id` travel on these requests, so this
   * is for local test providers only. Default false: a non-https endpoint is rejected.
   */
  allowInsecureHttp?: boolean;
}

export interface CibaInitiateOptions extends CibaRequestOptions {
  /** Exactly one identifying hint is allowed (CIBA Core 7.1). `loginHint` comes from {@link CibaRequestOptions}. */
  loginHintToken?: string;
  idTokenHint?: string;
  /** `ping` sends a `client_notification_token` (generated if not given); `poll` (default) sends none. */
  delivery?: CibaDelivery;
  clientNotificationToken?: string;
  acrValues?: string;
  userCode?: string;
}

export interface CibaFlow {
  /** The OP-issued `auth_req_id`. */
  authReqId: string;
  expiresInSec: number;
  /** Interval the OP asked for, in seconds. */
  intervalSec: number;
  /** ms epoch the OP answered. */
  startedAt: number;
  delivery: CibaDelivery;
  clientNotificationToken?: string;
  /** The request PCA derived (scope, binding message, ...) that was sent. */
  request: CibaAuthRequest;
}

export interface CibaTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
}

export type CibaPollResult =
  | { status: 'pending'; intervalSec: number }
  | { status: 'approved'; tokens: CibaTokenResponse }
  | { status: 'denied'; error: string }
  | { status: 'expired' };

export interface CibaPoller {
  /** Current poll interval in seconds (grows on `slow_down`). */
  intervalSec(): number;
  /** Sleep until the interval allows it, then ask the token endpoint once. */
  poll(opts?: { signal?: AbortSignal }): Promise<CibaPollResult>;
  /** Poll until the flow settles; honours `signal`. */
  wait(opts?: { signal?: AbortSignal }): Promise<Exclude<CibaPollResult, { status: 'pending' }>>;
  /** A PING arrived: the next `poll()` may go out immediately, and a `poll()`/`wait()` that is sleeping wakes now. */
  notify(): void;
}

export interface CibaClient {
  initiate(stepUp: StepUpRequest, opts?: CibaInitiateOptions): Promise<CibaFlow>;
  poller(flow: CibaFlow): CibaPoller;
}

async function readJson(res: Response): Promise<Record<string, unknown>> {
  const text = await res.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new CibaProviderError(res.status, 'invalid_response', 'the provider reply was not JSON', true);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new CibaProviderError(res.status, 'invalid_response', 'the provider reply was not a JSON object');
  }
  return parsed as Record<string, unknown>;
}

function providerError(status: number, body: Record<string, unknown>): CibaProviderError {
  const error = typeof body['error'] === 'string' ? body['error'] : 'invalid_response';
  const desc = typeof body['error_description'] === 'string' ? body['error_description'] : undefined;
  return new CibaProviderError(status, error, desc);
}

function positiveInt(value: unknown, name: string, status: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new CibaProviderError(status, 'invalid_response', `${name} must be a positive integer`);
  }
  return value;
}

const MIN_NOTIFICATION_TOKEN_CHARS = 22; // 22 base64url chars = 132 bits
const MAX_NOTIFICATION_TOKEN_CHARS = 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_BACKOFF_MS = 60_000;
const MAX_CONSECUTIVE_TRANSIENT = 5;

function checkEndpoint(name: string, value: string, allowInsecure: boolean): void {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new RangeError(`ciba: ${name} is not a valid URL`);
  }
  if (u.protocol === 'https:') return;
  if (u.protocol === 'http:' && allowInsecure) return;
  throw new RangeError(`ciba: ${name} must be an https:// URL (set allowInsecureHttp only for a local test provider)`);
}

/** A fresh `client_notification_token` (CIBA Core 7.1: at least 128 bits of entropy, at most 1024 chars). */
export function newClientNotificationToken(): string {
  return randomBytes(32).toString('base64url');
}

export function createCibaClient(cfg: CibaClientConfig): CibaClient {
  const doFetch = cfg.fetch ?? fetch;
  const clock = cfg.now ?? Date.now;
  const timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new RangeError('ciba: timeoutMs must be a positive number');
  checkEndpoint('backchannelAuthenticationEndpoint', cfg.backchannelAuthenticationEndpoint, cfg.allowInsecureHttp === true);
  checkEndpoint('tokenEndpoint', cfg.tokenEndpoint, cfg.allowInsecureHttp === true);
  const basic = `Basic ${Buffer.from(`${encodeURIComponent(cfg.clientId)}:${encodeURIComponent(cfg.clientSecret)}`).toString('base64')}`;

  /** One request with a hard timeout; the caller's signal also cancels the fetch itself. */
  async function post(url: string, form: URLSearchParams, signal?: AbortSignal): Promise<Response> {
    if (signal?.aborted === true) throw new Error('ciba: wait aborted');
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(new Error('timeout')), timeoutMs);
    const onAbort = () => ac.abort(new Error('aborted'));
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      return await doFetch(url, {
        method: 'POST',
        headers: { authorization: basic, 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: form.toString(),
        signal: ac.signal,
      });
    } catch (e) {
      if (signal !== undefined && (signal as AbortSignal).aborted) throw new Error('ciba: wait aborted');
      throw new CibaProviderError(0, 'network_error', e instanceof Error ? e.message : 'request failed', true);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    }
  }

  return {
    async initiate(stepUp, opts = {}) {
      const hints = [opts.loginHint, opts.loginHintToken, opts.idTokenHint].filter((h) => h !== undefined);
      if (hints.length !== 1) {
        throw new RangeError('ciba: exactly one of loginHint, loginHintToken, idTokenHint is required (CIBA Core 7.1)');
      }
      const delivery = opts.delivery ?? 'poll';
      const notificationToken = delivery === 'ping' ? (opts.clientNotificationToken ?? newClientNotificationToken()) : undefined;
      if (
        opts.clientNotificationToken !== undefined &&
        (opts.clientNotificationToken.length < MIN_NOTIFICATION_TOKEN_CHARS ||
          opts.clientNotificationToken.length > MAX_NOTIFICATION_TOKEN_CHARS ||
          !/^[\x21-\x7E]+$/.test(opts.clientNotificationToken))
      ) {
        throw new RangeError(
          `ciba: clientNotificationToken must be ${String(MIN_NOTIFICATION_TOKEN_CHARS)}..${String(MAX_NOTIFICATION_TOKEN_CHARS)} printable characters (>= 128 bits, CIBA Core 7.1)`,
        );
      }
      const request = toCibaAuthRequest(stepUp, opts);
      const form = new URLSearchParams({
        scope: request.scope,
        binding_message: request.binding_message,
        requested_expiry: String(request.requested_expiry),
      });
      if (opts.loginHint !== undefined) form.set('login_hint', opts.loginHint);
      if (opts.loginHintToken !== undefined) form.set('login_hint_token', opts.loginHintToken);
      if (opts.idTokenHint !== undefined) form.set('id_token_hint', opts.idTokenHint);
      if (opts.acrValues !== undefined) form.set('acr_values', opts.acrValues);
      if (opts.userCode !== undefined) form.set('user_code', opts.userCode);
      if (notificationToken !== undefined) form.set('client_notification_token', notificationToken);
      const res = await post(cfg.backchannelAuthenticationEndpoint, form);
      const body = await readJson(res);
      if (!res.ok) throw providerError(res.status, body);
      const authReqId = body['auth_req_id'];
      if (typeof authReqId !== 'string' || authReqId.length === 0) {
        throw new CibaProviderError(res.status, 'invalid_response', 'auth_req_id missing');
      }
      const expiresInSec = positiveInt(body['expires_in'], 'expires_in', res.status);
      // CIBA Core 7.3: `interval` is optional and defaults to 5 seconds.
      const intervalSec = body['interval'] === undefined ? 5 : positiveInt(body['interval'], 'interval', res.status);
      return {
        authReqId,
        expiresInSec,
        intervalSec,
        startedAt: clock(),
        delivery,
        ...(notificationToken !== undefined ? { clientNotificationToken: notificationToken } : {}),
        request,
      };
    },

    poller(flow) {
      let intervalMs = flow.intervalSec * 1000;
      let nextAt = flow.startedAt + intervalMs;
      const deadline = flow.startedAt + flow.expiresInSec * 1000;
      let settled: Exclude<CibaPollResult, { status: 'pending' }> | undefined;
      let inflight: Promise<CibaPollResult> | undefined;
      let wake: (() => void) | undefined;
      let failures = 0;

      /** Sleep `ms`, ending early on notify() or on the caller's abort. */
      async function pause(ms: number, signal?: AbortSignal): Promise<void> {
        let timer: ReturnType<typeof setTimeout> | undefined;
        let onAbort: (() => void) | undefined;
        const racers: Promise<void>[] = [
          cfg.sleep !== undefined ? cfg.sleep(ms) : new Promise<void>((r) => { timer = setTimeout(r, ms); }),
          new Promise<void>((r) => { wake = r; }),
        ];
        if (signal !== undefined) {
          racers.push(new Promise<void>((r) => { onAbort = () => r(); signal.addEventListener('abort', onAbort, { once: true }); }));
        }
        try {
          await Promise.race(racers);
        } finally {
          wake = undefined;
          if (timer !== undefined) clearTimeout(timer);
          if (signal !== undefined && onAbort !== undefined) signal.removeEventListener('abort', onAbort);
        }
        if (signal?.aborted === true) throw new Error('ciba: wait aborted');
      }

      function backoff(): void {
        failures += 1;
        const delay = Math.min(MAX_BACKOFF_MS, intervalMs * 2 ** Math.min(failures, 6));
        nextAt = clock() + delay;
      }

      async function doPoll(signal?: AbortSignal): Promise<CibaPollResult> {
        if (settled !== undefined) return settled;
        const wait = nextAt - clock();
        if (wait > 0) await pause(wait, signal);
        if (settled !== undefined) return settled;
        if (clock() >= deadline) {
          settled = { status: 'expired' };
          return settled;
        }
        let res: Response;
        let body: Record<string, unknown>;
        try {
          res = await post(cfg.tokenEndpoint, new URLSearchParams({ grant_type: CIBA_GRANT, auth_req_id: flow.authReqId }), signal);
          if (res.status >= 500) {
            await res.text().catch(() => '');
            throw new CibaProviderError(res.status, 'server_error', 'the provider answered with a server error', true);
          }
          body = await readJson(res);
        } catch (e) {
          if (e instanceof CibaProviderError && e.retryable) backoff();
          throw e;
        }
        failures = 0;
        nextAt = clock() + intervalMs;
        if (res.ok) {
          const at = body['access_token'];
          const tt = body['token_type'];
          if (typeof at !== 'string' || typeof tt !== 'string') {
            throw new CibaProviderError(res.status, 'invalid_response', 'token response lacks access_token / token_type');
          }
          settled = { status: 'approved', tokens: body as unknown as CibaTokenResponse };
          return settled;
        }
        const err = providerError(res.status, body);
        switch (err.error) {
          case 'authorization_pending':
            return { status: 'pending', intervalSec: intervalMs / 1000 };
          case 'slow_down':
            intervalMs += SLOW_DOWN_STEP_SEC * 1000;
            nextAt = clock() + intervalMs;
            return { status: 'pending', intervalSec: intervalMs / 1000 };
          case 'access_denied':
            settled = { status: 'denied', error: err.error };
            return settled;
          case 'expired_token':
            settled = { status: 'expired' };
            return settled;
          default:
            throw err;
        }
      }

      const poller: CibaPoller = {
        intervalSec: () => intervalMs / 1000,
        notify() {
          nextAt = clock();
          wake?.();
        },
        // Concurrent callers share one in-flight request: an approved auth_req_id is single-use at real OPs.
        poll(opts = {}) {
          if (inflight !== undefined) return inflight;
          const p = doPoll(opts.signal).finally(() => {
            inflight = undefined;
          });
          inflight = p;
          return p;
        },
        async wait(opts = {}) {
          let transient = 0;
          for (;;) {
            if (opts.signal?.aborted === true) throw new Error('ciba: wait aborted');
            try {
              const r = await poller.poll(opts.signal !== undefined ? { signal: opts.signal } : {});
              transient = 0;
              if (r.status !== 'pending') return r;
            } catch (e) {
              if (!(e instanceof CibaProviderError) || !e.retryable || ++transient >= MAX_CONSECUTIVE_TRANSIENT) throw e;
            }
          }
        },
      };
      return poller;
    },
  };
}

/**
 * Validate a PING callback (CIBA Core 10.2): `Authorization: Bearer <client_notification_token>` and a JSON
 * body `{ "auth_req_id": ... }`. Returns the `auth_req_id` only when the bearer matches the token sent for
 * that flow (constant-time comparison); throws otherwise. The callback carries no decision: call
 * `poller.notify()` and then `poll()` to fetch it.
 */
export function verifyPingCallback(
  input: { authorization: string | undefined; body: unknown },
  flow: Pick<CibaFlow, 'authReqId' | 'clientNotificationToken'>,
): string {
  if (flow.clientNotificationToken === undefined) throw new Error('ciba: flow was not started in ping mode');
  const m = /^bearer +(\S+)$/i.exec(input.authorization ?? '');
  if (m === null) throw new Error('ciba: ping callback lacks a bearer token');
  const digest = (v: string) => createHash('sha256').update(v).digest();
  if (!timingSafeEqual(digest(m[1] as string), digest(flow.clientNotificationToken))) {
    throw new Error('ciba: ping callback bearer does not match the client_notification_token');
  }
  const id = typeof input.body === 'object' && input.body !== null ? (input.body as Record<string, unknown>)['auth_req_id'] : undefined;
  if (typeof id !== 'string' || id !== flow.authReqId) throw new Error('ciba: ping callback auth_req_id does not match this flow');
  return id;
}
