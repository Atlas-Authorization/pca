/**
 * (a) OAuth 2.0 bearer access token with scopes (RFC 6749 §3.3, RFC 6750), as a signed JWT access token
 * (RFC 9068) that the resource server validates locally: signature, `aud` (RFC 8707 resource indicator),
 * `exp`, and the required scope.
 *
 * Used well: short-lived, audience-bound, least scope. A scope is a string, so the token can say "may
 * send payments" but not to whom or how much. Narrowing for a sub-agent goes through the authorization
 * server (RFC 8693 token exchange) and can only drop scopes.
 */
import { RS, ed25519, jwsSign, jwsVerify, nonce, type Approach, type Authority, type Grant, type Payment, type Req, type Server, type Stolen } from '../common.js';

const SCOPE = 'payments:write';

interface Inner {
  token: string;
}

export function oauthApproach(): Approach {
  const as = ed25519(); // the authorization server's signing key

  const issue = (scope: string): string => {
    const now = Math.floor(Date.now() / 1000);
    return jwsSign(as, { iss: 'https://as.example', sub: 'user-1', client_id: 'agent', aud: RS, scope, iat: now, exp: now + 600, jti: nonce() });
  };

  const dropped = (a: Authority): string[] => [
    'payee allowlist',
    'per-payment ceiling',
    ...(a.maxTotal !== undefined ? ['cumulative ceiling'] : []),
    ...(a.exact ? ['the exact approved payments'] : []),
    ...(a.vouchedBy ? [`vouching by ${a.vouchedBy.source}`] : []),
  ];

  const req = (token: string, p: Payment): Req => ({ headers: { authorization: `Bearer ${token}` }, body: { ...p } });

  return {
    id: 'oauth',
    label: 'OAuth scopes',
    async grant(a) {
      return { inner: { token: issue(SCOPE) } satisfies Inner, dropped: dropped(a) };
    },
    server(): Server {
      return {
        async handle(r) {
          const m = /^Bearer (.+)$/.exec(r.headers.authorization ?? '');
          if (!m) return { ok: false, reason: 'no bearer token' };
          const claims = jwsVerify(as.publicKey, m[1]!);
          if (!claims) return { ok: false, reason: 'bad token signature' };
          if (claims.aud !== RS) return { ok: false, reason: 'token audience is not this server' };
          if (typeof claims.exp !== 'number' || claims.exp * 1000 < Date.now()) return { ok: false, reason: 'token expired' };
          const scopes = String(claims.scope ?? '').split(' ');
          if (!scopes.includes(SCOPE)) return { ok: false, reason: `missing scope ${SCOPE}` };
          return { ok: true, reason: `valid token with scope ${SCOPE}` };
        },
      };
    },
    async request(g, p) {
      return req((g.inner as Inner).token, p);
    },
    async attenuate(g, narrower) {
      // RFC 8693 token exchange: the AS may issue a token with a subset of the scopes. The narrower authority
      // differs only in payee and amount, which no scope string encodes, so the best it can issue is the same scope.
      return { inner: { token: issue(SCOPE) } satisfies Inner, dropped: dropped(narrower) };
    },
    steal(g): Stolen {
      return { inner: (g.inner as Inner).token };
    },
    async forge(s, p) {
      return req(s.inner as string, p);
    },
  };
}
