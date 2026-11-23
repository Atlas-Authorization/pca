/**
 * (b) OAuth 2.0 Rich Authorization Requests (RFC 9396): the access token carries `authorization_details`,
 * and the resource server checks each request against them.
 *
 * Used well:
 *  - When the payments are known before approval, one `payment_initiation` object per payment, in the shape
 *    of RFC 9396 §2 (instructedAmount, creditorName, locations, actions).
 *  - When they are not, an API-defined type (RFC 9396 §2.1 lets the API define its own types) carrying the
 *    payee allowlist, a per-payment ceiling and, if wanted, a cumulative ceiling. The resource server keeps
 *    the running total per token, because RFC 9396 says nothing about consumption across requests.
 *  - A sub-agent gets a new token with narrower authorization_details from the authorization server (an
 *    online round trip; RFC 9396 §6.1 shows narrowing on refresh, and token exchange per RFC 8693 is the
 *    usual route for a different client).
 * The token is still a bearer token: RFC 9396 does not add sender constraint or single use.
 */
import { RS, SpendLedger, ed25519, jwsSign, jwsVerify, nonce, type Approach, type Authority, type Payment, type Req, type Server, type Stolen } from '../common.js';

const VENDOR_TYPE = 'https://payments.example/vendor_payments';

type Detail =
  | { type: 'payment_initiation'; actions: string[]; locations: string[]; instructedAmount: { currency: string; amount: string }; creditorName: string }
  | { type: typeof VENDOR_TYPE; actions: string[]; locations: string[]; creditorNames: string[]; maxAmountPerPayment: { currency: string; amount: string }; maxTotalAmount?: { currency: string; amount: string } };

interface Inner {
  token: string;
}

const money = (n: number) => ({ currency: 'USD', amount: n.toFixed(2) });

export function detailsFor(a: Authority): Detail[] {
  if (a.exact) {
    return a.exact.map((p) => ({
      type: 'payment_initiation' as const,
      actions: ['initiate'],
      locations: [RS],
      instructedAmount: money(p.amount),
      creditorName: p.payee,
    }));
  }
  return [
    {
      type: VENDOR_TYPE,
      actions: ['initiate'],
      locations: [RS],
      creditorNames: [...a.payees],
      maxAmountPerPayment: money(a.maxPerCall),
      ...(a.maxTotal !== undefined ? { maxTotalAmount: money(a.maxTotal) } : {}),
    },
  ];
}

export function rarApproach(): Approach {
  const as = ed25519();

  const issue = (details: Detail[]): string => {
    const now = Math.floor(Date.now() / 1000);
    return jwsSign(as, { iss: 'https://as.example', sub: 'user-1', client_id: 'agent', aud: RS, authorization_details: details, iat: now, exp: now + 600, jti: nonce() });
  };
  const req = (token: string, p: Payment): Req => ({ headers: { authorization: `Bearer ${token}` }, body: { ...p } });

  return {
    id: 'rar',
    label: 'OAuth RAR',
    async grant(a) {
      // authorization_details state what the principal consented to; RFC 9396 has no member through which a second
      // system vouches for the values at request time.
      return { inner: { token: issue(detailsFor(a)) } satisfies Inner, dropped: a.vouchedBy ? [`vouching by ${a.vouchedBy.source}`] : [] };
    },
    server(): Server {
      const ledger = new SpendLedger(); // running totals, keyed by token id
      return {
        async handle(r) {
          const m = /^Bearer (.+)$/.exec(r.headers.authorization ?? '');
          if (!m) return { ok: false, reason: 'no bearer token' };
          const c = jwsVerify(as.publicKey, m[1]!);
          if (!c) return { ok: false, reason: 'bad token signature' };
          if (c.aud !== RS) return { ok: false, reason: 'token audience is not this server' };
          if (typeof c.exp !== 'number' || c.exp * 1000 < Date.now()) return { ok: false, reason: 'token expired' };
          const details = (c.authorization_details ?? []) as Detail[];
          const { payee, amount } = r.body;
          for (const d of details) {
            if (!d.actions.includes('initiate') || !d.locations.includes(RS)) continue;
            if (d.type === 'payment_initiation') {
              if (d.creditorName === payee && Number(d.instructedAmount.amount) === amount) {
                return { ok: true, reason: 'request matches an approved payment_initiation detail' };
              }
            } else if (d.type === VENDOR_TYPE) {
              if (!d.creditorNames.includes(payee)) continue;
              if (amount > Number(d.maxAmountPerPayment.amount)) continue;
              if (d.maxTotalAmount) {
                const key = String(c.jti);
                const spent = ledger.spent(key);
                if (spent + amount > Number(d.maxTotalAmount.amount)) {
                  return { ok: false, reason: `maxTotalAmount ${d.maxTotalAmount.amount}: already spent $${spent}, this payment would exceed it` };
                }
                ledger.add(key, amount);
              }
              return { ok: true, reason: 'request is inside the vendor_payments detail' };
            }
          }
          return { ok: false, reason: `no authorization_details entry covers $${amount} to ${payee}` };
        },
      };
    },
    async request(g, p) {
      return req((g.inner as Inner).token, p);
    },
    async attenuate(_g, narrower) {
      // The authorization server checks the narrower details are within the original grant, then issues a new token.
      return { inner: { token: issue(detailsFor(narrower)) } satisfies Inner, dropped: [] };
    },
    steal(g): Stolen {
      return { inner: (g.inner as Inner).token };
    },
    async forge(s, p) {
      return req(s.inner as string, p);
    },
  };
}
