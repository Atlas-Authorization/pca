/**
 * The attacks. Each one first runs a legitimate control request that MUST be allowed (so a "stopped" result
 * can never come from an approach that simply denies everything), then runs the attack and records whether
 * the resource server refused it, with the server's own reason.
 */
import { fmt, type Approach, type Authority, type Payment, type Verdict } from './common.js';

export interface Outcome {
  stopped: boolean;
  /** The resource server's verdict reason for the attack request. */
  reason: string;
  /** Why it got through, when it did. */
  why?: string;
}

export interface Attack {
  id: string;
  title: string;
  story: string;
  run(ap: Approach): Promise<Outcome>;
}

const VENDORS = ['acme-hosting', 'paper-co'];
const ACME_120: Payment = { payee: 'acme-hosting', amount: 120 };
const PAPER_80: Payment = { payee: 'paper-co', amount: 80 };

const BEARER = new Set(['oauth', 'rar', 'macaroon']);

class SetupError extends Error {}

function mustAllow(ap: Approach, what: string, v: Verdict): void {
  if (!v.ok) throw new SetupError(`${ap.label}: the legitimate control request (${what}) was refused: ${v.reason}`);
}

const result = (v: Verdict, why: string): Outcome => (v.ok ? { stopped: false, reason: v.reason, why } : { stopped: true, reason: v.reason });

const dropped = (d: string[]): string => (d.length ? ` It cannot express: ${d.join(', ')}.` : '');

export const ATTACKS: Attack[] = [
  {
    id: 'A1',
    title: 'Confused deputy: injected, in-scope, unintended payment',
    story:
      'The principal approves two invoices: $120 to acme-hosting and $80 to paper-co. While working, the agent reads an injected message ("paper-co sent a revised invoice") and pays $250 to paper-co: an approved vendor, under the $500 per-payment ceiling, but not a payment anyone approved.',
    async run(ap) {
      const auth: Authority = { payees: VENDORS, maxPerCall: 500, exact: [ACME_120, PAPER_80] };
      const g = await ap.grant(auth);
      const s = ap.server(g);
      mustAllow(ap, fmt(ACME_120), await s.handle(await ap.request(g, ACME_120)));
      const v = await s.handle(await ap.request(g, { payee: 'paper-co', amount: 250 }));
      return result(v, `Anything inside the scope is authorized.${dropped(g.dropped)}`);
    },
  },
  {
    id: 'A2',
    title: 'Poisoned approval: the injected payment is in what the principal approved',
    story:
      'The injection happens earlier, while the agent drafts the work. It proposes $120 to acme-hosting and $180 (not $80) to paper-co, and the principal approves that list without noticing. The company\'s accounts-payable system holds the real invoices ($120 and $80), and the principal\'s authority requires every payment\'s payee and amount to be vouched for by it. The agent then pays $180 to paper-co.',
    async run(ap) {
      const poisoned: Payment = { payee: 'paper-co', amount: 180 };
      const g = await ap.grant({ payees: VENDORS, maxPerCall: 500, exact: [ACME_120, poisoned], vouchedBy: { source: 'ap.example', records: [ACME_120, PAPER_80] } });
      const s = ap.server(g);
      mustAllow(ap, fmt(ACME_120), await s.handle(await ap.request(g, ACME_120)));
      const v = await s.handle(await ap.request(g, poisoned));
      const why =
        ap.id === 'rar'
          ? 'The token carries what the principal consented to, and the principal approved this payment. RFC 9396 has no member through which a second system vouches for the values at request time.'
          : `The principal approved exactly this payment.${dropped(g.dropped)}`;
      return result(v, why);
    },
  },
  {
    id: 'A3',
    title: 'Stolen credential used by someone else for a different payment',
    story:
      'The agent may pay acme-hosting or paper-co, up to $150 each. An attacker copies the agent\'s credential (from a log, a crash dump or a compromised tool) but not its private key, and pays $150 to paper-co.',
    async run(ap) {
      const g = await ap.grant({ payees: VENDORS, maxPerCall: 150 });
      const s = ap.server(g);
      mustAllow(ap, fmt(ACME_120), await s.handle(await ap.request(g, ACME_120)));
      const v = await s.handle(await ap.forge(ap.steal(g), { payee: 'paper-co', amount: 150 }));
      return result(
        v,
        ap.id === 'macaroon'
          ? 'It is a bearer credential: whoever holds it can use it. Macaroons and Biscuit are specified as bearer tokens.'
          : BEARER.has(ap.id)
            ? 'It is a bearer credential: whoever holds it can use it. Sender-constraining the token (DPoP, RFC 9449, or mTLS, RFC 8705) would stop this.'
            : 'The credential was usable without the holder key.',
      );
    },
  },
  {
    id: 'A4',
    title: 'Captured request replayed verbatim',
    story: 'An attacker records the agent\'s legitimate request ($120 to acme-hosting) on the wire and sends it again, byte for byte.',
    async run(ap) {
      const g = await ap.grant({ payees: VENDORS, maxPerCall: 150 });
      const s = ap.server(g);
      const req = await ap.request(g, ACME_120);
      mustAllow(ap, fmt(ACME_120), await s.handle(req));
      const v = await s.handle(structuredClone(req));
      return result(
        v,
        ap.id === 'macaroon'
          ? 'Nothing in the request is single-use: the token is meant to be presented again until a caveat (such as expiry) fails.'
          : BEARER.has(ap.id)
            ? 'Nothing in the request is single-use: the token is meant to be presented again until it expires. A DPoP proof whose jti the server tracks (RFC 9449) would stop this.'
            : 'Nothing in the request is single-use.',
      );
    },
  },
  {
    id: 'A5',
    title: 'Over-broad delegation to a sub-agent',
    story:
      'The agent may pay acme-hosting or paper-co up to $500 each. It hands a sub-agent the narrower job "pay paper-co, at most $100". The sub-agent (buggy or steered) pays $200 to paper-co, which the parent could have done.',
    async run(ap) {
      const g = await ap.grant({ payees: VENDORS, maxPerCall: 500 });
      const s = ap.server(g);
      const sub = await ap.attenuate(g, { payees: ['paper-co'], maxPerCall: 100 });
      mustAllow(ap, 'sub-agent pays $60 to paper-co', await s.handle(await ap.request(sub, { payee: 'paper-co', amount: 60 })));
      const v = await s.handle(await ap.request(sub, { payee: 'paper-co', amount: 200 }));
      return result(v, `Narrowing can only drop scopes (RFC 8693 token exchange), so the sub-agent's token is as broad as the parent's.${dropped(sub.dropped)}`);
    },
  },
  {
    id: 'A6',
    title: 'Payee and amount swapped after approval',
    story:
      'The principal approves $120 to acme-hosting and $80 to paper-co. Between the agent and the server (a compromised tool wrapper or proxy), the $80 payment is rewritten to $480 to mallory.',
    async run(ap) {
      const g = await ap.grant({ payees: VENDORS, maxPerCall: 500, exact: [ACME_120, PAPER_80] });
      const s = ap.server(g);
      mustAllow(ap, fmt(ACME_120), await s.handle(await ap.request(g, ACME_120)));
      const req = await ap.request(g, PAPER_80);
      req.body = { ...req.body, payee: 'mallory', amount: 480 };
      const v = await s.handle(req);
      return result(v, `The token is valid and the scope matches; nothing binds the payee or amount.${dropped(g.dropped)}`);
    },
  },
  {
    id: 'A7',
    title: 'Delegated agent exceeds a cumulative spending limit across calls',
    story:
      'The agent may pay acme-hosting or paper-co, at most $150 per payment and $300 in total. It pays $140, $140, then tries a third $140: each call is under the per-payment ceiling, the sum is not.',
    async run(ap) {
      const g = await ap.grant({ payees: VENDORS, maxPerCall: 150, maxTotal: 300 });
      const s = ap.server(g);
      mustAllow(ap, '$140 to acme-hosting', await s.handle(await ap.request(g, { payee: 'acme-hosting', amount: 140 })));
      mustAllow(ap, '$140 to paper-co', await s.handle(await ap.request(g, { payee: 'paper-co', amount: 140 })));
      const v = await s.handle(await ap.request(g, { payee: 'acme-hosting', amount: 140 }));
      const why =
        ap.id === 'ucan'
          ? 'A UCAN policy is evaluated over one invocation\'s args, so a running total cannot be stated in the delegation; the executor would need its own out-of-band limit.'
          : `Each call is individually in scope.${dropped(g.dropped)}`;
      return result(v, why);
    },
  },
];

export { SetupError };
