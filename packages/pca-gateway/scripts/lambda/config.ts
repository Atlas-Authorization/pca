import type { RouteRule } from '../../src/index';

/** Routes the real-runtime Lambda test authorizer enforces (shared by the handler bundle and the offline replay test). */
export const LAMBDA_TEST_ROUTES: RouteRule[] = [
  { method: 'GET', path: '/request', capability: { verb: 'stripe.refund' } },
  { method: 'POST', path: '/my/path', capability: { verb: 'stripe.refund' } },
  { method: 'POST', path: '/refunds', capability: { verb: 'stripe.refund' } },
  { method: 'POST', path: '/payouts', capability: { verb: 'stripe.payout' } },
  // The SAM local API Gateway emulation mounts each API under its own prefix.
  ...['rest', 'tok', 'h1', 'h2'].flatMap((p): RouteRule[] => [
    { method: 'POST', path: `/${p}/refunds`, capability: { verb: 'stripe.refund' } },
    { method: 'POST', path: `/${p}/payouts`, capability: { verb: 'stripe.payout' } },
  ]),
];
