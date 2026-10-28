import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, type Capability } from '@atlasauth/pca';
import { authorize, requestBinding, type GatewayOptions } from './index';

/** Signature-only on purpose (0.5: an explicit mode): these tests are about routing, adapters and binding; full mode is in full-policy.test.ts. */
const SIG_ONLY = { policy: { mode: 'signature-only' as const }, replayGuard: { claim: async () => true }, requireChecks: [] as string[] };

const AUD = 'ins_acme';

/** RT-09: mint a proof whose params ARE the request binding for `path`. */
function mint(path: string, extra?: { bodySha256?: string; authority?: string; counter?: number }) {
  const a = agent({
    principal: generateKeyPair(),
    goal: 'refunds',
    permissions: { stripe: ['refund'] },
    limits: { refund: '$500/day' },
    aud: AUD,
  });
  const binding = requestBinding(
    { method: 'POST', path, headers: {}, ...(extra?.bodySha256 ? { bodySha256: extra.bodySha256 } : {}), ...(extra?.authority ? { authority: extra.authority } : {}) },
    { authority: extra?.authority !== undefined, body: extra?.bodySha256 !== undefined },
  );
  const { encoded, pcactn } = a.act('stripe.refund', 'charge:ch_1', binding, { counter: extra?.counter ?? 1 });
  return { grant: a.grant as Capability, ref: pcactn.grant_ref, encoded };
}

function cfg(m: ReturnType<typeof mint>, o?: Partial<GatewayOptions>): GatewayOptions {
  return {
    audience: AUD,
    routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: 'stripe.refund' } }],
    resolveGrant: async (r) => (r === m.ref ? m.grant : null),
    ...SIG_ONLY,
    ...o,
  };
}
const hdrs = (e: string) => ({ [PCA_HEADER.toLowerCase()]: pcaHeaders(e)[PCA_HEADER]! });

describe('RT-09 request binding', () => {
  it('R2-11: binding is ON by default; only an explicit bindRequest:false makes the proof a route bearer', async () => {
    const m = mint('/refunds/ch_1');
    const d0 = await authorize({ method: 'POST', path: '/refunds/ch_VICTIM', headers: hdrs(m.encoded) }, cfg(m));
    expect(d0.allow).toBe(false);
    expect(d0.code).toBe('request-mismatch');
    const d = await authorize({ method: 'POST', path: '/refunds/ch_VICTIM', headers: hdrs(m.encoded) }, cfg(m, { bindRequest: false }));
    expect(d.allow).toBe(true);
  });
  it('R2-11: the query string is bound; a proof for one query is refused on another', async () => {
    const m = mint('/refunds/ch_1');
    const ok = await authorize({ method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) }, cfg(m));
    expect(ok.allow).toBe(true);
    const evil = await authorize({ method: 'POST', path: '/refunds/ch_1', query: 'to=attacker', headers: hdrs(m.encoded) }, cfg(m));
    expect(evil.allow).toBe(false);
    expect(evil.code).toBe('request-mismatch');
  });
  it('R2-11: the body hash is bound by default when the request carries one', async () => {
    const m = mint('/refunds/ch_1', { bodySha256: 'aa' });
    const ok = await authorize({ method: 'POST', path: '/refunds/ch_1', bodySha256: 'aa', headers: hdrs(m.encoded) }, cfg(m));
    expect(ok.allow).toBe(true);
    const other = await authorize({ method: 'POST', path: '/refunds/ch_1', bodySha256: 'bb', headers: hdrs(m.encoded) }, cfg(m));
    expect(other.allow).toBe(false);
  });
  it('bindRequest denies a proof used on a different path', async () => {
    const m = mint('/refunds/ch_1');
    const d = await authorize({ method: 'POST', path: '/refunds/ch_VICTIM', headers: hdrs(m.encoded) }, cfg(m, { bindRequest: {} }));
    expect(d.allow).toBe(false);
    expect(d.code).toBe('request-mismatch');
  });
  it('bindRequest allows the exact bound request', async () => {
    const m = mint('/refunds/ch_1');
    const d = await authorize({ method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) }, cfg(m, { bindRequest: {} }));
    expect(d.allow).toBe(true);
  });
  it('bindRequest denies a different method', async () => {
    const m = mint('/refunds/ch_1');
    const o = cfg(m, { bindRequest: {}, routes: [{ path: '/refunds/*', capability: { verb: 'stripe.refund' } }] });
    const d = await authorize({ method: 'DELETE', path: '/refunds/ch_1', headers: hdrs(m.encoded) }, o);
    expect(d.code).toBe('request-mismatch');
  });
  it('body binding: a different body hash is denied, a missing hash fails closed', async () => {
    const m = mint('/refunds/ch_1', { bodySha256: 'a'.repeat(64) });
    const o = cfg(m, { bindRequest: { body: true } });
    const ok = await authorize({ method: 'POST', path: '/refunds/ch_1', bodySha256: 'a'.repeat(64), headers: hdrs(m.encoded) }, o);
    expect(ok.allow).toBe(true);
    const other = await authorize({ method: 'POST', path: '/refunds/ch_1', bodySha256: 'b'.repeat(64), headers: hdrs(m.encoded) }, o);
    expect(other.code).toBe('request-mismatch');
    const none = await authorize({ method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) }, o);
    expect(none.code).toBe('request-mismatch');
  });
  it('authority binding', async () => {
    const m = mint('/refunds/ch_1', { authority: 'api.a.example' });
    const o = cfg(m, { bindRequest: { authority: true } });
    const ok = await authorize({ method: 'POST', path: '/refunds/ch_1', authority: 'api.a.example', headers: hdrs(m.encoded) }, o);
    expect(ok.allow).toBe(true);
    const bad = await authorize({ method: 'POST', path: '/refunds/ch_1', authority: 'api.b.example', headers: hdrs(m.encoded) }, o);
    expect(bad.code).toBe('request-mismatch');
  });
  it('checkProof hook (per-proof limits) can deny and fails closed on throw', async () => {
    const m = mint('/refunds/ch_1');
    const deny = await authorize({ method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) }, cfg(m, { checkProof: () => ({ allow: false, reason: 'over limit' }) }));
    expect(deny.code).toBe('proof-rejected');
    const thr = await authorize({ method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) }, cfg(m, { checkProof: () => { throw new Error('boom'); } }));
    expect(thr.allow).toBe(false);
    const ok = await authorize({ method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) }, cfg(m, { checkProof: () => true }));
    expect(ok.allow).toBe(true);
  });
  it('requireChecks fails closed on not-enforced checks (revocation hook absent)', async () => {
    const m = mint('/refunds/ch_1');
    const d = await authorize({ method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) }, cfg(m, { requireChecks: ['revocation'] }));
    expect(d.code).toBe('proof-rejected');
  });
  it('a revocation hook is passed to the core verifier', async () => {
    const m = mint('/refunds/ch_1');
    const d = await authorize(
      { method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) },
      cfg(m, { requireChecks: ['revocation'], hooks: { revocation: () => ({ enforced: true, ok: false, reason: 'revoked' }) } }),
    );
    expect(d.allow).toBe(false);
    const ok = await authorize(
      { method: 'POST', path: '/refunds/ch_1', headers: hdrs(m.encoded) },
      cfg(m, { requireChecks: ['revocation'], hooks: { revocation: () => ({ enforced: true, ok: true }) } }),
    );
    expect(ok.allow).toBe(true);
  });
});

describe('R3-07 duplicate query parameters are refused', () => {
  const rb = (query: string) => requestBinding({ method: 'GET', path: '/p', query, headers: {} });
  it('requestBinding throws on duplicates (any order, encoded, case), on ; and on bad escapes', () => {
    expect(() => rb('amount=1&amount=1000000')).toThrow(/duplicate/);
    expect(() => rb('amount=1000000&amount=1')).toThrow(/duplicate/);
    expect(() => rb('a=1&%61=2')).toThrow(/duplicate/);
    expect(() => rb('Amount=1&amount=2')).toThrow(/duplicate/);
    expect(() => rb('a&a=1')).toThrow(/duplicate/);
    expect(() => rb('a=1;b=2')).toThrow(/;/);
    expect(() => rb('%zz=1')).toThrow(/malformed/);
    expect(rb('b=2&a=1').query).toBe('a=1&b=2');
  });
  it('authorize denies a duplicate-parameter request with request-mismatch (no throw)', async () => {
    const m = mint('/refunds/ch_1');
    const d = await authorize({ method: 'POST', path: '/refunds/ch_1', query: 'amount=1&amount=1000000', headers: hdrs(m.encoded) }, cfg(m));
    expect(d.allow).toBe(false);
    expect(d.code).toBe('request-mismatch');
  });
});
