/** 0.4.2 mutation kills: canonical query keys, the unbindable-request refusal, and the kept (by-reference) members of createGateway. */
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, pcaHeaders, PCA_HEADER, type Capability } from '@atlasauth/pca';
import { authorize, canonicalQuery, createGateway, requestBinding, type GatewayOptions } from './index';

describe('canonicalQuery: parameter names', () => {
  it('an empty name (a leading "=") is the name "", so two of them are a duplicate', () => {
    expect(() => canonicalQuery('=a&=b')).toThrow("duplicate query parameter ''");
    expect(canonicalQuery('=a')).toBe('=a');
  });
  it('names compare lower-cased and the duplicate message quotes the lower-cased name', () => {
    expect(() => canonicalQuery('A=1&a=2')).toThrow("duplicate query parameter 'a'");
    expect(() => canonicalQuery('Ab%43=1&abC=2')).toThrow("duplicate query parameter 'abc'");
  });
  it('"+" in a name is a space, not nothing: "a+b" and "ab" are different names', () => {
    expect(() => canonicalQuery('a+b=1&ab=2')).not.toThrow();
    expect(() => canonicalQuery('a+b=1&a%20b=2')).toThrow("duplicate query parameter 'a b'");
  });
});

describe('authorize: a request that cannot be bound is refused with the reason and the verdict', () => {
  const AUD = 'ins_k042';
  it("a ';' in the query: request-mismatch 403, reason names the cause, verdict and pcactn are attached", async () => {
    const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: AUD });
    const binding = requestBinding({ method: 'POST', path: '/refunds/ch_1', headers: {} });
    const { encoded, pcactn } = a.act('stripe.refund', 'charge:ch_1', binding, { counter: 1 });
    const opts: GatewayOptions = {
      audience: AUD,
      routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: 'stripe.refund' } }],
      resolveGrant: async (r) => (r === pcactn.grant_ref ? (a.grant as Capability) : null),
    };
    const d = await authorize({ method: 'POST', path: '/refunds/ch_1', query: 'a=1;b=2', headers: { [PCA_HEADER.toLowerCase()]: pcaHeaders(encoded)[PCA_HEADER]! } }, opts);
    expect(d.allow).toBe(false);
    expect(d.status).toBe(403);
    expect(d.code).toBe('request-mismatch');
    expect(d.reason).toBe("the request cannot be bound: query contains ';' (parsers disagree on it as a separator)");
    expect(d.pcactn?.grant_ref).toBe(pcactn.grant_ref);
    expect(d.verdict).toBeDefined();
  });
});

describe('createGateway keeps behaviour / state members by reference', () => {
  it('replayGuard and hooks are not walked or copied at construction (a snapshot would read and clone them)', async () => {
    let reads = 0;
    const spy = (): Record<string, unknown> => Object.defineProperty({}, 'probe', { enumerable: true, get() { reads++; return undefined; } });
    const claimed: string[] = [];
    const replayGuard = Object.assign(spy(), { seen: claimed, claim(key: string): boolean { this.seen.push(key); return true; } });
    const hooks = spy();
    const a = agent({ principal: generateKeyPair(), goal: 'refunds', permissions: { stripe: ['refund'] }, limits: { refund: '$500/day' }, aud: 'ins_keep' });
    const binding = requestBinding({ method: 'POST', path: '/refunds/ch_1', headers: {} });
    const { encoded, pcactn } = a.act('stripe.refund', 'charge:ch_1', binding, { counter: 1 });
    const gw = createGateway({
      audience: 'ins_keep',
      routes: [{ method: 'POST', path: '/refunds/*', capability: { verb: 'stripe.refund' } }],
      resolveGrant: async (r) => (r === pcactn.grant_ref ? (a.grant as Capability) : null),
      replayGuard: replayGuard as never,
      hooks: hooks as never,
    });
    expect(reads).toBe(0);
    const d = await gw({ method: 'POST', path: '/refunds/ch_1', headers: { [PCA_HEADER.toLowerCase()]: pcaHeaders(encoded)[PCA_HEADER]! } });
    expect(d.allow).toBe(true);
    expect(claimed).toHaveLength(1); // the guard the caller holds is the one that was asked
  });
});
