/**
 * Mutation-kill tests for pq.ts (part 6): R6-API-04 short-circuit for the LESS hybrid. A forged Ed25519 half must be
 * refused WITHOUT invoking the LESS verifier (the other hybrids are covered by r6-api-hybrid-shortcircuit.test.ts by
 * timing; LESS needs an optional wasm back end, so it is checked here by counting calls on a stubbed back end).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { utf8 } from './hash';

const MSG = utf8('pq-6 message');
const LESS_SIG = 'x'.repeat(1329);
const PERMISSIVE = (s: unknown, len?: number): Uint8Array => new Uint8Array(len ?? (typeof s === 'string' ? s.length : 1329));
let edOk = true;

afterEach(() => {
  vi.doUnmock('./keys');
  vi.doUnmock('./hash');
  vi.resetModules();
});

describe('hybrid-ed25519-less-cat1: the Ed25519 half is checked first', () => {
  it('a failing Ed25519 half never reaches the LESS verifier; a passing one does', async () => {
    vi.resetModules();
    vi.doMock('./keys', async () => ({ ...(await vi.importActual<object>('./keys')), verifyB64u: () => edOk }));
    vi.doMock('./hash', async () => ({ ...(await vi.importActual<object>('./hash')), decodeB64uStrict: PERMISSIVE }));
    const P = await import('./pq');
    let lessCalls = 0;
    P.setLessBackendLoaderForTests(() => ({ keygen() {}, seedWith() {}, signDetached() {}, verify: () => (lessCalls++, true) }) as never);
    const pq = P.resolvePqVerifyKey('', undefined, { trustedPk: 'PQ' })!;
    const keys = { edPub: 'ED', pq };
    lessCalls = 0; // the loader's own instantiation probe may call verify once
    P.lessBackendStatus();
    lessCalls = 0;
    edOk = false;
    expect(P.verifyWithSuite('hybrid-ed25519-less-cat1', keys, MSG, { sig: 'S', pq_sig: LESS_SIG })).toBe(false);
    expect(lessCalls).toBe(0);
    edOk = true;
    expect(P.verifyWithSuite('hybrid-ed25519-less-cat1', keys, MSG, { sig: 'S', pq_sig: LESS_SIG })).toBe(true);
    expect(lessCalls).toBe(1);
    P.setLessBackendLoaderForTests(undefined);
  });
});
