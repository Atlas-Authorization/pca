/**
 * requirePCA residual mutants. (1) Configuration snapshot at construction: DATA (incl. the attestation trust config) is
 * read once and frozen, while stores, hooks and the attestation's nonceStore / hardwareVerifier stay the caller's objects
 * (never enumerated or copied). Accessor properties make "was it copied?" observable. (2) A failed server-side PQ pin is
 * an authentication failure (401 + challenge), not an authorization denial.
 */
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '../keys';
import { mintRoot } from '../capability';
import { buildPCActn } from '../pcactn';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from '../pq';
import { requirePCA as requirePCA05 } from './require-pca';
const requirePCA = (o: Parameters<typeof requirePCA05>[0]): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o }); // unbound and single-instance on purpose: these tests are not about operation binding or store scope (see breaking-05.test.ts)


const AUD = 'rs-mk2';
const NOW = Date.UTC(2026, 9, 11, 12, 0, 0);

describe('requirePCA configuration snapshot', () => {
  it('stores, hooks, nonceStore and hardwareVerifier are kept by reference; the attestation data is snapshotted once', () => {
    const reads = { budgetStore: 0, hooks: 0, nonceStore: 0, hardwareVerifier: 0, trusted: 0 };
    const budgetStore = {
      get probe() {
        reads.budgetStore++;
        return 1;
      },
      get: async () => undefined,
      put: async () => {},
    };
    const hooks = {
      get probe() {
        reads.hooks++;
        return 1;
      },
    };
    const nonceStore = {
      get probe() {
        reads.nonceStore++;
        return 1;
      },
      consume: async () => true,
    };
    const hardwareVerifier = {
      get probe() {
        reads.hardwareVerifier++;
        return 1;
      },
      verify: async () => ({ ok: false }),
    };
    const attestation = {
      get trustedAttestorKeys() {
        reads.trusted++;
        return ['k'];
      },
      nonceStore,
      hardwareVerifier,
      resolveDocument: () => undefined,
    };
    requirePCA({ audience: AUD, resolveGrant: async () => null, budgetStore, hooks, attestation } as never);
    expect(reads).toEqual({ budgetStore: 0, hooks: 0, nonceStore: 0, hardwareVerifier: 0, trusted: 1 });
  });
});

describe('requirePCA: a failed PQ pin is 401', () => {
  it('pure-PQ grant with a wrong pin: pq_pin fails alone and the response is an authentication challenge', async () => {
    const principal = generateKeyPair();
    const holder = generateKeyPair();
    const ml = mlDsa65Keygen(new Uint8Array(32).fill(7));
    const grant = mintRoot({
      principalSecret: principal.secretKey,
      principalPublic: encodeKey(principal.publicKey),
      holder: encodeKey(holder.publicKey),
      caveats: [{ type: 'ttl', secs: 3600 }],
      suite: { alg: 'ml-dsa-65', mlDsa: ml },
    });
    const plan = [{ id: 'n', verb: 'refund', resource: 'order/1', reversibility_class: 'reversible' as const }];
    const actn = buildPCActn({ grant, chain: [grant], plan, nodeId: 'n', counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
    const wrongPin = encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(8)).publicKey);
    const g = requirePCA({ audience: AUD, now: () => NOW, resolveGrant: async (ref) => (ref === grant.id ? grant : null), insecureAllowUnenforced: true, pqPins: { [grant.issuer]: wrongPin } });
    const r = await g({ headers: {}, body: { pcactn: actn } });
    expect(r.verdict.checks['pq_pin']).toBe('fail');
    for (const c of ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'leaf_signature', 'malformed', 'grant_ref']) {
      expect(r.verdict.checks[c], c).not.toBe('fail');
    }
    expect(r.ok).toBe(false);
    expect(!r.ok && r.status).toBe(401);
    expect(!r.ok && 'wwwAuthenticate' in r && r.wwwAuthenticate).toContain('error="invalid_pcactn"');
  });
});
