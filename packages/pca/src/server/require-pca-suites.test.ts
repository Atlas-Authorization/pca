import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '../keys';
import { mintRoot } from '../capability';
import { buildPCActn } from '../pcactn';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from '../pq';
import { requirePCA as requirePCA05 } from './require-pca';
import { verifyPCActn as verifyPCActn05 } from './verify';
const requirePCA = (o: Parameters<typeof requirePCA05>[0]): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o }); // unbound and single-instance on purpose: these tests are not about operation binding or store scope (see breaking-05.test.ts)
const verifyPCActn = (p: Parameters<typeof verifyPCActn05>[0], o: Parameters<typeof verifyPCActn05>[1]): ReturnType<typeof verifyPCActn05> => verifyPCActn05(p, 'require' in o ? o : Object.create(o, { require: { value: [], enumerable: true } })); // report-only: these tests are not about the 0.5 default required checks (see breaking-05.test.ts)


/**
 * R6-CORE-04 follow-up: requirePCA takes the same suite policy (`allowedSuites`) and server-side PQ pins (`pqPins`) as
 * verifyPCActn, fail closed. A registered pure-PQ grant verifies only when the server accepts its suite, and, when the
 * server pins PQ keys, only when the grant's `pq_pk` equals the pin for its issuer.
 */
const AUD = 'rs-suites';
const NOW = Date.UTC(2026, 9, 11, 12, 0, 0);

function pqGrant() {
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
  return { grant, actn, pin: encodeMlDsaPublicKey(ml.publicKey) };
}

const guard = (grant: ReturnType<typeof pqGrant>['grant'], extra: Record<string, unknown>) =>
  requirePCA({ audience: AUD, now: () => NOW, resolveGrant: async (ref) => (ref === grant.id ? grant : null), insecureAllowUnenforced: true, ...extra });

describe('requirePCA: allowedSuites / pqPins', () => {
  it('control: without a suite policy the registered pure-PQ grant chain verifies', async () => {
    const { grant, actn } = pqGrant();
    const r = await guard(grant, {})({ headers: {}, body: { pcactn: actn } });
    expect(r.verdict.checks['cap_chain']).toBe('pass');
  });

  it('allowedSuites: [ed25519] refuses the pure-PQ grant (401, cap_chain fail)', async () => {
    const { grant, actn } = pqGrant();
    const r = await guard(grant, { allowedSuites: ['ed25519'] })({ headers: {}, body: { pcactn: actn } });
    expect(r.ok).toBe(false);
    expect(r.verdict.checks['cap_chain']).toBe('fail');
    expect(!r.ok && r.status).toBe(401);
  });

  it('allowedSuites is snapshotted: mutating the caller array later does not widen it', async () => {
    const { grant, actn } = pqGrant();
    const suites: string[] = ['ed25519'];
    const g = guard(grant, { allowedSuites: suites });
    suites.push('ml-dsa-65');
    const r = await g({ headers: {}, body: { pcactn: actn } });
    expect(r.verdict.checks['cap_chain']).toBe('fail');
  });

  it('pqPins: a wrong or missing pin for the grant issuer denies; the right pin passes', async () => {
    const { grant, actn, pin } = pqGrant();
    const wrong = await guard(grant, { pqPins: { [grant.issuer]: encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(8)).publicKey) } })({ headers: {}, body: { pcactn: actn } });
    expect(wrong.ok).toBe(false);
    expect(wrong.verdict.checks['pq_pin']).toBe('fail');
    const missing = await guard(grant, { pqPins: {} })({ headers: {}, body: { pcactn: actn } });
    expect(missing.ok).toBe(false);
    expect(missing.verdict.checks['pq_pin']).toBe('fail');
    const right = await guard(grant, { pqPins: { [grant.issuer]: pin } })({ headers: {}, body: { pcactn: actn } });
    expect(right.verdict.checks['pq_pin']).toBe('pass');
    expect(right.verdict.checks['cap_chain']).toBe('pass');
  });

  it('verifyPCActn applies pqPins the same way (and leaves an ed25519 grant unaffected)', async () => {
    const { grant, actn, pin } = pqGrant();
    const bad = await verifyPCActn(actn, { grant, audience: AUD, now: NOW, pqPins: {} });
    expect(bad.allow).toBe(false);
    expect(bad.checks['pq_pin']).toBe('fail');
    const good = await verifyPCActn(actn, { grant, audience: AUD, now: NOW, pqPins: { [grant.issuer]: pin } });
    expect(good.checks['pq_pin']).toBe('pass');
  });
});
