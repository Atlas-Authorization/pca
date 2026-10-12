/** verifyPCActn pq_pin residual mutants: the Ed25519 pass, the pq_pk-less PQ grant, and both refusal reasons exactly. */
import { describe, expect, it } from 'vitest';
import { encodeKey, generateKeyPair } from '../keys';
import { mintRoot } from '../capability';
import { buildPCActn } from '../pcactn';
import { encodeMlDsaPublicKey, mlDsa65Keygen } from '../pq';
import { verifyPCActn } from './verify';

const AUD = 'rs-mk4';
const NOW = Date.UTC(2026, 9, 11, 12, 0, 0);

function grantAndActn(pq: boolean) {
  const principal = generateKeyPair();
  const holder = generateKeyPair();
  const ml = mlDsa65Keygen(new Uint8Array(32).fill(7));
  const grant = mintRoot({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    caveats: [{ type: 'ttl', secs: 3600 }],
    ...(pq ? { suite: { alg: 'ml-dsa-65' as const, mlDsa: ml } } : {}),
  });
  const plan = [{ id: 'n', verb: 'refund', resource: 'order/1', reversibility_class: 'reversible' as const }];
  const actn = buildPCActn({ grant, chain: [grant], plan, nodeId: 'n', counter: 1, signerSecret: holder.secretKey, aud: AUD, now: NOW });
  return { grant, actn };
}

describe('verifyPCActn pq_pin', () => {
  it('an Ed25519 grant passes pq_pin even with an empty pin table', async () => {
    const { grant, actn } = grantAndActn(false);
    expect(grant.alg).toBeUndefined();
    const v = await verifyPCActn(actn, { grant, audience: AUD, now: NOW, pqPins: {} });
    expect(v.checks['pq_pin']).toBe('pass');
    expect(v.reasons.filter((r) => r.startsWith('pq_pin'))).toEqual([]);
  });
  it('missing pin and wrong pin carry their exact reasons', async () => {
    const { grant, actn } = grantAndActn(true);
    const missing = await verifyPCActn(actn, { grant, audience: AUD, now: NOW, pqPins: {} });
    expect(missing.checks['pq_pin']).toBe('fail');
    expect(missing.reasons).toContain('pq_pin: no server-side PQ pin for the grant issuer (suite ml-dsa-65)');
    const other = encodeMlDsaPublicKey(mlDsa65Keygen(new Uint8Array(32).fill(8)).publicKey);
    const wrong = await verifyPCActn(actn, { grant, audience: AUD, now: NOW, pqPins: { [grant.issuer]: other } });
    expect(wrong.checks['pq_pin']).toBe('fail');
    expect(wrong.reasons).toContain('pq_pin: the grant pq_pk does not match the server-side pin');
  });
  it('a PQ grant without pq_pk never matches an absent pin', async () => {
    const { grant, actn } = grantAndActn(true);
    const { pq_pk: _drop, ...noPk } = grant;
    const v = await verifyPCActn(actn, { grant: noPk as typeof grant, audience: AUD, now: NOW, pqPins: {} });
    expect(v.checks['pq_pin']).toBe('fail');
    expect(v.reasons).toContain('pq_pin: no server-side PQ pin for the grant issuer (suite ml-dsa-65)');
  });
});
