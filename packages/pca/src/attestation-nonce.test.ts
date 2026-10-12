import { describe, expect, it } from 'vitest';
import { attestationRegistry, createAttestationVerifier, createDevAttestor, memoryNonceStore, nonceEntropyOk } from './attestation';
import { enforced } from './attestation.test-util';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import { checkSevSnpPolicy, type ParsedSevSnpReport } from './hardware-sevsnp';

/** F-5: consume-once nonce store, entropy minimum, VMPL default. */
const T = 1_000_000;
const STRONG = 'q3Vx8mZ0aT7bLk2RwYp9Hs'; // 22 b64u chars, 16 bytes
const P = generateKeyPair();
const A = generateKeyPair();
const HOLDER = encodeKey(A.publicKey);

function rig(nonce: string, nonceStore?: ReturnType<typeof memoryNonceStore>) {
  const { grant } = mintGrant({
    principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: HOLDER, goal: 'g',
    envelope: { predicates: [{ verb: 'read', resource: '/a/*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  const p = buildPCActn({
    aud: 'x', grant, chain: [grant], plan: [{ id: 'n1', verb: 'read', resource: '/a/1', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1,
    signerSecret: A.secretKey, attestation: { quote_digest: nonce, epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
  });
  const attestor = createDevAttestor(generateKeyPair().secretKey);
  const doc = attestor.attest({ model_id: 'm', weights_digest: 'w', runtime_measurement: 'x', operator: 'o', nonce, issued_at: T - 1000, expires_at: T + 60_000, holder_pub: HOLDER, grant_ref: p.grant_ref, epoch: 1 });
  const verify = createAttestationVerifier({
    trustedAttestorKeys: [attestor.publicKey], resolveDocument: attestationRegistry([doc]),
    expectedBinding: (ctx) => ({ holderPub: HOLDER, grantRef: ctx.pcactn.grant_ref, epoch: 1, nonce, nonceIssuedAt: T - 1000 }),
    now: () => T, ...(nonceStore ? { nonceStore } : {}),
  });
  return { verify, ctx: { pcactn: p, grant } };
}

describe('F-5 attestation nonce', () => {
  it('a strong nonce verifies; the same quote replayed is refused once a nonceStore is wired', async () => {
    const store = memoryNonceStore();
    const { verify, ctx } = rig(STRONG, store);
    expect(await verify(ctx)).toMatchObject({ ok: true, bound: true });
    const again = await verify(ctx);
    expect(again).toMatchObject({ ok: false });
    expect((again as { reason: string }).reason).toMatch(/already consumed/);
  });

  it('a failed verification does not burn the nonce', async () => {
    const store = memoryNonceStore();
    expect(store.consume('other')).toBe(true);
    const { verify, ctx } = rig(STRONG, store);
    const bad = { ...ctx, pcactn: { ...ctx.pcactn, grant_ref: 'wrong' } };
    expect(enforced(await verify(bad)).ok).toBe(false);
    expect(enforced(await verify(ctx)).ok).toBe(true);
  });

  it('a low-entropy nonce is refused', async () => {
    const { verify, ctx } = rig('nonce-epoch-1');
    const r = await verify(ctx);
    expect(enforced(r).ok).toBe(false);
    expect((r as { reason: string }).reason).toMatch(/128 bits/);
  });

  it('nonceEntropyOk', () => {
    expect(nonceEntropyOk(STRONG)).toBe(true);
    expect(nonceEntropyOk('0123456789abcdef0123456789abcdef')).toBe(true);
    expect(nonceEntropyOk('a'.repeat(40))).toBe(false);
    expect(nonceEntropyOk('short')).toBe(false);
    expect(nonceEntropyOk(5)).toBe(false);
    expect(nonceEntropyOk(STRONG, 1)).toBe(true); // cannot be configured below 128 bits
    expect(nonceEntropyOk(STRONG.slice(0, 16), 1)).toBe(false);
  });
});

describe('F-5 SEV-SNP requireVmpl defaults to 0', () => {
  const rep = (vmpl: number) => ({ vmpl, signature_algo: 1, policy: 0n, guest_svn: 0, reported_tcb: 0n, committed_tcb: 0n, launch_tcb: 0n, measurement: new Uint8Array(48), chip_id: new Uint8Array(64) }) as unknown as ParsedSevSnpReport;
  it('rejects VMPL>0 by default, allows an explicit level or any', () => {
    expect(checkSevSnpPolicy(rep(2), {})).toMatch(/vmpl 2 is not the required 0/);
    expect(checkSevSnpPolicy(rep(0), {})).toBeNull();
    expect(checkSevSnpPolicy(rep(2), { requireVmpl: 2 })).toBeNull();
    expect(checkSevSnpPolicy(rep(3), { requireVmpl: 'any' })).toBeNull();
  });
});
