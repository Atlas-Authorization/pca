import { describe, expect, it } from 'vitest';
import { MemoryBlueprintStore } from './blueprint';
import { DEFAULT_RISK_POLICY, delegate, encodeKey, generateKeyPair, mintGrant, type AttestationDocument, type HardwareAttestationVerifier } from '@atlasauth/pca';
import { signerOf } from './sig';
import { BlueprintRegistry, checkBlueprints, groupKill, signBlueprint } from './blueprint';
import { AdmissionRegistry, admitBlueprintInstance } from './blueprint-admission';

const NOW = 1_800_000_000_000;
const principal = generateKeyPair();
const operator = generateKeyPair();
const bpKey = generateKeyPair();
const inst = generateKeyPair();
const BP = encodeKey(bpKey.publicKey);
const grant = mintGrant({ principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: BP, goal: 'g', envelope: { predicates: [{ verb: '*', resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY } }).grant;
const hop = delegate(grant, encodeKey(inst.publicKey), [], bpKey.secretKey);
const chain = [grant, hop].map((c) => ({ issuer: c.issuer, holder: c.holder }));
const pin = { runtime_measurement: 'rt-1', operator: 'acme' };
const bp = signBlueprint(operator.secretKey, { id: 'fleet', key: BP, ceiling: [], epoch: 1, status: 'active', issued_at: NOW, runtime_pins: [pin] });
const expected = { holderPub: encodeKey(inst.publicKey), grantRef: grant.id, epoch: 1, nonce: 'n'.repeat(24) };
const doc = {} as AttestationDocument;
const ctx = {} as never;
const verifier = (r: unknown): HardwareAttestationVerifier => ({ verify: async () => r as never });
const good = { ok: true, bound: true, measured: { model_id: 'm', weights_digest: 'w', runtime_measurement: 'rt-1', operator: 'acme' } };
const admit = (v: HardwareAttestationVerifier, document: AttestationDocument | undefined = doc) => admitBlueprintInstance({ blueprint: bp, document, verifier: v, ctx, expected, nowMs: NOW });

describe('attestation-gated blueprint admission - T-589', () => {
  it('admits on verified, bound evidence whose MEASURED identity matches a pin', async () => {
    expect(await admit(verifier(good))).toMatchObject({ admitted: true, pin });
  });
  it('everything unverifiable is a deny', async () => {
    expect(await admit(verifier(good), null as never)).toMatchObject({ admitted: false, code: 'not_ok' });
    expect(await admit(verifier({ ok: false, reason: 'bad quote' }))).toMatchObject({ admitted: false, code: 'not_ok', reason: 'bad quote' });
    expect(await admit(verifier({ ...good, bound: false }))).toMatchObject({ admitted: false, code: 'not_bound' });
    expect(await admit(verifier({ ok: true, bound: true }))).toMatchObject({ admitted: false, code: 'no_identity' });
    expect(await admit(verifier({ ...good, measured: { ...good.measured, runtime_measurement: 'rt-2' } }))).toMatchObject({ admitted: false, code: 'no_matching_pin' });
    expect(await admit({ verify: async () => { throw new Error('x'); } })).toMatchObject({ admitted: false, code: 'verifier_error' });
    expect(await admit(verifier(undefined))).toMatchObject({ admitted: false, code: 'not_ok' });
    // a blueprint without pins cannot admit anything
    const plain = signBlueprint(operator.secretKey, { id: 'p', key: BP, ceiling: [], epoch: 1, status: 'active', issued_at: NOW });
    expect(await admitBlueprintInstance({ blueprint: plain, document: doc, verifier: verifier(good), ctx, expected, nowMs: NOW })).toMatchObject({ admitted: false, code: 'no_pins' });
  });
  it('the document own claims are never the identity (only the verifier measurement counts)', async () => {
    const lying = { ...doc, runtime_measurement: 'rt-1' } as unknown as AttestationDocument;
    expect(await admit(verifier({ ...good, measured: { ...good.measured, runtime_measurement: 'other' } }), lying)).toMatchObject({ admitted: false, code: 'no_matching_pin' });
  });
  it('checkBlueprints refuses a pinned blueprint without admission, admits after, and a group kill voids the admission', async () => {
    const reg = new BlueprintRegistry([signerOf(operator.secretKey)], new MemoryBlueprintStore());
    await reg.accept(bp);
    expect(await checkBlueprints(chain, reg, { now: NOW, mode: 'require' })).toMatchObject({ code: 'admission_required' });
    const adm = new AdmissionRegistry();
    expect(await checkBlueprints(chain, reg, { now: NOW, mode: 'require', admitted: adm.checker(NOW) })).toMatchObject({ code: 'not_admitted' });
    adm.admit(encodeKey(inst.publicKey), bp, NOW + 1000);
    expect(await checkBlueprints(chain, reg, { now: NOW, mode: 'require', admitted: adm.checker(NOW) })).toMatchObject({ decision: 'allow' });
    expect(await checkBlueprints(chain, reg, { now: NOW + 1000, mode: 'require', admitted: adm.checker(NOW + 1000) })).toMatchObject({ code: 'not_admitted' });
    // re-enable under a higher epoch: the old admission no longer counts
    await groupKill(operator.secretKey, reg, BP, { now: NOW });
    await reg.accept(signBlueprint(operator.secretKey, { id: 'fleet', key: BP, ceiling: [], epoch: 3, status: 'active', issued_at: NOW, runtime_pins: [pin] }));
    expect(await checkBlueprints(chain, reg, { now: NOW, mode: 'require', admitted: adm.checker(NOW) })).toMatchObject({ code: 'not_admitted' });
    expect(adm.revoke(encodeKey(inst.publicKey), BP)).toBe(true);
  });
  it('malformed pins make the record unsignable', () => {
    for (const runtime_pins of [[], [{}], [{ bogus: 'x' }], [{ operator: '' }]] as never[]) {
      expect(() => signBlueprint(operator.secretKey, { id: 'x', key: BP, ceiling: [], epoch: 1, status: 'active', issued_at: NOW, runtime_pins })).toThrow(RangeError);
    }
  });
});
