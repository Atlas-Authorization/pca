/**
 * Fail-closed table for the attestation hook: every row is "missing / invalid X => exact result". A row passes only
 * when the WHOLE settled result equals the expectation, so a regression that turns a denial into a pass (or into a
 * different denial) fails here. Software mode with the sanctioned reference attestor, the hardware seam with doubles.
 */
import { describe, expect, it } from 'vitest';
import {
  type AttestationDocument, type AttestationVerifierOpts, type HardwareAttestationResult, type HardwareAttestationVerifier, type ExpectedAttestationBinding,
  attestationRegistry, createAttestationVerifier, createDevAttestor, memoryNonceStore,
} from './attestation';
import { assuranceLabelOf, setAssuranceLabel } from './assurance';
import { mintGrant } from './envelope';
import { encodeKey, generateKeyPair } from './keys';
import { buildPCActn, type VerifyContext } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';

const T = 1_000_000;
const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs'; // 16 bytes of base64url, 8+ distinct symbols
const P = generateKeyPair();
const A = generateKeyPair();
const HOLDER = encodeKey(A.publicKey);
const attestor = createDevAttestor(generateKeyPair().secretKey);

function rig(over: { grantBinding?: Record<string, unknown> } = {}) {
  const { grant } = mintGrant({
    principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: HOLDER, goal: 'g',
    envelope: { predicates: [{ verb: 'read', resource: '/a/*' }], caveats: [], agent_binding: over.grantBinding ?? { model_allowlist: ['m'] }, risk_policy: DEFAULT_RISK_POLICY },
  });
  const p = buildPCActn({
    aud: 'x', grant, chain: [grant], plan: [{ id: 'n1', verb: 'read', resource: '/a/1', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: A.secretKey,
    attestation: { quote_digest: NONCE, epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
  });
  return { ctx: { pcactn: p, grant } as VerifyContext, grantRef: p.grant_ref };
}
const claims = (r: ReturnType<typeof rig>, o: Partial<{ issued_at: number; expires_at: number; nonce: string; model_id: string }> = {}) => ({
  model_id: 'm', weights_digest: 'w', runtime_measurement: 'x', operator: 'o', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000,
  holder_pub: HOLDER, grant_ref: r.grantRef, epoch: 1, ...o,
});
type Cfg = Partial<AttestationVerifierOpts>;
function hook(r: ReturnType<typeof rig>, doc: AttestationDocument | undefined, cfg: Cfg = {}, binding: Partial<ExpectedAttestationBinding> | null = {}) {
  return createAttestationVerifier({
    trustedAttestorKeys: [attestor.publicKey],
    resolveDocument: attestationRegistry(doc ? [doc] : []),
    ...(binding === null ? {} : { expectedBinding: (ctx: VerifyContext) => ({ holderPub: HOLDER, grantRef: ctx.pcactn.grant_ref, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000, ...binding }) }),
    now: () => T,
    ...cfg,
  });
}
const settle = async (h: ReturnType<typeof hook>, ctx: VerifyContext) => {
  const r = await h(ctx);
  return { enforced: r.enforced, ok: (r as { ok?: boolean }).ok, present: r.present, bound: r.bound, reason: (r as { reason?: string }).reason };
};
const OK = { enforced: true, ok: true, present: true, bound: true, reason: undefined };
const deny = (reason: string, present = true) => ({ enforced: true, ok: false, present, bound: false, reason });

describe('software attestation: missing or invalid X => exact denial', () => {
  const r0 = rig();
  const good = attestor.attest(claims(r0));

  it('the baseline passes', async () => {
    expect(await settle(hook(r0, good), r0.ctx)).toEqual(OK);
  });

  const rows: Array<[string, () => Promise<unknown>, unknown]> = [
    ['no document for the action', () => settle(hook(r0, undefined), r0.ctx), deny('no attestation document for this action', false)],
    ['no server-issued binding configured (no expectedBinding)', () => settle(hook(r0, good, {}, null), r0.ctx), deny('no server-issued attestation nonce/binding available (fail closed)', true)],
    ['expectedBinding returns nothing', () => settle(hook(r0, good, { expectedBinding: () => undefined }, {}), r0.ctx), deny('no server-issued attestation nonce/binding available (fail closed)', true)],
    ['expectedBinding throws', () => settle(hook(r0, good, { expectedBinding: () => { throw new Error('nonce store down'); } }, {}), r0.ctx), deny('attestation verification error (fail closed): nonce store down', false)],
    ['unknown attestor key', () => settle(hook(r0, good, { trustedAttestorKeys: [createDevAttestor(generateKeyPair().secretKey).publicKey] }), r0.ctx), deny('attestor key is not trusted')],
    ['no trusted attestor keys at all', () => settle(hook(r0, good, { trustedAttestorKeys: [] }), r0.ctx), deny('attestor key is not trusted')],
    ['tampered measurement after signing', () => settle(hook(r0, { ...good, runtime_measurement: 'evil' }), r0.ctx), deny('attestation signature does not verify')],
    ['unsigned document (sig removed)', () => settle(hook(r0, { ...good, sig: '' }), r0.ctx), deny('attestation signature does not verify')],
    ['unknown signature algorithm', () => settle(hook(r0, { ...good, alg: 'rot13' as never }), r0.ctx), deny('attestation declares an unknown signature alg')],
    ['document nonce differs from the server nonce (resolver returns it anyway)', () => settle(hook(r0, attestor.attest(claims(r0, { nonce: 'other-nonce-value-0123456789' })), { resolveDocument: (() => attestor.attest(claims(r0, { nonce: 'other-nonce-value-0123456789' }))) }), r0.ctx), deny('attestation nonce does not match the server-issued nonce')],
    ['no document registered under the expected nonce (registry miss)', () => settle(hook(r0, attestor.attest(claims(r0, { nonce: 'other-nonce-value-0123456789' }))), r0.ctx), deny('no attestation document for this action', false)],
    ['document expired', () => settle(hook(r0, attestor.attest(claims(r0, { issued_at: T - 9000, expires_at: T - 1 }))), r0.ctx), deny('attestation expired')],
    ['document not yet valid (clock behind by 10s, no skew allowed)', () => settle(hook(r0, attestor.attest(claims(r0, { issued_at: T + 10_000, expires_at: T + 60_000 }))), r0.ctx), deny('attestation not yet valid')],
    ['server nonce older than the ceiling', () => settle(hook(r0, good, {}, { nonceIssuedAt: T - 5 * 60_000 - 1 }), r0.ctx), deny('attestation nonce expired (stale quote)')],
    ['software: nonce issue time unknown falls back to the signed validity window (documented weaker freshness)', () => settle(hook(r0, good, {}, { nonceIssuedAt: undefined }), r0.ctx), OK],
    ['nonce issued in the future (clock skew)', () => settle(hook(r0, good, {}, { nonceIssuedAt: T + 1000 }), r0.ctx), deny('nonce issued in the future')],
    ['low-entropy nonce', () => settle(hook(r0, good, {}, { nonce: 'short' }), r0.ctx), deny('attestation nonce has less than 128 bits of entropy (F-5; use a CSPRNG nonce of >= 16 bytes)')],
    ['binding for another holder', () => settle(hook(r0, good, {}, { holderPub: 'someone-else' }), r0.ctx), deny('attestation binding mismatch (holder/grant/epoch/nonce)')],
    ['binding for another epoch', () => settle(hook(r0, good, {}, { epoch: 2 }), r0.ctx), deny('attestation binding: PCActn attestation epoch differs from expected epoch')],
    ['document without a binding', () => settle(hook(r0, attestor.attest({ ...claims(r0), holder_pub: undefined } as never)), r0.ctx), deny('attestation is not bound (binding absent)')],
    ['model not in the grant allowlist', () => settle(hook(r0, attestor.attest(claims(r0, { model_id: 'other' }))), r0.ctx), deny('model_id other not in model_allowlist')],
    ['a hardware-mode document handed to a software verifier', () => settle(hook(r0, { ...good, mode: 'hardware' }), r0.ctx), deny('document mode hardware needs a hardwareVerifier')],
  ];
  it.each(rows)('%s', async (_n, run, want) => {
    expect(await run()).toEqual(want);
  });

  it('a replayed quote is refused once a nonce store is wired, and a refused one does not burn the nonce', async () => {
    const store = memoryNonceStore();
    const h = hook(r0, good, { nonceStore: store });
    expect(await settle(h, r0.ctx)).toEqual(OK);
    expect(await settle(h, r0.ctx)).toEqual(deny('attestation nonce already consumed (replay)'));
    const store2 = memoryNonceStore();
    expect(await settle(hook(r0, { ...good, runtime_measurement: 'evil' }, { nonceStore: store2 }), r0.ctx)).toEqual(deny('attestation signature does not verify'));
    expect(store2.consume(NONCE)).toBe(true); // still unspent
  });
});

describe('hardware seam: missing or invalid X => exact denial, labels honest', () => {
  const r0 = rig();
  const doc = attestor.attest(claims(r0));
  const ident = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'x', operator: 'o' };
  const hw = (res: HardwareAttestationResult | (() => HardwareAttestationResult | undefined), label: { level: string } | null = { level: 'hardware' }): HardwareAttestationVerifier => {
    const v = { verify: () => (typeof res === 'function' ? res() : res) } as unknown as HardwareAttestationVerifier;
    return label ? setAssuranceLabel(v, label) : v;
  };
  const rows: Array<[string, HardwareAttestationVerifier, unknown]> = [
    ['an invalid quote', hw({ ok: false, reason: 'cert chain invalid' }), deny('hardware attestation rejected: cert chain invalid')],
    ['an invalid quote with no reason', hw({ ok: false }), deny('hardware attestation rejected: invalid')],
    ['a valid quote not reported bound', hw({ ok: true, measured: ident }), deny('hardware verifier did not confirm report_data binding')],
    ['a valid bound quote with no measured identity', hw({ ok: true, bound: true }), deny('hardware verifier returned no measured identity')],
    ['the verifier returns nothing', hw(() => undefined), deny('attestation verification error (fail closed): Cannot read properties of undefined (reading \'ok\')')],
    ['the verifier throws (collateral fetch failed)', hw(() => { throw new Error('PCS unreachable'); }), deny('attestation verification error (fail closed): PCS unreachable')],
  ];
  it.each(rows)('%s', async (_n, v, want) => {
    expect(await settle(hook(r0, doc, { hardwareVerifier: v }), r0.ctx)).toEqual(want);
  });
  it('hardware freshness comes from the server nonce issue time: unknown or stale denies', async () => {
    const v = hw({ ok: true, bound: true, measured: ident });
    expect(await settle(hook(r0, doc, { hardwareVerifier: v }, { nonceIssuedAt: undefined }), r0.ctx)).toEqual(deny('server nonce issue time unknown (cannot establish freshness)'));
    expect(await settle(hook(r0, doc, { hardwareVerifier: v }, { nonceIssuedAt: T - 5 * 60_000 - 1 }), r0.ctx)).toEqual(deny('attestation nonce expired (stale quote)'));
    expect(await settle(hook(r0, doc, { hardwareVerifier: v }, { nonceIssuedAt: T - 5 * 60_000 }), r0.ctx)).toEqual(OK); // the ceiling itself is inclusive
  });
  it('a bound, measured quote passes with the measured identity matched against the grant, not the document', async () => {
    const lying = attestor.attest(claims(r0, { model_id: 'm' }));
    expect(await settle(hook(r0, lying, { hardwareVerifier: hw({ ok: true, bound: true, measured: { ...ident, model_id: 'swapped' } }) }), r0.ctx)).toEqual(deny('model_id swapped not in model_allowlist'));
    expect(await settle(hook(r0, lying, { hardwareVerifier: hw({ ok: true, bound: true, measured: ident }) }), r0.ctx)).toEqual(OK);
  });
  it('labels come from the configuration: software, the hardware verifier, unknown for an unlabelled one or the self-declared-nonce opt-out', () => {
    expect(assuranceLabelOf(hook(r0, doc))).toEqual({ level: 'software' });
    expect(assuranceLabelOf(hook(r0, doc, { hardwareVerifier: hw({ ok: false }) }))).toEqual({ level: 'hardware' });
    expect(assuranceLabelOf(hook(r0, doc, { hardwareVerifier: hw({ ok: false }, null) }))).toEqual({ level: 'unknown' });
    expect(assuranceLabelOf(hook(r0, doc, { insecure_selfDeclaredNonce: true }))).toEqual({ level: 'unknown', vendor: 'insecure-self-declared-nonce' });
  });
});
