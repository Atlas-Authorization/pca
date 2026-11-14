import { describe, expect, it } from 'vitest';
import { setAssuranceLabel } from '../assurance';
import type { HardwareAttestationVerifier } from '../attestation';
import { mintGrant } from '../envelope';
import { b64u } from '../hash';
import { encodeKey, generateKeyPair, publicKeyOf } from '../keys';
import { paramsDigest, type PlanNode } from '../merkle';
import { buildPCActn, encodePCActn } from '../pcactn';
import { issuePassport, signPassport, type SignedPassport } from '../passport';
import type { RiskPolicy } from '../risk';
import { createAuthorizer, missingAuthorizeComponents, type AuthorizeOptions } from './authorize';
import { memoryPcaStore } from './require-pca';
import { principalDirect } from '../test-support/provenance';

const SPEND_POLICY: RiskPolicy = { weights: { alpha: 0, beta: 0, gamma: 1, delta: 0, epsilon: 0, zeta: 0 }, theta1: 1, theta2: 1, kappa: 100, lambda: 0, rho: 0.5, bMax: 1_000_000 };
const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);
const AUD = 'rs';
const principal = generateKeyPair();
const holder = generateKeyPair();
const hPub = encodeKey(holder.publicKey);
const grant = mintGrant({
  principalSecret: principal.secretKey, principalPublic: encodeKey(principal.publicKey), holder: hPub, goal: 'g',
  envelope: { predicates: [{ verb: ['do'], resource: '*', where: [] }], caveats: [], agent_binding: {}, risk_policy: SPEND_POLICY },
}).grant;
const ISS_SECRET = new Uint8Array(32).fill(1);
const ISS = b64u(publicKeyOf(ISS_SECRET));
const ident = { model_id: 'm', weights_digest: 'w', operator: 'acme', hardware_rooted: false, weights_measured: true, issued_at: NOW - 1 };
const pp = (subject = hPub, hw = false): SignedPassport =>
  signPassport(issuePassport({ ...ident, hardware_rooted: hw }), { issuerSecret: ISS_SECRET, subject, exp: NOW + 60_000, ...(hw ? { evidence: { document: { nonce: 'n' } as never } } : {}) });
let counter = 0;
const params = { payee: 'acme', amount: 1 };
const operation = { verb: 'do', resource: 'r', params };
const act = () => {
  const node: PlanNode = { id: 'n1', verb: 'do', resource: 'r', params_digest: paramsDigest(params), reversibility_class: 'reversible' };
  return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n1', params, counter: ++counter, signerSecret: holder.secretKey, aud: AUD, now: NOW });
};
const options = (over: Partial<AuthorizeOptions> = {}): AuthorizeOptions => ({
  provenance: principalDirect(),
  audience: AUD, resolveGrant: async (r) => (r === grant.id ? grant : null), budgetStore: memoryPcaStore(),
  hooks: { revocation: () => ({ enforced: true, ok: true }) }, plan: 'single-step', now: () => NOW,
  risk: (o) => ({ blastRadius: Math.min(1, Number(o?.params?.amount) / 100), semanticDistance: 0, reversibility: 0, taint: 0, confidence: 1 }), ...over,
});
const rp = (over: Record<string, unknown> = {}) => ({ trustedIssuers: [ISS], revocation: () => false, now: () => NOW, ...over });
const hw = (over = {}): HardwareAttestationVerifier => setAssuranceLabel({ verify: () => ({ ok: true, bound: true, measured: { model_id: 'm', weights_digest: 'w', weights_measured: true, runtime_measurement: '1', operator: 'acme' }, ...over }) }, { level: 'hardware', vendor: 'amd-sev-snp' });

describe('authorize + requirePassport', () => {
  it('default behaviour is unchanged without the option (no passport needed, none reported)', async () => {
    const r = await createAuthorizer(options())({ operation, pcactn: act() });
    expect(r.allow).toBe(true);
    expect(r).not.toHaveProperty('passport');
    if (r.allow) expect(r.assurance).not.toHaveProperty('passport');
  });
  it('a missing trust list or revocation source denies with the component name', async () => {
    expect(missingAuthorizeComponents(options({ requirePassport: rp({ trustedIssuers: [] }) }))).toEqual(['requirePassport.trustedIssuers']);
    expect(missingAuthorizeComponents(options({ requirePassport: rp({ revocation: undefined }) }))).toEqual(['requirePassport.revocation']);
    const r = await createAuthorizer(options({ requirePassport: rp({ revocation: undefined }) }))({ operation, pcactn: act(), passport: pp() });
    expect(r).toMatchObject({ allow: false, status: 403, missing: ['requirePassport.revocation'] });
  });
  it('allows with a valid passport for the presenting key and labels it software', async () => {
    const r = await createAuthorizer(options({ requirePassport: rp() }))({ operation, pcactn: act(), passport: pp() });
    expect(r.allow).toBe(true);
    if (r.allow) {
      expect(r.assurance.passport).toEqual({ outcome: 'pass', level: 'software' });
      expect(r.passport).toMatchObject({ ok: true, sub: hPub, hardware_verified: false });
    }
  });
  it('denies without a passport, with a passport for another key, and when revoked', async () => {
    const az = createAuthorizer(options({ requirePassport: rp() }));
    expect(await az({ operation, pcactn: act() })).toMatchObject({ allow: false, status: 403, reason: 'passport: malformed' });
    const other = b64u(publicKeyOf(new Uint8Array(32).fill(8)));
    expect(await az({ operation, pcactn: act(), passport: pp(other) })).toMatchObject({ allow: false, reason: 'passport: subject_mismatch', assurance: { passport: { outcome: 'fail' } } });
    const rev = createAuthorizer(options({ requirePassport: rp({ revocation: () => true }) }));
    expect(await rev({ operation, pcactn: act(), passport: pp() })).toMatchObject({ allow: false, reason: 'passport: revoked' });
  });
  it('a PCActn that fails is denied for its own reason even with a good passport; a passport refusal marks the verdict', async () => {
    const az = createAuthorizer(options({ requirePassport: rp() }));
    const r = await az({ operation: { ...operation, params: { payee: 'acme', amount: 2 } }, pcactn: act(), passport: pp() });
    expect(r).toMatchObject({ allow: false });
    if (!r.allow) expect(r.reason).not.toMatch(/^passport:/);
    const p = await az({ operation, pcactn: act() });
    if (p.allow) throw new Error('x');
    expect(p.verdict.allow).toBe(false);
    expect(p.verdict.checks.passport).toBe('fail');
  });
  it('a refused passport never consumes the PCActn: the same PCActn is then allowed with a valid passport', async () => {
    const az = createAuthorizer(options({ requirePassport: rp() }));
    const a = act();
    expect(await az({ operation, pcactn: a })).toMatchObject({ allow: false, reason: 'passport: malformed' });
    const other = b64u(publicKeyOf(new Uint8Array(32).fill(8)));
    expect(await az({ operation, pcactn: a, passport: pp(other) })).toMatchObject({ allow: false, reason: 'passport: subject_mismatch' });
    expect(await az({ operation, pcactn: a, passport: pp() })).toMatchObject({ allow: true });
    // and once admitted it is consumed as usual
    expect(await az({ operation, pcactn: a, passport: pp() })).toMatchObject({ allow: false });
  });
  it('reads the leaf from an encoded PCActn too, and an unreadable PCActn is left to the guard (never a passport verdict)', async () => {
    const az = createAuthorizer(options({ requirePassport: rp() }));
    const a = act();
    const enc = encodePCActn(a);
    expect(await az({ operation, pcactn: enc })).toMatchObject({ allow: false, reason: 'passport: malformed' });
    expect(await az({ operation, pcactn: enc, passport: pp() })).toMatchObject({ allow: true });
    const notPassport = async (x: unknown) => {
      const r = await az({ operation, pcactn: x as never });
      expect(r.allow).toBe(false);
      if (!r.allow) expect(r.reason.startsWith('passport:')).toBe(false);
    };
    await notPassport('garbage');
    await notPassport({});
    await notPassport({ ...act(), cap_chain: [] });
    await notPassport({ ...act(), cap_chain: undefined });
    await notPassport(null);
    await notPassport({ ...act(), cap_chain: [{ holder: 5 }] });
  });
  it('fails closed when the PCActn the guard verifies is not the one the passport was checked for', async () => {
    const a = act();
    const forged = { ...a, cap_chain: [{ ...grant, holder: b64u(publicKeyOf(new Uint8Array(32).fill(8))) }] };
    const other = b64u(publicKeyOf(new Uint8Array(32).fill(8)));
    let n = 0;
    const flip = createAuthorizer(options({ requirePassport: rp(), extract: () => (n++ === 0 ? (forged as never) : a) }));
    const flipped = await flip({ operation, passport: pp(other) });
    expect(flipped).toMatchObject({ allow: false, status: 403, reason: 'passport: subject_mismatch', assurance: { passport: { outcome: 'fail' } } });
    if (!flipped.allow) expect(flipped.verdict.checks).toEqual({ passport: 'fail' });
    let m = 0;
    const unreadableFirst = createAuthorizer(options({ requirePassport: rp(), extract: () => { if (m++ === 0) throw new Error('once'); return act(); } }));
    expect(await unreadableFirst({ operation, passport: pp() })).toMatchObject({ allow: false, reason: 'passport: subject_mismatch' });
  });
  it('hardware: demanded => software passport denied; hardware passport accepted only with a verifier and labelled hardware', async () => {
    const need = { hardware: true };
    const soft = await createAuthorizer(options({ requirePassport: rp(need) }))({ operation, pcactn: act(), passport: pp() });
    expect(soft).toMatchObject({ allow: false, status: 403, reason: 'passport: hardware_evidence_missing', assurance: { passport: { outcome: 'fail' } } });
    if (!soft.allow) expect(soft.verdict.checks).toEqual({ passport: 'fail' });
    expect(await createAuthorizer(options({ requirePassport: rp(need) }))({ operation, pcactn: act(), passport: pp(hPub, true) })).toMatchObject({ allow: false, reason: 'passport: hardware_verifier_missing' });
    const ok = await createAuthorizer(options({ requirePassport: rp({ ...need, attestationVerifier: hw() }) }))({ operation, pcactn: act(), passport: pp(hPub, true) });
    expect(ok.allow).toBe(true);
    if (ok.allow) expect(ok.assurance.passport).toEqual({ outcome: 'pass', level: 'hardware', vendor: 'amd-sev-snp' });
    const lying = await createAuthorizer(options({ requirePassport: rp({ ...need, attestationVerifier: hw({ ok: false }) }) }))({ operation, pcactn: act(), passport: pp(hPub, true) });
    expect(lying).toMatchObject({ allow: false, reason: 'passport: hardware_attestation_failed' });
  });
});
