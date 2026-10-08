import { describe, expect, it } from 'vitest';
import {
  type AttestationDocument,
  type HardwareAttestationVerifier,
  attestationRegistry,
  attestationBinding,
  createAttestationVerifier,
  requiresAttestation,
  verifyAttestation,
  MAX_ATTESTATION_AGE_MS,
  createDevAttestor,
  matchAgentBinding,
} from './attestation';
import { mintGrant, type AgentBinding } from './envelope';
import { buildPCActn, type PCActn, type VerifyContext } from './pcactn';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';
import type { Capability } from './capability';

const P = generateKeyPair();
const A = generateKeyPair();
const NONCE = 'nonce-epoch-1';
const T = 1_000_000; // "now" in ms

const CLAIMS = {
  model_id: 'gpt-x',
  weights_digest: 'w-sha-1',
  runtime_measurement: 'm-launch-1',
  operator: 'acme-cloud',
  nonce: NONCE,
  issued_at: T - 1000,
  expires_at: T + 60_000,
};

function grantWith(binding: AgentBinding): Capability {
  return mintGrant({
    principalSecret: P.secretKey,
    principalPublic: encodeKey(P.publicKey),
    holder: encodeKey(A.publicKey),
    goal: 'secure my account',
    envelope: {
      predicates: [{ verb: 'read', resource: '/acct/*' }],
      caveats: [],
      agent_binding: binding,
      risk_policy: DEFAULT_RISK_POLICY,
    },
  }).grant;
}

function pcactn(grant: Capability, quoteDigest = NONCE): PCActn {
  const nodes = [{ id: 'n1', verb: 'read', resource: '/acct/1', reversibility_class: 'reversible' }];
  return buildPCActn({ aud: 'test-aud',
    grant,
    chain: [grant],
    plan: nodes,
    nodeId: 'n1',
    counter: 1,
    signerSecret: A.secretKey,
    attestation: { quote_digest: quoteDigest, epoch: 1, model_id: 'gpt-x', measurement: 'm-launch-1', operator: 'acme-cloud' },
  });
}

const HOLDER = encodeKey(A.publicKey);
/** Server-side expected binding for a PCActn (what the server derives + its issued nonce). */
const expectedFor = (ctx: VerifyContext) => ({ holderPub: HOLDER, grantRef: ctx.pcactn.grant_ref, epoch: 1, nonce: NONCE, nonceIssuedAt: T - 1000 });
/** Claims bound to a grant's PCActn (holder/grant/epoch + nonce). */
const bindOf = (grant: Capability) => ({ holder_pub: HOLDER, grant_ref: pcactn(grant).grant_ref, epoch: 1 });

const FULL_BINDING: AgentBinding = {
  model_allowlist: ['gpt-x', 'gpt-y'],
  min_measurement: 'm-launch-1',
  operator: 'acme-cloud',
  weights_allowlist: ['w-sha-1'],
};

describe('createAttestationVerifier (L0, software mode)', () => {
  it('valid dev doc passes and binds to agent_binding', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey],
      resolveDocument: attestationRegistry([doc]),
      expectedBinding: expectedFor,
      now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: true, present: true, bound: true });
  });

  it('expired attestation fails', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...{ ...CLAIMS, issued_at: T - 10_000, expires_at: T - 5_000 }, ...bindOf(grant) });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey],
      resolveDocument: attestationRegistry([doc]),
      expectedBinding: expectedFor,
      now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/expired/);
  });

  it('attestor key not trusted fails', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [createDevAttestor(generateKeyPair().secretKey).publicKey], // a DIFFERENT key
      resolveDocument: attestationRegistry([doc]),
      expectedBinding: expectedFor,
      now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/not trusted/);
  });

  it('tampered document breaks the signature', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const tampered: AttestationDocument = { ...doc, weights_digest: 'w-EVIL' };
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey],
      resolveDocument: () => tampered,
      expectedBinding: expectedFor,
      now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/signature does not verify/);
  });

  it('model not in allowlist fails', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith({ ...FULL_BINDING, model_allowlist: ['only-other-model'] });
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey],
      resolveDocument: attestationRegistry([doc]),
      expectedBinding: expectedFor,
      now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/model_allowlist/);
  });

  it('weights not in weights_allowlist fails (model swap / fine-tune)', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith({ ...FULL_BINDING, weights_allowlist: ['w-DIFFERENT'] });
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey],
      resolveDocument: attestationRegistry([doc]),
      expectedBinding: expectedFor,
      now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/weights_digest/);
  });

  it('nonce mismatch (document does not bind to the PCActn) fails', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) }); // nonce = NONCE
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey],
      resolveDocument: () => doc, // return the doc regardless of the PCActn's quote_digest
      expectedBinding: expectedFor,
      now: () => T,
    });
    const p = pcactn(grant, 'a-different-nonce'); // PCActn declares a different attestation
    const res = await verify({ pcactn: p, grant });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/nonce does not bind/);
  });

  it('no document resolved fails closed', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith(FULL_BINDING);
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey],
      resolveDocument: attestationRegistry([]), // empty registry
      expectedBinding: expectedFor,
      now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false });
    expect((res as { reason: string }).reason).toMatch(/no attestation document/);
  });

  it('hardware seam: delegates authenticity and binds the hardware-measured identity', async () => {
    const grant = grantWith(FULL_BINDING);
    // A document whose SELF-ASSERTED fields lie, but the hardware verifier returns the true measured
    // identity — the agent_binding check runs against the hardware identity, so the lie is irrelevant.
    const lyingDoc: AttestationDocument = {
      model_id: 'LIE',
      weights_digest: 'LIE',
      runtime_measurement: 'LIE',
      operator: 'LIE',
      nonce: NONCE,
      issued_at: T - 1000,
      expires_at: T + 60_000,
      attestor: 'n/a',
      mode: 'hardware',
      sig: 'n/a',
    };
    const hw: HardwareAttestationVerifier = {
      verify: () => ({
        ok: true,
        bound: true,
        measured: { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' },
      }),
    };
    const verify = createAttestationVerifier({ trustedAttestorKeys: [], hardwareVerifier: hw, resolveDocument: () => lyingDoc, expectedBinding: expectedFor, now: () => T });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: true, present: true, bound: true });

    // A rejecting hardware verifier fails.
    const hwReject: HardwareAttestationVerifier = { verify: () => ({ ok: false, reason: 'bad report' }) };
    const verify2 = createAttestationVerifier({ trustedAttestorKeys: [], hardwareVerifier: hwReject, resolveDocument: () => lyingDoc, expectedBinding: expectedFor, now: () => T });
    const res2 = await verify2({ pcactn: pcactn(grant), grant });
    expect(res2).toMatchObject({ enforced: true, ok: false });
    expect((res2 as { reason: string }).reason).toMatch(/hardware attestation rejected/);
  });
});

describe('attestation binding (relay / freshness / required)', () => {
  const attestor = createDevAttestor(generateKeyPair().secretKey);
  const hookFor = (doc: AttestationDocument | undefined, over: Record<string, unknown> = {}) =>
    createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey],
      resolveDocument: () => doc,
      expectedBinding: expectedFor,
      now: () => T,
      ...over,
    });

  it('attestationBinding is deterministic, 64 bytes, and domain-separated per field', () => {
    const base = { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' };
    const a = attestationBinding(base);
    expect(a.length).toBe(64);
    expect(attestationBinding({ ...base })).toEqual(a);
    for (const diff of [{ holderPub: 'h2' }, { grantRef: 'g2' }, { epoch: 2 }, { nonce: 'n2' }]) {
      expect(attestationBinding({ ...base, ...diff })).not.toEqual(a);
    }
    // framing: ("ab","c") vs ("a","bc") must differ
    expect(attestationBinding({ ...base, holderPub: 'ab', grantRef: 'c' })).not.toEqual(attestationBinding({ ...base, holderPub: 'a', grantRef: 'bc' }));
    expect(() => attestationBinding({ ...base, nonce: '' })).toThrow();
  });

  it('relay: a genuine signed quote bound to a different holder / grant / epoch / nonce is rejected', async () => {
    const grant = grantWith(FULL_BINDING);
    const ref = pcactn(grant).grant_ref;
    const real = { holder_pub: HOLDER, grant_ref: ref, epoch: 1 };
    const cases: Array<[string, Partial<typeof real> & { nonce?: string }]> = [
      ['holder', { holder_pub: encodeKey(generateKeyPair().publicKey) }],
      ['grant', { grant_ref: 'some-other-grant' }],
      ['epoch', { epoch: 2 }],
    ];
    for (const [, over] of cases) {
      const doc = attestor.attest({ ...CLAIMS, ...real, ...over });
      const res = await hookFor(doc)({ pcactn: pcactn(grant), grant });
      expect(res).toMatchObject({ enforced: true, ok: false, present: true, bound: false });
      expect((res as { reason: string }).reason).toMatch(/binding mismatch/);
    }
    // a quote for another server nonce: document nonce differs from the issued one
    const otherNonce = attestor.attest({ ...CLAIMS, ...real, nonce: 'other-nonce' });
    const r2 = await hookFor(otherNonce)({ pcactn: pcactn(grant), grant });
    expect(r2).toMatchObject({ ok: false, bound: false });
    expect((r2 as { reason: string }).reason).toMatch(/server-issued nonce/);
  });

  it('an unbound document (no binding) is rejected with a clear reason', async () => {
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest(CLAIMS); // no holder/grant/epoch => no binding
    const res = await hookFor(doc)({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ ok: false, present: true, bound: false });
    expect((res as { reason: string }).reason).toMatch(/binding absent/);
  });

  it('fails closed when the server supplies no expected binding (and the loud opt-out is off)', async () => {
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const res = await hookFor(doc, { expectedBinding: undefined })({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ ok: false, present: true, bound: false });
    expect((res as { reason: string }).reason).toMatch(/server-issued/);
  });

  it('reports present:false/bound:false when there is no document (server can fail closed)', async () => {
    const grant = grantWith(FULL_BINDING);
    const res = await hookFor(undefined)({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false, present: false, bound: false });
  });

  it('PCActn must itself commit to the expected grant/epoch/nonce', async () => {
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const res = await hookFor(doc, { expectedBinding: (c: VerifyContext) => ({ ...expectedFor(c), epoch: 9 }) })({ pcactn: pcactn(grant), grant });
    expect((res as { reason: string }).reason).toMatch(/epoch/);
  });

  describe('hardware mode freshness derives from the server nonce, not document dates', () => {
    const hwOk: HardwareAttestationVerifier = {
      verify: () => ({ ok: true, bound: true, measured: { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' } }),
    };
    const spoofDoc: AttestationDocument = {
      model_id: 'x', weights_digest: 'x', runtime_measurement: 'x', operator: 'x', nonce: NONCE,
      issued_at: 0, expires_at: Number.MAX_SAFE_INTEGER, attestor: 'n/a', mode: 'hardware', sig: 'n/a',
    };
    it('a stale server nonce is rejected despite a document claiming to be valid forever', async () => {
      const grant = grantWith(FULL_BINDING);
      const v = hookFor(spoofDoc, { hardwareVerifier: hwOk, expectedBinding: (c: VerifyContext) => ({ ...expectedFor(c), nonceIssuedAt: T - MAX_ATTESTATION_AGE_MS - 1 }) });
      const res = await v({ pcactn: pcactn(grant), grant });
      expect(res).toMatchObject({ ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/nonce expired/);
    });
    it('unknown nonce issue time fails closed; a fresh nonce passes (document dates ignored)', async () => {
      const grant = grantWith(FULL_BINDING);
      const unknown = hookFor(spoofDoc, { hardwareVerifier: hwOk, expectedBinding: (c: VerifyContext) => ({ ...expectedFor(c), nonceIssuedAt: undefined }) });
      expect(await unknown({ pcactn: pcactn(grant), grant })).toMatchObject({ ok: false });
      const expired = { ...spoofDoc, issued_at: 0, expires_at: 1 };
      expect(await hookFor(expired, { hardwareVerifier: hwOk })({ pcactn: pcactn(grant), grant })).toMatchObject({ ok: true, present: true, bound: true });
    });
    it('a hardware verifier that does not confirm the report_data binding is rejected', async () => {
      const grant = grantWith(FULL_BINDING);
      const unbound: HardwareAttestationVerifier = { verify: () => ({ ok: true, measured: { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' } }) };
      const res = await hookFor(spoofDoc, { hardwareVerifier: unbound })({ pcactn: pcactn(grant), grant });
      expect(res).toMatchObject({ ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/did not confirm/);
    });
  });

  it('verifyAttestation exposes the verdict directly and requiresAttestation gates on agent_binding', async () => {
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const p = pcactn(grant);
    const v = await verifyAttestation({ document: doc, ctx: { pcactn: p, grant }, expected: expectedFor({ pcactn: p, grant }), nowMs: T, trustedAttestorKeys: [attestor.publicKey] });
    expect(v).toMatchObject({ ok: true, present: true, bound: true });
    expect(requiresAttestation(FULL_BINDING)).toBe(true);
    expect(requiresAttestation({})).toBe(false);
    expect(requiresAttestation(undefined)).toBe(false);
    expect(requiresAttestation({ model_allowlist: [] })).toBe(false);
  });

  it('insecure_selfDeclaredNonce opt-out still binds holder/grant/epoch', async () => {
    const grant = grantWith(FULL_BINDING);
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const v = hookFor(doc, { expectedBinding: undefined, insecure_selfDeclaredNonce: true });
    expect(await v({ pcactn: pcactn(grant), grant })).toMatchObject({ ok: true, bound: true });
    const wrong = attestor.attest({ ...CLAIMS, ...bindOf(grant), holder_pub: 'someone-else' });
    expect(await hookFor(wrong, { expectedBinding: undefined, insecure_selfDeclaredNonce: true })({ pcactn: pcactn(grant), grant })).toMatchObject({ ok: false });
  });
});

describe('matchAgentBinding', () => {
  const id = { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' };
  it('empty binding matches anything', () => {
    expect(matchAgentBinding(id, {})).toBeNull();
    expect(matchAgentBinding(id, undefined)).toBeNull();
  });
  it('each field is gated independently', () => {
    expect(matchAgentBinding(id, { model_allowlist: ['gpt-x'] })).toBeNull();
    expect(matchAgentBinding(id, { model_allowlist: ['no'] })).toMatch(/model_allowlist/);
    expect(matchAgentBinding(id, { min_measurement: 'm-launch-1' })).toBeNull();
    expect(matchAgentBinding(id, { min_measurement: 'other' })).toMatch(/min_measurement/);
    expect(matchAgentBinding(id, { operator: 'acme-cloud' })).toBeNull();
    expect(matchAgentBinding(id, { operator: 'evil' })).toMatch(/operator/);
  });
});

describe('min_measurement monotone ladder ({ svn })', () => {
  const at = (svn: number) => ({ model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: String(svn), operator: 'acme-cloud' });
  it('accepted svn > min passes (upgraded enclave, no re-mint)', () => {
    expect(matchAgentBinding(at(7), { min_measurement: { svn: 5 } })).toBeNull();
  });
  it('accepted svn == min passes (lower bound is inclusive)', () => {
    expect(matchAgentBinding(at(5), { min_measurement: { svn: 5 } })).toBeNull();
  });
  it('accepted svn < min fails (downgrade rejected)', () => {
    expect(matchAgentBinding(at(3), { min_measurement: { svn: 5 } })).toMatch(/below required min svn 5/);
  });
  it('a non-integer runtime measurement under an svn bound fails closed', () => {
    const opaque = { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' };
    expect(matchAgentBinding(opaque, { min_measurement: { svn: 5 } })).toMatch(/not an integer SVN/);
    expect(matchAgentBinding({ ...opaque, runtime_measurement: '' }, { min_measurement: { svn: 1 } })).toMatch(/not an integer SVN/);
    expect(matchAgentBinding({ ...opaque, runtime_measurement: '5.5' }, { min_measurement: { svn: 5 } })).toMatch(/not an integer SVN/);
  });
  it('exact-digest equality is unchanged (default path)', () => {
    const opaque = { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' };
    expect(matchAgentBinding(opaque, { min_measurement: 'm-launch-1' })).toBeNull();
    expect(matchAgentBinding(opaque, { min_measurement: 'm-launch-2' })).toMatch(/does not match required min_measurement/);
    // a numeric digest is still EQUALITY under the string form, not a ladder
    expect(matchAgentBinding(at(5), { min_measurement: '5' })).toBeNull();
    expect(matchAgentBinding(at(7), { min_measurement: '5' })).toMatch(/does not match required min_measurement/);
  });
  it('requiresAttestation is true for an { svn } lower bound', () => {
    expect(requiresAttestation({ min_measurement: { svn: 0 } })).toBe(true);
    expect(requiresAttestation({ min_measurement: '' })).toBe(false);
  });
});

describe('agent_binding.require_hardware (fail closed for TEE-rooted attestation)', () => {
  const hwMeasured = { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' };
  const hwOk: HardwareAttestationVerifier = { verify: () => ({ ok: true, bound: true, measured: hwMeasured }) };
  const hwDoc: AttestationDocument = {
    ...hwMeasured, nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000, attestor: 'n/a', mode: 'hardware', sig: 'n/a',
  };

  it('require_hardware true + software doc + no hardware verifier => fail closed', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const grant = grantWith({ ...FULL_BINDING, require_hardware: true });
    const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) }); // software mode
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [attestor.publicKey], // a trusted software key must NOT rescue it
      resolveDocument: attestationRegistry([doc]),
      expectedBinding: expectedFor,
      now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
    expect((res as { reason: string }).reason).toMatch(/require_hardware/);
  });

  it('require_hardware true + software doc even WITH a hardware verifier => fail (doc is not hardware-rooted)', async () => {
    const grant = grantWith({ ...FULL_BINDING, require_hardware: true });
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const softDoc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [], hardwareVerifier: hwOk, resolveDocument: () => softDoc, expectedBinding: expectedFor, now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: false, bound: false });
    expect((res as { reason: string }).reason).toMatch(/software mode|require_hardware/);
  });

  it('require_hardware true + valid hardware doc + hardware verifier => pass', async () => {
    const grant = grantWith({ ...FULL_BINDING, require_hardware: true });
    const verify = createAttestationVerifier({
      trustedAttestorKeys: [], hardwareVerifier: hwOk, resolveDocument: () => hwDoc, expectedBinding: expectedFor, now: () => T,
    });
    const res = await verify({ pcactn: pcactn(grant), grant });
    expect(res).toMatchObject({ enforced: true, ok: true, present: true, bound: true });
  });

  it('require_hardware absent/false is unchanged: a software doc still passes', async () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    for (const binding of [FULL_BINDING, { ...FULL_BINDING, require_hardware: false }]) {
      const grant = grantWith(binding);
      const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
      const verify = createAttestationVerifier({
        trustedAttestorKeys: [attestor.publicKey], resolveDocument: attestationRegistry([doc]), expectedBinding: expectedFor, now: () => T,
      });
      const res = await verify({ pcactn: pcactn(grant), grant });
      expect(res).toMatchObject({ enforced: true, ok: true, present: true, bound: true });
    }
  });

  it('requiresAttestation is true when only require_hardware is set', () => {
    expect(requiresAttestation({ require_hardware: true })).toBe(true);
    expect(requiresAttestation({ require_hardware: false })).toBe(false);
    expect(requiresAttestation({})).toBe(false);
  });
});

describe('provenance beyond weights: system_prompt_digest + tool_manifest_digest', () => {
  const SP = 'sp-digest-1';
  const TM = 'tm-digest-1';
  const idWith = (over: Partial<Record<'system_prompt_digest' | 'tool_manifest_digest', string>> = {}) => ({
    model_id: 'gpt-x',
    weights_digest: 'w-sha-1',
    runtime_measurement: 'm-launch-1',
    operator: 'acme-cloud',
    ...over,
  });

  describe('matchAgentBinding gates each digest like weights_allowlist', () => {
    it('system_prompt_allowlist: matching digest passes', () => {
      expect(matchAgentBinding(idWith({ system_prompt_digest: SP }), { system_prompt_allowlist: [SP, 'sp-other'] })).toBeNull();
    });
    it('system_prompt_allowlist: mismatching digest fails', () => {
      expect(matchAgentBinding(idWith({ system_prompt_digest: 'sp-EVIL' }), { system_prompt_allowlist: [SP] })).toMatch(/system_prompt_digest/);
    });
    it('system_prompt_allowlist: required-but-absent fails closed', () => {
      // identity carries NO system_prompt_digest, but the binding pins one
      expect(matchAgentBinding(idWith(), { system_prompt_allowlist: [SP] })).toMatch(/system_prompt_digest/);
    });
    it('tool_manifest_allowlist: matching / mismatching / absent matrix', () => {
      expect(matchAgentBinding(idWith({ tool_manifest_digest: TM }), { tool_manifest_allowlist: [TM] })).toBeNull();
      expect(matchAgentBinding(idWith({ tool_manifest_digest: 'tm-EVIL' }), { tool_manifest_allowlist: [TM] })).toMatch(/tool_manifest_digest/);
      expect(matchAgentBinding(idWith(), { tool_manifest_allowlist: [TM] })).toMatch(/tool_manifest_digest/);
    });
    it('both pinned together are both enforced', () => {
      expect(matchAgentBinding(idWith({ system_prompt_digest: SP, tool_manifest_digest: TM }), { system_prompt_allowlist: [SP], tool_manifest_allowlist: [TM] })).toBeNull();
      expect(matchAgentBinding(idWith({ system_prompt_digest: SP, tool_manifest_digest: 'tm-EVIL' }), { system_prompt_allowlist: [SP], tool_manifest_allowlist: [TM] })).toMatch(/tool_manifest_digest/);
    });
    it('neither specified => digests ignored (unchanged behaviour even when the identity carries them)', () => {
      expect(matchAgentBinding(idWith({ system_prompt_digest: SP, tool_manifest_digest: TM }), {})).toBeNull();
      expect(matchAgentBinding(idWith(), {})).toBeNull();
      // an empty allowlist is not a constraint
      expect(matchAgentBinding(idWith(), { system_prompt_allowlist: [], tool_manifest_allowlist: [] })).toBeNull();
    });
  });

  it('requiresAttestation is true when only a prompt/tool allowlist is set, false when empty', () => {
    expect(requiresAttestation({ system_prompt_allowlist: [SP] })).toBe(true);
    expect(requiresAttestation({ tool_manifest_allowlist: [TM] })).toBe(true);
    expect(requiresAttestation({ system_prompt_allowlist: [], tool_manifest_allowlist: [] })).toBe(false);
  });

  describe('end-to-end through the software verifier', () => {
    const attestor = createDevAttestor(generateKeyPair().secretKey);
    const verifyFor = (grant: Capability, doc: AttestationDocument) =>
      createAttestationVerifier({
        trustedAttestorKeys: [attestor.publicKey],
        resolveDocument: attestationRegistry([doc]),
        expectedBinding: expectedFor,
        now: () => T,
      })({ pcactn: pcactn(grant), grant });

    it('binding specifies system_prompt_digest + matching measured doc => pass', async () => {
      const grant = grantWith({ ...FULL_BINDING, system_prompt_allowlist: [SP] });
      const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant), system_prompt_digest: SP });
      expect(await verifyFor(grant, doc)).toMatchObject({ enforced: true, ok: true, present: true, bound: true });
    });
    it('mismatch => fail', async () => {
      const grant = grantWith({ ...FULL_BINDING, system_prompt_allowlist: [SP] });
      const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant), system_prompt_digest: 'sp-EVIL' });
      const res = await verifyFor(grant, doc);
      expect(res).toMatchObject({ ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/system_prompt_digest/);
    });
    it('required-but-absent (doc omits the measurement) => fail closed', async () => {
      const grant = grantWith({ ...FULL_BINDING, system_prompt_allowlist: [SP] });
      const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) }); // no system_prompt_digest measured
      const res = await verifyFor(grant, doc);
      expect(res).toMatchObject({ ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/system_prompt_digest/);
    });
    it('tool_manifest_digest: matching passes, absent fails closed', async () => {
      const grantOk = grantWith({ ...FULL_BINDING, tool_manifest_allowlist: [TM] });
      const docOk = attestor.attest({ ...CLAIMS, ...bindOf(grantOk), tool_manifest_digest: TM });
      expect(await verifyFor(grantOk, docOk)).toMatchObject({ ok: true, bound: true });

      const grantAbsent = grantWith({ ...FULL_BINDING, tool_manifest_allowlist: [TM] });
      const docAbsent = attestor.attest({ ...CLAIMS, ...bindOf(grantAbsent) });
      const res = await verifyFor(grantAbsent, docAbsent);
      expect(res).toMatchObject({ ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/tool_manifest_digest/);
    });
    it('neither specified => a doc carrying the digests still passes exactly as before', async () => {
      const grant = grantWith(FULL_BINDING); // no prompt/tool pins
      const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant), system_prompt_digest: SP, tool_manifest_digest: TM });
      expect(await verifyFor(grant, doc)).toMatchObject({ ok: true, bound: true });
    });
    it('a doc minted WITHOUT the new digests signs and verifies identically (backward compat)', async () => {
      const grant = grantWith(FULL_BINDING);
      const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) });
      expect(doc.system_prompt_digest).toBeUndefined();
      expect(doc.tool_manifest_digest).toBeUndefined();
      expect(await verifyFor(grant, doc)).toMatchObject({ ok: true, bound: true });
    });
  });

  describe('combined with require_hardware: self-asserted digest is rejected', () => {
    const SP_GOOD = SP;
    const hwMeasured = (over: Partial<Record<'system_prompt_digest' | 'tool_manifest_digest', string>> = {}) => ({
      model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud', ...over,
    });

    it('software doc self-asserting the right system_prompt_digest cannot satisfy a require_hardware pin', async () => {
      const attestor = createDevAttestor(generateKeyPair().secretKey);
      const grant = grantWith({ ...FULL_BINDING, system_prompt_allowlist: [SP_GOOD], require_hardware: true });
      // The software doc LIES that its prompt digest is the pinned one; require_hardware must reject it
      // before the digest is ever consulted (self-asserted measurement is worthless here).
      const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant), system_prompt_digest: SP_GOOD });
      const res = await createAttestationVerifier({
        trustedAttestorKeys: [attestor.publicKey],
        resolveDocument: attestationRegistry([doc]),
        expectedBinding: expectedFor,
        now: () => T,
      })({ pcactn: pcactn(grant), grant });
      expect(res).toMatchObject({ ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/require_hardware/);
    });

    it('require_hardware: the digest that counts is the hardware-measured one, not the document self-assertion', async () => {
      const grant = grantWith({ ...FULL_BINDING, system_prompt_allowlist: [SP_GOOD], require_hardware: true });
      // A hardware-mode doc whose self-asserted prompt digest is a LIE, but the hardware verifier
      // returns the TRUE measured prompt digest => passes on the hardware measurement.
      const hwDocLying: AttestationDocument = {
        model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud',
        system_prompt_digest: 'sp-LIE', tool_manifest_digest: 'tm-LIE',
        nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000, attestor: 'n/a', mode: 'hardware', sig: 'n/a',
      };
      const hwGood: HardwareAttestationVerifier = {
        verify: () => ({ ok: true, bound: true, measured: hwMeasured({ system_prompt_digest: SP_GOOD }) }),
      };
      const resOk = await createAttestationVerifier({
        trustedAttestorKeys: [], hardwareVerifier: hwGood, resolveDocument: () => hwDocLying, expectedBinding: expectedFor, now: () => T,
      })({ pcactn: pcactn(grant), grant });
      expect(resOk).toMatchObject({ ok: true, present: true, bound: true });

      // When the hardware-measured identity carries NO prompt digest, the pin fails closed even though
      // the document self-asserts the pinned value.
      const hwNoPrompt: HardwareAttestationVerifier = { verify: () => ({ ok: true, bound: true, measured: hwMeasured() }) };
      const resFail = await createAttestationVerifier({
        trustedAttestorKeys: [], hardwareVerifier: hwNoPrompt, resolveDocument: () => hwDocLying, expectedBinding: expectedFor, now: () => T,
      })({ pcactn: pcactn(grant), grant });
      expect(resFail).toMatchObject({ ok: false, bound: false });
      expect((resFail as { reason: string }).reason).toMatch(/system_prompt_digest/);
    });
  });
});

describe('weights-level attestation: require_measured_weights (hardware-rooted weights)', () => {
  const id = (over: Partial<MeasuredIdentityForTest> = {}) => ({
    model_id: 'gpt-x',
    weights_digest: 'w-sha-1',
    runtime_measurement: 'm-launch-1',
    operator: 'acme-cloud',
    ...over,
  });

  describe('matchAgentBinding gates provenance only when require_measured_weights is set', () => {
    it('hardware-measured digest in allowlist passes', () => {
      expect(matchAgentBinding(id({ weights_measured: true }), { weights_allowlist: ['w-sha-1'], require_measured_weights: true })).toBeNull();
    });
    it('self-asserted digest (no weights_measured flag) fails closed even if the value is allowlisted', () => {
      expect(matchAgentBinding(id(), { weights_allowlist: ['w-sha-1'], require_measured_weights: true })).toMatch(/not hardware-measured/);
    });
    it('explicitly non-measured digest (weights_measured:false, e.g. host-asserted) fails closed', () => {
      expect(matchAgentBinding(id({ weights_measured: false }), { weights_allowlist: ['w-sha-1'], require_measured_weights: true })).toMatch(/not hardware-measured/);
    });
    it('measured but value NOT in allowlist still fails the allowlist check', () => {
      expect(matchAgentBinding(id({ weights_measured: true, weights_digest: 'w-EVIL' }), { weights_allowlist: ['w-sha-1'], require_measured_weights: true })).toMatch(/not in weights_allowlist/);
    });
    it('require_measured_weights with NO allowlist still demands the digest be measured', () => {
      expect(matchAgentBinding(id({ weights_measured: true }), { require_measured_weights: true })).toBeNull();
      expect(matchAgentBinding(id(), { require_measured_weights: true })).toMatch(/not hardware-measured/);
    });
    it('BACKWARD-COMPAT: a plain weights_allowlist (no require_measured_weights) matches by value, provenance ignored', () => {
      expect(matchAgentBinding(id(), { weights_allowlist: ['w-sha-1'] })).toBeNull(); // self-asserted still allowed
      expect(matchAgentBinding(id({ weights_measured: true }), { weights_allowlist: ['w-sha-1'] })).toBeNull();
      expect(matchAgentBinding(id({ weights_digest: 'w-EVIL' }), { weights_allowlist: ['w-sha-1'] })).toMatch(/not in weights_allowlist/);
    });
  });

  it('requiresAttestation is true when only require_measured_weights is set, false otherwise', () => {
    expect(requiresAttestation({ require_measured_weights: true })).toBe(true);
    expect(requiresAttestation({ require_measured_weights: false })).toBe(false);
  });

  describe('end-to-end: a SOFTWARE doc cannot satisfy require_measured_weights (self-asserted)', () => {
    it('software doc self-asserting the allowlisted weights fails closed', async () => {
      const attestor = createDevAttestor(generateKeyPair().secretKey);
      // weights are self-asserted in software mode; the pinned value matches the doc, but it must still fail.
      const grant = grantWith({ ...FULL_BINDING, require_measured_weights: true });
      const doc = attestor.attest({ ...CLAIMS, ...bindOf(grant) }); // weights_digest = 'w-sha-1' (in allowlist)
      const res = await createAttestationVerifier({
        trustedAttestorKeys: [attestor.publicKey],
        resolveDocument: attestationRegistry([doc]),
        expectedBinding: expectedFor,
        now: () => T,
      })({ pcactn: pcactn(grant), grant });
      expect(res).toMatchObject({ ok: false, bound: false });
      expect((res as { reason: string }).reason).toMatch(/not hardware-measured/);
    });

    it('a hardware verifier that returns weights_measured:true satisfies the pin', async () => {
      const grant = grantWith({ ...FULL_BINDING, require_measured_weights: true });
      const hwDoc: AttestationDocument = {
        model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud',
        nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000, attestor: 'n/a', mode: 'hardware', sig: 'n/a',
      };
      const hwMeasured: HardwareAttestationVerifier = {
        verify: () => ({ ok: true, bound: true, measured: { model_id: 'gpt-x', weights_digest: 'w-sha-1', weights_measured: true, runtime_measurement: 'm-launch-1', operator: 'acme-cloud' } }),
      };
      const resOk = await createAttestationVerifier({ trustedAttestorKeys: [], hardwareVerifier: hwMeasured, resolveDocument: () => hwDoc, expectedBinding: expectedFor, now: () => T })({ pcactn: pcactn(grant), grant });
      expect(resOk).toMatchObject({ ok: true, present: true, bound: true });

      // the SAME hardware verifier WITHOUT the measured flag fails closed under the pin
      const hwUnmeasured: HardwareAttestationVerifier = {
        verify: () => ({ ok: true, bound: true, measured: { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud' } }),
      };
      const resFail = await createAttestationVerifier({ trustedAttestorKeys: [], hardwareVerifier: hwUnmeasured, resolveDocument: () => hwDoc, expectedBinding: expectedFor, now: () => T })({ pcactn: pcactn(grant), grant });
      expect(resFail).toMatchObject({ ok: false, bound: false });
      expect((resFail as { reason: string }).reason).toMatch(/not hardware-measured/);
    });
  });
});

type MeasuredIdentityForTest = {
  model_id: string;
  weights_digest: string;
  weights_measured?: boolean;
  runtime_measurement: string;
  operator: string;
  system_prompt_digest?: string;
  tool_manifest_digest?: string;
};

// Compile-time: the verifier is assignable to the AttestationVerifier hook type.
const _hook: (ctx: VerifyContext) => unknown = createAttestationVerifier({ trustedAttestorKeys: [] });
void _hook;
