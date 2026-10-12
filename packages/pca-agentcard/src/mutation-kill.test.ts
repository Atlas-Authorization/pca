/** Mutation-kill tests for pca-agentcard: exact shapes, reason strings, key forms, header contents, path normalisation. */
import { describe, expect, it, vi } from 'vitest';
import { type AgentPassport, canonicalBytes, issuePassport } from '@atlasauth/pca';
import { FlattenedSign, exportJWK, flattenedVerify, generateKeyPair } from 'jose';
import {
  type AgentCard,
  type AgentFacts,
  addAttestation,
  agentCardHandler,
  agentFactsHandler,
  buildAgentCard,
  issueAgentFacts,
  issueSignedAgentCard,
  toRegistryEntry,
  verifyAgentCard,
  verifyAgentFacts,
} from './index';

const NOW = 1_800_000_000_000;
const passport: AgentPassport = issuePassport({
  model_id: 'm',
  weights_digest: 'wd',
  system_prompt_digest: 'sp',
  tool_manifest_digest: 'tm',
  operator: 'op',
  hardware_rooted: true,
  weights_measured: true,
  issued_at: NOW,
});
const hdr = (s: { protected: string }): Record<string, unknown> => JSON.parse(Buffer.from(s.protected, 'base64url').toString('utf8'));
const keys = async (alg = 'EdDSA') => generateKeyPair(alg, { extractable: true });
const cardBytes = (c: AgentCard): Uint8Array => {
  const { signatures: _s, ...rest } = c;
  void _s;
  return canonicalBytes(rest);
};

describe('key input forms', () => {
  it('signs with a private JWK and verifies with a public JWK, default alg EdDSA', async () => {
    const { publicKey, privateKey } = await keys();
    const priv = await exportJWK(privateKey);
    const pub = await exportJWK(publicKey);
    const signed = await issueSignedAgentCard(buildAgentCard(passport, { name: 'a' }), priv);
    expect(hdr(signed.signatures![0]!).alg).toBe('EdDSA');
    expect((await verifyAgentCard(signed, { key: pub })).ok).toBe(true);
  });
  it('JWK with an explicit alg (ES256) is imported for that alg on sign and verify', async () => {
    const { publicKey, privateKey } = await keys('ES256');
    const priv = await exportJWK(privateKey);
    const pub = await exportJWK(publicKey);
    const signed = await issueSignedAgentCard(buildAgentCard(passport, { name: 'a' }), priv, { alg: 'ES256' });
    expect(hdr(signed.signatures![0]!).alg).toBe('ES256');
    expect((await verifyAgentCard(signed, { key: pub, alg: 'ES256' })).ok).toBe(true);
  });
  it('an RSA JWK needs the explicit alg to be imported on verify', async () => {
    const { publicKey, privateKey } = await keys('RS256');
    const pub = await exportJWK(publicKey);
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey, { alg: 'RS256' });
    expect((await verifyAgentCard(s, { key: pub, alg: 'RS256' })).ok).toBe(true);
  });
  it('CryptoKey and raw secret keys are passed through (not treated as JWKs)', async () => {
    const { publicKey, privateKey } = await keys();
    const s1 = await issueSignedAgentCard(buildAgentCard(passport, { name: 'a' }), privateKey);
    expect((await verifyAgentCard(s1, { key: publicKey })).ok).toBe(true);
    const secret = new Uint8Array(32).fill(7);
    const s2 = await issueSignedAgentCard(buildAgentCard(passport, { name: 'a' }), secret, { alg: 'HS256' });
    expect((await verifyAgentCard(s2, { key: secret })).ok).toBe(true);
  });
  it('a null or string key is not a JWK (fails at verification, not as a TypeError at resolve)', async () => {
    const { privateKey } = await keys();
    const s = await issueSignedAgentCard(buildAgentCard(passport, { name: 'a' }), privateKey);
    for (const k of [null, 'abc', 5]) {
      const r = await verifyAgentCard(s, { key: k as never });
      expect(r.ok).toBe(false);
      expect(r.reason).toMatch(/^signature 0 did not verify: /);
    }
  });
  it('an object without kty (a plain object) is not a JWK', async () => {
    const { privateKey } = await keys();
    const s = await issueSignedAgentCard(buildAgentCard(passport, { name: 'a' }), privateKey);
    const r = await verifyAgentCard(s, { key: { crv: 'Ed25519' } as never });
    expect(r.reason).toMatch(/^signature 0 did not verify: /);
  });
  it('no key and no JWKS', async () => {
    const { privateKey } = await keys();
    const s = await issueSignedAgentCard(buildAgentCard(passport, { name: 'a' }), privateKey);
    expect(await verifyAgentCard(s, {})).toStrictEqual({ ok: false, reason: 'no verification key or JWKS supplied' });
  });
  it('an unimportable JWK reports the import error', async () => {
    const { privateKey } = await keys();
    const s = await issueSignedAgentCard(buildAgentCard(passport, { name: 'a' }), privateKey);
    const r = await verifyAgentCard(s, { key: { kty: 'bogus' } as never });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^could not resolve verification key: .+/);
    expect(r.reason!.length).toBeGreaterThan('could not resolve verification key: '.length + 3);
  });
});

describe('buildAgentCard', () => {
  it('only the supplied optional fields appear, in strict shape', () => {
    expect(buildAgentCard(passport, { name: 'n' })).toStrictEqual({ name: 'n', pcaPassport: { id: passport.id } });
    expect(
      buildAgentCard(passport, {
        name: 'n',
        description: 'd',
        url: 'u',
        version: 'v',
        skills: [{ id: 's', name: 'S' }],
        passportUri: 'p',
        pcaProofRef: { verificationEndpoint: 'e' },
      }),
    ).toStrictEqual({
      name: 'n',
      description: 'd',
      url: 'u',
      version: 'v',
      skills: [{ id: 's', name: 'S' }],
      pcaPassport: { id: passport.id, uri: 'p' },
      pcaProof: { verificationEndpoint: 'e' },
    });
  });
  it('passport refs: own uri wins over the option; a full passport ignores a stray uri', () => {
    expect(buildAgentCard({ id: 'x', uri: 'own' }, { name: 'n' }).pcaPassport).toStrictEqual({ id: 'x', uri: 'own' });
    expect(buildAgentCard({ id: 'x', uri: 'own' }, { name: 'n', passportUri: 'opt' }).pcaPassport).toStrictEqual({ id: 'x', uri: 'own' });
    expect(buildAgentCard({ id: 'x' }, { name: 'n', passportUri: 'opt' }).pcaPassport).toStrictEqual({ id: 'x', uri: 'opt' });
    expect(buildAgentCard({ id: 'x' }, { name: 'n' }).pcaPassport).toStrictEqual({ id: 'x' });
    const full = { ...passport, uri: 'stray' } as unknown as AgentPassport;
    expect(buildAgentCard(full, { name: 'n' }).pcaPassport).toStrictEqual({ id: passport.id });
    expect(buildAgentCard(full, { name: 'n', passportUri: 'opt' }).pcaPassport).toStrictEqual({ id: passport.id, uri: 'opt' });
  });
});

describe('issueSignedAgentCard', () => {
  it('header contents: alg, b64, crit, kid, pca_passport; no kid when absent', async () => {
    const { privateKey } = await keys();
    const card = buildAgentCard(passport, { name: 'n' });
    const s = await issueSignedAgentCard(card, privateKey);
    expect(hdr(s.signatures![0]!)).toStrictEqual({ alg: 'EdDSA', b64: false, crit: ['b64'], pca_passport: passport.id });
    const k = await issueSignedAgentCard(card, privateKey, { kid: 'k1' });
    expect(hdr(k.signatures![0]!)).toStrictEqual({ alg: 'EdDSA', b64: false, crit: ['b64'], kid: 'k1', pca_passport: passport.id });
    expect(Object.keys(s.signatures![0]!).sort()).toStrictEqual(['protected', 'signature']);
  });
  it('alg option is used (ES256)', async () => {
    const { privateKey } = await keys('ES256');
    const s = await issueSignedAgentCard(buildAgentCard(passport, { name: 'n' }), privateKey, { alg: 'ES256' });
    expect(hdr(s.signatures![0]!).alg).toBe('ES256');
  });
  it('opts.passport is embedded (with uri only when defined) and committed', async () => {
    const { privateKey } = await keys();
    const bare: AgentCard = { name: 'n' };
    const a = await issueSignedAgentCard(bare, privateKey, { passport: { id: 'P1' } });
    expect(a.pcaPassport).toStrictEqual({ id: 'P1' });
    expect(hdr(a.signatures![0]!).pca_passport).toBe('P1');
    const b = await issueSignedAgentCard(bare, privateKey, { passport: { id: 'P2', uri: 'U' } as never });
    expect(b.pcaPassport).toStrictEqual({ id: 'P2', uri: 'U' });
    const c = await issueSignedAgentCard(bare, privateKey, { passport: { id: 'P3', uri: undefined } as never });
    expect(c.pcaPassport).toStrictEqual({ id: 'P3' });
    // opts.passport overrides the card's own
    const d = await issueSignedAgentCard({ name: 'n', pcaPassport: { id: 'OLD' } }, privateKey, { passport: { id: 'NEW' } });
    expect(d.pcaPassport).toStrictEqual({ id: 'NEW' });
  });
  it('with no passport anywhere: no pcaPassport key, no pca_passport header, verification has no passportRef', async () => {
    const { publicKey, privateKey } = await keys();
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey);
    expect('pcaPassport' in s).toBe(false);
    expect('pca_passport' in hdr(s.signatures![0]!)).toBe(false);
    expect(await verifyAgentCard(s, { key: publicKey })).toStrictEqual({ ok: true });
  });
  it('appends to existing signatures', async () => {
    const { privateKey } = await keys();
    const once = await issueSignedAgentCard({ name: 'n' }, privateKey);
    const twice = await issueSignedAgentCard(once, privateKey);
    expect(twice.signatures!.length).toBe(2);
    expect(twice.signatures![0]).toStrictEqual(once.signatures![0]);
  });
});

describe('verifyAgentCard', () => {
  it('no/empty/non-array signatures', async () => {
    const { publicKey } = await keys();
    for (const signatures of [undefined, [], 'x' as never]) {
      expect(await verifyAgentCard({ name: 'n', signatures }, { key: publicKey })).toStrictEqual({ ok: false, reason: 'agent card carries no signatures' });
    }
  });
  it('a missing (undefined) signature entry', async () => {
    const { publicKey } = await keys();
    expect(await verifyAgentCard({ name: 'n', signatures: [undefined as never] }, { key: publicKey })).toStrictEqual({ ok: false, reason: 'signature 0 is missing' });
  });
  it('malformed signature members', async () => {
    const { publicKey, privateKey } = await keys();
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey);
    const good = s.signatures![0]!;
    for (const bad of [{ protected: 5, signature: good.signature }, { protected: good.protected, signature: 5 }, { protected: 5, signature: 5 }]) {
      expect(await verifyAgentCard({ ...s, signatures: [bad as never] }, { key: publicKey })).toStrictEqual({
        ok: false,
        reason: 'signature 0 did not verify: signature is malformed',
      });
    }
  });
  it('a tampered card carries the verifier message; the failing index is reported', async () => {
    const { publicKey, privateKey } = await keys();
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey);
    const r = await verifyAgentCard({ ...s, name: 'evil' }, { key: publicKey });
    expect(r).toStrictEqual({ ok: false, reason: 'signature 0 did not verify: signature verification failed' });
    const two = { ...s, signatures: [s.signatures![0]!, { protected: s.signatures![0]!.protected, signature: 'AAAA' }] };
    expect((await verifyAgentCard(two, { key: publicKey })).reason).toMatch(/^signature 1 did not verify: .+/);
  });
  it('the first signature carrying a string pca_passport wins; non-string values are ignored', async () => {
    const { publicKey, privateKey } = await keys();
    const base: AgentCard = { name: 'n' };
    const sign = async (extra: Record<string, unknown>) => {
      const j = await new FlattenedSign(cardBytes(base)).setProtectedHeader({ alg: 'EdDSA', b64: false, crit: ['b64'], ...extra }).sign(privateKey);
      return { protected: j.protected!, signature: j.signature };
    };
    const num = await sign({ pca_passport: 123 });
    const none = await sign({});
    const b = await sign({ pca_passport: 'B' });
    const c = await sign({ pca_passport: 'C' });
    expect((await verifyAgentCard({ ...base, signatures: [num, b, c] }, { key: publicKey })).passportRef).toBe('B');
    expect((await verifyAgentCard({ ...base, signatures: [b, c] }, { key: publicKey })).passportRef).toBe('B');
    expect((await verifyAgentCard({ ...base, signatures: [none, b] }, { key: publicKey })).passportRef).toBe('B');
    expect('passportRef' in (await verifyAgentCard({ ...base, signatures: [num, none] }, { key: publicKey }))).toBe(false);
  });
  it('JWKS verification', async () => {
    const { publicKey, privateKey } = await keys();
    const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'EdDSA' };
    const s = await issueSignedAgentCard({ name: 'n' }, privateKey, { kid: 'k1' });
    expect((await verifyAgentCard(s, { jwks: { keys: [jwk] } })).ok).toBe(true);
    expect((await verifyAgentCard(s, { jwks: { keys: [] } })).ok).toBe(false);
  });
  it('passport and pcaProof come from the card body', async () => {
    const { publicKey, privateKey } = await keys();
    const card = buildAgentCard(passport, { name: 'n', passportUri: 'u', pcaProofRef: { verificationEndpoint: 'e', proofRef: 'r', aud: 'a' } });
    const s = await issueSignedAgentCard(card, privateKey);
    expect(await verifyAgentCard(s, { key: publicKey })).toStrictEqual({
      ok: true,
      passportRef: passport.id,
      passport: { id: passport.id, uri: 'u' },
      pcaProof: { verificationEndpoint: 'e', proofRef: 'r', aud: 'a' },
    });
  });
});

describe('AgentFacts issue', () => {
  it('shape, defaults and the signed statement bytes (independent verification)', async () => {
    const { publicKey, privateKey } = await keys();
    const f = await issueAgentFacts(passport, { attestorKey: privateKey, attests: { a: 1 }, now: NOW });
    expect(f.type).toBe('AgentFacts');
    expect(f['@context']).toStrictEqual(['https://www.w3.org/ns/did/v1', 'https://nanda.ai/agentfacts/v1']);
    expect(f.id).toBe(passport.id);
    expect(f.selfAsserted).toStrictEqual({});
    const att = f.attestations[0]!;
    expect(att.validFrom).toBe(new Date(NOW).toISOString());
    expect(att.issuer).toBe('did:atlas:pca-attestor');
    expect('validUntil' in att).toBe(false);
    expect(Object.keys(att).sort()).toStrictEqual(['attests', 'issuer', 'signature', 'subject', 'validFrom']);
    expect(hdr(att.signature)).toStrictEqual({ alg: 'EdDSA', b64: false, crit: ['b64'], attestor: 'did:atlas:pca-attestor' });
    const payload = canonicalBytes({
      d: 'atlas-pca/agentfacts/attestation/v1',
      issuer: att.issuer,
      subject: att.subject,
      attests: att.attests,
      validFrom: att.validFrom,
      validUntil: null,
    });
    const ok = await flattenedVerify({ protected: att.signature.protected, payload, signature: att.signature.signature }, publicKey);
    expect(ok.protectedHeader?.attestor).toBe('did:atlas:pca-attestor');
  });
  it('options: agentId, attestorId, validUntil, kid, alg, selfAsserted, context, validFrom', async () => {
    const { privateKey } = await keys('ES256');
    const f = await issueAgentFacts(passport, {
      attestorKey: privateKey,
      attests: { a: 1 },
      agentId: 'did:x',
      attestorId: 'did:att',
      validFrom: '2030-01-01T00:00:00.000Z',
      validUntil: '2031-01-01T00:00:00.000Z',
      kid: 'kk',
      alg: 'ES256',
      selfAsserted: { s: 1 },
      context: ['c'],
    });
    expect(f['@context']).toStrictEqual(['c']);
    expect(f.id).toBe('did:x');
    expect(f.selfAsserted).toStrictEqual({ s: 1 });
    const att = f.attestations[0]!;
    expect(att).toMatchObject({ issuer: 'did:att', subject: 'did:x', validFrom: '2030-01-01T00:00:00.000Z', validUntil: '2031-01-01T00:00:00.000Z' });
    expect(hdr(att.signature)).toStrictEqual({ alg: 'ES256', b64: false, crit: ['b64'], kid: 'kk', attestor: 'did:att' });
  });
  it('default validFrom uses the wall clock when now is absent', async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(NOW);
      const { privateKey } = await keys();
      const f = await issueAgentFacts(passport, { attestorKey: privateKey, attests: {} });
      expect(f.attestations[0]!.validFrom).toBe(new Date(NOW).toISOString());
      const g = await addAttestation(f, { attestorKey: privateKey, attests: {} });
      expect(g.attestations[1]!.validFrom).toBe(new Date(NOW).toISOString());
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('addAttestation', () => {
  it('appends without mutating, signs for the doc id, honours every option', async () => {
    const { publicKey, privateKey } = await keys();
    const f = await issueAgentFacts(passport, { attestorKey: privateKey, attests: { a: 1 }, now: NOW });
    const g = await addAttestation(f, { attestorKey: privateKey, attests: { b: 2 }, now: NOW + 5000 });
    expect(f.attestations.length).toBe(1);
    expect(g.attestations.length).toBe(2);
    const a = g.attestations[1]!;
    expect(a).toMatchObject({ issuer: 'did:atlas:pca-attestor', subject: passport.id, validFrom: new Date(NOW + 5000).toISOString() });
    expect('validUntil' in a).toBe(false);
    expect(hdr(a.signature)).toStrictEqual({ alg: 'EdDSA', b64: false, crit: ['b64'], attestor: 'did:atlas:pca-attestor' });
    const r = await verifyAgentFacts(g, { key: publicKey, now: NOW + 6000 });
    expect(r.ok).toBe(true);
    const h = await addAttestation(f, {
      attestorKey: privateKey,
      attests: { c: 3 },
      attestorId: 'did:other',
      validFrom: '2030-01-01T00:00:00.000Z',
      validUntil: '2031-01-01T00:00:00.000Z',
      kid: 'q',
      alg: 'EdDSA',
    });
    const b = h.attestations[1]!;
    expect(b).toMatchObject({ issuer: 'did:other', validFrom: '2030-01-01T00:00:00.000Z', validUntil: '2031-01-01T00:00:00.000Z' });
    expect(hdr(b.signature)).toStrictEqual({ alg: 'EdDSA', b64: false, crit: ['b64'], kid: 'q', attestor: 'did:other' });
  });
  it('alg option reaches the signature (ES256)', async () => {
    const { privateKey } = await keys('ES256');
    const f: AgentFacts = { '@context': [], id: 'i', type: 'AgentFacts', selfAsserted: {}, attestations: [] };
    const g = await addAttestation(f, { attestorKey: privateKey, attests: {}, alg: 'ES256' });
    expect(hdr(g.attestations[0]!.signature).alg).toBe('ES256');
  });
});

describe('verifyAgentFacts', () => {
  const mk = async () => {
    const { publicKey, privateKey } = await keys();
    const facts = await issueAgentFacts(passport, { attestorKey: privateKey, attests: { a: 1 }, selfAsserted: { s: 1, a: 0 }, now: NOW });
    return { publicKey, privateKey, facts };
  };
  it('success shape and provenance, with attested winning overlap', async () => {
    const { publicKey, facts } = await mk();
    const r = await verifyAgentFacts(facts, { key: publicKey, now: NOW });
    expect(r).toStrictEqual({
      ok: true,
      agentId: passport.id,
      attestations: [{ issuer: 'did:atlas:pca-attestor', ok: true, attests: { a: 1 } }],
      attested: { a: 1 },
      selfAsserted: { s: 1, a: 0 },
      claims: { s: 'self-asserted', a: 'attested' },
    });
  });
  it('validity window boundaries are inclusive and the default clock is the wall clock', async () => {
    const { publicKey, privateKey } = await keys();
    const f = await issueAgentFacts(passport, {
      attestorKey: privateKey,
      attests: {},
      validFrom: new Date(NOW).toISOString(),
      validUntil: new Date(NOW + 1000).toISOString(),
    });
    expect((await verifyAgentFacts(f, { key: publicKey, now: NOW })).ok).toBe(true);
    expect((await verifyAgentFacts(f, { key: publicKey, now: NOW + 1000 })).ok).toBe(true);
    expect((await verifyAgentFacts(f, { key: publicKey, now: NOW - 1 })).attestations[0]).toStrictEqual({ issuer: 'did:atlas:pca-attestor', ok: false, reason: 'attestation is not yet valid' });
    expect((await verifyAgentFacts(f, { key: publicKey, now: NOW + 1001 })).attestations[0]).toStrictEqual({ issuer: 'did:atlas:pca-attestor', ok: false, reason: 'attestation has expired' });
    vi.useFakeTimers();
    try {
      vi.setSystemTime(NOW + 500);
      expect((await verifyAgentFacts(f, { key: publicKey })).ok).toBe(true);
      vi.setSystemTime(NOW + 5000);
      expect((await verifyAgentFacts(f, { key: publicKey })).ok).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
  it('unparseable dates', async () => {
    const { publicKey, privateKey } = await keys();
    const bad1 = await issueAgentFacts(passport, { attestorKey: privateKey, attests: {}, validFrom: 'garbage' });
    expect((await verifyAgentFacts(bad1, { key: publicKey, now: NOW })).attestations[0]).toStrictEqual({ issuer: 'did:atlas:pca-attestor', ok: false, reason: 'attestation validFrom is not a valid date' });
    const bad2 = await issueAgentFacts(passport, { attestorKey: privateKey, attests: {}, now: NOW, validUntil: 'garbage' });
    expect((await verifyAgentFacts(bad2, { key: publicKey, now: NOW })).attestations[0]).toStrictEqual({ issuer: 'did:atlas:pca-attestor', ok: false, reason: 'attestation validUntil is not a valid date' });
  });
  it('subject mismatch, tamper, whole-document reason', async () => {
    const { publicKey, facts } = await mk();
    const wrongDoc = { ...facts, id: 'other' };
    const r1 = await verifyAgentFacts(wrongDoc, { key: publicKey, now: NOW });
    expect(r1.ok).toBe(false);
    expect(r1.reason).toBe('one or more attestations did not verify');
    expect(r1.attestations[0]!.reason).toBe(`attestation subject '${passport.id}' does not match agent id 'other'`);
    expect(r1.attested).toStrictEqual({});
    expect(r1.claims).toStrictEqual({ s: 'self-asserted', a: 'self-asserted' });
    const tampered = { ...facts, attestations: [{ ...facts.attestations[0]!, attests: { a: 2 } }] };
    const r2 = await verifyAgentFacts(tampered, { key: publicKey, now: NOW });
    expect(r2.attestations[0]).toStrictEqual({ issuer: 'did:atlas:pca-attestor', ok: false, reason: 'signature did not verify: signature verification failed' });
  });
  it('a statement with validUntil verifies (the window is part of the signed bytes)', async () => {
    const { publicKey, privateKey } = await keys();
    const f = await issueAgentFacts(passport, { attestorKey: privateKey, attests: { a: 1 }, now: NOW, validUntil: new Date(NOW + 9999).toISOString() });
    expect((await verifyAgentFacts(f, { key: publicKey, now: NOW })).ok).toBe(true);
    const moved = { ...f, attestations: [{ ...f.attestations[0]!, validUntil: new Date(NOW + 99999).toISOString() }] };
    expect((await verifyAgentFacts(moved, { key: publicKey, now: NOW })).ok).toBe(false);
    const dropped = { ...f, attestations: [{ ...f.attestations[0]!, validUntil: undefined }] };
    expect((await verifyAgentFacts(dropped as never, { key: publicKey, now: NOW })).ok).toBe(false);
  });
  it('malformed attestations (each required member) report the issuer when known', async () => {
    const { publicKey, facts } = await mk();
    const a = facts.attestations[0]!;
    const cases: [unknown, string][] = [
      [null, '<unknown>'],
      [{ ...a, subject: 5 }, a.issuer],
      [{ ...a, attests: null }, a.issuer],
      [{ ...a, attests: [] }, a.issuer],
      [{ ...a, attests: 'x' }, a.issuer],
      [{ ...a, validFrom: 5 }, a.issuer],
      [{ ...a, issuer: 5, subject: 5 }, '<unknown>'],
    ];
    for (const [att, issuer] of cases) {
      const r = await verifyAgentFacts({ ...facts, attestations: [att as never] }, { key: publicKey, now: NOW });
      expect(r.attestations[0]).toStrictEqual({ issuer, ok: false, reason: 'attestation is malformed' });
    }
  });
  it('non-array attestations', async () => {
    const { publicKey, facts } = await mk();
    const r = await verifyAgentFacts({ ...facts, attestations: undefined as never }, { key: publicKey, now: NOW });
    expect(r).toStrictEqual({
      ok: false,
      reason: 'agent facts has no attestations array',
      agentId: passport.id,
      attestations: [],
      attested: {},
      selfAsserted: { s: 1, a: 0 },
      claims: {},
    });
  });
  it('no key with attestations: per-attestation missing-key checks', async () => {
    const { facts } = await mk();
    const a = facts.attestations[0]!;
    const r = await verifyAgentFacts({ ...facts, attestations: [a, null as never, { ...a, issuer: 5 as never }] }, { now: NOW });
    expect(r).toStrictEqual({
      ok: false,
      reason: 'no verification key or JWKS supplied',
      agentId: passport.id,
      attestations: [
        { issuer: a.issuer, ok: false, reason: 'no verification key or JWKS supplied' },
        { issuer: '<unknown>', ok: false, reason: 'no verification key or JWKS supplied' },
        { issuer: '<unknown>', ok: false, reason: 'no verification key or JWKS supplied' },
      ],
      attested: {},
      selfAsserted: { s: 1, a: 0 },
      claims: {},
    });
  });
  it('zero attestations verify with no key and attest nothing', async () => {
    const r = await verifyAgentFacts({ '@context': [], id: 'i', type: 'AgentFacts', selfAsserted: { s: 1 }, attestations: [] }, {});
    expect(r).toStrictEqual({ ok: true, agentId: 'i', attestations: [], attested: {}, selfAsserted: { s: 1 }, claims: { s: 'self-asserted' } });
  });
  it('selfAsserted must be a plain object', async () => {
    for (const bad of [null, [1, 2], 'abc', 5, undefined]) {
      const r = await verifyAgentFacts({ '@context': [], id: 'i', type: 'AgentFacts', selfAsserted: bad as never, attestations: [] }, {});
      expect(r.selfAsserted).toStrictEqual({});
      expect(r.claims).toStrictEqual({});
    }
  });
  it('multiple attestations merge, later wins on overlap; one failure fails the doc but keeps good claims', async () => {
    const { publicKey, privateKey, facts } = await mk();
    const g = await addAttestation(facts, { attestorKey: privateKey, attests: { a: 9, b: 2 }, now: NOW });
    const r = await verifyAgentFacts(g, { key: publicKey, now: NOW });
    expect(r.attested).toStrictEqual({ a: 9, b: 2 });
    const broken = { ...g, attestations: [g.attestations[0]!, { ...g.attestations[1]!, attests: { zzz: 1 } }] };
    const r2 = await verifyAgentFacts(broken, { key: publicKey, now: NOW });
    expect(r2.ok).toBe(false);
    expect(r2.attested).toStrictEqual({ a: 1 });
    expect(r2.attestations.map((c) => c.ok)).toStrictEqual([true, false]);
  });
});

describe('hosting handlers', () => {
  const card: AgentCard = { name: 'n' };
  it('exact response and path normalisation', () => {
    const h = agentCardHandler(card);
    expect(h('/.well-known/agent-card.json')).toStrictEqual({
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
      body: JSON.stringify(card),
    });
    expect(h('/.well-known/agent-card.json/')).toBeDefined();
    expect(h('/.well-known/agent-card.json?x=1')).toBeDefined();
    expect(h('/.well-known/agent-card.jso')).toBeUndefined();
    expect(h('/other')).toBeUndefined();
  });
  it('trailing slash is stripped from both the target and the request, root is kept', () => {
    const h = agentCardHandler(card, '/foo/');
    expect(h('/foo')).toBeDefined();
    expect(h('/foo/')).toBeDefined();
    expect(h('/fo/')).toBeUndefined();
    expect(h('/fo')).toBeUndefined();
    expect(h('/foo//')).toBeUndefined();
    const root = agentCardHandler(card, '/');
    expect(root('/')).toBeDefined();
    expect(root('')).toBeUndefined();
    expect(root('/x')).toBeUndefined();
    const f = agentFactsHandler({ '@context': [], id: 'i', type: 'AgentFacts', selfAsserted: {}, attestations: [] });
    expect(f('/.well-known/agent-facts.json')!.body).toContain('"id":"i"');
    expect(f('/.well-known/agent-card.json')).toBeUndefined();
    const single = agentCardHandler(card, 'a');
    expect(single('a')).toBeDefined();
    expect(single('')).toBeUndefined();
  });
});

describe('toRegistryEntry', () => {
  const facts: AgentFacts = {
    '@context': [],
    id: 'did:i',
    type: 'AgentFacts',
    selfAsserted: { s: 1, a: 2 },
    attestations: [{ issuer: 'i', subject: 'did:i', attests: { a: 1, b: 1 }, validFrom: 'x', signature: { protected: 'p', signature: 's' } }],
  };
  it('minimal card has no optional keys', () => {
    expect(toRegistryEntry({ name: 'n' }, facts)).toStrictEqual({
      id: 'did:i',
      name: 'n',
      card: { name: 'n' },
      facts,
      attestedClaims: ['a', 'b'],
      selfAssertedClaims: ['s'],
    });
  });
  it('full card carries optional fields and the well-known URL', () => {
    const card: AgentCard = {
      name: 'n',
      url: 'https://h.example/svc/x',
      version: '2',
      skills: [{ id: 's', name: 'S' }],
      pcaPassport: { id: 'p' },
      pcaProof: { verificationEndpoint: 'e' },
    };
    expect(toRegistryEntry(card, facts)).toStrictEqual({
      id: 'did:i',
      name: 'n',
      url: 'https://h.example/svc/x',
      version: '2',
      skills: [{ id: 's', name: 'S' }],
      passport: { id: 'p' },
      pcaProof: { verificationEndpoint: 'e' },
      card,
      agentCardUrl: 'https://h.example/.well-known/agent-card.json',
      facts,
      attestedClaims: ['a', 'b'],
      selfAssertedClaims: ['s'],
    });
  });
  it('an unparseable card url yields no agentCardUrl', () => {
    const e = toRegistryEntry({ name: 'n', url: 'not a url' }, facts);
    expect('agentCardUrl' in e).toBe(false);
    expect(e.url).toBe('not a url');
  });
  it('tolerates junk attestations / selfAsserted', () => {
    const junk = { ...facts, selfAsserted: [1] as never, attestations: [null, { attests: 'abc' }, { attests: null }, { attests: { k: 1 } }] as never };
    const e = toRegistryEntry({ name: 'n' }, junk);
    expect(e.attestedClaims).toStrictEqual(['k']);
    expect(e.selfAssertedClaims).toStrictEqual([]);
    const e2 = toRegistryEntry({ name: 'n' }, { ...facts, selfAsserted: 'abc' as never });
    expect(e2.selfAssertedClaims).toStrictEqual([]);
  });
});
