import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { issuePassport } from '@atlasauth/pca/ext/attestation';
import { AGENT_PASSPORT_CONTEXT, AGENT_PASSPORT_CONTEXT_DIGEST, AGENT_PASSPORT_CONTEXT_DOC, VC_CONTEXT, didKeyFromEd25519, passportToVC, resolveAgentPassportContext, verifyPassportVC } from './index';

const keys = () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = new Uint8Array(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32));
  return { publicKey, privateKey, did: didKeyFromEd25519(raw) };
};
const claims = (tok: string) => JSON.parse(Buffer.from(tok.split('~')[0]!.split('.')[1]!, 'base64url').toString('utf8')) as { vc: { credentialSubject: Record<string, unknown> } };

describe('the passport vocabulary context is bundled and complete', () => {
  it('resolves only its own IRI, offline', () => {
    expect(resolveAgentPassportContext(AGENT_PASSPORT_CONTEXT)).toBe(AGENT_PASSPORT_CONTEXT_DOC);
    expect(resolveAgentPassportContext(VC_CONTEXT)).toBeUndefined();
    expect(resolveAgentPassportContext('https://example.com/x')).toBeUndefined();
  });
  it('is protected and has a stable, pinned digest', () => {
    const ctx = AGENT_PASSPORT_CONTEXT_DOC['@context'] as Record<string, unknown>;
    expect(ctx['@protected']).toBe(true);
    expect(AGENT_PASSPORT_CONTEXT_DIGEST).toMatch(/^[0-9a-f]{64}$/);
    expect(AGENT_PASSPORT_CONTEXT_DIGEST).toBe('4a9725f10964e8ae87aabf7a6645d73aabb63fefa9f70f25c08ad397eff2b8d4');
  });
  it('defines every term the issuer emits in credentialSubject', async () => {
    const k = keys();
    const p = issuePassport({ model_id: 'm', operator: 'op', hardware_rooted: true, issued_at: 1, weights_digest: 'a', system_prompt_digest: 'b', tool_manifest_digest: 'c', runtime_measurement: 'd', weights_measured: true } as never);
    const vc = await passportToVC(p, { issuerKey: k.privateKey, issuerDid: k.did, subjectDid: k.did });
    const terms = ((AGENT_PASSPORT_CONTEXT_DOC['@context'] as Record<string, { '@context': Record<string, unknown> }>).AgentPassportCredential!)['@context'];
    for (const name of Object.keys(claims(vc).vc.credentialSubject)) {
      if (name === 'id') expect(terms.id).toBe('@id');
      else expect(terms[name], name).toBeDefined();
    }
  });
});

describe('verifyPassportVC requires exactly the two known contexts', () => {
  it('accepts the emitted pair; the issuer emits exactly it', async () => {
    const k = keys();
    const p = issuePassport({ model_id: 'm', operator: 'op', hardware_rooted: true, issued_at: 1 });
    const vc = await passportToVC(p, { issuerKey: k.privateKey, issuerDid: k.did, subjectDid: k.did });
    const tok = vc.split('~')[0]!;
    const payload = JSON.parse(Buffer.from(tok.split('.')[1]!, 'base64url').toString('utf8')) as { vc: { '@context': string[] } };
    expect(payload.vc['@context']).toEqual([VC_CONTEXT, AGENT_PASSPORT_CONTEXT]);
    expect((await verifyPassportVC(vc, k.publicKey)).passport.model_id).toBe('m');
  });
});

describe('the shipped context file is the bundled document', () => {
  it('context/agent-passport-v1.jsonld parses to exactly AGENT_PASSPORT_CONTEXT_DOC', () => {
    const file = JSON.parse(readFileSync(new URL('../context/agent-passport-v1.jsonld', import.meta.url), 'utf8'));
    expect(file).toEqual(AGENT_PASSPORT_CONTEXT_DOC);
  });
});
