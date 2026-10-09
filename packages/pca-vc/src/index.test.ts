import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { issuePassport, type AgentPassport } from '@atlasauth/pca';
import {
  didKeyFromEd25519,
  ed25519FromDidKey,
  passportToVC,
  verifyPassportVC,
  signRequestMessage,
  verifyRequestSignature,
} from './index';

function rawPublicKey(key: KeyObject): Uint8Array {
  const jwk = key.export({ format: 'jwk' });
  if (typeof jwk.x !== 'string') throw new Error('expected an OKP public key with x');
  return new Uint8Array(Buffer.from(jwk.x, 'base64url'));
}

function samplePassport(): AgentPassport {
  return issuePassport({
    model_id: 'anthropic/claude-opus-4-8',
    weights_digest: 'sha256:weights-abc',
    system_prompt_digest: 'sha256:prompt-def',
    tool_manifest_digest: 'sha256:tools-ghi',
    runtime_measurement: '42',
    operator: 'acme-robotics',
    hardware_rooted: true,
    weights_measured: true,
    issued_at: 1_700_000_000,
  });
}

describe('did:key (Ed25519)', () => {
  it('encodes and decodes an Ed25519 public key round-trip', () => {
    const { publicKey } = generateKeyPairSync('ed25519');
    const raw = rawPublicKey(publicKey);
    const did = didKeyFromEd25519(raw);
    expect(did.startsWith('did:key:z')).toBe(true);
    expect(Array.from(ed25519FromDidKey(did))).toEqual(Array.from(raw));
  });

  it('matches the did:key spec test vector', () => {
    // w3c-ccg did:key — canonical Ed25519 example. Decode it (32-byte key), then re-encode == itself.
    const canonical = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    const raw = ed25519FromDidKey(canonical);
    expect(raw.length).toBe(32);
    expect(didKeyFromEd25519(raw)).toBe(canonical);
  });

  it('rejects a non-32-byte key', () => {
    expect(() => didKeyFromEd25519(new Uint8Array(31))).toThrow();
  });
});

describe('passport → W3C VC 2.0 (SD-JWT)', () => {
  it('issues a VC and round-trips, preserving the subject digests', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const { privateKey: subPriv, publicKey: subPub } = generateKeyPairSync('ed25519');
    void subPriv;
    const issuerDid = didKeyFromEd25519(rawPublicKey(publicKey));
    const subjectDid = didKeyFromEd25519(rawPublicKey(subPub));
    const passport = samplePassport();

    const vc = await passportToVC(passport, { issuerKey: privateKey, issuerDid, subjectDid, ttlSec: 3600 });
    expect(vc.split('~').filter((p) => p.length > 0).length).toBe(1 + 4); // jwt + 4 disclosures

    const out = await verifyPassportVC(vc, publicKey);
    expect(out.issuerDid).toBe(issuerDid);
    expect(out.subjectDid).toBe(subjectDid);
    expect(out.passport.weights_digest).toBe(passport.weights_digest);
    expect(out.passport.system_prompt_digest).toBe(passport.system_prompt_digest);
    expect(out.passport.tool_manifest_digest).toBe(passport.tool_manifest_digest);
    expect(out.passport.runtime_measurement).toBe(passport.runtime_measurement);
    expect(out.passport.model_id).toBe(passport.model_id);
    expect(out.passport.operator).toBe(passport.operator);
    expect(out.passport.hardware_rooted).toBe(true);
    expect(out.passport.id).toBe(passport.id);
  });

  it('omits SD disclosures for absent passport fields', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const did = didKeyFromEd25519(rawPublicKey(publicKey));
    const minimal = issuePassport({ model_id: 'm', operator: 'op', hardware_rooted: false, issued_at: 1 });
    const vc = await passportToVC(minimal, { issuerKey: privateKey, issuerDid: did, subjectDid: did });
    expect(vc.split('~').filter((p) => p.length > 0).length).toBe(1); // jwt only, no disclosures
    const out = await verifyPassportVC(vc, publicKey);
    expect(out.passport.weights_digest).toBeUndefined();
    expect(out.passport.model_id).toBe('m');
  });

  it('fails a tampered VC (flipped JWT byte)', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const did = didKeyFromEd25519(rawPublicKey(publicKey));
    const vc = await passportToVC(samplePassport(), { issuerKey: privateKey, issuerDid: did, subjectDid: did });
    const [jwt, ...rest] = vc.split('~');
    const body = (jwt as string).split('.');
    const flipped = `${body[0]}.${body[1]}X.${body[2]}`;
    const tampered = [flipped, ...rest].join('~');
    await expect(verifyPassportVC(tampered, publicKey)).rejects.toThrow();
  });

  it('fails a forged disclosure not present in _sd', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const did = didKeyFromEd25519(rawPublicKey(publicKey));
    const vc = await passportToVC(samplePassport(), { issuerKey: privateKey, issuerDid: did, subjectDid: did });
    const forged = Buffer.from(JSON.stringify(['saltsalt', 'weights_digest', 'sha256:EVIL']), 'utf8').toString(
      'base64url',
    );
    const tampered = `${vc}${forged}~`;
    await expect(verifyPassportVC(tampered, publicKey)).rejects.toThrow();
  });
});

describe('RFC 9421 HTTP Message Signatures (Web Bot Auth)', () => {
  const req = {
    method: 'POST',
    url: 'https://api.acme.com/v1/orders?ref=42',
    headers: { host: 'api.acme.com', 'content-type': 'application/json' },
  };

  it('signs and verifies a request', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const keyid = didKeyFromEd25519(rawPublicKey(publicKey));
    const signed = signRequestMessage({ ...req, key: privateKey, keyid, created: 1_700_000_000 });
    expect(signed.signatureInput.startsWith('sig1=(')).toBe(true);
    expect(signed.signature.startsWith('sig1=:')).toBe(true);
    const ok = verifyRequestSignature(
      { ...req, signatureInput: signed.signatureInput, signature: signed.signature },
      publicKey,
    );
    expect(ok).toBe(true);
  });

  it('emits the Web Bot Auth Signature-Agent header and covers it', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const keyid = 'test-key';
    const signatureAgent = 'https://bots.acme.com';
    const signed = signRequestMessage({ ...req, key: privateKey, keyid, signatureAgent });
    expect(signed.signatureAgent).toBe('"https://bots.acme.com"');
    expect(signed.signatureInput.includes('"signature-agent"')).toBe(true);
    expect(signed.signatureInput.includes('tag="web-bot-auth"')).toBe(true);
    const ok = verifyRequestSignature(
      {
        ...req,
        signatureInput: signed.signatureInput,
        signature: signed.signature,
        signatureAgent: signed.signatureAgent,
      },
      publicKey,
    );
    expect(ok).toBe(true);
  });

  it('fails when the request method is changed', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const signed = signRequestMessage({ ...req, key: privateKey, keyid: 'k', created: 1_700_000_000 });
    const ok = verifyRequestSignature(
      { ...req, method: 'GET', signatureInput: signed.signatureInput, signature: signed.signature },
      publicKey,
    );
    expect(ok).toBe(false);
  });

  it('fails when a covered header is changed', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const signed = signRequestMessage({ ...req, key: privateKey, keyid: 'k', created: 1_700_000_000 });
    const ok = verifyRequestSignature(
      {
        ...req,
        headers: { ...req.headers, 'content-type': 'text/plain' },
        signatureInput: signed.signatureInput,
        signature: signed.signature,
      },
      publicKey,
    );
    expect(ok).toBe(false);
  });

  it('fails verification with a different key', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const { publicKey: otherPub } = generateKeyPairSync('ed25519');
    const signed = signRequestMessage({ ...req, key: privateKey, keyid: 'k', created: 1_700_000_000 });
    const ok = verifyRequestSignature(
      { ...req, signatureInput: signed.signatureInput, signature: signed.signature },
      otherPub,
    );
    expect(ok).toBe(false);
  });
});
