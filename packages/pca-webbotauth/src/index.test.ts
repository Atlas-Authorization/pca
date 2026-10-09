import { describe, it, expect } from 'vitest';
import { agent, generateKeyPair, type PCActn } from '@atlasauth/pca';
import {
  signRequest,
  verifySignedRequest,
  buildKeyDirectory,
  directoryHandler,
  resolveFromDirectory,
  jwkThumbprint,
  signRequestWithProof,
  verifySignedRequestWithProof,
  decodeProofHeader,
  WELL_KNOWN_DIRECTORY_PATH,
  DIRECTORY_CONTENT_TYPE,
  WEB_BOT_AUTH_TAG,
  PCA_HEADER,
  PCA_PROOF_COMPONENT,
  type KeyDirectory,
} from './index';

const key = generateKeyPair();
const keyid = jwkThumbprint(key.publicKey);
const directory: KeyDirectory = buildKeyDirectory([{ publicKey: key.publicKey, keyid }]);

const baseReq = {
  method: 'POST',
  url: 'https://api.example.com/v1/refunds?id=42',
  headers: { 'content-type': 'application/json' },
};

function signNow(overrides: Partial<Parameters<typeof signRequest>[0]> = {}) {
  return signRequest({
    method: baseReq.method,
    url: baseReq.url,
    headers: baseReq.headers,
    key,
    keyid,
    agentDirectoryUrl: 'https://agent.example.com',
    ...overrides,
  });
}

describe('signRequest / verifySignedRequest', () => {
  it('signs a request and verifies it (round-trip, via jwks)', async () => {
    const signed = signNow();
    expect(signed.covered).toEqual(['@authority', '@method', '@path', 'signature-agent']);
    expect(signed.signatureInput).toContain(`tag="${WEB_BOT_AUTH_TAG}"`);
    expect(signed.signatureInput).toContain('alg="ed25519"');
    expect(signed.headers['Signature-Agent']).toBe('"https://agent.example.com"');

    const res = await verifySignedRequest(
      {
        method: baseReq.method,
        url: baseReq.url,
        headers: { ...baseReq.headers, ...signed.headers },
      },
      { jwks: directory },
    );
    expect(res.valid).toBe(true);
    expect(res.keyid).toBe(keyid);
    expect(res.tag).toBe(WEB_BOT_AUTH_TAG);
    expect(res.covered).toContain('@authority');
  });

  it('verifies via a resolveKey returning raw bytes', async () => {
    const signed = signNow();
    const res = await verifySignedRequest(
      { method: baseReq.method, url: baseReq.url, headers: { ...baseReq.headers, ...signed.headers } },
      { resolveKey: (kid) => (kid === keyid ? key.publicKey : null) },
    );
    expect(res.valid).toBe(true);
  });

  it('fails when the method is tampered', async () => {
    const signed = signNow();
    const res = await verifySignedRequest(
      { method: 'GET', url: baseReq.url, headers: { ...baseReq.headers, ...signed.headers } },
      { jwks: directory },
    );
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/does not verify/);
  });

  it('fails when the path is tampered', async () => {
    const signed = signNow();
    const res = await verifySignedRequest(
      { method: baseReq.method, url: 'https://api.example.com/v1/transfers?id=42', headers: { ...baseReq.headers, ...signed.headers } },
      { jwks: directory },
    );
    expect(res.valid).toBe(false);
  });

  it('fails when a covered header is tampered', async () => {
    const signed = signRequest({
      method: baseReq.method,
      url: baseReq.url,
      headers: { 'content-digest': 'sha-256=:abc:' },
      key,
      keyid,
      coverHeaders: ['content-digest'],
    });
    const res = await verifySignedRequest(
      {
        method: baseReq.method,
        url: baseReq.url,
        headers: { 'content-digest': 'sha-256=:DIFFERENT:', ...signed.headers },
      },
      { jwks: directory },
    );
    expect(res.valid).toBe(false);
  });

  it('fails an expired signature', async () => {
    const past = Math.floor(Date.now() / 1000) - 10_000;
    const signed = signNow({ created: past, expiresInSec: 60 });
    const res = await verifySignedRequest(
      { method: baseReq.method, url: baseReq.url, headers: { ...baseReq.headers, ...signed.headers } },
      { jwks: directory },
    );
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/expired/);
  });

  it('fails a wrong tag (fail closed)', async () => {
    const signed = signNow();
    // Rewrite the tag in both headers to something non-web-bot-auth.
    const mangledInput = signed.signatureInput.replace(`tag="${WEB_BOT_AUTH_TAG}"`, 'tag="other"');
    const res = await verifySignedRequest(
      {
        method: baseReq.method,
        url: baseReq.url,
        headers: { ...baseReq.headers, 'Signature-Input': mangledInput, Signature: signed.signature, 'Signature-Agent': signed.signatureAgent ?? '' },
      },
      { jwks: directory },
    );
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/tag/);
  });

  it('fails an unknown key', async () => {
    const signed = signNow();
    const res = await verifySignedRequest(
      { method: baseReq.method, url: baseReq.url, headers: { ...baseReq.headers, ...signed.headers } },
      { resolveKey: () => null },
    );
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/resolve key/);
  });
});

describe('buildKeyDirectory / directoryHandler', () => {
  it('round-trips the directory and resolves a key from it', () => {
    const handler = directoryHandler([{ publicKey: key.publicKey, keyid }]);
    const miss = handler('/some/other/path');
    expect(miss).toBeNull();

    const hit = handler(WELL_KNOWN_DIRECTORY_PATH);
    expect(hit).not.toBeNull();
    expect(hit?.status).toBe(200);
    expect(hit?.headers['content-type']).toBe(DIRECTORY_CONTENT_TYPE);

    const parsed = JSON.parse(hit?.body ?? '') as KeyDirectory;
    const resolved = resolveFromDirectory(parsed, keyid);
    expect(resolved).toBeDefined();
    expect(resolved?.kty).toBe('OKP');
    expect(resolved?.crv).toBe('Ed25519');
    expect(resolved?.x).toBe(directory.keys[0]?.x);
  });

  it('a signature verifies against a key resolved from the published directory', async () => {
    const handler = directoryHandler([{ publicKey: key.publicKey, keyid }]);
    const published = JSON.parse(handler(WELL_KNOWN_DIRECTORY_PATH)?.body ?? '') as KeyDirectory;
    const signed = signNow();
    const res = await verifySignedRequest(
      { method: baseReq.method, url: baseReq.url, headers: { ...baseReq.headers, ...signed.headers } },
      { jwks: published },
    );
    expect(res.valid).toBe(true);
  });
});

describe('PCA proof binding', () => {
  function buildPCActn(): PCActn {
    const a = agent({
      principal: generateKeyPair(),
      holder: key,
      goal: 'issue customer refunds',
      permissions: { stripe: ['refund'] },
      limits: { refund: '$500' },
      aud: 'https://api.example.com',
    });
    return a.act('stripe.refund', 'charge_123', { amount: 100 }).pcactn;
  }

  it('signs a proof-bound request that verifies and yields the carried PCActn', async () => {
    const pcactn = buildPCActn();
    const signed = signRequestWithProof({
      method: baseReq.method,
      url: baseReq.url,
      headers: baseReq.headers,
      key,
      keyid,
      agentDirectoryUrl: 'https://agent.example.com',
      pcactn,
    });
    expect(signed.covered).toContain(PCA_PROOF_COMPONENT);
    expect(signed.headers[PCA_HEADER]).toBeDefined();

    const res = await verifySignedRequestWithProof(
      { method: baseReq.method, url: baseReq.url, headers: { ...baseReq.headers, ...signed.headers } },
      { jwks: directory, expectedPCActn: pcactn },
    );
    expect(res.valid).toBe(true);
    expect(res.pcactn).toBeDefined();
    expect(res.pcactn?.action.verb).toBe('stripe.refund');
  });

  it('the carried PCActn survives the header round-trip', () => {
    const pcactn = buildPCActn();
    const signed = signRequestWithProof({
      method: baseReq.method,
      url: baseReq.url,
      key,
      keyid,
      pcactn,
    });
    const headerValue = signed.headers[PCA_HEADER];
    expect(headerValue).toBeDefined();
    const decoded = decodeProofHeader(headerValue ?? '');
    expect(decoded.aud).toBe('https://api.example.com');
  });

  it('fails when the proof header is tampered (binding is tamper-evident)', async () => {
    const pcactn = buildPCActn();
    const other = buildPCActn();
    const signed = signRequestWithProof({
      method: baseReq.method,
      url: baseReq.url,
      headers: baseReq.headers,
      key,
      keyid,
      pcactn,
    });
    // Swap the proof header for a different (otherwise valid) PCActn — signature must break.
    const otherHeader = (
      await import('./index')
    ).proofHeaders(other)[PCA_HEADER];
    const res = await verifySignedRequestWithProof(
      {
        method: baseReq.method,
        url: baseReq.url,
        headers: { ...baseReq.headers, ...signed.headers, [PCA_HEADER]: otherHeader ?? '' },
      },
      { jwks: directory },
    );
    expect(res.valid).toBe(false);
  });

  it('fails closed when the proof header is not a covered component', async () => {
    const pcactn = buildPCActn();
    // Plain signRequest does NOT cover PCA-Action; attach the proof header separately.
    const signed = signNow();
    const proof = (await import('./index')).proofHeaders(pcactn);
    const res = await verifySignedRequestWithProof(
      {
        method: baseReq.method,
        url: baseReq.url,
        headers: { ...baseReq.headers, ...signed.headers, ...proof },
      },
      { jwks: directory },
    );
    expect(res.valid).toBe(false);
    expect(res.reason).toMatch(/not covered/);
  });
});
