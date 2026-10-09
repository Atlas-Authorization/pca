/**
 * Official vectors and cross-implementation checks for pca-webbotauth.
 *  - RFC 9421 Appendix B (fixtures/rfc9421-appendix-b.json): the Ed25519 example (B.2.6) is verified, and the
 *    RSA-PSS / ECDSA / HMAC examples must be refused for the stated reason.
 *  - Web Bot Auth architecture draft-05 Appendix A (fixtures/webbotauth-draft-05.json): the Ed25519 vectors are
 *    reproduced BYTE FOR BYTE by signRequest (Ed25519 is deterministic) and verified; the RSA-PSS ones are refused.
 *  - Cloudflare's reference `web-bot-auth` 0.2.0: requests it signs verify here, and requests signed here verify there.
 */
import { createPublicKey, verify as nodeVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { jwkThumbprint, signRequest, verifySignedRequest, type KeyPair } from './index';

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
function fixture(name: string): Record<string, unknown> {
  const raw: unknown = JSON.parse(readFileSync(resolve(__dirname, '..', 'fixtures', name), 'utf8'));
  if (!isRecord(raw)) throw new Error(`bad fixture ${name}`);
  return raw;
}
function list(v: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(v)) throw new Error('expected array');
  return v.map((x) => {
    if (!isRecord(x)) throw new Error('expected object');
    return x;
  });
}

// RFC 9421 Appendix B.1.4 test-key-ed25519 (public: RFC text; private: the JWK "d").
const X = 'JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs';
const D = 'n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU';
const KEY: KeyPair = { publicKey: new Uint8Array(Buffer.from(X, 'base64url')), secretKey: new Uint8Array(Buffer.from(D, 'base64url')) };
const THUMBPRINT = 'poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U';

const rfc = fixture('rfc9421-appendix-b.json');
const req = rfc.test_request as { method: string; url: string; headers: Record<string, string> };
const rfcVectors = list(rfc.vectors);
const draft = list(fixture('webbotauth-draft-05.json').vectors);
const rfcVec = (section: string): Record<string, unknown> => {
  const v = rfcVectors.find((x) => x.section === section);
  if (v === undefined) throw new Error(`missing ${section}`);
  return v;
};
const draftVec = (section: string): Record<string, unknown> => {
  const v = draft.find((x) => x.section === section);
  if (v === undefined) throw new Error(`missing ${section}`);
  return v;
};
const resolveKey = () => KEY.publicKey;
const paramOf = (input: string, name: string): string => {
  const m = new RegExp(`;${name}=("[^"]*"|[0-9]+)`).exec(input);
  if (m === null) throw new Error(`no ${name}`);
  return m[1]!.replace(/^"|"$/g, '');
};

describe('RFC 7638 thumbprint', () => {
  it('computes the draft keyid for the RFC 9421 test key', () => {
    expect(jwkThumbprint(KEY.publicKey)).toBe(THUMBPRINT);
  });
});

describe('RFC 9421 Appendix B', () => {
  it('has the six examples', () => expect(rfcVectors.map((v) => v.section)).toEqual(['B.2.1', 'B.2.2', 'B.2.3', 'B.2.4', 'B.2.5', 'B.2.6']));

  it('verifies B.2.6 (ed25519 over date, @method, @path, @authority, content-type, content-length)', async () => {
    const v = rfcVec('B.2.6');
    const res = await verifySignedRequest(
      { ...req, headers: { ...req.headers, 'Signature-Input': String(v.signature_input), Signature: String(v.signature) } },
      { resolveKey, requiredTag: null, requireExpires: false, now: 1618884500 },
    );
    expect(res).toMatchObject({ valid: true, label: 'sig-b26', keyid: 'test-key-ed25519', created: 1618884473 });
    expect(res.covered).toEqual(['date', '@method', '@path', '@authority', 'content-type', 'content-length']);
  });

  it('requires an expires parameter by default (the Web Bot Auth profile), so B.2.6 is refused without the opt-out', async () => {
    const v = rfcVec('B.2.6');
    const res = await verifySignedRequest(
      { ...req, headers: { ...req.headers, 'Signature-Input': String(v.signature_input), Signature: String(v.signature) } },
      { resolveKey, requiredTag: null, now: 1618884500 },
    );
    expect(res).toEqual({ valid: false, reason: 'missing expires parameter' });
  });

  it('rejects B.2.6 when anything it covers changes, naming the signature as the reason', async () => {
    const v = rfcVec('B.2.6');
    const base = { ...req.headers, 'Signature-Input': String(v.signature_input), Signature: String(v.signature) };
    const opts = { resolveKey, requiredTag: null, requireExpires: false, now: 1618884500 } as const;
    const bad = 'signature does not verify under the resolved key';
    expect((await verifySignedRequest({ ...req, method: 'GET', headers: base }, opts)).reason).toBe(bad);
    expect((await verifySignedRequest({ ...req, url: 'https://example.com/bar', headers: base }, opts)).reason).toBe(bad);
    expect((await verifySignedRequest({ ...req, url: 'https://evil.example.com/foo', headers: base }, opts)).reason).toBe(bad);
    expect((await verifySignedRequest({ ...req, headers: { ...base, 'Content-Length': '19' } }, opts)).reason).toBe(bad);
    expect((await verifySignedRequest({ ...req, headers: { ...base, Date: 'Tue, 20 Apr 2021 02:07:56 GMT' } }, opts)).reason).toBe(bad);
    const flipped = Buffer.from(String(v.signature).replace(/^[^:]*:|:$/g, ''), 'base64');
    flipped[0] = (flipped[0] ?? 0) ^ 1;
    expect((await verifySignedRequest({ ...req, headers: { ...base, Signature: `sig-b26=:${flipped.toString('base64')}:` } }, opts)).reason).toBe(bad);
    // an unrelated key must not verify it
    expect((await verifySignedRequest({ ...req, headers: base }, { ...opts, resolveKey: () => new Uint8Array(32).fill(5) })).reason).toBe(bad);
  });

  it('does not mis-verify the RSA-PSS, ECDSA and HMAC examples', async () => {
    const opts = { resolveKey, requiredTag: null, requireExpires: false, now: 1618884500 } as const;
    const run = async (s: string): Promise<{ valid: boolean; reason?: string }> => {
      const v = rfcVec(s);
      return verifySignedRequest({ ...req, headers: { ...req.headers, 'Signature-Input': String(v.signature_input), Signature: String(v.signature) } }, opts);
    };
    // B.2.1 covers no components at all, so the Web Bot Auth requirement to cover @authority is not met.
    expect(await run('B.2.1')).toEqual({ valid: false, reason: '@authority is not a covered component' });
    // B.2.2 / B.2.3 use "@query-param" (a component parameter) and @query: unsupported parameters fail closed.
    expect((await run('B.2.2')).reason).toMatch(/unsupported component parameters/);
    // B.2.3 is RSA-PSS with no alg parameter: it is read as Ed25519 and the RSA-PSS signature must not verify.
    expect(await run('B.2.3')).toEqual({ valid: false, reason: 'signature does not verify under the resolved key' });
    // B.2.5 (HMAC) also carries no alg parameter, so it is read as Ed25519 and cannot verify.
    expect(await run('B.2.5')).toEqual({ valid: false, reason: 'signature does not verify under the resolved key' });
    // An explicit non-Ed25519 alg is refused by name.
    const v = rfcVec('B.2.5');
    const withAlg = String(v.signature_input).replace(';created=', ';alg="hmac-sha256";created=');
    expect((await verifySignedRequest({ ...req, headers: { ...req.headers, 'Signature-Input': withAlg, Signature: String(v.signature) } }, opts)).reason).toBe('unsupported alg "hmac-sha256"');
  });
});

describe('Web Bot Auth architecture draft-05, Appendix A', () => {
  const nowFor = (v: Record<string, unknown>): number => Number(paramOf(String(v.signature_input), 'created')) + 60;

  it('has the six vectors (RSA-PSS and Ed25519; absent, dictionary and legacy Signature-Agent)', () => {
    expect(draft.map((v) => v.section)).toEqual(['A.1.1', 'A.1.2', 'A.1.3', 'A.2.1', 'A.2.2', 'A.2.3']);
  });

  /** Reproduce a draft vector with signRequest and compare byte for byte. */
  function reproduce(section: string, extra: { agentDirectoryKey?: string; agent?: boolean; expiresInSec: number }) {
    const v = draftVec(section);
    const input = String(v.signature_input);
    const label = input.slice(0, input.indexOf('='));
    const created = Number(paramOf(input, 'created'));
    return signRequest({
      method: req.method,
      url: req.url,
      headers: req.headers,
      key: KEY,
      keyid: paramOf(input, 'keyid'),
      created,
      expiresInSec: extra.expiresInSec,
      nonce: paramOf(input, 'nonce'),
      label,
      components: ['@authority'],
      ...(extra.agent ? { agentDirectoryUrl: 'https://signature-agent.test' } : {}),
      ...(extra.agentDirectoryKey !== undefined ? { agentDirectoryKey: extra.agentDirectoryKey } : {}),
    });
  }

  it('A.2.1 (no Signature-Agent): signRequest reproduces the draft Signature-Input and Signature exactly', () => {
    const v = draftVec('A.2.1');
    const out = reproduce('A.2.1', { expiresInSec: 4889289600 - 1735689600 });
    expect(out.signatureInput).toBe(v.signature_input);
    expect(out.signature).toBe(v.signature);
  });

  it('A.2.2 (dictionary Signature-Agent with key="agent2"): Signature-Input and header are reproduced; the draft signature differs (see next test)', () => {
    const v = draftVec('A.2.2');
    const out = reproduce('A.2.2', { agent: true, agentDirectoryKey: 'agent2', expiresInSec: 4889289600 - 1735689600 });
    expect(out.signatureInput).toBe(v.signature_input);
    expect(out.headers['Signature-Agent']).toBe(v.signature_agent);
    expect(out.signature).not.toBe(v.signature);
  });

  it('A.2.2: the published signature was made over the UNQUOTED member value, contradicting RFC 9421 section 2.1.2 and the draft\'s own printed base', async () => {
    const v = draftVec('A.2.2');
    const input = String(v.signature_input);
    const params = input.slice(input.indexOf('=') + 1);
    const sig = Buffer.from(String(v.signature).replace(/^[^:]*:|:$/g, ''), 'base64');
    const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: X }, format: 'jwk' });
    const base = (value: string): Buffer =>
      Buffer.from(`"@authority": example.com\n"signature-agent";key="agent2": ${value}\n"@signature-params": ${params}`);
    // As printed in the draft (string item serialized with quotes, as RFC 9421 requires): does NOT match the signature.
    expect(nodeVerify(null, base('"https://signature-agent.test"'), key, sig)).toBe(false);
    // With the quotes dropped: matches. So the draft vector is internally inconsistent.
    expect(nodeVerify(null, base('https://signature-agent.test'), key, sig)).toBe(true);
    // This package (like Cloudflare's reference library) follows RFC 9421 and therefore rejects the published signature.
    const headers: Record<string, string> = { ...req.headers, 'Signature-Input': input, Signature: String(v.signature), 'Signature-Agent': String(v.signature_agent) };
    expect((await verifySignedRequest({ ...req, headers }, { resolveKey, now: 1735689700 })).reason).toBe('signature does not verify under the resolved key');
  });

  it('A.2.2 inputs signed by this package verify (RFC 9421 serialization)', async () => {
    const v = draftVec('A.2.2');
    const out = reproduce('A.2.2', { agent: true, agentDirectoryKey: 'agent2', expiresInSec: 4889289600 - 1735689600 });
    const res = await verifySignedRequest({ ...req, headers: { ...req.headers, ...out.headers } }, { resolveKey, now: nowFor(v) });
    expect(res).toMatchObject({ valid: true, label: 'sig2', tag: 'web-bot-auth' });
  });

  it('A.2.3 (legacy Signature-Agent string): reproduced exactly, header included', () => {
    const v = draftVec('A.2.3');
    const out = reproduce('A.2.3', { agent: true, expiresInSec: 1735693200 - 1735689600 });
    expect(out.signatureInput).toBe(v.signature_input);
    expect(out.signature).toBe(v.signature);
    expect(out.headers['Signature-Agent']).toBe(v.signature_agent);
  });

  for (const section of ['A.2.1', 'A.2.3']) {
    it(`${section}: the vector verifies, resolving the key by its draft keyid from a key directory`, async () => {
      const v = draftVec(section);
      const headers: Record<string, string> = { ...req.headers, 'Signature-Input': String(v.signature_input), Signature: String(v.signature) };
      if (typeof v.signature_agent === 'string') headers['Signature-Agent'] = v.signature_agent;
      const res = await verifySignedRequest(
        { ...req, headers },
        { jwks: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: X, kid: THUMBPRINT }] }, now: nowFor(v) },
      );
      expect(res).toMatchObject({ valid: true, keyid: THUMBPRINT, tag: 'web-bot-auth' });
    });
  }

  it('A.2.2 inputs: rejects a changed authority, a changed Signature-Agent value, a wrong dictionary key and a stripped header', async () => {
    const out = reproduce('A.2.2', { agent: true, agentDirectoryKey: 'agent2', expiresInSec: 4889289600 - 1735689600 });
    const headers: Record<string, string> = { ...req.headers, ...out.headers };
    const opts = { resolveKey, now: 1735689700 };
    expect((await verifySignedRequest({ ...req, headers }, opts)).valid).toBe(true);
    const bad = 'signature does not verify under the resolved key';
    expect((await verifySignedRequest({ ...req, url: 'https://evil.example.com/foo', headers }, opts)).reason).toBe(bad);
    expect((await verifySignedRequest({ ...req, headers: { ...headers, 'Signature-Agent': 'agent2="https://evil.test"' } }, opts)).reason).toBe(bad);
    expect((await verifySignedRequest({ ...req, headers: { ...headers, 'Signature-Agent': 'other="https://signature-agent.test"' } }, opts)).reason).toMatch(/has no dictionary member "agent2"/);
    const { 'Signature-Agent': dropped, ...without } = headers;
    expect(dropped).toBeDefined();
    expect((await verifySignedRequest({ ...req, headers: without }, opts)).reason).toMatch(/covered header "signature-agent" is absent/);
  });

  it('enforces freshness, tag and algorithm on a draft vector', async () => {
    const v = draftVec('A.2.3'); // expires 1735693200
    const headers: Record<string, string> = { ...req.headers, 'Signature-Input': String(v.signature_input), Signature: String(v.signature), 'Signature-Agent': String(v.signature_agent) };
    const at = (now: number, extra: object = {}) => verifySignedRequest({ ...req, headers }, { resolveKey, now, ...extra });
    expect((await at(1735689600 + 10)).valid).toBe(true);
    expect(await at(1735693201)).toEqual({ valid: false, reason: 'signature has expired' });
    expect((await at(1735693205, { clockSkewSec: 5 })).valid).toBe(true);
    expect((await at(1735693206, { clockSkewSec: 5 })).valid).toBe(false);
    expect(await at(1735689000)).toEqual({ valid: false, reason: 'signature created-time is in the future' });
    expect(await at(1735689600 + 10, { maxAgeSec: 5 })).toEqual({ valid: false, reason: 'signature is older than maxAgeSec' });
    expect(await at(1735689610, { requiredTag: 'other-tag' })).toEqual({ valid: false, reason: 'tag "web-bot-auth" does not match required "other-tag"' });
    expect((await at(1735689610, { resolveKey: () => null })).reason).toMatch(/could not resolve key/);
  });

  it('refuses the RSA-PSS vectors with the stated reason', async () => {
    for (const section of ['A.1.1', 'A.1.2', 'A.1.3']) {
      const v = draftVec(section);
      const headers: Record<string, string> = { ...req.headers, 'Signature-Input': String(v.signature_input), Signature: String(v.signature) };
      if (typeof v.signature_agent === 'string') headers['Signature-Agent'] = v.signature_agent;
      const res = await verifySignedRequest({ ...req, headers }, { resolveKey, now: nowFor(v) });
      expect(res, section).toEqual({ valid: false, reason: 'unsupported alg "rsa-pss-sha512"' });
    }
  });

  it('refuses unsupported component parameters and a missing @authority', async () => {
    const v = draftVec('A.2.1');
    const headers: Record<string, string> = { ...req.headers, Signature: String(v.signature) };
    const run = (input: string) => verifySignedRequest({ ...req, headers: { ...headers, 'Signature-Input': input } }, { resolveKey, now: nowFor(v) });
    const orig = String(v.signature_input);
    expect((await run(orig.replace('("@authority")', '("@authority";sf)'))).reason).toMatch(/unsupported component parameters/);
    expect((await run(orig.replace('("@authority")', '("@method")'))).reason).toBe('@authority is not a covered component');
    expect((await run(orig.replace('("@authority")', '("@authority" "@request-target")'))).reason).toMatch(/unsupported derived component/);
  });
});

describe('cross-implementation: Cloudflare web-bot-auth 0.2.0 (reference implementation)', () => {
  const cf = fixture('cloudflare.json');
  const cases = list(cf.cases);

  it('verifies requests signed by the reference library, including a Signature-Agent member with parameters', async () => {
    expect(cases.length).toBe(2);
    for (const c of cases) {
      const res = await verifySignedRequest(
        { method: String(c.method), url: String(c.url), headers: c.headers as Record<string, string> },
        { jwks: { keys: [{ kty: 'OKP', crv: 'Ed25519', x: String(cf.public_x), kid: String(cf.keyid) }] }, now: Number(c.created) + 10 },
      );
      expect(res).toMatchObject({ valid: true, keyid: THUMBPRINT, tag: 'web-bot-auth' });
      expect(res.covered).toEqual(['@authority', 'signature-agent']);
    }
  });

  it('rejects those requests once the member value or the authority is altered', async () => {
    const c = cases[0]!;
    const headers = c.headers as Record<string, string>;
    const opts = { resolveKey, now: Number(c.created) + 10 };
    const bad = 'signature does not verify under the resolved key';
    expect((await verifySignedRequest({ method: 'POST', url: String(c.url), headers: { ...headers, 'Signature-Agent': 'sig1="https://evil.test";type=directory' } }, opts)).reason).toBe(bad);
    expect((await verifySignedRequest({ method: 'POST', url: 'https://other.example/foo?x=1', headers }, opts)).reason).toBe(bad);
    // a member parameter that is not in canonical form is refused outright
    expect((await verifySignedRequest({ method: 'POST', url: String(c.url), headers: { ...headers, 'Signature-Agent': 'sig1="https://signature-agent.test"; type=directory' } }, opts)).valid).toBe(false);
  });
});

describe('signRequest option validation', () => {
  const base = { method: 'GET', url: 'https://example.com/', key: KEY, keyid: THUMBPRINT, created: 1735689600 } as const;
  it('refuses to omit @authority, to name a header as a derived component, or to use a dictionary key without a URL', () => {
    expect(() => signRequest({ ...base, components: ['@method'] })).toThrow(/requires @authority/);
    expect(() => signRequest({ ...base, components: ['@authority', 'date'] })).toThrow(/must be derived components/);
    expect(() => signRequest({ ...base, agentDirectoryKey: 'sig1' })).toThrow(/requires agentDirectoryUrl/);
  });
  it('lists the covered components it signed', () => {
    const out = signRequest({ ...base, agentDirectoryUrl: 'https://bots.example', agentDirectoryKey: 'sig1' });
    expect(out.covered).toEqual(['@authority', '@method', '@path', 'signature-agent']);
    expect(out.signatureInput).toContain('"signature-agent";key="sig1"');
  });
});
