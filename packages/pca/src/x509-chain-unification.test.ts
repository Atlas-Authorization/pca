/**
 * B15 (0.5): the MAA `x5c` chain, the MAA key-set chain, the GCP `x5c` chain and the NVIDIA device chain run the same strict
 * profile as the AMD and Intel chains (`strictChainError`): CA roles (leaf is not a CA, every issuer is a CA with keyCertSign
 * and a respected pathLenConstraint) and no unrecognised critical extension. Each chain below is signed correctly, inside its
 * validity window and anchored in the configured root, so before B15 every one of them verified; now each is refused with an
 * exact reason, and the well-formed control chain still passes.
 */
import { describe, expect, it } from 'vitest';
import { verifyX5cChain } from './attest-azure-maa';
import { verifyJwkX5cChain } from './attest-gcp-confidential-space';
import { verifyNvidiaDeviceChain } from './attest-nvidia-spdm';
import { evaluateMaaJwks } from './attest-maa-keys';
import { strictChainError } from './x509-strict';
import { ext, extension, forgeCert, forgeKey, octets, seq, boolean, type Extension, type ForgeKey } from './test-support/forge-x509';

const NOW = Date.UTC(2026, 5, 1);
const FROM = new Date(Date.UTC(2020, 0, 1));
const TO = new Date(Date.UTC(2040, 0, 1));
const rootKey = forgeKey('b15-root', 'P-384');
const midKey = forgeKey('b15-mid', 'P-384');
const leafKey = forgeKey('b15-leaf', 'P-384');

interface Shape { root?: Extension[]; mid?: Extension[]; leaf?: Extension[] }
const CA = [ext.basicConstraints(true), ext.keyUsage(['keyCertSign', 'cRLSign'])];
const LEAF = [ext.basicConstraints(false), ext.keyUsage(['digitalSignature'])];
const unknownCritical = extension('1.2.3.4.5', true, octets(seq(boolean(true))));

function chain(s: Shape = {}) {
  const root = forgeCert({ subject: [['CN', 'B15 Root']], issuer: [['CN', 'B15 Root']], subjectKey: rootKey, signer: rootKey, serial: 1n, notBefore: FROM, notAfter: TO, extensions: s.root ?? CA });
  const mid = forgeCert({ subject: [['CN', 'B15 Mid']], issuer: [['CN', 'B15 Root']], subjectKey: midKey, signer: rootKey, serial: 2n, notBefore: FROM, notAfter: TO, extensions: s.mid ?? CA });
  const leaf = forgeCert({ subject: [['CN', 'B15 Leaf']], issuer: [['CN', 'B15 Mid']], subjectKey: leafKey, signer: midKey, serial: 3n, notBefore: FROM, notAfter: TO, extensions: s.leaf ?? LEAF });
  return { ders: [leaf.der, mid.der, root.der], b64: [leaf, mid, root].map((c) => Buffer.from(c.der).toString('base64')), pem: [leaf, mid, root].map((c) => c.pem).join('') };
}

/** Each row is a chain that is correctly signed and anchored but violates one profile rule. */
const BAD: Array<[string, Shape, string]> = [
  ['leaf asserts CA:TRUE', { leaf: [ext.basicConstraints(true), ext.keyUsage(['digitalSignature'])] }, 'leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)'],
  ['intermediate is CA:FALSE', { mid: [ext.basicConstraints(false), ext.keyUsage(['keyCertSign'])] }, 'issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)'],
  ['intermediate has no BasicConstraints', { mid: [ext.keyUsage(['keyCertSign'])] }, 'issuer certificate at depth 1 has no BasicConstraints (not a CA)'],
  ['intermediate keyUsage lacks keyCertSign', { mid: [ext.basicConstraints(true), ext.keyUsage(['digitalSignature'])] }, 'issuer certificate at depth 1 keyUsage lacks keyCertSign'],
  ['root pathLenConstraint exceeded', { root: [ext.basicConstraints(true, 0), ext.keyUsage(['keyCertSign'])] }, 'issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)'],
  ['unrecognised critical extension on the leaf', { leaf: [...LEAF, unknownCritical] }, 'certificate at depth 0 has an unrecognised critical extension 1.2.3.4.5'],
  ['unrecognised critical extension on the intermediate', { mid: [...CA, unknownCritical] }, 'certificate at depth 1 has an unrecognised critical extension 1.2.3.4.5'],
];

describe('strictChainError: the shared profile', () => {
  it('passes the control chain and gives the exact reason for every violation', () => {
    expect(strictChainError(chain().ders)).toBeUndefined();
    for (const [, shape, reason] of BAD) expect(strictChainError(chain(shape).ders)).toBe(reason);
  });
  it('a pathLenConstraint that is respected passes; a critical ExtendedKeyUsage is recognised', () => {
    expect(strictChainError(chain({ root: [ext.basicConstraints(true, 1), ext.keyUsage(['keyCertSign'])] }).ders)).toBeUndefined();
    expect(strictChainError(chain({ leaf: [...LEAF, ext.extKeyUsage(['1.3.6.1.5.5.7.3.1'], true)] }).ders)).toBeUndefined();
  });
  it('garbage DER is a failure, never a pass', () => {
    expect(strictChainError([Uint8Array.of(1, 2, 3)])).toMatch(/^certificate extension parse failed: /);
  });
});

describe('MAA x5c chain (verifyX5cChain)', () => {
  const anchors = { rootSpkiSha256: [rootKey.spkiSha256] };
  it('the control chain verifies', async () => {
    expect(await verifyX5cChain(chain().b64, anchors, { nowMs: NOW })).toMatchObject({ ok: true });
  });
  it.each(BAD)('%s is refused', async (_n, shape, reason) => {
    expect(await verifyX5cChain(chain(shape).b64, anchors, { nowMs: NOW })).toEqual({ ok: false, reason: `x5c chain profile: ${reason}` });
  });
  it('the same holds when the anchor is an intermediate: only the chain up to it is judged', async () => {
    const c = chain({ root: [ext.basicConstraints(false)] }); // the root is above the pinned anchor and never consulted
    expect(await verifyX5cChain(c.b64, { rootSpkiSha256: [midKey.spkiSha256] }, { nowMs: NOW })).toMatchObject({ ok: true });
    const bad = chain({ leaf: [ext.basicConstraints(true)] });
    expect(await verifyX5cChain(bad.b64, { rootSpkiSha256: [midKey.spkiSha256] }, { nowMs: NOW })).toMatchObject({ ok: false });
  });
});

describe('GCP x5c chain (verifyJwkX5cChain)', () => {
  const anchors = { trustedKeySpki: [rootKey.spkiSha256] };
  it('the control chain verifies', async () => {
    expect(await verifyJwkX5cChain(chain().b64, anchors, { nowMs: NOW, skewMs: 0 })).toBeNull();
  });
  it.each(BAD)('%s is refused', async (_n, shape, reason) => {
    expect(await verifyJwkX5cChain(chain(shape).b64, anchors, { nowMs: NOW, skewMs: 0 })).toBe(`x5c chain profile: ${reason}`);
  });
});

describe('NVIDIA device chain (verifyNvidiaDeviceChain)', () => {
  const pins = [rootKey.spkiSha256];
  it('the control chain verifies', () => {
    expect(verifyNvidiaDeviceChain(chain().pem, pins, NOW)).toMatchObject({ ok: true });
  });
  it.each(BAD)('%s is refused', (_n, shape, reason) => {
    // the pre-existing `ca` flag check fires first for a CA:FALSE intermediate; the profile reports every other violation
    const r = verifyNvidiaDeviceChain(chain(shape).pem, pins, NOW);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason === `device chain profile: ${reason}` || /is not a CA/.test(r.reason)).toBe(true);
  });
});

describe('MAA key-set chains (evaluateMaaJwks)', () => {
  const ISSUER = 'https://b15.attest.example';
  const policy = (over = {}) => ({ trustedIssuers: [ISSUER], allowTrustOnFirstUse: true, builtinPins: false as const, chainRootSpkiSha256: [rootKey.spkiSha256], ...over });
  const jwks = (b64: string[]) => ({ keys: [{ kid: 'k1', kty: 'EC', x5c: b64 }] }) as never;
  it('the control chain is accepted under the pinned root', () => {
    expect(evaluateMaaJwks(jwks(chain().b64), ISSUER, policy(), NOW).accepted.map((a) => a.spki)).toEqual([rootKey.spkiSha256]);
  });
  it.each(BAD)('%s is rejected with the profile reason', (_n, shape, reason) => {
    const ev = evaluateMaaJwks(jwks(chain(shape).b64), ISSUER, policy(), NOW);
    expect(ev.accepted).toEqual([]);
    expect(ev.rejected).toEqual([{ kid: 'k1', reason: `chain profile: ${reason}` }]);
  });
});
