import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair } from '@atlasauth/pca';
import { admitWithEvidence, signBlueprint } from '@atlasauth/pca-grants';
import { holderBindingMessage, spiffeAdmissionEvidence } from './index';

const ID = 'spiffe://example.org/workload/db';
const operator = generateKeyPair();
const bp = (spiffe_id: string) => signBlueprint(operator.secretKey, { id: 'fleet', key: 'bpkey', ceiling: [], epoch: 1, status: 'active', issued_at: 1, runtime_pins: [{ spiffe_id }] });

const dir = mkdtempSync(join(tmpdir(), 'spiffe-adm-'));
const sh = (...a: string[]): void => void execFileSync('openssl', a, { cwd: dir, stdio: 'ignore' });
let haveOpenssl = true;
try {
  sh('req', '-x509', '-newkey', 'ed25519', '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-subj', '/CN=root', '-days', '30', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  writeFileSync(join(dir, 'ext'), `subjectAltName=URI:${ID}\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n`);
  sh('genpkey', '-algorithm', 'ed25519', '-out', 'ed.key');
  sh('req', '-new', '-key', 'ed.key', '-subj', '/CN=ed', '-out', 'ed.csr');
  sh('x509', '-req', '-in', 'ed.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'ed.pem', '-days', '10', '-extfile', 'ext');
} catch {
  haveOpenssl = false;
}
const NOW = new Date();
const rd = (f: string): string => readFileSync(join(dir, f), 'utf8');
const x509 = (over: object = {}) => ({ kind: 'x509' as const, chain: rd('ed.pem'), verify: { trustDomain: 'example.org', roots: [rd('root.pem')], now: NOW, ...over } });

describe('SPIFFE evidence for blueprint admission - T-593', () => {
  it.runIf(haveOpenssl)('a verified X.509-SVID bound to the instance key admits under a matching spiffe_id pin', async () => {
    const svidKey = createPrivateKey(rd('ed.key'));
    const stranger = generateKeyPair();
    const strangerKey = b64u(stranger.publicKey);
    const proof = b64u(nodeSign(null, holderBindingMessage(ID, strangerKey), svidKey));
    const e = await spiffeAdmissionEvidence({ ...x509(), bind: { proof } }, strangerKey);
    expect(e).toEqual({ ok: true, bound: true, identity: { spiffe_id: ID } });
    expect(await admitWithEvidence(bp(ID), () => e)).toMatchObject({ admitted: true });
    expect(await admitWithEvidence(bp('spiffe://example.org/workload/other'), () => e)).toMatchObject({ admitted: false, code: 'no_matching_pin' });
  });
  it.runIf(haveOpenssl)('everything unverifiable or unbound denies', async () => {
    const stranger = b64u(generateKeyPair().publicKey);
    expect(await spiffeAdmissionEvidence(x509(), stranger)).toMatchObject({ ok: false, bound: false }); // a different key needs a proof
    expect(await spiffeAdmissionEvidence(x509({ trustDomain: 'other.org' }), stranger)).toMatchObject({ ok: false });
    expect(await spiffeAdmissionEvidence(x509({ roots: [rd('ed.pem')] }), stranger)).toMatchObject({ ok: false }); // not an authority of the bundle
    expect(await spiffeAdmissionEvidence(x509({ now: new Date(NOW.getTime() + 365 * 86_400_000) }), stranger)).toMatchObject({ ok: false }); // expired
    expect(await spiffeAdmissionEvidence({ ...x509(), chain: 'not a certificate' }, stranger)).toMatchObject({ ok: false });
    expect(await spiffeAdmissionEvidence({ kind: 'jwt', token: 'x.y.z', verify: { trustDomain: 'example.org', audience: 'a', key: new Uint8Array(32) } }, stranger)).toMatchObject({ ok: false });
    const wrong = b64u(nodeSign(null, holderBindingMessage(ID, b64u(generateKeyPair().publicKey)), createPrivateKey(rd('ed.key'))));
    expect(await spiffeAdmissionEvidence({ ...x509(), bind: { proof: wrong } }, stranger)).toMatchObject({ ok: false }); // proof is for another key
  });
});
