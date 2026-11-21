import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { compactJwsAliases } from '@atlasauth/pca';
import { issuePassport } from '@atlasauth/pca/ext/attestation';
import { compactVerify } from 'jose';
import { describe, expect, it } from 'vitest';
import { didKeyFromEd25519, passportToVC, verifyPassportVC } from './index';

const raw = (k: KeyObject) => new Uint8Array(Buffer.from((k.export({ format: 'jwk' }) as { x: string }).x, 'base64url'));

describe('canonical-spelling gate (re-encoded JWT-VC strings are rejected)', () => {
  it('rejects every alias of the issuer JWT and of each disclosure; the original passes', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const sub = generateKeyPairSync('ed25519').publicKey;
    const passport = issuePassport({ model_id: 'm', weights_digest: 'w', system_prompt_digest: 'p', tool_manifest_digest: 't', runtime_measurement: '1', operator: 'o', hardware_rooted: true, weights_measured: true, issued_at: 1_700_000_000 });
    const vc = await passportToVC(passport, { issuerKey: privateKey, issuerDid: didKeyFromEd25519(raw(publicKey)), subjectDid: didKeyFromEd25519(raw(sub)), ttlSec: 3600 });
    await verifyPassportVC(vc, publicKey);
    const parts = vc.split('~');
    const aliases = compactJwsAliases(parts[0] as string);
    const joseOk = await Promise.all(aliases.map((a) => compactVerify(a.token, publicKey).then(() => 1, () => 0)));
    expect(joseOk.reduce((x: number, y: number) => x + y, 0)).toBeGreaterThan(0); // jose alone accepts an alias
    for (const a of aliases) {
      await expect(verifyPassportVC([a.token, ...parts.slice(1)].join('~'), publicKey), a.name).rejects.toThrow(/non-canonical compact JWS/);
    }
    for (const bad of [`${parts[1]}=`, ` ${parts[1]}`, `${parts[1]}\n`]) {
      await expect(verifyPassportVC([parts[0], bad, ...parts.slice(2)].join('~'), publicKey)).rejects.toThrow(/non-canonical/);
    }
  });
});
