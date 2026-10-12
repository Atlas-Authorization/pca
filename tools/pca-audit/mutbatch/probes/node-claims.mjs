// Direct probes of library behaviour that ledger reasons rely on (run on a cloud box: node tools/pca-audit/mutbatch/probes/node-claims.mjs).
import { generateKeyPairSync, verify, sign, createPublicKey } from 'node:crypto';
const out = (k, v) => console.log('CLAIM', k, '=>', JSON.stringify(v));
out("Buffer base64 skips ':' delimiters (webbotauth 1725)", Buffer.from(':YWJj:', 'base64').toString() === Buffer.from('YWJj', 'base64').toString());
out("Buffer base64 skips ':' mid-value", Buffer.from(':YW:Jj:', 'base64').toString());
out('Buffer base64 ignores surrounding whitespace (require-pca 94)', Buffer.from('  eyJhIjoxfQ \t\n', 'base64').toString());
const ed = generateKeyPairSync('ed25519');
const msg = Buffer.from('m');
const good = sign(null, msg, ed.privateKey);
for (const len of [0, 1, 63, 65, 128]) {
  let r; try { r = verify(null, msg, ed.publicKey, Buffer.alloc(len)); } catch (e) { r = 'THROWS ' + e.code; }
  out(`ed25519 verify with ${len}-byte signature returns false, never throws`, r);
}
let r2; try { r2 = verify(null, msg, ed.publicKey, null); } catch (e) { r2 = 'THROWS ' + e.code; }
out('ed25519 verify with null signature throws (spiffe 2012)', r2);
out('ed25519 good verifies', verify(null, msg, ed.publicKey, good));
out('Ed25519 JWK export has string x (spiffe 2006)', typeof ed.publicKey.export({ format: 'jwk' }).x);
for (const c of ['prime256v1', 'secp384r1', 'secp256k1']) {
  const k = generateKeyPairSync('ec', { namedCurve: c });
  out(`EC ${c} asymmetricKeyDetails.namedCurve`, k.publicKey.asymmetricKeyDetails?.namedCurve);
  for (const len of [0, 1, 64, 200]) { let r; try { r = verify('sha256', msg, { key: k.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.alloc(len)); } catch (e) { r = 'THROWS ' + e.code; } out(`EC ${c} p1363 verify ${len}B`, r); }
}
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
for (const len of [0, 1, 256, 300]) { let r; try { r = verify('sha256', msg, rsa.publicKey, Buffer.alloc(len)); } catch (e) { r = 'THROWS ' + e.code; } out(`RSA verify ${len}B`, r); }
