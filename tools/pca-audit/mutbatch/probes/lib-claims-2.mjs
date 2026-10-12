// More direct probes of library behaviour that ledger reasons rely on (cloud box only).
import { createRequire } from 'node:module';
const require = createRequire(new URL('../../../../packages/pca-oidc/package.json', import.meta.url));
const jose = await import(require.resolve('jose'));
const out = (k, v) => console.log('CLAIM', k, '=>', JSON.stringify(v));
for (const s of ['', '!!!', 'abc', '\u0000', 'a=', '====', 'x'.repeat(5)]) {
  let r; try { r = jose.base64url.decode(s).length; } catch (e) { r = 'THROWS ' + e.message; }
  out(`jose base64url.decode(${JSON.stringify(s)}) never throws (oidc)`, r);
}
for (const u of ['http://[::1]/', 'http://[::1]:8080/x', 'https://[0:0:0:0:0:0:0:1]/']) out(`URL hostname of ${u} is bracketed (mcp-rs)`, new URL(u).hostname);
const { generateKeyPairSync } = await import('node:crypto');
const ed = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
for (const alg of ['EdDSA', '', 'RS256', undefined]) { let r; try { const k = await jose.importJWK(ed, alg); r = k.type ?? typeof k; } catch (e) { r = 'THROWS ' + e.code; } out(`jose importJWK(OKP, ${JSON.stringify(alg)})`, r); }
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
for (const alg of ['ES256', '', 'RS256', undefined]) { let r; try { const k = await jose.importJWK(ec, alg); r = k.type ?? typeof k; } catch (e) { r = 'THROWS ' + e.code; } out(`jose importJWK(EC, ${JSON.stringify(alg)})`, r); }
out('jose version', (await import(require.resolve('jose/package.json'), { with: { type: 'json' } }).catch(() => ({ default: {} }))).default.version);
