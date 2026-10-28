/**
 * An OAuth authorization server carries a PCA grant; the resource server still requires a per-action proof.
 *
 *   npm install && npm start                      # offline: the authorization server is simulated in-process
 *   ATLAS_ISSUER=https://id.example.com ATLAS_CLIENT_ID=... ATLAS_CLIENT_SECRET=... ATLAS_ACCESS_TOKEN=... npm start
 *                                                 # live: the token is introspected at the Atlas instance
 *
 * Live mode needs an Atlas instance with `oauthProvider.authorizationDetailsTypesSupported` containing `pca_grant`
 * and an access token that was requested with the `authorization_details` this script prints (see README).
 */
import { agent, generateKeyPair, verifyPCActnCore } from '@atlasauth/pca';
import { authorizePcaGrantToken, buildPcaGrantDetail, pcaGrantRequestParam } from '@atlasauth/pca-oauth';

const RESOURCE = 'https://api.example.com';

// The agent and its grant (the principal approved: write tickets).
const bot = agent({ principal: generateKeyPair(), goal: 'close duplicate tickets', permissions: { tickets: ['write'] }, aud: RESOURCE });
const { pcactn } = bot.act('write', 'tickets/42', { aud: RESOURCE });
const chainIds = pcactn.cap_chain.map((c) => c.id);

// 1. The detail the client asks the authorization server to put into the access token.
const detail = buildPcaGrantDetail({ chainIds: chainIds.slice(0, 1), locations: [RESOURCE] });
console.log('authorization_details =', pcaGrantRequestParam([detail]));

// 2. What the authorization server returns for that token (RFC 7662 introspection with RFC 9396 section 9.2).
async function introspect(): Promise<{ active: boolean; authorization_details?: unknown }> {
  const issuer = process.env.ATLAS_ISSUER;
  if (!issuer) return { active: true, authorization_details: [detail] }; // simulated server
  const basic = Buffer.from(`${process.env.ATLAS_CLIENT_ID}:${process.env.ATLAS_CLIENT_SECRET}`).toString('base64');
  const res = await fetch(`${issuer}/oauth2/introspect`, {
    method: 'POST',
    headers: { authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: process.env.ATLAS_ACCESS_TOKEN ?? '' }),
  });
  return (await res.json()) as { active: boolean; authorization_details?: unknown };
}

// 3. The resource server: the token names the grant, the PCActn proves this action.
const token = await introspect();
const proofVerified = (await verifyPCActnCore(pcactn, { grant: bot.grant, audience: RESOURCE })).allow;
const withProof = token.active ? authorizePcaGrantToken({ authorizationDetails: token.authorization_details, resource: RESOURCE, chainIds, proofVerified }) : { allow: false };
const tokenAlone = token.active ? authorizePcaGrantToken({ authorizationDetails: token.authorization_details, resource: RESOURCE, chainIds, proofVerified: false }) : { allow: false };

console.log('token + verified proof ->', withProof.allow ? 'ALLOWED' : 'DENIED');
console.log('token alone            ->', tokenAlone.allow ? 'ALLOWED' : 'DENIED');
if (!withProof.allow || tokenAlone.allow) process.exit(1);
