/**
 * The agent never holds the credential. It describes the HTTP request it wants made, with a proof that a person authorized
 * exactly that request. The vault re-derives the proof's parameters from the request, and only then attaches the stored token
 * and makes the call itself.
 *
 * The outbound network is a fake here (a function that records what it was asked to send), so the script runs offline.
 *
 * Run it:  npm run token-vault-proxy      (exits nonzero if any outcome is not the expected one)
 */
import { b64u, buildPCActn, encodeKey, generateKeyPair, mintRoot, paramsDigest, publicKeyOf, type PCActn, type PlanNode } from '@atlasauth/pca';
import {
  TokenVault, httpExtractor, oauthScopeCaveat, verifyReleaseReceipt,
  type ProxyFetch, type ProxyRequest, type ReleaseReceipt, type VaultAction,
} from '@atlasauth/pca-connect';
import { InMemoryConnectionStore } from '@atlasauth/pca-connect/testing';
import { expectOutcome, finish } from './check.js';

const NOW = 1_800_000_000_000;
const VERB = 'bank.transfer.send';
const SECRET_TOKEN = 'AT-SECRET-VALUE'; // stands for the real provider token; it must never reach the agent

// The operator pins how a request maps back to the action's parameters. Anything the mapping does not name is refused.
const extract = httpExtractor({
  method: 'POST',
  url: 'https://api.bank.example/v1/accounts/{account}/transfers',
  body: 'json',
  fixed: { source: 'vault' },
});
const action: VaultAction = {
  verb: VERB,
  def_digest: 'A'.repeat(43),
  confirmed: true, // the action definition carries a valid signed confirmation
  upstream: { provider: 'bank', scopes_min: ['transfers:write'] },
  extract,
};

// A fake transport: records what would have been sent and answers 201.
const sent: Array<Parameters<ProxyFetch>[0]> = [];
const proxyFetch: ProxyFetch = async (req) => {
  sent.push(req);
  return { status: 201, headers: { 'content-type': 'application/json' }, body: '{"id":"tr_1"}' };
};

const receipts: ReleaseReceipt[] = [];
const vaultKey = generateKeyPair();
const vault = new TokenVault({
  strict: false, // local development; production uses an encrypting store, a replay store and a revocation source
  insecureSkipPlanRootCheck: true, // production pins the plan roots the principal authorized
  store: new InMemoryConnectionStore(),
  now: () => NOW,
  actions: (verb) => (verb === VERB ? action : undefined),
  proxyFetch,
  receipts: { secretKey: vaultKey.secretKey, sink: (r) => { receipts.push(r); } },
});

const principal = generateKeyPair();
const agent = generateKeyPair();
const principalId = encodeKey(principal.publicKey);
const agentId = encodeKey(agent.publicKey);

await vault.putConnection({
  agentId, provider: 'bank', accessToken: SECRET_TOKEN, expiresAt: NOW + 3_600_000,
  scopes: ['transfers:write', 'accounts:read'],
  authority: { principal: principalId, scopes: ['transfers:write', 'accounts:read'] },
});

// The person's grant: the agent may use the bank connection with the transfers:write scope only.
const grant = mintRoot({
  principalSecret: principal.secretKey, principalPublic: principalId, holder: agentId,
  caveats: [oauthScopeCaveat('bank', ['transfers:write'])],
});

// The proof the agent signs for one transfer. Its params digest commits to the exact parameters.
let counter = 0;
const params = { account: 'acct_1', amount: 12_500, currency: 'EUR', payee: 'Acme GmbH' };
const proofFor = (p: Record<string, unknown>, verb = VERB): PCActn => {
  const node: PlanNode = { id: 'n', verb, resource: 'bank:acct_1', params_digest: paramsDigest(p), reversibility_class: 'irreversible' };
  return buildPCActn({ grant, chain: [grant], plan: [node], nodeId: 'n', params: p, counter: ++counter, signerSecret: agent.secretKey, aud: 'rs', now: NOW });
};

const request = (body: object, url = 'https://api.bank.example/v1/accounts/acct_1/transfers'): ProxyRequest => ({
  method: 'POST', url, headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ source: 'vault', amount: 12_500, currency: 'EUR', payee: 'Acme GmbH', ...body }),
});
const outcome = async (req: ProxyRequest): Promise<string> => {
  try {
    const r = await vault.proxyCall(proofFor(params), req, { provider: 'bank' });
    return `status ${r.response.status}`;
  } catch (e) {
    return (e as { code?: string }).code ?? String(e);
  }
};

// 1. The authorized request goes through, with the token attached by the vault.
const ok = await vault.proxyCall(proofFor(params), request({}), { provider: 'bank' });
expectOutcome('the authorized transfer', ok.response.status, 201);
expectOutcome('the vault attached the token', sent[0]?.headers.authorization, `Bearer ${SECRET_TOKEN}`);
expectOutcome('the call was made with redirects off', sent[0]?.redirect, 'manual');
expectOutcome('the agent never sees the token', JSON.stringify(ok).includes(SECRET_TOKEN), false);

// 2. The receipt names what was done, and it is signed by the vault.
const vaultId = b64u(publicKeyOf(vaultKey.secretKey));
const receipt = receipts[0];
expectOutcome('a signed receipt', [receipt?.mode, receipt?.outcome, receipt?.http_status], ['proxy', 'executed', 201]);
expectOutcome('the receipt verifies against the vault key', receipt !== undefined && verifyReleaseReceipt(receipt, vaultId), true);
expectOutcome('a receipt with an edited status does not', receipt !== undefined && verifyReleaseReceipt({ ...receipt, http_status: 200 }, vaultId), false);

// 3. Every change to the request is refused before anything is sent.
const before = sent.length;
expectOutcome('a different amount', await outcome(request({ amount: 99_999 })), 'request_mismatch');
expectOutcome('a different payee', await outcome(request({ payee: 'Mallory' })), 'request_mismatch');
expectOutcome('an extra body member', await outcome(request({ memo: 'hi' })), 'request_mismatch');
expectOutcome('another account in the path', await outcome(request({}, 'https://api.bank.example/v1/accounts/acct_2/transfers')), 'request_mismatch');
expectOutcome('another host', await outcome(request({}, 'https://evil.example/v1/accounts/acct_1/transfers')), 'request_mismatch');
expectOutcome('an Authorization header from the agent', await outcome({ ...request({}), headers: { 'Content-Type': 'application/json', Authorization: 'Bearer x' } }), 'request_mismatch');
expectOutcome('nothing extra was sent', sent.length - before, 0);

// 4. A verb the operator never pinned releases nothing.
const stray = proofFor(params, 'bank.other.verb');
expectOutcome('an action nobody pinned', await vault.proxyCall(stray, request({}), { provider: 'bank' }).then(() => 'released', (e: { code?: string }) => e.code), 'unknown_action');

finish();
