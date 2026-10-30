/**
 * Tell a client exactly what was missing. A resource server that answers 403 insufficient_scope can add one more field to the
 * WWW-Authenticate header, pca_need, with the typed requirement (which verb on which resource, what limit). A stock OAuth or MCP
 * client ignores it and steps up by scope as it always did. A PCA-aware client reads it and can start an approve-or-amend flow.
 *
 * The hint is unsigned and advisory. It grants nothing; the server decides again from the proof it is shown next time.
 *
 * Run it:  npm run mcp-pca-need      (exits nonzero if any outcome is not the expected one)
 */
import { decodePcaNeed, encodePcaNeed, pcaNeedDigest, pcaNeedFromChallenge, type PcaNeed } from '@atlasauth/pca';
import { pcaNeedProblem, planStepUp } from '@atlasauth/pca-mcp';
import { wwwAuthenticateChallenge } from '@atlasauth/pca-mcp-rs';
import { expectOutcome, finish } from './check.js';

const METADATA = 'https://rs.example/.well-known/oauth-protected-resource';

// ---- server: the refund the agent asked for is over what its grant allows ---------------------------------------------------

const need: PcaNeed = {
  v: 1,
  kind: 'scope',
  verb: 'stripe.refund',
  resource: 'charge/ch_1',
  scopes: ['refunds:write'],
  limits: { 'money.usd': 40 }, // the amount this request would need
};
const header = wwwAuthenticateChallenge({
  resourceMetadataUrl: METADATA,
  error: 'insufficient_scope',
  scope: 'refunds:write',
  pcaNeed: need,
});
const plain = wwwAuthenticateChallenge({ resourceMetadataUrl: METADATA, error: 'insufficient_scope', scope: 'refunds:write' });

expectOutcome('the header carries pca_need', header.includes('pca_need="'), true);
expectOutcome('the header still names the scope', header.includes('scope="refunds:write"'), true);
expectOutcome('the need round-trips', pcaNeedFromChallenge(header), { ok: true, need });

// ---- a stock client: ignores pca_need, same plan as without it -------------------------------------------------------------

const state = { requested: ['tickets:read'], attempts: 0 };
const stock = planStepUp(403, header, state);
expectOutcome('a stock client steps up by scope', stock, { action: 'scope', scopes: ['refunds:write', 'tickets:read'], attempts: 1 });
expectOutcome('and does exactly what it does without the field', planStepUp(403, plain, state), stock);

// ---- a PCA-aware client: gets the typed need, and the scope fallback too ---------------------------------------------------

const aware = planStepUp(403, header, { ...state, pcaAware: true });
expectOutcome('a PCA-aware client gets the typed need', aware, { action: 'pca', need, fallbackScopes: ['refunds:write', 'tickets:read'], attempts: 1 });
expectOutcome('a need has a stable content address for the approval record', pcaNeedDigest(need) === pcaNeedDigest({ ...need }), true);
expectOutcome('a different resource has a different one', pcaNeedDigest(need) === pcaNeedDigest({ ...need, resource: 'charge/ch_2' }), false);

// ---- bad or hostile values never break the client --------------------------------------------------------------------------

const broken = `Bearer error="insufficient_scope", scope="refunds:write", pca_need="!!!"`;
expectOutcome('a malformed pca_need falls back to the scope step-up', planStepUp(403, broken, { requested: [], attempts: 0, pcaAware: true }), { action: 'scope', scopes: ['refunds:write'], attempts: 1 });
expectOutcome('and the client can log why', pcaNeedProblem(broken), 'bad_base64');
const extra = encodePcaNeed(need).replace(/.$/, '');
expectOutcome('a truncated value is refused, not guessed', decodePcaNeed(extra).ok, false);
expectOutcome('a need with an unreviewed member is refused', decodePcaNeed(Buffer.from(JSON.stringify({ ...need, admin: true })).toString('base64url')), { ok: false, code: 'unknown_member' });

// ---- the loop is bounded -----------------------------------------------------------------------------------------------------

expectOutcome('the third retry', planStepUp(403, header, { requested: [], attempts: 3 }), { action: 'give_up', reason: 'retry_limit' });
expectOutcome('asking again for a scope already held', planStepUp(403, plain, { requested: ['refunds:write'], attempts: 1 }), { action: 'give_up', reason: 'no_new_scope' });
expectOutcome('a 401 is not a step-up', planStepUp(401, plain, state), { action: 'give_up', reason: 'not_insufficient_scope' });

// ---- a step-up that needs a person ----------------------------------------------------------------------------------------

const escalate: PcaNeed = { v: 1, kind: 'escalate', verb: 'stripe.refund', resource: 'charge/ch_1', tier: 3 };
expectOutcome('an escalation names who must approve', decodePcaNeed(encodePcaNeed(escalate)), { ok: true, need: escalate });
expectOutcome('a tier on a scope need is malformed', decodePcaNeed(Buffer.from(JSON.stringify({ ...need, tier: 2 })).toString('base64url')), { ok: false, code: 'bad_field' });

finish();
