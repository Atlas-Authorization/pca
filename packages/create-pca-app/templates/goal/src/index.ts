/**
 * Goal -> policy -> review -> enforce.
 *
 *   1. DRAFT    a model turns a plain instruction into a proposed policy (permissions and limits). Here the model is a
 *               stub so the template runs offline; pass your own `complete(prompt)` to use a real one.
 *   2. REVIEW   a person reads the draft. The static analyzer's findings and any verb the model made up are shown.
 *   3. SIGN     the reviewer signs the exact draft. A different draft, or an unpinned reviewer key, will not load.
 *   4. ENFORCE  only a signed draft becomes an agent, and a server decides every action against its grant.
 *
 * The model can only propose. It cannot widen anything after the person signs.
 *
 * Run it:  npm start      (exits nonzero if any outcome is not the expected one)
 */

import { encodeKey, generateKeyPair, protect, requireAuthorized } from '@atlasauth/pca';
import { agentFromApprovedNL, approveDraft, draftPolicyFromNL, loadApprovedPolicy } from '@atlasauth/pca/ext/research';

const AUD = 'ins_goal';
const instruction = 'let the support bot refund customers up to $200 a day';

// A stand-in for your model call. Real models return the same JSON shape (see nlPrompt in @atlasauth/pca).
const complete = (): string => JSON.stringify({ permissions: { stripe: ['refund'] }, limits: { refund: '$200/day' } });

let ok = true;
const check = (label: string, good: boolean, detail = ''): void => {
  if (!good) ok = false;
  console.log(`${good ? 'ok  ' : 'FAIL'} ${label}${detail ? `  ${detail}` : ''}`);
};

// 1. DRAFT
const draft = await draftPolicyFromNL({ instruction, complete });
console.log(`draft: permissions ${JSON.stringify(draft.permissions)}, limits ${JSON.stringify(draft.limits)}, analyzer ok: ${draft.analyzerOk}`);

// 2 + 3. REVIEW and SIGN (the reviewer's key is the one you pin on the server side of this step)
const reviewer = generateKeyPair();
const approval = approveDraft(draft, reviewer.secretKey);
const reviewers = [encodeKey(reviewer.publicKey)];

const forged = { ...draft, limits: { refund: '$2000/day' } }; // someone edits the draft after it was signed
check('a draft edited after signing does not load', !loadApprovedPolicy(forged, approval, { reviewers }).ok);
check('a signature from an unpinned key does not load', !loadApprovedPolicy(draft, approval, { reviewers: [encodeKey(generateKeyPair().publicKey)] }).ok);

// 4. ENFORCE
const principal = generateKeyPair();
const { agent } = agentFromApprovedNL({ draft, approval, reviewers, principal, goal: instruction, aud: AUD });
const guard = requireAuthorized(
  protect({
    audience: AUD,
    grants: [agent.grant],
    operation: (req) => {
      const b = req.body as { charge: string; params: Record<string, unknown> };
      return { verb: 'stripe.refund', resource: `charge:${b.charge}`, params: b.params };
    },
  }).options,
);
const refund = async (charge: string, amount: number): Promise<boolean> => {
  const params = { amount, currency: 'usd' };
  return (await guard({ headers: {}, body: { pcactn: agent.act('stripe.refund', `charge:${charge}`, params).encoded, charge, params } })).ok;
};
// Irreversible refunds auto-approve up to a quarter of the cap ($50 of $200); above that a human co-signs.
check('refund $40 (inside the signed policy)', await refund('ch_1', 40));
check('refund $900 (outside it)', !(await refund('ch_2', 900)));

console.log(ok ? '\nAll outcomes as expected.' : '\nAn outcome was not as expected.');
process.exit(ok ? 0 : 1);
