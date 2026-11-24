import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { publicKeyOf } from './keys';
import { mintRoot } from './capability';
import { buildPCActn, signPCActn, type PCActn } from './pcactn';
import { verifyPCActnCore } from './pcactn-full';
import { signFreshAt, type FreshAtPolicy, type FreshAtState } from './fresh-at';
import { decisionOf } from './decision';
import { paramsDigest } from './merkle';

/**
 * Conformance vectors for the `fresh_at` PCActn member (conformance/fresh-at-vectors.json), in the case shape of vectors.json
 * (grant, plan_nodes, context, pcactn, expect) plus `context.fresh_at` (the verifier's policy: pinned signer, scope, its own state
 * counters, optional max token age, `require`, and the pre-member `side_carried` token). Every native verifier replays them.
 * Deterministic (seeds = sha256 of a label, Ed25519 signatures are deterministic). UPDATE_FRESH_AT_VECTORS=1 rewrites the file.
 */
const FILE = join(__dirname, '..', 'conformance', 'fresh-at-vectors.json');
const seed = (label: string): Uint8Array => new Uint8Array(createHash('sha256').update(`atlas-pca-conformance/${label}`).digest());
const NOW = 1_800_000_000_000;
const AUD = 'rs-conformance';
const CHECKS = ['version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'] as const;
const KEYMAP: Record<string, string> = { chain: 'cap_chain' };

const S: FreshAtState = { revocation_epoch: 5, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest: 'pd3' };

async function build() {
  const principal = seed('principal');
  const agent = seed('agent');
  const tokenKey = seed('fresh-at-signer');
  const otherKey = seed('fresh-at-other-signer');
  const root = mintRoot({ principalSecret: principal, principalPublic: b64u(publicKeyOf(principal)), holder: b64u(publicKeyOf(agent)), caveats: [] });
  const planNodes = [{ id: 'n1', verb: 'read', resource: 'db/users' }, { id: 'n2', verb: 'write', resource: 'db/orders', params_digest: paramsDigest({ qty: 3 }), reversibility_class: 'reversible' }];
  const signer = b64u(publicKeyOf(tokenKey));
  const tok = (state: FreshAtState = S, o: { scope?: string; at?: number; key?: Uint8Array } = {}) => signFreshAt(o.key ?? tokenKey, o.scope ?? 'inst_1', state, o.at ?? NOW - 1000);
  const act = (fresh_at?: unknown): PCActn =>
    buildPCActn({ aud: AUD, now: NOW, ttlMs: 600_000, grant: root, chain: [root], plan: planNodes, nodeId: 'n2', params: { qty: 3 }, counter: 7, signerSecret: agent, ...(fresh_at !== undefined ? { freshAt: fresh_at as never } : {}) });
  const policy = (local: FreshAtState = S, extra: Record<string, unknown> = {}) => ({ signer, scope: 'inst_1', local, ...extra });

  /** The vector context is snake_case JSON; `side_carried` present (even null) means a side-carried token was presented. */
  const toPolicy = (f: Record<string, unknown>): FreshAtPolicy => ({
    signer: f.signer as string, scope: f.scope as string, local: f.local as FreshAtState,
    ...(f.max_token_age_ms !== undefined ? { maxTokenAgeMs: f.max_token_age_ms as number } : {}),
    ...(f.require === true ? { require: true } : {}),
    ...('side_carried' in f ? { sideCarried: f.side_carried } : {}),
  });
  const vectors: unknown[] = [];
  async function add(name: string, description: string, pcactn: unknown, fresh: Record<string, unknown> | undefined, want: { allow: boolean; fresh_at: 'pass' | 'fail' | 'absent'; decision: 'allow' | 'deny' | 'escalate'; reason?: string; falseChecks?: string[] }) {
    const r = await verifyPCActnCore(pcactn as PCActn, { insecureSkipPlanRootCheck: true, grant: root, nowEpoch: NOW, audience: AUD, ...(fresh ? { freshAt: toPolicy(fresh) } : {}) });
    const c = r.checks;
    const wireFail = c.wire === 'fail';
    const checks: Record<string, boolean> = wireFail ? { wire: false } : { wire: true, ...Object.fromEntries(CHECKS.map((k) => [k, c[KEYMAP[k] ?? k] === 'pass'])) };
    const gotFresh = wireFail ? 'absent' : c.fresh_at === undefined ? 'absent' : c.fresh_at;
    const decision = decisionOf({ allow: r.allow, checks: c, reasons: r.reason ? [r.reason] : [] });
    // assert the stated intent: the reference result is checked against what we meant, so a reference bug cannot become a vector
    if (r.allow !== want.allow || gotFresh !== want.fresh_at || decision !== want.decision || (want.reason !== undefined && r.reason !== want.reason)) {
      throw new Error(`vector ${name}: reference ${JSON.stringify({ allow: r.allow, fresh_at: gotFresh, decision, reason: r.reason })} != intended ${JSON.stringify(want)}`);
    }
    const falseGot = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k).sort();
    if (JSON.stringify(falseGot) !== JSON.stringify([...(want.falseChecks ?? [])].sort())) throw new Error(`vector ${name}: false checks ${falseGot} != intended ${want.falseChecks}`);
    vectors.push({
      name, class: want.allow ? 'positive' : 'negative', description, grant: root, plan_nodes: planNodes,
      context: { now: NOW, aud: AUD, ...(fresh ? { fresh_at: fresh } : {}) }, pcactn,
      expect: { allow: r.allow, checks, fresh_at: gotFresh, decision, ...(r.reason !== undefined ? { reason: r.reason } : {}) },
    });
  }

  const T = tok();
  const P0 = act(T);
  await add('member-equal-state', 'Verifier state equals the token: fresh_at passes.', P0, policy(), { allow: true, fresh_at: 'pass', decision: 'allow' });
  await add('member-newer-state', 'Verifier is ahead of the token on every counter.', P0, policy({ revocation_epoch: 9, ledger_tree_size: 500, budget_version: 8, policy_revision: 4, policy_digest: 'pd4' }), { allow: true, fresh_at: 'pass', decision: 'allow' });
  for (const k of ['revocation_epoch', 'ledger_tree_size', 'budget_version'] as const) {
    await add(`member-stale-${k}`, `Verifier is behind the token on ${k}: escalate (stale_state), never allow.`, P0, policy({ ...S, [k]: S[k] - 1 }), {
      allow: false, fresh_at: 'fail', decision: 'escalate', reason: `fresh_at: escalate: stale_state (verifier state is behind the token on ${k})`,
    });
  }
  await add('member-stale-policy-revision', 'Verifier runs an older policy revision than the token.', P0, policy({ ...S, policy_revision: 2, policy_digest: 'pd2' }), {
    allow: false, fresh_at: 'fail', decision: 'escalate', reason: 'fresh_at: escalate: stale_state (verifier state is behind the token on policy_revision)',
  });
  await add('member-stale-two-fields', 'Two counters behind: both are named, in field order.', P0, policy({ ...S, revocation_epoch: 4, budget_version: 6 }), {
    allow: false, fresh_at: 'fail', decision: 'escalate', reason: 'fresh_at: escalate: stale_state (verifier state is behind the token on revocation_epoch, budget_version)',
  });
  await add('member-policy-fork', 'Same policy revision, different digest: a fork is a hard denial.', P0, policy({ ...S, policy_digest: 'other' }), { allow: false, fresh_at: 'fail', decision: 'deny', reason: 'fresh_at: policy_fork' });
  await add('member-wrong-scope', 'The token is for another scope.', P0, policy(S, { scope: 'inst_2' }), { allow: false, fresh_at: 'fail', decision: 'deny', reason: 'fresh_at: wrong_scope' });
  await add('member-wrong-signer', 'The verifier pins a different token signer.', P0, policy(S, { signer: b64u(publicKeyOf(otherKey)) }), { allow: false, fresh_at: 'fail', decision: 'deny', reason: 'fresh_at: bad_token' });
  await add('member-too-old', 'maxTokenAgeMs is exceeded (token age 1000 ms, limit 999).', P0, policy(S, { max_token_age_ms: 999 }), { allow: false, fresh_at: 'fail', decision: 'deny', reason: 'fresh_at: token_too_old' });
  await add('member-age-boundary', 'Token age equals the limit: ok.', P0, policy(S, { max_token_age_ms: 1000 }), { allow: true, fresh_at: 'pass', decision: 'allow' });
  await add('member-from-the-future', 'The token is issued more than 60 s after the verifier clock.', act(tok(S, { at: NOW + 60_001 })), policy(), { allow: false, fresh_at: 'fail', decision: 'deny', reason: 'fresh_at: token_from_the_future' });
  await add('member-future-skew-boundary', 'Issued exactly 60 s ahead: ok.', act(tok(S, { at: NOW + 60_000 })), policy(), { allow: true, fresh_at: 'pass', decision: 'allow' });
  {
    const forged = { ...T, sig: (T.sig.startsWith('A') ? 'B' : 'A') + T.sig.slice(1) };
    await add('member-forged-token-signature', 'The token signature does not verify (the PCActn itself is correctly signed over it).', act(forged), policy(), { allow: false, fresh_at: 'fail', decision: 'deny', reason: 'fresh_at: bad_token' });
  }
  {
    const swapped = { ...P0, fresh_at: tok({ ...S, revocation_epoch: 0 }) };
    await add('member-swapped-after-signing', 'The member was replaced after the leaf signed: leaf_signature fails.', swapped, policy(), { allow: false, fresh_at: 'pass', decision: 'deny', falseChecks: ['leaf_signature'] });
  }
  await add('member-without-policy', 'The PCActn carries fresh_at but the verifier has no fresh_at policy: refused (fail closed).', P0, undefined, {
    allow: false, fresh_at: 'fail', decision: 'deny', reason: 'fresh_at: the PCActn carries fresh_at but this verifier has no fresh_at policy (fail closed)',
  });
  await add('no-member-no-policy', 'No member and no policy: the check is not reported (byte-identical to before).', act(), undefined, { allow: true, fresh_at: 'absent', decision: 'allow' });
  await add('no-member-policy-not-required', 'A policy that does not require a token and no token: not reported.', act(), policy(), { allow: true, fresh_at: 'absent', decision: 'allow' });
  await add('no-member-required', 'The policy requires a token and none is presented: escalate (refresh and retry).', act(), policy(S, { require: true }), {
    allow: false, fresh_at: 'fail', decision: 'escalate', reason: 'fresh_at: escalate: a consistency token is required (refresh and retry with the token of your latest write)',
  });
  await add('side-carried-ok', 'No member, a side-carried token (the pre-member form, readable for one release) at the verifier state: ok.', act(), policy(S, { side_carried: T }), { allow: true, fresh_at: 'pass', decision: 'allow' });
  await add('side-carried-stale', 'The side-carried token is ahead of the verifier: escalate.', act(), policy({ ...S, revocation_epoch: 4 }, { side_carried: T }), {
    allow: false, fresh_at: 'fail', decision: 'escalate', reason: 'fresh_at: escalate: stale_state (verifier state is behind the token on revocation_epoch)',
  });
  await add('member-wins-over-side-carried', 'Both present: the signed member is what counts, the header beside it is ignored.', P0, policy(S, { side_carried: tok({ ...S, revocation_epoch: 99 }) }), { allow: true, fresh_at: 'pass', decision: 'allow' });
  await add('side-carried-garbage', 'A side-carried value that is not a token is a bad token (deny), never a missing one.', act(), policy(S, { side_carried: null }), { allow: false, fresh_at: 'fail', decision: 'deny', reason: 'fresh_at: bad_token' });
  // wire failures: terminal, nothing else evaluated
  for (const [name, member, why] of [
    ['wire-unknown-member-key', { ...T, extra: 1 }, "'fresh_at' has an unknown field 'extra'"],
    ['wire-negative-counter', { ...T, revocation_epoch: -1 }, "'fresh_at.revocation_epoch' must be a non-negative safe integer"],
    ['wire-short-signature', { ...T, sig: 'AAAA' }, "'fresh_at.sig' is not canonical base64url (64 bytes)"],
    ['wire-not-an-object', 'x', "'fresh_at' must be an object"],
  ] as const) {
    const { sig: _s, ...body } = P0;
    void _s;
    const p = signPCActn({ ...body, fresh_at: member } as never, agent);
    await add(name, `Malformed member (${why}): the wire check fails and nothing else is evaluated.`, p, policy(), { allow: false, fresh_at: 'absent', decision: 'deny', falseChecks: ['wire'] });
  }
  return { format: 1, about: 'Conformance vectors for the fresh_at PCActn member. context.fresh_at: {signer, scope, local, max_token_age_ms?, require?, side_carried?}. Generated by packages/pca/src/fresh-at-vectors.test.ts.', check_order: ['wire', ...CHECKS, 'fresh_at'], vectors };
}

describe('fresh-at-vectors.json', () => {
  it('the committed file is what the reference produces and every case matches its stated intent', async () => {
    const text = `${JSON.stringify(await build(), null, 1)}\n`;
    if (process.env.UPDATE_FRESH_AT_VECTORS === '1') writeFileSync(FILE, text);
    expect(readFileSync(FILE, 'utf8')).toBe(text);
  });
});
