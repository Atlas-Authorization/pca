import { describe, expect, it, vi } from 'vitest';
import {
  type Capability,
  type CapabilityChain,
  type PCActn,
  type PlanNode,
  type PolicyDecision,
  type Signer,
  type ThresholdSignature,
  type VerifyResult,
  DEFAULT_RISK_POLICY,
  assembleThreshold,
  attenuate,
  budgetAllocCaveat,
  buildPCActn,
  decide,
  delegate,
  encodeKey,
  generateKeyPair,
  mintGrant,
  requiredThreshold,
  signShare,
  thresholdMessage,
  verifyPCActnCore,
} from '@atlasauth/pca';
import {
  type FetchLike,
  type FetchLikeResponse,
  type PcaDecisionRecord,
  type SiemEvent,
  type SiemSink,
  consoleSink,
  exportBatch,
  exportDecision,
  formatDecision,
  httpSink,
  toCef,
  toEcs,
  toOcsfEvent,
} from './index';

// A fixed clock so every fixture is deterministic.
const NOW = 1_800_000_000_000;
const AUD = 'rs-prod-1';

// ---------------------------------------------------------------------------------------------------
// Fixtures — REAL verified PCActns built with the core, one per auditor-facing outcome.
// ---------------------------------------------------------------------------------------------------

function keys() {
  return {
    principal: generateKeyPair(),
    agent: generateKeyPair(),
    sub: generateKeyPair(),
    guardian: generateKeyPair(),
  };
}

const PLAN: PlanNode[] = [
  { id: 'n-refund', verb: 'stripe.refund', resource: 'charge/ch_1', reversibility_class: 'reversible' },
  { id: 'n-delete', verb: 'account.delete', resource: 'acct/ac_9', reversibility_class: 'irreversible' },
];

function mintEnvelopeGrant(k: ReturnType<typeof keys>): Capability {
  const { grant } = mintGrant({
    principalSecret: k.principal.secretKey,
    principalPublic: encodeKey(k.principal.publicKey),
    holder: encodeKey(k.agent.publicKey),
    goal: 'process customer refunds',
    envelope: {
      predicates: [
        { verb: 'stripe.refund', resource: 'charge/*' },
        { verb: 'account.delete', resource: 'acct/*' },
      ],
      caveats: [],
      agent_binding: {},
      risk_policy: DEFAULT_RISK_POLICY,
    },
  });
  return grant;
}

/** A real three-hop chain: root grant → attenuated agent hop (adds budget_alloc) → sub-agent leaf. */
function buildChain(k: ReturnType<typeof keys>, grant: Capability): CapabilityChain {
  const agentHop = attenuate(grant, [budgetAllocCaveat(0.5)], k.agent.secretKey);
  const leaf = delegate(agentHop, encodeKey(k.sub.publicKey), [], k.agent.secretKey);
  return [grant, agentHop, leaf];
}

function buildActn(
  k: ReturnType<typeof keys>,
  grant: Capability,
  chain: CapabilityChain,
  nodeId: string,
  opts: { threshold?: ThresholdSignature; counter?: number } = {},
): PCActn {
  const actn = buildPCActn({
    grant,
    chain,
    plan: PLAN,
    nodeId,
    counter: opts.counter ?? 1,
    signerSecret: k.sub.secretKey,
    aud: AUD,
    iat: NOW,
    exp: NOW + 60_000,
  });
  if (opts.threshold) return { ...actn, threshold: opts.threshold };
  return actn;
}

function coSign(k: ReturnType<typeof keys>, actn: PCActn): ThresholdSignature {
  const signerSet: Signer[] = [
    { role: 'agent', publicKey: encodeKey(k.sub.publicKey) },
    { role: 'guardian', publicKey: encodeKey(k.guardian.publicKey) },
    { role: 'principal', publicKey: encodeKey(k.principal.publicKey) },
  ];
  const msg = thresholdMessage(actn);
  const t = 3;
  const agentShare = signShare('agent', k.sub.secretKey, msg);
  const guardianShare = signShare('guardian', k.guardian.secretKey, msg, { signerSet, t });
  const principalShare = signShare('principal', k.principal.secretKey, msg, { signerSet, t });
  return assembleThreshold([agentShare, guardianShare, principalShare]);
}

interface Fixture {
  record: PcaDecisionRecord;
  verify: VerifyResult;
  decision?: PolicyDecision;
  k: ReturnType<typeof keys>;
}

/** ALLOW — a low-risk refund, auto-admitted by the real Policy VM. */
async function allowFixture(): Promise<Fixture> {
  const k = keys();
  const grant = mintEnvelopeGrant(k);
  const chain = buildChain(k, grant);
  const actn = buildActn(k, grant, chain, 'n-refund');
  const verify = await verifyPCActnCore(actn, { grant, nowEpoch: NOW, audience: AUD });
  const decision = decide({
    grant,
    chain,
    action: { action: { verb: 'stripe.refund', resource: 'charge/ch_1' } },
    plan: PLAN,
    risk: { semanticDistance: 0.05, reversibility: 1, blastRadius: 0.05, taint: 0, confidence: 1 },
    budget: { B: 1, tau: NOW },
    now: NOW,
    nodeId: 'n-refund',
  });
  return { record: { pcactn: actn, verify, decision, now: NOW }, verify, decision, k };
}

/** DENY — a tampered PCActn: the core verifier rejects it (real deny from the core). */
async function denyFixture(): Promise<Fixture> {
  const k = keys();
  const grant = mintEnvelopeGrant(k);
  const chain = buildChain(k, grant);
  const actn = buildActn(k, grant, chain, 'n-refund', { counter: 2 });
  const tampered: PCActn = { ...actn, action: { ...actn.action, resource: 'charge/ch_ATTACKER' } };
  const verify = await verifyPCActnCore(tampered, { grant, nowEpoch: NOW, audience: AUD });
  return { record: { pcactn: tampered, verify, now: NOW }, verify, k };
}

/** STEP-UP (approved) — a high-risk irreversible action, released by a signed principal co-signature. */
async function stepUpFixture(): Promise<Fixture> {
  const k = keys();
  const grant = mintEnvelopeGrant(k);
  const chain = buildChain(k, grant);
  const base = buildActn(k, grant, chain, 'n-delete', { counter: 3 });
  const threshold = coSign(k, base);
  const actn = buildActn(k, grant, chain, 'n-delete', { threshold, counter: 3 });
  const verify = await verifyPCActnCore(actn, { grant, nowEpoch: NOW, audience: AUD });
  const rt = requiredThreshold(0.9, DEFAULT_RISK_POLICY, { irreversible: true });
  const decision: PolicyDecision = {
    releaseGuardianShare: true,
    requiredThreshold: rt,
    r: 0.9,
    admit: false,
    needStepUp: true,
    reasons: ['high-risk irreversible action requires human co-signature'],
    budget: { B: 1, tau: NOW },
  };
  return { record: { pcactn: actn, verify, decision, now: NOW }, verify, decision, k };
}

// ---------------------------------------------------------------------------------------------------
// toOcsfEvent
// ---------------------------------------------------------------------------------------------------

describe('toOcsfEvent — OCSF 1.x Authorize Session (IAM)', () => {
  it('ALLOW: right class/activity/action/status + actor(agent+principal) + resource/api + proof digest in unmapped', async () => {
    const { record, verify } = await allowFixture();
    expect(verify.allow).toBe(true);
    const ev = toOcsfEvent(record);

    // Authorization/IAM category + Authorize Session class.
    expect(ev.category_uid).toBe(3);
    expect(ev.category_name).toBe('Identity & Access Management');
    expect(ev.class_uid).toBe(3003);
    expect(ev.class_name).toBe('Authorize Session');
    // activity_id carries the allow disposition; type_uid follows the OCSF rule.
    expect(ev.activity_id).toBe(1);
    expect(ev.activity_name).toBe('Allow');
    expect(ev.type_uid).toBe(3003 * 100 + 1);
    // canonical disposition + success status.
    expect(ev.action_id).toBe(1);
    expect(ev.action).toBe('Allowed');
    expect(ev.status_id).toBe(1);
    expect(ev.status).toBe('Success');
    expect(ev.severity_id).toBe(1); // tier-1 allow = Informational

    // actor = agent + authorizing principal.
    const leaf = record.pcactn.cap_chain[record.pcactn.cap_chain.length - 1];
    const root = record.pcactn.cap_chain[0];
    expect(ev.actor.user.uid).toBe(leaf?.holder);
    expect(ev.actor.user.type).toBe('Agent');
    expect(ev.actor.invoked_by).toBe(root?.issuer);
    expect(ev.user.uid).toBe(root?.issuer); // OCSF subject = authorizing principal

    // resource + api describe the action.
    expect(ev.resources[0]?.name).toBe('charge/ch_1');
    expect(ev.api.operation).toBe('stripe.refund');

    // metadata.product = PCA.
    expect(ev.metadata.product.name).toBe('PCA');
    expect(ev.time).toBe(record.pcactn.iat);

    // PCA edge in unmapped: proof digest + risk tier + delegation depth + full chain.
    const u = ev.unmapped;
    expect(typeof u.proof_digest).toBe('string');
    expect(u.proof_digest).not.toBe('(undigestible)');
    expect(u.risk_tier).toBe(1);
    expect(u.delegation_depth).toBe(2);
    expect(Array.isArray(u.delegation_chain)).toBe(true);
    expect((u.delegation_chain as unknown[]).length).toBe(3);
    expect(u.cryptographically_verifiable).toBe(true);
    // The proof digest is also an observable.
    expect(ev.observables.some((o) => o.name === 'pca.proof.digest' && o.value === u.proof_digest)).toBe(true);
  });

  it('DENY: activity/action/status reflect the denial; still cites the (unverifiable) proof', async () => {
    const { record, verify } = await denyFixture();
    expect(verify.allow).toBe(false);
    const ev = toOcsfEvent(record);
    expect(ev.activity_id).toBe(2);
    expect(ev.activity_name).toBe('Deny');
    expect(ev.action).toBe('Denied');
    expect(ev.status_id).toBe(2);
    expect(ev.status).toBe('Failure');
    expect(ev.severity_id).toBe(4); // a security check (plan_inclusion/leaf_signature) failed => High
    expect(ev.unmapped.cryptographically_verifiable).toBe(false);
    expect(typeof ev.unmapped.proof_digest).toBe('string');
    expect(ev.unmapped.checks).toBeTypeOf('object');
  });

  it('STEP-UP: distinct activity + Other status + human-override recorded', async () => {
    const { record } = await stepUpFixture();
    const ev = toOcsfEvent(record);
    expect(ev.activity_id).toBe(3);
    expect(ev.activity_name).toBe('Step-Up');
    expect(ev.status).toBe('Other');
    const ho = ev.unmapped.human_override as { human_approved?: boolean; approvers?: string[] } | undefined;
    expect(ho?.human_approved).toBe(true);
    expect((ho?.approvers ?? []).length).toBe(1);
    expect(ev.unmapped.risk_tier).toBe(3);
  });
});

// ---------------------------------------------------------------------------------------------------
// toCef
// ---------------------------------------------------------------------------------------------------

describe('toCef — ArcSight CEF line', () => {
  it('ALLOW: well-formed header + PCA extensions, with escaping', async () => {
    const { record } = await allowFixture();
    const line = toCef(record);

    // CEF:0|Atlas|PCA|<ver>|<sigId>|<name>|<sev>|ext...  — 7 header fields (no reserved pipes here),
    // then the extension (which contains no '|'), so split('|') yields exactly 8 fields.
    expect(line.startsWith('CEF:0|Atlas|PCA|')).toBe(true);
    const fields = line.split('|');
    expect(fields).toHaveLength(8);
    expect(fields[1]).toBe('Atlas');
    expect(fields[2]).toBe('PCA');
    expect(fields[3]).toBe('2'); // PCActn wire version
    expect(fields[4]).toBe('pca-authz-allow');
    expect(fields[5]).toContain('stripe.refund');
    expect(Number(fields[6])).toBeGreaterThanOrEqual(0);

    const ext = fields[7] ?? '';
    expect(ext).toContain('act=allow');
    expect(ext).toContain('outcome=allow');
    const leaf = record.pcactn.cap_chain[record.pcactn.cap_chain.length - 1];
    expect(ext).toContain(`duser=${leaf?.holder}`);
    // PCA edge: the proof digest + delegation chain are carried as labelled custom fields.
    expect(ext).toContain('cs1Label=pcaProofDigest');
    expect(ext).toMatch(/cs1=[A-Za-z0-9_\-]/);
    expect(ext).toContain('cs2Label=pcaDelegationChain');
    expect(ext).toContain('cn2Label=pcaDelegationDepth');
    expect(ext).toContain('cn2=2');
  });

  it('escapes reserved characters in extension values (= , backslash , newline) and pipe in the header name', () => {
    const pcactn: PCActn = {
      ver: 2,
      action: { verb: 'weird|verb', resource: 'a=b\nc\\d', params_digest: 'pd', reversibility_class: 'reversible' },
      grant_ref: 'g',
      cap_chain: [],
      plan: { root: 'r', inclusion_proof: { index: 0, size: 1, path: [] }, node_id: 'n' },
      attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
      provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
      freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
      counter: 0,
      risk_claim: { r: 0, inputs: {} },
      aud: AUD,
      iat: NOW,
      exp: NOW + 1000,
      sig: 'deadbeef',
    };
    const record: PcaDecisionRecord = {
      pcactn,
      verify: { allow: false, checks: { wire: 'fail' }, reason: 'wire: x=y\nbad' },
      now: NOW,
    };
    const line = toCef(record);
    expect(line.startsWith('CEF:0|Atlas|PCA|')).toBe(true);
    // The header NAME escapes the reserved pipe as '\|' (so it is not a header delimiter).
    expect(line).toContain('weird\\|verb');
    // Extension values escape '\', '=' and newlines (colon is NOT reserved in CEF values).
    expect(line).toContain('request=a\\=b\\nc\\\\d');
    expect(line).toContain('msg=wire: x\\=y\\nbad');
    // No raw newline (or carriage return) survived anywhere in the line.
    expect(line.includes('\n')).toBe(false);
    expect(line.includes('\r')).toBe(false);
  });
});

// ---------------------------------------------------------------------------------------------------
// toEcs
// ---------------------------------------------------------------------------------------------------

describe('toEcs — Elastic Common Schema', () => {
  it('ALLOW: category/action/outcome + user + related + pca.* edge', async () => {
    const { record } = await allowFixture();
    const ev = toEcs(record);
    expect(ev['ecs.version']).toBe('8.11.0');
    expect(ev.event.kind).toBe('event');
    expect(ev.event.category).toEqual(['iam']);
    expect(ev.event.type).toEqual(['allowed']);
    expect(ev.event.outcome).toBe('success');
    expect(ev.event.action).toBe('stripe.refund');
    expect(typeof ev.event.risk_score).toBe('number');

    const leaf = record.pcactn.cap_chain[record.pcactn.cap_chain.length - 1];
    const root = record.pcactn.cap_chain[0];
    expect(ev.user.id).toBe(leaf?.holder);
    expect(ev.user.effective.id).toBe(root?.issuer); // authorizing principal
    // related.user correlates agent + principal; related.hash carries the proof digest.
    expect(ev.related.user).toContain(leaf?.holder);
    expect(ev.related.user).toContain(root?.issuer);
    expect(ev.related.hash.length).toBeGreaterThan(0);

    const pca = ev.pca as { proof?: { digest?: string }; delegation?: { depth?: number; chain?: string } };
    expect(typeof pca.proof?.digest).toBe('string');
    expect(pca.delegation?.depth).toBe(2);
    expect(typeof pca.delegation?.chain).toBe('string');
  });

  it('DENY maps to failure/denied; STEP-UP maps to unknown/info', async () => {
    const deny = toEcs((await denyFixture()).record);
    expect(deny.event.outcome).toBe('failure');
    expect(deny.event.type).toEqual(['denied']);

    const stepUp = toEcs((await stepUpFixture()).record);
    expect(stepUp.event.outcome).toBe('unknown');
    expect(stepUp.event.type).toEqual(['info']);
  });
});

// ---------------------------------------------------------------------------------------------------
// Sinks + export orchestration
// ---------------------------------------------------------------------------------------------------

describe('httpSink — batched POST via an injectable fetch', () => {
  it('POSTs the batch as NDJSON in the chosen format with headers', async () => {
    const calls: { url: string; init: { method: string; headers: Record<string, string>; body: string } }[] = [];
    const fakeFetch: FetchLike = async (url, init) => {
      calls.push({ url, init });
      return { ok: true, status: 200 } satisfies FetchLikeResponse;
    };
    const sink = httpSink('https://hec.example/services/collector', {
      format: 'ocsf',
      fetch: fakeFetch,
      headers: { authorization: 'Splunk test-token' },
    });

    const batch = [(await allowFixture()).record, (await denyFixture()).record];
    const res = await exportBatch(batch, sink);
    expect(res.ok).toBe(true);
    expect(res.delivered).toBe(2);
    expect(res.format).toBe('ocsf');

    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call?.url).toBe('https://hec.example/services/collector');
    expect(call?.init.method).toBe('POST');
    expect(call?.init.headers['content-type']).toBe('application/x-ndjson');
    expect(call?.init.headers.authorization).toBe('Splunk test-token');
    // Body is two NDJSON lines, each a parseable OCSF object.
    const lines = (call?.init.body ?? '').split('\n');
    expect(lines).toHaveLength(2);
    const first = JSON.parse(lines[0] ?? '{}') as { class_uid?: number; metadata?: { product?: { name?: string } } };
    expect(first.class_uid).toBe(3003);
    expect(first.metadata?.product?.name).toBe('PCA');
  });

  it('serializes CEF as raw lines (not JSON)', async () => {
    let body = '';
    const fakeFetch: FetchLike = async (_url, init) => {
      body = init.body;
      return { ok: true, status: 202 };
    };
    const sink = httpSink('https://intake.example', { format: 'cef', fetch: fakeFetch });
    const res = await exportDecision((await allowFixture()).record, sink);
    expect(res.ok).toBe(true);
    expect(body.startsWith('CEF:0|Atlas|PCA|')).toBe(true);
  });
});

describe('fail-safe — a sink error never throws into the caller', () => {
  it('swallows a thrown fetch error, reports via onError, returns ok:false', async () => {
    const throwingFetch: FetchLike = async () => {
      throw new Error('network down');
    };
    const sink = httpSink('https://down.example', { format: 'ecs', fetch: throwingFetch });
    const onError = vi.fn();

    let result: Awaited<ReturnType<typeof exportDecision>> | undefined;
    await expect(
      (async () => {
        result = await exportDecision((await allowFixture()).record, sink, { onError });
      })(),
    ).resolves.toBeUndefined();

    expect(result?.ok).toBe(false);
    expect(result?.delivered).toBe(0);
    expect(result?.error).toContain('network down');
    expect(onError).toHaveBeenCalledTimes(1);
  });

  it('swallows a non-2xx status', async () => {
    const fiveHundred: FetchLike = async () => ({ ok: false, status: 503, statusText: 'Service Unavailable' });
    const sink = httpSink('https://err.example', { format: 'ecs', fetch: fiveHundred });
    const res = await exportDecision((await allowFixture()).record, sink);
    expect(res.ok).toBe(false);
    expect(res.error).toContain('503');
  });

  it('an onError callback that itself throws cannot escape', async () => {
    const throwingFetch: FetchLike = async () => {
      throw new Error('boom');
    };
    const sink = httpSink('https://x.example', { format: 'ocsf', fetch: throwingFetch });
    const res = await exportDecision((await allowFixture()).record, sink, {
      onError: () => {
        throw new Error('onError blew up');
      },
    });
    expect(res.ok).toBe(false);
    expect(res.error).toContain('boom');
  });

  it('a sink whose deliver() throws synchronously is still contained', async () => {
    const badSink: SiemSink = {
      name: 'bad',
      format: 'ocsf',
      deliver(): never {
        throw new Error('deliver exploded');
      },
    };
    const res = await exportDecision((await allowFixture()).record, badSink);
    expect(res.ok).toBe(false);
    expect(res.error).toContain('deliver exploded');
  });
});

describe('consoleSink + formatDecision', () => {
  it('consoleSink writes each event line to the logger', async () => {
    const seen: string[] = [];
    const sink = consoleSink({ format: 'ecs', logger: (l) => seen.push(l) });
    const res = await exportBatch([(await allowFixture()).record, (await stepUpFixture()).record], sink);
    expect(res.ok).toBe(true);
    expect(res.delivered).toBe(2);
    expect(seen).toHaveLength(2);
    const parsed = JSON.parse(seen[0] ?? '{}') as { 'ecs.version'?: string };
    expect(parsed['ecs.version']).toBe('8.11.0');
  });

  it('formatDecision produces an object line for ocsf/ecs and a string line for cef', async () => {
    const { record } = await allowFixture();
    const ocsf: SiemEvent = formatDecision(record, 'ocsf');
    expect(ocsf.object).toBeDefined();
    expect(JSON.parse(ocsf.line)).toBeTypeOf('object');
    const cef: SiemEvent = formatDecision(record, 'cef');
    expect(cef.object).toBeUndefined();
    expect(cef.line.startsWith('CEF:0|')).toBe(true);
  });
});
