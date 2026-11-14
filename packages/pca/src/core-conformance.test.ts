// PCA Core: a full mint -> delegate -> act -> verify round trip, and the Core conformance profile
// (conformance/core-profile.json), both through the `@atlasauth/pca/core` entry point ONLY.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  type Capability,
  type PCActn,
  type PlanNode,
  InMemoryReplayStore,
  buildPCActn,
  canonicalizeStrict,
  decodeB64uStrict,
  decodePCActn,
  decodePcaHeader,
  delegate,
  encodeKey,
  encodePCActn,
  evaluateAgentCaveats,
  generateKeyPair,
  guardPCActnReplay,
  merkleRoot,
  mintRoot,
  paramsDigest,
  pcaHeaders,
  PCA_HEADER,
  policyCaveats,
  strictParse,
  verifyChain,
  verifyInclusion,
  verifyPCActnCore,
} from './core';

describe('PCA Core round trip (mint -> delegate -> act -> verify)', () => {
  const NOW = 1_767_225_600_000; // 2026-01-01T00:00:00Z
  const AUD = 'https://payments.example';
  const principal = generateKeyPair();
  const agent = generateKeyPair();
  const sub = generateKeyPair();

  // 1. The principal mints a grant (the root capability) for the agent.
  const grant = mintRoot({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(agent.publicKey),
    caveats: [
      { type: 'expires', at: NOW + 86_400_000 },
      { type: 'max_spend', usd: 500 },
    ],
  });
  // 2. The agent delegates a narrower capability to a sub-agent (caveats can only be appended).
  const leaf = delegate(grant, encodeKey(sub.publicKey), [{ type: 'delegation_depth', max: 1 }], agent.secretKey);
  const chain: Capability[] = [grant, leaf];
  // 3. The plan the sub-agent commits to, and the one action it takes.
  const params = { amount: 42, currency: 'usd' };
  const plan: PlanNode[] = [
    { id: 'n1', verb: 'refund', resource: 'charge:ch_123', params_digest: paramsDigest(params) },
    { id: 'n2', verb: 'notify', resource: 'customer:cus_9' },
  ];
  const act = (over: Partial<Parameters<typeof buildPCActn>[0]> = {}): PCActn =>
    buildPCActn({ grant, chain, plan, nodeId: 'n1', params, counter: 1, nonce: 'n-1', signerSecret: sub.secretKey, aud: AUD, now: NOW, ...over });

  it('verifies, evaluates the caveats and accepts the action exactly once', async () => {
    expect(verifyChain(chain, grant.issuer).ok).toBe(true);
    // the sub-agent sends it in the PCA-Action header; the resource server decodes it with the strict profile
    const headers = pcaHeaders(encodePCActn(act()));
    const received = decodePCActn(decodePcaHeader(headers[PCA_HEADER]!));

    const v = await verifyPCActnCore(received, { insecureSkipPlanRootCheck: true, grant, audience: AUD, nowEpoch: NOW + 1_000 });
    expect(v.allow).toBe(true);
    for (const c of ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format']) {
      expect([c, v.checks[c]]).toEqual([c, 'pass']);
    }
    // caveat semantics (the resource server knows the plaintext params and opens params_digest with them)
    expect(paramsDigest(params)).toBe(received.action.params_digest);
    const cv = evaluateAgentCaveats(policyCaveats(grant, received.cap_chain), { now: NOW + 1_000, delegationDepth: 1 }, {
      action: { verb: received.action.verb, resource: received.action.resource, params, reversibility_class: received.action.reversibility_class },
    });
    expect(cv).toEqual({ ok: true, failed: [] });
    // anti-replay, only after verification
    const store = new InMemoryReplayStore();
    expect(await guardPCActnReplay(store, received, { aud: AUD, now: NOW + 1_000, counters: store })).toEqual({ ok: true });
    expect(await guardPCActnReplay(store, received, { aud: AUD, now: NOW + 2_000, counters: store })).toMatchObject({ ok: false, code: 'replay' });
  });

  it('denies a tampered action, a foreign audience, an expired action, an uncommitted node and a non-holder signer', async () => {
    const good = act();
    const tampered = { ...good, action: { ...good.action, resource: 'charge:ch_999' } };
    const r1 = await verifyPCActnCore(tampered, { insecureSkipPlanRootCheck: true, grant, audience: AUD, nowEpoch: NOW });
    expect([r1.allow, r1.checks.plan_inclusion, r1.checks.leaf_signature]).toEqual([false, 'fail', 'fail']);
    const r2 = await verifyPCActnCore(good, { insecureSkipPlanRootCheck: true, grant, audience: 'https://other.example', nowEpoch: NOW });
    expect([r2.allow, r2.checks.audience]).toEqual([false, 'fail']);
    const r3 = await verifyPCActnCore(good, { insecureSkipPlanRootCheck: true, grant, audience: AUD, nowEpoch: good.exp + 1 });
    expect([r3.allow, r3.checks.validity]).toEqual([false, 'fail']);
    const r4 = await verifyPCActnCore(act({ signerSecret: agent.secretKey }), { insecureSkipPlanRootCheck: true, grant, audience: AUD, nowEpoch: NOW });
    expect([r4.allow, r4.checks.leaf_signature]).toEqual([false, 'fail']);
    expect(() => act({ nodeId: 'n9' })).toThrow();
    // a valid proof of an action the caveats forbid: $900 is over max_spend
    const big = { amount: 900, currency: 'usd' };
    const p = act({ params: big, plan: [{ id: 'n1', verb: 'refund', resource: 'charge:ch_123', params_digest: paramsDigest(big) }] });
    expect((await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant, audience: AUD, nowEpoch: NOW })).allow).toBe(true);
    const cv = evaluateAgentCaveats(policyCaveats(grant, chain), { now: NOW, delegationDepth: 1 }, { action: { verb: 'refund', resource: 'charge:ch_123', params: big } });
    expect(cv).toEqual({ ok: false, failed: ['max_spend'] });
  });
});

// ---------------------------------------------------------------------------------------------- Core conformance profile
type Vector = {
  name: string;
  grant: Capability;
  context: { now: number; aud: string } & Record<string, unknown>;
  pcactn?: PCActn;
  pcactn_json?: string;
  expect: { allow: boolean; checks: Record<string, boolean>; reason_contains?: string };
  requires?: string;
  requires_suite?: unknown;
};
type Expand = { marker: string; levels: number; leaf: unknown };
const conf = (f: string) => JSON.parse(readFileSync(join(__dirname, '..', 'conformance', f), 'utf8'));
const corpus = conf('vectors.json');
const profile = conf('core-profile.json') as {
  check_order: string[];
  counts: Record<string, number>;
  vectors: string[];
  primitives: { caveat_eval: string[]; malformed: string[]; depth: string[] };
};
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- corpus entries are untyped JSON, checked field by field below
type Entry = any;
const byName = (xs: Entry[], names: string[]): Entry[] => {
  const m = new Map<string, Entry>(xs.map((x) => [x.name, x]));
  return names.map((n) => {
    const x = m.get(n);
    if (x === undefined) throw new Error(`core profile names a missing entry: ${n}`);
    return x;
  });
};
const KEY: Record<string, string> = { chain: 'cap_chain' };
const EXT_TOP = ['alg', 'pq_pk', 'pq_sig', 'threshold', 'intent', 'intent_session', 'zk_compliance', 'bond_ref'];
const EXT_HOP = ['alg', 'pq_pk', 'pq_sig', 'holder_pq'];
const has = (o: unknown, k: string) => o !== null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);

describe('PCA Core conformance profile (pca-core/1)', () => {
  const vectors: Vector[] = byName(corpus.vectors, profile.vectors);

  it('is current: the selection rule (scripts/gen-core-profile.mjs) reproduces the committed profile', async () => {
    const gen = join(__dirname, '..', 'scripts', 'gen-core-profile.mjs');
    const { selectCoreProfile } = (await import(gen)) as { selectCoreProfile: (f: unknown) => unknown };
    expect(selectCoreProfile(corpus)).toEqual(profile);
  });

  it('is a non-trivial, extension-free subset of the corpus', () => {
    expect(profile.check_order).toEqual(corpus.check_order);
    expect(vectors.length).toBe(profile.counts.vectors);
    expect(vectors.length).toBeGreaterThanOrEqual(250);
    expect(vectors.filter((v) => v.expect.allow).length).toBeGreaterThanOrEqual(30);
    for (const v of vectors) {
      expect([v.name, v.requires, v.requires_suite]).toEqual([v.name, undefined, undefined]);
      expect([v.name, Object.keys(v.context).sort()]).toEqual([v.name, ['aud', 'now']]);
      for (const k of Object.keys(v.expect.checks)) expect(corpus.check_order).toContain(k);
      const p = v.pcactn ?? (() => { try { return JSON.parse(v.pcactn_json!); } catch { return undefined; } })();
      for (const k of EXT_TOP) expect([v.name, k, has(p, k)]).toEqual([v.name, k, false]);
      for (const h of [v.grant, ...(Array.isArray(p?.cap_chain) ? p.cap_chain : [])]) for (const k of EXT_HOP) expect([v.name, k, has(h, k)]).toEqual([v.name, k, false]);
    }
  });

  for (const v of vectors) {
    it(v.name, async () => {
      let p: PCActn;
      if (v.pcactn_json !== undefined) {
        try {
          p = decodePCActn(v.pcactn_json);
        } catch {
          expect(v.expect).toEqual({ allow: false, checks: { wire: false } });
          return;
        }
      } else p = v.pcactn!;
      const r = await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant: v.grant, nowEpoch: v.context.now, audience: v.context.aud });
      expect(r.allow).toBe(v.expect.allow);
      if (v.expect.reason_contains !== undefined) expect(String(r.reason ?? '')).toContain(v.expect.reason_contains);
      const got: Record<string, boolean> = {};
      for (const k of Object.keys(v.expect.checks)) got[k] = r.checks[KEY[k] ?? k] === 'pass';
      expect(got).toEqual(v.expect.checks);
      if (v.expect.checks.wire === false) expect(Object.keys(r.checks)).toEqual(['wire']);
    });
  }

  it('primitives: canonical JSON, strict JSON, strict base64url, Merkle, PCA-Action header', () => {
    const P = corpus.primitives;
    for (const c of P.canonical) expect(canonicalizeStrict(c.value)).toBe(c.expect);
    for (const j of P.json_parse) {
      if (j.accept) expect(canonicalizeStrict(strictParse(j.input))).toBe(j.canonical);
      else expect(() => strictParse(j.input), j.input).toThrow();
    }
    for (const b of P.b64u) expect(decodeB64uStrict(b.input, b.len) !== null, b.input).toBe(b.valid);
    for (const m of P.merkle) {
      expect(merkleRoot(m.leaves)).toBe(m.root);
      m.leaves.forEach((_l: unknown, i: number) => expect(verifyInclusion(m.root, m.proofs[i], m.leaves[i])).toBe(true));
    }
    expect(paramsDigest()).toBe(P.params_digest_empty);
    for (const h of P.pca_header) {
      let text: string | undefined;
      let valid = true;
      try {
        text = decodePcaHeader(h.input);
      } catch {
        valid = false;
      }
      expect([h.name, valid]).toEqual([h.name, h.valid]);
      if (valid) expect(text).toBe(h.text);
    }
  });

  it('primitives: caveat_eval (Core caveat types)', () => {
    for (const c of byName(corpus.primitives.caveat_eval, profile.primitives.caveat_eval)) {
      const x = c.context;
      const r = evaluateAgentCaveats(
        policyCaveats(c.grant, c.chain),
        {
          now: x.now,
          delegationDepth: x.delegation_depth,
          ...(x.blast_radius !== undefined ? { blastRadius: x.blast_radius } : {}),
          ...(x.reversibility_class !== undefined ? { reversibilityClass: x.reversibility_class } : {}),
          ...(x.recent_action_times !== undefined ? { recentActionTimes: x.recent_action_times } : {}),
        },
        { action: x.action },
      );
      expect([c.name, { allow: r.ok, failed: r.failed }]).toEqual([c.name, c.expect]);
    }
  });

  it('primitives: malformed inputs are clean denials', async () => {
    for (const m of byName(corpus.primitives.malformed, profile.primitives.malformed)) {
      if (m.api === 'chain') {
        expect([m.name, verifyChain(m.input.chain, m.input.expected_root_issuer).ok]).toEqual([m.name, false]);
        continue;
      }
      let tree: unknown;
      try {
        tree = strictParse(m.input.text);
      } catch {
        continue;
      }
      const r = await verifyPCActnCore(tree as PCActn, { insecureSkipPlanRootCheck: true, grant: m.input.grant, nowEpoch: m.input.now, audience: m.input.aud });
      expect([m.name, r.allow]).toEqual([m.name, false]);
    }
  });

  it('primitives: nesting-depth limits', async () => {
    const nest = (levels: number, leaf: unknown): unknown => {
      let v = leaf;
      for (let i = 0; i < levels; i++) v = [v];
      return v;
    };
    const subst = (v: unknown, marker: string, repl: unknown): unknown => {
      if (v === marker) return repl;
      if (Array.isArray(v)) return v.map((x) => subst(x, marker, repl));
      if (v !== null && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, subst(x, marker, repl)]));
      return v;
    };
    for (const c of byName(corpus.primitives.depth, profile.primitives.depth)) {
      const e = c.expand as Expand | undefined;
      let inp = c.input;
      if (e && (c.api === 'pcactn_json' || c.api === 'json_parse')) inp = { ...inp, text: inp.text.replace(e.marker, '['.repeat(e.levels) + JSON.stringify(e.leaf) + ']'.repeat(e.levels)) };
      else if (e) inp = subst(inp, e.marker, nest(e.levels, e.leaf));
      let ok: boolean;
      if (c.api === 'chain') ok = verifyChain(inp.chain, inp.expected_root_issuer).ok;
      else {
        let tree: unknown;
        try {
          tree = strictParse(inp.text);
        } catch {
          tree = undefined;
        }
        if (tree === undefined) ok = false;
        else if (c.api === 'json_parse') ok = true;
        else ok = (await verifyPCActnCore(tree as PCActn, { insecureSkipPlanRootCheck: true, grant: inp.grant, nowEpoch: inp.now, audience: inp.aud })).allow;
      }
      expect([c.name, ok]).toEqual([c.name, c.valid]);
    }
  });
});
