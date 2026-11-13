import { describe, expect, it, vi } from 'vitest';

type Fn = (...a: unknown[]) => unknown;
const m = vi.hoisted(() => ({ verify: undefined as Fn | undefined, authz: undefined as Fn | undefined, review: undefined as Fn | undefined }));
vi.mock('@atlasauth/pca', async (importOriginal) => {
  const real = await importOriginal<typeof import('@atlasauth/pca')>();
  return {
    ...real,
    verifyPCActnCore: (...a: unknown[]) => (m.verify ? m.verify(...a) : (real.verifyPCActnCore as Fn)(...a)),
    authorizeExecution: (...a: unknown[]) => (m.authz ? m.authz(...a) : (real.authorizeExecution as Fn)(...a)),
    reviewAction: (...a: unknown[]) => (m.review ? m.review(...a) : (real.reviewAction as Fn)(...a)),
  };
});

import type { PCActn, Agent, VerifyResult } from '@atlasauth/pca';
import {
  PcaToolDenied,
  pcaPrepareStep,
  pcaTools,
  provenanceFromContext,
  proofFromArgHeaders,
  proofFromContext,
  reviewToolCall,
  withPcaTool,
  type PcaToolExecuteOptions,
} from './index';

const act = (verb = 'stripe.refund'): PCActn => ({ action: { verb } }) as unknown as PCActn;
const okVerify = async (): Promise<VerifyResult> => ({ allow: true, checks: { sig: 'pass' } }) as unknown as VerifyResult;
const tool = (execute: unknown = async () => 'out') => ({ description: 'd', execute }) as never;
const denial = (p: Promise<unknown>): Promise<PcaToolDenied> =>
  p.then(
    () => {
      throw new Error('expected a denial');
    },
    (e: unknown) => e as PcaToolDenied,
  );
const sig = (over: Record<string, unknown> = {}) => ({ mode: 'signature-only' as const, verify: okVerify, require: () => act(), ...over }) as never;
const ctx = (c: unknown): PcaToolExecuteOptions => ({ experimental_context: c });

describe('PcaToolDenied', () => {
  it('carries name, verb, kind, checks and a formatted message', () => {
    const e = new PcaToolDenied('why', 'v.x', 'policy', { a: 'pass' } as never);
    expect(e.name).toBe('PcaToolDenied');
    expect(e.message).toBe('PCA tool denied (policy) for v.x: why');
    expect([e.verb, e.kind, e.checks]).toEqual(['v.x', 'policy', { a: 'pass' }]);
  });
});

describe('proof and provenance sources', () => {
  it('proofFromContext reads pca, then pcaProof, and only strings', () => {
    expect(proofFromContext({}, ctx({ pca: 'x' }))).toBe('x');
    expect(proofFromContext({}, ctx({ pcaProof: 'y' }))).toBe('y');
    expect(proofFromContext({}, ctx({ pca: 5 }))).toBeUndefined();
    expect(proofFromContext({}, ctx({ pca: 5, pcaProof: 'y' }))).toBeUndefined();
    for (const c of [undefined, null, 'str', 7]) expect(proofFromContext({}, ctx(c))).toBeUndefined();
  });
  it('provenanceFromContext reads the three spellings in order and tolerates non-records', () => {
    expect(provenanceFromContext({}, ctx({ pcaProvenance: 1, pca_provenance: 2, 'PCA-Provenance': 3 }))).toBe(1);
    expect(provenanceFromContext({}, ctx({ pca_provenance: 2, 'PCA-Provenance': 3 }))).toBe(2);
    expect(provenanceFromContext({}, ctx({ 'PCA-Provenance': 3 }))).toBe(3);
    for (const c of [undefined, null, 'str']) expect(provenanceFromContext({}, ctx(c))).toBeUndefined();
  });
  it('proofFromArgHeaders reads the default and custom header locations, strings only', () => {
    const src = proofFromArgHeaders<Record<string, unknown>>();
    expect(src({ headers: { 'PCA-Action': 'tok' } }, {})).toBe('tok');
    expect(src({ headers: { 'PCA-Action': 5 } }, {})).toBeUndefined();
    expect(src({ headers: {} }, {})).toBeUndefined();
    for (const bag of [undefined, null, 'str', 4]) expect(src({ headers: bag }, {})).toBeUndefined();
    for (const args of [null, undefined, 5, 'str']) expect(src(args as never, {})).toBeUndefined();
    expect(proofFromArgHeaders<Record<string, unknown>>('h', 'X')({ h: { X: 'z' }, headers: { 'PCA-Action': 'no' } }, {})).toBe('z');
  });
});

describe('withPcaTool denials', () => {
  it('a missing proof is a typed denial naming the label, with the exact message', async () => {
    const bare = withPcaTool(tool(), sig({ require: () => undefined }));
    const e = await denial(bare.execute!({}, {}));
    expect(e).toBeInstanceOf(PcaToolDenied);
    expect(e.message).toBe('PCA tool denied (missing) for (tool): no proof-carrying action present on the call');
    const named = withPcaTool(tool(), sig({ require: () => null, verb: 'stripe.refund' }));
    expect((await denial(named.execute!({}, {}))).verb).toBe('stripe.refund');
  });
  it('an undecodable proof is malformed and names the cause', async () => {
    const t = withPcaTool(tool(), sig({ require: () => '!!not a proof!!' }));
    const e = await denial(t.execute!({}, {}));
    expect(e.kind).toBe('malformed');
    expect(e.message.startsWith('PCA tool denied (malformed) for (tool): proof could not be decoded: ')).toBe(true);
    expect(e.message.length).toBeGreaterThan('PCA tool denied (malformed) for (tool): proof could not be decoded: '.length);
  });
  it('a proof for another verb is a binding denial with both verbs', async () => {
    const t = withPcaTool(tool(), sig({ require: () => act('other.verb'), verb: 'stripe.refund' }));
    const e = await denial(t.execute!({}, {}));
    expect(e.kind).toBe('binding');
    expect(e.verb).toBe('other.verb');
    expect(e.message).toBe("PCA tool denied (binding) for other.verb: proof is for 'other.verb', not this tool's 'stripe.refund'");
  });
  it('every denial path reports through onDeny when given', async () => {
    const seen: string[] = [];
    const onDeny = (e: PcaToolDenied) => void seen.push(e.kind);
    await denial(withPcaTool(tool(), sig({ require: () => undefined, onDeny })).execute!({}, {}));
    await denial(withPcaTool(tool(), sig({ require: () => '!!', onDeny })).execute!({}, {}));
    await denial(withPcaTool(tool(), sig({ require: () => act('x'), verb: 'y', onDeny })).execute!({}, {}));
    await denial(withPcaTool(tool(), sig({ verify: async () => ({ allow: false, checks: {}, reason: 'r' }), onDeny })).execute!({}, {}));
    expect(seen).toEqual(['missing', 'malformed', 'binding', 'verify']);
  });
  it('a failed signature check is a verify denial with the reason, or the default text', async () => {
    const checks = { sig: 'fail' };
    const withReason = withPcaTool(tool(), sig({ verify: async () => ({ allow: false, checks, reason: 'bad sig' }) }));
    const e = await denial(withReason.execute!({}, {}));
    expect(e.kind).toBe('verify');
    expect(e.checks).toEqual(checks);
    expect(e.message).toBe('PCA tool denied (verify) for stripe.refund: bad sig');
    const noReason = withPcaTool(tool(), sig({ verify: async () => ({ allow: false, checks: {} }) }));
    expect((await denial(noReason.execute!({}, {}))).message).toBe('PCA tool denied (verify) for stripe.refund: verification failed');
  });
  it('a wrapped tool without execute is refused after verification', async () => {
    const t = withPcaTool({ description: 'd' } as never, sig());
    await expect(t.execute!({}, {})).rejects.toThrow(new Error('withPcaTool: the wrapped tool has no execute()'));
  });
});

describe('withPcaTool success path', () => {
  it('reports the verified result and records the output under the proof verb, or the label', async () => {
    const seen: unknown[] = [];
    const recorded: unknown[] = [];
    const recorder = { tool: (v: string, out: unknown) => void recorded.push([v, out]) } as never;
    const t = withPcaTool(tool(), sig({ onVerified: (r: unknown, p: unknown, a: unknown) => void seen.push([r, p, a]), recorder }));
    expect(await t.execute!({ q: 1 }, {})).toBe('out');
    expect(seen).toEqual([[{ allow: true, checks: { sig: 'pass' } }, act(), { q: 1 }]]);
    expect(recorded).toEqual([['stripe.refund', 'out']]);
    const noVerb = withPcaTool(tool(), sig({ require: () => ({}) as unknown as PCActn, recorder }));
    await noVerb.execute!({}, {});
    expect(recorded[1]).toEqual(['(tool)', 'out']);
  });
});

describe('runVerify (signature-only with a grant)', () => {
  const grant = { id: 'g' } as never;
  const run = async (verify: unknown, audience?: string | null) => {
    let seen: Record<string, unknown> | undefined;
    m.verify = (_p, o) => {
      seen = o as Record<string, unknown>;
      return okVerify();
    };
    try {
      await withPcaTool(tool(), sig({ verify, ...(audience !== undefined ? { audience } : {}) })).execute!({}, {});
    } finally {
      m.verify = undefined;
    }
    return seen!;
  };
  it('passes only what was configured', async () => {
    expect(await run({ grant }, 'aud-1')).toStrictEqual({ grant, audience: 'aud-1' });
  });
  it('passes every configured option through, evaluating a clock thunk', async () => {
    const enforce = { taint: true } as never;
    const hooks = { revocation: () => null } as never;
    const roots = ['r1'];
    const seen = await run({ grant, nowEpoch: () => 42, enforce, hooks, authorizedPlanRoots: roots, insecureSkipPlanRootCheck: true }, null);
    expect(seen).toStrictEqual({ grant, audience: null, nowEpoch: 42, enforce, hooks, authorizedPlanRoots: roots, insecureSkipPlanRootCheck: true });
  });
  it('a zero clock and a false skip flag behave as configured', async () => {
    expect(await run({ grant, nowEpoch: 0, insecureSkipPlanRootCheck: false }, 'a')).toStrictEqual({ grant, audience: 'a', nowEpoch: 0 });
  });
  it('a function verifier receives the decoded proof and its result is used as is', async () => {
    const seen: unknown[] = [];
    const t = withPcaTool(tool(), sig({ verify: async (p: unknown) => (seen.push(p), { allow: false, checks: {}, reason: 'custom' }) }));
    expect((await denial(t.execute!({}, {}))).message).toBe('PCA tool denied (verify) for stripe.refund: custom');
    expect(seen).toEqual([act()]);
  });
});

describe('full-policy configuration', () => {
  const comp = { grant: { id: 'g' }, state: { get: () => undefined, put: () => undefined }, isRevoked: () => false };
  const full = (o: Record<string, unknown> = {}) => ({ authorize: { ...comp, operation: () => ({ verb: 'v', params: {} }) }, audience: 'aud', require: () => act(), ...o }) as never;
  it('refuses unknown modes and conflicting combinations with exact messages', () => {
    expect(() => withPcaTool(tool(), { mode: 'x' } as never)).toThrow(new TypeError("withPcaTool: unknown mode 'x'"));
    expect(() => withPcaTool(tool(), { mode: 'signature-only', authorize: comp, verify: okVerify } as never)).toThrow(
      new TypeError("withPcaTool: `authorize` is the full mode; drop it, or drop mode: 'signature-only'"),
    );
    expect(() => withPcaTool(tool(), { mode: 'signature-only' } as never)).toThrow(new TypeError("withPcaTool: mode 'signature-only' needs `verify`"));
    expect(() => withPcaTool(tool(), {} as never)).toThrow(
      new TypeError("withPcaTool: pass `authorize` (full policy, the default mode), or set mode: 'signature-only' with `verify` to check the signature only"),
    );
    expect(() => withPcaTool(tool(), { authorize: comp, verify: okVerify, audience: 'a', verb: 'v' } as never)).toThrow(
      new TypeError("withPcaTool: `verify` checks the signature only: set mode: 'signature-only' to use it, and drop `authorize`"),
    );
  });
  it('lists every missing component joined with a comma and a space', () => {
    expect(() => withPcaTool(tool(), { authorize: {}, audience: 'a' } as never)).toThrow(
      new TypeError("withPcaTool: full policy mode is missing grant or resolveGrant, state, isRevoked, operation (or the guard's verb)"),
    );
  });
  it('a null or absent audience is a configuration error, never "any audience"', () => {
    for (const audience of [null, undefined]) {
      expect(() => withPcaTool(tool(), full({ audience }))).toThrow(new TypeError('withPcaTool: full policy mode is missing audience'));
    }
  });
  it('the operation (or the guard verb) is required', () => {
    expect(() => withPcaTool(tool(), full({ authorize: comp }))).toThrow(new TypeError("withPcaTool: full policy mode is missing operation (or the guard's verb)"));
    expect(() => withPcaTool(tool(), full({ authorize: comp, verb: 'v' }))).not.toThrow();
  });
});

describe('full-policy execution', () => {
  const comp = { grant: { id: 'g' }, state: { get: () => undefined, put: () => undefined }, isRevoked: () => false };
  const decisionOk = { allow: true, verdict: { checks: { sig: 'pass' } } };
  const capture = async (options: Record<string, unknown>, decision: unknown = decisionOk) => {
    const calls: unknown[][] = [];
    m.authz = (...a) => (calls.push(a), decision);
    try {
      const seen: unknown[] = [];
      const t = withPcaTool(tool(), { audience: 'aud', require: () => act(), onVerified: (r: unknown) => void seen.push(r), ...options } as never);
      const out = await t.execute!({ a: 1 }, ctx({ pcaProvenance: { records: [] } }));
      return { calls, seen, out };
    } finally {
      m.authz = undefined;
    }
  };
  it('hands the operation, the audience and the rest of the policy to authorizeExecution and reports its checks', async () => {
    const operation = () => ({ verb: 'v', params: { a: 1 }, provenance: 'given' });
    const { calls, seen } = await capture({ authorize: { ...comp, operation } });
    expect(calls).toHaveLength(1);
    expect(calls[0]![1]).toStrictEqual({ verb: 'v', params: { a: 1 }, provenance: 'given' });
    expect(calls[0]![2]).toStrictEqual({ ...comp, audience: 'aud' });
    expect(seen).toEqual([{ allow: true, checks: { sig: 'pass' } }]);
  });
  it('without a provenance on the operation the provenance source is consulted, and nothing is added when it yields none', async () => {
    const operation = () => ({ verb: 'v', params: {} });
    const withCtx = await capture({ authorize: { ...comp, operation } });
    expect((withCtx.calls[0]![1] as Record<string, unknown>).provenance).toEqual({ records: [] });
    const none = await capture({ authorize: { ...comp, operation }, provenance: () => undefined });
    expect('provenance' in (none.calls[0]![1] as object)).toBe(false);
  });
  it('the default operation is the guard verb with the call args', async () => {
    const { calls } = await capture({ authorize: comp, verb: 'stripe.refund', provenance: () => undefined });
    expect(calls[0]![1]).toStrictEqual({ verb: 'stripe.refund', params: { a: 1 } });
  });
  it('a refused decision is a denial of the decision kind, authn being reported as verify', async () => {
    const refuse = (kind: string) => ({ allow: false, kind, reason: 'nope', checks: { c: 'fail' } });
    const operation = () => ({ verb: 'v', params: {} });
    for (const [kind, want] of [['authn', 'verify'], ['policy', 'policy'], ['replay', 'replay']] as const) {
      m.authz = () => refuse(kind);
      try {
        const e = await denial(withPcaTool(tool(), { audience: 'aud', require: () => act(), authorize: { ...comp, operation } } as never).execute!({}, {}));
        expect([e.kind, e.message, e.checks]).toEqual([want, `PCA tool denied (${want}) for stripe.refund: nope`, { c: 'fail' }]);
      } finally {
        m.authz = undefined;
      }
    }
  });
  it('a refusal for a proof without an action is attributed to the guard label', async () => {
    m.authz = () => ({ allow: false, kind: 'policy', reason: 'nope' });
    try {
      const e = await denial(
        withPcaTool(tool(), { audience: 'aud', require: () => ({}) as unknown as PCActn, authorize: { ...comp, operation: () => ({ verb: 'v', params: {} }) } } as never).execute!({}, {}),
      );
      expect(e.verb).toBe('(tool)');
    } finally {
      m.authz = undefined;
    }
  });
});

describe('pcaTools option merging', () => {
  const run = async (base: Record<string, unknown>, per: Record<string, unknown> | undefined, args: unknown = {}) => {
    const tools = pcaTools({ t: tool() } as never, { ...base, ...(per ? { per: { t: per } } : {}) } as never) as Record<string, { execute: (a: unknown, o: unknown) => Promise<unknown> }>;
    return tools.t!.execute(args, {});
  };
  const baseSig = { mode: 'signature-only', verify: okVerify, audience: 'aud', require: () => act() };

  it('a per-tool verb overrides the shared one and is inherited otherwise', async () => {
    expect((await denial(run({ ...baseSig, verb: 'a.b' }, undefined))).kind).toBe('binding');
    expect(await run({ ...baseSig, verb: 'stripe.refund' }, { verb: 'stripe.refund' })).toBe('out');
    expect((await denial(run({ ...baseSig, verb: 'stripe.refund' }, { verb: 'a.b' }))).message).toContain("this tool's 'a.b'");
    expect((await denial(run({ ...baseSig, verb: 'a.b' }, { onDeny: () => undefined }))).message).toContain("this tool's 'a.b'");
  });
  it('a per-tool proof source overrides the shared one and is inherited otherwise', async () => {
    const seen: string[] = [];
    const base = { ...baseSig, require: () => (seen.push('base'), act()) };
    await run(base, { onDeny: () => undefined });
    await run(base, { require: () => (seen.push('over'), act()) });
    expect(seen).toEqual(['base', 'over']);
  });
  it('callbacks and recorder merge with the override winning and the shared one inherited', async () => {
    const log: string[] = [];
    const base = {
      ...baseSig,
      require: () => undefined,
      onDeny: () => void log.push('base-deny'),
    };
    await denial(run(base, { verb: 'x' }));
    await denial(run(base, { onDeny: () => void log.push('over-deny') }));
    await denial(run({ ...baseSig, require: () => undefined }, { onDeny: () => void log.push('only-over') }));
    expect(log).toEqual(['base-deny', 'over-deny', 'only-over']);

    const v: string[] = [];
    const okBase = { ...baseSig, onVerified: () => void v.push('base-ok'), recorder: { tool: () => void v.push('base-rec') } };
    await run(okBase, { verb: 'stripe.refund' });
    await run(okBase, { onVerified: () => void v.push('over-ok'), recorder: { tool: () => void v.push('over-rec') } });
    await run({ ...baseSig }, { onVerified: () => void v.push('only-ok'), recorder: { tool: () => void v.push('only-rec') } });
    expect(v).toEqual(['base-ok', 'base-rec', 'over-ok', 'over-rec', 'only-ok', 'only-rec']);
  });
  it('audience: an explicit per-tool value (even undefined) replaces the shared one', async () => {
    const audiences: unknown[] = [];
    m.verify = (_p, o) => (audiences.push((o as { audience: unknown }).audience), okVerify());
    try {
      const base = { ...baseSig, verify: { grant: { id: 'g' } } };
      await run(base, undefined);
      await run(base, { audience: 'other' });
      await run(base, { audience: undefined });
      await run(base, { onDeny: () => undefined });
    } finally {
      m.verify = undefined;
    }
    expect(audiences).toEqual(['aud', 'other', undefined, 'aud']);
  });
  it('mode follows the override, and a per-tool authorize or verify replaces the shared mode', async () => {
    const comp = { grant: { id: 'g' }, state: { get: () => undefined, put: () => undefined }, isRevoked: () => false, operation: () => ({ verb: 'v', params: {} }) };
    const calls: string[] = [];
    m.authz = () => (calls.push('authz'), { allow: true, verdict: { checks: {} } });
    try {
      // shared signature-only, per-tool authorize => full mode
      expect(await run({ ...baseSig }, { authorize: comp })).toBe('out');
      // shared full, inherited authorize survives a per-tool verb-only override
      expect(await run({ authorize: comp, audience: 'aud', require: () => act() }, { verb: 'stripe.refund' })).toBe('out');
      // shared full, per-tool verify with explicit signature-only mode
      expect(await run({ authorize: comp, audience: 'aud', require: () => act() }, { mode: 'signature-only', verify: okVerify })).toBe('out');
    } finally {
      m.authz = undefined;
    }
    expect(calls).toEqual(['authz', 'authz']);
  });
  it('a shared provenance source is inherited and an override wins', async () => {
    const comp = { grant: { id: 'g' }, state: { get: () => undefined, put: () => undefined }, isRevoked: () => false, operation: () => ({ verb: 'v', params: {} }) };
    const provs: unknown[] = [];
    m.authz = (_p, op) => (provs.push((op as { provenance?: unknown }).provenance), { allow: true, verdict: { checks: {} } });
    // a source's value is used as the bundle only when it is an object (a string is parsed as a header)
    const src = (tag: string) => () => ({ tag });
    try {
      const base = { authorize: comp, audience: 'aud', require: () => act(), provenance: src('base-prov') };
      await run(base, { verb: 'stripe.refund' });
      await run(base, { provenance: src('over-prov') });
      await run({ authorize: comp, audience: 'aud', require: () => act() }, { provenance: src('only-prov') });
    } finally {
      m.authz = undefined;
    }
    expect(provs).toEqual([{ tag: 'base-prov' }, { tag: 'over-prov' }, { tag: 'only-prov' }]);
  });
  it('only listed tools are guarded', () => {
    const a = tool();
    const b = tool();
    const out = pcaTools({ a, b } as never, { ...baseSig, only: ['a'] } as never) as Record<string, unknown>;
    expect(out['b']).toBe(b);
    expect(out['a']).not.toBe(a);
  });
});

describe('reviewToolCall', () => {
  const ag = {} as Agent;
  it('an unmapped tool is auto and never reaches the reviewer', () => {
    m.review = () => {
      throw new Error('must not review');
    };
    try {
      expect(reviewToolCall(ag, 't', {}, { intent: () => null })).toEqual({ tool: 't', review: { kind: 'auto' } });
    } finally {
      m.review = undefined;
    }
  });
  it('passes the mapped params (or the call args) and exactly the options that were set', () => {
    const calls: unknown[][] = [];
    m.review = (...a) => (calls.push(a), { kind: 'auto' });
    try {
      const intent = (_t: string, _a?: Record<string, unknown>) => ({ verb: 'v', resource: 'r', params: { p: 1 } });
      reviewToolCall(ag, 't', { a: 1 }, { intent });
      reviewToolCall(ag, 't', { a: 1 }, { intent: () => ({ verb: 'v', resource: 'r' }) });
      const renderer = (() => undefined) as never;
      reviewToolCall(ag, 't', undefined, { intent, now: 0, goal: '', standing: [], renderer, insecureUnboundApproval: false });
    } finally {
      m.review = undefined;
    }
    expect(calls[0]!.slice(1)).toEqual(['v', 'r', { p: 1 }, {}]);
    expect(Object.keys(calls[0]![4] as object)).toEqual([]);
    expect(calls[1]![3]).toEqual({ a: 1 });
    expect(calls[2]![4]).toStrictEqual({ now: 0, goal: '', standing: [], renderer: expect.any(Function), insecureUnboundApproval: false });
  });
});

describe('pcaPrepareStep', () => {
  const ag = {} as Agent;
  const stepUp = { kind: 'step_up', request: { id: 's1' } };
  const withReview = (fn: () => void) => {
    m.review = (_a, verb) => (verb === 'risky' ? stepUp : { kind: 'auto' });
    try {
      fn();
    } finally {
      m.review = undefined;
    }
  };
  const intent = (t: string) => ({ verb: t === 'delete' ? 'risky' : 'safe', resource: 'r' });
  it('does nothing without tool calls', () => {
    const f = pcaPrepareStep(ag, { intent, tools: ['delete'] });
    expect(f({ steps: [], stepNumber: 0 })).toBeUndefined();
    expect(f({ steps: [{}], stepNumber: 1 })).toBeUndefined();
    expect(f({ steps: [{ toolCalls: [] }], stepNumber: 1 })).toBeUndefined();
  });
  it('blocks a step-up tool for the next step, with or without an onStepUp observer', () => {
    withReview(() => {
      const seen: unknown[] = [];
      const calls = [{ toolName: 'delete', input: { x: 1 } }, { toolName: 'read', args: { y: 2 } }];
      const quiet = pcaPrepareStep(ag, { intent, tools: ['delete', 'read'] });
      expect(quiet({ steps: [{ toolCalls: calls }], stepNumber: 1 })).toEqual({ activeTools: ['read'] });
      const loud = pcaPrepareStep(ag, { intent, tools: ['delete', 'read'], onStepUp: (p) => void seen.push(p) });
      loud({ steps: [{ toolCalls: calls }], stepNumber: 1 });
      expect(seen).toEqual([[{ tool: 'delete', request: { id: 's1' } }]]);
    });
  });
  it('reads the call arguments from input, falling back to args', () => {
    const got: unknown[] = [];
    const f = pcaPrepareStep(ag, {
      intent: (_t, a) => (got.push(a), null),
      tools: [],
    });
    f({ steps: [{ toolCalls: [{ toolName: 'a', input: { i: 1 }, args: { a: 1 } }, { toolName: 'b', args: { a: 2 } }] }], stepNumber: 1 });
    expect(got).toEqual([{ i: 1 }, { a: 2 }]);
  });
  it('an approved step-up is let through', () => {
    withReview(() => {
      const f = pcaPrepareStep(ag, { intent, tools: ['delete'], approved: () => true });
      expect(f({ steps: [{ toolCalls: [{ toolName: 'delete' }] }], stepNumber: 1 })).toBeUndefined();
    });
  });
});
